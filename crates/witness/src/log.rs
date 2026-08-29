//! The append-only log a witness operates.

use afrolink_crypto::hash::{Domain, Hash32, hash};
use afrolink_crypto::{ConsistencyProof, MerkleProof, MerkleTree, SecretKey};
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{ChainId, Height, Timestamp};

use crate::WitnessError;
use crate::head::{LogId, SignedTreeHead, TreeHead};

/// One observation: "at this wall-clock time, the chain's tip was this block".
///
/// Deliberately tiny. A witness records what it saw, never what it decided —
/// nothing here can cause anything to happen on the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Height observed.
    pub height: Height,
    /// The block at that height.
    pub block_id: Hash32,
    /// The witness's wall clock when it observed. Advisory.
    pub observed_at: Timestamp,
}

impl LogEntry {
    /// The leaf hash this entry contributes to the log's Merkle tree.
    #[must_use]
    pub fn leaf(&self) -> Hash32 {
        hash(Domain::WitnessEntry, &self.to_bytes())
    }
}

/// A witness's append-only log of what it saw on the chain.
///
/// The tree is rebuilt on demand rather than cached. That is `O(n)` per proof
/// and fine at the sizes a witness reaches by polling a chain periodically; a
/// production operator serving many clients would keep an incremental tree.
#[derive(Debug, Clone)]
pub struct WitnessLog {
    chain_id: ChainId,
    log: LogId,
    entries: Vec<LogEntry>,
}

impl WitnessLog {
    /// An empty log for `chain_id`, named by `log`.
    #[must_use]
    pub fn new(chain_id: ChainId, log: LogId) -> Self {
        Self {
            chain_id,
            log,
            entries: Vec::new(),
        }
    }

    /// Append an observation.
    ///
    /// Both height and time must strictly increase. Height must, because the
    /// chain has one-block finality and so can never revisit a height — a log
    /// recording otherwise is recording a reorg that cannot have happened. Time
    /// must, because a log whose timestamps wander is a log whose ordering
    /// carries no information.
    ///
    /// # Errors
    /// [`WitnessError::NonMonotonic`] if either goes backwards or repeats.
    pub fn append(&mut self, entry: LogEntry) -> Result<u64, WitnessError> {
        if let Some(last) = self.entries.last()
            && (entry.height <= last.height || entry.observed_at <= last.observed_at)
        {
            return Err(WitnessError::NonMonotonic {
                got: entry.height.0,
                last: last.height.0,
            });
        }
        self.entries.push(entry);
        Ok(self.size().saturating_sub(1))
    }

    /// Which chain this log observes.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Number of entries.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::try_from(self.entries.len()).unwrap_or(u64::MAX)
    }

    /// The entry at `index`, if any.
    #[must_use]
    pub fn entry(&self, index: u64) -> Option<&LogEntry> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.entries.get(i))
    }

    /// The most recent entry, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&LogEntry> {
        self.entries.last()
    }

    fn tree(&self) -> MerkleTree {
        MerkleTree::from_leaf_hashes(self.entries.iter().map(LogEntry::leaf).collect())
    }

    /// The current Merkle root.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        self.tree().root()
    }

    /// The head to publish at `signed_at`.
    #[must_use]
    pub fn head(&self, signed_at: Timestamp) -> TreeHead {
        TreeHead {
            log: self.log,
            chain_id: self.chain_id.clone(),
            size: self.size(),
            root: self.root(),
            signed_at,
        }
    }

    /// Sign and publish the current head.
    ///
    /// # Errors
    /// [`WitnessError::LogMismatch`] if `key` is not the key this log is named
    /// after — signing under someone else's identifier is refused at the source
    /// as well as at the verifier.
    pub fn sign_head(
        &self,
        key: &SecretKey,
        signed_at: Timestamp,
    ) -> Result<SignedTreeHead, WitnessError> {
        if LogId::from_public_key(&key.public_key()) != self.log {
            return Err(WitnessError::LogMismatch);
        }
        Ok(self.head(signed_at).sign(key))
    }

    /// Prove that the entry at `index` is committed under the current root.
    ///
    /// # Errors
    /// [`WitnessError::IndexOutOfRange`] if there is no such entry.
    pub fn prove_inclusion(&self, index: u64) -> Result<MerkleProof, WitnessError> {
        let i = usize::try_from(index).map_err(|_| WitnessError::IndexOutOfRange)?;
        self.tree()
            .prove(i)
            .map_err(|_| WitnessError::IndexOutOfRange)
    }

    /// Prove that the log at `old_size` is a prefix of the log now.
    ///
    /// **This is the mechanism the whole design rests on.** A wallet that
    /// remembers one head can demand this and check it locally; a witness that
    /// rewrote or dropped anything cannot produce it.
    ///
    /// # Errors
    /// [`WitnessError::SizeMismatch`] if `old_size` exceeds the log.
    pub fn prove_consistency(&self, old_size: u64) -> Result<ConsistencyProof, WitnessError> {
        let old = usize::try_from(old_size).map_err(|_| WitnessError::SizeMismatch {
            got: old_size,
            expected: self.size(),
        })?;
        self.tree()
            .prove_consistency(old)
            .map_err(|_| WitnessError::SizeMismatch {
                got: old_size,
                expected: self.size(),
            })
    }
}

impl Encode for LogEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        self.height.encode(out);
        self.block_id.encode(out);
        self.observed_at.encode(out);
    }
}

impl Decode for LogEntry {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::decode(r)?,
            block_id: Hash32::decode(r)?,
            observed_at: Timestamp::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_primitives::codec::decode_exact;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn entry(h: u64) -> LogEntry {
        LogEntry {
            height: Height(h),
            block_id: Hash32::from_bytes([u8::try_from(h % 251).unwrap_or(0); 32]),
            observed_at: Timestamp::from_millis(1_700_000_000_000 + h * 1_000),
        }
    }

    fn log_with(n: u64) -> WitnessLog {
        let mut log = WitnessLog::new(chain(), LogId::from_public_key(&key(1).public_key()));
        for h in 1..=n {
            log.append(entry(h)).expect("monotonic");
        }
        log
    }

    #[test]
    fn a_log_records_what_it_saw_and_proves_it_later() {
        let log = log_with(20);
        let proof = log.prove_inclusion(7).expect("in range");
        let e = log.entry(7).expect("in range");
        assert!(proof.verify(log.root(), e.leaf()).is_ok());
    }

    #[test]
    fn a_log_cannot_revisit_a_height() {
        // One-block finality means a height happens once. A log claiming
        // otherwise is claiming a reorg that cannot have occurred.
        let mut log = log_with(5);
        assert!(matches!(
            log.append(entry(5)),
            Err(WitnessError::NonMonotonic { .. })
        ));
        assert!(matches!(
            log.append(entry(3)),
            Err(WitnessError::NonMonotonic { .. })
        ));
    }

    #[test]
    fn a_log_cannot_stall_or_rewind_its_clock() {
        let mut log = log_with(5);
        let mut stalled = entry(6);
        stalled.observed_at = log.latest().expect("non-empty").observed_at;
        assert!(matches!(
            log.append(stalled),
            Err(WitnessError::NonMonotonic { .. })
        ));
    }

    #[test]
    fn a_wallet_that_remembers_one_head_can_check_everything_since() {
        // The headline mechanism: 32 bytes plus a size, and six months of log
        // growth becomes verifiable.
        let early = log_with(9);
        let remembered_root = early.root();

        let later = log_with(400);
        let proof = later.prove_consistency(9).expect("in range");
        assert!(proof.verify(remembered_root, later.root()).is_ok());
    }

    #[test]
    fn a_witness_that_rewrote_history_cannot_satisfy_that_wallet() {
        let honest = log_with(50);
        let remembered_root = log_with(9).root();

        // The witness swaps out an entry the wallet already saw.
        let mut forged = log_with(50);
        forged.entries[4].block_id = Hash32::from_bytes([0xEE; 32]);

        let proof = forged.prove_consistency(9).expect("in range");
        assert!(
            proof.verify(remembered_root, forged.root()).is_err(),
            "a rewritten log must fail against a root the wallet already holds"
        );
        assert!(
            honest
                .prove_consistency(9)
                .expect("in range")
                .verify(remembered_root, honest.root())
                .is_ok()
        );
    }

    #[test]
    fn a_witness_cannot_sign_its_log_with_the_wrong_key() {
        let log = log_with(3);
        assert_eq!(
            log.sign_head(&key(2), Timestamp::from_millis(1)).err(),
            Some(WitnessError::LogMismatch)
        );
        assert!(log.sign_head(&key(1), Timestamp::from_millis(1)).is_ok());
    }

    #[test]
    fn a_signed_head_describes_the_log_it_came_from() {
        let log = log_with(12);
        let sth = log
            .sign_head(&key(1), Timestamp::from_millis(1_700_000_100_000))
            .expect("right key");
        assert_eq!(sth.head.size, 12);
        assert_eq!(sth.head.root, log.root());
        assert!(sth.verify(&key(1).public_key()).is_ok());
    }

    #[test]
    fn an_entry_round_trips() {
        let e = entry(3);
        assert_eq!(decode_exact::<LogEntry>(&e.to_bytes()), Ok(e));
    }
}
