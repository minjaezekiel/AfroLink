//! The wallet side: known witnesses, and the checks that turn a witness's
//! claim into something a wallet is allowed to act on.
//!
//! Nothing here returns a usable value without having verified it first. An
//! [`Observation`] cannot be constructed by hand — the only way to obtain one is
//! [`WitnessSet::observe`], which checks the signature, the chain, and the
//! inclusion proof before it will build one. That mirrors `ProvedValue` in
//! `crates/rpc`, for the same reason: an unverified claim should not be
//! *representable* as a verified one.

use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{ConsistencyProof, MerkleProof, PublicKey};
use afrolink_primitives::{ChainId, Height, Timestamp};

use crate::WitnessError;
use crate::head::{LogId, SignedTreeHead};
use crate::log::LogEntry;

/// A witness a wallet is willing to listen to.
///
/// `country` is not decoration. Corroboration requires agreement across
/// jurisdictions, because the failure this defends against — collusion — is
/// cheapest among parties under one legal authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// The log's identifier, derived from `key`.
    pub log: LogId,
    /// The key the witness signs heads with.
    pub key: PublicKey,
    /// ISO 3166-1 alpha-2 code of the licensing jurisdiction.
    pub country: [u8; 2],
    /// Human-readable label, for wallets to display.
    pub name: String,
}

impl Witness {
    /// Build a witness from its signing key, deriving the log identifier.
    #[must_use]
    pub fn new(key: PublicKey, country: [u8; 2], name: impl Into<String>) -> Self {
        Self {
            log: LogId::from_public_key(&key),
            key,
            country,
            name: name.into(),
        }
    }
}

/// The set of witnesses a wallet ships with.
///
/// Shipped in the binary, updated with the app, and auditable by anyone who
/// reads it. This is a *bootstrap* list, not an authority: a witness in here can
/// be caught lying by any other witness, and no witness can cause anything to
/// happen on the chain.
#[derive(Debug, Clone)]
pub struct WitnessSet {
    witnesses: Vec<Witness>,
}

impl WitnessSet {
    /// Build a witness set.
    ///
    /// # Errors
    /// [`WitnessError::EmptyWitnessSet`] if empty, or
    /// [`WitnessError::DuplicateWitness`] if a log appears twice — a duplicate
    /// would let one operator count as two toward corroboration, which is the
    /// exact thing corroboration exists to prevent.
    pub fn new(witnesses: Vec<Witness>) -> Result<Self, WitnessError> {
        if witnesses.is_empty() {
            return Err(WitnessError::EmptyWitnessSet);
        }
        for (i, w) in witnesses.iter().enumerate() {
            if witnesses
                .iter()
                .skip(i.saturating_add(1))
                .any(|o| o.log == w.log)
            {
                return Err(WitnessError::DuplicateWitness);
            }
        }
        Ok(Self { witnesses })
    }

    /// Look up a witness by log identifier.
    #[must_use]
    pub fn get(&self, log: &LogId) -> Option<&Witness> {
        self.witnesses.iter().find(|w| &w.log == log)
    }

    /// How many witnesses are known.
    #[must_use]
    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    /// Whether the set is empty. Never true for a constructed set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    /// How many distinct jurisdictions are represented.
    ///
    /// A wallet should compare this against its [`Policy`](crate::Policy)
    /// *before* it needs it: a set that cannot satisfy the policy is a set that
    /// will strand the user at exactly the wrong moment.
    #[must_use]
    pub fn countries(&self) -> usize {
        let mut seen: Vec<[u8; 2]> = Vec::new();
        for w in &self.witnesses {
            if !seen.contains(&w.country) {
                seen.push(w.country);
            }
        }
        seen.len()
    }

    /// Verify a witness's claim that it recorded `entry` at `index`.
    ///
    /// Checks, in order: the witness is known; the head is genuinely signed by
    /// it; the head is for the chain we care about; the proof was built against
    /// the size the head commits to; and the entry is actually in the tree.
    ///
    /// # Errors
    /// The first check that fails. Nothing partial is returned.
    pub fn observe(
        &self,
        chain_id: &ChainId,
        sth: &SignedTreeHead,
        index: u64,
        entry: &LogEntry,
        proof: &MerkleProof,
    ) -> Result<Observation, WitnessError> {
        let witness = self
            .get(&sth.head.log)
            .ok_or(WitnessError::UnknownWitness)?;
        sth.verify(&witness.key)?;

        if &sth.head.chain_id != chain_id {
            return Err(WitnessError::WrongChain {
                got: sth.head.chain_id.to_string(),
                expected: chain_id.to_string(),
            });
        }
        // The proof must be against the tree the head committed to, at the
        // index claimed. Without both, a witness could prove membership in some
        // other tree of its own choosing.
        // Checked here as well as inside `verify`, so the failure is reported as
        // a size mismatch rather than as a generic bad proof. The check in the
        // primitive is the backstop for callers that forget; this one is for
        // whoever has to read the error.
        let total = u64::try_from(proof.total).unwrap_or(u64::MAX);
        let at = u64::try_from(proof.index).unwrap_or(u64::MAX);
        if total != sth.head.size || at != index {
            return Err(WitnessError::SizeMismatch {
                got: total,
                expected: sth.head.size,
            });
        }
        let at_index = usize::try_from(index).map_err(|_| WitnessError::IndexOutOfRange)?;
        let at_total = usize::try_from(sth.head.size).map_err(|_| WitnessError::IndexOutOfRange)?;
        // Position and tree size are passed explicitly: a proof's own `index`
        // and `total` are prover-chosen and prove nothing on their own.
        proof
            .verify(sth.head.root, entry.leaf(), at_index, at_total)
            .map_err(|_| WitnessError::BadInclusionProof)?;

        Ok(Observation {
            log: witness.log,
            country: witness.country,
            height: entry.height,
            block_id: entry.block_id,
            head_size: sth.head.size,
            head_root: sth.head.root,
            signed_at: sth.head.signed_at,
        })
    }

    /// Verify that a witness's log still contains everything the wallet saw.
    ///
    /// `remembered` is what the wallet stored at the end of its last session —
    /// a size and a root, 40 bytes. The witness must produce a proof that its
    /// log at that size is a prefix of its log now.
    ///
    /// **This is the check that survives a long absence.** It does not weaken
    /// with time: a proof spanning six months is exactly as conclusive as one
    /// spanning an hour, because either the hashes reconcile or they do not.
    ///
    /// # Errors
    /// [`WitnessError::BadConsistencyProof`] if the log cannot show it kept the
    /// history the wallet already holds.
    pub fn check_continuity(
        &self,
        remembered: &Remembered,
        sth: &SignedTreeHead,
        proof: &ConsistencyProof,
    ) -> Result<(), WitnessError> {
        let witness = self
            .get(&sth.head.log)
            .ok_or(WitnessError::UnknownWitness)?;
        sth.verify(&witness.key)?;

        if sth.head.log != remembered.log {
            return Err(WitnessError::LogMismatch);
        }
        // A log may only grow. Shrinking is a rewrite by another name.
        if sth.head.size < remembered.size {
            return Err(WitnessError::SizeMismatch {
                got: sth.head.size,
                expected: remembered.size,
            });
        }
        let declared_old = u64::try_from(proof.old_size).unwrap_or(u64::MAX);
        let declared_new = u64::try_from(proof.new_size).unwrap_or(u64::MAX);
        if declared_old != remembered.size || declared_new != sth.head.size {
            return Err(WitnessError::SizeMismatch {
                got: declared_old,
                expected: remembered.size,
            });
        }
        let old = usize::try_from(remembered.size).map_err(|_| WitnessError::IndexOutOfRange)?;
        let new = usize::try_from(sth.head.size).map_err(|_| WitnessError::IndexOutOfRange)?;
        proof
            .verify(remembered.root, sth.head.root, old, new)
            .map_err(|_| WitnessError::BadConsistencyProof)
    }
}

/// What a wallet keeps about one witness between sessions.
///
/// Forty bytes. This is the entire cost of being able to detect, months later,
/// that a witness rewrote its history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remembered {
    /// Which log.
    pub log: LogId,
    /// Its size when last seen.
    pub size: u64,
    /// Its root at that size.
    pub root: Hash32,
}

impl Remembered {
    /// Record a head the wallet has just verified.
    #[must_use]
    pub fn from_head(sth: &SignedTreeHead) -> Self {
        Self {
            log: sth.head.log,
            size: sth.head.size,
            root: sth.head.root,
        }
    }
}

/// A witness claim that has been checked.
///
/// Fields are readable because construction proved them. There is no way to
/// build one from an unverified claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    log: LogId,
    country: [u8; 2],
    height: Height,
    block_id: Hash32,
    head_size: u64,
    head_root: Hash32,
    signed_at: Timestamp,
}

impl Observation {
    /// Which witness said this.
    #[must_use]
    pub const fn log(&self) -> LogId {
        self.log
    }

    /// The witness's jurisdiction.
    #[must_use]
    pub const fn country(&self) -> [u8; 2] {
        self.country
    }

    /// The height observed.
    #[must_use]
    pub const fn height(&self) -> Height {
        self.height
    }

    /// The block the witness saw at that height.
    #[must_use]
    pub const fn block_id(&self) -> Hash32 {
        self.block_id
    }

    /// The head this observation was proved against, for the wallet to store.
    #[must_use]
    pub const fn remembered(&self) -> Remembered {
        Remembered {
            log: self.log,
            size: self.head_size,
            root: self.head_root,
        }
    }

    /// When the witness signed the head. Advisory — a witness's own clock is
    /// not evidence, which is why nothing in corroboration depends on it.
    #[must_use]
    pub const fn signed_at(&self) -> Timestamp {
        self.signed_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::WitnessLog;
    use afrolink_crypto::SecretKey;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn witness(seed: u8, country: &[u8; 2]) -> Witness {
        Witness::new(key(seed).public_key(), *country, format!("witness-{seed}"))
    }

    fn entry(h: u64) -> LogEntry {
        LogEntry {
            height: Height(h),
            block_id: Hash32::from_bytes([u8::try_from(h % 251).unwrap_or(0); 32]),
            observed_at: Timestamp::from_millis(1_700_000_000_000 + h * 1_000),
        }
    }

    fn log(seed: u8, n: u64) -> WitnessLog {
        let mut l = WitnessLog::new(chain(), LogId::from_public_key(&key(seed).public_key()));
        for h in 1..=n {
            l.append(entry(h)).expect("monotonic");
        }
        l
    }

    fn at() -> Timestamp {
        Timestamp::from_millis(1_700_000_500_000)
    }

    #[test]
    fn a_wallet_accepts_a_proved_observation() {
        let set = WitnessSet::new(vec![witness(1, b"ke")]).expect("valid");
        let l = log(1, 10);
        let sth = l.sign_head(&key(1), at()).expect("own key");
        let proof = l.prove_inclusion(4).expect("in range");

        let obs = set
            .observe(&chain(), &sth, 4, l.entry(4).expect("in range"), &proof)
            .expect("proved");
        assert_eq!(obs.height(), Height(5));
        assert_eq!(obs.country(), *b"ke");
    }

    #[test]
    fn a_witness_the_wallet_does_not_know_is_ignored() {
        // The bootstrap list is the wallet's own; a stranger cannot join it by
        // showing up with a well-formed proof.
        let set = WitnessSet::new(vec![witness(1, b"ke")]).expect("valid");
        let l = log(9, 10);
        let sth = l.sign_head(&key(9), at()).expect("own key");
        let proof = l.prove_inclusion(0).expect("in range");
        assert_eq!(
            set.observe(&chain(), &sth, 0, l.entry(0).expect("in range"), &proof),
            Err(WitnessError::UnknownWitness)
        );
    }

    #[test]
    fn a_witness_for_another_network_is_refused() {
        let set = WitnessSet::new(vec![witness(1, b"ke")]).expect("valid");
        let other = ChainId::new("afrolink-testnet").expect("valid");
        let mut l = WitnessLog::new(other, LogId::from_public_key(&key(1).public_key()));
        l.append(entry(1)).expect("monotonic");
        let sth = l.sign_head(&key(1), at()).expect("own key");
        let proof = l.prove_inclusion(0).expect("in range");

        assert!(matches!(
            set.observe(&chain(), &sth, 0, l.entry(0).expect("in range"), &proof),
            Err(WitnessError::WrongChain { .. })
        ));
    }

    #[test]
    fn an_entry_the_witness_never_committed_cannot_be_proved() {
        let set = WitnessSet::new(vec![witness(1, b"ke")]).expect("valid");
        let l = log(1, 10);
        let sth = l.sign_head(&key(1), at()).expect("own key");
        let proof = l.prove_inclusion(4).expect("in range");

        // Same proof, different entry: the witness claims it saw a block it did
        // not record.
        let mut invented = l.entry(4).expect("in range").clone();
        invented.block_id = Hash32::from_bytes([0xAB; 32]);
        assert_eq!(
            set.observe(&chain(), &sth, 4, &invented, &proof),
            Err(WitnessError::BadInclusionProof)
        );
    }

    #[test]
    fn a_proof_against_a_different_tree_size_is_refused() {
        // A witness signs a head at one size and proves against another, which
        // would let it show membership in a tree nobody vouched for.
        let set = WitnessSet::new(vec![witness(1, b"ke")]).expect("valid");
        let big = log(1, 20);
        let small = log(1, 10);
        let sth = big.sign_head(&key(1), at()).expect("own key");
        let proof = small.prove_inclusion(4).expect("in range");

        assert!(matches!(
            set.observe(&chain(), &sth, 4, small.entry(4).expect("in range"), &proof),
            Err(WitnessError::SizeMismatch { .. })
        ));
    }

    #[test]
    fn a_wallet_returning_after_a_long_absence_checks_continuity() {
        // Six months of growth, verified against forty remembered bytes.
        let set = WitnessSet::new(vec![witness(1, b"ke")]).expect("valid");
        let early = log(1, 12);
        let remembered = Remembered::from_head(&early.sign_head(&key(1), at()).expect("own key"));

        let later = log(1, 5_000);
        let sth = later.sign_head(&key(1), at()).expect("own key");
        let proof = later.prove_consistency(12).expect("in range");

        assert!(set.check_continuity(&remembered, &sth, &proof).is_ok());
    }

    #[test]
    fn a_witness_that_rewrote_history_fails_continuity() {
        let set = WitnessSet::new(vec![witness(1, b"ke")]).expect("valid");
        let early = log(1, 12);
        let remembered = Remembered::from_head(&early.sign_head(&key(1), at()).expect("own key"));

        // The witness quietly changes a block it reported months ago.
        let mut forged = WitnessLog::new(chain(), LogId::from_public_key(&key(1).public_key()));
        for h in 1..=5_000u64 {
            let mut e = entry(h);
            if h == 6 {
                e.block_id = Hash32::from_bytes([0xEE; 32]);
            }
            forged.append(e).expect("monotonic");
        }
        let sth = forged.sign_head(&key(1), at()).expect("own key");
        let proof = forged.prove_consistency(12).expect("in range");

        assert_eq!(
            set.check_continuity(&remembered, &sth, &proof),
            Err(WitnessError::BadConsistencyProof)
        );
    }

    #[test]
    fn a_witness_cannot_shrink_its_log() {
        let set = WitnessSet::new(vec![witness(1, b"ke")]).expect("valid");
        let remembered =
            Remembered::from_head(&log(1, 50).sign_head(&key(1), at()).expect("own key"));
        let shrunk = log(1, 20);
        let sth = shrunk.sign_head(&key(1), at()).expect("own key");
        let proof = shrunk.prove_consistency(20).expect("in range");

        assert!(matches!(
            set.check_continuity(&remembered, &sth, &proof),
            Err(WitnessError::SizeMismatch { .. })
        ));
    }

    #[test]
    fn one_operator_cannot_be_listed_twice() {
        // Otherwise a single party satisfies a policy that asks for two.
        let dup = WitnessSet::new(vec![witness(1, b"ke"), witness(1, b"ng")]);
        assert_eq!(dup.err(), Some(WitnessError::DuplicateWitness));
    }

    #[test]
    fn a_witness_set_reports_its_jurisdictional_spread() {
        let set = WitnessSet::new(vec![
            witness(1, b"ke"),
            witness(2, b"ke"),
            witness(3, b"ng"),
        ])
        .expect("valid");
        assert_eq!(set.len(), 3);
        assert_eq!(set.countries(), 2, "three witnesses, two jurisdictions");
    }
}
