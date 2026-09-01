//! The light client — the whole design thesis, in one small crate.
//!
//! Research §5: ~600 million people in Africa have no electricity, entry-level
//! smartphones cost a quarter of monthly GDP per capita, and only mobile *data*
//! is genuinely affordable. A chain for this context cannot ask users to store
//! it or to trust whoever serves it to them.
//!
//! So a wallet here holds two things:
//!
//! * the **validator set**, and
//! * one **32-byte block header** per height it cares about.
//!
//! Everything else — balances, group records, issuance history — is fetched from
//! an untrusted server *with a proof*, and checked locally. The server can be
//! hostile, compromised, or a state actor; it can withhold an answer, but it
//! cannot forge one.
//!
//! # The two verifications
//!
//! 1. **Is this header real?** A [`Commit`] carries the precommit signatures of
//!    more than two thirds of voting power. Checking them is pure signature
//!    arithmetic — no chain, no execution.
//! 2. **Is this value in that state?** The header commits to an `app_hash`, the
//!    root of the sparse Merkle state tree. A proof either reconstructs that
//!    root or it does not.
//!
//! Crucially the second also proves **absence**, so a server cannot lie by
//! omission — "you have no balance" is a claim it must prove like any other.
//!
//! # The third thing: staying inside the trusting period
//!
//! Signature arithmetic alone is not enough on a proof-of-stake chain. A
//! validator who has since unbonded has nothing left to lose, so an attacker who
//! later acquires those old keys can sign a perfectly valid-looking alternate
//! history — a **long-range attack**. Every signature checks out; the chain is a
//! fiction.
//!
//! The defence is economic and it has a deadline. Stake stays slashable for the
//! **unbonding period** after a validator exits, so within that window forging
//! history is punishable. Past it, it is free. A client whose trusted header is
//! older than that window therefore cannot safely verify anything, and this
//! client says so ([`LightError::TrustExpired`]) rather than accepting a chain
//! it cannot judge.
//!
//! That deadline has a cost, and it lands on exactly the users this chain is
//! for: a wallet offline longer than the trusting period needs a fresh
//! checkpoint before it can do anything. [`LightClient::from_block_id`] makes
//! that checkpoint as small as it can possibly be — a chain, a height and 32
//! bytes — so it fits in a QR code an agent can hand out with no network at all.
//! `crates/witness` is how a wallet obtains those 32 bytes without having to
//! believe any single source.
//!
//! Full reasoning: [ADR-0010](../../../docs/adr/0010-long-range-attacks.md) and
//! [ADR-0011](../../../docs/adr/0011-objective-anchors.md).

#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
    )
)]

use afrolink_consensus::{Commit, CommitError, ValidatorSet};
use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_executor::BlockHeader;
use afrolink_primitives::codec::decode_exact;
use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
use afrolink_state::{Proof, StoreKey};
use thiserror::Error;

/// Why a light-client check failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LightError {
    /// The commit did not verify against the validator set.
    #[error(transparent)]
    Commit(#[from] CommitError),
    /// The commit finalises a different block than the header presented.
    #[error("commit is for a different block than this header")]
    HeaderMismatch,
    /// The header belongs to another network.
    #[error("header is for chain {got}, expected {expected}")]
    WrongChain {
        /// Chain named in the header.
        got: String,
        /// Chain this client follows.
        expected: String,
    },
    /// The header does not extend the trusted one.
    #[error("header at height {got} does not follow the trusted height {trusted}")]
    NonSequential {
        /// Height offered.
        got: u64,
        /// Height currently trusted.
        trusted: u64,
    },
    /// The header's parent is not the trusted block.
    #[error("header does not name the trusted block as its parent")]
    BrokenChain,
    /// A state proof did not reconstruct the header's `app_hash`.
    #[error("state proof does not verify against the trusted app hash")]
    BadProof,
    /// A proved value did not decode.
    #[error("proved value is malformed")]
    MalformedValue,
    /// The trusted header is older than the trusting period.
    ///
    /// **Not a transient failure.** The client can no longer distinguish the
    /// real chain from a forged one, and no amount of retrying changes that. It
    /// needs a fresh checkpoint from a source it trusts.
    #[error(
        "trusted header is {age_ms}ms old, trusting period is {period_ms}ms — \
         a new checkpoint is required"
    )]
    TrustExpired {
        /// Age of the trusted header, in milliseconds.
        age_ms: u64,
        /// The configured trusting period, in milliseconds.
        period_ms: u64,
    },
    /// A header moved backwards in time.
    #[error("header time {got} is not after the trusted header time {trusted}")]
    NonMonotonicTime {
        /// Time on the offered header.
        got: u64,
        /// Time on the trusted header.
        trusted: u64,
    },
    /// The validator set offered does not match what the chain committed to.
    #[error("validator set does not match the commitment in the header")]
    ValidatorSetMismatch,
    /// Too little of the *trusted* set signed the new header to justify skipping.
    #[error("only {got} of {needed} trusted voting power signed; cannot skip to this height")]
    InsufficientOverlap {
        /// Trusted power that signed.
        got: u64,
        /// Trusted power required.
        needed: u64,
    },
    /// The header is dated further ahead than any honest clock skew explains.
    #[error("header time {got} is more than {drift_ms}ms ahead of the local clock {now}")]
    FromTheFuture {
        /// Time on the offered header.
        got: u64,
        /// The client's own clock.
        now: u64,
        /// Drift allowance.
        drift_ms: u64,
    },
    /// The header offered is not the block the checkpoint names.
    #[error("header does not match the checkpointed block")]
    WrongBlock,
}

/// How long a trusted header stays usable, in milliseconds.
///
/// Two thirds of [`UNBONDING_MS`], following Tendermint's practice of keeping
/// the trusting period comfortably inside the unbonding period. The margin is
/// what gives the network time to detect misbehaviour and slash while the
/// offender's stake is still bonded.
pub const TRUSTING_PERIOD_MS: u64 = UNBONDING_MS / 3 * 2;

/// How long stake stays slashable after a validator begins exiting.
///
/// Defined in `afrolink_primitives` and re-exported, because `crates/staking`
/// enforces the same number and the two must never drift.
pub use afrolink_primitives::UNBONDING_MS;

// The margin between the two is the whole mechanism: it leaves time to detect
// misbehaviour and slash while the offender's stake is still bonded. If they
// were equal, an attacker could unbond at the exact moment a client's trust
// expired. Enforced at compile time so no future edit can close the gap.
const _: () = assert!(TRUSTING_PERIOD_MS < UNBONDING_MS);

/// How far ahead of the local clock a header's time may be.
///
/// Monotonic time alone stops an attacker *rewinding* the trusting-period clock.
/// It does nothing about the opposite move: a header dated next year parks the
/// deadline in the future and keeps a client accepting a dead chain
/// indefinitely. Both directions have to be bounded.
///
/// Five seconds is generous against real clock skew on a handset and useless as
/// an attack window at one-second blocks.
pub const MAX_CLOCK_DRIFT_MS: u64 = 5_000;

/// A wallet's view of the chain.
///
/// Holds the trusted header plus the validator set that signed it and the set
/// entitled to sign the next one. Carrying `next_validators` is what allows an
/// update across a set change to be *verified* rather than assumed.
#[derive(Debug, Clone)]
pub struct LightClient {
    chain_id: ChainId,
    validators: ValidatorSet,
    next_validators: ValidatorSet,
    trusted: BlockHeader,
    trusting_period_ms: u64,
}

impl LightClient {
    /// Start from a genesis header and the genesis validator set.
    ///
    /// This is the client's only act of trust, and it is unavoidable: every
    /// verification system needs a root. Here it is a public, auditable file
    /// whose hash operators publish before launch.
    #[must_use]
    pub fn new(chain_id: ChainId, validators: ValidatorSet, genesis_header: BlockHeader) -> Self {
        Self {
            chain_id,
            next_validators: validators.clone(),
            validators,
            trusted: genesis_header,
            trusting_period_ms: TRUSTING_PERIOD_MS,
        }
    }

    /// Start from a checkpoint rather than from genesis.
    ///
    /// **This is the intended way to onboard a wallet**, and the honest name for
    /// the trust it requires. Syncing from genesis is safe but slow; syncing
    /// from a recent header is fast and requires believing whoever supplied it.
    ///
    /// The belief is cheap to check and hard to abuse: a checkpoint is a height
    /// and a hash, publishable by every validator, exchange, wallet vendor and
    /// block explorer independently. A user who compares two sources that do not
    /// collude has a stronger guarantee than any purely cryptographic one
    /// available here — which is what "weak subjectivity" actually means.
    ///
    /// # Errors
    /// Returns [`LightError::ValidatorSetMismatch`] if either set does not match
    /// the header's commitments — so a bad checkpoint fails immediately rather
    /// than poisoning every later verification.
    pub fn from_checkpoint(
        chain_id: ChainId,
        header: BlockHeader,
        validators: ValidatorSet,
        next_validators: ValidatorSet,
    ) -> Result<Self, LightError> {
        if validators.hash() != header.validators_hash
            || next_validators.hash() != header.next_validators_hash
        {
            return Err(LightError::ValidatorSetMismatch);
        }
        Ok(Self {
            chain_id,
            validators,
            next_validators,
            trusted: header,
            trusting_period_ms: TRUSTING_PERIOD_MS,
        })
    }

    /// Start from a block identifier alone — the smallest possible root of trust.
    ///
    /// **This is what makes a checkpoint scannable.** `from_checkpoint` needs a
    /// header and both validator sets, which is far too much to read off a
    /// screen or carry on paper. But a header's identifier commits to its own
    /// contents, including both validator-set hashes, and each set is checked
    /// against those. So the header and the sets can come from **anybody at all**
    /// — a hostile server, a stranger's phone — and only `block_id` has to be
    /// obtained honestly.
    ///
    /// A chain identifier, a height and 32 bytes: small enough for a QR code an
    /// agent prints once and hands out offline, which is the difference between
    /// a defensible security model and one that strands users with intermittent
    /// connectivity.
    ///
    /// Obtain `block_id` from `afrolink_witness::corroborate` rather than from a
    /// single source, so that no one party's word is load-bearing.
    ///
    /// # Errors
    /// [`LightError::WrongBlock`] if `header` is not that block,
    /// [`LightError::WrongChain`] if it belongs to another network, or
    /// [`LightError::ValidatorSetMismatch`] if either set does not match the
    /// header's commitments.
    pub fn from_block_id(
        chain_id: ChainId,
        block_id: Hash32,
        header: BlockHeader,
        validators: ValidatorSet,
        next_validators: ValidatorSet,
    ) -> Result<Self, LightError> {
        if header.chain_id != chain_id {
            return Err(LightError::WrongChain {
                got: header.chain_id.to_string(),
                expected: chain_id.to_string(),
            });
        }
        if header.id() != block_id {
            return Err(LightError::WrongBlock);
        }
        Self::from_checkpoint(chain_id, header, validators, next_validators)
    }

    /// Override the trusting period. Testing and bespoke deployments only.
    #[must_use]
    pub fn with_trusting_period(mut self, period_ms: u64) -> Self {
        self.trusting_period_ms = period_ms;
        self
    }

    /// Whether the trusted header is still inside the trusting period at `now`.
    ///
    /// A wallet should check this before showing a balance, not only before
    /// updating: a stale trusted header makes every proof against it
    /// meaningless, however well-formed.
    #[must_use]
    pub fn is_trusted_at(&self, now: Timestamp) -> bool {
        now.0.saturating_sub(self.trusted.time.0) <= self.trusting_period_ms
    }

    /// The set entitled to sign the next block.
    #[must_use]
    pub fn next_validators(&self) -> &ValidatorSet {
        &self.next_validators
    }

    /// The header currently trusted.
    #[must_use]
    pub fn trusted_header(&self) -> &BlockHeader {
        &self.trusted
    }

    /// The height currently trusted.
    #[must_use]
    pub fn height(&self) -> Height {
        self.trusted.height
    }

    /// The state root the client will check proofs against.
    #[must_use]
    pub fn app_hash(&self) -> Hash32 {
        self.trusted.app_hash
    }

    /// Verify the next header in sequence and adopt it.
    ///
    /// The strict path: `header` must be the direct successor of the trusted
    /// one. Cheap, and the right choice when a client is already up to date.
    ///
    /// `validators` is the set that signed `header`. It is checked against the
    /// trusted header's `next_validators_hash`, so a caller cannot substitute a
    /// set of its own choosing.
    ///
    /// # Errors
    /// Returns the first [`LightError`] encountered. The trusted state is left
    /// unchanged on any failure.
    pub fn update(
        &mut self,
        header: BlockHeader,
        commit: &Commit,
        validators: ValidatorSet,
        next_validators: ValidatorSet,
        now: Timestamp,
    ) -> Result<(), LightError> {
        self.check_freshness(now)?;
        self.check_chain_and_time(&header, now)?;

        if header.height != self.trusted.height.next() {
            return Err(LightError::NonSequential {
                got: header.height.0,
                trusted: self.trusted.height.0,
            });
        }
        if header.parent != self.trusted.id() {
            return Err(LightError::BrokenChain);
        }
        self.check_commit_and_sets(&header, commit, &validators, &next_validators)?;
        // The set signing this block must be the one the trusted header said
        // would sign it.
        if header.validators_hash != self.trusted.next_validators_hash {
            return Err(LightError::ValidatorSetMismatch);
        }

        commit.verify(&self.chain_id, &validators)?;
        self.adopt(header, validators, next_validators);
        Ok(())
    }

    /// Verify a header many blocks ahead without downloading the ones between.
    ///
    /// **This is what makes syncing a phone practical.** Walking every header
    /// from a month-old checkpoint at one-second blocks means ~1.8 million
    /// headers; skipping means a handful.
    ///
    /// The safety argument is the `1/3` overlap rule. If more than one third of
    /// the *currently trusted* voting power signed the new header, then at least
    /// one correct validator signed it — because a Byzantine coalition is
    /// bounded by one third. One correct signer is enough, since a correct
    /// validator will not sign a header on a forked chain.
    ///
    /// Note the threshold is `> 1/3` of the **trusted** set, *and* separately a
    /// full `> 2/3` quorum of the **new** set. Both are required: the first ties
    /// the new header to the history the client already believes, the second is
    /// ordinary consensus validity.
    ///
    /// When overlap is insufficient the caller should bisect — verify a header
    /// halfway between and try again — which is why
    /// [`LightError::InsufficientOverlap`] is a distinct, recoverable error
    /// rather than a flat rejection.
    ///
    /// # Errors
    /// Returns the first [`LightError`] encountered. The trusted state is left
    /// unchanged on any failure.
    pub fn verify_skipping(
        &mut self,
        header: BlockHeader,
        commit: &Commit,
        validators: ValidatorSet,
        next_validators: ValidatorSet,
        now: Timestamp,
    ) -> Result<(), LightError> {
        self.check_freshness(now)?;
        self.check_chain_and_time(&header, now)?;

        if header.height <= self.trusted.height {
            return Err(LightError::NonSequential {
                got: header.height.0,
                trusted: self.trusted.height.0,
            });
        }

        self.check_commit_and_sets(&header, commit, &validators, &next_validators)?;

        // Ordinary validity: the new set reached a quorum on this block.
        commit.verify(&self.chain_id, &validators)?;

        // The sequential case needs no overlap argument — the trusted header
        // already named this exact set.
        if header.height == self.trusted.height.next()
            && header.validators_hash == self.trusted.next_validators_hash
        {
            self.adopt(header, validators, next_validators);
            return Ok(());
        }

        // Skipping: require more than a third of the trusted set to have signed.
        let overlap = self.trusted_power_in(commit);
        let needed = self.validators.max_byzantine_power().saturating_add(1);
        if overlap < needed {
            return Err(LightError::InsufficientOverlap {
                got: overlap,
                needed,
            });
        }

        self.adopt(header, validators, next_validators);
        Ok(())
    }

    /// How much of the currently trusted voting power signed `commit`.
    ///
    /// Counts each trusted validator at most once and only for signatures that
    /// actually verify, so a commit stuffed with repeated or forged entries
    /// gains nothing.
    fn trusted_power_in(&self, commit: &Commit) -> u64 {
        let mut counted: Vec<Address> = Vec::new();
        let mut power: u64 = 0;

        for signed in &commit.signatures {
            let address = signed.vote.validator;
            if counted.contains(&address) {
                continue;
            }
            let Some(validator) = self.validators.get(&address) else {
                continue;
            };
            if validator
                .public_key
                .verify(
                    afrolink_crypto::hash::Domain::VoteSignDoc,
                    &signed.vote.sign_doc(),
                    &signed.signature,
                )
                .is_err()
            {
                continue;
            }
            counted.push(address);
            power = power.saturating_add(validator.voting_power);
        }
        power
    }

    /// Network and time checks, run before anything more expensive.
    fn check_chain_and_time(&self, header: &BlockHeader, now: Timestamp) -> Result<(), LightError> {
        if header.chain_id != self.chain_id {
            return Err(LightError::WrongChain {
                got: header.chain_id.to_string(),
                expected: self.chain_id.to_string(),
            });
        }
        // Time is bounded in both directions, because both directions are
        // attacks on the same deadline.
        //
        // Backwards: an older-timestamped header rewinds the trusting-period
        // clock, keeping a stale client alive indefinitely.
        if header.time <= self.trusted.time {
            return Err(LightError::NonMonotonicTime {
                got: header.time.0,
                trusted: self.trusted.time.0,
            });
        }
        // Forwards: a header dated far ahead parks the deadline in the future,
        // so a client keeps trusting a chain that stopped long ago.
        if header.time.0 > now.0.saturating_add(MAX_CLOCK_DRIFT_MS) {
            return Err(LightError::FromTheFuture {
                got: header.time.0,
                now: now.0,
                drift_ms: MAX_CLOCK_DRIFT_MS,
            });
        }
        Ok(())
    }

    /// The commit must finalise *this* header, and the supplied sets must be
    /// the ones the header commits to.
    ///
    /// The second half is the check that closes the substitution hole: without
    /// it a caller supplies both a header and the set that validates it, which
    /// validates nothing.
    fn check_commit_and_sets(
        &self,
        header: &BlockHeader,
        commit: &Commit,
        validators: &ValidatorSet,
        next_validators: &ValidatorSet,
    ) -> Result<(), LightError> {
        if commit.block_id != header.id() || commit.height != header.height {
            return Err(LightError::HeaderMismatch);
        }
        if validators.hash() != header.validators_hash
            || next_validators.hash() != header.next_validators_hash
        {
            return Err(LightError::ValidatorSetMismatch);
        }
        Ok(())
    }

    /// Refuse to verify anything once the trusted header is too old.
    fn check_freshness(&self, now: Timestamp) -> Result<(), LightError> {
        let age = now.0.saturating_sub(self.trusted.time.0);
        if age > self.trusting_period_ms {
            return Err(LightError::TrustExpired {
                age_ms: age,
                period_ms: self.trusting_period_ms,
            });
        }
        Ok(())
    }

    fn adopt(
        &mut self,
        header: BlockHeader,
        validators: ValidatorSet,
        next_validators: ValidatorSet,
    ) {
        self.trusted = header;
        self.validators = validators;
        self.next_validators = next_validators;
    }

    /// Verify a value the server claims is at `key`, against the trusted root.
    ///
    /// # Errors
    /// Returns [`LightError::BadProof`] if the proof does not reconstruct the
    /// trusted `app_hash`.
    pub fn verify_value(
        &self,
        key: &StoreKey,
        value: Option<&[u8]>,
        proof: &Proof,
    ) -> Result<(), LightError> {
        if proof.verify(self.app_hash(), key.as_bytes(), value) {
            Ok(())
        } else {
            Err(LightError::BadProof)
        }
    }

    /// Verify a balance a server reported.
    ///
    /// Returns the verified balance, which is [`Amount::ZERO`] when the proof
    /// shows the key is absent — an unfunded account and a zero balance are the
    /// same thing, and both are *proved*, not assumed.
    ///
    /// # Errors
    /// Returns [`LightError::BadProof`] or [`LightError::MalformedValue`].
    pub fn verify_balance(
        &self,
        address: &Address,
        denom: &Denom,
        claimed: Option<&[u8]>,
        proof: &Proof,
    ) -> Result<Amount, LightError> {
        let key = StoreKey::balance(address, denom);
        self.verify_value(&key, claimed, proof)?;
        match claimed {
            None => Ok(Amount::ZERO),
            Some(bytes) => decode_exact::<Amount>(bytes).map_err(|_| LightError::MalformedValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_bank::{Bank, Issuer};
    use afrolink_consensus::{CountryCode, Validator, Vote, VoteType};
    use afrolink_crypto::SecretKey;
    use afrolink_executor::{Allocation, Block, Executor, Genesis, GenesisLimits, ValidatorSets};
    use afrolink_primitives::codec::Encode;
    use afrolink_primitives::{Round, Timestamp};
    use afrolink_state::{KeyValueStore, MemoryStore};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    /// A wall-clock reading well inside the trusting period for these fixtures.
    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_100_000)
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid")
    }

    fn validators() -> ValidatorSet {
        ValidatorSet::new(
            (1..=4u8)
                .map(|i| {
                    Validator::new(
                        key(i).public_key(),
                        1,
                        CountryCode::new("ke").expect("valid"),
                    )
                })
                .collect(),
        )
        .expect("valid set")
    }

    /// Genesis with one funded account, and the resulting state.
    fn genesis_chain() -> (MemoryStore, Block) {
        let genesis = Genesis {
            chain_id: chain(),
            genesis_time: Timestamp::from_millis(1_700_000_000_000),
            validators: validators(),
            issuers: vec![(kes(), Issuer::new(addr(100)))],
            attestors: Vec::new(),
            allocations: vec![Allocation {
                address: addr(50),
                denom: kes(),
                amount: Amount::from_afri(1_000),
            }],
        };
        let mut store = MemoryStore::new();
        let block = genesis
            .apply(&mut store, GenesisLimits::devnet())
            .expect("applies");
        (store, block)
    }

    /// Produce the next block over `store` and a commit signed by `seeds`.
    fn next_block(store: &mut MemoryStore, parent: &Block, seeds: &[u8]) -> (Block, Commit) {
        let executor = Executor::new(chain());
        let (block, _) = executor.build_block(
            store,
            parent.header.height.next(),
            // Time advances with height, as it does on a real chain: header
            // times are strictly monotonic and the client relies on it.
            Timestamp::from_millis(1_700_000_000_000 + parent.header.height.next().0 * 1_000),
            parent.header.id(),
            Vec::new(),
            ValidatorSets::unchanged(&validators()),
        );
        let block_id = block.header.id();
        let signatures = seeds
            .iter()
            .map(|s| {
                Vote {
                    chain_id: chain(),
                    height: block.header.height,
                    round: Round::ZERO,
                    vote_type: VoteType::Precommit,
                    block_id: Some(block_id),
                    validator: addr(*s),
                }
                .sign(&key(*s))
            })
            .collect();
        let commit = Commit::new(block.header.height, Round::ZERO, block_id, signatures);
        (block, commit)
    }

    #[test]
    fn a_wallet_verifies_a_balance_from_a_header_it_holds() {
        // The headline claim: a phone holding 32 bytes checks its money.
        let (store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header);

        // An untrusted server answers a balance query with a proof.
        let key = StoreKey::balance(&addr(50), &kes());
        let (value, proof) = store.get_with_proof(&key);

        let balance = client
            .verify_balance(&addr(50), &kes(), value.as_deref(), &proof)
            .expect("proof must verify");
        assert_eq!(balance, Amount::from_afri(1_000));
    }

    #[test]
    fn a_lying_server_cannot_inflate_a_balance() {
        let (store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header);

        let key = StoreKey::balance(&addr(50), &kes());
        let (_, proof) = store.get_with_proof(&key);

        // The server keeps the real proof but reports a bigger number.
        let lie = Amount::from_afri(999_999).to_bytes();
        assert_eq!(
            client.verify_balance(&addr(50), &kes(), Some(&lie), &proof),
            Err(LightError::BadProof)
        );
    }

    #[test]
    fn a_lying_server_cannot_deny_a_funded_account() {
        // Lying by omission: claiming the account does not exist.
        let (store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header);

        let key = StoreKey::balance(&addr(50), &kes());
        let (_, proof) = store.get_with_proof(&key);

        assert_eq!(
            client.verify_balance(&addr(50), &kes(), None, &proof),
            Err(LightError::BadProof)
        );
    }

    #[test]
    fn an_absent_balance_is_proved_not_assumed() {
        let (store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header);

        let stranger = addr(77);
        let key = StoreKey::balance(&stranger, &kes());
        let (value, proof) = store.get_with_proof(&key);
        assert!(value.is_none());

        let balance = client
            .verify_balance(&stranger, &kes(), None, &proof)
            .expect("absence must be provable");
        assert_eq!(balance, Amount::ZERO);
    }

    #[test]
    fn a_quorum_backed_header_is_adopted() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, commit) = next_block(&mut store, &genesis, &[1, 2, 3]);

        client
            .update(
                block.header.clone(),
                &commit,
                validators(),
                validators(),
                now(),
            )
            .expect("valid commit");
        assert_eq!(client.height(), Height(1));
        assert_eq!(client.app_hash(), block.header.app_hash);
    }

    #[test]
    fn a_header_without_a_quorum_is_refused_and_the_client_does_not_move() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, commit) = next_block(&mut store, &genesis, &[1, 2]); // 2 of 4

        assert!(
            client
                .update(block.header, &commit, validators(), validators(), now())
                .is_err()
        );
        assert_eq!(
            client.trusted_header(),
            &genesis.header,
            "a rejected update must leave the trusted header untouched"
        );
    }

    #[test]
    fn a_commit_for_a_different_block_does_not_certify_this_header() {
        // A server pairing a real header with a real commit for another block.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, mut commit) = next_block(&mut store, &genesis, &[1, 2, 3]);
        commit.block_id = Hash32::ZERO;

        assert_eq!(
            client.update(block.header, &commit, validators(), validators(), now()),
            Err(LightError::HeaderMismatch)
        );
    }

    #[test]
    fn a_header_that_skips_a_height_is_refused() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (mut block, commit) = next_block(&mut store, &genesis, &[1, 2, 3]);
        block.header.height = Height(5);

        assert!(matches!(
            client.update(block.header, &commit, validators(), validators(), now()),
            Err(LightError::NonSequential { .. })
        ));
    }

    #[test]
    fn a_header_not_descending_from_the_trusted_block_is_refused() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (mut block, commit) = next_block(&mut store, &genesis, &[1, 2, 3]);
        block.header.parent = Hash32::ZERO;

        assert_eq!(
            client.update(block.header, &commit, validators(), validators(), now()),
            Err(LightError::BrokenChain)
        );
    }

    #[test]
    fn a_header_from_another_chain_is_refused() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (mut block, commit) = next_block(&mut store, &genesis, &[1, 2, 3]);
        block.header.chain_id = ChainId::new("afrolink-testnet-3").expect("valid");

        assert!(matches!(
            client.update(block.header, &commit, validators(), validators(), now()),
            Err(LightError::WrongChain { .. })
        ));
    }

    #[test]
    fn following_the_chain_keeps_balances_verifiable() {
        // A wallet tracks heights and keeps checking its money as state moves.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());

        let mut parent = genesis;
        for _ in 0..3 {
            let (block, commit) = next_block(&mut store, &parent, &[1, 2, 3, 4]);
            client
                .update(
                    block.header.clone(),
                    &commit,
                    validators(),
                    validators(),
                    now(),
                )
                .expect("valid");
            parent = block;
        }
        assert_eq!(client.height(), Height(3));

        // Move money, then verify against the newest trusted header.
        {
            let mut bank = Bank::new(&mut store);
            bank.transfer(&addr(50), &addr(51), &kes(), Amount::from_afri(400))
                .expect("transfers");
        }
        let (block, commit) = next_block(&mut store, &parent, &[1, 2, 3, 4]);
        client
            .update(block.header, &commit, validators(), validators(), now())
            .expect("valid");

        let key = StoreKey::balance(&addr(51), &kes());
        let (value, proof) = store.get_with_proof(&key);
        let balance = client
            .verify_balance(&addr(51), &kes(), value.as_deref(), &proof)
            .expect("proof verifies against the latest header");
        assert_eq!(balance, Amount::from_afri(400));
    }

    #[test]
    fn a_proof_against_a_stale_header_does_not_verify() {
        // A server replaying an old proof after state has moved on.
        let (mut store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header.clone());

        let key = StoreKey::balance(&addr(50), &kes());
        let (old_value, old_proof) = store.get_with_proof(&key);

        {
            let mut bank = Bank::new(&mut store);
            bank.transfer(&addr(50), &addr(51), &kes(), Amount::from_afri(100))
                .expect("transfers");
        }

        // The old proof still matches the old root the client trusts.
        assert!(
            client
                .verify_balance(&addr(50), &kes(), old_value.as_deref(), &old_proof)
                .is_ok()
        );

        // But the *new* value does not verify against that stale header, so a
        // wallet that has not updated cannot be shown post-transfer state.
        let (new_value, _) = store.get_with_proof(&key);
        assert_eq!(
            client.verify_balance(&addr(50), &kes(), new_value.as_deref(), &old_proof),
            Err(LightError::BadProof)
        );
    }

    // -- Long-range attack defence (ADR-0010) --------------------------------

    #[test]
    fn a_client_outside_the_trusting_period_refuses_to_verify() {
        // The headline defence. Past the trusting period the old validator set
        // may have unbonded, so a forged history is no longer punishable and
        // the client cannot tell it from the real one. It must say so rather
        // than accept a chain it cannot judge.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, commit) = next_block(&mut store, &genesis, &[1, 2, 3, 4]);

        let stale = Timestamp::from_millis(genesis.header.time.0 + TRUSTING_PERIOD_MS + 1);

        let err = client
            .update(block.header, &commit, validators(), validators(), stale)
            .expect_err("a stale client must refuse");

        assert!(
            matches!(err, LightError::TrustExpired { .. }),
            "got {err:?}"
        );
        assert_eq!(
            client.height(),
            Height::GENESIS,
            "and must not move on failure"
        );
    }

    #[test]
    fn freshness_is_reported_before_a_balance_is_shown() {
        // A wallet must be able to ask "is my trust still good?" without
        // attempting an update, because a stale trusted header makes every
        // proof against it meaningless however well-formed.
        let (_store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header.clone());

        let fresh = Timestamp::from_millis(genesis.header.time.0 + 1_000);
        let stale = Timestamp::from_millis(genesis.header.time.0 + TRUSTING_PERIOD_MS + 1);

        assert!(client.is_trusted_at(fresh));
        assert!(!client.is_trusted_at(stale));
    }

    #[test]
    fn the_trusting_period_sits_inside_the_unbonding_period() {
        // The ordering itself is asserted at compile time above; this pins the
        // ratio, so a future tuning change is a deliberate edit here rather
        // than a silent one.
        assert_eq!(TRUSTING_PERIOD_MS, UNBONDING_MS / 3 * 2);
        assert_eq!(UNBONDING_MS, 21 * 24 * 60 * 60 * 1_000, "21 days");
    }

    #[test]
    fn a_substituted_validator_set_is_rejected() {
        // The attack this closes: a server hands a wallet a header together
        // with a validator set of the attacker's choosing. The signatures would
        // verify perfectly against that set. The header's commitment is what
        // makes the substitution detectable.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, commit) = next_block(&mut store, &genesis, &[1, 2, 3, 4]);

        let attacker_set = ValidatorSet::new(vec![Validator::new(
            key(66).public_key(),
            1,
            CountryCode::new("ke").expect("valid"),
        )])
        .expect("valid set");

        assert_eq!(
            client.update(
                block.header,
                &commit,
                attacker_set.clone(),
                attacker_set,
                now()
            ),
            Err(LightError::ValidatorSetMismatch)
        );
    }

    #[test]
    fn a_checkpoint_with_a_mismatched_set_is_refused_at_construction() {
        // A bad checkpoint must fail immediately rather than poisoning every
        // later verification.
        let (_store, genesis) = genesis_chain();
        let wrong = ValidatorSet::new(vec![Validator::new(
            key(66).public_key(),
            1,
            CountryCode::new("ke").expect("valid"),
        )])
        .expect("valid set");

        assert_eq!(
            LightClient::from_checkpoint(chain(), genesis.header.clone(), wrong.clone(), wrong)
                .err(),
            Some(LightError::ValidatorSetMismatch)
        );

        // The honest checkpoint is accepted.
        let client = LightClient::from_checkpoint(
            chain(),
            genesis.header.clone(),
            validators(),
            validators(),
        )
        .expect("a matching checkpoint is accepted");
        assert_eq!(client.height(), Height::GENESIS);
    }

    #[test]
    fn a_client_can_skip_many_heights_at_once() {
        // What makes syncing a phone practical: at one-second blocks a
        // month-old checkpoint is ~2.6 million headers. Skipping needs a
        // handful.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());

        let mut parent = genesis;
        let mut latest = None;
        for _ in 0..8 {
            let (block, commit) = next_block(&mut store, &parent, &[1, 2, 3, 4]);
            parent = block.clone();
            latest = Some((block, commit));
        }
        let (block, commit) = latest.expect("blocks were produced");
        let target = block.header.height;

        client
            .verify_skipping(block.header, &commit, validators(), validators(), now())
            .expect("full overlap must allow the skip");

        assert_eq!(
            client.height(),
            target,
            "jumped without the headers between"
        );
    }

    #[test]
    fn skipping_needs_more_than_a_third_of_the_trusted_set() {
        // The safety argument: above one third, at least one *correct*
        // validator signed, because Byzantine power is bounded by one third.
        // One correct signer is enough, since a correct validator will not sign
        // on a forked chain.
        //
        // Here the trusted set has four equal validators, so a single signer is
        // 25% — below the bar — while the new set still reaches its own quorum.
        let (mut store, genesis) = genesis_chain();

        // A disjoint set takes over, and only one original validator overlaps.
        let successor = ValidatorSet::new(vec![
            Validator::new(
                key(1).public_key(),
                1,
                CountryCode::new("ke").expect("valid"),
            ),
            Validator::new(
                key(70).public_key(),
                1,
                CountryCode::new("ng").expect("valid"),
            ),
            Validator::new(
                key(71).public_key(),
                1,
                CountryCode::new("za").expect("valid"),
            ),
            Validator::new(
                key(72).public_key(),
                1,
                CountryCode::new("gh").expect("valid"),
            ),
        ])
        .expect("valid set");

        let executor = Executor::new(chain());
        let (block, _) = executor.build_block(
            &mut store,
            Height(5),
            Timestamp::from_millis(1_700_000_005_000),
            genesis.header.id(),
            Vec::new(),
            ValidatorSets {
                current: &successor,
                next: &successor,
            },
        );
        let block_id = block.header.id();
        let signatures = [1u8, 70, 71, 72]
            .iter()
            .map(|s| {
                Vote {
                    chain_id: chain(),
                    height: block.header.height,
                    round: Round::ZERO,
                    vote_type: VoteType::Precommit,
                    block_id: Some(block_id),
                    validator: Address::from_public_key(&key(*s).public_key()),
                }
                .sign(&key(*s))
            })
            .collect();
        let commit = Commit::new(block.header.height, Round::ZERO, block_id, signatures);

        let mut client = LightClient::new(chain(), validators(), genesis.header);
        let err = client
            .verify_skipping(block.header, &commit, successor.clone(), successor, now())
            .expect_err("25% overlap is not enough to skip");

        assert!(
            matches!(err, LightError::InsufficientOverlap { .. }),
            "got {err:?}"
        );
        assert_eq!(client.height(), Height::GENESIS, "and the client stays put");
    }

    #[test]
    fn thirty_two_bytes_are_enough_to_bootstrap() {
        // The QR-code path. Only `block_id` need be obtained honestly; the
        // header and both validator sets can come from anyone, because the
        // block identifier commits to all of them.
        let (mut store, genesis) = genesis_chain();
        let (block, _) = next_block(&mut store, &genesis, &[1, 2, 3, 4]);
        let block_id = block.header.id();

        let client = LightClient::from_block_id(
            chain(),
            block_id,
            block.header.clone(),
            validators(),
            validators(),
        )
        .expect("the header matches the identifier");
        assert_eq!(client.height(), block.header.height);
    }

    #[test]
    fn a_substituted_header_does_not_match_the_scanned_identifier() {
        // A hostile server hands over a different block than the checkpoint
        // names, with sets that are internally consistent with it.
        let (mut store, genesis) = genesis_chain();
        let (block, _) = next_block(&mut store, &genesis, &[1, 2, 3, 4]);

        assert_eq!(
            LightClient::from_block_id(
                chain(),
                genesis.header.id(),
                block.header,
                validators(),
                validators(),
            )
            .err(),
            Some(LightError::WrongBlock)
        );
    }

    #[test]
    fn a_checkpoint_for_another_network_is_refused() {
        let (_, genesis) = genesis_chain();
        let other = ChainId::new("afrolink-testnet").expect("valid");
        assert!(matches!(
            LightClient::from_block_id(
                other,
                genesis.header.id(),
                genesis.header.clone(),
                validators(),
                validators(),
            ),
            Err(LightError::WrongChain { .. })
        ));
    }

    #[test]
    fn a_header_dated_in_the_future_is_refused() {
        // The mirror of the rewind attack, and the more dangerous one: a header
        // dated next year parks the trusting-period deadline in the future, so
        // a client keeps trusting a chain that stopped months ago.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (mut block, commit) = next_block(&mut store, &genesis, &[1, 2, 3, 4]);

        block.header.time = Timestamp::from_millis(now().0 + MAX_CLOCK_DRIFT_MS + 1);

        let err = client
            .update(block.header, &commit, validators(), validators(), now())
            .expect_err("a header from the future must be refused");
        assert!(
            matches!(err, LightError::FromTheFuture { .. }),
            "got {err:?}"
        );
        assert_eq!(
            client.trusted_header(),
            &genesis.header,
            "and the client stays put"
        );
    }

    #[test]
    fn ordinary_clock_skew_is_tolerated() {
        // The bound must not reject honest handsets whose clocks run fast.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, commit) = next_block(&mut store, &genesis, &[1, 2, 3, 4]);

        // A phone whose clock lags a second behind the header it is offered.
        let lagging = Timestamp::from_millis(block.header.time.0 - 1_000);
        assert!(
            client
                .update(block.header, &commit, validators(), validators(), lagging)
                .is_ok()
        );
    }

    #[test]
    fn a_header_that_rewinds_time_is_refused() {
        // Otherwise an attacker replays an old-timestamped header to reset the
        // trusting-period clock and keep a stale client alive forever.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (mut block, commit) = next_block(&mut store, &genesis, &[1, 2, 3, 4]);

        block.header.time = Timestamp::from_millis(genesis.header.time.0 - 1);

        let err = client
            .update(block.header, &commit, validators(), validators(), now())
            .expect_err("time must move forward");
        assert!(
            matches!(err, LightError::NonMonotonicTime { .. }),
            "got {err:?}"
        );
    }
}
