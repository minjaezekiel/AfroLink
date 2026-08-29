//! Witness logs: how a wallet gets a starting point it can **check** rather
//! than one it is simply **told**.
//!
//! # The problem this exists for
//!
//! [ADR-0010](../../../docs/adr/0010-long-range-attacks.md) closed the
//! long-range attack for a client that is already up to date. It could not close
//! it for a client that is not, and said so: a wallet offline for more than the
//! trusting period needs a fresh checkpoint from somewhere, and "somewhere" was
//! a person reading a hash off a website.
//!
//! Note what does *not* solve this, because it is the usual suggestion.
//! Finality, two-thirds quorums, "never revert a finalised block", slashing,
//! signed checkpoints — every one of them protects a node **that was online when
//! finality happened**. The long-range victim is by definition the node that was
//! not. A forged history carries a perfect quorum at every height, so a syncing
//! client applying those rules accepts it happily. The gap is not the acceptance
//! rule; it is the starting point the rule is applied from.
//!
//! # What is here
//!
//! An append-only [`WitnessLog`], operated by the licensed attestors
//! [ADR-0007](../../../docs/adr/0007-distribution-and-sybil-resistance.md)
//! already commits to — mobile operators, banks, national identity authorities.
//! Each records what it saw, publishes a [`SignedTreeHead`], and can be made to
//! prove two things:
//!
//! * **Inclusion** — this observation is in that tree.
//! * **Consistency** — the tree you showed me last time is still a prefix of
//!   this one.
//!
//! The second is the load-bearing one. A wallet keeps forty bytes — a log size
//! and a root — and on returning, months later, demands a proof that nothing it
//! previously saw has been altered. A witness that rewrote history cannot
//! produce one, because there is no sequence of hashes reconciling the two
//! roots. This does not weaken with time: a proof spanning six months is exactly
//! as conclusive as one spanning an hour.
//!
//! For a wallet with nothing remembered at all, [`corroborate`] requires several
//! witnesses in several jurisdictions to say the same thing, and refuses
//! outright if any two of them disagree.
//!
//! # Why this has teeth here and not elsewhere
//!
//! Transparency logs are not new; Certificate Transparency has run this design
//! for a decade. What makes it *enforceable* is that misbehaviour must cost the
//! operator something. Google can enforce CT because it can distrust a
//! certificate authority. Most chains have no equivalent — their checkpoint
//! providers can only be argued with.
//!
//! AfroLink does, and by accident of a decision made for another reason
//! entirely: the attestor layer built for [ADR-0008](../../../docs/adr/0008-human-readable-addressing.md)
//! consists of licensed entities with legal identities and banking permissions.
//! An [`Equivocation`] is a compact proof, checkable offline by anyone, that one
//! of them published two conflicting histories. The consequence is a licence,
//! not a slashed bond.
//!
//! # The hard limit, stated plainly
//!
//! **Witnesses observe. They never cause.** Nothing in this crate can halt the
//! chain, reorganise it, censor a transaction, or admit a block. A lying witness
//! is caught with a proof; a vanished witness simply stops counting toward
//! [`Policy`] and the wallet refuses rather than being misled. If any future
//! change lets a witness *do* something rather than *observe* something, this
//! design has become a federation and has failed.
//!
//! Corroboration across jurisdictions is a defence against collusion, not a
//! guarantee against it. Enough colluding witnesses defeat this layer — which is
//! why [ADR-0011](../../../docs/adr/0011-objective-anchors.md) pairs it with an
//! external anchor whose failure mode is unrelated.
//!
//! # Not built here
//!
//! No networking. A witness log is a data structure and a set of proofs; how
//! heads are fetched is the transport layer's problem, as it is for
//! `crates/rpc`.

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

pub mod audit;
pub mod head;
pub mod log;
pub mod policy;

pub use audit::{Observation, Remembered, Witness, WitnessSet};
pub use head::{Equivocation, LogId, SignedTreeHead, TreeHead};
pub use log::{LogEntry, WitnessLog};
pub use policy::{Checkpoint, MAX_CORROBORATION, Policy, corroborate};

use thiserror::Error;

/// Why a witness's claim was not accepted.
///
/// Note what is absent: there is no variant meaning "probably fine". Every
/// failure here leaves the wallet exactly where it was.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// The head was signed by a key this wallet does not know.
    #[error("the wallet does not know this witness")]
    UnknownWitness,
    /// A signature did not verify.
    #[error("witness signature did not verify")]
    BadSignature,
    /// A head's log identifier does not match the key or the log it claims.
    #[error("signed head does not belong to the log it names")]
    LogMismatch,
    /// The witness observes a different network.
    #[error("witness log is for chain {got}, expected {expected}")]
    WrongChain {
        /// Chain the witness named.
        got: String,
        /// Chain the wallet follows.
        expected: String,
    },
    /// An entry went backwards in height or in time.
    #[error("log entry at height {got} does not follow {last}")]
    NonMonotonic {
        /// Height offered.
        got: u64,
        /// Height already recorded.
        last: u64,
    },
    /// No entry at that index.
    #[error("no log entry at that index")]
    IndexOutOfRange,
    /// A proof was built against a different tree than the head commits to.
    #[error("proof covers a log of {got} entries, expected {expected}")]
    SizeMismatch {
        /// Size the proof covers.
        got: u64,
        /// Size expected.
        expected: u64,
    },
    /// An inclusion proof did not reconstruct the head's root.
    #[error("inclusion proof does not verify against the signed root")]
    BadInclusionProof,
    /// A consistency proof did not reconcile the two roots.
    ///
    /// **The witness rewrote or dropped history the wallet had already seen.**
    /// Not transient, and not worth retrying against the same witness.
    #[error("consistency proof does not verify: the log no longer contains what the wallet saw")]
    BadConsistencyProof,
    /// Two witnesses reported different blocks at one height.
    ///
    /// The wallet must not pick a side. Either a witness is lying or the chain
    /// has done something it should be impossible for it to do, and both call
    /// for a human.
    #[error("witnesses disagree about height {height}; refusing to choose between them")]
    SplitView {
        /// The disputed height.
        height: u64,
    },
    /// Not enough independent agreement to adopt a checkpoint.
    #[error(
        "only {witnesses} witness(es) across {countries} jurisdiction(s) agreed; \
         need {need_witnesses} across {need_countries}"
    )]
    NotCorroborated {
        /// Best agreement reached, by witness count.
        witnesses: usize,
        /// Best agreement reached, by jurisdiction count.
        countries: usize,
        /// Witnesses the policy required.
        need_witnesses: usize,
        /// Jurisdictions the policy required.
        need_countries: usize,
    },
    /// A wallet was built with no witnesses.
    #[error("a witness set must contain at least one witness")]
    EmptyWitnessSet,
    /// One operator was listed twice, which would let it corroborate itself.
    #[error("the same witness log appears twice in the set")]
    DuplicateWitness,
    /// The two heads offered as proof of equivocation are consistent.
    #[error("these heads are not evidence of equivocation")]
    NotEquivocation,
}
