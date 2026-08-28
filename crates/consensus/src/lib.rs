//! Ubuntu-BFT — Tendermint-class Byzantine fault tolerant consensus.
//!
//! See [ADR-0002](../../../docs/adr/0002-consensus.md) for why this design and
//! not a faster or more novel one. The short version: a market trader handing
//! over goods cannot reason about reorg probability, so finality must be
//! deterministic and reached in a single round.
//!
//! The crate is deliberately split so the parts that carry the safety argument
//! are small enough to read in one sitting:
//!
//! * [`validator`] — voting power and the `> 2/3` quorum rule.
//! * [`vote`] — vote accounting, duplicate suppression and equivocation evidence.
//! * [`round`] — the round state machine and the locking rules.
//!
//! There is **no networking here**. This is a pure state machine over messages,
//! which is what makes Byzantine behaviour testable without a network: every
//! test in this crate is an adversary doing something specific.

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

pub mod commit;
pub mod round;
pub mod validator;
pub mod vote;

pub use commit::{Commit, CommitError};
pub use round::{Decision, RoundState, Step};
pub use validator::{CountryCode, Validator, ValidatorError, ValidatorSet};
pub use vote::{Equivocation, SignedVote, Vote, VoteError, VoteOutcome, VoteSet, VoteType};
