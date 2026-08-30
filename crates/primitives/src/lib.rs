//! Core primitives shared by every AfroLink crate.
//!
//! Everything in here is **consensus-critical**: two nodes that disagree about
//! how an [`Amount`] is encoded will fork the chain. The rules are therefore
//! deliberately boring and explicit:
//!
//! * Integers are fixed-width little-endian. No varints, no float, ever.
//! * Variable-length data carries a `u32` length prefix.
//! * There is exactly one valid encoding of any value ([`codec`]).
//! * All arithmetic on balances is checked ([`Amount`]).

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

pub mod amount;
pub mod codec;
pub mod denom;
pub mod error;
pub mod ids;

pub use amount::Amount;
pub use codec::{CodecError, Decode, Encode, Reader};
pub use denom::Denom;
pub use error::{Error, Result};
pub use ids::{ChainId, Height, Round, Timestamp};

/// How long stake stays slashable after a validator begins exiting.
///
/// 21 days, matching the Cosmos Hub. The number is not arbitrary: it must exceed
/// the time it takes humans to notice an attack, agree it happened, and act —
/// because after it elapses the offender's stake is beyond reach and forging old
/// history becomes free.
///
/// # Why this lives here rather than in `light` or `staking`
///
/// Both need it and they must never disagree. `crates/light` derives its
/// trusting period from this number, and `crates/staking` locks real money for
/// it; a chain whose unbonding period is shorter than its clients believe is a
/// chain whose clients can be shown forged history. Defining it in either crate
/// meant the other importing it, and `staking -> light -> executor -> staking`
/// is a dependency cycle. A shared protocol constant belongs at the bottom.
///
/// See [ADR-0010](../../../docs/adr/0010-long-range-attacks.md).
pub const UNBONDING_MS: u64 = 21 * 24 * 60 * 60 * 1_000;
