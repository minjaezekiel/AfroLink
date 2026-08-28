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
