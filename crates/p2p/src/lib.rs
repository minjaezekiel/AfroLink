//! Validator-to-validator networking.
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

pub mod addrbook;
pub mod handshake;
pub mod manager;
pub mod peer;
pub mod secret;
pub mod transport;
pub mod wire;
