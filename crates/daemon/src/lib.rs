//! `afrolinkd`, as a library.
//!
//! The binary is a thin argument parser over this. The split exists so the node
//! can be **assembled inside a test**: an integration test can start several real
//! nodes, on real sockets, with real stores, and drive real consensus between
//! them — which is the one thing neither the consensus simulator nor the peer
//! suite can do, and the thing that has caught the defects both of them missed.
//!
//! See [10-network-hardening.md](../../../docs/10-network-hardening.md) §15 for
//! why that harness is treated as load-bearing rather than as extra coverage.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
    )
)]

pub mod anchors;
pub mod chain;
pub mod config;
pub mod identity;
pub mod init;
pub mod run;
pub mod signing;
