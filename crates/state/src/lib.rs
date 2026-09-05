//! Authenticated state for AfroLink.
//!
//! The whole ledger lives in one compact sparse Merkle tree ([`smt`]) whose root
//! — 32 bytes — is committed in every block header. That single design choice is
//! what makes the mobile story work:
//!
//! * A phone syncs block *headers* only (a few hundred bytes each), not blocks.
//! * To check "did I receive the money?", it asks any untrusted server for the
//!   balance plus a Merkle proof, and verifies the proof against the header it
//!   already has. A lying server is caught immediately.
//! * The same machinery proves a **negative** — "this account does not exist",
//!   "this stablecoin was never issued" — which is what lets a light client
//!   detect an omitted result rather than only a forged one.
//!
//! A full node needs gigabytes. A wallet on a $40 handset needs kilobytes.

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

pub mod nodes;
pub mod smt;
pub mod store;

pub use nodes::{MemoryNodes, Node, NodeSink, NodeSource, WriteStats, commit_tree, load_tree};
pub use smt::{NodeKind, NodeRef, Proof, ProofLeaf, SparseMerkleTree};
pub use store::{KeyValueStore, MemoryStore, StateError, StoreKey};
