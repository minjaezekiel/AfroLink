//! Cryptographic primitives for AfroLink.
//!
//! Choices and why:
//!
//! * **BLAKE3** for hashing. Faster than SHA-256 on the ARM cores that dominate
//!   African handsets and cheap validator hardware, with a 256-bit output.
//! * **Ed25519** for signatures. Small keys, fast verification, no parameter
//!   choices to get wrong, and hardware-wallet support everywhere.
//! * **Domain separation everywhere** ([`hash::Domain`]). Every hash and every
//!   signature is bound to a purpose string, so a byte string valid in one
//!   context can never be replayed in another.
//! * **Bech32m addresses**. Checksummed, case-insensitive, and unambiguous when
//!   read aloud or typed on a feature phone — which matters for a chain meant to
//!   be used over USSD.

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

pub mod address;
pub mod bech32;
pub mod hash;
pub mod keys;
pub mod merkle;

pub use address::Address;
pub use hash::{Domain, Hash32};
pub use keys::{PublicKey, SecretKey, Signature};
pub use merkle::{MerkleProof, MerkleTree};

use thiserror::Error;

/// Errors from cryptographic operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// A byte string was not a valid key.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// A byte string was not a valid secret key.
    #[error("invalid secret key")]
    InvalidSecretKey,
    /// A byte string was not a valid signature encoding.
    #[error("invalid signature encoding")]
    InvalidSignature,
    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,
    /// An address string could not be parsed.
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    /// A bech32 string was malformed.
    #[error("bech32: {0}")]
    Bech32(String),
    /// A Merkle proof did not reconstruct the expected root.
    #[error("merkle proof invalid: {0}")]
    InvalidProof(&'static str),
    /// The operating system entropy source failed.
    ///
    /// Never recoverable by retrying with a weaker source: a predictable key is
    /// worse than no key.
    #[error("operating system entropy source unavailable")]
    EntropyUnavailable,
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, CryptoError>;
