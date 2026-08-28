//! Shared error type for primitive operations.

use thiserror::Error;

/// Convenience alias for fallible primitive operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can arise from the primitive types.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// A canonical-codec failure.
    #[error(transparent)]
    Codec(#[from] crate::codec::CodecError),

    /// A denomination string violated the naming rules.
    #[error("invalid denom {denom:?}: {reason}")]
    InvalidDenom {
        /// The rejected string.
        denom: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A chain identifier violated the naming rules.
    #[error("invalid chain id {id:?}: {reason}")]
    InvalidChainId {
        /// The rejected string.
        id: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A checked arithmetic operation would have wrapped.
    #[error("arithmetic overflow in {op}")]
    Overflow {
        /// The operation that overflowed.
        op: &'static str,
    },
}
