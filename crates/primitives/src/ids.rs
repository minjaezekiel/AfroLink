//! Chain, block and time identifiers.

use crate::codec::{CodecError, Decode, Encode, Reader};
use crate::error::{Error, Result};

/// A block height. Genesis is height 0.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Height(pub u64);

impl Height {
    /// The height of the genesis block.
    pub const GENESIS: Self = Self(0);

    /// The next height, saturating at `u64::MAX`.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl core::fmt::Display for Height {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A consensus round within a height. Rounds restart at 0 for each height.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Round(pub u32);

impl Round {
    /// The first round of a height.
    pub const ZERO: Self = Self(0);

    /// The next round, saturating at `u32::MAX`.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl core::fmt::Display for Round {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Milliseconds since the Unix epoch.
///
/// Block time is agreed by the validator set, not read from a local clock, so
/// this is a consensus value rather than a wall-clock reading.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Construct from milliseconds since the Unix epoch.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Whole seconds since the Unix epoch.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000
    }
}

/// A human-readable network identifier, e.g. `afrolink-1` or `afrolink-testnet-3`.
///
/// The chain id is mixed into every signature. Without it, a transaction signed
/// on testnet would be replayable on mainnet.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId(String);

impl ChainId {
    /// Longest permitted chain id.
    pub const MAX_LEN: usize = 50;

    /// Validate and wrap a chain id string.
    ///
    /// # Errors
    /// Returns [`Error::InvalidChainId`] if empty, too long, or containing
    /// characters outside `[a-z0-9-]`.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        let invalid = |reason| Error::InvalidChainId {
            id: s.clone(),
            reason,
        };
        if s.is_empty() {
            return Err(invalid("must not be empty"));
        }
        if s.len() > Self::MAX_LEN {
            return Err(invalid("longer than 50 bytes"));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(invalid("may only contain [a-z0-9-]"));
        }
        Ok(Self(s))
    }

    /// The underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ChainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

macro_rules! impl_newtype_codec {
    ($($outer:ty => $inner:ty),* $(,)?) => {$(
        impl Encode for $outer {
            fn encode(&self, out: &mut Vec<u8>) {
                self.0.encode(out);
            }
        }
        impl Decode for $outer {
            fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
                Ok(Self(<$inner>::decode(r)?))
            }
        }
    )*};
}

impl_newtype_codec!(Height => u64, Round => u32, Timestamp => u64);

impl Encode for ChainId {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for ChainId {
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        Self::new(String::decode(r)?).map_err(|e| CodecError::Invalid(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heights_and_rounds_advance() {
        assert_eq!(Height::GENESIS.next(), Height(1));
        assert_eq!(Round::ZERO.next(), Round(1));
    }

    #[test]
    fn height_saturates_rather_than_wrapping() {
        assert_eq!(Height(u64::MAX).next(), Height(u64::MAX));
    }

    #[test]
    fn chain_ids_are_validated() {
        assert!(ChainId::new("afrolink-1").is_ok());
        assert!(ChainId::new("AfroLink-1").is_err());
        assert!(ChainId::new("").is_err());
        assert!(ChainId::new("a".repeat(51)).is_err());
    }
}
