//! Token denominations.
//!
//! A denom names an asset on the chain. AfroLink carries three families:
//!
//! | Form                | Example              | Issued by                        |
//! |---------------------|----------------------|----------------------------------|
//! | native              | `afri`               | protocol emission                |
//! | sovereign stablecoin| `sov/ke/kes`         | a licensed or central-bank issuer|
//! | contract asset      | `cw/<contract-addr>` | a smart contract                 |
//!
//! The namespaces are enforced here rather than by convention, so a contract can
//! never mint something that renders as a national currency in a wallet. That is
//! the single most important anti-fraud property in the whole asset model.

use crate::codec::{CodecError, Decode, Encode, Reader};
use crate::error::{Error, Result};

/// Longest permitted denom string.
pub const MAX_DENOM_LEN: usize = 128;
/// Shortest permitted denom string.
pub const MIN_DENOM_LEN: usize = 3;

/// Reserved prefix for state-issued (sovereign) stablecoins.
pub const SOVEREIGN_PREFIX: &str = "sov/";
/// Reserved prefix for assets minted by smart contracts.
pub const CONTRACT_PREFIX: &str = "cw/";

/// A validated token denomination.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Denom(String);

impl Denom {
    /// The native staking, gas and governance token.
    #[must_use]
    pub fn native() -> Self {
        Self("afri".to_owned())
    }

    /// Validate and wrap a denom string.
    ///
    /// Accepts lowercase ASCII alphanumerics plus `/`, `-`, `.`, and must begin
    /// with a letter. Uppercase is rejected outright rather than normalised:
    /// silently lowercasing would make `KES` and `kes` the same asset in one
    /// implementation and different assets in another.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDenom`] describing the first rule violated.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        let invalid = |reason| Error::InvalidDenom {
            denom: s.clone(),
            reason,
        };

        if s.len() < MIN_DENOM_LEN {
            return Err(invalid("shorter than 3 bytes"));
        }
        if s.len() > MAX_DENOM_LEN {
            return Err(invalid("longer than 128 bytes"));
        }
        if !s.starts_with(|c: char| c.is_ascii_lowercase()) {
            return Err(invalid("must start with a lowercase ASCII letter"));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '/' | '-' | '.'))
        {
            return Err(invalid("may only contain [a-z0-9/.-]"));
        }
        if s.contains("//") || s.ends_with('/') {
            return Err(invalid("malformed path segments"));
        }
        Ok(Self(s))
    }

    /// Build the denom for a sovereign stablecoin, e.g. `sov/ke/kes`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidDenom`] if the country code is not two lowercase
    /// ASCII letters or the resulting denom is otherwise invalid.
    pub fn sovereign(country_code: &str, unit: &str) -> Result<Self> {
        if country_code.len() != 2 || !country_code.chars().all(|c| c.is_ascii_lowercase()) {
            return Err(Error::InvalidDenom {
                denom: country_code.to_owned(),
                reason: "country code must be two lowercase ASCII letters (ISO 3166-1 alpha-2)",
            });
        }
        Self::new(format!("{SOVEREIGN_PREFIX}{country_code}/{unit}"))
    }

    /// The underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the native AFRI token.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.0 == "afri"
    }

    /// Whether this denom lives in the sovereign-issuer namespace.
    #[must_use]
    pub fn is_sovereign(&self) -> bool {
        self.0.starts_with(SOVEREIGN_PREFIX)
    }

    /// Whether this denom was minted by a smart contract.
    #[must_use]
    pub fn is_contract(&self) -> bool {
        self.0.starts_with(CONTRACT_PREFIX)
    }
}

impl core::fmt::Display for Denom {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Encode for Denom {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for Denom {
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        let s = String::decode(r)?;
        // Re-validate on the way in: a peer can put anything on the wire.
        Self::new(s).map_err(|e| CodecError::Invalid(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_denom_is_recognised() {
        assert!(Denom::native().is_native());
    }

    #[test]
    fn sovereign_denoms_are_namespaced() {
        let kes = Denom::sovereign("ke", "kes").expect("valid sovereign denom");
        assert_eq!(kes.as_str(), "sov/ke/kes");
        assert!(kes.is_sovereign());
        assert!(!kes.is_contract());
    }

    #[test]
    fn uppercase_is_rejected_not_normalised() {
        // Normalising would make `KES` and `kes` the same asset in one client
        // and different assets in another. Reject instead.
        assert!(Denom::new("KES").is_err());
    }

    #[test]
    fn bad_country_codes_are_rejected() {
        assert!(Denom::sovereign("KEN", "kes").is_err());
        assert!(Denom::sovereign("k", "kes").is_err());
    }

    #[test]
    fn malformed_paths_are_rejected() {
        assert!(Denom::new("sov//kes").is_err());
        assert!(Denom::new("sov/ke/").is_err());
        assert!(Denom::new("1ash").is_err());
        assert!(Denom::new("ab").is_err());
    }

    #[test]
    fn decoding_revalidates_untrusted_bytes() {
        // Hand-craft the wire form of an invalid denom and confirm the decoder
        // rejects it rather than admitting a bogus asset into state.
        let mut bytes = Vec::new();
        "KES".to_owned().encode(&mut bytes);
        assert!(crate::codec::decode_exact::<Denom>(&bytes).is_err());
    }
}
