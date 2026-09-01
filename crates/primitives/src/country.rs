//! ISO 3166-1 alpha-2 country codes.
//!
//! A primitive rather than a consensus type, because two unrelated parts of the
//! chain need to name a jurisdiction and neither should be re-deriving the rule.
//! Validators carry one so the geographic distribution requirement in
//! [ADR-0002](../../../docs/adr/0002-consensus.md) can be enforced by the
//! protocol rather than hoped for; attestors carry one to say which regulator
//! licensed them ([ADR-0007](../../../docs/adr/0007-distribution-and-sybil-resistance.md)).
//!
//! It lived in `crates/consensus` while validators were the only user. When the
//! attestor registry needed one it stored a bare `[u8; 2]` instead — so `"ke"`,
//! `"KE"` and two arbitrary bytes were all accepted, in a record hashed into the
//! state root. One rule in one place is the fix; a second copy of the rule is
//! how two spellings of a value drift apart.

use crate::codec::{CodecError, Decode, Encode, Reader};
use crate::error::{Error, Result};

/// An ISO 3166-1 alpha-2 country code, lowercase.
///
/// Exactly two lowercase ASCII letters, checked on construction **and** on
/// decode. Lowercase is chosen rather than accepted: a code that could be
/// written two ways is a value with two encodings, and this one is hashed into
/// the state root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Validate and wrap a two-letter code.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] unless the input is exactly two lowercase
    /// ASCII letters. Uppercase is refused rather than folded, for the same
    /// reason the codec refuses rather than normalises everywhere else.
    pub fn new(s: &str) -> Result<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_lowercase) {
            return Err(Error::Invalid {
                what: "CountryCode",
            });
        }
        let mut out = [0u8; 2];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The code as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("??")
    }
}

impl core::fmt::Display for CountryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Encode for CountryCode {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for CountryCode {
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        let bytes = r.take_array::<2>()?;
        if !bytes.iter().all(u8::is_ascii_lowercase) {
            return Err(CodecError::Invalid(
                "country code must be two lowercase ASCII letters".to_owned(),
            ));
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::decode_exact;

    #[test]
    fn only_two_lowercase_letters_are_a_country() {
        assert!(CountryCode::new("ke").is_ok());
        for bad in ["KE", "Ke", "k", "ken", "", "k1", "k ", "ké"] {
            assert!(CountryCode::new(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_code_that_could_be_written_two_ways_is_refused_on_decode() {
        // The defect this type was moved here to close: a bare `[u8; 2]` in a
        // state-root-hashed record accepted "KE", "ke" and arbitrary bytes as
        // three spellings of one jurisdiction.
        assert!(decode_exact::<CountryCode>(b"ke").is_ok());
        for bad in [b"KE", b"Ke", b"k1", b"\x00\x00"] {
            assert!(
                decode_exact::<CountryCode>(bad).is_err(),
                "{bad:?} must not decode"
            );
        }
    }

    #[test]
    fn country_codes_round_trip() {
        let ke = CountryCode::new("ke").expect("valid");
        assert_eq!(decode_exact::<CountryCode>(&ke.to_bytes()), Ok(ke));
        assert_eq!(ke.to_string(), "ke");
    }
}
