//! Account addresses.
//!
//! An address is the first 20 bytes of a domain-separated hash of the public key,
//! rendered as bech32m with the `afri` prefix:
//!
//! ```text
//! afri1qzp8h4cthjxue7g0kk4dmz9nvvqhs6xk3nlq2m
//! ```
//!
//! 20 bytes (160 bits) gives 80-bit collision resistance, which is the same
//! trade-off Bitcoin and Cosmos make. It keeps addresses short enough to be read
//! aloud or entered on a feature phone, which is a hard requirement here.

use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

use crate::hash::{Domain, hash};
use crate::{CryptoError, PublicKey, Result};

/// Human-readable prefix for AfroLink account addresses.
pub const HRP: &str = "afri";

/// Length of the address payload in bytes.
pub const ADDRESS_LEN: usize = 20;

/// A 20-byte account address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// The zero address. Used as the burn sink and never as a signer.
    pub const ZERO: Self = Self([0u8; ADDRESS_LEN]);

    /// Derive the address of a public key.
    #[must_use]
    pub fn from_public_key(pk: &PublicKey) -> Self {
        let digest = hash(Domain::Address, &pk.to_bytes());
        let mut out = [0u8; ADDRESS_LEN];
        // Truncating a 256-bit hash to 160 bits is standard practice; the
        // remaining bytes carry no extra security for this purpose.
        out.copy_from_slice(
            digest
                .as_bytes()
                .get(..ADDRESS_LEN)
                .unwrap_or(&[0; ADDRESS_LEN]),
        );
        Self(out)
    }

    /// Derive an address deterministically from arbitrary seed bytes.
    ///
    /// Used for accounts that have no key: group accounts (derived from creator
    /// and nonce) and module accounts (derived from the module name). The domain
    /// keeps these disjoint from key-derived addresses, so a derived address can
    /// never collide with one somebody holds a key for.
    #[must_use]
    pub fn derived(domain: Domain, seed: &[u8]) -> Self {
        let digest = hash(domain, seed);
        let mut out = [0u8; ADDRESS_LEN];
        out.copy_from_slice(
            digest
                .as_bytes()
                .get(..ADDRESS_LEN)
                .unwrap_or(&[0; ADDRESS_LEN]),
        );
        Self(out)
    }

    /// Wrap raw address bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ADDRESS_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }

    /// Render as a bech32m string.
    ///
    /// # Errors
    /// Returns [`CryptoError::Bech32`] only if the encoder rejects the fixed
    /// prefix, which cannot happen for the compiled-in [`HRP`].
    pub fn to_bech32(&self) -> Result<String> {
        crate::bech32::encode(HRP, &self.0)
    }

    /// Parse a bech32m address string.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidAddress`] if the checksum fails, the prefix
    /// is wrong, or the payload is not exactly [`ADDRESS_LEN`] bytes.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, data) =
            crate::bech32::decode(s).map_err(|e| CryptoError::InvalidAddress(e.to_string()))?;
        if hrp != HRP {
            return Err(CryptoError::InvalidAddress(format!(
                "wrong prefix {hrp:?}, expected {HRP:?}"
            )));
        }
        let bytes: [u8; ADDRESS_LEN] = data.as_slice().try_into().map_err(|_| {
            CryptoError::InvalidAddress(format!(
                "payload is {} bytes, expected {ADDRESS_LEN}",
                data.len()
            ))
        })?;
        Ok(Self(bytes))
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.to_bech32() {
            Ok(s) => f.write_str(&s),
            // Unreachable with the compiled-in HRP, but Display must not panic.
            Err(_) => write!(f, "{HRP}!invalid:{}", hex::encode(self.0)),
        }
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self}")
    }
}

impl Encode for Address {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Address {
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        Ok(Self(r.take_array::<ADDRESS_LEN>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;

    #[test]
    fn addresses_round_trip_through_bech32() {
        let addr = Address::from_public_key(
            &SecretKey::generate()
                .expect("entropy available")
                .public_key(),
        );
        let s = addr.to_bech32().expect("encodes");
        assert!(s.starts_with("afri1"), "got {s}");
        assert_eq!(Address::from_bech32(&s).expect("decodes"), addr);
    }

    #[test]
    fn derivation_is_deterministic() {
        let sk = SecretKey::from_bytes(&[9u8; 32]);
        let pk = sk.public_key();
        assert_eq!(Address::from_public_key(&pk), Address::from_public_key(&pk));
    }

    #[test]
    fn distinct_keys_give_distinct_addresses() {
        let a = Address::from_public_key(&SecretKey::from_bytes(&[1u8; 32]).public_key());
        let b = Address::from_public_key(&SecretKey::from_bytes(&[2u8; 32]).public_key());
        assert_ne!(a, b);
    }

    #[test]
    fn a_typo_is_rejected_rather_than_sending_funds_astray() {
        let addr = Address::from_public_key(
            &SecretKey::generate()
                .expect("entropy available")
                .public_key(),
        );
        let s = addr.to_bech32().expect("encodes");
        let mut typo = s.clone();
        let i = s.len() - 3;
        let replacement = if s.as_bytes()[i] == b'q' { "p" } else { "q" };
        typo.replace_range(i..=i, replacement);
        assert!(
            Address::from_bech32(&typo).is_err(),
            "checksum must reject {typo}"
        );
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let payload = [3u8; ADDRESS_LEN];
        let foreign = crate::bech32::encode("cosmos", &payload).expect("encodes");
        assert!(Address::from_bech32(&foreign).is_err());
    }

    #[test]
    fn wrong_payload_length_is_rejected() {
        let short = crate::bech32::encode(HRP, &[1u8; 10]).expect("encodes");
        assert!(Address::from_bech32(&short).is_err());
    }
}
