//! Ed25519 keys and signatures.

use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use ed25519_dalek::Signer as _;

use crate::hash::Domain;
use crate::{CryptoError, Result};

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(ed25519_dalek::Signature);

/// An Ed25519 secret key.
///
/// Deliberately does not implement `Debug`, `Display`, `Clone` or serialisation:
/// the only way to get the bytes out is [`SecretKey::to_bytes`], which is easy to
/// grep for in an audit.
pub struct SecretKey(ed25519_dalek::SigningKey);

impl SecretKey {
    /// Generate a fresh key from the operating system CSPRNG.
    ///
    /// Seeds from `getrandom` rather than `SigningKey::generate` so this crate
    /// is not pinned to whichever `rand_core` major version `ed25519-dalek`
    /// happens to depend on. An Ed25519 key *is* 32 uniform random bytes, so
    /// there is no cryptographic difference.
    ///
    /// # Errors
    /// Returns [`CryptoError::EntropyUnavailable`] if the OS entropy source
    /// fails. Callers must not fall back to a weaker source.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::EntropyUnavailable)?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    /// Reconstruct from 32 seed bytes.
    #[must_use]
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The 32 seed bytes. Handle with care.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Sign `message` within `domain`.
    ///
    /// The domain is folded into the signed bytes, so a signature produced for a
    /// transaction can never be presented as a signature over a consensus vote.
    #[must_use]
    pub fn sign(&self, domain: Domain, message: &[u8]) -> Signature {
        Signature(self.0.sign(crate::hash::hash(domain, message).as_bytes()))
    }
}

impl PublicKey {
    /// Parse from 32 compressed bytes.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidPublicKey`] if the bytes are not a valid
    /// compressed Edwards point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// The 32 compressed bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify `signature` over `message` within `domain`.
    ///
    /// Uses `verify_strict`, which rejects small-order and non-canonical public
    /// keys. Plain `verify` would accept signatures that some Ed25519 libraries
    /// reject — and a validator set that disagrees about whether a signature is
    /// valid is a chain split.
    ///
    /// # Errors
    /// Returns [`CryptoError::VerificationFailed`] if the signature does not
    /// verify under the strict rules.
    pub fn verify(&self, domain: Domain, message: &[u8], signature: &Signature) -> Result<()> {
        self.0
            .verify_strict(crate::hash::hash(domain, message).as_bytes(), &signature.0)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// Non-strict verification is intentionally not provided.
    ///
    /// Kept as documentation so nobody "helpfully" adds it later.
    #[doc(hidden)]
    pub fn verify_lenient_is_forbidden() {}
}

impl Signature {
    /// Parse from 64 bytes.
    ///
    /// # Errors
    /// Never fails for a 64-byte input; the check lives in verification.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        Ok(Self(ed25519_dalek::Signature::from_bytes(bytes)))
    }

    /// The 64 signature bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PublicKey({}…)",
            hex::encode(self.to_bytes()).get(..12).unwrap_or_default()
        )
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Signature({}…)",
            hex::encode(self.to_bytes()).get(..12).unwrap_or_default()
        )
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    /// Byte order on the compressed encoding. Gives validator sets a canonical
    /// ordering that every node computes identically.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl core::hash::Hash for PublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl Encode for PublicKey {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bytes());
    }
}

impl Decode for PublicKey {
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        let bytes = r.take_array::<32>()?;
        Self::from_bytes(&bytes).map_err(|e| CodecError::Invalid(e.to_string()))
    }
}

impl Encode for Signature {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bytes());
    }
}

impl Decode for Signature {
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        let bytes = r.take_array::<64>()?;
        Self::from_bytes(&bytes).map_err(|e| CodecError::Invalid(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_within_their_domain() {
        let sk = SecretKey::generate().expect("entropy available");
        let pk = sk.public_key();
        let sig = sk.sign(Domain::TxSignDoc, b"pay 100 ash");
        assert!(pk.verify(Domain::TxSignDoc, b"pay 100 ash", &sig).is_ok());
    }

    #[test]
    fn signatures_do_not_cross_domains() {
        // The core anti-replay property: a transaction signature must not be
        // presentable as a consensus vote signature.
        let sk = SecretKey::generate().expect("entropy available");
        let pk = sk.public_key();
        let sig = sk.sign(Domain::TxSignDoc, b"payload");
        assert!(pk.verify(Domain::VoteSignDoc, b"payload", &sig).is_err());
    }

    #[test]
    fn tampered_messages_fail() {
        let sk = SecretKey::generate().expect("entropy available");
        let sig = sk.sign(Domain::TxSignDoc, b"pay 100 ash");
        assert!(
            sk.public_key()
                .verify(Domain::TxSignDoc, b"pay 900 ash", &sig)
                .is_err()
        );
    }

    #[test]
    fn other_keys_cannot_verify() {
        let sk = SecretKey::generate().expect("entropy available");
        let other = SecretKey::generate().expect("entropy available");
        let sig = sk.sign(Domain::TxSignDoc, b"msg");
        assert!(
            other
                .public_key()
                .verify(Domain::TxSignDoc, b"msg", &sig)
                .is_err()
        );
    }

    #[test]
    fn keys_round_trip_through_codec() {
        let pk = SecretKey::generate()
            .expect("entropy available")
            .public_key();
        let bytes = pk.to_bytes();
        assert_eq!(PublicKey::from_bytes(&bytes).expect("valid key"), pk);
    }

    #[test]
    fn seed_determines_the_key() {
        let seed = [42u8; 32];
        assert_eq!(
            SecretKey::from_bytes(&seed).public_key(),
            SecretKey::from_bytes(&seed).public_key()
        );
    }
}
