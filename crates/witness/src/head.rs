//! Log identifiers, signed tree heads, and the proof that a witness lied.

use afrolink_crypto::hash::{Domain, Hash32, hash};
use afrolink_crypto::{PublicKey, SecretKey, Signature};
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{ChainId, Timestamp};

use crate::WitnessError;

/// A witness log's identifier, derived from its public key.
///
/// Deriving rather than assigning means a log cannot be impersonated: claiming
/// an identifier requires holding the key that produces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogId(Hash32);

impl LogId {
    /// The identifier of the log signed by `key`.
    #[must_use]
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self(hash(Domain::WitnessLogId, &key.to_bytes()))
    }

    /// The raw digest.
    #[must_use]
    pub const fn as_hash(&self) -> &Hash32 {
        &self.0
    }
}

/// A witness's public claim: "my log has `size` entries and this root".
///
/// Everything a wallet needs to hold between sessions is in here, and it is
/// small enough to keep alongside the checkpoint itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    /// Which log this describes.
    pub log: LogId,
    /// Which chain the log observes. A witness for one network must never be
    /// accepted as a witness for another.
    pub chain_id: ChainId,
    /// Number of entries committed.
    pub size: u64,
    /// Merkle root over those entries.
    pub root: Hash32,
    /// When the witness signed. Advisory: it is the witness's own clock.
    pub signed_at: Timestamp,
}

impl TreeHead {
    /// The bytes a signature commits to.
    #[must_use]
    pub fn sign_doc(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Sign this head.
    #[must_use]
    pub fn sign(&self, key: &SecretKey) -> SignedTreeHead {
        SignedTreeHead {
            signature: key.sign(Domain::TreeHeadSignDoc, &self.sign_doc()),
            head: self.clone(),
        }
    }
}

/// A [`TreeHead`] with the witness's signature over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// The claim.
    pub head: TreeHead,
    /// The witness's signature.
    pub signature: Signature,
}

impl SignedTreeHead {
    /// Check the signature, and that `key` is the key this log is named after.
    ///
    /// The second half is what stops one witness signing under another's
    /// identifier: [`LogId`] is derived from the key, so the pair either agrees
    /// or the head is not this log's.
    ///
    /// # Errors
    /// [`WitnessError::LogMismatch`] if the key does not derive the head's log
    /// identifier, or [`WitnessError::BadSignature`] if the signature fails.
    pub fn verify(&self, key: &PublicKey) -> Result<(), WitnessError> {
        if LogId::from_public_key(key) != self.head.log {
            return Err(WitnessError::LogMismatch);
        }
        key.verify(
            Domain::TreeHeadSignDoc,
            &self.head.sign_doc(),
            &self.signature,
        )
        .map_err(|_| WitnessError::BadSignature)
    }
}

/// Two signed heads that prove one witness published conflicting history.
///
/// This is the compact, self-contained proof of misbehaviour: anyone holding it
/// and the witness's public key can check it offline, and it is what a regulator
/// acts on. A witness that equivocates cannot deny it.
///
/// # What this cannot catch
///
/// Only *same-size* conflicts are compactly provable. A witness that simply
/// refuses to serve a consistency proof is unavailable rather than provably
/// dishonest, and the absence of a proof is not itself a proof. That case is
/// handled by corroboration: an unavailable witness stops counting toward the
/// [`Policy`](crate::Policy), so the wallet refuses rather than being misled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    /// One signed head.
    pub a: SignedTreeHead,
    /// The other, at the same size with a different root.
    pub b: SignedTreeHead,
}

impl Equivocation {
    /// Check that this really is proof of equivocation by `key`.
    ///
    /// # Errors
    /// [`WitnessError::NotEquivocation`] if the two heads are consistent with
    /// each other, or [`WitnessError::LogMismatch`] / [`WitnessError::BadSignature`]
    /// if either head is not genuinely this witness's.
    pub fn check(&self, key: &PublicKey) -> Result<(), WitnessError> {
        self.a.verify(key)?;
        self.b.verify(key)?;
        if self.a.head.log != self.b.head.log {
            return Err(WitnessError::LogMismatch);
        }
        // Same log, same size, different root: the witness committed to two
        // different histories of identical length. No honest log can do this.
        if self.a.head.size != self.b.head.size || self.a.head.root == self.b.head.root {
            return Err(WitnessError::NotEquivocation);
        }
        Ok(())
    }
}

impl Encode for LogId {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for LogId {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(Hash32::decode(r)?))
    }
}

impl Encode for TreeHead {
    fn encode(&self, out: &mut Vec<u8>) {
        self.log.encode(out);
        self.chain_id.encode(out);
        self.size.encode(out);
        self.root.encode(out);
        self.signed_at.encode(out);
    }
}

impl Decode for TreeHead {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            log: LogId::decode(r)?,
            chain_id: ChainId::decode(r)?,
            size: u64::decode(r)?,
            root: Hash32::decode(r)?,
            signed_at: Timestamp::decode(r)?,
        })
    }
}

impl Encode for SignedTreeHead {
    fn encode(&self, out: &mut Vec<u8>) {
        self.head.encode(out);
        out.extend_from_slice(&self.signature.to_bytes());
    }
}

impl Decode for SignedTreeHead {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let head = TreeHead::decode(r)?;
        let bytes = r.take_array::<64>()?;
        let signature = Signature::from_bytes(&bytes)
            .map_err(|_| CodecError::Invalid("malformed signature".to_owned()))?;
        Ok(Self { head, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_primitives::codec::decode_exact;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn head(seed: u8, size: u64, root: u8) -> TreeHead {
        TreeHead {
            log: LogId::from_public_key(&key(seed).public_key()),
            chain_id: chain(),
            size,
            root: Hash32::from_bytes([root; 32]),
            signed_at: Timestamp::from_millis(1_700_000_000_000),
        }
    }

    #[test]
    fn a_head_verifies_under_the_key_that_names_the_log() {
        let sth = head(1, 10, 7).sign(&key(1));
        assert!(sth.verify(&key(1).public_key()).is_ok());
    }

    #[test]
    fn a_witness_cannot_sign_under_another_witnesss_identifier() {
        // Witness 2 signs a head claiming to be witness 1's log. The signature
        // is real; the identity is not.
        let mut forged = head(1, 10, 7);
        forged.size = 11;
        let sth = forged.sign(&key(2));
        assert_eq!(
            sth.verify(&key(2).public_key()),
            Err(WitnessError::LogMismatch)
        );
    }

    #[test]
    fn a_tampered_head_does_not_verify() {
        let mut sth = head(1, 10, 7).sign(&key(1));
        sth.head.root = Hash32::from_bytes([8u8; 32]);
        assert_eq!(
            sth.verify(&key(1).public_key()),
            Err(WitnessError::BadSignature)
        );
    }

    #[test]
    fn two_roots_at_one_size_is_provable_equivocation() {
        // The thing a regulator acts on: self-contained, checkable offline.
        let evidence = Equivocation {
            a: head(1, 10, 7).sign(&key(1)),
            b: head(1, 10, 8).sign(&key(1)),
        };
        assert!(evidence.check(&key(1).public_key()).is_ok());
    }

    #[test]
    fn an_honest_pair_of_heads_is_not_equivocation() {
        // Growth is not misbehaviour, and neither is republishing the same head.
        let grown = Equivocation {
            a: head(1, 10, 7).sign(&key(1)),
            b: head(1, 20, 8).sign(&key(1)),
        };
        assert_eq!(
            grown.check(&key(1).public_key()),
            Err(WitnessError::NotEquivocation)
        );

        let repeated = Equivocation {
            a: head(1, 10, 7).sign(&key(1)),
            b: head(1, 10, 7).sign(&key(1)),
        };
        assert_eq!(
            repeated.check(&key(1).public_key()),
            Err(WitnessError::NotEquivocation)
        );
    }

    #[test]
    fn equivocation_by_one_witness_cannot_be_pinned_on_another() {
        let evidence = Equivocation {
            a: head(1, 10, 7).sign(&key(1)),
            b: head(2, 10, 8).sign(&key(2)),
        };
        assert!(evidence.check(&key(1).public_key()).is_err());
        assert!(evidence.check(&key(2).public_key()).is_err());
    }

    #[test]
    fn a_signed_head_round_trips() {
        let sth = head(1, 10, 7).sign(&key(1));
        assert_eq!(decode_exact::<SignedTreeHead>(&sth.to_bytes()), Ok(sth));
    }
}
