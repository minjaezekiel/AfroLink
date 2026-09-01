//! Phone numbers and email addresses, bound to accounts without ever being
//! stored.
//!
//! # Why a hash is not enough
//!
//! The obvious design is to put `hash(phone_number)` on chain. It does not work,
//! and the reason is arithmetic rather than cryptographic: a national phone
//! number space is around `10^9` entries. Anyone can hash all of them in
//! minutes and build a complete reverse index of the country's population,
//! their addresses, and — because state is public and provable — their
//! balances.
//!
//! Celo hit this exactly and built ODIS, a rate-limited threshold OPRF, in
//! response. The relevant lesson is not the machinery but the requirement it
//! encodes: **someone who already knows the number must be able to resolve it,
//! and someone who does not must not be able to enumerate.**
//!
//! It is also where the incumbent moved. In 2026 Safaricom began masking phone
//! numbers in M-Pesa transactions, approved by the Central Bank of Kenya, after
//! two decades of exposing them enabled harvesting and fraud. Publishing
//! numbers on a public ledger would be walking the other way.
//!
//! # The construction
//!
//! ```text
//! commitment = H( ContactCommitment, pepper || kind || normalised_identifier )
//! ```
//!
//! The pepper is high-entropy and held by the attesting issuer, so the
//! commitment cannot be brute-forced even though the identifier space is small.
//! Resolution goes through a rate-limited lookup at that issuer — see
//! `docs/07-resolver-service.md`, including the threshold-OPRF hardening that
//! removes the issuer's ability to enumerate its own users.
//!
//! Nothing in this module can be reversed. That is the point, and it is why
//! there is no `StoreKey` constructor anywhere that accepts a phone number.

use afrolink_crypto::Address;
use afrolink_crypto::hash::{Domain, Hash32, hash_parts};
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{CountryCode, Height};
use thiserror::Error;

/// Minimum acceptable pepper length.
///
/// 16 bytes of entropy is what makes the commitment unguessable despite the
/// identifier being drawn from a space small enough to enumerate exhaustively.
pub const MIN_PEPPER_LEN: usize = 16;

/// Why a contact identifier was rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContactError {
    /// A phone number was not in E.164 form.
    #[error("phone number must be E.164: '+' then 8..=15 digits")]
    NotE164,
    /// An email address was not plausibly an address.
    #[error("email address is malformed")]
    MalformedEmail,
    /// The pepper carried too little entropy to resist enumeration.
    #[error("pepper must be at least {MIN_PEPPER_LEN} bytes, got {0}")]
    WeakPepper(usize),
}

/// Which kind of contact identifier a commitment covers.
///
/// Part of the hash input, so a phone number and an email address that happen to
/// normalise to the same string cannot produce the same commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactKind {
    /// An E.164 phone number.
    Phone,
    /// An email address.
    Email,
}

impl ContactKind {
    /// The tag mixed into the commitment.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Phone => 1,
            Self::Email => 2,
        }
    }
}

/// A commitment to a phone number or email address.
///
/// Deliberately opaque: there is no accessor returning the identifier, because
/// this type never holds one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContactCommitment(Hash32);

impl ContactCommitment {
    /// Commit to an identifier under a pepper.
    ///
    /// # Errors
    /// Returns [`ContactError`] if the identifier does not normalise or the
    /// pepper is too short to resist enumeration.
    pub fn new(kind: ContactKind, identifier: &str, pepper: &[u8]) -> Result<Self, ContactError> {
        if pepper.len() < MIN_PEPPER_LEN {
            return Err(ContactError::WeakPepper(pepper.len()));
        }
        let normalised = normalise(kind, identifier)?;
        Ok(Self(hash_parts(
            Domain::ContactCommitment,
            &[pepper, &[kind.tag()], normalised.as_bytes()],
        )))
    }

    /// The commitment digest, for use as a state key.
    #[must_use]
    pub fn as_hash(&self) -> &Hash32 {
        &self.0
    }
}

/// Canonical form of an identifier, so that the same contact always commits to
/// the same value.
///
/// Without this, `+254 712 345 678` and `+254712345678` would be different
/// people, and a user who typed their number with spaces would silently fail to
/// be found.
///
/// # Errors
/// Returns [`ContactError`] if the identifier is not a plausible phone number
/// or email address.
pub fn normalise(kind: ContactKind, identifier: &str) -> Result<String, ContactError> {
    match kind {
        ContactKind::Phone => {
            let trimmed = identifier.trim();
            let digits: String = trimmed
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-' && *c != '(' && *c != ')')
                .collect();

            let rest = digits.strip_prefix('+').ok_or(ContactError::NotE164)?;
            if !(8..=15).contains(&rest.len()) || !rest.chars().all(|c| c.is_ascii_digit()) {
                return Err(ContactError::NotE164);
            }
            Ok(format!("+{rest}"))
        }
        ContactKind::Email => {
            let lowered = identifier.trim().to_lowercase();
            let (local, domain) = lowered
                .split_once('@')
                .ok_or(ContactError::MalformedEmail)?;
            if local.is_empty()
                || domain.is_empty()
                || !domain.contains('.')
                || domain.starts_with('.')
                || domain.ends_with('.')
                || lowered.chars().any(char::is_whitespace)
            {
                return Err(ContactError::MalformedEmail);
            }
            Ok(lowered)
        }
    }
}

/// A pending change of the address a contact resolves to.
///
/// See [`crate::rebind`] for why this exists and why it takes time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRebind {
    /// Where the contact would point after the delay elapses.
    pub new_address: Address,
    /// The attestor that requested it.
    pub issuer: Address,
    /// First height at which the rebind may be applied.
    pub effective_at: Height,
}

/// What the chain stores for a phone number or email address.
///
/// Note what is absent: the identifier. A full state dump reveals which
/// commitments exist and where they point, and nothing about whose numbers they
/// are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRecord {
    /// The account this contact currently resolves to.
    pub address: Address,
    /// The licensed attestor that vouched for the binding.
    pub issuer: Address,
    /// When the binding was made.
    pub attested_at: Height,
    /// An in-flight rebinding, if any.
    pub rebind: Option<PendingRebind>,
}

impl ContactRecord {
    /// A fresh binding with no rebind in flight.
    #[must_use]
    pub fn new(address: Address, issuer: Address, attested_at: Height) -> Self {
        Self {
            address,
            issuer,
            attested_at,
            rebind: None,
        }
    }
}

/// A party licensed to attest contact bindings — an MNO, a bank, a national ID
/// authority.
///
/// [ADR-0007](../../../docs/adr/0007-distribution-and-sybil-resistance.md)
/// commits us to identity being attested rather than custodial, and this is that
/// decision made concrete: the chain verifies a credential from a licensed
/// party. It does not run verification, and it holds no documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestor {
    /// Which jurisdiction licensed this attestor.
    ///
    /// A validated [`CountryCode`] rather than two loose bytes. It was the
    /// latter until attestors became reachable, which meant `"ke"`, `"KE"` and
    /// any two bytes at all were three spellings of one jurisdiction — in a
    /// record hashed into the state root.
    pub country: CountryCode,
    /// A human-readable label for wallets to display.
    pub name: String,
    /// Whether the attestor is currently permitted to attest.
    ///
    /// Governance suspends rather than deletes, so existing bindings keep a
    /// resolvable provenance after a licence is withdrawn.
    pub active: bool,
}

impl Encode for ContactCommitment {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for ContactCommitment {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(Hash32::decode(r)?))
    }
}

impl Encode for PendingRebind {
    fn encode(&self, out: &mut Vec<u8>) {
        self.new_address.encode(out);
        self.issuer.encode(out);
        self.effective_at.encode(out);
    }
}

impl Decode for PendingRebind {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            new_address: Address::decode(r)?,
            issuer: Address::decode(r)?,
            effective_at: Height::decode(r)?,
        })
    }
}

impl Encode for ContactRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.issuer.encode(out);
        self.attested_at.encode(out);
        self.rebind.encode(out);
    }
}

impl Decode for ContactRecord {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            issuer: Address::decode(r)?,
            attested_at: Height::decode(r)?,
            rebind: Option::<PendingRebind>::decode(r)?,
        })
    }
}

/// Longest display name an attestor may carry.
///
/// The name is shown to a user deciding whether to trust a binding, so it is
/// state a stranger would like to write: unbounded, it is a place to put a
/// paragraph of text that every node stores and every wallet renders.
pub const MAX_ATTESTOR_NAME: usize = 64;

impl Encode for Attestor {
    fn encode(&self, out: &mut Vec<u8>) {
        self.country.encode(out);
        self.name.encode(out);
        self.active.encode(out);
    }
}

impl Decode for Attestor {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let attestor = Self {
            country: CountryCode::decode(r)?,
            name: String::decode(r)?,
            active: bool::decode(r)?,
        };
        if attestor.name.is_empty() || attestor.name.len() > MAX_ATTESTOR_NAME {
            return Err(CodecError::Invalid(format!(
                "an attestor name must be 1..={MAX_ATTESTOR_NAME} bytes"
            )));
        }
        Ok(attestor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_primitives::codec::decode_exact;

    const PEPPER: &[u8] = b"a-sixteen-byte-pepper-or-longer";

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&afrolink_crypto::SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    #[test]
    fn the_same_number_written_differently_gives_one_commitment() {
        // A user typing spaces or dashes must still be found.
        let canonical =
            ContactCommitment::new(ContactKind::Phone, "+254712345678", PEPPER).expect("valid");

        for variant in [
            "+254 712 345 678",
            " +254712345678 ",
            "+254-712-345-678",
            "+254 (712) 345678",
        ] {
            assert_eq!(
                ContactCommitment::new(ContactKind::Phone, variant, PEPPER).expect("valid"),
                canonical,
                "{variant} must normalise to the same commitment"
            );
        }
    }

    #[test]
    fn emails_are_case_insensitive_and_trimmed() {
        let canonical =
            ContactCommitment::new(ContactKind::Email, "amina@example.com", PEPPER).expect("valid");
        for variant in [
            "Amina@Example.com",
            " AMINA@EXAMPLE.COM ",
            "amina@example.COM",
        ] {
            assert_eq!(
                ContactCommitment::new(ContactKind::Email, variant, PEPPER).expect("valid"),
                canonical
            );
        }
    }

    #[test]
    fn a_different_pepper_gives_a_different_commitment() {
        // This is what stops one issuer's records from being cross-referenced
        // against another's, and what stops a global rainbow table.
        let a = ContactCommitment::new(ContactKind::Phone, "+254712345678", PEPPER).expect("valid");
        let b = ContactCommitment::new(
            ContactKind::Phone,
            "+254712345678",
            b"a-completely-different-pepper",
        )
        .expect("valid");
        assert_ne!(a, b);
    }

    #[test]
    fn a_weak_pepper_is_refused() {
        // Without this, a caller could pass an empty pepper and reintroduce the
        // enumerable hash this whole module exists to avoid.
        assert_eq!(
            ContactCommitment::new(ContactKind::Phone, "+254712345678", b"short"),
            Err(ContactError::WeakPepper(5))
        );
        assert_eq!(
            ContactCommitment::new(ContactKind::Phone, "+254712345678", b""),
            Err(ContactError::WeakPepper(0))
        );
    }

    #[test]
    fn a_phone_and_an_email_cannot_collide() {
        // The kind tag is why. Without it, an identifier that normalised the
        // same way under both kinds would produce one commitment for two people.
        let phone =
            ContactCommitment::new(ContactKind::Phone, "+254712345678", PEPPER).expect("valid");
        let email =
            ContactCommitment::new(ContactKind::Email, "amina@example.com", PEPPER).expect("valid");
        assert_ne!(phone, email);
    }

    #[test]
    fn malformed_identifiers_are_rejected() {
        for bad in ["254712345678", "+254", "+abcdefghij", "0712345678", ""] {
            assert!(
                ContactCommitment::new(ContactKind::Phone, bad, PEPPER).is_err(),
                "{bad:?} must be rejected as a phone number"
            );
        }
        for bad in [
            "amina",
            "amina@",
            "@example.com",
            "amina@example",
            "a b@c.com",
        ] {
            assert!(
                ContactCommitment::new(ContactKind::Email, bad, PEPPER).is_err(),
                "{bad:?} must be rejected as an email"
            );
        }
    }

    #[test]
    fn a_contact_record_does_not_contain_the_phone_number() {
        // The headline privacy claim, asserted on the actual stored bytes: a
        // full state dump must not yield anyone's number.
        let commitment =
            ContactCommitment::new(ContactKind::Phone, "+254712345678", PEPPER).expect("valid");
        let record = ContactRecord::new(addr(1), addr(2), Height(100));

        let stored = [commitment.to_bytes(), record.to_bytes()].concat();
        let as_text = String::from_utf8_lossy(&stored);

        assert!(!as_text.contains("254712345678"));
        assert!(!as_text.contains("712345678"));
        assert!(
            !stored.windows(9).any(|w| w == b"712345678"),
            "the number must not appear in the stored bytes in any form"
        );
    }

    #[test]
    fn records_round_trip_through_the_wire_format() {
        let record = ContactRecord {
            address: addr(1),
            issuer: addr(2),
            attested_at: Height(100),
            rebind: Some(PendingRebind {
                new_address: addr(3),
                issuer: addr(2),
                effective_at: Height(359_200),
            }),
        };
        assert_eq!(
            decode_exact::<ContactRecord>(&record.to_bytes()),
            Ok(record)
        );

        let attestor = Attestor {
            country: CountryCode::new("ke").expect("valid country"),
            name: "Safaricom".to_owned(),
            active: true,
        };
        assert_eq!(decode_exact::<Attestor>(&attestor.to_bytes()), Ok(attestor));
    }
}
