//! Payment references — the field an exchange or a merchant reconciles against.
//!
//! # Why a memo is not enough
//!
//! A transaction already carries a `memo`, and it is the wrong tool. Free text
//! gets truncated, re-encoded, auto-corrected by a phone keyboard, translated by
//! a helpful wallet, and pasted with a trailing space. An exchange crediting
//! customer accounts from memo text is doing string matching on user input, and
//! it is why "I sent it but it never arrived" is the most common support ticket
//! in the industry.
//!
//! XRPL solved this with **destination tags**: one machine-readable integer,
//! carried beside the payment, that an off-ledger system indexes on. A single
//! exchange address serves millions of customers, and each deposit says which
//! account to credit. Stellar reached the same answer with memo IDs.
//!
//! So this is a `u64`, not a string, and it is a distinct field rather than a
//! convention inside another one.
//!
//! # What it is not
//!
//! A reference's **value** has no on-ledger meaning. The protocol does not read
//! it, route on it, or validate it beyond its type. It is data for the
//! recipient's own systems — the same position XRPL takes, and the reason the
//! feature stays simple enough to be reliable.
//!
//! # The failure this prevents, and the one it does not
//!
//! It prevents an exchange guessing which customer a deposit belongs to. On its
//! own it does **not** prevent a user forgetting to include one, which is the
//! other half of the same support ticket.
//!
//! That half is answered twice over. Before sending,
//! [`PaymentRequest`](crate::request::PaymentRequest) carries the reference so
//! the sender never types it. And at the ledger,
//! [`RequiresReference`] is no longer only advice: an account that sets
//! `RequireReference` in its own record makes the executor **refuse** an
//! untagged payment outright, which is XRPL's `asfRequireDest`
//! ([ADR-0016](../../../docs/adr/0016-required-payment-references.md)).

use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

/// A machine-readable reference the recipient's systems index on.
///
/// Deliberately a newtype rather than a bare `u64`, so it cannot be silently
/// swapped with an amount, a nonce or a height at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PaymentReference(pub u64);

impl PaymentReference {
    /// Render for a URI or a QR code.
    #[must_use]
    pub fn to_decimal(self) -> String {
        self.0.to_string()
    }

    /// Parse from decimal text.
    ///
    /// Rejects anything that is not plain digits — no sign, no whitespace, no
    /// separators. A reference that parses loosely is a reference that gets
    /// mangled in transit, which is the failure this whole module exists to
    /// prevent.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse::<u64>().ok().map(Self)
    }
}

impl core::fmt::Display for PaymentReference {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Whether an account can credit payments that arrive without a reference.
///
/// An exchange deposit address cannot: a payment with no reference belongs to
/// nobody, and the money sits in limbo until a human intervenes. A market
/// trader's own address obviously can.
///
/// # Where this is decided
///
/// This type is the *answer*, not the storage. The authority is
/// `AccountFlag::RequireReference` on the recipient's own account record, which
/// is in state and so provable against a header. `Account::requires_reference`
/// converts one to the other, and it is the only bridge — so a wallet's warning
/// and the ledger's refusal read the same bit and cannot disagree.
///
/// Publishing the requirement in state does two jobs at once: a wallet can warn
/// *before* sending, which is the only point at which a warning helps, and the
/// executor refuses afterwards for the sender who was not warned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiresReference {
    /// Payments without a reference are fine.
    No,
    /// Payments without a reference cannot be credited to anyone.
    Yes,
}

impl RequiresReference {
    /// Whether a payment carrying `reference` is acceptable.
    #[must_use]
    pub fn accepts(self, reference: Option<PaymentReference>) -> bool {
        match self {
            Self::No => true,
            Self::Yes => reference.is_some(),
        }
    }
}

impl Encode for PaymentReference {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for PaymentReference {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_primitives::codec::decode_exact;

    #[test]
    fn a_reference_round_trips_through_text() {
        for n in [0u64, 1, 42, 1_000_000, u64::MAX] {
            let reference = PaymentReference(n);
            assert_eq!(
                PaymentReference::parse(&reference.to_decimal()),
                Some(reference)
            );
        }
    }

    #[test]
    fn loose_parsing_is_refused() {
        // Every one of these is something a phone keyboard, a spreadsheet or a
        // copy-paste can produce. Accepting them would credit the wrong
        // customer, which is worse than refusing the payment.
        for bad in [
            "", " 42", "42 ", "+42", "-42", "4 2", "42.0", "1,000", "0x2a", "42abc", "abc",
        ] {
            assert_eq!(
                PaymentReference::parse(bad),
                None,
                "{bad:?} must not parse as a reference"
            );
        }
    }

    #[test]
    fn leading_zeros_parse_to_the_same_reference() {
        // An exchange that formats tags with padding must not create a second
        // identity for the same customer.
        assert_eq!(PaymentReference::parse("0042"), Some(PaymentReference(42)));
    }

    #[test]
    fn an_exchange_address_refuses_unreferenced_payments() {
        // This is the predicate the executor calls. `crates/executor` proves the
        // end-to-end refusal; here it is only that the answer is the right way
        // round, which is the sort of thing a negation typo silently reverses.
        let exchange = RequiresReference::Yes;
        assert!(
            !exchange.accepts(None),
            "a deposit with no tag has no owner"
        );
        assert!(exchange.accepts(Some(PaymentReference(7))));

        let person = RequiresReference::No;
        assert!(person.accepts(None));
        assert!(person.accepts(Some(PaymentReference(7))));
    }

    #[test]
    fn references_round_trip_through_the_wire_format() {
        let reference = PaymentReference(9_876_543_210);
        assert_eq!(
            decode_exact::<PaymentReference>(&reference.to_bytes()),
            Ok(reference)
        );
    }
}
