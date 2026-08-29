//! Payment requests and the `afri:` URI scheme.
//!
//! # What this is for
//!
//! "Accept AFRI" has to be a two-line integration or nobody does it. The
//! primitive that made that true elsewhere is a **payment request URI**:
//! BIP-21 for Bitcoin, ERC-681 for Ethereum. A merchant emits one string; it
//! goes in a link, a QR code or an HTTP `402` challenge; any wallet understands
//! it. No SDK, no API key, no account with us.
//!
//! ```text
//! afri:@amina?denom=sov/ke/kes&amount=250.00&ref=88121&label=Duka%20la%20Amina
//! ```
//!
//! # Design rules, and why each one is here
//!
//! **The recipient may be an alias.** A merchant publishing
//! `afri1qzp8h4cthjxue7g0kk4dmz9nvvqhs6xk3nlq2m` on a shopfront is publishing
//! nothing anyone can check. `@duka-la-amina` is legible, and
//! [ADR-0008](../../../docs/adr/0008-human-readable-addressing.md) makes it
//! resolvable with a proof.
//!
//! **Resolution happens in the wallet, and the signed transaction still names an
//! address.** A URI is untrusted input from a poster, an email or a compromised
//! web page. It is a *request*, never an instruction — the wallet resolves,
//! shows the user who they are about to pay, and only then signs.
//!
//! **The amount is optional.** A tip jar, a donation link and a market stall all
//! want "pay me, you decide how much". A request that forces an amount cannot
//! express them.
//!
//! **The denomination is explicit and never defaulted.** Guessing that a bare
//! amount means AFRI would make a request for 250 shillings pay 250 AFRI. The
//! two differ by orders of magnitude, and the mistake is unrecoverable.
//!
//! # What this deliberately does not do
//!
//! It does not carry a signature, so a request cannot prove who created it.
//! Anyone can generate a URI naming any recipient — exactly like a Bitcoin
//! address on a poster. The protection is not in the URI, it is that the wallet
//! shows the resolved recipient before signing. Adding a signature here would
//! suggest a guarantee the format cannot make.

use afrolink_alias::Username;
use afrolink_crypto::Address;
use afrolink_primitives::{Amount, Denom};
use thiserror::Error;

use crate::reference::PaymentReference;

/// The URI scheme. Registered as `afri:` to match the address prefix.
pub const SCHEME: &str = "afri";

/// Longest permitted label or note, in bytes.
///
/// Both are attacker-controlled text that a wallet will render, so they are
/// bounded here rather than left to the UI to truncate.
pub const MAX_TEXT_LEN: usize = 128;

/// Why a payment request could not be parsed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// Not an `afri:` URI.
    #[error("payment request must begin with '{SCHEME}:'")]
    WrongScheme,
    /// The recipient was missing or unparseable.
    #[error("payment request names no valid recipient")]
    BadRecipient,
    /// A query parameter was malformed.
    #[error("malformed parameter {0:?}")]
    BadParameter(String),
    /// The denomination was absent or invalid.
    #[error("payment request must name a valid denomination")]
    BadDenom,
    /// The amount was not a valid decimal quantity.
    #[error("amount is not a valid decimal quantity")]
    BadAmount,
    /// Label or note exceeded [`MAX_TEXT_LEN`].
    #[error("text field exceeds {MAX_TEXT_LEN} bytes")]
    TextTooLong,
    /// The same parameter appeared twice.
    ///
    /// Rejected rather than resolved: a request carrying `amount=1&amount=1000`
    /// means different things depending on which a parser keeps, and a wallet
    /// disagreeing with a merchant's till about which one is real is a dispute
    /// nobody can settle afterwards.
    #[error("parameter {0:?} appears more than once")]
    DuplicateParameter(String),
}

/// Who a payment request names.
///
/// A request may name an alias, which is the point — but the wallet resolves it
/// and signs the resulting address, so nothing here is a payment instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payee {
    /// A raw account address.
    Address(Address),
    /// A username, to be resolved and confirmed before paying.
    Name(Username),
}

impl core::fmt::Display for Payee {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Address(a) => write!(f, "{a}"),
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

/// A request to be paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequest {
    /// Who is to be paid.
    pub payee: Payee,
    /// Which asset. Never defaulted — see the module docs.
    pub denom: Denom,
    /// How much, or `None` for "payer decides".
    pub amount: Option<Amount>,
    /// The recipient's own reconciliation reference.
    pub reference: Option<PaymentReference>,
    /// Who the payee is, for display.
    pub label: Option<String>,
    /// What the payment is for, for display.
    pub note: Option<String>,
}

impl PaymentRequest {
    /// The simplest useful request: pay this party, in this asset, any amount.
    #[must_use]
    pub fn new(payee: Payee, denom: Denom) -> Self {
        Self {
            payee,
            denom,
            amount: None,
            reference: None,
            label: None,
            note: None,
        }
    }

    /// Fix the amount.
    #[must_use]
    pub fn with_amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Attach a reconciliation reference.
    #[must_use]
    pub fn with_reference(mut self, reference: PaymentReference) -> Self {
        self.reference = Some(reference);
        self
    }

    /// Attach a display label for the payee.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Attach a note describing what the payment is for.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Render as an `afri:` URI.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut params: Vec<String> =
            vec![format!("denom={}", encode_component(self.denom.as_str()))];

        if let Some(amount) = self.amount {
            params.push(format!("amount={}", amount.to_decimal()));
        }
        if let Some(reference) = self.reference {
            params.push(format!("ref={}", reference.to_decimal()));
        }
        if let Some(label) = &self.label {
            params.push(format!("label={}", encode_component(label)));
        }
        if let Some(note) = &self.note {
            params.push(format!("note={}", encode_component(note)));
        }

        format!("{SCHEME}:{}?{}", self.payee, params.join("&"))
    }

    /// Parse an `afri:` URI from untrusted input.
    ///
    /// # Errors
    /// Returns the first [`RequestError`] encountered. Unknown parameters are
    /// ignored rather than rejected, so a wallet built today keeps working
    /// against a merchant that adds a field tomorrow.
    pub fn parse(uri: &str) -> Result<Self, RequestError> {
        let rest = uri
            .strip_prefix(SCHEME)
            .and_then(|r| r.strip_prefix(':'))
            .ok_or(RequestError::WrongScheme)?;

        let (payee_part, query) = match rest.split_once('?') {
            Some((p, q)) => (p, q),
            None => (rest, ""),
        };

        let payee = parse_payee(payee_part)?;

        let mut denom: Option<Denom> = None;
        let mut amount: Option<Amount> = None;
        let mut reference: Option<PaymentReference> = None;
        let mut label: Option<String> = None;
        let mut note: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, raw) = pair
                .split_once('=')
                .ok_or_else(|| RequestError::BadParameter(pair.to_owned()))?;

            if seen.iter().any(|k| k == key) {
                return Err(RequestError::DuplicateParameter(key.to_owned()));
            }
            seen.push(key.to_owned());

            let value =
                decode_component(raw).ok_or_else(|| RequestError::BadParameter(key.to_owned()))?;

            match key {
                "denom" => {
                    denom = Some(Denom::new(&value).map_err(|_| RequestError::BadDenom)?);
                }
                "amount" => {
                    amount =
                        Some(Amount::from_decimal(&value).map_err(|_| RequestError::BadAmount)?);
                }
                "ref" => {
                    reference = Some(
                        PaymentReference::parse(&value)
                            .ok_or_else(|| RequestError::BadParameter("ref".to_owned()))?,
                    );
                }
                "label" => label = Some(bounded(value)?),
                "note" => note = Some(bounded(value)?),
                // Forward compatibility: ignore what we do not know.
                _ => {}
            }
        }

        Ok(Self {
            payee,
            denom: denom.ok_or(RequestError::BadDenom)?,
            amount,
            reference,
            label,
            note,
        })
    }
}

impl core::fmt::Display for PaymentRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_uri())
    }
}

fn bounded(value: String) -> Result<String, RequestError> {
    if value.len() > MAX_TEXT_LEN {
        return Err(RequestError::TextTooLong);
    }
    Ok(value)
}

fn parse_payee(part: &str) -> Result<Payee, RequestError> {
    if let Some(name) = part.strip_prefix('@') {
        return Username::new(name)
            .map(Payee::Name)
            .map_err(|_| RequestError::BadRecipient);
    }
    Address::from_bech32(part)
        .map(Payee::Address)
        .map_err(|_| RequestError::BadRecipient)
}

/// Percent-encode everything outside an unreserved set.
///
/// Deliberately conservative: `/` is escaped even though a URI path would allow
/// it, because denominations contain slashes (`sov/ke/kes`) and an unescaped one
/// in a query value is the kind of thing a lenient parser silently mis-splits.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Percent-decode, rejecting malformed escapes rather than passing them through.
fn decode_component(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;

    while let Some(&byte) = bytes.get(i) {
        if byte == b'%' {
            let hi = bytes.get(i.checked_add(1)?)?;
            let lo = bytes.get(i.checked_add(2)?)?;
            let digit = |c: u8| char::from(c).to_digit(16);
            let value = digit(*hi)?.checked_mul(16)?.checked_add(digit(*lo)?)?;
            out.push(u8::try_from(value).ok()?);
            i = i.checked_add(3)?;
        } else if byte == b'+' {
            // `+` means space in form encoding and a literal plus in a URI. A
            // phone number in a label would silently lose its country code if we
            // guessed wrong, so it stays literal.
            out.push(b'+');
            i = i.checked_add(1)?;
        } else {
            out.push(byte);
            i = i.checked_add(1)?;
        }
    }

    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid")
    }

    fn name(s: &str) -> Username {
        Username::new(s).expect("valid")
    }

    #[test]
    fn a_market_stall_request_round_trips() {
        // The canonical case: a printed QR code on a shopfront.
        let request = PaymentRequest::new(Payee::Name(name("duka-la-amina")), kes())
            .with_amount(Amount::from_afri(250))
            .with_reference(PaymentReference(88_121))
            .with_label("Duka la Amina")
            .with_note("Sukari 2kg");

        let uri = request.to_uri();
        assert!(uri.starts_with("afri:@duka-la-amina?"), "got {uri}");
        assert_eq!(PaymentRequest::parse(&uri), Ok(request));
    }

    #[test]
    fn a_request_can_name_a_raw_address() {
        // Exchanges and existing tooling must not be forced into aliases.
        let request = PaymentRequest::new(Payee::Address(addr(1)), kes())
            .with_reference(PaymentReference(42));
        assert_eq!(PaymentRequest::parse(&request.to_uri()), Ok(request));
    }

    #[test]
    fn an_amount_is_optional_so_a_tip_jar_works() {
        let request = PaymentRequest::new(Payee::Name(name("amina")), kes());
        let parsed = PaymentRequest::parse(&request.to_uri()).expect("parses");
        assert_eq!(parsed.amount, None);
    }

    #[test]
    fn a_denomination_is_never_guessed() {
        // Defaulting a bare amount to AFRI would turn "250 shillings" into
        // "250 AFRI" — orders of magnitude apart, and unrecoverable.
        assert_eq!(
            PaymentRequest::parse("afri:@amina?amount=250"),
            Err(RequestError::BadDenom)
        );
        assert_eq!(
            PaymentRequest::parse("afri:@amina"),
            Err(RequestError::BadDenom)
        );
    }

    #[test]
    fn a_slash_in_a_denomination_survives_the_round_trip() {
        // `sov/ke/kes` is the exact shape a lenient encoder mangles.
        let request = PaymentRequest::new(Payee::Name(name("amina")), kes());
        let uri = request.to_uri();
        assert!(uri.contains("denom=sov%2Fke%2Fkes"), "got {uri}");
        assert_eq!(PaymentRequest::parse(&uri).expect("parses").denom, kes());
    }

    #[test]
    fn a_duplicated_parameter_is_refused_rather_than_resolved() {
        // A request saying both 1 and 1000 means different things depending on
        // which a parser keeps. Refusing is the only safe reading.
        assert_eq!(
            PaymentRequest::parse("afri:@amina?denom=afri&amount=1&amount=1000"),
            Err(RequestError::DuplicateParameter("amount".to_owned()))
        );
    }

    #[test]
    fn a_confusable_or_invalid_name_in_a_uri_is_rejected() {
        // The URI is untrusted input, so ADR-0008's name rules have to hold
        // here too — a poster is exactly where a lookalike name would be used.
        for uri in [
            "afri:@\u{430}mina?denom=afri",
            "afri:@am ina?denom=afri",
            "afri:@ab?denom=afri",
            "afri:@afri?denom=afri",
        ] {
            assert_eq!(
                PaymentRequest::parse(uri),
                Err(RequestError::BadRecipient),
                "{uri} must be rejected"
            );
        }
    }

    #[test]
    fn a_corrupted_address_is_rejected_rather_than_paid() {
        let good = addr(1).to_bech32().expect("encodes");
        let mut broken = good.clone();
        broken.replace_range(good.len() - 2.., "qq");

        assert_eq!(
            PaymentRequest::parse(&format!("afri:{broken}?denom=afri")),
            Err(RequestError::BadRecipient)
        );
    }

    #[test]
    fn the_wrong_scheme_is_rejected() {
        for uri in [
            "bitcoin:@amina?denom=afri",
            "ethereum:0xabc",
            "@amina?denom=afri",
            "",
        ] {
            assert_eq!(
                PaymentRequest::parse(uri),
                Err(RequestError::WrongScheme),
                "{uri:?} must be rejected"
            );
        }
    }

    #[test]
    fn unknown_parameters_are_ignored_for_forward_compatibility() {
        // A wallet shipped today must keep working against a merchant that adds
        // a field tomorrow, or the ecosystem fragments on every extension.
        let parsed =
            PaymentRequest::parse("afri:@amina?denom=afri&amount=5&expires=1234&campaign=harvest")
                .expect("parses");
        assert_eq!(parsed.amount, Some(Amount::from_afri(5)));
    }

    #[test]
    fn attacker_controlled_text_is_bounded() {
        let long = "x".repeat(MAX_TEXT_LEN + 1);
        assert_eq!(
            PaymentRequest::parse(&format!("afri:@amina?denom=afri&label={long}")),
            Err(RequestError::TextTooLong)
        );
    }

    #[test]
    fn percent_escapes_survive_and_malformed_ones_are_rejected() {
        let request =
            PaymentRequest::new(Payee::Name(name("amina")), kes()).with_note("Sukari & chai");
        assert_eq!(
            PaymentRequest::parse(&request.to_uri())
                .expect("parses")
                .note
                .as_deref(),
            Some("Sukari & chai")
        );

        for broken in [
            "afri:@amina?denom=afri&note=%",
            "afri:@amina?denom=afri&note=%ZZ",
        ] {
            assert!(
                PaymentRequest::parse(broken).is_err(),
                "{broken} must be rejected"
            );
        }
    }

    #[test]
    fn a_plus_in_a_label_stays_a_plus() {
        // Form encoding would turn this into a space and silently corrupt a
        // phone number printed on a receipt.
        let request =
            PaymentRequest::new(Payee::Name(name("amina")), kes()).with_label("+254712345678");
        assert_eq!(
            PaymentRequest::parse(&request.to_uri())
                .expect("parses")
                .label
                .as_deref(),
            Some("+254712345678")
        );
    }
}
