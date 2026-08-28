//! Sovereign stablecoin issuer records.
//!
//! An issuer is the authority permitted to mint and burn one `sov/<cc>/<unit>`
//! denomination — a central bank, or a licensed institution supervised by one.
//!
//! The powers here are real and deliberately bounded. An issuer controls its own
//! denomination and nothing else: it cannot touch AFRI, another country's
//! currency, or any other asset an account holds. Every action it takes is an
//! on-chain event attributable to a named authority. See
//! [ADR-0005](../../../docs/adr/0005-african-first-design.md) and architecture
//! §4.2 for why the capability exists at all — a central bank will not issue on
//! rails where it cannot meet a court order, and a network with no sovereign
//! issuers on it helps nobody.

use afrolink_crypto::Address;
use afrolink_primitives::Amount;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

/// The authority record for one sovereign denomination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuer {
    /// The account permitted to mint, burn, freeze and pause.
    pub authority: Address,
    /// Optional hard cap on total supply.
    ///
    /// A cap is how an issuer binds itself publicly: with one set, holders can
    /// verify from the chain alone that no more than the reserved amount can
    /// exist, without trusting an attestation.
    pub max_supply: Option<Amount>,
    /// While true, minting is refused. Burning and transfers continue.
    pub paused: bool,
}

impl Issuer {
    /// An uncapped, unpaused issuer.
    #[must_use]
    pub const fn new(authority: Address) -> Self {
        Self {
            authority,
            max_supply: None,
            paused: false,
        }
    }

    /// The same issuer with a hard supply cap.
    #[must_use]
    pub const fn with_cap(mut self, cap: Amount) -> Self {
        self.max_supply = Some(cap);
        self
    }

    /// The same issuer, paused.
    #[must_use]
    pub const fn paused(mut self) -> Self {
        self.paused = true;
        self
    }

    /// Whether `account` may act for this issuer.
    #[must_use]
    pub fn is_authority(&self, account: &Address) -> bool {
        &self.authority == account
    }
}

impl Encode for Issuer {
    fn encode(&self, out: &mut Vec<u8>) {
        self.authority.encode(out);
        self.max_supply.encode(out);
        self.paused.encode(out);
    }
}

impl Decode for Issuer {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            authority: Address::decode(r)?,
            max_supply: Option::<Amount>::decode(r)?,
            paused: bool::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::codec::decode_exact;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    #[test]
    fn builders_compose() {
        let issuer = Issuer::new(addr(1))
            .with_cap(Amount::from_afri(1_000))
            .paused();
        assert_eq!(issuer.max_supply, Some(Amount::from_afri(1_000)));
        assert!(issuer.paused);
        assert!(issuer.is_authority(&addr(1)));
        assert!(!issuer.is_authority(&addr(2)));
    }

    #[test]
    fn issuer_records_round_trip() {
        for issuer in [
            Issuer::new(addr(1)),
            Issuer::new(addr(2)).with_cap(Amount::from_afri(500)),
            Issuer::new(addr(3)).paused(),
        ] {
            assert_eq!(decode_exact::<Issuer>(&issuer.to_bytes()), Ok(issuer));
        }
    }
}
