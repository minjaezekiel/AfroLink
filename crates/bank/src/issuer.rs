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
//!
//! # Why there is more than one key
//!
//! The first version of this record had a single `authority` that could mint,
//! burn, freeze and pause. Every audit of a production stablecoin flags exactly
//! that: *a single all-powerful owner address is a dangerous single point of
//! failure*, and the highest-severity question in any stablecoin is who can call
//! mint. So the roles are split the way Circle's FiatToken splits them
//! ([ADR-0020](../../../docs/adr/0020-sovereign-issuance.md)):
//!
//! | Role | Held by | May |
//! |---|---|---|
//! | **Authority** | the cold key — a central bank | configure minters and the freezer, pause, lower the cap |
//! | **Minter** | a hot key, per licensed institution | mint **up to its remaining allowance**, and burn its own holdings |
//! | **Freezer** | a compliance key | freeze and unfreeze holders |
//!
//! The allowance is the part that matters. A minter's key lives on a machine
//! that signs every day; the authority's does not. With an allowance, a stolen
//! hot key mints what was left on it and then stops. Without one, it mints until
//! somebody notices.
//!
//! This is also the two-tier issuance model every major central bank has
//! converged on, expressed in keys: the central bank operates the ledger and
//! holds the authority; licensed intermediaries hold minter keys and put money
//! into circulation.

use afrolink_crypto::Address;
use afrolink_primitives::Amount;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

/// Most minters one denomination may have.
///
/// A bound because the record is read on every mint and written back on each
/// one; an unbounded list would make issuance cost grow with the number of
/// institutions that have ever held a key. Far above the number of licensed
/// intermediaries any single currency has.
pub const MAX_MINTERS: usize = 16;

/// One hot key permitted to put a denomination into circulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Minter {
    /// The account that signs mint transactions.
    pub address: Address,
    /// What remains of this minter's authorisation.
    ///
    /// Decremented by every mint and never restored by a burn — getting more is
    /// a deliberate act by the authority, which is the whole point. Circle's
    /// minter allowance works the same way and for the same reason.
    pub allowance: Amount,
}

impl Minter {
    /// A minter authorised for `allowance`.
    #[must_use]
    pub const fn new(address: Address, allowance: Amount) -> Self {
        Self { address, allowance }
    }
}

impl Encode for Minter {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.allowance.encode(out);
    }
}

impl Decode for Minter {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            allowance: Amount::decode(r)?,
        })
    }
}

/// Why an issuer record could not be changed as asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssuerError {
    /// More minters than [`MAX_MINTERS`].
    #[error("a denomination may have at most {MAX_MINTERS} minters")]
    TooManyMinters,
    /// A supply cap that would give the issuer more room than it had.
    ///
    /// The ratchet. See [`Issuer::tighten_cap`].
    #[error("a supply cap may only be lowered, never raised or removed")]
    CapWouldRise,
}

/// The authority record for one sovereign denomination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuer {
    /// The cold key that governs this denomination.
    ///
    /// Configures minters and the freezer, pauses issuance, and tightens the
    /// cap. It cannot itself mint: a key that can both authorise and issue is
    /// the single point of failure this record exists to avoid.
    pub authority: Address,
    /// Hot keys permitted to mint, each with a finite allowance.
    ///
    /// Sorted by address and free of repeats. Both are checked on decode and
    /// **neither is repaired**, because this record is hashed into the state
    /// root: a second spelling of one issuer would be a second state root for
    /// one state. Sorting a repeat away would also silently merge two entries
    /// for one address, and the one that survived would decide how much can be
    /// minted.
    pub minters: Vec<Minter>,
    /// The key permitted to freeze and unfreeze holders.
    ///
    /// `None` leaves the power with the authority. Separate because freezing is
    /// a compliance decision made under a court order or a sanctions listing,
    /// on a different timescale and by different people than issuance.
    pub freezer: Option<Address>,
    /// Optional hard cap on total supply.
    ///
    /// A cap is how an issuer binds itself publicly: with one set, holders can
    /// verify from the chain alone that no more than the reserved amount can
    /// exist, without trusting an attestation. That guarantee is only worth
    /// something if it cannot be taken back, which is why [`Self::tighten_cap`]
    /// is a ratchet.
    pub max_supply: Option<Amount>,
    /// While true, minting is refused. Burning and transfers continue.
    ///
    /// The circuit breaker: it stops new money without freezing money that
    /// already exists, so a suspected key compromise does not become a payments
    /// outage for everyone holding the currency.
    pub paused: bool,
}

impl Issuer {
    /// An uncapped, unpaused issuer with no minters yet.
    #[must_use]
    pub const fn new(authority: Address) -> Self {
        Self {
            authority,
            minters: Vec::new(),
            freezer: None,
            max_supply: None,
            paused: false,
        }
    }

    /// The same issuer with a hard supply cap.
    #[must_use]
    pub fn with_cap(mut self, cap: Amount) -> Self {
        self.max_supply = Some(cap);
        self
    }

    /// The same issuer, paused.
    #[must_use]
    pub fn paused(mut self) -> Self {
        self.paused = true;
        self
    }

    /// The same issuer with `address` authorised to mint up to `allowance`.
    ///
    /// # Panics
    /// If more than [`MAX_MINTERS`] are added. For genesis and tests, where the
    /// list is written by hand; the message path uses [`Self::set_minter`].
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "a builder used only where the list is written out by hand — a genesis \
                  file is read through `Decode`, which refuses an over-long list rather \
                  than panicking, so no node path reaches this"
    )]
    pub fn with_minter(mut self, address: Address, allowance: Amount) -> Self {
        self.set_minter(address, allowance)
            .expect("a fixture must not exceed the minter cap");
        self
    }

    /// The same issuer with a separate freezing key.
    #[must_use]
    pub fn with_freezer(mut self, freezer: Address) -> Self {
        self.freezer = Some(freezer);
        self
    }

    /// Whether `account` governs this denomination.
    #[must_use]
    pub fn is_authority(&self, account: &Address) -> bool {
        &self.authority == account
    }

    /// Whether `account` may freeze holders of this denomination.
    ///
    /// The authority when no freezer is named — a denomination must never end up
    /// with nobody able to answer a court order, which is the reason the freeze
    /// power exists at all.
    #[must_use]
    pub fn may_freeze(&self, account: &Address) -> bool {
        self.freezer
            .as_ref()
            .map_or_else(|| self.is_authority(account), |f| f == account)
    }

    /// This minter's record, if `address` is one.
    #[must_use]
    pub fn minter(&self, address: &Address) -> Option<&Minter> {
        let at = self
            .minters
            .binary_search_by(|m| m.address.cmp(address))
            .ok()?;
        self.minters.get(at)
    }

    /// What `address` may still mint. Zero for a non-minter.
    #[must_use]
    pub fn allowance_of(&self, address: &Address) -> Amount {
        self.minter(address).map_or(Amount::ZERO, |m| m.allowance)
    }

    /// Authorise `address` for exactly `allowance`, or remove it at zero.
    ///
    /// Absolute rather than an increment: the authority is stating what this
    /// minter may do from now on, and an operator reading the record should not
    /// have to replay history to know the answer. Zero removes the entry rather
    /// than storing it, so "is this a minter" and "may this minter mint" are the
    /// same question.
    ///
    /// # Errors
    /// Returns [`IssuerError::TooManyMinters`].
    pub fn set_minter(&mut self, address: Address, allowance: Amount) -> Result<(), IssuerError> {
        match self.minters.binary_search_by(|m| m.address.cmp(&address)) {
            Ok(at) => {
                if allowance.is_zero() {
                    self.minters.remove(at);
                } else if let Some(minter) = self.minters.get_mut(at) {
                    minter.allowance = allowance;
                }
            }
            Err(at) => {
                if allowance.is_zero() {
                    return Ok(());
                }
                if self.minters.len() >= MAX_MINTERS {
                    return Err(IssuerError::TooManyMinters);
                }
                self.minters.insert(at, Minter::new(address, allowance));
            }
        }
        Ok(())
    }

    /// Draw `amount` against `address`'s allowance.
    ///
    /// Returns `false` if `address` is not a minter or has less than `amount`
    /// left, having changed nothing.
    ///
    /// Deducting here rather than checking here and deducting later is
    /// deliberate: several small mints in one block must consume the allowance
    /// they add up to. A check that reads a value the caller then forgets to
    /// write back is a per-transaction limit pretending to be a total.
    #[must_use]
    pub fn spend_allowance(&mut self, address: &Address, amount: Amount) -> bool {
        let Ok(at) = self.minters.binary_search_by(|m| m.address.cmp(address)) else {
            return false;
        };
        let Some(minter) = self.minters.get_mut(at) else {
            return false;
        };
        let Ok(remaining) = minter.allowance.checked_sub(amount) else {
            return false;
        };
        if remaining.is_zero() {
            self.minters.remove(at);
        } else {
            minter.allowance = remaining;
        }
        true
    }

    /// Bind this denomination to a supply cap no looser than the current one.
    ///
    /// **A ratchet, and that is the whole value of it.** A cap is a promise to
    /// holders that no more than a stated amount can exist; a promise the
    /// promiser can revoke is not a promise, it is a preference. So an issuer
    /// may set a first cap, or lower one it has already set, and may never raise
    /// one or remove it.
    ///
    /// Stellar reaches the same rule from the same reasoning — an issuer may
    /// only *clear* a clawback flag, never set one, *"to give asset holders
    /// perpetual confidence about the future state of their holdings"* — and
    /// XRPL refuses to enable clawback once any of the asset has been issued.
    /// A holder should be able to check what can be done to them once, at the
    /// moment they accept the asset, and rely on the answer.
    ///
    /// A cap below the supply already outstanding is allowed: it means no more
    /// may be minted until burns bring the total back under, which is exactly
    /// how an issuer winds a currency down.
    ///
    /// # Errors
    /// Returns [`IssuerError::CapWouldRise`].
    pub fn tighten_cap(&mut self, cap: Amount) -> Result<(), IssuerError> {
        if self.max_supply.is_some_and(|current| cap > current) {
            return Err(IssuerError::CapWouldRise);
        }
        self.max_supply = Some(cap);
        Ok(())
    }
}

impl Encode for Issuer {
    fn encode(&self, out: &mut Vec<u8>) {
        self.authority.encode(out);
        self.minters.encode(out);
        self.freezer.encode(out);
        self.max_supply.encode(out);
        self.paused.encode(out);
    }
}

impl Decode for Issuer {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let issuer = Self {
            authority: Address::decode(r)?,
            minters: Vec::<Minter>::decode(r)?,
            freezer: Option::<Address>::decode(r)?,
            max_supply: Option::<Amount>::decode(r)?,
            paused: bool::decode(r)?,
        };
        if issuer.minters.len() > MAX_MINTERS {
            return Err(CodecError::Invalid(format!(
                "a denomination may have at most {MAX_MINTERS} minters, got {}",
                issuer.minters.len()
            )));
        }
        // Refused, never repaired — see the field's own documentation. A repeat
        // is the dangerous case: sorting it away would merge two authorisations
        // into one and silently pick which allowance survives.
        if !issuer.minters.is_sorted_by(|a, b| a.address < b.address) {
            return Err(CodecError::Invalid(
                "issuer minters must be sorted by address and unique".into(),
            ));
        }
        // A minter with nothing left is not a minter. Storing one would make
        // "is a minter" and "may mint" two different questions, and every
        // caller would have to remember to ask the second.
        if issuer.minters.iter().any(|m| m.allowance.is_zero()) {
            return Err(CodecError::Invalid(
                "an issuer minter must have a non-zero allowance".into(),
            ));
        }
        Ok(issuer)
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
            .with_minter(addr(2), Amount::from_afri(100))
            .with_freezer(addr(3))
            .paused();
        assert_eq!(issuer.max_supply, Some(Amount::from_afri(1_000)));
        assert!(issuer.paused);
        assert!(issuer.is_authority(&addr(1)));
        assert!(!issuer.is_authority(&addr(2)));
        assert_eq!(issuer.allowance_of(&addr(2)), Amount::from_afri(100));
        assert!(issuer.may_freeze(&addr(3)));
        assert!(
            !issuer.may_freeze(&addr(1)),
            "naming a freezer moves the power rather than sharing it"
        );
    }

    #[test]
    fn the_authority_freezes_when_no_freezer_is_named() {
        // A denomination must never reach a state where nobody can answer a
        // court order — that capability is the reason a central bank will put
        // its currency on this chain at all.
        let issuer = Issuer::new(addr(1));
        assert!(issuer.may_freeze(&addr(1)));
        assert!(!issuer.may_freeze(&addr(9)));
    }

    #[test]
    fn a_supply_cap_can_only_ever_tighten() {
        // The ratchet. A cap holders can verify from the chain is worth
        // something only because the issuer cannot take it back.
        let mut issuer = Issuer::new(addr(1));
        issuer
            .tighten_cap(Amount::from_afri(1_000))
            .expect("first cap");
        issuer.tighten_cap(Amount::from_afri(400)).expect("lower");
        assert_eq!(
            issuer.tighten_cap(Amount::from_afri(401)),
            Err(IssuerError::CapWouldRise),
            "not by a single unit"
        );
        assert_eq!(issuer.max_supply, Some(Amount::from_afri(400)));
        issuer
            .tighten_cap(Amount::ZERO)
            .expect("winding a currency down is tightening");
    }

    #[test]
    fn allowances_are_spent_down_and_never_go_negative() {
        let mut issuer = Issuer::new(addr(1)).with_minter(addr(2), Amount::from_afri(100));
        assert!(issuer.spend_allowance(&addr(2), Amount::from_afri(60)));
        assert_eq!(issuer.allowance_of(&addr(2)), Amount::from_afri(40));
        assert!(
            !issuer.spend_allowance(&addr(2), Amount::from_afri(41)),
            "one unit over must fail"
        );
        assert_eq!(
            issuer.allowance_of(&addr(2)),
            Amount::from_afri(40),
            "and a failed draw must change nothing"
        );
        assert!(issuer.spend_allowance(&addr(2), Amount::from_afri(40)));
        assert!(
            issuer.minter(&addr(2)).is_none(),
            "a spent minter is removed, so `is a minter` and `may mint` stay one question"
        );
        assert!(!issuer.spend_allowance(&addr(9), Amount::from_afri(1)));
    }

    #[test]
    fn setting_an_allowance_to_zero_revokes_the_minter() {
        let mut issuer = Issuer::new(addr(1)).with_minter(addr(2), Amount::from_afri(100));
        issuer.set_minter(addr(2), Amount::ZERO).expect("revokes");
        assert!(issuer.minter(&addr(2)).is_none());
        issuer.set_minter(addr(9), Amount::ZERO).expect("no-op");
        assert!(issuer.minters.is_empty());
    }

    #[test]
    fn minters_stay_sorted_however_they_are_added() {
        let mut issuer = Issuer::new(addr(1));
        for seed in [7u8, 2, 9, 4] {
            issuer
                .set_minter(addr(seed), Amount::from_afri(10))
                .expect("under the cap");
        }
        assert!(issuer.minters.is_sorted_by(|a, b| a.address < b.address));
        assert_eq!(issuer.minters.len(), 4);
    }

    #[test]
    fn more_minters_than_the_cap_are_refused() {
        let mut issuer = Issuer::new(addr(1));
        for seed in 0..u8::try_from(MAX_MINTERS).unwrap() {
            issuer
                .set_minter(addr(seed + 10), Amount::from_afri(1))
                .expect("under the cap");
        }
        assert_eq!(
            issuer.set_minter(addr(200), Amount::from_afri(1)),
            Err(IssuerError::TooManyMinters)
        );
        // Raising an existing minter's allowance is not adding one.
        issuer
            .set_minter(addr(10), Amount::from_afri(50))
            .expect("still allowed at the cap");
    }

    #[test]
    fn issuer_records_round_trip() {
        for issuer in [
            Issuer::new(addr(1)),
            Issuer::new(addr(2)).with_cap(Amount::from_afri(500)),
            Issuer::new(addr(3)).paused(),
            Issuer::new(addr(4))
                .with_minter(addr(5), Amount::from_afri(10))
                .with_minter(addr(6), Amount::from_afri(20))
                .with_freezer(addr(7)),
        ] {
            assert_eq!(decode_exact::<Issuer>(&issuer.to_bytes()), Ok(issuer));
        }
    }

    #[test]
    fn a_record_with_unsorted_or_repeated_minters_is_refused_rather_than_sorted() {
        // The repeat is the dangerous one: sorting it away merges two
        // authorisations and silently decides which allowance survives — and
        // that number is how much money can be created.
        let good = Issuer::new(addr(1))
            .with_minter(addr(5), Amount::from_afri(10))
            .with_minter(addr(6), Amount::from_afri(20));

        let mut reversed = good.clone();
        reversed.minters.reverse();
        assert!(decode_exact::<Issuer>(&reversed.to_bytes()).is_err());

        let mut doubled = good.clone();
        let first = doubled.minters[0];
        doubled.minters.insert(1, first);
        assert!(decode_exact::<Issuer>(&doubled.to_bytes()).is_err());

        let mut spent = good.clone();
        spent.minters[0].allowance = Amount::ZERO;
        assert!(decode_exact::<Issuer>(&spent.to_bytes()).is_err());

        assert_eq!(decode_exact::<Issuer>(&good.to_bytes()), Ok(good));
    }
}
