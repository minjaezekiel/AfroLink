//! The bank module: balances, supply accounting and sovereign issuance.
//!
//! # The invariant
//!
//! For every denomination, **the sum of all balances equals the recorded total
//! supply**. Every operation here either preserves that or is a deliberate,
//! authorised change to supply ([`Bank::mint`] / [`Bank::burn`]). Nothing else
//! may create or destroy value.
//!
//! This is the property that makes the ledger worth anything, so it is checked
//! by tests directly rather than being left as an assumption.
//!
//! # Atomicity
//!
//! Every mutation computes *all* resulting values before writing *any* of them.
//! A transfer that would overflow the recipient's balance leaves the sender's
//! balance untouched. There is no partial application, so a failed operation
//! cannot leave the ledger short.
//!
//! # Zero balances are deleted
//!
//! When a balance reaches zero its key is removed rather than storing a zero.
//! That keeps the state tree small, and it means "this account holds none of
//! this asset" is answered by an absence proof — which a light client can
//! verify just as well as a presence proof.

#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
    )
)]

pub mod issuer;

pub use issuer::{Issuer, IssuerError, MAX_MINTERS, Minter};

use afrolink_crypto::Address;
use afrolink_primitives::{Amount, Denom};
use afrolink_state::{KeyValueStore, StateError, StoreKey};
use thiserror::Error;

/// Why a bank operation failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BankError {
    /// The account does not hold enough of the asset.
    #[error("insufficient funds: {denom} balance is {available}, needed {needed}")]
    InsufficientFunds {
        /// Asset involved.
        denom: String,
        /// Amount required.
        needed: String,
        /// Amount held.
        available: String,
    },
    /// A zero-valued operation, which is always a caller bug.
    #[error("amount must be greater than zero")]
    ZeroAmount,
    /// Arithmetic would have wrapped.
    #[error("arithmetic overflow in {0}")]
    Overflow(&'static str),
    /// The signer is not the registered issuer for this denomination.
    #[error("account is not the authorised issuer of {0}")]
    NotIssuer(String),
    /// The signer is not an authorised minter of this denomination.
    #[error("account is not an authorised minter of {0}")]
    NotMinter(String),
    /// The mint would draw more than the minter's remaining allowance.
    ///
    /// Its own error rather than a shade of [`Self::NotMinter`]: the two are
    /// fixed by different people. A non-minter needs authorising; a minter out
    /// of allowance needs topping up, and telling them apart is what lets an
    /// operator page the right person at three in the morning.
    #[error("minting {amount} of {denom} exceeds this minter's remaining allowance of {allowance}")]
    MintAllowanceExceeded {
        /// Asset involved.
        denom: String,
        /// Amount requested.
        amount: String,
        /// What the minter had left.
        allowance: String,
    },
    /// The signer may not freeze holders of this denomination.
    #[error("account may not freeze holders of {0}")]
    NotFreezer(String),
    /// The issuer record could not be changed as asked.
    #[error(transparent)]
    Issuer(#[from] IssuerError),
    /// No issuer has been registered for this denomination.
    #[error("no issuer registered for {0}")]
    NoIssuer(String),
    /// The issuer has paused this denomination.
    #[error("issuance of {0} is paused")]
    IssuerPaused(String),
    /// Minting would exceed the issuer's declared cap.
    #[error("minting {amount} would exceed the supply cap for {denom}")]
    SupplyCapExceeded {
        /// Asset involved.
        denom: String,
        /// Amount requested.
        amount: String,
    },
    /// The account is frozen for this denomination.
    #[error("account is frozen for {0}")]
    AccountFrozen(String),
    /// Only the protocol may mint the native coin.
    #[error("the native coin cannot be minted by an issuer")]
    NativeNotIssuable,
    /// Corrupt state.
    #[error(transparent)]
    State(#[from] StateError),
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, BankError>;

/// Read-only balance and supply queries over a borrowed store.
///
/// Separate from [`Bank`] so that queries need only a shared borrow — which is
/// what lets a caller total up balances while holding the store immutably.
pub struct BankView<'a, S: KeyValueStore> {
    store: &'a S,
}

impl<'a, S: KeyValueStore> BankView<'a, S> {
    /// Borrow a store for reading.
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// An account's balance. Absent keys read as zero.
    ///
    /// # Errors
    /// Returns [`BankError::State`] if the stored value is corrupt.
    pub fn balance(&self, address: &Address, denom: &Denom) -> Result<Amount> {
        Ok(self
            .store
            .get_decoded::<Amount>(&StoreKey::balance(address, denom))?
            .unwrap_or(Amount::ZERO))
    }

    /// The recorded total supply of a denomination.
    ///
    /// # Errors
    /// Returns [`BankError::State`] if the stored value is corrupt.
    pub fn total_supply(&self, denom: &Denom) -> Result<Amount> {
        Ok(self
            .store
            .get_decoded::<Amount>(&StoreKey::supply(denom))?
            .unwrap_or(Amount::ZERO))
    }

    /// Whether `address` is frozen for `denom`.
    #[must_use]
    pub fn is_frozen(&self, address: &Address, denom: &Denom) -> bool {
        self.store.get(&StoreKey::frozen(denom, address)).is_some()
    }

    /// The registered issuer of a denomination, if any.
    ///
    /// # Errors
    /// Returns [`BankError::State`] if the stored record is corrupt.
    pub fn issuer(&self, denom: &Denom) -> Result<Option<Issuer>> {
        Ok(self.store.get_decoded::<Issuer>(&StoreKey::issuer(denom))?)
    }
}

/// Balance and supply operations over a state store.
pub struct Bank<'a, S: KeyValueStore> {
    store: &'a mut S,
}

impl<'a, S: KeyValueStore> Bank<'a, S> {
    /// Borrow a store as a bank.
    pub fn new(store: &'a mut S) -> Self {
        Self { store }
    }

    // -- reads ------------------------------------------------------------

    /// A read-only view over the same store.
    #[must_use]
    pub fn view(&self) -> BankView<'_, S> {
        BankView::new(self.store)
    }

    /// An account's balance. Absent keys read as zero.
    ///
    /// # Errors
    /// Returns [`BankError::State`] if the stored value is corrupt.
    pub fn balance(&self, address: &Address, denom: &Denom) -> Result<Amount> {
        self.view().balance(address, denom)
    }

    /// The recorded total supply of a denomination.
    ///
    /// # Errors
    /// Returns [`BankError::State`] if the stored value is corrupt.
    pub fn total_supply(&self, denom: &Denom) -> Result<Amount> {
        self.view().total_supply(denom)
    }

    /// Whether `address` is frozen for `denom`.
    #[must_use]
    pub fn is_frozen(&self, address: &Address, denom: &Denom) -> bool {
        self.view().is_frozen(address, denom)
    }

    /// The registered issuer of a denomination, if any.
    ///
    /// # Errors
    /// Returns [`BankError::State`] if the stored record is corrupt.
    pub fn issuer(&self, denom: &Denom) -> Result<Option<Issuer>> {
        self.view().issuer(denom)
    }

    // -- internal writes --------------------------------------------------

    /// Write a balance, deleting the key when the balance is zero.
    fn write_balance(&mut self, address: &Address, denom: &Denom, amount: Amount) {
        let key = StoreKey::balance(address, denom);
        if amount.is_zero() {
            self.store.delete(&key);
        } else {
            self.store.set_encoded(&key, &amount);
        }
    }

    fn write_supply(&mut self, denom: &Denom, amount: Amount) {
        let key = StoreKey::supply(denom);
        if amount.is_zero() {
            self.store.delete(&key);
        } else {
            self.store.set_encoded(&key, &amount);
        }
    }

    fn insufficient(denom: &Denom, needed: Amount, available: Amount) -> BankError {
        BankError::InsufficientFunds {
            denom: denom.to_string(),
            needed: needed.units().to_string(),
            available: available.units().to_string(),
        }
    }

    // -- operations -------------------------------------------------------

    /// Move `amount` of `denom` from one account to another.
    ///
    /// Supply is unchanged. Both new balances are computed before either is
    /// written, so a failure leaves the ledger exactly as it was.
    ///
    /// # Errors
    /// Returns [`BankError::InsufficientFunds`], [`BankError::AccountFrozen`],
    /// [`BankError::ZeroAmount`] or [`BankError::Overflow`].
    pub fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        denom: &Denom,
        amount: Amount,
    ) -> Result<()> {
        if amount.is_zero() {
            return Err(BankError::ZeroAmount);
        }
        // Freezing is scoped to one denom and one issuer's own asset.
        if self.is_frozen(from, denom) || self.is_frozen(to, denom) {
            return Err(BankError::AccountFrozen(denom.to_string()));
        }

        // A self-transfer must be a no-op, not a doubling. Computing the
        // recipient's new balance from a stale read would credit `amount` twice.
        if from == to {
            let balance = self.balance(from, denom)?;
            if balance < amount {
                return Err(Self::insufficient(denom, amount, balance));
            }
            return Ok(());
        }

        let from_balance = self.balance(from, denom)?;
        let to_balance = self.balance(to, denom)?;

        let new_from = from_balance
            .checked_sub(amount)
            .map_err(|_| Self::insufficient(denom, amount, from_balance))?;
        let new_to = to_balance
            .checked_add(amount)
            .map_err(|_| BankError::Overflow("transfer/credit"))?;

        // Both succeeded; only now do we write.
        self.write_balance(from, denom, new_from);
        self.write_balance(to, denom, new_to);
        Ok(())
    }

    /// Load an issuer record, or say why this denomination has none.
    fn require_issuer(&self, denom: &Denom) -> Result<Issuer> {
        if denom.is_native() {
            return Err(BankError::NativeNotIssuable);
        }
        self.issuer(denom)?
            .ok_or_else(|| BankError::NoIssuer(denom.to_string()))
    }

    /// Load an issuer record that `authority` governs.
    fn require_authority(&self, authority: &Address, denom: &Denom) -> Result<Issuer> {
        let issuer = self.require_issuer(denom)?;
        if !issuer.is_authority(authority) {
            return Err(BankError::NotIssuer(denom.to_string()));
        }
        Ok(issuer)
    }

    fn write_issuer(&mut self, denom: &Denom, issuer: &Issuer) {
        self.store.set_encoded(&StoreKey::issuer(denom), issuer);
    }

    /// Create `amount` of `denom` and credit it to `to`, raising total supply.
    ///
    /// `minter` must hold a minter authorisation with at least `amount`
    /// remaining, and the draw is **deducted here**. That is what makes the
    /// allowance a total rather than a per-transaction limit: a hundred small
    /// mints in one block consume what they add up to, which is the exact
    /// bypass a stablecoin audit looks for.
    ///
    /// The authority deliberately cannot mint. A key that both authorises
    /// issuance and performs it is the single point of failure this whole record
    /// exists to avoid; if a central bank wants to issue directly it gives
    /// itself a minter allowance, and that act is on the chain.
    ///
    /// The native coin is never issuable this way — it is created only by
    /// protocol emission.
    ///
    /// # Errors
    /// Returns [`BankError::NativeNotIssuable`], [`BankError::NoIssuer`],
    /// [`BankError::NotMinter`], [`BankError::MintAllowanceExceeded`],
    /// [`BankError::IssuerPaused`], [`BankError::AccountFrozen`],
    /// [`BankError::SupplyCapExceeded`] or [`BankError::Overflow`].
    pub fn mint(
        &mut self,
        minter: &Address,
        to: &Address,
        denom: &Denom,
        amount: Amount,
    ) -> Result<()> {
        if amount.is_zero() {
            return Err(BankError::ZeroAmount);
        }
        let mut issuer = self.require_issuer(denom)?;
        if issuer.minter(minter).is_none() {
            return Err(BankError::NotMinter(denom.to_string()));
        }
        if issuer.paused {
            return Err(BankError::IssuerPaused(denom.to_string()));
        }
        // Crediting a frozen holder is a change to a balance the issuer has
        // declared immobile. Refusing it here means a freeze means one thing
        // rather than two.
        if self.is_frozen(to, denom) {
            return Err(BankError::AccountFrozen(denom.to_string()));
        }

        let supply = self.total_supply(denom)?;
        let new_supply = supply
            .checked_add(amount)
            .map_err(|_| BankError::Overflow("mint/supply"))?;

        if let Some(cap) = issuer.max_supply
            && new_supply > cap
        {
            return Err(BankError::SupplyCapExceeded {
                denom: denom.to_string(),
                amount: amount.units().to_string(),
            });
        }

        let balance = self.balance(to, denom)?;
        let new_balance = balance
            .checked_add(amount)
            .map_err(|_| BankError::Overflow("mint/credit"))?;

        if !issuer.spend_allowance(minter, amount) {
            return Err(BankError::MintAllowanceExceeded {
                denom: denom.to_string(),
                amount: amount.units().to_string(),
                allowance: issuer.allowance_of(minter).units().to_string(),
            });
        }

        // Everything succeeded; only now do we write.
        self.write_balance(to, denom, new_balance);
        self.write_supply(denom, new_supply);
        self.write_issuer(denom, &issuer);
        Ok(())
    }

    /// Destroy `amount` of `denom` **from the minter's own balance**, lowering
    /// total supply.
    ///
    /// # Why there is no `from`
    ///
    /// Burning somebody else's holdings is confiscation with an accounting name
    /// on it, and an issuer that can do it silently makes every balance of that
    /// asset conditional. Redemption does not need it: a holder who wants cash
    /// **transfers to the minter and the minter burns what it now owns**, which
    /// is Circle's shape and leaves the holder's consent on the chain as a
    /// signed transfer. An issuer that must take funds without consent has
    /// [`Self::freeze`], which is visible, reversible and attributable.
    ///
    /// A burn does **not** restore the minter's allowance. Getting more room to
    /// issue is a deliberate act by the authority, and letting a mint-then-burn
    /// cycle refill it would make the allowance a rate limit on net issuance
    /// rather than a ceiling on the damage a stolen key can do.
    ///
    /// # Errors
    /// Returns [`BankError::InsufficientFunds`], [`BankError::NotMinter`],
    /// [`BankError::AccountFrozen`], or the issuer errors of [`Self::mint`].
    pub fn burn(&mut self, minter: &Address, denom: &Denom, amount: Amount) -> Result<()> {
        if amount.is_zero() {
            return Err(BankError::ZeroAmount);
        }
        let issuer = self.require_issuer(denom)?;
        if issuer.minter(minter).is_none() {
            return Err(BankError::NotMinter(denom.to_string()));
        }
        if self.is_frozen(minter, denom) {
            return Err(BankError::AccountFrozen(denom.to_string()));
        }

        let balance = self.balance(minter, denom)?;
        let new_balance = balance
            .checked_sub(amount)
            .map_err(|_| Self::insufficient(denom, amount, balance))?;

        let supply = self.total_supply(denom)?;
        let new_supply = supply
            .checked_sub(amount)
            .map_err(|_| BankError::Overflow("burn/supply"))?;

        self.write_balance(minter, denom, new_balance);
        self.write_supply(denom, new_supply);
        Ok(())
    }

    // -- issuer configuration, by the authority ---------------------------

    /// Authorise `minter` for exactly `allowance`, or revoke it at zero.
    ///
    /// # Errors
    /// Returns [`BankError::NotIssuer`], [`BankError::NoIssuer`] or
    /// [`BankError::Issuer`].
    pub fn set_minter_allowance(
        &mut self,
        authority: &Address,
        denom: &Denom,
        minter: &Address,
        allowance: Amount,
    ) -> Result<()> {
        let mut issuer = self.require_authority(authority, denom)?;
        issuer.set_minter(*minter, allowance)?;
        self.write_issuer(denom, &issuer);
        Ok(())
    }

    /// Name, or clear, the key permitted to freeze holders.
    ///
    /// # Errors
    /// Returns [`BankError::NotIssuer`] or [`BankError::NoIssuer`].
    pub fn set_freezer(
        &mut self,
        authority: &Address,
        denom: &Denom,
        freezer: Option<Address>,
    ) -> Result<()> {
        let mut issuer = self.require_authority(authority, denom)?;
        issuer.freezer = freezer;
        self.write_issuer(denom, &issuer);
        Ok(())
    }

    /// Stop or resume new issuance, leaving existing money alone.
    ///
    /// # Errors
    /// Returns [`BankError::NotIssuer`] or [`BankError::NoIssuer`].
    pub fn set_paused(&mut self, authority: &Address, denom: &Denom, paused: bool) -> Result<()> {
        let mut issuer = self.require_authority(authority, denom)?;
        issuer.paused = paused;
        self.write_issuer(denom, &issuer);
        Ok(())
    }

    /// Bind this denomination to a cap no looser than its current one.
    ///
    /// See [`Issuer::tighten_cap`] for why this only goes one way.
    ///
    /// # Errors
    /// Returns [`BankError::NotIssuer`], [`BankError::NoIssuer`] or
    /// [`BankError::Issuer`] when the cap would rise.
    pub fn tighten_supply_cap(
        &mut self,
        authority: &Address,
        denom: &Denom,
        cap: Amount,
    ) -> Result<()> {
        let mut issuer = self.require_authority(authority, denom)?;
        issuer.tighten_cap(cap)?;
        self.write_issuer(denom, &issuer);
        Ok(())
    }

    /// Credit newly emitted native coin — protocol use only.
    ///
    /// This is the one path that creates AFRI, used for block rewards, agent
    /// liquidity mining, light-node and oracle rewards. It takes no authority
    /// argument because no account may call it; only consensus can.
    ///
    /// # Errors
    /// Returns [`BankError::Overflow`] if supply or balance would wrap.
    pub fn emit_native(&mut self, to: &Address, amount: Amount) -> Result<()> {
        if amount.is_zero() {
            return Err(BankError::ZeroAmount);
        }
        let denom = Denom::native();
        let supply = self.total_supply(&denom)?;
        let new_supply = supply
            .checked_add(amount)
            .map_err(|_| BankError::Overflow("emit/supply"))?;
        let balance = self.balance(to, &denom)?;
        let new_balance = balance
            .checked_add(amount)
            .map_err(|_| BankError::Overflow("emit/credit"))?;

        self.write_balance(to, &denom, new_balance);
        self.write_supply(&denom, new_supply);
        Ok(())
    }

    /// Destroy native coin held by the staking module, lowering supply.
    ///
    /// The counterpart to [`Self::emit_native`], and the only path that reduces
    /// AFRI supply. [`Self::burn`] deliberately refuses the native coin: burning
    /// there is an *issuer* power over a sovereign stablecoin, and no issuer may
    /// ever touch AFRI.
    ///
    /// Slashed stake is destroyed rather than redistributed. Paying it to
    /// anybody — a treasury, the reporter, the remaining validators — creates a
    /// party that profits from slashing, and therefore a party with a reason to
    /// manufacture it. Burning leaves every holder better off in proportion and
    /// nobody better off in particular.
    ///
    /// Callers must be module code. Nothing reachable from a transaction
    /// signature may call this.
    ///
    /// # Errors
    /// [`BankError::ZeroAmount`], [`BankError::InsufficientFunds`] if the
    /// account does not hold that much, or [`BankError::Overflow`].
    pub fn slash_native(&mut self, from: &Address, amount: Amount) -> Result<()> {
        if amount.is_zero() {
            return Err(BankError::ZeroAmount);
        }
        let denom = Denom::native();
        let balance = self.balance(from, &denom)?;
        let new_balance =
            balance
                .checked_sub(amount)
                .map_err(|_| BankError::InsufficientFunds {
                    denom: denom.to_string(),
                    needed: amount.to_string(),
                    available: balance.to_string(),
                })?;
        let supply = self.total_supply(&denom)?;
        let new_supply = supply
            .checked_sub(amount)
            .map_err(|_| BankError::Overflow("slash/supply"))?;

        self.write_balance(from, &denom, new_balance);
        self.write_supply(&denom, new_supply);
        Ok(())
    }

    /// Credit an allocation at genesis, raising supply.
    ///
    /// The one path that creates value without an authority check, because at
    /// height 0 there is no authority yet — the genesis file *is* the authority,
    /// and every node validates it independently before starting. Callers must
    /// never expose this after genesis; the executor does not.
    ///
    /// # Errors
    /// Returns [`BankError::ZeroAmount`] or [`BankError::Overflow`].
    pub fn genesis_allocate(&mut self, to: &Address, denom: &Denom, amount: Amount) -> Result<()> {
        if amount.is_zero() {
            return Err(BankError::ZeroAmount);
        }
        let supply = self.total_supply(denom)?;
        let new_supply = supply
            .checked_add(amount)
            .map_err(|_| BankError::Overflow("genesis/supply"))?;
        let balance = self.balance(to, denom)?;
        let new_balance = balance
            .checked_add(amount)
            .map_err(|_| BankError::Overflow("genesis/credit"))?;

        self.write_balance(to, denom, new_balance);
        self.write_supply(denom, new_supply);
        Ok(())
    }

    /// Register the issuer of a sovereign denomination.
    ///
    /// # Errors
    /// Returns [`BankError::NativeNotIssuable`] for the native coin.
    pub fn register_issuer(&mut self, denom: &Denom, issuer: &Issuer) -> Result<()> {
        if denom.is_native() {
            return Err(BankError::NativeNotIssuable);
        }
        self.store.set_encoded(&StoreKey::issuer(denom), issuer);
        Ok(())
    }

    /// Freeze `address` for `denom`, on the authority of its issuer's freezer.
    ///
    /// Scoped deliberately: an issuer may freeze holdings of *its own* asset and
    /// can never reach AFRI, another country's currency, or anything else the
    /// account holds. Every freeze is an on-chain, attributable event.
    ///
    /// # Errors
    /// Returns [`BankError::NotFreezer`] or [`BankError::NoIssuer`].
    pub fn freeze(&mut self, caller: &Address, address: &Address, denom: &Denom) -> Result<()> {
        let issuer = self.require_issuer(denom)?;
        if !issuer.may_freeze(caller) {
            return Err(BankError::NotFreezer(denom.to_string()));
        }
        self.store
            .set_encoded(&StoreKey::frozen(denom, address), &1u8);
        Ok(())
    }

    /// Lift a freeze.
    ///
    /// # Errors
    /// Returns [`BankError::NotFreezer`] or [`BankError::NoIssuer`].
    pub fn unfreeze(&mut self, caller: &Address, address: &Address, denom: &Denom) -> Result<()> {
        let issuer = self.require_issuer(denom)?;
        if !issuer.may_freeze(caller) {
            return Err(BankError::NotFreezer(denom.to_string()));
        }
        self.store.delete(&StoreKey::frozen(denom, address));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;
    use afrolink_state::MemoryStore;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid denom")
    }

    /// Central bank of Kenya, as the registered issuer of `sov/ke/kes`.
    fn cbk() -> Address {
        addr(100)
    }

    /// A licensed intermediary holding the hot minting key.
    ///
    /// Separate from [`cbk`] on purpose: the authority configures and never
    /// issues, which is the whole shape of the record.
    fn treasury() -> Address {
        addr(101)
    }

    fn setup() -> MemoryStore {
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        bank.register_issuer(
            &kes(),
            &Issuer::new(cbk()).with_minter(treasury(), Amount::from_afri(1_000_000)),
        )
        .expect("registers");
        bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(1_000))
            .expect("mints");
        store
    }

    /// Sum of balances across every account that could hold `denom`.
    fn sum_balances(store: &MemoryStore, denom: &Denom, accounts: &[Address]) -> Amount {
        let bank = BankView::new(store);
        accounts.iter().fold(Amount::ZERO, |acc, a| {
            acc.checked_add(bank.balance(a, denom).expect("readable"))
                .expect("no overflow")
        })
    }

    #[test]
    fn a_transfer_moves_value_without_creating_it() {
        let mut store = setup();
        let accounts = [addr(1), addr(2)];
        let before = sum_balances(&store, &kes(), &accounts);

        let mut bank = Bank::new(&mut store);
        bank.transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(250))
            .expect("transfers");

        assert_eq!(
            bank.balance(&addr(1), &kes()).expect("read"),
            Amount::from_afri(750)
        );
        assert_eq!(
            bank.balance(&addr(2), &kes()).expect("read"),
            Amount::from_afri(250)
        );
        assert_eq!(
            sum_balances(&store, &kes(), &accounts),
            before,
            "value must be conserved"
        );
    }

    #[test]
    fn the_supply_invariant_holds_across_every_operation() {
        // The property the whole ledger rests on.
        let mut store = setup();
        let accounts = [addr(1), addr(2), addr(3)];
        {
            let mut bank = Bank::new(&mut store);
            bank.transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(300))
                .expect("t1");
            bank.transfer(&addr(2), &addr(3), &kes(), Amount::from_afri(100))
                .expect("t2");
            bank.mint(&treasury(), &addr(3), &kes(), Amount::from_afri(500))
                .expect("mint");
            // Redemption, in the two steps it actually takes: the holder signs
            // the money back to the minter, and the minter burns what it now
            // owns. There is no path that destroys a holder's balance directly.
            bank.transfer(&addr(1), &treasury(), &kes(), Amount::from_afri(200))
                .expect("redeem");
            bank.burn(&treasury(), &kes(), Amount::from_afri(200))
                .expect("burn");
        }
        let bank = BankView::new(&store);
        assert_eq!(
            sum_balances(&store, &kes(), &accounts),
            bank.total_supply(&kes()).expect("read"),
            "sum of balances must equal recorded supply"
        );
    }

    #[test]
    fn overspending_is_refused_and_changes_nothing() {
        let mut store = setup();
        let root_before = store.root();
        let mut bank = Bank::new(&mut store);
        let err = bank
            .transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(5_000))
            .expect_err("must fail");
        assert!(matches!(err, BankError::InsufficientFunds { .. }));
        assert_eq!(
            store.root(),
            root_before,
            "a failed transfer must not alter state"
        );
    }

    #[test]
    fn a_self_transfer_does_not_double_the_balance() {
        // Reading both balances before writing would credit `amount` twice here.
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        bank.transfer(&addr(1), &addr(1), &kes(), Amount::from_afri(400))
            .expect("no-op");
        assert_eq!(
            bank.balance(&addr(1), &kes()).expect("read"),
            Amount::from_afri(1_000)
        );
    }

    #[test]
    fn a_self_transfer_beyond_the_balance_still_fails() {
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        assert!(
            bank.transfer(&addr(1), &addr(1), &kes(), Amount::from_afri(9_999))
                .is_err()
        );
    }

    #[test]
    fn only_an_authorised_minter_can_mint() {
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        let impostor = addr(66);
        let err = bank
            .mint(&impostor, &impostor, &kes(), Amount::from_afri(1_000_000))
            .expect_err("must fail");
        assert!(matches!(err, BankError::NotMinter(_)));
        assert_eq!(bank.balance(&impostor, &kes()).expect("read"), Amount::ZERO);
    }

    #[test]
    fn the_native_coin_cannot_be_minted_by_an_issuer() {
        // AFRI is created by protocol emission only; an issuer route would let a
        // registered party inflate the staking token.
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        assert_eq!(
            bank.mint(
                &treasury(),
                &addr(1),
                &Denom::native(),
                Amount::from_afri(1)
            ),
            Err(BankError::NativeNotIssuable)
        );
        assert_eq!(
            bank.burn(&treasury(), &Denom::native(), Amount::from_afri(1)),
            Err(BankError::NativeNotIssuable)
        );
        assert_eq!(
            bank.register_issuer(&Denom::native(), &Issuer::new(cbk())),
            Err(BankError::NativeNotIssuable)
        );
    }

    #[test]
    fn protocol_emission_creates_native_coin() {
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        bank.emit_native(&addr(1), Amount::from_afri(50))
            .expect("emits");
        assert_eq!(
            bank.balance(&addr(1), &Denom::native()).expect("read"),
            Amount::from_afri(50)
        );
        assert_eq!(
            bank.total_supply(&Denom::native()).expect("read"),
            Amount::from_afri(50)
        );
    }

    #[test]
    fn a_supply_cap_is_enforced() {
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        let capped = Issuer::new(cbk())
            .with_cap(Amount::from_afri(1_000))
            .with_minter(treasury(), Amount::from_afri(1_000_000));
        bank.register_issuer(&kes(), &capped).expect("registers");

        bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(1_000))
            .expect("at the cap");
        let err = bank
            .mint(&treasury(), &addr(1), &kes(), Amount::from_afri(1))
            .expect_err("over the cap");
        assert!(matches!(err, BankError::SupplyCapExceeded { .. }));
    }

    #[test]
    fn a_paused_issuer_cannot_mint() {
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        bank.register_issuer(
            &kes(),
            &Issuer::new(cbk())
                .with_minter(treasury(), Amount::from_afri(100))
                .paused(),
        )
        .expect("registers");
        assert!(matches!(
            bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(1)),
            Err(BankError::IssuerPaused(_))
        ));
    }

    #[test]
    fn a_freeze_blocks_transfers_of_that_denom_only() {
        // The compliance power, and its limit: an issuer reaches its own asset
        // and nothing else the account holds.
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        bank.emit_native(&addr(1), Amount::from_afri(10))
            .expect("emits AFRI");
        bank.freeze(&cbk(), &addr(1), &kes()).expect("freezes");

        assert!(matches!(
            bank.transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(1)),
            Err(BankError::AccountFrozen(_))
        ));
        // AFRI is untouched by a KES issuer's freeze.
        bank.transfer(&addr(1), &addr(2), &Denom::native(), Amount::from_afri(5))
            .expect("AFRI must still move");
    }

    #[test]
    fn only_the_issuer_can_freeze_and_a_freeze_can_be_lifted() {
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        assert!(matches!(
            bank.freeze(&addr(66), &addr(1), &kes()),
            Err(BankError::NotFreezer(_))
        ));
        bank.freeze(&cbk(), &addr(1), &kes()).expect("freezes");
        assert!(bank.is_frozen(&addr(1), &kes()));
        bank.unfreeze(&cbk(), &addr(1), &kes()).expect("unfreezes");
        assert!(!bank.is_frozen(&addr(1), &kes()));
        bank.transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(1))
            .expect("moves again");
    }

    #[test]
    fn zero_balances_are_deleted_so_absence_is_provable() {
        let mut store = setup();
        {
            let mut bank = Bank::new(&mut store);
            bank.transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(1_000))
                .expect("drains");
        }
        let key = StoreKey::balance(&addr(1), &kes());
        assert!(
            store.get(&key).is_none(),
            "a zero balance must not be stored"
        );

        // And a light client can prove that emptiness against the state root.
        let (value, proof) = store.get_with_proof(&key);
        assert!(value.is_none());
        assert!(proof.verify(store.root(), key.as_bytes(), None));
    }

    #[test]
    fn zero_amount_operations_are_rejected() {
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        assert_eq!(
            bank.transfer(&addr(1), &addr(2), &kes(), Amount::ZERO),
            Err(BankError::ZeroAmount)
        );
        assert_eq!(
            bank.emit_native(&addr(1), Amount::ZERO),
            Err(BankError::ZeroAmount)
        );
    }

    #[test]
    fn burning_more_than_held_is_refused() {
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        assert!(matches!(
            bank.burn(&treasury(), &kes(), Amount::from_afri(2_000)),
            Err(BankError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn minting_an_unregistered_denom_fails() {
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        assert!(matches!(
            bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(1)),
            Err(BankError::NoIssuer(_))
        ));
    }

    // -- Sovereign issuance (ADR-0020) ------------------------------------

    #[test]
    fn the_authority_cannot_itself_mint() {
        // The point of splitting the roles. A key that both authorises issuance
        // and performs it is the most valuable target on the network, and it is
        // the highest-severity finding in any review of a stablecoin.
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        assert!(matches!(
            bank.mint(&cbk(), &addr(1), &kes(), Amount::from_afri(1)),
            Err(BankError::NotMinter(_))
        ));
        // It may of course grant itself an allowance — and that act is on the
        // chain, which is the difference that matters.
        bank.set_minter_allowance(&cbk(), &kes(), &cbk(), Amount::from_afri(5))
            .expect("authority may authorise anyone, itself included");
        bank.mint(&cbk(), &addr(1), &kes(), Amount::from_afri(5))
            .expect("now it may mint");
    }

    #[test]
    fn a_minter_cannot_mint_past_its_allowance_however_it_splits_the_mints() {
        // The bypass a stablecoin audit looks for: many small mints in one block
        // adding up to more than the ceiling. The allowance is a total, not a
        // per-transaction limit.
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        bank.register_issuer(
            &kes(),
            &Issuer::new(cbk()).with_minter(treasury(), Amount::from_afri(100)),
        )
        .expect("registers");

        for _ in 0..10 {
            bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(10))
                .expect("within the allowance");
        }
        assert!(
            matches!(
                bank.mint(&treasury(), &addr(1), &kes(), Amount::from_units(1)),
                Err(BankError::NotMinter(_))
            ),
            "a fully spent minter is no longer a minter"
        );
        assert_eq!(
            bank.total_supply(&kes()).expect("read"),
            Amount::from_afri(100),
            "exactly the allowance reached circulation, and not a unit more"
        );
    }

    #[test]
    fn a_burn_does_not_refill_the_allowance() {
        // Otherwise a mint-and-burn cycle turns a ceiling on the damage a stolen
        // key can do into a rate limit on net issuance, which is not the same
        // promise at all.
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        bank.register_issuer(
            &kes(),
            &Issuer::new(cbk()).with_minter(treasury(), Amount::from_afri(100)),
        )
        .expect("registers");
        bank.mint(&treasury(), &treasury(), &kes(), Amount::from_afri(100))
            .expect("spends the whole allowance");
        bank.burn(&treasury(), &kes(), Amount::from_afri(100))
            .expect_err("a spent minter is not a minter, so it cannot burn either");
        assert_eq!(
            bank.issuer(&kes()).expect("read").expect("exists").minters,
            Vec::new()
        );
    }

    #[test]
    fn a_supply_cap_cannot_be_raised_or_removed_by_the_issuer_that_set_it() {
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        bank.tighten_supply_cap(&cbk(), &kes(), Amount::from_afri(5_000))
            .expect("a first cap");
        assert!(matches!(
            bank.tighten_supply_cap(&cbk(), &kes(), Amount::from_afri(5_001)),
            Err(BankError::Issuer(IssuerError::CapWouldRise))
        ));
        bank.tighten_supply_cap(&cbk(), &kes(), Amount::from_afri(1_200))
            .expect("lowering is always allowed");
        assert!(matches!(
            bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(500)),
            Err(BankError::SupplyCapExceeded { .. })
        ));
    }

    #[test]
    fn a_cap_below_current_supply_stops_issuance_without_touching_holders() {
        // How a currency is wound down: no more may be created, and everything
        // already in circulation keeps working.
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        bank.tighten_supply_cap(&cbk(), &kes(), Amount::ZERO)
            .expect("winding down is tightening");
        assert!(matches!(
            bank.mint(&treasury(), &addr(1), &kes(), Amount::from_units(1)),
            Err(BankError::SupplyCapExceeded { .. })
        ));
        bank.transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(10))
            .expect("existing money still moves");
    }

    #[test]
    fn pausing_stops_new_money_without_freezing_existing_money() {
        // The response to a suspected key compromise must not be a payments
        // outage for everyone holding the currency.
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        bank.set_paused(&cbk(), &kes(), true).expect("authority");
        assert!(matches!(
            bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(1)),
            Err(BankError::IssuerPaused(_))
        ));
        bank.transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(10))
            .expect("transfers continue");
        bank.mint(&treasury(), &treasury(), &kes(), Amount::from_afri(1))
            .expect_err("still paused");
        bank.set_paused(&cbk(), &kes(), false).expect("authority");
        bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(1))
            .expect("resumed");
    }

    #[test]
    fn only_the_named_freezer_may_freeze_once_one_exists() {
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        // With no freezer named the authority holds the power, so a
        // denomination is never left unable to answer a court order.
        bank.freeze(&cbk(), &addr(1), &kes()).expect("authority");
        bank.unfreeze(&cbk(), &addr(1), &kes()).expect("authority");

        bank.set_freezer(&cbk(), &kes(), Some(addr(50)))
            .expect("authority names a compliance key");
        assert!(matches!(
            bank.freeze(&cbk(), &addr(1), &kes()),
            Err(BankError::NotFreezer(_))
        ));
        bank.freeze(&addr(50), &addr(1), &kes()).expect("freezer");
        assert!(bank.is_frozen(&addr(1), &kes()));
        assert!(
            !bank.is_frozen(&addr(1), &Denom::native()),
            "a freeze reaches one denomination and no other"
        );
    }

    #[test]
    fn a_frozen_holder_can_be_neither_credited_nor_drained() {
        // A freeze must mean one thing. If minting could still credit a frozen
        // account, an issuer could inflate a balance it has declared immobile.
        let mut store = setup();
        let mut bank = Bank::new(&mut store);
        bank.freeze(&cbk(), &addr(1), &kes()).expect("authority");
        assert!(matches!(
            bank.mint(&treasury(), &addr(1), &kes(), Amount::from_afri(1)),
            Err(BankError::AccountFrozen(_))
        ));
        assert!(matches!(
            bank.transfer(&addr(1), &addr(2), &kes(), Amount::from_afri(1)),
            Err(BankError::AccountFrozen(_))
        ));
    }

    #[test]
    fn a_stranger_can_change_nothing_about_a_denomination_it_does_not_issue() {
        let mut store = setup();
        let root_before = store.root();
        let mut bank = Bank::new(&mut store);
        let thief = addr(66);
        assert!(matches!(
            bank.mint(&thief, &thief, &kes(), Amount::from_afri(1)),
            Err(BankError::NotMinter(_))
        ));
        assert!(matches!(
            bank.set_minter_allowance(&thief, &kes(), &thief, Amount::from_afri(1)),
            Err(BankError::NotIssuer(_))
        ));
        assert!(matches!(
            bank.set_paused(&thief, &kes(), true),
            Err(BankError::NotIssuer(_))
        ));
        assert!(matches!(
            bank.tighten_supply_cap(&thief, &kes(), Amount::ZERO),
            Err(BankError::NotIssuer(_))
        ));
        assert!(matches!(
            bank.set_freezer(&thief, &kes(), Some(thief)),
            Err(BankError::NotIssuer(_))
        ));
        assert!(matches!(
            bank.freeze(&thief, &addr(1), &kes()),
            Err(BankError::NotFreezer(_))
        ));
        assert_eq!(
            store.root(),
            root_before,
            "and none of it left a mark on the ledger"
        );
    }
}
