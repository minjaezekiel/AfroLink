//! Binding contacts to accounts, and the delay that defends against SIM swap.
//!
//! # The threat, with numbers
//!
//! SIM-swap fraud rose **327% in Kenya during 2025** — over 123,000 fraudulent
//! SIMs issued, around $3.8M drained from mobile wallets — and accounts for as
//! much as **43% of mobile-money fraud** across African markets. An attacker
//! persuades or bribes a telco into reissuing a number, and every system that
//! treats the number as proof of identity falls at once.
//!
//! [ADR-0005](../../../docs/adr/0005-african-first-design.md) §D.1 calls a naive
//! phone-to-key binding "the most dangerous thing we could ship". This module is
//! the reason that stays true.
//!
//! # The defence
//!
//! Two rules, and the second is what does the work:
//!
//! 1. **A contact resolves; it never authorises.** Holding the number lets you
//!    be *found*. Spending requires the key, always. There is no path in this
//!    crate from a phone number to a signature.
//! 2. **Rebinding is delayed and vetoable.** Pointing a number at a new account
//!    takes effect only after [`REBIND_DELAY_BLOCKS`], and during that window the
//!    *current* holder can cancel it with their key.
//!
//! So a SIM swap produces a visible request that the real owner refuses, rather
//! than a silent redirect. The attacker holds the number and gets nothing.
//!
//! # Real recovery still works
//!
//! Someone who genuinely lost their phone *and* their key cannot veto — so after
//! the delay, the rebind completes and they recover their number. The mechanism
//! does not distinguish the honest case from the attack; it does not need to.
//! It only needs the honest owner to be the one holding a key, which they are.

use afrolink_crypto::Address;
use afrolink_primitives::Height;
use afrolink_state::{KeyValueStore, StoreKey};
use thiserror::Error;

use crate::contact::{Attestor, ContactCommitment, ContactRecord, PendingRebind};

/// How long a rebinding waits before it may be applied, in blocks.
///
/// At ~1s blocks this is about 72 hours. The number is a trade-off with one side
/// far heavier than the other: too short and a victim asleep or without
/// connectivity cannot veto in time; too long and honest recovery is merely
/// slow. Governance may raise it; lowering it needs a very good argument.
pub const REBIND_DELAY_BLOCKS: u64 = 259_200;

/// Why a binding operation failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The caller is not a registered attestor.
    #[error("{0} is not a registered attestor")]
    NotAnAttestor(Address),
    /// The attestor's licence is suspended.
    #[error("attestor {0} is suspended")]
    AttestorSuspended(Address),
    /// The commitment is not bound to any account.
    #[error("no account is bound to this contact")]
    NotBound,
    /// The commitment is already bound; use a rebind.
    #[error("this contact is already bound; rebinding is required")]
    AlreadyBound,
    /// No rebinding is pending.
    #[error("no rebinding is pending for this contact")]
    NoPendingRebind,
    /// A rebinding is already pending.
    #[error("a rebinding is already pending for this contact")]
    RebindPending,
    /// The rebinding delay has not elapsed.
    #[error("rebinding is not effective until height {effective_at}, now {now}")]
    TooEarly {
        /// When it becomes effective.
        effective_at: u64,
        /// Current height.
        now: u64,
    },
    /// The caller does not hold the account currently bound.
    #[error("only the currently bound account may veto a rebinding")]
    NotBoundAccount,
    /// Stored state did not decode.
    #[error("corrupt contact record: {0}")]
    Corrupt(String),
}

/// Reads and writes contact bindings over any state store.
pub struct Bindings<'a, S: KeyValueStore> {
    store: &'a mut S,
}

impl<'a, S: KeyValueStore> Bindings<'a, S> {
    /// Borrow a store as a binding registry.
    pub fn new(store: &'a mut S) -> Self {
        Self { store }
    }

    /// Resolve a contact commitment to the account it currently points at.
    ///
    /// Returns the *current* binding, ignoring any pending rebind — a payment
    /// today must go where the contact points today.
    ///
    /// # Errors
    /// Returns [`BindError::Corrupt`] if stored bytes do not decode.
    pub fn resolve(
        &self,
        commitment: &ContactCommitment,
    ) -> Result<Option<ContactRecord>, BindError> {
        self.store
            .get_decoded::<ContactRecord>(&StoreKey::contact(commitment.as_hash()))
            .map_err(|e| BindError::Corrupt(e.to_string()))
    }

    /// Register a party as licensed to attest bindings.
    ///
    /// Governance-gated at the message layer; this is the state write.
    pub fn register_attestor(&mut self, address: &Address, attestor: &Attestor) {
        self.store
            .set_encoded(&StoreKey::attestor(address), attestor);
    }

    /// Bind a contact to an account for the first time.
    ///
    /// # Errors
    /// Returns the first [`BindError`] encountered.
    pub fn attest(
        &mut self,
        commitment: &ContactCommitment,
        address: Address,
        issuer: Address,
        now: Height,
    ) -> Result<(), BindError> {
        self.require_active_attestor(&issuer)?;
        if self.resolve(commitment)?.is_some() {
            // A first binding must not silently overwrite an existing one, or
            // an attestor could redirect a number with no delay and no veto.
            return Err(BindError::AlreadyBound);
        }
        let record = ContactRecord::new(address, issuer, now);
        self.store
            .set_encoded(&StoreKey::contact(commitment.as_hash()), &record);
        Ok(())
    }

    /// Request that a contact point at a different account.
    ///
    /// Does not take effect now. See the module docs.
    ///
    /// # Errors
    /// Returns the first [`BindError`] encountered.
    pub fn request_rebind(
        &mut self,
        commitment: &ContactCommitment,
        new_address: Address,
        issuer: Address,
        now: Height,
    ) -> Result<Height, BindError> {
        self.require_active_attestor(&issuer)?;
        let mut record = self.resolve(commitment)?.ok_or(BindError::NotBound)?;
        if record.rebind.is_some() {
            // Otherwise an attacker could replace a pending request the victim
            // was about to veto, resetting the clock and hiding the first one.
            return Err(BindError::RebindPending);
        }

        let effective_at = Height(now.0.saturating_add(REBIND_DELAY_BLOCKS));
        record.rebind = Some(PendingRebind {
            new_address,
            issuer,
            effective_at,
        });
        self.store
            .set_encoded(&StoreKey::contact(commitment.as_hash()), &record);
        Ok(effective_at)
    }

    /// Cancel a pending rebinding.
    ///
    /// **Only the currently bound account may do this**, using its key. That is
    /// the entire SIM-swap defence: possession of the number is not possession
    /// of the account.
    ///
    /// # Errors
    /// Returns the first [`BindError`] encountered.
    pub fn veto_rebind(
        &mut self,
        commitment: &ContactCommitment,
        caller: Address,
    ) -> Result<(), BindError> {
        let mut record = self.resolve(commitment)?.ok_or(BindError::NotBound)?;
        if record.rebind.is_none() {
            return Err(BindError::NoPendingRebind);
        }
        if record.address != caller {
            return Err(BindError::NotBoundAccount);
        }
        record.rebind = None;
        self.store
            .set_encoded(&StoreKey::contact(commitment.as_hash()), &record);
        Ok(())
    }

    /// Apply a rebinding whose delay has elapsed.
    ///
    /// # Errors
    /// Returns the first [`BindError`] encountered.
    pub fn apply_rebind(
        &mut self,
        commitment: &ContactCommitment,
        now: Height,
    ) -> Result<(), BindError> {
        let mut record = self.resolve(commitment)?.ok_or(BindError::NotBound)?;
        let pending = record.rebind.clone().ok_or(BindError::NoPendingRebind)?;

        if now < pending.effective_at {
            return Err(BindError::TooEarly {
                effective_at: pending.effective_at.0,
                now: now.0,
            });
        }

        record.address = pending.new_address;
        record.issuer = pending.issuer;
        record.attested_at = now;
        record.rebind = None;
        self.store
            .set_encoded(&StoreKey::contact(commitment.as_hash()), &record);
        Ok(())
    }

    /// Remove a binding entirely.
    ///
    /// Available to the bound account, so a user can always stop being findable
    /// by a number without needing their attestor's cooperation.
    ///
    /// # Errors
    /// Returns the first [`BindError`] encountered.
    pub fn revoke(
        &mut self,
        commitment: &ContactCommitment,
        caller: Address,
    ) -> Result<(), BindError> {
        let record = self.resolve(commitment)?.ok_or(BindError::NotBound)?;
        if record.address != caller {
            return Err(BindError::NotBoundAccount);
        }
        self.store.delete(&StoreKey::contact(commitment.as_hash()));
        Ok(())
    }

    fn require_active_attestor(&self, address: &Address) -> Result<(), BindError> {
        let attestor = self
            .store
            .get_decoded::<Attestor>(&StoreKey::attestor(address))
            .map_err(|e| BindError::Corrupt(e.to_string()))?
            .ok_or(BindError::NotAnAttestor(*address))?;
        if !attestor.active {
            return Err(BindError::AttestorSuspended(*address));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::ContactKind;
    use afrolink_crypto::SecretKey;
    use afrolink_state::MemoryStore;

    const PEPPER: &[u8] = b"a-sixteen-byte-pepper-or-longer";

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    /// Amina's number.
    fn amina_phone() -> ContactCommitment {
        ContactCommitment::new(ContactKind::Phone, "+254712345678", PEPPER).expect("valid")
    }

    fn safaricom() -> Attestor {
        Attestor {
            country: *b"ke",
            name: "Safaricom".to_owned(),
            active: true,
        }
    }

    /// A store where Safaricom is licensed and Amina's number is bound to her.
    fn bound_store() -> MemoryStore {
        let mut store = MemoryStore::new();
        let mut bindings = Bindings::new(&mut store);
        bindings.register_attestor(&addr(10), &safaricom());
        bindings
            .attest(&amina_phone(), addr(1), addr(10), Height(100))
            .expect("attests");
        store
    }

    #[test]
    fn a_phone_number_resolves_to_the_account_it_was_bound_to() {
        let mut store = bound_store();
        let bindings = Bindings::new(&mut store);
        let record = bindings.resolve(&amina_phone()).unwrap().unwrap();
        assert_eq!(record.address, addr(1));
        assert_eq!(record.issuer, addr(10));
    }

    #[test]
    fn a_sim_swap_alone_cannot_redirect_an_alias() {
        // The headline test. An attacker takes over the number and gets their
        // attestor to request a rebind. Amina still holds her key.
        let mut store = bound_store();
        let mut bindings = Bindings::new(&mut store);

        let effective_at = bindings
            .request_rebind(&amina_phone(), addr(66), addr(10), Height(200))
            .expect("request is accepted");

        // Nothing has moved yet.
        assert_eq!(
            bindings.resolve(&amina_phone()).unwrap().unwrap().address,
            addr(1),
            "the contact must still point at Amina during the window"
        );

        // Applying early fails.
        assert!(matches!(
            bindings.apply_rebind(&amina_phone(), Height(201)),
            Err(BindError::TooEarly { .. })
        ));

        // Amina vetoes with her key.
        bindings
            .veto_rebind(&amina_phone(), addr(1))
            .expect("the bound account may veto");

        // And the attacker's rebind is gone for good.
        assert!(matches!(
            bindings.apply_rebind(&amina_phone(), effective_at),
            Err(BindError::NoPendingRebind)
        ));
        assert_eq!(
            bindings.resolve(&amina_phone()).unwrap().unwrap().address,
            addr(1)
        );
    }

    #[test]
    fn the_attacker_cannot_veto_on_the_victims_behalf() {
        // Veto authority follows the key, not the number and not the attestor.
        let mut store = bound_store();
        let mut bindings = Bindings::new(&mut store);
        bindings
            .request_rebind(&amina_phone(), addr(66), addr(10), Height(200))
            .expect("requests");

        assert_eq!(
            bindings.veto_rebind(&amina_phone(), addr(66)),
            Err(BindError::NotBoundAccount)
        );
        assert_eq!(
            bindings.veto_rebind(&amina_phone(), addr(10)),
            Err(BindError::NotBoundAccount),
            "not even the attestor that requested it"
        );
    }

    #[test]
    fn a_rebind_completes_when_the_owner_cannot_veto() {
        // Genuine recovery: Amina lost the phone and the key. Nobody vetoes, so
        // after the delay she gets her number back on a new account.
        let mut store = bound_store();
        let mut bindings = Bindings::new(&mut store);

        let effective_at = bindings
            .request_rebind(&amina_phone(), addr(2), addr(10), Height(200))
            .expect("requests");

        bindings
            .apply_rebind(&amina_phone(), effective_at)
            .expect("applies once the delay has elapsed");

        let record = bindings.resolve(&amina_phone()).unwrap().unwrap();
        assert_eq!(record.address, addr(2));
        assert!(record.rebind.is_none());
    }

    #[test]
    fn the_delay_is_three_days_of_blocks() {
        let mut store = bound_store();
        let mut bindings = Bindings::new(&mut store);
        let effective_at = bindings
            .request_rebind(&amina_phone(), addr(2), addr(10), Height(1_000))
            .expect("requests");
        assert_eq!(effective_at, Height(1_000 + REBIND_DELAY_BLOCKS));
    }

    #[test]
    fn a_pending_rebind_cannot_be_replaced_to_reset_the_clock() {
        // Otherwise an attacker spams requests, and the victim's veto never
        // catches the one that is actually live.
        let mut store = bound_store();
        let mut bindings = Bindings::new(&mut store);
        bindings
            .request_rebind(&amina_phone(), addr(66), addr(10), Height(200))
            .expect("first request");

        assert_eq!(
            bindings.request_rebind(&amina_phone(), addr(67), addr(10), Height(300)),
            Err(BindError::RebindPending)
        );
    }

    #[test]
    fn an_unlicensed_attestor_cannot_bind_a_contact() {
        let mut store = MemoryStore::new();
        let mut bindings = Bindings::new(&mut store);

        assert_eq!(
            bindings.attest(&amina_phone(), addr(1), addr(99), Height(100)),
            Err(BindError::NotAnAttestor(addr(99)))
        );
    }

    #[test]
    fn a_suspended_attestor_cannot_bind_or_rebind() {
        let mut store = bound_store();
        let mut bindings = Bindings::new(&mut store);
        bindings.register_attestor(
            &addr(10),
            &Attestor {
                active: false,
                ..safaricom()
            },
        );

        assert_eq!(
            bindings.request_rebind(&amina_phone(), addr(66), addr(10), Height(200)),
            Err(BindError::AttestorSuspended(addr(10)))
        );
    }

    #[test]
    fn a_first_binding_cannot_silently_overwrite_an_existing_one() {
        // Without this an attestor could redirect a number with no delay at all,
        // which would route around the entire defence.
        let mut store = bound_store();
        let mut bindings = Bindings::new(&mut store);

        assert_eq!(
            bindings.attest(&amina_phone(), addr(66), addr(10), Height(200)),
            Err(BindError::AlreadyBound)
        );
    }

    #[test]
    fn the_bound_account_can_stop_being_findable() {
        // Revocation must not require the attestor's cooperation: a user who
        // wants out should not have to ask their telco.
        let mut store = bound_store();
        let mut bindings = Bindings::new(&mut store);

        assert_eq!(
            bindings.revoke(&amina_phone(), addr(66)),
            Err(BindError::NotBoundAccount)
        );
        bindings
            .revoke(&amina_phone(), addr(1))
            .expect("the bound account may revoke");
        assert_eq!(bindings.resolve(&amina_phone()).unwrap(), None);
    }

    #[test]
    fn an_unbound_contact_resolves_to_nothing() {
        let mut store = MemoryStore::new();
        let bindings = Bindings::new(&mut store);
        assert_eq!(bindings.resolve(&amina_phone()).unwrap(), None);
    }
}
