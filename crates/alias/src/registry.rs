//! Username ownership: registration, renewal, transfer and expiry.

use afrolink_crypto::Address;
use afrolink_primitives::Height;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_state::{KeyValueStore, StoreKey};
use thiserror::Error;

use crate::name::{NameError, Skeleton, Username};

/// How long a registration lasts before renewal, in blocks.
///
/// At ~1s blocks this is about a year. Names expire on purpose: a namespace
/// where registration is permanent gets exhausted by squatters within weeks of
/// being valuable, and the people who lose out are the ones who arrive later —
/// which here means the ones who get connectivity later.
pub const REGISTRATION_BLOCKS: u64 = 31_536_000;

/// Grace period after expiry during which only the previous owner may renew.
///
/// About 30 days. Someone who misses a renewal by a day should not lose their
/// payment identity to a bot watching for expiries.
pub const GRACE_BLOCKS: u64 = 2_592_000;

/// Why a registry operation failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The name itself was invalid.
    #[error(transparent)]
    Name(#[from] NameError),
    /// Already registered and not expired.
    #[error("{0} is already registered")]
    Taken(String),
    /// A registered name folds to the same skeleton.
    ///
    /// Carries the existing name so a wallet can show *what* it collides with,
    /// which is the difference between a usable error and a mystifying one.
    #[error("{requested} is too easily confused with the existing name {existing}")]
    Confusable {
        /// What was asked for.
        requested: String,
        /// What already exists.
        existing: String,
    },
    /// The name is not registered.
    #[error("{0} is not registered")]
    NotFound(String),
    /// The caller does not own the name.
    #[error("caller does not own {0}")]
    NotOwner(String),
    /// Stored state did not decode.
    #[error("corrupt registry record: {0}")]
    Corrupt(String),
}

/// A username registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRecord {
    /// The account that controls this name.
    pub owner: Address,
    /// When it was first registered.
    pub registered_at: Height,
    /// First height at which it is no longer owned.
    pub expires_at: Height,
}

impl NameRecord {
    /// Whether the registration has lapsed at `now`.
    #[must_use]
    pub fn is_expired(&self, now: Height) -> bool {
        now >= self.expires_at
    }

    /// Whether the name is claimable by someone new at `now`.
    ///
    /// Distinct from [`Self::is_expired`]: during the grace period the name is
    /// expired but not yet available.
    #[must_use]
    pub fn is_claimable(&self, now: Height) -> bool {
        now >= Height(self.expires_at.0.saturating_add(GRACE_BLOCKS))
    }
}

/// Reads and writes username registrations over any state store.
pub struct Registry<'a, S: KeyValueStore> {
    store: &'a mut S,
}

impl<'a, S: KeyValueStore> Registry<'a, S> {
    /// Borrow a store as a registry.
    pub fn new(store: &'a mut S) -> Self {
        Self { store }
    }

    /// Look up a registration.
    ///
    /// # Errors
    /// Returns [`RegistryError::Corrupt`] if stored bytes do not decode.
    pub fn get(&self, name: &Username) -> Result<Option<NameRecord>, RegistryError> {
        self.store
            .get_decoded::<NameRecord>(&StoreKey::alias(name.as_str()))
            .map_err(|e| RegistryError::Corrupt(e.to_string()))
    }

    /// The name a wallet should display for an address, if it set one.
    ///
    /// # Errors
    /// Returns [`RegistryError::Corrupt`] if stored bytes do not decode.
    pub fn primary_name(&self, address: &Address) -> Result<Option<String>, RegistryError> {
        self.store
            .get_decoded::<String>(&StoreKey::alias_reverse(address))
            .map_err(|e| RegistryError::Corrupt(e.to_string()))
    }

    /// Register a name to `owner`.
    ///
    /// Refuses when the name is taken, or when it folds to the same skeleton as
    /// an existing name — see [`crate::name`] for why the second check matters
    /// as much as the first.
    ///
    /// # Errors
    /// Returns the first [`RegistryError`] encountered.
    pub fn register(
        &mut self,
        name: &Username,
        owner: Address,
        now: Height,
    ) -> Result<(), RegistryError> {
        if let Some(existing) = self.get(name)?
            && !existing.is_claimable(now)
        {
            return Err(RegistryError::Taken(name.as_str().to_owned()));
        }

        let skeleton = name.skeleton();
        if let Some(holder) = self.skeleton_holder(&skeleton)?
            && holder != *name.as_str()
        {
            // Only a live registration blocks; an abandoned lookalike should not
            // sterilise the skeleton forever.
            let holder_name = Username::new(&holder)?;
            let blocked = self
                .get(&holder_name)?
                .is_some_and(|r| !r.is_claimable(now));
            if blocked {
                return Err(RegistryError::Confusable {
                    requested: name.as_str().to_owned(),
                    existing: holder,
                });
            }
        }

        let record = NameRecord {
            owner,
            registered_at: now,
            expires_at: Height(now.0.saturating_add(REGISTRATION_BLOCKS)),
        };
        self.store
            .set_encoded(&StoreKey::alias(name.as_str()), &record);
        self.store.set_encoded(
            &StoreKey::alias_skeleton(skeleton.as_str()),
            &name.as_str().to_owned(),
        );
        Ok(())
    }

    /// Extend a registration. Only the owner may renew.
    ///
    /// # Errors
    /// Returns the first [`RegistryError`] encountered.
    pub fn renew(
        &mut self,
        name: &Username,
        caller: Address,
        now: Height,
    ) -> Result<(), RegistryError> {
        let mut record = self.owned_by(name, caller, now)?;
        // Extend from whichever is later, so renewing early adds time rather
        // than resetting it, and renewing late does not backdate.
        let base = record.expires_at.0.max(now.0);
        record.expires_at = Height(base.saturating_add(REGISTRATION_BLOCKS));
        self.store
            .set_encoded(&StoreKey::alias(name.as_str()), &record);
        Ok(())
    }

    /// Hand a name to another account.
    ///
    /// # Errors
    /// Returns the first [`RegistryError`] encountered.
    pub fn transfer(
        &mut self,
        name: &Username,
        caller: Address,
        to: Address,
        now: Height,
    ) -> Result<(), RegistryError> {
        let mut record = self.owned_by(name, caller, now)?;
        record.owner = to;
        self.store
            .set_encoded(&StoreKey::alias(name.as_str()), &record);
        // The old owner's display name must not survive the transfer, or a
        // wallet would keep showing a name its holder no longer controls.
        if self.primary_name(&caller)?.as_deref() == Some(name.as_str()) {
            self.store.delete(&StoreKey::alias_reverse(&caller));
        }
        Ok(())
    }

    /// Set the name wallets display for the caller's address.
    ///
    /// **Opt-in, and worth understanding before opting in.** Forward lookup
    /// (name → address) is what a payer needs. This is the *reverse* link, and
    /// it is strictly a disclosure: it lets anyone who sees the address in a
    /// transaction discover the handle, and therefore link every payment that
    /// address ever makes to one name.
    ///
    /// A merchant wants exactly that. A person often does not, which is why it
    /// is a separate action rather than a side effect of registering, and why
    /// [`Self::clear_primary`] exists.
    ///
    /// # Errors
    /// Returns the first [`RegistryError`] encountered.
    pub fn set_primary(
        &mut self,
        name: &Username,
        caller: Address,
        now: Height,
    ) -> Result<(), RegistryError> {
        self.owned_by(name, caller, now)?;
        self.store
            .set_encoded(&StoreKey::alias_reverse(&caller), &name.as_str().to_owned());
        Ok(())
    }

    /// Stop publishing a display name for the caller's address.
    ///
    /// Unconditional and always available: it touches only the caller's own
    /// reverse entry, and a privacy control that can be refused is not a
    /// privacy control. The name itself is untouched and keeps resolving
    /// forward — you become unlisted, not unpayable.
    ///
    /// Returns whether an entry was actually removed.
    ///
    /// Note the limit honestly: this stops *future* lookups. It cannot unlink
    /// what observers recorded while the entry was published, because the chain
    /// is public and history does not move.
    pub fn clear_primary(&mut self, caller: &Address) -> bool {
        self.store.delete(&StoreKey::alias_reverse(caller))
    }

    /// Give up a name entirely, freeing it and its skeleton for others.
    ///
    /// For someone who wants no on-chain handle at all rather than merely an
    /// unpublished one.
    ///
    /// # Errors
    /// Returns the first [`RegistryError`] encountered.
    pub fn release(
        &mut self,
        name: &Username,
        caller: Address,
        now: Height,
    ) -> Result<(), RegistryError> {
        self.owned_by(name, caller, now)?;

        self.store.delete(&StoreKey::alias(name.as_str()));
        self.store
            .delete(&StoreKey::alias_skeleton(name.skeleton().as_str()));
        if self.primary_name(&caller)?.as_deref() == Some(name.as_str()) {
            self.store.delete(&StoreKey::alias_reverse(&caller));
        }
        Ok(())
    }

    /// Fetch a record and require that `caller` owns it and it has not lapsed.
    fn owned_by(
        &self,
        name: &Username,
        caller: Address,
        now: Height,
    ) -> Result<NameRecord, RegistryError> {
        let record = self
            .get(name)?
            .ok_or_else(|| RegistryError::NotFound(name.as_str().to_owned()))?;
        if record.owner != caller {
            return Err(RegistryError::NotOwner(name.as_str().to_owned()));
        }
        if record.is_claimable(now) {
            // Past the grace period the name is nobody's, including the person
            // who used to hold it.
            return Err(RegistryError::NotFound(name.as_str().to_owned()));
        }
        Ok(record)
    }

    fn skeleton_holder(&self, skeleton: &Skeleton) -> Result<Option<String>, RegistryError> {
        self.store
            .get_decoded::<String>(&StoreKey::alias_skeleton(skeleton.as_str()))
            .map_err(|e| RegistryError::Corrupt(e.to_string()))
    }
}

impl Encode for NameRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        self.owner.encode(out);
        self.registered_at.encode(out);
        self.expires_at.encode(out);
    }
}

impl Decode for NameRecord {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            owner: Address::decode(r)?,
            registered_at: Height::decode(r)?,
            expires_at: Height::decode(r)?,
        })
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

    fn name(s: &str) -> Username {
        Username::new(s).expect("valid name")
    }

    #[test]
    fn a_name_can_be_registered_and_resolved() {
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);

        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");

        let record = registry
            .get(&name("amina"))
            .expect("reads")
            .expect("exists");
        assert_eq!(record.owner, addr(1));
        assert_eq!(record.registered_at, Height(100));
    }

    #[test]
    fn a_taken_name_cannot_be_registered_twice() {
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");

        assert_eq!(
            registry.register(&name("amina"), addr(2), Height(200)),
            Err(RegistryError::Taken("amina".to_owned()))
        );
    }

    #[test]
    fn a_confusable_name_cannot_be_registered() {
        // The attack: register something that renders like an existing name and
        // collect payments meant for its owner.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");

        for lookalike in ["arnina", "am1na", "am-ina", "amlna"] {
            assert!(
                matches!(
                    registry.register(&name(lookalike), addr(2), Height(200)),
                    Err(RegistryError::Confusable { .. })
                ),
                "{lookalike} must be refused"
            );
        }
    }

    #[test]
    fn an_unrelated_name_is_unaffected_by_the_skeleton_index() {
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");

        registry
            .register(&name("kwame"), addr(2), Height(100))
            .expect("an unrelated name must still be registrable");
    }

    #[test]
    fn only_the_owner_can_renew_or_transfer() {
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");

        assert_eq!(
            registry.renew(&name("amina"), addr(66), Height(200)),
            Err(RegistryError::NotOwner("amina".to_owned()))
        );
        assert_eq!(
            registry.transfer(&name("amina"), addr(66), addr(66), Height(200)),
            Err(RegistryError::NotOwner("amina".to_owned()))
        );
    }

    #[test]
    fn renewing_early_extends_rather_than_resets() {
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");
        let before = registry.get(&name("amina")).unwrap().unwrap().expires_at;

        registry
            .renew(&name("amina"), addr(1), Height(200))
            .expect("renews");
        let after = registry.get(&name("amina")).unwrap().unwrap().expires_at;

        assert_eq!(after.0, before.0 + REGISTRATION_BLOCKS);
    }

    #[test]
    fn a_lapsed_name_is_protected_during_the_grace_period() {
        // Missing a renewal by a day must not cost someone their payment
        // identity to a bot watching the expiry queue.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(0))
            .expect("registers");

        let just_expired = Height(REGISTRATION_BLOCKS + 1);
        assert!(
            registry
                .get(&name("amina"))
                .unwrap()
                .unwrap()
                .is_expired(just_expired)
        );
        assert_eq!(
            registry.register(&name("amina"), addr(2), just_expired),
            Err(RegistryError::Taken("amina".to_owned())),
            "grace period must block a new registrant"
        );

        // The original owner can still rescue it.
        registry
            .renew(&name("amina"), addr(1), just_expired)
            .expect("owner renews during grace");
    }

    #[test]
    fn an_expired_name_can_be_reregistered_by_someone_else() {
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(0))
            .expect("registers");

        let after_grace = Height(REGISTRATION_BLOCKS + GRACE_BLOCKS + 1);
        registry
            .register(&name("amina"), addr(2), after_grace)
            .expect("claimable after grace");

        assert_eq!(
            registry.get(&name("amina")).unwrap().unwrap().owner,
            addr(2)
        );
    }

    #[test]
    fn an_abandoned_name_does_not_sterilise_its_skeleton_forever() {
        // If it did, every expired name would permanently block a family of
        // lookalikes, and the namespace would shrink with every lapse.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(0))
            .expect("registers");

        let after_grace = Height(REGISTRATION_BLOCKS + GRACE_BLOCKS + 1);
        registry
            .register(&name("arnina"), addr(2), after_grace)
            .expect("lookalike becomes available once the original is claimable");
    }

    #[test]
    fn a_display_name_does_not_survive_a_transfer() {
        // Otherwise a wallet keeps showing @amina for an address that no longer
        // controls it — a free impersonation.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");
        registry
            .set_primary(&name("amina"), addr(1), Height(100))
            .expect("sets primary");
        assert_eq!(
            registry.primary_name(&addr(1)).unwrap().as_deref(),
            Some("amina")
        );

        registry
            .transfer(&name("amina"), addr(1), addr(2), Height(200))
            .expect("transfers");

        assert_eq!(registry.primary_name(&addr(1)).unwrap(), None);
        assert_eq!(
            registry.get(&name("amina")).unwrap().unwrap().owner,
            addr(2)
        );
    }

    // -- Pseudonymity ------------------------------------------------------
    //
    // A username is a self-chosen handle pointing at an address. It is not an
    // identity, and nothing in this crate ever asks who the holder is. These
    // tests pin that down, because it is the kind of property that erodes
    // silently when someone later adds a "convenient" field.

    #[test]
    fn a_name_record_says_nothing_about_who_holds_it() {
        // The entire stored record is an address, two heights, and no third
        // thing. There is nowhere for a legal name, a document or a country to
        // be added without this test failing.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");

        let record = registry.get(&name("amina")).unwrap().unwrap();
        assert_eq!(
            record,
            NameRecord {
                owner: addr(1),
                registered_at: Height(100),
                expires_at: Height(100 + REGISTRATION_BLOCKS),
            }
        );
    }

    #[test]
    fn registering_a_name_does_not_publish_a_reverse_link() {
        // Forward lookup is what a payer needs. The reverse link is a
        // disclosure, so it must never be a side effect of registering.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");

        assert_eq!(
            registry.primary_name(&addr(1)).expect("reads"),
            None,
            "an address must stay unlisted until its holder chooses otherwise"
        );
    }

    #[test]
    fn a_holder_can_unlink_their_address_from_their_name() {
        // Without this, opting in to a display name would be irreversible, and
        // an irreversible disclosure is not a choice.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");
        registry
            .set_primary(&name("amina"), addr(1), Height(100))
            .expect("opts in");
        assert_eq!(
            registry.primary_name(&addr(1)).unwrap().as_deref(),
            Some("amina")
        );

        assert!(registry.clear_primary(&addr(1)), "an entry was removed");
        assert_eq!(registry.primary_name(&addr(1)).unwrap(), None);

        // Unlisted, not unpayable: the name still resolves forward.
        assert_eq!(
            registry.get(&name("amina")).unwrap().unwrap().owner,
            addr(1)
        );
    }

    #[test]
    fn one_person_can_hold_several_addresses_and_name_only_one() {
        // The compartmentalisation property. A trader publishes @duka for the
        // shop and keeps a separate unnamed address for everything else; the
        // chain cannot associate them.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("duka-la-amina"), addr(1), Height(100))
            .expect("registers");
        registry
            .set_primary(&name("duka-la-amina"), addr(1), Height(100))
            .expect("opts in");

        assert_eq!(
            registry.primary_name(&addr(2)).expect("reads"),
            None,
            "a second address must not inherit the first's name"
        );
    }

    #[test]
    fn a_released_name_leaves_nothing_behind() {
        // For someone who wants no on-chain handle at all. The skeleton entry
        // has to go too, or an abandoned name would keep blocking lookalikes
        // forever and quietly shrink the namespace.
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");
        registry
            .set_primary(&name("amina"), addr(1), Height(100))
            .expect("opts in");

        registry
            .release(&name("amina"), addr(1), Height(200))
            .expect("releases");

        assert_eq!(registry.get(&name("amina")).expect("reads"), None);
        assert_eq!(registry.primary_name(&addr(1)).expect("reads"), None);

        // And somebody else may now take it, or a name resembling it.
        registry
            .register(&name("arnina"), addr(2), Height(300))
            .expect("the skeleton was freed too");
    }

    #[test]
    fn a_stranger_cannot_release_or_unlist_someone_else() {
        let mut store = MemoryStore::new();
        let mut registry = Registry::new(&mut store);
        registry
            .register(&name("amina"), addr(1), Height(100))
            .expect("registers");
        registry
            .set_primary(&name("amina"), addr(1), Height(100))
            .expect("opts in");

        assert_eq!(
            registry.release(&name("amina"), addr(66), Height(200)),
            Err(RegistryError::NotOwner("amina".to_owned()))
        );
        // clear_primary only ever touches the caller's own entry.
        assert!(!registry.clear_primary(&addr(66)));
        assert_eq!(
            registry.primary_name(&addr(1)).unwrap().as_deref(),
            Some("amina")
        );
    }

    #[test]
    fn a_name_that_was_never_registered_resolves_to_nothing() {
        let mut store = MemoryStore::new();
        let registry = Registry::new(&mut store);
        assert_eq!(registry.get(&name("nobody")).expect("reads"), None);
    }
}
