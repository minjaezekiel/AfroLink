//! The keyspace layout and the storage trait modules are written against.
//!
//! Keys are namespaced by a single-byte prefix so that modules cannot collide,
//! and so a range scan over one module's data is cheap. The prefix is part of
//! consensus: changing it changes every state root.

use afrolink_crypto::hash::Hash32;
use afrolink_primitives::{Denom, codec::Encode};
use thiserror::Error;

use crate::smt::{Proof, SparseMerkleTree};

/// Errors from state access.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StateError {
    /// A stored value did not decode, meaning the database is corrupt or was
    /// written by an incompatible version.
    #[error("corrupt state at key {key}: {reason}")]
    Corrupt {
        /// Hex of the offending key.
        key: String,
        /// Decoder message.
        reason: String,
    },
}

/// Namespace prefixes. Never reuse or renumber a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Namespace {
    /// Account metadata: nonce, and the public key once first revealed.
    Account = 0x01,
    /// Token balances, keyed by (address, denom).
    Balance = 0x02,
    /// Total supply per denom.
    Supply = 0x03,
    /// Sovereign stablecoin issuer registry.
    Issuer = 0x04,
    /// Validator records.
    Validator = 0x05,
    /// Delegation records, keyed by (delegator, validator).
    Delegation = 0x06,
    /// Governance parameters.
    Params = 0x07,
    /// Smart-contract code and instance storage.
    Contract = 0x08,
    /// Accounts frozen by a sovereign issuer, keyed by (denom, address).
    ///
    /// Scoped to a single denom on purpose: an issuer may freeze its own
    /// stablecoin for an account and can never touch AFRI, another country's
    /// currency, or anything else that account holds.
    Frozen = 0x09,
}

/// A namespaced state key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreKey(Vec<u8>);

impl StoreKey {
    /// Build a key in `ns` from raw parts.
    ///
    /// Each part is length-prefixed so that `("ab", "c")` and `("a", "bc")`
    /// cannot produce the same key — a classic way to make one account's data
    /// readable as another's.
    #[must_use]
    pub fn new(ns: Namespace, parts: &[&[u8]]) -> Self {
        let mut out = vec![ns as u8];
        for part in parts {
            afrolink_primitives::codec::encode_bytes(part, &mut out);
        }
        Self(out)
    }

    /// The key for an account's balance in one denomination.
    #[must_use]
    pub fn balance(address: &afrolink_crypto::Address, denom: &Denom) -> Self {
        Self::new(
            Namespace::Balance,
            &[address.as_bytes(), denom.as_str().as_bytes()],
        )
    }

    /// The key for an account record.
    #[must_use]
    pub fn account(address: &afrolink_crypto::Address) -> Self {
        Self::new(Namespace::Account, &[address.as_bytes()])
    }

    /// The key for a denomination's total supply.
    #[must_use]
    pub fn supply(denom: &Denom) -> Self {
        Self::new(Namespace::Supply, &[denom.as_str().as_bytes()])
    }

    /// The key for a sovereign issuer's authorisation record.
    #[must_use]
    pub fn issuer(denom: &Denom) -> Self {
        Self::new(Namespace::Issuer, &[denom.as_str().as_bytes()])
    }

    /// The key recording that `address` is frozen for `denom`.
    #[must_use]
    pub fn frozen(denom: &Denom, address: &afrolink_crypto::Address) -> Self {
        Self::new(
            Namespace::Frozen,
            &[denom.as_str().as_bytes(), address.as_bytes()],
        )
    }

    /// The raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The interface state-touching modules are written against.
///
/// Keeping modules behind this trait means the same logic runs over the
/// in-memory tree in tests and over a disk-backed tree in production, with no
/// conditional compilation in consensus code.
pub trait KeyValueStore {
    /// Read a value.
    fn get(&self, key: &StoreKey) -> Option<Vec<u8>>;

    /// Write a value.
    fn set(&mut self, key: &StoreKey, value: Vec<u8>);

    /// Delete a value, returning whether it existed.
    fn delete(&mut self, key: &StoreKey) -> bool;

    /// The authenticated root over all current entries.
    fn root(&self) -> Hash32;

    /// Read a value together with a proof of the result, including absence.
    fn get_with_proof(&self, key: &StoreKey) -> (Option<Vec<u8>>, Proof);

    /// Read and decode a typed value.
    ///
    /// # Errors
    /// Returns [`StateError::Corrupt`] if stored bytes do not decode.
    fn get_decoded<T: afrolink_primitives::codec::Decode>(
        &self,
        key: &StoreKey,
    ) -> Result<Option<T>, StateError> {
        match self.get(key) {
            None => Ok(None),
            Some(bytes) => afrolink_primitives::codec::decode_exact::<T>(&bytes)
                .map(Some)
                .map_err(|e| StateError::Corrupt {
                    key: hex_of(key.as_bytes()),
                    reason: e.to_string(),
                }),
        }
    }

    /// Encode and write a typed value.
    fn set_encoded<T: Encode>(&mut self, key: &StoreKey, value: &T) {
        self.set(key, value.to_bytes());
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An in-memory store backed by the sparse Merkle tree.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    tree: SparseMerkleTree,
}

impl MemoryStore {
    /// A fresh empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// The underlying tree, for persistence.
    #[must_use]
    pub fn tree(&self) -> &SparseMerkleTree {
        &self.tree
    }

    /// Wrap an already-built tree, as reconstructed from persisted nodes.
    #[must_use]
    pub fn from_tree(tree: SparseMerkleTree) -> Self {
        Self { tree }
    }
}

impl KeyValueStore for MemoryStore {
    fn get(&self, key: &StoreKey) -> Option<Vec<u8>> {
        self.tree.get(key.as_bytes()).cloned()
    }

    fn set(&mut self, key: &StoreKey, value: Vec<u8>) {
        self.tree.insert(key.as_bytes(), value);
    }

    fn delete(&mut self, key: &StoreKey) -> bool {
        self.tree.remove(key.as_bytes())
    }

    fn root(&self) -> Hash32 {
        self.tree.root()
    }

    fn get_with_proof(&self, key: &StoreKey) -> (Option<Vec<u8>>, Proof) {
        (self.get(key), self.tree.prove(key.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::{Address, SecretKey};
    use afrolink_primitives::Amount;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    #[test]
    fn namespaces_keep_modules_apart() {
        let a = StoreKey::new(Namespace::Balance, &[b"x"]);
        let b = StoreKey::new(Namespace::Supply, &[b"x"]);
        assert_ne!(a, b);
    }

    #[test]
    fn key_parts_are_length_prefixed() {
        // ("ab","c") and ("a","bc") must not collide, or one account's balance
        // could be read or written as another's.
        let a = StoreKey::new(Namespace::Balance, &[b"ab", b"c"]);
        let b = StoreKey::new(Namespace::Balance, &[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn typed_round_trip_through_the_store() {
        let mut store = MemoryStore::new();
        let key = StoreKey::balance(&addr(1), &Denom::native());
        store.set_encoded(&key, &Amount::from_afri(250));
        assert_eq!(
            store.get_decoded::<Amount>(&key).expect("decodes"),
            Some(Amount::from_afri(250))
        );
    }

    #[test]
    fn corrupt_bytes_are_reported_not_panicked_on() {
        let mut store = MemoryStore::new();
        let key = StoreKey::balance(&addr(1), &Denom::native());
        store.set(&key, vec![0x01, 0x02]); // too short for a u128
        assert!(matches!(
            store.get_decoded::<Amount>(&key),
            Err(StateError::Corrupt { .. })
        ));
    }

    #[test]
    fn a_light_client_can_verify_a_balance_it_was_told() {
        let mut store = MemoryStore::new();
        let alice = addr(1);
        let key = StoreKey::balance(&alice, &Denom::native());
        store.set_encoded(&key, &Amount::from_afri(1_000));

        // The phone holds only this 32-byte root, from a block header.
        let root = store.root();

        let (value, proof) = store.get_with_proof(&key);
        let value = value.expect("balance present");
        assert!(proof.verify(root, key.as_bytes(), Some(&value)));

        // And an inflated balance from a dishonest server does not verify.
        let lie = Amount::from_afri(1_000_000).to_bytes();
        assert!(!proof.verify(root, key.as_bytes(), Some(&lie)));
    }

    #[test]
    fn absence_of_an_unfunded_account_is_provable() {
        let mut store = MemoryStore::new();
        store.set_encoded(
            &StoreKey::balance(&addr(1), &Denom::native()),
            &Amount::from_afri(5),
        );
        let root = store.root();

        let missing = StoreKey::balance(&addr(2), &Denom::native());
        let (value, proof) = store.get_with_proof(&missing);
        assert!(value.is_none());
        assert!(proof.verify(root, missing.as_bytes(), None));
    }

    #[test]
    fn deleting_a_key_changes_the_root() {
        let mut store = MemoryStore::new();
        let key = StoreKey::balance(&addr(1), &Denom::native());
        let empty = store.root();
        store.set_encoded(&key, &Amount::from_afri(1));
        assert_ne!(empty, store.root());
        assert!(store.delete(&key));
        assert_eq!(empty, store.root());
    }
}
