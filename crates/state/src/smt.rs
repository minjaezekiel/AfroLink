//! A compact sparse Merkle tree.
//!
//! Conceptually the tree has `2^256` slots, one per hashed key. Storing that is
//! obviously impossible, so the tree is *compacted*: any subtree containing a
//! single entry collapses to one leaf node, and any empty subtree collapses to a
//! constant. Proof length is therefore `O(log n)` in the number of entries
//! actually present — typically 20–30 hashes — not 256.
//!
//! # Node hashing
//!
//! ```text
//! empty        = 0x00…00                       (a fixed constant)
//! leaf(k, v)   = H_leaf( key_hash || value_hash )
//! node(l, r)   = H_node( left     || right     )
//! ```
//!
//! Leaves commit to the **key** as well as the value. Without that, a proof for
//! key A could be replayed as a proof for key B whose path happens to overlap,
//! which would let a server show a wallet somebody else's balance.

use afrolink_crypto::hash::{Domain, Hash32, hash, hash_parts};
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader, decode_bytes, encode_bytes};
use std::collections::BTreeMap;

/// The deepest a proof can be: one sibling per bit of the 256-bit key hash.
///
/// Real proofs are 20–30 hashes because the tree is compacted. This is the
/// absolute ceiling, and it is enforced when decoding a proof from an untrusted
/// source as well as when verifying one.
pub const MAX_PROOF_DEPTH: usize = 256;

/// The hash of an empty subtree.
///
/// A constant rather than a hash so that empty subtrees cost nothing to
/// recognise, and so a leaf can never accidentally equal one.
pub const EMPTY: Hash32 = Hash32::from_bytes([0u8; 32]);

/// Hash of a leaf binding a key to a value.
#[must_use]
pub fn leaf_hash(key_hash: Hash32, value: &[u8]) -> Hash32 {
    let value_hash = hash(Domain::StateLeaf, value);
    hash_parts(
        Domain::StateLeaf,
        &[key_hash.as_bytes(), value_hash.as_bytes()],
    )
}

/// Hash of an internal node.
#[must_use]
pub fn node_hash(left: Hash32, right: Hash32) -> Hash32 {
    hash_parts(Domain::StateNode, &[left.as_bytes(), right.as_bytes()])
}

/// Map a raw key to its 256-bit path through the tree.
#[must_use]
pub fn key_hash(key: &[u8]) -> Hash32 {
    hash(Domain::StateLeaf, key)
}

/// What a proof terminates in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofLeaf {
    /// The queried key is present with this value.
    Present {
        /// The committed value.
        value: Vec<u8>,
    },
    /// The path ends in an empty subtree, so the key is absent.
    Absent,
    /// The path ends in a *different* key's leaf, so the queried key is absent.
    ///
    /// This happens when the two keys share a prefix: the other leaf occupies
    /// the slot our key would have descended into.
    AbsentOccupied {
        /// The colliding key's path hash.
        other_key_hash: Hash32,
        /// The colliding leaf's committed value.
        other_value: Vec<u8>,
    },
}

/// A membership or non-membership proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Sibling hashes ordered from the root downward.
    pub siblings: Vec<Hash32>,
    /// The terminal node.
    pub leaf: ProofLeaf,
}

impl Proof {
    /// Recompute the root this proof implies for `key`.
    ///
    /// Returns `None` if the proof is malformed — for example an
    /// [`ProofLeaf::AbsentOccupied`] whose "other" key does not actually share
    /// the queried key's prefix, which would otherwise let a server deny the
    /// existence of an account that is in fact funded.
    #[must_use]
    pub fn compute_root(&self, key: &[u8]) -> Option<Hash32> {
        let kh = key_hash(key);
        let depth = self.siblings.len();
        if depth > MAX_PROOF_DEPTH {
            return None;
        }

        let mut acc = match &self.leaf {
            ProofLeaf::Present { value } => leaf_hash(kh, value),
            ProofLeaf::Absent => EMPTY,
            ProofLeaf::AbsentOccupied {
                other_key_hash,
                other_value,
            } => {
                if *other_key_hash == kh {
                    // Claiming absence while presenting our own key is a lie.
                    return None;
                }
                if !shares_prefix(&kh, other_key_hash, depth) {
                    // The other leaf is not on our path, so it proves nothing
                    // about our key.
                    return None;
                }
                leaf_hash(*other_key_hash, other_value)
            }
        };

        for level in (0..depth).rev() {
            let sibling = *self.siblings.get(level)?;
            acc = if kh.bit(level) {
                node_hash(sibling, acc)
            } else {
                node_hash(acc, sibling)
            };
        }
        Some(acc)
    }

    /// Verify that `key` maps to `expected` under `root`.
    ///
    /// `expected` is `None` to assert absence.
    #[must_use]
    pub fn verify(&self, root: Hash32, key: &[u8], expected: Option<&[u8]>) -> bool {
        let matches_claim = match (&self.leaf, expected) {
            (ProofLeaf::Present { value }, Some(want)) => value.as_slice() == want,
            (ProofLeaf::Absent | ProofLeaf::AbsentOccupied { .. }, None) => true,
            _ => false,
        };
        matches_claim && self.compute_root(key) == Some(root)
    }
}

fn shares_prefix(a: &Hash32, b: &Hash32, bits: usize) -> bool {
    (0..bits).all(|i| a.bit(i) == b.bit(i))
}

/// An in-memory compact sparse Merkle tree.
///
/// Entries are held in a [`BTreeMap`] keyed by path hash, which gives the
/// deterministic ordering the root computation depends on. Two nodes with the
/// same entries always compute the same root regardless of insertion order.
#[derive(Debug, Clone, Default)]
pub struct SparseMerkleTree {
    entries: BTreeMap<Hash32, Vec<u8>>,
}

impl SparseMerkleTree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the tree holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or overwrite `key`.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        self.entries.insert(key_hash(key), value);
    }

    /// Remove `key`, returning whether it was present.
    pub fn remove(&mut self, key: &[u8]) -> bool {
        self.entries.remove(&key_hash(key)).is_some()
    }

    /// Look up `key`.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.entries.get(&key_hash(key))
    }

    /// Iterate entries as `(path hash, value)`, in canonical order.
    ///
    /// Used by [`crate::nodes`] to materialise the tree for persistence.
    pub fn entries(&self) -> impl Iterator<Item = (Hash32, &Vec<u8>)> {
        self.entries.iter().map(|(k, v)| (*k, v))
    }

    /// Build a tree directly from already-hashed entries.
    ///
    /// The counterpart of [`Self::entries`], used when reconstructing a tree
    /// from persisted nodes. Keys are already path hashes, so they are not
    /// re-hashed.
    #[must_use]
    pub fn from_entries(entries: BTreeMap<Hash32, Vec<u8>>) -> Self {
        Self { entries }
    }

    /// The current root hash.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let items: Vec<(Hash32, &Vec<u8>)> = self.entries.iter().map(|(k, v)| (*k, v)).collect();
        Self::root_of(&items, 0)
    }

    fn root_of(items: &[(Hash32, &Vec<u8>)], depth: usize) -> Hash32 {
        match items {
            [] => EMPTY,
            [(k, v)] => leaf_hash(*k, v),
            _ => {
                // Beyond 256 bits two distinct keys cannot be separated, which
                // would mean a BLAKE3 collision. Terminate rather than recurse
                // forever if that ever happens.
                if depth >= 256 {
                    return EMPTY;
                }
                let split = Self::partition_point(items, depth);
                let (left, right) = items.split_at(split);
                // `depth < 256` here, so the increments cannot overflow.
                node_hash(
                    Self::root_of(left, depth.saturating_add(1)),
                    Self::root_of(right, depth.saturating_add(1)),
                )
            }
        }
    }

    /// Index of the first item whose `depth`-th bit is 1.
    ///
    /// Items are sorted by key hash, so all zero-bit keys precede all one-bit
    /// keys at every level and a binary search is valid.
    fn partition_point(items: &[(Hash32, &Vec<u8>)], depth: usize) -> usize {
        items.partition_point(|(k, _)| !k.bit(depth))
    }

    /// Build a proof for `key`, whether present or absent.
    #[must_use]
    pub fn prove(&self, key: &[u8]) -> Proof {
        let kh = key_hash(key);
        let items: Vec<(Hash32, &Vec<u8>)> = self.entries.iter().map(|(k, v)| (*k, v)).collect();
        let mut siblings = Vec::new();
        let leaf = Self::descend(&items, kh, 0, &mut siblings);
        Proof { siblings, leaf }
    }

    fn descend(
        items: &[(Hash32, &Vec<u8>)],
        kh: Hash32,
        depth: usize,
        siblings: &mut Vec<Hash32>,
    ) -> ProofLeaf {
        match items {
            [] => ProofLeaf::Absent,
            [(k, v)] => {
                if *k == kh {
                    ProofLeaf::Present {
                        value: (*v).clone(),
                    }
                } else {
                    ProofLeaf::AbsentOccupied {
                        other_key_hash: *k,
                        other_value: (*v).clone(),
                    }
                }
            }
            _ => {
                if depth >= 256 {
                    return ProofLeaf::Absent;
                }
                let split = Self::partition_point(items, depth);
                let (left, right) = items.split_at(split);
                let next = depth.saturating_add(1);
                if kh.bit(depth) {
                    siblings.push(Self::root_of(left, next));
                    Self::descend(right, kh, next, siblings)
                } else {
                    siblings.push(Self::root_of(right, next));
                    Self::descend(left, kh, next, siblings)
                }
            }
        }
    }
}

impl Encode for ProofLeaf {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Present { value } => {
                out.push(0);
                encode_bytes(value, out);
            }
            Self::Absent => out.push(1),
            Self::AbsentOccupied {
                other_key_hash,
                other_value,
            } => {
                out.push(2);
                other_key_hash.encode(out);
                encode_bytes(other_value, out);
            }
        }
    }
}

impl Decode for ProofLeaf {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Present {
                value: decode_bytes(r)?,
            }),
            1 => Ok(Self::Absent),
            2 => Ok(Self::AbsentOccupied {
                other_key_hash: Hash32::decode(r)?,
                other_value: decode_bytes(r)?,
            }),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "ProofLeaf",
            }),
        }
    }
}

impl Encode for Proof {
    fn encode(&self, out: &mut Vec<u8>) {
        self.siblings.encode(out);
        self.leaf.encode(out);
    }
}

impl Decode for Proof {
    /// # Errors
    /// Rejects a sibling list longer than the tree can produce.
    ///
    /// A proof arrives from an untrusted server, so the length bound is enforced
    /// at decode rather than left to [`Proof::compute_root`]. Without it, a
    /// server could send a multi-gigabyte sibling list and make a phone allocate
    /// it before discovering the proof was nonsense.
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let siblings = Vec::<Hash32>::decode(r)?;
        if siblings.len() > MAX_PROOF_DEPTH {
            return Err(CodecError::Invalid(format!(
                "proof has {} siblings, maximum is {MAX_PROOF_DEPTH}",
                siblings.len()
            )));
        }
        Ok(Self {
            siblings,
            leaf: ProofLeaf::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_with(n: usize) -> SparseMerkleTree {
        let mut t = SparseMerkleTree::new();
        for i in 0..n {
            t.insert(
                format!("account/{i}").as_bytes(),
                format!("balance:{i}").into_bytes(),
            );
        }
        t
    }

    #[test]
    fn membership_proofs_verify_for_every_entry() {
        let t = tree_with(64);
        let root = t.root();
        for i in 0..64 {
            let key = format!("account/{i}");
            let want = format!("balance:{i}").into_bytes();
            let proof = t.prove(key.as_bytes());
            assert!(
                proof.verify(root, key.as_bytes(), Some(&want)),
                "membership proof failed for {key}"
            );
        }
    }

    #[test]
    fn non_membership_proofs_verify() {
        let t = tree_with(32);
        let root = t.root();
        for i in 100..140 {
            let key = format!("account/{i}");
            let proof = t.prove(key.as_bytes());
            assert!(
                proof.verify(root, key.as_bytes(), None),
                "absence proof failed for {key}"
            );
        }
    }

    #[test]
    fn a_server_cannot_forge_a_balance() {
        // The attack this defends against: a wallet asks an untrusted node for
        // its balance, and the node inflates it.
        let t = tree_with(16);
        let root = t.root();
        let key = b"account/3";
        let proof = t.prove(key);
        assert!(proof.verify(root, key, Some(b"balance:3")));
        assert!(!proof.verify(root, key, Some(b"balance:999999")));
    }

    #[test]
    fn a_server_cannot_deny_a_funded_account() {
        let t = tree_with(16);
        let root = t.root();
        let key = b"account/7";
        // Forge an absence proof by taking a real proof for a different key.
        let forged = t.prove(b"account/11");
        assert!(
            !forged.verify(root, key, None),
            "absence of a present key must not verify"
        );
    }

    #[test]
    fn a_proof_for_one_key_does_not_verify_for_another() {
        let t = tree_with(16);
        let root = t.root();
        let proof = t.prove(b"account/3");
        assert!(
            !proof.verify(root, b"account/4", Some(b"balance:3")),
            "leaves must commit to their key"
        );
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        let mut a = SparseMerkleTree::new();
        let mut b = SparseMerkleTree::new();
        for i in 0..40 {
            a.insert(format!("k{i}").as_bytes(), vec![i as u8]);
        }
        for i in (0..40).rev() {
            b.insert(format!("k{i}").as_bytes(), vec![i as u8]);
        }
        assert_eq!(
            a.root(),
            b.root(),
            "consensus depends on order independence"
        );
    }

    #[test]
    fn mutations_change_the_root() {
        let mut t = tree_with(8);
        let before = t.root();
        t.insert(b"account/3", b"balance:tampered".to_vec());
        assert_ne!(before, t.root());
    }

    #[test]
    fn removal_restores_the_previous_root() {
        let mut t = tree_with(8);
        let before = t.root();
        t.insert(b"account/999", b"x".to_vec());
        assert_ne!(before, t.root());
        assert!(t.remove(b"account/999"));
        assert_eq!(before, t.root(), "state roots must be path-independent");
    }

    #[test]
    fn empty_tree_root_is_the_empty_constant() {
        assert_eq!(SparseMerkleTree::new().root(), EMPTY);
    }

    #[test]
    fn single_entry_tree_needs_no_siblings() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"solo", b"v".to_vec());
        let proof = t.prove(b"solo");
        assert!(proof.siblings.is_empty());
        assert!(proof.verify(t.root(), b"solo", Some(b"v")));
    }

    #[test]
    fn proofs_stay_short() {
        // The mobile budget: proofs must be tens of hashes, not 256.
        let t = tree_with(1_000);
        let proof = t.prove(b"account/500");
        assert!(
            proof.siblings.len() < 40,
            "proof was {} hashes",
            proof.siblings.len()
        );
    }
}
