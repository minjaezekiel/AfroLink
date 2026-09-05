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
use std::sync::Arc;

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

/// A node of the tree, shared between versions.
///
/// # Why the structure is stored rather than recomputed
///
/// This was a flat `BTreeMap<Hash32, Vec<u8>>` and every call to [`root`] or
/// [`prove`] rebuilt the whole tree from every entry. That made **changing one
/// balance cost the same as rebuilding the entire state**: measured at 63ms for
/// one write against 100 000 accounts, against 0.8ms at 1 000 — linear in the
/// state, on a path taken at least twice per block. A payments network for a
/// continent cannot have a per-block cost proportional to how many people have
/// signed up.
///
/// Keeping the nodes, with each one's hash cached, turns that into work
/// proportional to what changed:
///
/// | operation | before | after |
/// |---|---|---|
/// | [`root`] | `O(n)` hashes | `O(1)`, cached |
/// | [`insert`] / [`remove`] | `O(1)` + an `O(n)` root | `O(log n)` |
/// | [`prove`] | `O(n)` | `O(log n)` |
/// | `clone` | `O(n)` deep copy | `O(1)` refcount |
/// | [`crate::nodes::commit_tree`] | `O(n)` hashes | `O(changed · log n)` |
///
/// [`root`]: SparseMerkleTree::root
/// [`prove`]: SparseMerkleTree::prove
/// [`insert`]: SparseMerkleTree::insert
/// [`remove`]: SparseMerkleTree::remove
///
/// # Structural sharing is what makes a version cheap
///
/// Children are held behind [`Arc`], so inserting rebuilds only the path from
/// the changed leaf to the root — every untouched subtree is *the same
/// allocation*, shared with the previous version. That is what
/// [ADR-0006](../../../docs/adr/0006-state-persistence-and-retention.md) already
/// claimed the persistence layer got from content addressing; the in-memory tree
/// now gets it too, and for the same reason. It is also why `MemoryStore` can be
/// cloned per commit — which the daemon does — without copying the state.
///
/// # The hashing is unchanged, deliberately
///
/// Every rule is exactly as it was: an empty subtree is [`EMPTY`], a subtree of
/// one entry collapses to that leaf whatever its depth, and anything else is
/// `node(left, right)`. Roots are byte-identical to the flat implementation's,
/// which is what lets the existing suite stand as the proof of correctness
/// rather than being rewritten alongside the thing it checks. A differential
/// test drives both against the same random operations and compares roots and
/// proofs at every step.
#[derive(Debug)]
enum TreeNode {
    /// One key's path hash bound to its value.
    Leaf {
        key: Hash32,
        value: Vec<u8>,
        hash: Hash32,
    },
    /// A branch. Holds **at least two** entries beneath it, always: a branch
    /// that would hold fewer is collapsed on removal, which is what keeps the
    /// tree in the one canonical shape the hashing assumes.
    Internal {
        left: Link,
        right: Link,
        hash: Hash32,
        len: usize,
    },
}

/// A child, absent when that side of the tree holds nothing.
type Link = Option<Arc<TreeNode>>;

/// The hash of a possibly-absent subtree.
fn link_hash(link: &Link) -> Hash32 {
    link.as_ref().map_or(EMPTY, |node| node.hash())
}

/// How many entries a possibly-absent subtree holds.
fn link_len(link: &Link) -> usize {
    link.as_ref().map_or(0, |node| node.len())
}

impl TreeNode {
    fn hash(&self) -> Hash32 {
        match self {
            Self::Leaf { hash, .. } | Self::Internal { hash, .. } => *hash,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Leaf { .. } => 1,
            Self::Internal { len, .. } => *len,
        }
    }

    fn leaf(key: Hash32, value: Vec<u8>) -> Arc<Self> {
        let hash = leaf_hash(key, &value);
        Arc::new(Self::Leaf { key, value, hash })
    }

    fn internal(left: Link, right: Link) -> Arc<Self> {
        let hash = node_hash(link_hash(&left), link_hash(&right));
        let len = link_len(&left).saturating_add(link_len(&right));
        Arc::new(Self::Internal {
            left,
            right,
            hash,
            len,
        })
    }
}

/// Put `key` into `link` at `depth`, returning the new subtree.
///
/// `added` is set when the key was not already present, so the caller can keep
/// its count without walking the tree.
fn insert_at(link: &Link, key: Hash32, value: Vec<u8>, depth: usize, added: &mut bool) -> Link {
    match link.as_deref() {
        None => {
            *added = true;
            Some(TreeNode::leaf(key, value))
        }
        Some(TreeNode::Leaf {
            key: existing,
            value: existing_value,
            ..
        }) => {
            if *existing == key {
                return Some(TreeNode::leaf(key, value));
            }
            // Two distinct keys sharing all 256 bits is a BLAKE3 collision. The
            // tree cannot represent both, and the flat implementation returned
            // `EMPTY` for that subtree; neither is a real outcome, so take the
            // one that at least keeps the newer write.
            if depth >= MAX_PROOF_DEPTH {
                return Some(TreeNode::leaf(key, value));
            }
            *added = true;
            let existing_leaf = TreeNode::leaf(*existing, existing_value.clone());
            let new_leaf = TreeNode::leaf(key, value);
            Some(split(existing_leaf, *existing, new_leaf, key, depth))
        }
        Some(TreeNode::Internal { left, right, .. }) => {
            if depth >= MAX_PROOF_DEPTH {
                return link.clone();
            }
            let next = depth.saturating_add(1);
            if key.bit(depth) {
                let rebuilt = insert_at(right, key, value, next, added);
                Some(TreeNode::internal(left.clone(), rebuilt))
            } else {
                let rebuilt = insert_at(left, key, value, next, added);
                Some(TreeNode::internal(rebuilt, right.clone()))
            }
        }
    }
}

/// Branch two leaves apart, starting at `depth`.
///
/// Walks down creating single-child branches for as long as the two paths agree,
/// then puts one leaf on each side. Only the differing prefix costs nodes, which
/// is why the tree stays `O(log n)` deep for random keys.
fn split(
    a: Arc<TreeNode>,
    a_key: Hash32,
    b: Arc<TreeNode>,
    b_key: Hash32,
    depth: usize,
) -> Arc<TreeNode> {
    if depth >= MAX_PROOF_DEPTH {
        return b;
    }
    let a_bit = a_key.bit(depth);
    let b_bit = b_key.bit(depth);
    if a_bit == b_bit {
        let deeper = split(a, a_key, b, b_key, depth.saturating_add(1));
        return if a_bit {
            TreeNode::internal(None, Some(deeper))
        } else {
            TreeNode::internal(Some(deeper), None)
        };
    }
    if a_bit {
        TreeNode::internal(Some(b), Some(a))
    } else {
        TreeNode::internal(Some(a), Some(b))
    }
}

/// Take `key` out of `link` at `depth`, returning the new subtree.
fn remove_at(link: &Link, key: Hash32, depth: usize, removed: &mut bool) -> Link {
    match link.as_deref() {
        None => None,
        Some(TreeNode::Leaf { key: existing, .. }) => {
            if *existing == key {
                *removed = true;
                None
            } else {
                link.clone()
            }
        }
        Some(TreeNode::Internal { left, right, .. }) => {
            if depth >= MAX_PROOF_DEPTH {
                return link.clone();
            }
            let next = depth.saturating_add(1);
            let (rebuilt_left, rebuilt_right) = if key.bit(depth) {
                (left.clone(), remove_at(right, key, next, removed))
            } else {
                (remove_at(left, key, next, removed), right.clone())
            };
            collapse(rebuilt_left, rebuilt_right)
        }
    }
}

/// Rebuild a branch, collapsing it if it no longer holds two entries.
///
/// **The invariant the hashing depends on.** A subtree of one entry hashes as
/// that leaf, at whatever depth it sits — so a branch left holding a single leaf
/// after a removal must *become* that leaf, or the tree would hash differently
/// from a tree built by inserting the same keys in another order. Getting this
/// wrong would not corrupt anything visibly; it would make two honest nodes
/// disagree on the app hash after one of them happened to delete a key.
fn collapse(left: Link, right: Link) -> Link {
    match (&left, &right) {
        (None, None) => None,
        (Some(only), None) | (None, Some(only)) if matches!(**only, TreeNode::Leaf { .. }) => {
            Some(Arc::clone(only))
        }
        _ => Some(TreeNode::internal(left, right)),
    }
}

/// Find `key` in `link`.
fn get_at(link: &Link, key: Hash32, depth: usize) -> Option<&Vec<u8>> {
    match link.as_deref() {
        None => None,
        Some(TreeNode::Leaf {
            key: existing,
            value,
            ..
        }) => (*existing == key).then_some(value),
        Some(TreeNode::Internal { left, right, .. }) => {
            if depth >= MAX_PROOF_DEPTH {
                return None;
            }
            let next = depth.saturating_add(1);
            if key.bit(depth) {
                get_at(right, key, next)
            } else {
                get_at(left, key, next)
            }
        }
    }
}

/// An in-memory compact sparse Merkle tree.
///
/// See [`TreeNode`] for why the structure is kept rather than recomputed.
#[derive(Debug, Clone, Default)]
pub struct SparseMerkleTree {
    root: Link,
    len: usize,
}

impl SparseMerkleTree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the tree holds no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert or overwrite `key`.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        self.insert_hashed(key_hash(key), value);
    }

    /// Insert under an already-hashed path, for reconstruction.
    fn insert_hashed(&mut self, key: Hash32, value: Vec<u8>) {
        let mut added = false;
        self.root = insert_at(&self.root, key, value, 0, &mut added);
        if added {
            self.len = self.len.saturating_add(1);
        }
    }

    /// Remove `key`, returning whether it was present.
    pub fn remove(&mut self, key: &[u8]) -> bool {
        let mut removed = false;
        self.root = remove_at(&self.root, key_hash(key), 0, &mut removed);
        if removed {
            self.len = self.len.saturating_sub(1);
        }
        removed
    }

    /// Look up `key`.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        get_at(&self.root, key_hash(key), 0)
    }

    /// Iterate entries as `(path hash, value)`, in canonical order.
    ///
    /// An in-order walk, which visits leaves in path-hash order because the tree
    /// branches on successive bits of that hash — the same order the flat
    /// `BTreeMap` produced, which several callers depend on.
    pub fn entries(&self) -> Entries<'_> {
        Entries::new(self.root.as_deref())
    }

    /// Build a tree directly from already-hashed entries.
    ///
    /// The counterpart of [`Self::entries`], used when reconstructing a tree
    /// from persisted nodes. Keys are already path hashes, so they are not
    /// re-hashed.
    #[must_use]
    pub fn from_entries(entries: BTreeMap<Hash32, Vec<u8>>) -> Self {
        let mut tree = Self::new();
        for (key, value) in entries {
            tree.insert_hashed(key, value);
        }
        tree
    }

    /// The current root hash.
    ///
    /// `O(1)`: every node caches its own hash, so this reads the top one.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        link_hash(&self.root)
    }

    /// The root node, for the persistence layer to walk.
    #[must_use]
    pub fn root_node(&self) -> Option<NodeRef<'_>> {
        self.root.as_deref().map(NodeRef)
    }

    /// Build a proof for `key`, whether present or absent.
    #[must_use]
    pub fn prove(&self, key: &[u8]) -> Proof {
        let kh = key_hash(key);
        let mut siblings = Vec::new();
        let mut current = self.root.as_deref();
        let mut depth = 0usize;
        let leaf = loop {
            match current {
                None => break ProofLeaf::Absent,
                Some(TreeNode::Leaf { key: k, value, .. }) => {
                    break if *k == kh {
                        ProofLeaf::Present {
                            value: value.clone(),
                        }
                    } else {
                        ProofLeaf::AbsentOccupied {
                            other_key_hash: *k,
                            other_value: value.clone(),
                        }
                    };
                }
                Some(TreeNode::Internal { left, right, .. }) => {
                    if depth >= MAX_PROOF_DEPTH {
                        break ProofLeaf::Absent;
                    }
                    if kh.bit(depth) {
                        siblings.push(link_hash(left));
                        current = right.as_deref();
                    } else {
                        siblings.push(link_hash(right));
                        current = left.as_deref();
                    }
                    depth = depth.saturating_add(1);
                }
            }
        };
        Proof { siblings, leaf }
    }
}

/// A borrowed view of one node, for the persistence layer.
///
/// Exposed so [`crate::nodes`] can walk the real structure — and stop walking
/// wherever the store already holds a hash — without this module knowing what a
/// database is.
#[derive(Debug, Clone, Copy)]
pub struct NodeRef<'a>(&'a TreeNode);

/// What a [`NodeRef`] turned out to be.
#[derive(Debug)]
pub enum NodeKind<'a> {
    /// One key bound to one value.
    Leaf {
        /// The key's path hash.
        key_hash: Hash32,
        /// The stored value.
        value: &'a [u8],
    },
    /// A branch and its two sides, either of which may be empty.
    Internal {
        /// The left subtree.
        left: Option<NodeRef<'a>>,
        /// The right subtree.
        right: Option<NodeRef<'a>>,
    },
}

impl<'a> NodeRef<'a> {
    /// This node's cached hash.
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        self.0.hash()
    }

    /// What kind of node this is.
    #[must_use]
    pub fn kind(&self) -> NodeKind<'a> {
        match self.0 {
            TreeNode::Leaf { key, value, .. } => NodeKind::Leaf {
                key_hash: *key,
                value,
            },
            TreeNode::Internal { left, right, .. } => NodeKind::Internal {
                left: left.as_deref().map(NodeRef),
                right: right.as_deref().map(NodeRef),
            },
        }
    }
}

/// An in-order walk over a tree's entries.
pub struct Entries<'a> {
    stack: Vec<&'a TreeNode>,
}

impl<'a> Entries<'a> {
    fn new(root: Option<&'a TreeNode>) -> Self {
        let mut walk = Self { stack: Vec::new() };
        if let Some(node) = root {
            walk.stack.push(node);
        }
        walk
    }
}

impl<'a> Iterator for Entries<'a> {
    type Item = (Hash32, &'a Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                TreeNode::Leaf { key, value, .. } => return Some((*key, value)),
                TreeNode::Internal { left, right, .. } => {
                    // Right first, so the left side comes off the stack first
                    // and leaves arrive in ascending path-hash order.
                    if let Some(r) = right.as_deref() {
                        self.stack.push(r);
                    }
                    if let Some(l) = left.as_deref() {
                        self.stack.push(l);
                    }
                }
            }
        }
        None
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
