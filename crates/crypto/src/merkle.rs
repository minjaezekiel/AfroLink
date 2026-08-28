//! Binary Merkle trees with inclusion proofs (RFC 6962 shape).
//!
//! Used for the transaction root in each block header, and as the building block
//! that lets a phone verify "my payment is in block N" while holding only the
//! 32-byte header.
//!
//! Two details matter for security:
//!
//! * **Distinct leaf and node domains.** Hashing leaves and internal nodes with
//!   the same function lets an attacker present an internal node as a leaf, so a
//!   proof for a value that was never committed can be forged.
//! * **Split at the largest power of two, never duplicate.** Bitcoin duplicates
//!   the final node when a level has odd width, which makes two different
//!   transaction lists produce the same root (CVE-2012-2459). RFC 6962's uneven
//!   split has no such collision.

use crate::hash::{Domain, Hash32, hash, hash_parts};
use crate::{CryptoError, Result};

/// A Merkle tree over an ordered list of leaves.
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    leaves: Vec<Hash32>,
}

/// An inclusion proof for one leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Index of the proved leaf.
    pub index: usize,
    /// Total number of leaves the proof was built against.
    pub total: usize,
    /// Sibling hashes, ordered from the leaf upward.
    pub siblings: Vec<Hash32>,
}

/// Hash of an empty tree.
#[must_use]
pub fn empty_root() -> Hash32 {
    hash(Domain::MerkleNode, b"")
}

/// Hash a leaf's raw bytes into a leaf node.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash32 {
    hash(Domain::MerkleLeaf, data)
}

fn node_hash(left: Hash32, right: Hash32) -> Hash32 {
    hash_parts(Domain::MerkleNode, &[left.as_bytes(), right.as_bytes()])
}

/// The largest power of two strictly less than `n`. Requires `n >= 2`.
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k.saturating_mul(2) < n {
        k = k.saturating_mul(2);
    }
    k
}

impl MerkleTree {
    /// Build from already-hashed leaves.
    #[must_use]
    pub fn from_leaf_hashes(leaves: Vec<Hash32>) -> Self {
        Self { leaves }
    }

    /// Build from raw leaf payloads, hashing each one.
    #[must_use]
    pub fn from_items<I, T>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        Self {
            leaves: items.into_iter().map(|i| leaf_hash(i.as_ref())).collect(),
        }
    }

    /// Number of leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree has no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The Merkle root.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        Self::root_of(&self.leaves)
    }

    fn root_of(leaves: &[Hash32]) -> Hash32 {
        match leaves {
            [] => empty_root(),
            [only] => *only,
            _ => {
                let k = split_point(leaves.len());
                let (left, right) = leaves.split_at(k);
                node_hash(Self::root_of(left), Self::root_of(right))
            }
        }
    }

    /// Build an inclusion proof for leaf `index`.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidProof`] if `index` is out of range.
    pub fn prove(&self, index: usize) -> Result<MerkleProof> {
        if index >= self.leaves.len() {
            return Err(CryptoError::InvalidProof("leaf index out of range"));
        }
        let mut siblings = Vec::new();
        Self::collect_siblings(&self.leaves, index, &mut siblings);
        Ok(MerkleProof {
            index,
            total: self.leaves.len(),
            siblings,
        })
    }

    fn collect_siblings(leaves: &[Hash32], index: usize, out: &mut Vec<Hash32>) {
        if leaves.len() <= 1 {
            return;
        }
        let k = split_point(leaves.len());
        let (left, right) = leaves.split_at(k);
        if index < k {
            out.push(Self::root_of(right));
            Self::collect_siblings(left, index, out);
        } else {
            out.push(Self::root_of(left));
            Self::collect_siblings(right, index.saturating_sub(k), out);
        }
    }
}

impl MerkleProof {
    /// Recompute the root implied by this proof for `leaf`.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidProof`] if the proof is structurally
    /// inconsistent (bad index, wrong number of siblings).
    pub fn compute_root(&self, leaf: Hash32) -> Result<Hash32> {
        if self.total == 0 || self.index >= self.total {
            return Err(CryptoError::InvalidProof("index out of range for total"));
        }
        // Sibling order was collected top-down; replay it bottom-up.
        let mut acc = leaf;
        let mut siblings = self.siblings.iter().rev();
        let mut frames = Vec::new();
        let (mut idx, mut total) = (self.index, self.total);
        while total > 1 {
            let k = split_point(total);
            if idx < k {
                frames.push(true);
                total = k;
            } else {
                frames.push(false);
                idx = idx.saturating_sub(k);
                total = total.saturating_sub(k);
            }
        }
        if frames.len() != self.siblings.len() {
            return Err(CryptoError::InvalidProof(
                "sibling count does not match tree shape",
            ));
        }
        for on_left in frames.into_iter().rev() {
            let sibling = *siblings
                .next()
                .ok_or(CryptoError::InvalidProof("ran out of siblings"))?;
            acc = if on_left {
                node_hash(acc, sibling)
            } else {
                node_hash(sibling, acc)
            };
        }
        Ok(acc)
    }

    /// Check that `leaf` is committed at [`Self::index`] under `root`.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidProof`] if the recomputed root differs.
    pub fn verify(&self, root: Hash32, leaf: Hash32) -> Result<()> {
        if self.compute_root(leaf)? == root {
            Ok(())
        } else {
            Err(CryptoError::InvalidProof("recomputed root does not match"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(n: usize) -> MerkleTree {
        MerkleTree::from_items((0..n).map(|i| format!("tx-{i}")))
    }

    #[test]
    fn every_leaf_proves_against_the_root_at_many_sizes() {
        // Odd sizes are where naive implementations break, so sweep them.
        for n in 1..=33 {
            let t = tree(n);
            let root = t.root();
            for i in 0..n {
                let proof = t.prove(i).expect("index in range");
                let leaf = leaf_hash(format!("tx-{i}").as_bytes());
                assert!(proof.verify(root, leaf).is_ok(), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn a_wrong_leaf_does_not_verify() {
        let t = tree(8);
        let proof = t.prove(3).expect("index in range");
        assert!(proof.verify(t.root(), leaf_hash(b"tx-9")).is_err());
    }

    #[test]
    fn leaf_and_node_domains_differ() {
        // If they matched, an internal node could be replayed as a leaf.
        let a = leaf_hash(b"x");
        let b = hash(Domain::MerkleNode, b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn odd_width_does_not_collide_like_bitcoins_duplicate_rule() {
        // Under Bitcoin's "duplicate the last node" rule, [a,b,c] and [a,b,c,c]
        // share a root. The RFC 6962 split must keep them distinct.
        let three = MerkleTree::from_items(["a", "b", "c"]);
        let four = MerkleTree::from_items(["a", "b", "c", "c"]);
        assert_ne!(three.root(), four.root());
    }

    #[test]
    fn out_of_range_proof_requests_error() {
        assert!(tree(4).prove(4).is_err());
    }

    #[test]
    fn tampered_proof_length_is_rejected() {
        let t = tree(8);
        let mut proof = t.prove(0).expect("index in range");
        proof.siblings.pop();
        assert!(proof.verify(t.root(), leaf_hash(b"tx-0")).is_err());
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let t = MerkleTree::from_items(["only"]);
        assert_eq!(t.root(), leaf_hash(b"only"));
    }

    #[test]
    fn empty_tree_has_a_defined_root() {
        assert_eq!(MerkleTree::default().root(), empty_root());
    }
}
