//! Binary Merkle trees with inclusion and consistency proofs (RFC 6962 shape).
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
//!
//! # Why consistency proofs are here
//!
//! An inclusion proof answers "is this leaf in that tree?". A
//! [`ConsistencyProof`] answers a different and, for an append-only log, more
//! important question: **"is the tree I saw before still a prefix of the tree
//! you are showing me now?"**
//!
//! That is what turns a Merkle tree into a log nobody can rewrite. A witness
//! that quietly drops or edits history cannot produce one, because there is no
//! sequence of hashes that reconciles the old root with the new. See
//! [ADR-0011](../../../docs/adr/0011-objective-anchors.md) and `crates/witness`.

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

/// Proof that a tree of `old_size` leaves is a prefix of one of `new_size`.
///
/// RFC 6962 §2.1.2. The nodes are the minimal set from which *both* roots can be
/// recomputed; a verifier that reproduces the old root it already trusted and
/// the new root it was offered knows nothing between them was altered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// Size of the earlier tree.
    pub old_size: usize,
    /// Size of the later tree.
    pub new_size: usize,
    /// Subtree hashes, in the order the recursion consumes them.
    pub nodes: Vec<Hash32>,
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

    /// Build a proof that the first `old_size` leaves of this tree are exactly
    /// the tree that had that size.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidProof`] if `old_size` exceeds the tree.
    pub fn prove_consistency(&self, old_size: usize) -> Result<ConsistencyProof> {
        let new_size = self.leaves.len();
        if old_size > new_size {
            return Err(CryptoError::InvalidProof("old size exceeds tree size"));
        }
        let mut nodes = Vec::new();
        // Both degenerate cases need no nodes: an empty tree is a prefix of
        // everything, and a tree is trivially a prefix of itself.
        if old_size != 0 && old_size != new_size {
            Self::collect_consistency(&self.leaves, old_size, true, &mut nodes);
        }
        Ok(ConsistencyProof {
            old_size,
            new_size,
            nodes,
        })
    }

    /// RFC 6962 `SUBPROOF`. `is_top` tracks whether the old root is the one the
    /// verifier already holds — in which case it is omitted rather than sent.
    fn collect_consistency(leaves: &[Hash32], m: usize, is_top: bool, out: &mut Vec<Hash32>) {
        let n = leaves.len();
        if m == n {
            if !is_top {
                out.push(Self::root_of(leaves));
            }
            return;
        }
        let k = split_point(n);
        let (left, right) = leaves.split_at(k);
        if m <= k {
            Self::collect_consistency(left, m, is_top, out);
            out.push(Self::root_of(right));
        } else {
            Self::collect_consistency(right, m.saturating_sub(k), false, out);
            out.push(Self::root_of(left));
        }
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

    /// Check that `leaf` is the leaf at `index` of a tree of exactly `total`
    /// leaves whose root is `root`.
    ///
    /// # Why `index` and `total` are parameters, not just fields
    ///
    /// The sibling list does **not** determine the tree's size. A proof for
    /// `(index 17, total 64)` replays the same left/right walk as
    /// `(index 17, total 33)`, so the same siblings recompute the same root for
    /// both — found by the adversarial harness, not by inspection.
    ///
    /// That is not a forgery: the leaf really is committed either way. But it
    /// means the proof's own `index` and `total` are **attacker-chosen**, so a
    /// caller that reads them off the proof learns nothing. RFC 6962 avoids this
    /// by treating the leaf index and tree size as things the verifier already
    /// knows — from a signed tree head, or from having asked for that index —
    /// and this signature enforces that rather than trusting each call site to
    /// remember.
    ///
    /// # Errors
    /// [`CryptoError::InvalidProof`] if the proof describes a different position
    /// or tree size than the caller expected, or if the root does not match.
    pub fn verify(&self, root: Hash32, leaf: Hash32, index: usize, total: usize) -> Result<()> {
        if self.index != index || self.total != total {
            return Err(CryptoError::InvalidProof(
                "proof is for a different position or tree size",
            ));
        }
        if self.compute_root(leaf)? == root {
            Ok(())
        } else {
            Err(CryptoError::InvalidProof("recomputed root does not match"))
        }
    }
}

impl ConsistencyProof {
    /// Check that the tree of `old_size` leaves with `old_root` is a prefix of
    /// the tree of `new_size` leaves with `new_root`.
    ///
    /// Both roots are supplied by the caller and both are *recomputed* from the
    /// proof. Reproducing only one would let a log rewrite history and hand over
    /// a matching root for the version it wanted believed.
    ///
    /// The sizes are parameters for the same reason they are on
    /// [`MerkleProof::verify`]: the node list does not determine them. A proof
    /// spanning `9 → 40` replays identically at `9 → 39`, so a caller reading
    /// `new_size` off the proof would be reading a number the prover chose. A
    /// verifier learns the real sizes from a signed tree head and from what it
    /// remembered last session.
    ///
    /// # Errors
    /// [`CryptoError::InvalidProof`] if the proof spans different sizes than the
    /// caller expected, the node count does not match the tree shape, or either
    /// root fails to reproduce.
    pub fn verify(
        &self,
        old_root: Hash32,
        new_root: Hash32,
        old_size: usize,
        new_size: usize,
    ) -> Result<()> {
        if self.old_size != old_size || self.new_size != new_size {
            return Err(CryptoError::InvalidProof(
                "proof spans a different pair of tree sizes",
            ));
        }
        if self.old_size > self.new_size {
            return Err(CryptoError::InvalidProof("old size exceeds new size"));
        }
        // An empty tree is a prefix of every tree, and a tree is a prefix of
        // itself. Both must carry no nodes, or a caller could smuggle in a
        // proof body that is never checked.
        if self.old_size == 0 || self.old_size == self.new_size {
            if !self.nodes.is_empty() {
                return Err(CryptoError::InvalidProof(
                    "degenerate consistency proof must be empty",
                ));
            }
            let expected = if self.old_size == 0 {
                empty_root()
            } else {
                new_root
            };
            return if old_root == expected {
                Ok(())
            } else {
                Err(CryptoError::InvalidProof("old root does not match"))
            };
        }

        let mut nodes = self.nodes.iter();
        let (old, new) = Self::replay(self.old_size, self.new_size, true, old_root, &mut nodes)?;
        if nodes.next().is_some() {
            return Err(CryptoError::InvalidProof(
                "consistency proof has spare nodes",
            ));
        }
        if old != old_root {
            return Err(CryptoError::InvalidProof(
                "proof does not reproduce the old root",
            ));
        }
        if new != new_root {
            return Err(CryptoError::InvalidProof(
                "proof does not reproduce the new root",
            ));
        }
        Ok(())
    }

    /// Recompute `(old_root, new_root)`, mirroring
    /// [`MerkleTree::collect_consistency`] exactly.
    fn replay<'a, I>(
        m: usize,
        n: usize,
        is_top: bool,
        known_old: Hash32,
        nodes: &mut I,
    ) -> Result<(Hash32, Hash32)>
    where
        I: Iterator<Item = &'a Hash32>,
    {
        if m == n {
            // At the top the old root is the one the verifier already holds, so
            // the prover never sends it.
            if is_top {
                return Ok((known_old, known_old));
            }
            let h = *next_node(nodes)?;
            return Ok((h, h));
        }
        let k = split_point(n);
        if m <= k {
            // The old tree sits entirely inside the left subtree.
            let (old, new_left) = Self::replay(m, k, is_top, known_old, nodes)?;
            let right = *next_node(nodes)?;
            Ok((old, node_hash(new_left, right)))
        } else {
            // The old tree spans the whole left subtree plus part of the right,
            // so the same left node completes both roots.
            let (old_right, new_right) = Self::replay(
                m.saturating_sub(k),
                n.saturating_sub(k),
                false,
                known_old,
                nodes,
            )?;
            let left = *next_node(nodes)?;
            Ok((node_hash(left, old_right), node_hash(left, new_right)))
        }
    }
}

fn next_node<'a, I: Iterator<Item = &'a Hash32>>(nodes: &mut I) -> Result<&'a Hash32> {
    nodes.next().ok_or(CryptoError::InvalidProof(
        "consistency proof ran out of nodes",
    ))
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
                assert!(proof.verify(root, leaf, i, n).is_ok(), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn a_wrong_leaf_does_not_verify() {
        let t = tree(8);
        let proof = t.prove(3).expect("index in range");
        assert!(proof.verify(t.root(), leaf_hash(b"tx-9"), 3, 8).is_err());
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
        assert!(proof.verify(t.root(), leaf_hash(b"tx-0"), 0, 8).is_err());
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

    #[test]
    fn an_append_only_log_proves_consistent_at_every_pair_of_sizes() {
        // Sweep every (old, new) pair, because the RFC 6962 recursion has three
        // distinct shapes and only an exhaustive sweep exercises all of them.
        for new_size in 0..=33 {
            let new = tree(new_size);
            for old_size in 0..=new_size {
                let old = tree(old_size);
                let proof = new.prove_consistency(old_size).expect("size in range");
                assert!(
                    proof
                        .verify(old.root(), new.root(), old_size, new_size)
                        .is_ok(),
                    "old={old_size} new={new_size}"
                );
            }
        }
    }

    #[test]
    fn a_log_that_rewrote_an_old_entry_cannot_prove_consistency() {
        // The whole point. A witness that edits history has no sequence of
        // hashes that reconciles the root a client already saw with its new one.
        let honest = tree(16);
        let old_root = tree(6).root();

        let mut leaves: Vec<_> = (0..16)
            .map(|i| leaf_hash(format!("tx-{i}").as_bytes()))
            .collect();
        leaves[2] = leaf_hash(b"tampered");
        let rewritten = MerkleTree::from_leaf_hashes(leaves);

        let proof = rewritten.prove_consistency(6).expect("size in range");
        assert!(
            proof.verify(old_root, rewritten.root(), 6, 16).is_err(),
            "a rewritten prefix must be unprovable"
        );
        // And the honest log still verifies, so the test is not passing by
        // accident of a broken verifier.
        assert!(
            honest
                .prove_consistency(6)
                .expect("size in range")
                .verify(old_root, honest.root(), 6, 16)
                .is_ok()
        );
    }

    #[test]
    fn a_truncated_log_cannot_prove_consistency() {
        // Dropping entries is as much a rewrite as changing them.
        let old_root = tree(10).root();
        let truncated = tree(7);
        assert!(truncated.prove_consistency(10).is_err());
        // Nor can it claim the old size was smaller than it was and pass off
        // the resulting proof as covering the client's actual position.
        let proof = truncated.prove_consistency(4).expect("size in range");
        assert!(proof.verify(old_root, truncated.root(), 4, 7).is_err());
    }

    #[test]
    fn a_degenerate_proof_may_not_smuggle_nodes() {
        // old == new needs no nodes; accepting a body there would leave bytes
        // that are never checked.
        let t = tree(8);
        let mut proof = t.prove_consistency(8).expect("size in range");
        assert!(proof.nodes.is_empty());
        proof.nodes.push(Hash32::from_bytes([9u8; 32]));
        assert!(proof.verify(t.root(), t.root(), 8, 8).is_err());
    }

    #[test]
    fn spare_or_missing_nodes_are_rejected() {
        let new = tree(13);
        let old = tree(5);
        let good = new.prove_consistency(5).expect("size in range");
        assert!(good.verify(old.root(), new.root(), 5, 13).is_ok());

        let mut extra = good.clone();
        extra.nodes.push(Hash32::from_bytes([1u8; 32]));
        assert!(extra.verify(old.root(), new.root(), 5, 13).is_err());

        let mut short = good;
        short.nodes.pop();
        assert!(short.verify(old.root(), new.root(), 5, 13).is_err());
    }

    #[test]
    fn an_empty_log_is_a_prefix_of_every_log() {
        let new = tree(9);
        let proof = new.prove_consistency(0).expect("size in range");
        assert!(proof.verify(empty_root(), new.root(), 0, 9).is_ok());
        // But only against the real empty root.
        assert!(proof.verify(Hash32::ZERO, new.root(), 0, 9).is_err());
    }
}
