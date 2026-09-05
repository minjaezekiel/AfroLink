//! The new tree must agree with the old one on everything, always.
//!
//! # Why this test exists
//!
//! [`SparseMerkleTree`] was a flat `BTreeMap` that recomputed the whole tree on
//! every `root()` and `prove()`. It is now a persistent node tree that caches
//! its hashes, which made one write against 100 000 accounts go from 63ms to
//! 10us. That is a change to a **consensus** data structure: the app hash is in
//! every block header, so a tree that disagrees with the old one by a single bit
//! does not run slower, it forks the chain.
//!
//! The existing suite is the first line of defence — a great many tests assert
//! specific roots and proofs, and they all still pass. But a suite written
//! against an implementation tends to exercise the paths that implementation
//! made easy, and the one thing the flat map never had to get right is the case
//! this one can get wrong: **collapsing a branch after a removal**. A subtree
//! holding one entry must hash as that leaf at whatever depth it sits, so a
//! branch left with a single leaf has to *become* it. Get that wrong and nothing
//! looks broken — two honest nodes simply disagree on the app hash after one of
//! them happened to delete a key.
//!
//! So this drives both implementations through the same random sequence of
//! inserts, overwrites and removals, comparing the root and a proof after every
//! single operation. The reference below is the old algorithm, kept verbatim.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_crypto::hash::Hash32;
use afrolink_state::SparseMerkleTree;
use afrolink_state::smt::{EMPTY, Proof, ProofLeaf, key_hash, leaf_hash, node_hash};
use std::collections::BTreeMap;

/// **The previous implementation, unchanged.** Roots and proofs computed from a
/// flat map of entries, exactly as they were before the tree kept its structure.
#[derive(Default, Clone)]
struct Reference {
    entries: BTreeMap<Hash32, Vec<u8>>,
}

impl Reference {
    fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        self.entries.insert(key_hash(key), value);
    }

    fn remove(&mut self, key: &[u8]) -> bool {
        self.entries.remove(&key_hash(key)).is_some()
    }

    fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.entries.get(&key_hash(key))
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn root(&self) -> Hash32 {
        let items: Vec<(Hash32, &Vec<u8>)> = self.entries.iter().map(|(k, v)| (*k, v)).collect();
        Self::root_of(&items, 0)
    }

    fn root_of(items: &[(Hash32, &Vec<u8>)], depth: usize) -> Hash32 {
        match items {
            [] => EMPTY,
            [(k, v)] => leaf_hash(*k, v),
            _ => {
                if depth >= 256 {
                    return EMPTY;
                }
                let split = items.partition_point(|(k, _)| !k.bit(depth));
                let (left, right) = items.split_at(split);
                node_hash(
                    Self::root_of(left, depth + 1),
                    Self::root_of(right, depth + 1),
                )
            }
        }
    }

    fn prove(&self, key: &[u8]) -> Proof {
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
                let split = items.partition_point(|(k, _)| !k.bit(depth));
                let (left, right) = items.split_at(split);
                if kh.bit(depth) {
                    siblings.push(Self::root_of(left, depth + 1));
                    Self::descend(right, kh, depth + 1, siblings)
                } else {
                    siblings.push(Self::root_of(right, depth + 1));
                    Self::descend(left, kh, depth + 1, siblings)
                }
            }
        }
    }

    fn entries(&self) -> Vec<(Hash32, Vec<u8>)> {
        self.entries.iter().map(|(k, v)| (*k, v.clone())).collect()
    }
}

/// A deterministic generator, so a failure is reproducible from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*, plenty for choosing test operations.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn check(seed: u64, operations: usize, key_space: u64) {
    let mut rng = Rng(seed);
    let mut tree = SparseMerkleTree::new();
    let mut reference = Reference::default();

    for step in 0..operations {
        let k = format!("key/{}", rng.below(key_space));
        let key = k.as_bytes();
        match rng.below(10) {
            // Removals are deliberately frequent: collapsing a branch back into
            // a leaf is the one rule the flat map never had to implement, so it
            // is the one this test is really here for.
            0..=3 => {
                let a = tree.remove(key);
                let b = reference.remove(key);
                assert_eq!(a, b, "seed {seed} step {step}: remove disagreed on {k}");
            }
            _ => {
                let value = vec![u8::try_from(rng.below(251)).unwrap_or(0); 1 + (step % 5)];
                tree.insert(key, value.clone());
                reference.insert(key, value);
            }
        }

        assert_eq!(
            tree.root(),
            reference.root(),
            "seed {seed} step {step}: roots diverged after touching {k}"
        );
        assert_eq!(
            tree.len(),
            reference.len(),
            "seed {seed} step {step}: lengths diverged"
        );
    }

    // Proofs, for keys that are present and keys that are not.
    for i in 0..key_space.saturating_mul(2) {
        let k = format!("key/{i}");
        let key = k.as_bytes();
        assert_eq!(
            tree.get(key),
            reference.get(key),
            "seed {seed}: get disagreed on {k}"
        );
        let mine = tree.prove(key);
        let theirs = reference.prove(key);
        assert_eq!(mine, theirs, "seed {seed}: proofs diverged for {k}");
        assert!(
            mine.verify(tree.root(), key, reference.get(key).map(Vec::as_slice)),
            "seed {seed}: own proof failed to verify for {k}"
        );
    }

    let mine: Vec<(Hash32, Vec<u8>)> = tree.entries().map(|(k, v)| (k, v.clone())).collect();
    assert_eq!(
        mine,
        reference.entries(),
        "seed {seed}: iteration order or contents diverged"
    );
}

#[test]
fn the_tree_agrees_with_the_old_implementation_on_random_histories() {
    // Small key spaces on purpose: they force collisions in the high bits, deep
    // branches, and branches that repeatedly collapse and re-form — which is
    // where a structural implementation goes wrong and a recomputing one cannot.
    for seed in 1..=24u64 {
        check(seed, 300, 12);
        check(seed, 300, 64);
        check(seed, 600, 400);
    }
}

#[test]
fn a_tree_emptied_key_by_key_returns_to_the_empty_root() {
    // The strongest single statement of the collapse rule: every removal order
    // must arrive at exactly the same place, and that place must be `EMPTY`.
    for seed in 1..=16u64 {
        let mut rng = Rng(seed);
        let mut tree = SparseMerkleTree::new();
        let mut keys: Vec<String> = (0..80).map(|i| format!("acct/{i}")).collect();
        for k in &keys {
            tree.insert(k.as_bytes(), vec![7; 4]);
        }
        let full = tree.root();

        // Remove in a shuffled order.
        for i in (1..keys.len()).rev() {
            let j = usize::try_from(rng.below(u64::try_from(i + 1).unwrap_or(1))).unwrap_or(0);
            keys.swap(i, j);
        }
        for k in &keys {
            assert!(tree.remove(k.as_bytes()));
        }
        assert_eq!(
            tree.root(),
            EMPTY,
            "seed {seed}: an emptied tree is not empty"
        );
        assert_eq!(tree.len(), 0);

        // And putting them back must reach the same root it started at, whatever
        // order they go in. Insertion order changing the root would be a fork
        // between two nodes that executed the same block.
        for k in &keys {
            tree.insert(k.as_bytes(), vec![7; 4]);
        }
        assert_eq!(
            tree.root(),
            full,
            "seed {seed}: rebuilt tree has a different root"
        );
    }
}

#[test]
fn removing_the_second_of_two_deep_neighbours_collapses_the_branch() {
    // The specific shape the collapse rule exists for, pinned rather than left
    // to chance: two keys sharing a long prefix build a chain of single-child
    // branches, and removing one must leave the other hashing exactly as it
    // would if it had been alone all along — not wrapped in the branches its
    // departed neighbour needed.
    let mut pair = SparseMerkleTree::new();
    let mut alone = SparseMerkleTree::new();

    // Search for two keys whose hashes share several leading bits, so the branch
    // is genuinely deep rather than nominally so.
    let mut best: Option<(String, String, usize)> = None;
    for i in 0..3_000u32 {
        for j in (i + 1)..(i + 40).min(3_000) {
            let a = format!("k{i}");
            let b = format!("k{j}");
            let (ha, hb) = (key_hash(a.as_bytes()), key_hash(b.as_bytes()));
            let shared = (0..256).take_while(|d| ha.bit(*d) == hb.bit(*d)).count();
            if shared >= 4 && best.as_ref().is_none_or(|(_, _, s)| shared > *s) {
                best = Some((a, b, shared));
            }
        }
    }
    let (a, b, shared) = best.expect("two keys sharing a prefix exist");
    assert!(shared >= 4, "wanted a deep branch, got {shared} bits");

    pair.insert(a.as_bytes(), vec![1]);
    pair.insert(b.as_bytes(), vec![2]);
    alone.insert(a.as_bytes(), vec![1]);

    assert!(pair.remove(b.as_bytes()));
    assert_eq!(
        pair.root(),
        alone.root(),
        "a branch left holding one leaf must hash as that leaf"
    );
    assert_eq!(pair.prove(a.as_bytes()), alone.prove(a.as_bytes()));
}
