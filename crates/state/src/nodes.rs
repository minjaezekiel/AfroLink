//! Content-addressed persistence for the state tree.
//!
//! Implements the storage model from
//! [ADR-0006](../../../docs/adr/0006-state-persistence-and-retention.md), taken
//! from XRP Ledger's SHAMap/NodeStore design.
//!
//! Every node of the sparse Merkle tree is stored under **its own hash**. Two
//! properties fall out, and together they replace an entire snapshot subsystem:
//!
//! * **Structural sharing.** Consecutive versions of the tree differ only along
//!   the paths that changed. Every untouched subtree keeps the same hash, so it
//!   is already in the store and is never rewritten. Committing a version writes
//!   `O(log n)` new nodes per changed key.
//! * **Versions are free.** "The state at root R" is just the tree reachable
//!   from R. There is no snapshot to take, schedule, or verify — historical state
//!   is addressable as long as its nodes are retained.
//!
//! Startup therefore costs a single root lookup rather than replaying the chain.
//!
//! # Retention
//!
//! Nothing here deletes. Garbage collection over a shared-structure store is
//! genuinely dangerous — a node reachable from a root you meant to keep, deleted
//! because another root stopped referencing it, is silent corruption that only
//! appears on a later read. It needs reference tracking and adversarial tests,
//! and is deliberately not part of this first step.

use afrolink_crypto::hash::Hash32;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader, decode_exact};
use std::collections::BTreeMap;

use crate::smt::{EMPTY, NodeKind, NodeRef, SparseMerkleTree, key_hash, leaf_hash, node_hash};

/// A materialised node of the state tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A leaf binding one key's path hash to its value.
    ///
    /// The value is stored inline rather than by reference: state values here are
    /// small (a balance is 16 bytes) and an extra indirection per read would cost
    /// more than it saves.
    Leaf {
        /// The key's path hash.
        key_hash: Hash32,
        /// The stored value.
        value: Vec<u8>,
    },
    /// An internal node naming its two children by hash.
    ///
    /// A child of [`EMPTY`] means that side of the subtree holds nothing.
    Internal {
        /// Left child hash.
        left: Hash32,
        /// Right child hash.
        right: Hash32,
    },
}

impl Node {
    /// The hash this node is stored under.
    ///
    /// Matches the hashing the in-memory tree already uses, so a materialised
    /// tree and a computed one agree on every hash.
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        match self {
            Self::Leaf { key_hash, value } => leaf_hash(*key_hash, value),
            Self::Internal { left, right } => node_hash(*left, *right),
        }
    }
}

impl Encode for Node {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Leaf { key_hash, value } => {
                out.push(0);
                key_hash.encode(out);
                value.encode(out);
            }
            Self::Internal { left, right } => {
                out.push(1);
                left.encode(out);
                right.encode(out);
            }
        }
    }
}

impl Decode for Node {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Leaf {
                key_hash: Hash32::decode(r)?,
                value: Vec::<u8>::decode(r)?,
            }),
            1 => Ok(Self::Internal {
                left: Hash32::decode(r)?,
                right: Hash32::decode(r)?,
            }),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "Node",
            }),
        }
    }
}

/// Somewhere nodes can be read from.
///
/// A trait rather than a concrete type so the same reconstruction logic runs
/// over an in-memory map in tests and over the database in production.
pub trait NodeSource {
    /// Fetch a node by its hash.
    fn get_node(&self, hash: Hash32) -> Option<Node>;
}

/// Somewhere nodes can be written to.
pub trait NodeSink {
    /// Whether a node is already stored.
    ///
    /// Content addressing makes writes idempotent, so this is purely an
    /// optimisation — it is what turns a full re-materialisation into `O(log n)`
    /// actual writes.
    fn has_node(&self, hash: Hash32) -> bool;

    /// Store a node under its hash.
    fn put_node(&mut self, hash: Hash32, node: &Node);
}

/// An in-memory node store, used by tests and as a staging buffer.
#[derive(Debug, Clone, Default)]
pub struct MemoryNodes {
    nodes: BTreeMap<Hash32, Vec<u8>>,
}

impl MemoryNodes {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct nodes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether it holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Every stored node, as raw encoded bytes.
    pub fn iter_raw(&self) -> impl Iterator<Item = (Hash32, &Vec<u8>)> {
        self.nodes.iter().map(|(h, v)| (*h, v))
    }
}

impl NodeSource for MemoryNodes {
    fn get_node(&self, hash: Hash32) -> Option<Node> {
        self.nodes
            .get(&hash)
            .and_then(|b| decode_exact::<Node>(b).ok())
    }
}

impl NodeSink for MemoryNodes {
    fn has_node(&self, hash: Hash32) -> bool {
        self.nodes.contains_key(&hash)
    }

    fn put_node(&mut self, hash: Hash32, node: &Node) {
        self.nodes.insert(hash, node.to_bytes());
    }
}

/// How many nodes a commit actually wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteStats {
    /// Nodes visited while materialising the tree.
    pub visited: usize,
    /// Nodes that were new and had to be written.
    ///
    /// After the first commit this should be a small multiple of the number of
    /// changed keys — that is structural sharing working.
    pub written: usize,
}

/// Write every node of `tree` into `sink`, returning the root hash.
///
/// Nodes already present are skipped, so only genuinely new nodes are written.
pub fn commit_tree<S: NodeSink>(tree: &SparseMerkleTree, sink: &mut S) -> (Hash32, WriteStats) {
    let mut stats = WriteStats {
        visited: 0,
        written: 0,
    };
    let root = match tree.root_node() {
        Some(node) => write_node(node, sink, &mut stats),
        None => EMPTY,
    };
    (root, stats)
}

/// Write a node and everything new beneath it.
///
/// # Why this may stop early
///
/// Nodes are addressed by their own hash, so a hash the sink already holds names
/// a subtree the sink already holds *in full*: nothing beneath it could have
/// changed without changing that hash. Returning there is what makes a commit
/// cost `O(changed · log n)` rather than `O(n)`.
///
/// That was always true of the *writes* — `has_node` skipped them. It was not
/// true of the **work**, because the previous implementation computed every hash
/// bottom-up from a flat list of entries and so had to visit all of them before
/// it could know what to skip. The tree caches its hashes now, so the check
/// happens on the way *down* and the saving is real rather than only in the
/// write count.
fn write_node<S: NodeSink>(node: NodeRef<'_>, sink: &mut S, stats: &mut WriteStats) -> Hash32 {
    let hash = node.hash();
    stats.visited = stats.visited.saturating_add(1);
    if sink.has_node(hash) {
        return hash;
    }
    let materialised = match node.kind() {
        NodeKind::Leaf { key_hash, value } => Node::Leaf {
            key_hash,
            value: value.to_vec(),
        },
        NodeKind::Internal { left, right } => Node::Internal {
            left: left.map_or(EMPTY, |child| write_node(child, sink, stats)),
            right: right.map_or(EMPTY, |child| write_node(child, sink, stats)),
        },
    };
    sink.put_node(hash, &materialised);
    stats.written = stats.written.saturating_add(1);
    hash
}

/// Rebuild a tree from the nodes reachable from `root`.
///
/// Returns `None` if any node on the way is missing, which is how a truncated or
/// corrupted store is detected rather than silently producing partial state.
#[must_use]
pub fn load_tree<S: NodeSource>(root: Hash32, source: &S) -> Option<SparseMerkleTree> {
    let mut entries = BTreeMap::new();
    collect(root, source, &mut entries)?;
    Some(SparseMerkleTree::from_entries(entries))
}

fn collect<S: NodeSource>(
    hash: Hash32,
    source: &S,
    out: &mut BTreeMap<Hash32, Vec<u8>>,
) -> Option<()> {
    if hash == EMPTY {
        return Some(());
    }
    match source.get_node(hash)? {
        Node::Leaf { key_hash, value } => {
            out.insert(key_hash, value);
            Some(())
        }
        Node::Internal { left, right } => {
            collect(left, source, out)?;
            collect(right, source, out)
        }
    }
}

/// The path hash a raw key maps to, re-exported for callers building proofs.
#[must_use]
pub fn path_of(key: &[u8]) -> Hash32 {
    key_hash(key)
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
    fn a_committed_tree_reloads_to_the_same_root() {
        // The property that replaces replay: state comes back from a root hash.
        let tree = tree_with(64);
        let mut nodes = MemoryNodes::new();
        let (root, _) = commit_tree(&tree, &mut nodes);
        assert_eq!(
            root,
            tree.root(),
            "the stored root must match the computed one"
        );

        let reloaded = load_tree(root, &nodes).expect("all nodes present");
        assert_eq!(reloaded.root(), tree.root());
        for i in 0..64 {
            let key = format!("account/{i}");
            assert_eq!(
                reloaded.get(key.as_bytes()),
                tree.get(key.as_bytes()),
                "value for {key} must survive the round trip"
            );
        }
    }

    #[test]
    fn changing_one_key_writes_only_a_handful_of_nodes() {
        // Structural sharing is the whole point: an unchanged subtree keeps its
        // hash, is already stored, and is never rewritten.
        let mut tree = tree_with(512);
        let mut nodes = MemoryNodes::new();
        let (_, first) = commit_tree(&tree, &mut nodes);
        assert_eq!(
            first.written, first.visited,
            "the first commit writes everything"
        );

        tree.insert(b"account/100", b"balance:changed".to_vec());
        let (_, second) = commit_tree(&tree, &mut nodes);

        assert!(
            second.written < 40,
            "one changed key should touch ~log2(512) nodes, wrote {}",
            second.written
        );
        assert!(
            second.written < first.written / 10,
            "second commit wrote {} of {} — structural sharing is not working",
            second.written,
            first.written
        );
    }

    #[test]
    fn an_unchanged_tree_writes_nothing_at_all() {
        let tree = tree_with(128);
        let mut nodes = MemoryNodes::new();
        commit_tree(&tree, &mut nodes);
        let (_, again) = commit_tree(&tree, &mut nodes);
        assert_eq!(
            again.written, 0,
            "re-committing identical state must be free"
        );
    }

    #[test]
    fn historical_versions_stay_addressable() {
        // XRPL's property: an old root still resolves, because its nodes were
        // never overwritten. This is what makes archive nodes a config flag.
        let mut tree = tree_with(32);
        let mut nodes = MemoryNodes::new();
        let (old_root, _) = commit_tree(&tree, &mut nodes);

        tree.insert(b"account/5", b"balance:updated".to_vec());
        let (new_root, _) = commit_tree(&tree, &mut nodes);
        assert_ne!(old_root, new_root);

        let old = load_tree(old_root, &nodes).expect("old version still reachable");
        assert_eq!(old.get(b"account/5"), Some(&b"balance:5".to_vec()));

        let new = load_tree(new_root, &nodes).expect("new version reachable");
        assert_eq!(new.get(b"account/5"), Some(&b"balance:updated".to_vec()));
    }

    #[test]
    fn a_missing_node_is_detected_rather_than_producing_partial_state() {
        // Truncated or corrupted storage must fail loudly. Silently returning a
        // tree with some accounts missing would be a fork waiting to happen.
        let tree = tree_with(16);
        let mut nodes = MemoryNodes::new();
        let (root, _) = commit_tree(&tree, &mut nodes);

        // Drop one node by rebuilding the store without it.
        let victim = nodes.iter_raw().nth(3).map(|(h, _)| h).expect("has nodes");
        let mut damaged = MemoryNodes::new();
        for (h, raw) in nodes.iter_raw() {
            if h != victim {
                damaged.nodes.insert(h, raw.clone());
            }
        }

        assert!(
            load_tree(root, &damaged).is_none(),
            "a gap must be reported"
        );
    }

    #[test]
    fn an_empty_tree_round_trips() {
        let tree = SparseMerkleTree::new();
        let mut nodes = MemoryNodes::new();
        let (root, stats) = commit_tree(&tree, &mut nodes);
        assert_eq!(root, EMPTY);
        assert_eq!(stats.written, 0);
        assert_eq!(load_tree(root, &nodes).expect("empty loads").root(), EMPTY);
    }

    #[test]
    fn proofs_still_verify_against_a_reloaded_tree() {
        // Reconstruction must preserve the tree exactly, or a wallet's proof
        // would stop verifying after a node restart.
        let tree = tree_with(100);
        let mut nodes = MemoryNodes::new();
        let (root, _) = commit_tree(&tree, &mut nodes);
        let reloaded = load_tree(root, &nodes).expect("loads");

        let key = b"account/42";
        let proof = reloaded.prove(key);
        assert!(proof.verify(root, key, Some(b"balance:42")));

        let absent = b"account/9999";
        assert!(reloaded.prove(absent).verify(root, absent, None));
    }

    #[test]
    fn nodes_round_trip_through_the_codec() {
        let leaf = Node::Leaf {
            key_hash: path_of(b"k"),
            value: b"v".to_vec(),
        };
        let internal = Node::Internal {
            left: leaf.hash(),
            right: EMPTY,
        };
        for node in [leaf, internal] {
            assert_eq!(decode_exact::<Node>(&node.to_bytes()), Ok(node));
        }
    }
}
