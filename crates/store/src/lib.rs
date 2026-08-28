//! Durable storage for the chain.
//!
//! # What is persisted
//!
//! Genesis, every block, every commit certificate, and — since
//! [ADR-0006](../../../docs/adr/0006-state-persistence-and-retention.md) — the
//! **state tree itself**, stored content-addressed in XRP Ledger's
//! SHAMap/NodeStore style.
//!
//! Startup is therefore a single root lookup rather than a replay of the chain.
//! Replay is kept as the repair path: if nodes are missing or were pruned, the
//! node rebuilds from genesis and checks every block's computed `app_hash`
//! against its stored header, so corruption or a change in execution semantics
//! fails loudly instead of forking.
//!
//! Blocks and commits are written together and atomically, because a block
//! without its certificate cannot be served to a light client, and a certificate
//! without its block proves nothing.
//!
//! TRON needs an explicit checkpoint mechanism here because its underlying
//! stores cannot make one atomic write across several databases. redb gives us
//! real multi-table transactions, so the atomicity comes from the storage layer
//! rather than from a protocol on top of it.
//!
//! # Not yet done
//!
//! * **Retention.** Nothing is ever deleted. XRPL's `online_delete` keeps the
//!   most recent 2,000 ledgers by default, and its full history had reached
//!   ~39 TB by January 2026 — bounded retention is not optional at scale.
//! * **Incremental writes.** Only new nodes reach disk, so writes are already
//!   `O(log n)` per changed key, but the node set is recomputed each commit at
//!   `O(n)` CPU. Copy-on-write updates are the follow-up.

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

use afrolink_consensus::Commit;
use afrolink_crypto::hash::Hash32;
use afrolink_executor::{Block, Executor, Genesis, GenesisError, GenesisLimits};
use afrolink_primitives::Height;
use afrolink_primitives::codec::{CodecError, Encode, decode_exact};
use afrolink_state::nodes::{Node, NodeSink, NodeSource, WriteStats, commit_tree, load_tree};
use afrolink_state::{KeyValueStore, MemoryStore};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;
use thiserror::Error;

/// Blocks by height.
const BLOCKS: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("blocks");
/// Commit certificates by height.
const COMMITS: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("commits");
/// Singleton values: genesis, latest height.
const META: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("meta");
/// State tree nodes, keyed by their own hash (ADR-0006).
const NODES: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("nodes");

const KEY_GENESIS: &str = "genesis";
const KEY_HEIGHT: &str = "height";

/// Why a storage operation failed.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The underlying database reported a failure.
    #[error("database: {0}")]
    Database(String),
    /// Stored bytes did not decode.
    #[error("corrupt record at {what}: {reason}")]
    Corrupt {
        /// Which record.
        what: String,
        /// Decoder message.
        reason: String,
    },
    /// The store holds no genesis, so nothing can be replayed.
    #[error("store has no genesis")]
    NoGenesis,
    /// A height between genesis and the tip is missing.
    #[error("block {0} is missing from an otherwise complete chain")]
    MissingBlock(u64),
    /// Applying genesis failed.
    #[error(transparent)]
    Genesis(#[from] GenesisError),
    /// Replay produced a different state than the stored header claims.
    ///
    /// Means the database is corrupt, or execution semantics changed under a
    /// stored chain. Either way the node must not start.
    #[error("replay diverged at height {height}: computed {computed}, header says {expected}")]
    StateDivergence {
        /// Height at which the mismatch appeared.
        height: u64,
        /// Hash computed by replaying.
        computed: String,
        /// Hash recorded in the stored header.
        expected: String,
    },
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, StoreError>;

fn db_err<E: core::fmt::Display>(e: E) -> StoreError {
    StoreError::Database(e.to_string())
}

fn corrupt(what: &str, e: &CodecError) -> StoreError {
    StoreError::Corrupt {
        what: what.to_owned(),
        reason: e.to_string(),
    }
}

/// Durable storage for blocks, commits and genesis.
pub struct ChainStore {
    db: Database,
}

impl ChainStore {
    /// Open or create a store at `path`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] if the file cannot be opened or the
    /// tables cannot be created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(db_err)?;
        // Create the tables up front so later reads do not have to special-case
        // a store that has never been written to.
        let tx = db.begin_write().map_err(db_err)?;
        {
            tx.open_table(BLOCKS).map_err(db_err)?;
            tx.open_table(COMMITS).map_err(db_err)?;
            tx.open_table(META).map_err(db_err)?;
            tx.open_table(NODES).map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        Ok(Self { db })
    }

    /// Record the genesis file. Idempotent.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] on write failure.
    pub fn put_genesis(&self, genesis: &Genesis) -> Result<()> {
        let tx = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = tx.open_table(META).map_err(db_err)?;
            table
                .insert(KEY_GENESIS, genesis.to_bytes().as_slice())
                .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    /// The stored genesis, if any.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the stored bytes do not decode.
    pub fn genesis(&self) -> Result<Option<Genesis>> {
        let tx = self.db.begin_read().map_err(db_err)?;
        let table = tx.open_table(META).map_err(db_err)?;
        let Some(raw) = table.get(KEY_GENESIS).map_err(db_err)? else {
            return Ok(None);
        };
        decode_exact::<Genesis>(raw.value())
            .map(Some)
            .map_err(|e| corrupt("genesis", &e))
    }

    /// Store a block and its commit certificate atomically.
    ///
    /// Both land in one write transaction: a block whose certificate is missing
    /// cannot be served to a light client, and a certificate without its block
    /// proves nothing, so a partial write would leave the store unable to answer
    /// for that height.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] on write failure.
    pub fn put_block(&self, block: &Block, commit: &Commit) -> Result<()> {
        let height = block.header.height.0;
        let tx = self.db.begin_write().map_err(db_err)?;
        {
            let mut blocks = tx.open_table(BLOCKS).map_err(db_err)?;
            blocks
                .insert(height, block.to_bytes().as_slice())
                .map_err(db_err)?;

            let mut commits = tx.open_table(COMMITS).map_err(db_err)?;
            commits
                .insert(height, commit.to_bytes().as_slice())
                .map_err(db_err)?;

            let mut meta = tx.open_table(META).map_err(db_err)?;
            let current = meta
                .get(KEY_HEIGHT)
                .map_err(db_err)?
                .and_then(|v| decode_exact::<Height>(v.value()).ok())
                .unwrap_or(Height::GENESIS);
            if height >= current.0 {
                meta.insert(KEY_HEIGHT, Height(height).to_bytes().as_slice())
                    .map_err(db_err)?;
            }
        }
        tx.commit().map_err(db_err)
    }

    /// The highest stored block height.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the stored height does not decode.
    pub fn height(&self) -> Result<Height> {
        let tx = self.db.begin_read().map_err(db_err)?;
        let table = tx.open_table(META).map_err(db_err)?;
        match table.get(KEY_HEIGHT).map_err(db_err)? {
            None => Ok(Height::GENESIS),
            Some(raw) => decode_exact::<Height>(raw.value()).map_err(|e| corrupt("height", &e)),
        }
    }

    /// Fetch one block.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the stored bytes do not decode.
    pub fn block(&self, height: Height) -> Result<Option<Block>> {
        let tx = self.db.begin_read().map_err(db_err)?;
        let table = tx.open_table(BLOCKS).map_err(db_err)?;
        let Some(raw) = table.get(height.0).map_err(db_err)? else {
            return Ok(None);
        };
        decode_exact::<Block>(raw.value())
            .map(Some)
            .map_err(|e| corrupt(&format!("block {height}"), &e))
    }

    /// Fetch one commit certificate.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the stored bytes do not decode.
    pub fn commit(&self, height: Height) -> Result<Option<Commit>> {
        let tx = self.db.begin_read().map_err(db_err)?;
        let table = tx.open_table(COMMITS).map_err(db_err)?;
        let Some(raw) = table.get(height.0).map_err(db_err)? else {
            return Ok(None);
        };
        decode_exact::<Commit>(raw.value())
            .map(Some)
            .map_err(|e| corrupt(&format!("commit {height}"), &e))
    }

    /// Rebuild state by applying genesis and replaying every stored block.
    ///
    /// Returns the reconstructed state and the tip block (the genesis block if
    /// no blocks have been stored yet).
    ///
    /// Each replayed block's computed `app_hash` is compared against the one in
    /// its stored header. A mismatch stops the node rather than letting it serve
    /// state that disagrees with the chain it claims to be following.
    ///
    /// # Errors
    /// Returns [`StoreError::NoGenesis`], [`StoreError::MissingBlock`] or
    /// [`StoreError::StateDivergence`].
    pub fn replay(&self, limits: GenesisLimits) -> Result<(MemoryStore, Block)> {
        let genesis = self.genesis()?.ok_or(StoreError::NoGenesis)?;
        let mut state = MemoryStore::new();
        let genesis_block = genesis.apply(&mut state, limits)?;

        let executor = Executor::new(genesis.chain_id.clone());
        let tip_height = self.height()?;
        let mut tip = genesis_block;

        for h in 1..=tip_height.0 {
            let height = Height(h);
            let block = self.block(height)?.ok_or(StoreError::MissingBlock(h))?;
            let outcome = executor.execute_block(&mut state, height, &block.transactions);

            if outcome.app_hash != block.header.app_hash {
                return Err(StoreError::StateDivergence {
                    height: h,
                    computed: outcome.app_hash.to_hex(),
                    expected: block.header.app_hash.to_hex(),
                });
            }
            tip = block;
        }

        Ok((state, tip))
    }

    /// Persist the state tree, writing only nodes not already stored.
    ///
    /// Implements [ADR-0006]: nodes are content-addressed, so unchanged subtrees
    /// keep their hashes and are skipped. Returns the root and how many nodes
    /// were actually written.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] on write failure.
    pub fn persist_state(&self, state: &MemoryStore) -> Result<(Hash32, WriteStats)> {
        let tx = self.db.begin_write().map_err(db_err)?;
        let result = {
            let table = tx.open_table(NODES).map_err(db_err)?;
            let mut sink = TableSink {
                table,
                failed: None,
            };
            let (root, stats) = commit_tree(state.tree(), &mut sink);
            match sink.failed {
                Some(e) => Err(StoreError::Database(e)),
                None => Ok((root, stats)),
            }
        };
        let out = result?;
        tx.commit().map_err(db_err)?;
        Ok(out)
    }

    /// Reconstruct state from the nodes reachable from `root`.
    ///
    /// Returns `None` if any node is missing, which is how a truncated or
    /// pruned store is detected rather than silently yielding partial state.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] on read failure.
    pub fn load_state(&self, root: Hash32) -> Result<Option<MemoryStore>> {
        let tx = self.db.begin_read().map_err(db_err)?;
        let table = tx.open_table(NODES).map_err(db_err)?;
        let source = TableSource { table };
        Ok(load_tree(root, &source).map(MemoryStore::from_tree))
    }

    /// Open state for the stored tip, replaying only if necessary.
    ///
    /// The fast path is a single root lookup, which is the point of ADR-0006:
    /// startup no longer costs `O(chain length)`. Replay remains as the repair
    /// path for a store whose nodes are missing or pruned, and its app-hash
    /// check still catches corruption.
    ///
    /// Returns the state, the tip block, and whether replay was needed.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if neither path can produce verified state.
    pub fn open_state(&self, limits: GenesisLimits) -> Result<(MemoryStore, Block, bool)> {
        let height = self.height()?;

        if height == Height::GENESIS {
            let (state, tip) = self.replay(limits)?;
            return Ok((state, tip, true));
        }

        if let Some(tip) = self.block(height)?
            && let Some(state) = self.load_state(tip.header.app_hash)?
        {
            // Cheap sanity check: the reconstructed tree must hash to the root
            // we asked for. Guards against a node store that decodes but is
            // structurally wrong.
            if state.root() == tip.header.app_hash {
                return Ok((state, tip, false));
            }
        }

        let (state, tip) = self.replay(limits)?;
        Ok((state, tip, true))
    }

    /// The state root the store's tip claims.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the tip cannot be read.
    pub fn tip_app_hash(&self) -> Result<Option<Hash32>> {
        let height = self.height()?;
        if height == Height::GENESIS {
            return Ok(None);
        }
        Ok(self.block(height)?.map(|b| b.header.app_hash))
    }
}

/// Reads nodes straight out of the database.
struct TableSource {
    table: redb::ReadOnlyTable<&'static [u8], &'static [u8]>,
}

impl NodeSource for TableSource {
    fn get_node(&self, hash: Hash32) -> Option<Node> {
        let raw = self.table.get(hash.as_bytes().as_slice()).ok()??;
        decode_exact::<Node>(raw.value()).ok()
    }
}

/// Writes nodes into the database, skipping any already present.
///
/// Content addressing makes the skip safe: a node's key *is* its hash, so an
/// existing entry is byte-identical to what we would write.
struct TableSink<'txn> {
    table: redb::Table<'txn, &'static [u8], &'static [u8]>,
    /// First write error, surfaced after the tree walk rather than panicking
    /// inside it — this runs on the commit path and must not abort a node.
    failed: Option<String>,
}

impl NodeSink for TableSink<'_> {
    fn has_node(&self, hash: Hash32) -> bool {
        matches!(self.table.get(hash.as_bytes().as_slice()), Ok(Some(_)))
    }

    fn put_node(&mut self, hash: Hash32, node: &Node) {
        if let Err(e) = self
            .table
            .insert(hash.as_bytes().as_slice(), node.to_bytes().as_slice())
            && self.failed.is_none()
        {
            self.failed = Some(e.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_bank::Issuer;
    use afrolink_consensus::{CountryCode, Validator, ValidatorSet, Vote, VoteType};
    use afrolink_crypto::{Address, SecretKey};
    use afrolink_executor::Allocation;
    use afrolink_primitives::{Amount, ChainId, Denom, Round, Timestamp};
    use afrolink_state::KeyValueStore;
    use std::path::PathBuf;

    /// A temporary database path that cleans itself up.
    struct TempDb(PathBuf);

    impl TempDb {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!("afrolink-{tag}-{nanos}.redb"));
            Self(path)
        }

        fn path(&self) -> &PathBuf {
            &self.0
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid")
    }

    fn validators() -> ValidatorSet {
        ValidatorSet::new(
            (1..=4u8)
                .map(|i| {
                    Validator::new(
                        key(i).public_key(),
                        1,
                        CountryCode::new("ke").expect("valid"),
                    )
                })
                .collect(),
        )
        .expect("valid set")
    }

    fn genesis() -> Genesis {
        Genesis {
            chain_id: chain(),
            genesis_time: Timestamp::from_millis(1_700_000_000_000),
            validators: validators(),
            issuers: vec![(kes(), Issuer::new(addr(100)))],
            allocations: vec![Allocation {
                address: addr(50),
                denom: kes(),
                amount: Amount::from_afri(1_000),
            }],
        }
    }

    /// Build the next empty block over `state`, plus a quorum commit.
    fn next_block(state: &mut MemoryStore, parent: &Block) -> (Block, Commit) {
        let executor = Executor::new(chain());
        let height = parent.header.height.next();
        let (block, _) = executor.build_block(
            state,
            height,
            Timestamp::from_millis(1_700_000_001_000),
            parent.header.id(),
            Vec::new(),
        );
        let block_id = block.header.id();
        let signatures = (1..=3u8)
            .map(|s| {
                Vote {
                    chain_id: chain(),
                    height,
                    round: Round::ZERO,
                    vote_type: VoteType::Precommit,
                    block_id: Some(block_id),
                    validator: addr(s),
                }
                .sign(&key(s))
            })
            .collect();
        (
            block.clone(),
            Commit::new(height, Round::ZERO, block_id, signatures),
        )
    }

    /// Store genesis plus `n` blocks, returning the store and the live state.
    fn seeded(tag: &str, n: u64) -> (TempDb, MemoryStore) {
        let temp = TempDb::new(tag);
        let store = ChainStore::open(temp.path()).expect("opens");
        let g = genesis();
        store.put_genesis(&g).expect("stores genesis");

        let mut state = MemoryStore::new();
        let mut parent = g
            .apply(&mut state, GenesisLimits::devnet())
            .expect("applies");
        for _ in 0..n {
            let (block, commit) = next_block(&mut state, &parent);
            store.put_block(&block, &commit).expect("stores block");
            parent = block;
        }
        (temp, state)
    }

    #[test]
    fn blocks_and_commits_survive_a_reopen() {
        // The whole point of persistence: a node restart must not lose the chain.
        let (temp, _) = seeded("reopen", 3);
        // Original handle dropped by re-opening from the same path.
        let store = ChainStore::open(temp.path()).expect("reopens");

        assert_eq!(store.height().expect("reads"), Height(3));
        for h in 1..=3 {
            assert!(
                store.block(Height(h)).expect("reads").is_some(),
                "block {h} survived"
            );
            assert!(
                store.commit(Height(h)).expect("reads").is_some(),
                "commit {h} survived"
            );
        }
        assert!(store.genesis().expect("reads").is_some());
    }

    #[test]
    fn replay_reproduces_the_live_state_exactly() {
        // Replay is only trustworthy if it lands on the same root as execution.
        let (temp, live) = seeded("replay", 5);
        let store = ChainStore::open(temp.path()).expect("reopens");

        let (replayed, tip) = store.replay(GenesisLimits::devnet()).expect("replays");
        assert_eq!(
            replayed.root(),
            live.root(),
            "replayed state must match live state"
        );
        assert_eq!(tip.header.height, Height(5));
        assert_eq!(tip.header.app_hash, live.root());
    }

    #[test]
    fn replay_of_an_empty_chain_yields_genesis_state() {
        let (temp, live) = seeded("empty", 0);
        let store = ChainStore::open(temp.path()).expect("reopens");

        let (replayed, tip) = store.replay(GenesisLimits::devnet()).expect("replays");
        assert_eq!(replayed.root(), live.root());
        assert_eq!(tip.header.height, Height::GENESIS);
    }

    #[test]
    fn a_tampered_block_is_caught_rather_than_silently_applied() {
        // Database corruption, or a change in execution semantics under a stored
        // chain, must stop the node instead of forking it.
        let temp = TempDb::new("tamper");
        let store = ChainStore::open(temp.path()).expect("opens");
        let g = genesis();
        store.put_genesis(&g).expect("stores genesis");

        let mut state = MemoryStore::new();
        let parent = g
            .apply(&mut state, GenesisLimits::devnet())
            .expect("applies");
        let (mut block, commit) = next_block(&mut state, &parent);

        // Claim a state root the transactions do not produce.
        block.header.app_hash = Hash32::ZERO;
        store.put_block(&block, &commit).expect("stores block");

        assert!(matches!(
            store.replay(GenesisLimits::devnet()),
            Err(StoreError::StateDivergence { height: 1, .. })
        ));
    }

    #[test]
    fn a_gap_in_the_chain_is_detected() {
        let temp = TempDb::new("gap");
        let store = ChainStore::open(temp.path()).expect("opens");
        let g = genesis();
        store.put_genesis(&g).expect("stores genesis");

        let mut state = MemoryStore::new();
        let parent = g
            .apply(&mut state, GenesisLimits::devnet())
            .expect("applies");
        let (block, commit) = next_block(&mut state, &parent);

        // Store it as height 4, leaving 1..=3 missing.
        let mut orphan = block;
        orphan.header.height = Height(4);
        store.put_block(&orphan, &commit).expect("stores block");

        assert!(matches!(
            store.replay(GenesisLimits::devnet()),
            Err(StoreError::MissingBlock(1))
        ));
    }

    #[test]
    fn replay_without_genesis_is_refused() {
        let temp = TempDb::new("nogenesis");
        let store = ChainStore::open(temp.path()).expect("opens");
        assert!(matches!(
            store.replay(GenesisLimits::devnet()),
            Err(StoreError::NoGenesis)
        ));
    }

    #[test]
    fn a_stored_commit_still_verifies_after_a_round_trip() {
        // Certificates must survive encoding intact, or a restarted node cannot
        // prove its own history to a light client.
        let (temp, _) = seeded("commitverify", 2);
        let store = ChainStore::open(temp.path()).expect("reopens");

        let commit = store.commit(Height(2)).expect("reads").expect("exists");
        assert_eq!(commit.verify(&chain(), &validators()), Ok(()));

        let block = store.block(Height(2)).expect("reads").expect("exists");
        assert_eq!(commit.block_id, block.header.id());
    }

    #[test]
    fn missing_heights_read_as_absent_rather_than_erroring() {
        let (temp, _) = seeded("missing", 1);
        let store = ChainStore::open(temp.path()).expect("reopens");
        assert!(store.block(Height(99)).expect("reads").is_none());
        assert!(store.commit(Height(99)).expect("reads").is_none());
    }

    #[test]
    fn height_tracks_the_tip_and_does_not_go_backwards() {
        let (temp, _) = seeded("tip", 2);
        let store = ChainStore::open(temp.path()).expect("reopens");
        assert_eq!(store.height().expect("reads"), Height(2));

        // Re-storing an older block must not rewind the recorded tip.
        let block = store.block(Height(1)).expect("reads").expect("exists");
        let commit = store.commit(Height(1)).expect("reads").expect("exists");
        store.put_block(&block, &commit).expect("stores");
        assert_eq!(
            store.height().expect("reads"),
            Height(2),
            "tip must not rewind"
        );
    }

    #[test]
    fn tip_app_hash_matches_the_stored_header() {
        let (temp, live) = seeded("tiphash", 3);
        let store = ChainStore::open(temp.path()).expect("reopens");
        assert_eq!(store.tip_app_hash().expect("reads"), Some(live.root()));
    }
    #[test]
    fn state_persists_and_reloads_from_its_root() {
        // The ADR-0006 fast path: startup is a root lookup, not a replay.
        let (temp, live) = seeded("persist", 3);
        let store = ChainStore::open(temp.path()).expect("reopens");

        let (root, _) = store.persist_state(&live).expect("persists");
        assert_eq!(root, live.root());

        let reloaded = store
            .load_state(root)
            .expect("reads")
            .expect("all nodes present");
        assert_eq!(
            reloaded.root(),
            live.root(),
            "reloaded state must match exactly"
        );
    }

    #[test]
    fn startup_uses_the_fast_path_when_state_is_persisted() {
        let (temp, live) = seeded("faststart", 3);
        let store = ChainStore::open(temp.path()).expect("reopens");
        store.persist_state(&live).expect("persists");

        let (state, tip, replayed) = store.open_state(GenesisLimits::devnet()).expect("opens");
        assert!(!replayed, "persisted state must not trigger a replay");
        assert_eq!(state.root(), live.root());
        assert_eq!(tip.header.height, Height(3));
    }

    #[test]
    fn startup_falls_back_to_replay_when_nodes_are_absent() {
        // A store with blocks but no persisted nodes — an older database, or one
        // that was pruned. It must still start, just slowly.
        let (temp, live) = seeded("fallback", 3);
        let store = ChainStore::open(temp.path()).expect("reopens");

        let (state, tip, replayed) = store.open_state(GenesisLimits::devnet()).expect("opens");
        assert!(replayed, "with no nodes stored, replay is the only route");
        assert_eq!(
            state.root(),
            live.root(),
            "and it must land on the same state"
        );
        assert_eq!(tip.header.height, Height(3));
    }

    #[test]
    fn only_changed_nodes_are_written_between_versions() {
        // Structural sharing at the database layer: a second commit that changes
        // little must write little, or persistence costs O(state) per block.
        let temp = TempDb::new("sharing");
        let store = ChainStore::open(temp.path()).expect("opens");
        let g = genesis();
        store.put_genesis(&g).expect("stores genesis");

        let mut state = MemoryStore::new();
        g.apply(&mut state, GenesisLimits::devnet())
            .expect("applies");
        for i in 0..400u32 {
            state.set(
                &afrolink_state::StoreKey::balance(&addr(60), &kes()),
                i.to_le_bytes().to_vec(),
            );
            state.set(
                &afrolink_state::StoreKey::new(
                    afrolink_state::store::Namespace::Account,
                    &[&i.to_le_bytes()],
                ),
                vec![1],
            );
        }
        let (_, first) = store.persist_state(&state).expect("persists");

        state.set(
            &afrolink_state::StoreKey::balance(&addr(61), &kes()),
            vec![9],
        );
        let (_, second) = store.persist_state(&state).expect("persists again");

        assert!(
            second.written < first.written / 10,
            "second commit wrote {} of {} nodes — sharing is not working",
            second.written,
            first.written
        );
    }

    #[test]
    fn re_persisting_unchanged_state_writes_nothing() {
        let (temp, live) = seeded("idempotent", 2);
        let store = ChainStore::open(temp.path()).expect("reopens");
        store.persist_state(&live).expect("first");
        let (_, again) = store.persist_state(&live).expect("second");
        assert_eq!(again.written, 0, "identical state must cost no writes");
    }

    #[test]
    fn an_unknown_root_reports_absence_rather_than_partial_state() {
        let (temp, live) = seeded("unknownroot", 1);
        let store = ChainStore::open(temp.path()).expect("reopens");
        store.persist_state(&live).expect("persists");

        // A root that was never committed has no nodes behind it.
        let bogus = afrolink_crypto::hash::hash(
            afrolink_crypto::hash::Domain::StateNode,
            b"never committed",
        );
        assert!(store.load_state(bogus).expect("reads").is_none());
    }

    #[test]
    fn historical_state_stays_addressable_after_newer_commits() {
        // XRPL's property, at the database layer: old roots keep resolving,
        // which is what makes an archive node a config flag rather than a fork.
        let (temp, mut live) = seeded("history", 1);
        let store = ChainStore::open(temp.path()).expect("reopens");
        let (old_root, _) = store.persist_state(&live).expect("persists");

        live.set(
            &afrolink_state::StoreKey::balance(&addr(50), &kes()),
            vec![7],
        );
        let (new_root, _) = store.persist_state(&live).expect("persists");
        assert_ne!(old_root, new_root);

        let old = store
            .load_state(old_root)
            .expect("reads")
            .expect("old root resolves");
        assert_eq!(
            old.root(),
            old_root,
            "historical state must still reconstruct"
        );
    }
}
