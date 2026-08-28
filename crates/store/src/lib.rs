//! Durable storage for the chain.
//!
//! # What is persisted, and what is not
//!
//! This store keeps the **genesis file, every block, and every commit
//! certificate**. It does *not* persist the state tree. On startup the node
//! replays blocks from genesis to reconstruct state, then checks that the
//! resulting `app_hash` matches the one in the last stored header.
//!
//! That is a deliberate trade, and worth being explicit about:
//!
//! * **Cost:** startup is `O(chain length)`. At 1s blocks a year of history is
//!   ~31 million blocks, which is far too slow — so state snapshotting is
//!   required before any long-lived network, and is on the Phase 2 roadmap.
//! * **Benefit:** there is exactly one source of truth. A state snapshot that
//!   disagrees with the blocks is a silent, catastrophic class of bug; replay
//!   makes that disagreement impossible to represent, and the app-hash check on
//!   startup turns database corruption or an accidental change in execution
//!   semantics into a loud failure rather than a fork.
//!
//! Blocks and commits are stored together and atomically, because a block
//! without its certificate cannot be served to a light client, and a certificate
//! without its block proves nothing.

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
use afrolink_state::MemoryStore;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;
use thiserror::Error;

/// Blocks by height.
const BLOCKS: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("blocks");
/// Commit certificates by height.
const COMMITS: TableDefinition<'_, u64, &[u8]> = TableDefinition::new("commits");
/// Singleton values: genesis, latest height.
const META: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("meta");

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
}
