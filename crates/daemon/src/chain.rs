//! Where the layers meet.
//!
//! `crates/p2p` defines what it needs from storage as two traits and knows
//! nothing about redb. `crates/store` implements the database and knows nothing
//! about peers. This module is the only place the two names appear together, and
//! it is three newtypes and no logic — which is the point. If either side needed
//! to change to accommodate the other, the seam would be in the wrong place.
//!
//! There is a second reason it lives here rather than in either crate: neither
//! could implement the other's trait without taking on the other's dependency.
//! `crates/store` would grow a Diffie–Hellman implementation to serve a block.

use std::sync::{Arc, Mutex};

use afrolink_consensus::Commit;
use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_executor::{Block, TxReceipt};
use afrolink_p2p::sync::{BlockSource, SyncBlock};
use afrolink_p2p::transport::CommitSink;
use afrolink_primitives::{ChainId, Height};
use afrolink_rpc::{ChainView, HistoryEntry, QueryError, SignedHeader};
use afrolink_state::{KeyValueStore, MemoryStore, Proof, StoreKey};
use afrolink_store::{ChainStore, ServedChain};

/// Serves committed blocks to peers that fell behind.
///
/// Reads from the durable store rather than from the running node's memory. A
/// node serving from memory could only help peers who fell behind while it
/// happened to be up — precisely the case where they needed the least help — and
/// every sync request would queue behind the consensus lock.
pub struct Blocks(pub Arc<ChainStore>);

impl BlockSource for Blocks {
    fn block_at(&self, height: Height) -> Option<SyncBlock> {
        // A block without its certificate proves nothing, so a store that has one
        // and not the other serves neither. `put_block` writes them in a single
        // transaction, so this can only happen to a store somebody edited.
        let block = self.0.block(height).ok().flatten()?;
        let commit = self.0.commit(height).ok().flatten()?;
        Some(SyncBlock { block, commit })
    }
}

/// Writes every finalised block to disk, however this node reached it.
///
/// One implementation for both paths — decided here, learned from a peer —
/// because a node that syncs a height must end up with the same durable record as
/// one that voted on it.
pub struct Persist {
    store: Arc<ChainStore>,
    /// The state the query server answers from, replaced at each height.
    state: Arc<Mutex<MemoryStore>>,
    /// Set when a write fails. The daemon stops rather than carrying on.
    failed: Arc<Mutex<Option<String>>>,
    /// The last few (height, state root) pairs handed to this sink.
    ///
    /// Kept because "the published state is stale" cannot be diagnosed from the
    /// end result: it says which state is wrong and nothing about which write put
    /// it there. Bounded and pulled on failure, never logged as it goes.
    seen: Mutex<Vec<(u64, Hash32, Hash32)>>,
    /// The height of the state currently published.
    ///
    /// # Why publishing needs a guard
    ///
    /// A block reaches this sink from two threads: the consensus driver when
    /// this node decides a height, and the sync path when it learns one from a
    /// peer. Both capture the state **under the node lock and then release it**,
    /// because holding it across a disk write would put every socket behind
    /// consensus. So the interval between "capture state at height H" and
    /// "publish it" is unguarded, and two commits can arrive here out of order.
    ///
    /// The durable store does not care: nodes are content-addressed, so writing
    /// them in any order converges. The *published* view does — an older state
    /// overwriting a newer one means a wallet asks for its balance twice and
    /// gets the newer answer first and the older one second. Nothing is lost on
    /// disk and nothing forks; the money simply appears to go backwards, which
    /// for a payments network is its own kind of unacceptable.
    ///
    /// Locked **before** `state`, always, and it is the only pair of locks here.
    published_height: Mutex<Height>,
}

impl Persist {
    /// A sink writing to `store`, publishing state through `state`.
    #[must_use]
    pub fn new(
        store: Arc<ChainStore>,
        state: Arc<Mutex<MemoryStore>>,
        failed: Arc<Mutex<Option<String>>>,
    ) -> Self {
        Self {
            store,
            state,
            failed,
            published_height: Mutex::new(Height(0)),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// What this sink was handed, most recent last. For failure messages.
    #[must_use]
    pub fn recent(&self) -> String {
        self.seen.lock().map_or_else(
            |_| "poisoned".to_owned(),
            |seen| {
                seen.iter()
                    .map(|(h, root, want)| {
                        let flag = if root == want { "" } else { "!" };
                        format!(
                            "{h}:got={} want={}{flag}",
                            &root.to_hex()[..8],
                            &want.to_hex()[..8]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            },
        )
    }

    fn fail(&self, what: &str) {
        if let Ok(mut slot) = self.failed.lock()
            && slot.is_none()
        {
            *slot = Some(what.to_owned());
        }
    }
}

impl CommitSink for Persist {
    fn committed(
        &self,
        block: &Block,
        commit: &Commit,
        receipts: &[TxReceipt],
        state: &MemoryStore,
    ) {
        // Block, certificate and receipts in one transaction, because a block
        // without its certificate cannot be served to a light client and a
        // certificate without its block proves something about bytes nobody has.
        if let Err(e) = self.store.put_block(block, commit, receipts) {
            self.fail(&format!(
                "cannot store block {}: {e}",
                block.header.height.0
            ));
            return;
        }
        if let Err(e) = self.store.persist_state(state) {
            self.fail(&format!(
                "cannot store state at {}: {e}",
                block.header.height.0
            ));
            return;
        }
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((block.header.height.0, state.root(), block.header.app_hash));
            let len = seen.len();
            if len > 12 {
                seen.drain(..len.saturating_sub(12));
            }
        }
        // Only now is the new state published to readers. A query answered from a
        // state whose block is not yet durable would be a proof against a header
        // that a restart could take back.
        //
        // Never backwards: see `published_height`. The two locks are taken in
        // this order and in no other.
        let Ok(mut at) = self.published_height.lock() else {
            return;
        };
        if block.header.height < *at {
            return;
        }
        if let Ok(mut published) = self.state.lock() {
            *published = state.clone();
            *at = block.header.height;
        }
    }
}

/// A read-only view that follows the chain as it advances.
///
/// [`ServedChain`] borrows the state it proves against, which is right for a
/// value that lives as long as one query and wrong for a server that runs for
/// months. This holds the state behind a lock and builds a `ServedChain` per
/// call, so every query is answered against the tip as it stood when the query
/// arrived rather than as it stood when the process started.
pub struct LiveChain {
    chain_id: ChainId,
    store: Arc<ChainStore>,
    state: Arc<Mutex<MemoryStore>>,
}

impl LiveChain {
    /// A view over `store`, proving against whatever `state` currently holds.
    #[must_use]
    pub fn new(chain_id: ChainId, store: Arc<ChainStore>, state: Arc<Mutex<MemoryStore>>) -> Self {
        Self {
            chain_id,
            store,
            state,
        }
    }

    /// Answer one question against the current tip.
    ///
    /// A poisoned lock becomes a backend error rather than a panic: a query
    /// server that dies because one request panicked is a denial of service
    /// anyone can trigger.
    fn with<T>(
        &self,
        answer: impl FnOnce(&ServedChain<'_>) -> Result<T, QueryError>,
    ) -> Result<T, QueryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| QueryError::Backend("state lock is poisoned".to_owned()))?;
        answer(&ServedChain::new(
            self.chain_id.clone(),
            &self.store,
            &state,
        ))
    }
}

impl ChainView for LiveChain {
    fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    fn tip_height(&self) -> Result<Height, QueryError> {
        self.with(|c| c.tip_height())
    }

    fn signed_header(&self, height: Height) -> Result<Option<SignedHeader>, QueryError> {
        self.with(|c| c.signed_header(height))
    }

    fn prove(&self, key: &StoreKey) -> Result<(Option<Vec<u8>>, Proof), QueryError> {
        self.with(|c| c.prove(key))
    }

    fn block(&self, height: Height) -> Result<Option<Block>, QueryError> {
        self.with(|c| c.block(height))
    }

    fn receipts(&self, height: Height) -> Result<Option<Vec<TxReceipt>>, QueryError> {
        self.with(|c| c.receipts(height))
    }

    fn locate(&self, id: &Hash32) -> Result<Option<(Height, u32)>, QueryError> {
        self.with(|c| c.locate(id))
    }

    fn history(
        &self,
        address: &Address,
        from: Height,
        limit: usize,
    ) -> Result<Option<(Vec<HistoryEntry>, bool)>, QueryError> {
        self.with(|c| c.history(address, from, limit))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]
mod tests {
    use super::*;
    use afrolink_consensus::{CountryCode, Validator, ValidatorSet, Vote, VoteType};
    use afrolink_crypto::SecretKey;
    use afrolink_executor::{Allocation, Executor, Genesis, GenesisLimits, ValidatorSets};
    use afrolink_primitives::{Amount, Denom, Round, Timestamp};
    use afrolink_state::{KeyValueStore, StoreKey};
    use afrolink_types::{Fee, Message, TxBody};

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut path = std::env::temp_dir();
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            path.push(format!("afrolink-persist-{label}-{unique}"));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn chain_id() -> ChainId {
        ChainId::new("afrolink-persist").unwrap()
    }

    /// Genesis, plus two empty blocks on top of it, each with its own state.
    /// One committed height: the block, its certificate, its receipts, and the
    /// state it produced.
    type Committed = (Block, Commit, Vec<TxReceipt>, MemoryStore);

    fn two_heights() -> (Genesis, Vec<Committed>) {
        let validators = ValidatorSet::new(vec![Validator::new(
            key(1).public_key(),
            1,
            CountryCode::new("ke").unwrap(),
        )])
        .unwrap();
        let genesis = Genesis {
            chain_id: chain_id(),
            genesis_time: Timestamp::from_millis(1_700_000_000_000),
            validators: validators.clone(),
            issuers: Vec::new(),
            attestors: Vec::new(),
            council: afrolink_executor::Council::devnet(Address::from_public_key(
                &key(50).public_key(),
            )),
            params: afrolink_executor::ChainParams::devnet(),
            allocations: vec![Allocation {
                address: Address::from_public_key(&key(50).public_key()),
                denom: Denom::native(),
                amount: Amount::from_afri(10),
            }],
        };
        let mut state = MemoryStore::new();
        let mut parent = genesis.apply(&mut state, GenesisLimits::devnet()).unwrap();

        let executor = Executor::new(chain_id());
        let mut blocks = Vec::new();
        for _ in 0..2 {
            let height = parent.header.height.next();
            // A real transfer in each block, so the two states have *different*
            // roots. With empty blocks they do not, and this fixture would let
            // the ordering test pass whether or not the guard exists — which is
            // how it was first written, and why it was rewritten.
            let payment = TxBody {
                chain_id: chain_id(),
                sender: Address::from_public_key(&key(50).public_key()),
                nonce: height.0.saturating_sub(1),
                valid_until: Height(1_000),
                fee: Fee::new(Amount::from_units(1_000), Denom::native()),
                messages: vec![Message::Transfer {
                    to: Address::from_public_key(&key(60).public_key()),
                    denom: Denom::native(),
                    amount: Amount::from_afri(1),
                    reference: None,
                }],
                memo: String::new(),
            }
            .sign(&key(50));
            let (block, outcome) = executor.build_block(
                &mut state,
                height,
                Timestamp::from_millis(
                    1_700_000_000_000u64.saturating_add(height.0.saturating_mul(1_000)),
                ),
                parent.header.id(),
                vec![payment],
                ValidatorSets::unchanged(&validators),
            );
            let block_id = block.header.id();
            let signatures = vec![
                Vote {
                    chain_id: chain_id(),
                    height,
                    round: Round::ZERO,
                    vote_type: VoteType::Precommit,
                    block_id: Some(block_id),
                    validator: Address::from_public_key(&key(1).public_key()),
                }
                .sign(&key(1)),
            ];
            let commit = Commit::new(height, Round::ZERO, block_id, signatures);
            parent = block.clone();
            let receipts: Vec<TxReceipt> =
                outcome.outcomes.iter().map(|o| o.receipt.clone()).collect();
            blocks.push((block, commit, receipts, state.clone()));
        }
        (genesis, blocks)
    }

    #[test]
    fn a_later_state_is_never_replaced_by_an_earlier_one() {
        // **The race this guard exists for.** A block reaches this sink from two
        // threads — the consensus driver when this node decides a height, and
        // the sync path when it learns one from a peer. Both capture their state
        // under the node lock and then *release it* before writing, because
        // holding it across a disk write would put every socket behind
        // consensus. So the window between "capture the state at height H" and
        // "publish it" is unguarded, and two commits can reach the publish step
        // out of order.
        //
        // Modelled here by replaying height 1's commit after height 2's, which
        // is exactly what a late-scheduled thread does. The durable store does
        // not mind — content-addressed nodes converge in any order, and the
        // write is idempotent — but the published view is what queries read.
        //
        // Without the guard a wallet asks for its balance twice and gets the
        // newer answer first and the older one second: money appearing to go
        // backwards on a node behaving perfectly otherwise. Found by a sustained
        // load test rather than by reasoning — 1 000 payments, every receipt
        // `Success`, and the queried balance short by a quarter.
        let dir = TempDir::new("ordering");
        let store = Arc::new(ChainStore::open(dir.0.join("chain.redb")).unwrap());
        let (genesis, blocks) = two_heights();
        store.put_genesis(&genesis).unwrap();

        let published = Arc::new(Mutex::new(MemoryStore::new()));
        let sink = Persist::new(
            Arc::clone(&store),
            Arc::clone(&published),
            Arc::new(Mutex::new(None)),
        );

        let (block1, commit1, receipts1, state1) = &blocks[0];
        let (block2, commit2, receipts2, state2) = &blocks[1];
        assert_ne!(
            state1.root(),
            state2.root(),
            "the fixture must actually change state between heights, or this \
             test cannot tell a stale publish from a fresh one"
        );

        sink.committed(block1, commit1, receipts1, state1);
        sink.committed(block2, commit2, receipts2, state2);
        assert_eq!(published.lock().unwrap().root(), state2.root());

        // Height 1's publish, arriving late.
        sink.committed(block1, commit1, receipts1, state1);
        assert_eq!(
            published.lock().unwrap().root(),
            state2.root(),
            "an older state overwrote a newer one: a query would go backwards"
        );

        // And both blocks are still durable, because the store never had the
        // problem this guard is about.
        assert!(store.block(Height(1)).unwrap().is_some());
        assert!(store.block(Height(2)).unwrap().is_some());
    }

    #[test]
    fn the_newest_state_is_published_when_blocks_arrive_in_order() {
        // The ordinary case must not be broken by the guard: a chain that
        // commits 1 then 2 must end up publishing 2.
        let dir = TempDir::new("in-order");
        let store = Arc::new(ChainStore::open(dir.0.join("chain.redb")).unwrap());
        let (genesis, blocks) = two_heights();
        store.put_genesis(&genesis).unwrap();
        let published = Arc::new(Mutex::new(MemoryStore::new()));
        let sink = Persist::new(
            Arc::clone(&store),
            Arc::clone(&published),
            Arc::new(Mutex::new(None)),
        );

        for (block, commit, receipts, state) in &blocks {
            sink.committed(block, commit, receipts, state);
            assert_eq!(published.lock().unwrap().root(), state.root());
        }
    }

    #[test]
    fn a_balance_is_readable_from_the_published_state() {
        // The guard must not stop the published state being *usable*: a query
        // answered from it has to find the account genesis funded.
        let dir = TempDir::new("readable");
        let store = Arc::new(ChainStore::open(dir.0.join("chain.redb")).unwrap());
        let (genesis, blocks) = two_heights();
        store.put_genesis(&genesis).unwrap();
        let published = Arc::new(Mutex::new(MemoryStore::new()));
        let failed = Arc::new(Mutex::new(None));
        let sink = Persist::new(store, Arc::clone(&published), Arc::clone(&failed));
        let (block, commit, receipts, state) = &blocks[0];
        sink.committed(block, commit, receipts, state);
        assert!(
            failed.lock().unwrap().is_none(),
            "the sink refused the block: {:?}",
            failed.lock().unwrap()
        );
        assert_eq!(published.lock().unwrap().root(), state.root());

        let who = Address::from_public_key(&key(50).public_key());
        let raw = published
            .lock()
            .unwrap()
            .get(&StoreKey::balance(&who, &Denom::native()))
            .expect("genesis funded this account");
        let amount = afrolink_primitives::codec::decode_exact::<Amount>(raw.as_slice()).unwrap();
        // Genesis funded ten, and the block this fixture builds spends one plus
        // the fee. Stated as the arithmetic rather than as a constant, so the
        // number cannot drift away from what the fixture actually does.
        assert_eq!(
            amount.units(),
            Amount::from_afri(10).units() - Amount::from_afri(1).units() - 1_000,
        );
    }
}
