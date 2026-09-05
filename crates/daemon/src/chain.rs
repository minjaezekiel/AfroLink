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

use std::sync::atomic::{AtomicU64, Ordering};
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

/// The state queries are answered from, and the height it is the state *of*.
///
/// # Why these are one value
///
/// They were two: a `Mutex<Height>` beside a `Mutex<MemoryStore>`, kept
/// consistent by a lock-ordering rule written in a doc comment. The rule held
/// where it was written and did not survive the seam. `answer()` took the
/// height from the store's **block tip** and the proof from **this state**, and
/// stamped one on the other — so in the window where a node had written block N
/// but not yet published it, a wallet was handed a proof at N-1 labelled N, and
/// told to check it against block N's header. It does not verify. Not a stale
/// answer: an unverifiable one, from a node behaving correctly.
///
/// A pair of values that must agree, guarded by a convention, is a pair that
/// will eventually disagree. One value cannot.
pub struct Published {
    at: Height,
    state: MemoryStore,
}

impl Published {
    /// A view of `state`, at the height that state belongs to.
    #[must_use]
    pub const fn new(at: Height, state: MemoryStore) -> Self {
        Self { at, state }
    }

    /// The height this view answers at.
    #[must_use]
    pub const fn at(&self) -> Height {
        self.at
    }

    /// The state a proof is built from.
    #[must_use]
    pub const fn state(&self) -> &MemoryStore {
        &self.state
    }

    /// Move the view forward to `height`, unless something newer is published.
    ///
    /// # Never backwards
    ///
    /// A block reaches [`Persist`] from two threads: the consensus driver when
    /// this node decides a height, and the sync path when it learns one from a
    /// peer. Both capture their state **under the node lock and then release
    /// it**, because holding it across a disk write would put every socket
    /// behind consensus. So the interval between "capture state at height H"
    /// and "publish it" is unguarded, and two commits can arrive here out of
    /// order.
    ///
    /// The durable store does not care — nodes are content-addressed, so
    /// writing them in any order converges. This view does: an older state
    /// overwriting a newer one means a wallet asks for its balance twice and
    /// gets the newer answer first and the older one second. Nothing is lost on
    /// disk and nothing forks; the money simply appears to go backwards, which
    /// for a payments network is its own kind of unacceptable.
    ///
    /// Returns whether the view moved.
    pub fn advance(&mut self, height: Height, state: &MemoryStore) -> bool {
        if height < self.at {
            return false;
        }
        self.state = state.clone();
        self.at = height;
        true
    }
}

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
    /// The view the query server answers from, replaced at each height.
    state: Arc<Mutex<Published>>,
    /// Set when a write fails. The daemon stops rather than carrying on.
    failed: Arc<Mutex<Option<String>>>,
    /// The last few trips through this sink, and how far each one got.
    ///
    /// Kept because "the published state is stale" cannot be diagnosed from the
    /// end result: it names the state that is wrong and says nothing about which
    /// write put it there — or whether a write happened at all. Recording only
    /// *finished* commits could not tell "the call never came" from "the call is
    /// still running", and those have opposite causes. So a step is recorded on
    /// **entry** and updated as it advances.
    ///
    /// Bounded and pulled on failure, never logged as it goes: the same rule as
    /// `Manager::sync_snapshot`, and for the same reason — printing this every
    /// commit slowed the loop enough to hide the bug it was printed for.
    seen: Mutex<Vec<Step>>,
    /// Hands out a distinct ticket per call, so concurrent commits can each find
    /// their own entry in `seen` to update.
    tickets: AtomicU64,
}

/// How many trips through the sink are kept for a failure message.
///
/// Twelve is enough to show a stall in context and small enough that the scan
/// in `reached` is free.
const KEEP: usize = 12;

/// How far one trip through [`Persist`] got.
///
/// The distinction that matters is [`Self::Entered`] versus not being in the
/// list at all: a commit that is *in flight* and a commit that never happened
/// look identical from the outside and have nothing in common as causes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Called, and nothing written yet.
    Entered,
    /// State nodes and the block are both on disk.
    Stored,
    /// Readers can see it. The commit is finished.
    Published,
    /// Durable, but a higher height had already been published. Correct, not a
    /// failure — see `published_height`.
    Superseded,
    /// A write failed. The node is halting.
    Failed,
}

impl Stage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Entered => "entered",
            Self::Stored => "stored",
            Self::Published => "published",
            Self::Superseded => "superseded",
            Self::Failed => "failed",
        }
    }
}

/// One commit, as it moves through the sink.
struct Step {
    ticket: u64,
    height: u64,
    /// The root of the state this commit was handed.
    got: Hash32,
    /// The root its block's header claims. These disagreeing is corruption.
    want: Hash32,
    stage: Stage,
}

impl Persist {
    /// A sink writing to `store`, publishing state through `state`.
    #[must_use]
    pub fn new(
        store: Arc<ChainStore>,
        state: Arc<Mutex<Published>>,
        failed: Arc<Mutex<Option<String>>>,
    ) -> Self {
        Self {
            store,
            state,
            failed,
            seen: Mutex::new(Vec::new()),
            tickets: AtomicU64::new(0),
        }
    }

    /// What this sink was handed and how far each one got, oldest first.
    ///
    /// For failure messages only. A `!` marks a state root that disagrees with
    /// the header its block carries, which would be corruption rather than
    /// lateness.
    #[must_use]
    pub fn recent(&self) -> String {
        self.seen.lock().map_or_else(
            |_| "poisoned".to_owned(),
            |seen| {
                seen.iter()
                    .map(|step| {
                        let flag = if step.got == step.want { "" } else { "!" };
                        format!(
                            "{}:{}{flag} got={}",
                            step.height,
                            step.stage.as_str(),
                            &step.got.to_hex()[..8]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            },
        )
    }

    /// The height of the state readers are currently answered from.
    ///
    /// **This, not the store's block tip, is what "this node is ready to answer
    /// queries at height H" means.** The two move at different moments: the
    /// block tip advances when the block is written, and publication happens
    /// after that. Anything deciding whether a node is caught up — a health
    /// check, a load balancer, a test's settle condition — has to read this one,
    /// or it will call a node ready while its query view is still a block behind.
    #[must_use]
    pub fn published_height(&self) -> Height {
        self.state.lock().map_or(Height(0), |view| view.at())
    }

    /// Record a commit on the way in, and hand back the ticket that finds it.
    fn enter(&self, block: &Block, state: &MemoryStore) -> u64 {
        let ticket = self.tickets.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(Step {
                ticket,
                height: block.header.height.0,
                got: state.root(),
                want: block.header.app_hash,
                stage: Stage::Entered,
            });
            let len = seen.len();
            if len > KEEP {
                seen.drain(..len.saturating_sub(KEEP));
            }
        }
        ticket
    }

    /// Move a recorded commit on to its next stage.
    ///
    /// A ticket whose entry has already aged out of the buffer is dropped
    /// silently: this is a diagnostic, and one that could block a commit or
    /// panic would be worse than the defect it exists to explain.
    fn reached(&self, ticket: u64, stage: Stage) {
        if let Ok(mut seen) = self.seen.lock()
            && let Some(step) = seen.iter_mut().find(|step| step.ticket == ticket)
        {
            step.stage = stage;
        }
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
        let ticket = self.enter(block, state);

        // **State first, block second.** Both orders survive a crash — an
        // orphaned state node is unreferenced garbage, and a block whose state
        // is missing sends `open_state` down the replay path it already has —
        // so correctness does not choose between them. What chooses is the
        // window they leave open to a reader.
        //
        // The store's block tip is visible to everything: sync serves from it,
        // the harness settles on it, an operator's health check reads it. It
        // moves the instant `put_block` commits, while publication happens
        // after. Writing the state first shrinks the interval between those two
        // from a whole state-tree write down to a lock and a clone.
        //
        // That interval is exactly what [10 §18](../../../docs/10-network-hardening.md)
        // observed: a store holding block N whose published view was still at
        // N-1, on four healthy nodes at once, with nothing failed.
        if let Err(e) = self.store.persist_state(state) {
            self.reached(ticket, Stage::Failed);
            self.fail(&format!(
                "cannot store state at {}: {e}",
                block.header.height.0
            ));
            return;
        }
        // Block, certificate and receipts in one transaction, because a block
        // without its certificate cannot be served to a light client and a
        // certificate without its block proves something about bytes nobody has.
        if let Err(e) = self.store.put_block(block, commit, receipts) {
            self.reached(ticket, Stage::Failed);
            self.fail(&format!(
                "cannot store block {}: {e}",
                block.header.height.0
            ));
            return;
        }
        self.reached(ticket, Stage::Stored);

        // Only now is the new state published to readers. A query answered from
        // a state whose block is not yet durable would be a proof against a
        // header that a restart could take back.
        //
        // One lock, because the height and the state are one value. See
        // [`Published::advance`] for why it never moves backwards.
        let Ok(mut view) = self.state.lock() else {
            return;
        };
        let moved = view.advance(block.header.height, state);
        drop(view);
        self.reached(
            ticket,
            if moved {
                Stage::Published
            } else {
                Stage::Superseded
            },
        );
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
    state: Arc<Mutex<Published>>,
}

impl LiveChain {
    /// A view over `store`, proving against whatever `state` currently holds.
    #[must_use]
    pub fn new(chain_id: ChainId, store: Arc<ChainStore>, state: Arc<Mutex<Published>>) -> Self {
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
            state.state(),
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

    /// **Not** delegated to [`ServedChain`], and that is the whole point.
    ///
    /// `ServedChain::prove` answers with its store's block tip, which is right
    /// for a view built around the state at that tip. This one is not: the
    /// state here is what [`Persist`] has published, and a node that has
    /// written block N has not necessarily published it yet. Delegating would
    /// label an N-1 proof as N and send the client to a header it cannot check
    /// the proof against.
    ///
    /// The height and the proof come out of one lock on one value, so nothing
    /// can commit between them.
    fn prove(&self, key: &StoreKey) -> Result<(Height, Option<Vec<u8>>, Proof), QueryError> {
        let view = self
            .state
            .lock()
            .map_err(|_| QueryError::Backend("state lock is poisoned".to_owned()))?;
        let (value, proof) = view.state().get_with_proof(key);
        Ok((view.at(), value, proof))
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
    use afrolink_rpc::{Query, Response, answer};
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

        let published = Arc::new(Mutex::new(Published::new(Height(0), MemoryStore::new())));
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
        assert_eq!(published.lock().unwrap().state().root(), state2.root());

        // Height 1's publish, arriving late.
        sink.committed(block1, commit1, receipts1, state1);
        assert_eq!(
            published.lock().unwrap().state().root(),
            state2.root(),
            "an older state overwrote a newer one: a query would go backwards"
        );

        // And both blocks are still durable, because the store never had the
        // problem this guard is about.
        assert!(store.block(Height(1)).unwrap().is_some());
        assert!(store.block(Height(2)).unwrap().is_some());
    }

    #[test]
    fn a_proof_is_labelled_with_the_height_it_was_actually_built_from() {
        // **§18, made deterministic.**
        //
        // A node writes block N to its store and publishes the state a moment
        // later — two acts, no way to make them one. In between, the block store
        // says N and the view a query is answered from says N-1. Racy in the
        // wild; here it is simply *set up*, because a race whose window has been
        // shrunk still has to be tested, and the way to test it is to stop
        // relying on hitting the window.
        //
        // The old `answer()` took the height from the block store and the proof
        // from the published state. A wallet given that pair fetches the header
        // at N and checks an N-1 proof against it. It does not verify. The user
        // is not shown a stale balance — they are shown nothing at all, by a
        // node that is behaving correctly and cannot be told apart from one
        // serving forged proofs.
        let dir = TempDir::new("proof-height");
        let store = Arc::new(ChainStore::open(dir.0.join("chain.redb")).unwrap());
        let (genesis, blocks) = two_heights();
        store.put_genesis(&genesis).unwrap();

        let published = Arc::new(Mutex::new(Published::new(Height(0), MemoryStore::new())));
        let sink = Persist::new(
            Arc::clone(&store),
            Arc::clone(&published),
            Arc::new(Mutex::new(None)),
        );

        // Height 1 committed and published, the ordinary way.
        let (block1, commit1, receipts1, state1) = &blocks[0];
        sink.committed(block1, commit1, receipts1, state1);

        // Height 2 durable, not yet published: the window itself.
        let (block2, commit2, receipts2, _) = &blocks[1];
        store.put_block(block2, commit2, receipts2).unwrap();
        assert_eq!(store.height().unwrap(), Height(2));
        assert_eq!(published.lock().unwrap().at(), Height(1));

        let view = LiveChain::new(chain_id(), Arc::clone(&store), Arc::clone(&published));
        let who = Address::from_public_key(&key(50).public_key());
        let query = Query::Balance {
            address: who,
            denom: Denom::native(),
        };
        let Response::Value(proved) = answer(&view, &query).expect("the node can answer") else {
            panic!("a balance query is answered with a proved value");
        };

        // What a wallet does next: fetch the header the answer named, and check
        // the proof against the state root that header commits to.
        let header = store
            .block(proved.height())
            .unwrap()
            .expect("the node named a height it holds")
            .header;
        let key_bytes = StoreKey::balance(&who, &Denom::native());
        let value = published.lock().unwrap().state().get(&key_bytes);
        assert!(
            proved
                .proof()
                .verify(header.app_hash, key_bytes.as_bytes(), value.as_deref()),
            "the node answered at height {} but proved against a different state: \
             the header there claims {}, and this proof does not reconstruct it",
            proved.height().0,
            &header.app_hash.to_hex()[..12]
        );

        // And the reason it verifies is the label, not luck: the two heights
        // really do have different roots, so stamping the wrong one could not
        // have passed by coincidence.
        assert_eq!(proved.height(), Height(1));
        assert_ne!(
            blocks[0].0.header.app_hash, blocks[1].0.header.app_hash,
            "the fixture must change state between heights, or this test cannot \
             tell a correct label from a wrong one"
        );
    }

    #[test]
    fn the_newest_state_is_published_when_blocks_arrive_in_order() {
        // The ordinary case must not be broken by the guard: a chain that
        // commits 1 then 2 must end up publishing 2.
        let dir = TempDir::new("in-order");
        let store = Arc::new(ChainStore::open(dir.0.join("chain.redb")).unwrap());
        let (genesis, blocks) = two_heights();
        store.put_genesis(&genesis).unwrap();
        let published = Arc::new(Mutex::new(Published::new(Height(0), MemoryStore::new())));
        let sink = Persist::new(
            Arc::clone(&store),
            Arc::clone(&published),
            Arc::new(Mutex::new(None)),
        );

        for (block, commit, receipts, state) in &blocks {
            sink.committed(block, commit, receipts, state);
            assert_eq!(published.lock().unwrap().state().root(), state.root());
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
        let published = Arc::new(Mutex::new(Published::new(Height(0), MemoryStore::new())));
        let failed = Arc::new(Mutex::new(None));
        let sink = Persist::new(store, Arc::clone(&published), Arc::clone(&failed));
        let (block, commit, receipts, state) = &blocks[0];
        sink.committed(block, commit, receipts, state);
        assert!(
            failed.lock().unwrap().is_none(),
            "the sink refused the block: {:?}",
            failed.lock().unwrap()
        );
        assert_eq!(published.lock().unwrap().state().root(), state.root());

        let who = Address::from_public_key(&key(50).public_key());
        let raw = published
            .lock()
            .unwrap()
            .state()
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
