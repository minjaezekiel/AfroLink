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
use afrolink_state::{MemoryStore, Proof, StoreKey};
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
        // Only now is the new state published to readers. A query answered from a
        // state whose block is not yet durable would be a proof against a header
        // that a restart could take back.
        if let Ok(mut published) = self.state.lock() {
            *published = state.clone();
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
