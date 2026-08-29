//! Serving proof-carrying queries from durable storage.
//!
//! `crates/rpc` defines the protocol and deliberately knows nothing about redb.
//! This module is the join: it implements
//! [`ChainView`](afrolink_rpc::ChainView) over a [`ChainStore`] and the state
//! tree the node currently holds.
//!
//! The separation is worth the extra type. The query protocol is where a
//! hostile client meets the node, so it is tested against an adversary in
//! isolation; keeping storage out of it means those tests cannot accidentally
//! depend on a database being present.

use afrolink_primitives::{ChainId, Height};
use afrolink_rpc::{ChainView, QueryError, SignedHeader};
use afrolink_state::{KeyValueStore, MemoryStore, Proof, StoreKey};

use crate::ChainStore;

/// A read-only view over a node's blocks and current state.
///
/// Borrows rather than owns: the node keeps writing while queries are served,
/// and the borrow checker makes the read/write split explicit rather than
/// leaving it to a comment.
pub struct ServedChain<'a> {
    chain_id: ChainId,
    store: &'a ChainStore,
    state: &'a MemoryStore,
}

impl<'a> ServedChain<'a> {
    /// Wrap a store and the state at its tip.
    ///
    /// `state` must be the state the tip's `app_hash` commits to. Passing state
    /// from another height would produce proofs that verify against nothing —
    /// caught immediately by any client, but wasteful, so callers should pass
    /// what [`ChainStore::open_state`](crate::ChainStore::open_state) returned.
    #[must_use]
    pub fn new(chain_id: ChainId, store: &'a ChainStore, state: &'a MemoryStore) -> Self {
        Self {
            chain_id,
            store,
            state,
        }
    }
}

/// Storage failures become `Backend`, never a missing value.
fn backend(e: &crate::StoreError) -> QueryError {
    QueryError::Backend(e.to_string())
}

impl ChainView for ServedChain<'_> {
    fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    fn tip_height(&self) -> Result<Height, QueryError> {
        self.store.height().map_err(|e| backend(&e))
    }

    fn signed_header(&self, height: Height) -> Result<Option<SignedHeader>, QueryError> {
        let Some(block) = self.store.block(height).map_err(|e| backend(&e))? else {
            return Ok(None);
        };
        // A block without its commit is unusable to a light client, and saying
        // "not found" would send it looking elsewhere for something this node
        // actually has. Report the real problem instead.
        let commit = self
            .store
            .commit(height)
            .map_err(|e| backend(&e))?
            .ok_or(QueryError::NoCommit(height.0))?;

        Ok(Some(SignedHeader {
            header: block.header,
            commit,
        }))
    }

    fn prove(&self, key: &StoreKey) -> Result<(Option<Vec<u8>>, Proof), QueryError> {
        Ok(self.state.get_with_proof(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_bank::Issuer;
    use afrolink_consensus::{Commit, CountryCode, Validator, ValidatorSet, Vote, VoteType};
    use afrolink_crypto::{Address, SecretKey};
    use afrolink_executor::{Allocation, Block, Executor, Genesis, GenesisLimits};
    use afrolink_light::LightClient;
    use afrolink_primitives::{Amount, Denom, Round, Timestamp};
    use afrolink_rpc::{Query, Response, answer};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-serve-test").unwrap()
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").unwrap()
    }

    fn validators() -> ValidatorSet {
        ValidatorSet::new(
            (1..=4u8)
                .map(|i| Validator::new(key(i).public_key(), 1, CountryCode::new("ke").unwrap()))
                .collect(),
        )
        .unwrap()
    }

    fn commit_for(block: &Block) -> Commit {
        let block_id = block.header.id();
        let signatures = (1..=4u8)
            .map(|s| {
                Vote {
                    chain_id: chain(),
                    height: block.header.height,
                    round: Round::ZERO,
                    vote_type: VoteType::Precommit,
                    block_id: Some(block_id),
                    validator: addr(s),
                }
                .sign(&key(s))
            })
            .collect();
        Commit::new(block.header.height, Round::ZERO, block_id, signatures)
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("afrolink-serve-{name}-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// A funded chain on disk with a real tip above genesis, plus the state
    /// that tip commits to and a light client already advanced to it.
    ///
    /// Two blocks rather than one on purpose: `open_state` replays at genesis by
    /// design, so a genesis-only fixture would never exercise the fast path it
    /// is meant to test.
    fn chain_on_disk(path: &std::path::Path) -> (ChainStore, MemoryStore, Block, LightClient) {
        let genesis = Genesis {
            chain_id: chain(),
            genesis_time: Timestamp::from_millis(1_700_000_000_000),
            validators: validators(),
            issuers: vec![(kes(), Issuer::new(addr(100)))],
            allocations: vec![Allocation {
                address: addr(50),
                denom: kes(),
                amount: Amount::from_afri(2_500),
            }],
        };

        let store = ChainStore::open(path).unwrap();
        store.put_genesis(&genesis).unwrap();

        let mut state = MemoryStore::new();
        let genesis_block = genesis.apply(&mut state, GenesisLimits::devnet()).unwrap();
        store
            .put_block(&genesis_block, &commit_for(&genesis_block))
            .unwrap();

        let executor = Executor::new(chain());
        let (tip, _) = executor.build_block(
            &mut state,
            genesis_block.header.height.next(),
            Timestamp::from_millis(1_700_000_001_000),
            genesis_block.header.id(),
            Vec::new(),
        );
        let tip_commit = commit_for(&tip);
        store.put_block(&tip, &tip_commit).unwrap();
        store.persist_state(&state).unwrap();

        // The wallet starts at genesis — its only act of trust — and walks
        // forward by verifying commits, exactly as it would in the field.
        let mut client = LightClient::new(chain(), validators(), genesis_block.header.clone());
        client.update(tip.header.clone(), &tip_commit).unwrap();

        (store, state, tip, client)
    }

    #[test]
    fn a_wallet_verifies_a_balance_served_from_disk() {
        // The end-to-end claim, with a real database in the middle: a phone
        // holding one header and the validator set checks its money against a
        // node it does not trust.
        let path = temp_path("balance");
        let (store, state, _tip, client) = chain_on_disk(&path);
        let view = ServedChain::new(chain(), &store, &state);

        let query = Query::Balance {
            address: addr(50),
            denom: kes(),
        };
        let response = answer(&view, &query).unwrap();

        let balance = response
            .as_value()
            .unwrap()
            .verify_amount(&client, &query.store_key().unwrap())
            .unwrap();

        assert_eq!(balance, Amount::from_afri(2_500));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_status_query_returns_a_tip_that_verifies() {
        let path = temp_path("status");
        let (store, state, _tip, _client) = chain_on_disk(&path);
        let view = ServedChain::new(chain(), &store, &state);

        let Response::Status(status) = answer(&view, &Query::Status).unwrap() else {
            panic!("expected status");
        };

        assert_eq!(status.chain_id, chain());
        status.tip.verify(&chain(), &validators()).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_height_this_node_does_not_have_is_reported_as_missing() {
        let path = temp_path("missing");
        let (store, state, _tip, _client) = chain_on_disk(&path);
        let view = ServedChain::new(chain(), &store, &state);

        let err = answer(&view, &Query::Header { height: Height(7) }).unwrap_err();
        assert_eq!(err, QueryError::NoSuchHeight(7));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_absence_served_from_disk_is_proved_rather_than_asserted() {
        let path = temp_path("absent");
        let (store, state, _tip, client) = chain_on_disk(&path);
        let view = ServedChain::new(chain(), &store, &state);

        let query = Query::Balance {
            address: addr(77),
            denom: kes(),
        };
        let response = answer(&view, &query).unwrap();

        assert_eq!(
            response
                .as_value()
                .unwrap()
                .verify_amount(&client, &query.store_key().unwrap())
                .unwrap(),
            Amount::ZERO
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn state_restored_from_disk_serves_proofs_that_still_verify() {
        // Content-addressed persistence (ADR-0006) has to round-trip well
        // enough to prove against, not merely to reload. A node restarting and
        // serving unverifiable proofs would be a silent, client-side failure.
        let path = temp_path("reload");
        let (store, state, expected_tip, client) = chain_on_disk(&path);
        drop(state);

        let (reloaded, tip, replayed) = store.open_state(GenesisLimits::devnet()).unwrap();
        assert!(!replayed, "expected the fast path, not a replay");
        assert_eq!(tip.header.id(), expected_tip.header.id());

        let view = ServedChain::new(chain(), &store, &reloaded);

        let query = Query::Balance {
            address: addr(50),
            denom: kes(),
        };
        let balance = answer(&view, &query)
            .unwrap()
            .as_value()
            .unwrap()
            .verify_amount(&client, &query.store_key().unwrap())
            .unwrap();

        assert_eq!(balance, Amount::from_afri(2_500));
        let _ = std::fs::remove_file(&path);
    }
}
