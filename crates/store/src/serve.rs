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

use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_executor::{Block, TxReceipt};
use afrolink_primitives::{ChainId, Height};
use afrolink_rpc::{ChainView, HistoryEntry, QueryError, SignedHeader};
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

    fn block(&self, height: Height) -> Result<Option<Block>, QueryError> {
        self.store.block(height).map_err(|e| backend(&e))
    }

    fn receipts(&self, height: Height) -> Result<Option<Vec<TxReceipt>>, QueryError> {
        self.store.receipts(height).map_err(|e| backend(&e))
    }

    fn locate(&self, id: &Hash32) -> Result<Option<(Height, u32)>, QueryError> {
        self.store.locate(id).map_err(|e| backend(&e))
    }

    fn history(
        &self,
        address: &Address,
        from: Height,
        limit: usize,
    ) -> Result<Option<(Vec<HistoryEntry>, bool)>, QueryError> {
        // A `ChainStore` always indexes — the index is written in the same
        // transaction as the block, so it cannot lag. A node role that
        // deliberately does not index would return `Ok(None)` here instead.
        let (rows, truncated) = self
            .store
            .history(address, from, limit)
            .map_err(|e| backend(&e))?;
        let entries = rows
            .into_iter()
            .map(|(height, index, tx_id)| HistoryEntry {
                height,
                index,
                tx_id,
            })
            .collect();
        Ok(Some((entries, truncated)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_bank::Issuer;
    use afrolink_consensus::{Commit, CountryCode, Validator, ValidatorSet, Vote, VoteType};
    use afrolink_crypto::{Address, SecretKey};
    use afrolink_executor::{Allocation, Block, Executor, Genesis, GenesisLimits, ValidatorSets};
    use afrolink_light::LightClient;
    use afrolink_primitives::{Amount, Denom, Round, Timestamp};
    use afrolink_rpc::{Query, Response, answer};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    /// A wall-clock reading well inside the trusting period for these fixtures.
    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_100_000)
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

    /// The committed half of an execution — what a block's header commits to.
    fn receipts(outcome: &afrolink_executor::BlockOutcome) -> Vec<TxReceipt> {
        outcome.outcomes.iter().map(|o| o.receipt.clone()).collect()
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
            .put_block(&genesis_block, &commit_for(&genesis_block), &[])
            .unwrap();

        let executor = Executor::new(chain());
        let (tip, tip_outcome) = executor.build_block(
            &mut state,
            genesis_block.header.height.next(),
            Timestamp::from_millis(1_700_000_001_000),
            genesis_block.header.id(),
            Vec::new(),
            ValidatorSets::unchanged(&validators()),
        );
        let tip_commit = commit_for(&tip);
        store
            .put_block(&tip, &tip_commit, &receipts(&tip_outcome))
            .unwrap();
        store.persist_state(&state).unwrap();

        // The wallet starts at genesis — its only act of trust — and walks
        // forward by verifying commits, exactly as it would in the field.
        let mut client = LightClient::new(chain(), validators(), genesis_block.header.clone());
        client
            .update(
                tip.header.clone(),
                &tip_commit,
                validators(),
                validators(),
                now(),
            )
            .unwrap();

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

    // -- Human-readable addressing, end to end (ADR-0008) --------------------

    /// Seal the current state into a block, store it, and advance `client`.
    fn seal_block(
        store: &ChainStore,
        state: &mut MemoryStore,
        parent: &Block,
        client: &mut LightClient,
        transactions: Vec<afrolink_types::Transaction>,
    ) -> Block {
        let expected = transactions.len();
        let executor = Executor::new(chain());
        let (block, outcome) = executor.build_block(
            state,
            parent.header.height.next(),
            Timestamp::from_millis(1_700_000_002_000),
            parent.header.id(),
            transactions,
            ValidatorSets::unchanged(&validators()),
        );
        assert_eq!(
            outcome.succeeded(),
            expected,
            "expected {expected} successful transactions, got {:?}",
            outcome
                .outcomes
                .iter()
                .map(|o| &o.result)
                .collect::<Vec<_>>()
        );

        let commit = commit_for(&block);
        store
            .put_block(&block, &commit, &receipts(&outcome))
            .unwrap();
        store.persist_state(state).unwrap();
        client
            .update(
                block.header.clone(),
                &commit,
                validators(),
                validators(),
                now(),
            )
            .unwrap();
        block
    }

    /// A signed transaction from account 50 carrying `messages`.
    fn tx_from_50(messages: Vec<afrolink_types::Message>) -> afrolink_types::Transaction {
        use afrolink_types::{Fee, TxBody};

        TxBody {
            chain_id: chain(),
            sender: addr(50),
            nonce: 0,
            valid_until: Height(10_000),
            fee: Fee::new(Amount::from_units(1_000), kes()),
            messages,
            memo: String::new(),
        }
        .sign(&key(50))
    }

    #[test]
    fn a_wallet_resolves_a_username_to_an_address_with_a_proof() {
        // The whole point of ADR-0008, end to end and through a real database:
        // a user types @amina, and the wallet learns which address that is
        // without trusting the node that told it.
        use afrolink_alias::{NameRecord, Username};
        use afrolink_primitives::codec::decode_exact;

        let path = temp_path("resolve-name");
        let (store, mut state, tip, mut client) = chain_on_disk(&path);

        let name = Username::new("amina").unwrap();
        seal_block(
            &store,
            &mut state,
            &tip,
            &mut client,
            vec![tx_from_50(vec![afrolink_types::Message::RegisterName {
                name: name.clone(),
            }])],
        );

        let view = ServedChain::new(chain(), &store, &state);
        let query = Query::ResolveName { name };

        let response = answer(&view, &query).unwrap();
        let bytes = response
            .as_value()
            .unwrap()
            .verify(&client, &query.store_key().unwrap())
            .unwrap()
            .expect("the name is registered");

        let record = decode_exact::<NameRecord>(bytes).unwrap();
        assert_eq!(record.owner, addr(50));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_node_cannot_lie_about_who_owns_a_name() {
        // A hostile node's best attack is to answer with an address it
        // controls. The proof is against the app hash in a header the wallet
        // verified from commit signatures, so the substitution cannot survive.
        use afrolink_alias::{NameRecord, Username};
        use afrolink_primitives::codec::{Encode, decode_exact};

        let path = temp_path("forge-name");
        let (store, mut state, tip, mut client) = chain_on_disk(&path);

        let name = Username::new("amina").unwrap();
        seal_block(
            &store,
            &mut state,
            &tip,
            &mut client,
            vec![tx_from_50(vec![afrolink_types::Message::RegisterName {
                name: name.clone(),
            }])],
        );

        let view = ServedChain::new(chain(), &store, &state);
        let query = Query::ResolveName { name };
        let honest = answer(&view, &query).unwrap();
        let proof = honest.as_value().unwrap().proof().clone();

        // Forge the response the way a hostile node actually would: assemble
        // the wire bytes with the attacker's address and the honest proof, and
        // hand them to the wallet to decode.
        let forged_record = NameRecord {
            owner: addr(66),
            registered_at: Height(1),
            expires_at: Height(999_999),
        };

        let mut wire = vec![2u8]; // Response::Value
        honest.as_value().unwrap().height().encode(&mut wire);
        Some(forged_record.to_bytes()).encode(&mut wire);
        proof.encode(&mut wire);

        let forged = decode_exact::<afrolink_rpc::Response>(&wire).unwrap();

        assert!(
            forged
                .as_value()
                .unwrap()
                .verify(&client, &query.store_key().unwrap())
                .is_err(),
            "a substituted owner must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolving_an_unregistered_name_is_a_proved_absence() {
        // "Nobody has that name" is a claim the node must prove like any other,
        // so it cannot quietly withhold a registration it dislikes.
        use afrolink_alias::Username;

        let path = temp_path("absent-name");
        let (store, state, _tip, client) = chain_on_disk(&path);
        let view = ServedChain::new(chain(), &store, &state);

        let query = Query::ResolveName {
            name: Username::new("nobody").unwrap(),
        };
        let response = answer(&view, &query).unwrap();

        assert_eq!(
            response
                .as_value()
                .unwrap()
                .verify(&client, &query.store_key().unwrap())
                .unwrap(),
            None
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_phone_number_resolves_without_the_chain_ever_holding_it() {
        // Resolution works from a commitment alone. The node answering the
        // query never sees the number, and neither does the state it serves.
        use afrolink_alias::{Attestor, Bindings, ContactCommitment, ContactKind, ContactRecord};
        use afrolink_primitives::codec::decode_exact;
        use afrolink_state::KeyValueStore;

        let path = temp_path("resolve-phone");
        let (store, mut state, tip, mut client) = chain_on_disk(&path);

        // Licence an attestor directly in state: attestor registration is a
        // governance action, and governance is not built yet.
        Bindings::new(&mut state).register_attestor(
            &addr(10),
            &Attestor {
                country: *b"ke",
                name: "Safaricom".to_owned(),
                active: true,
            },
        );

        let pepper = b"a-sixteen-byte-pepper-or-longer";
        let commitment =
            ContactCommitment::new(ContactKind::Phone, "+254712345678", pepper).unwrap();
        Bindings::new(&mut state)
            .attest(&commitment, addr(50), addr(10), Height(1))
            .unwrap();

        // Seal that state into a block so a header commits to it.
        seal_block(&store, &mut state, &tip, &mut client, Vec::new());

        let view = ServedChain::new(chain(), &store, &state);
        let query = Query::ResolveContact { commitment };
        let response = answer(&view, &query).unwrap();
        let bytes = response
            .as_value()
            .unwrap()
            .verify(&client, &query.store_key().unwrap())
            .unwrap()
            .expect("the contact is bound");

        let record = decode_exact::<ContactRecord>(bytes).unwrap();
        assert_eq!(record.address, addr(50));

        // And the number appears nowhere in the state that was served.
        let key = query.store_key().unwrap();
        let stored = state.get(&key).unwrap();
        assert!(
            !stored.windows(9).any(|w| w == b"712345678"),
            "the served record must not contain the number"
        );
        let _ = std::fs::remove_file(&path);
    }
}
