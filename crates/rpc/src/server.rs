//! Answering queries: a pure function from a [`ChainView`] to a [`Response`].

use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::merkle::MerkleTree;
use afrolink_executor::{Block, TxReceipt};
use afrolink_primitives::codec::Encode;
use afrolink_primitives::{ChainId, Height};
use afrolink_state::{Proof, StoreKey};
use afrolink_types::Transaction;

use crate::query::{
    History, HistoryEntry, MAX_HISTORY, ProvedTransaction, ProvedValue, Query, QueryError,
    Response, SignedHeader, Status,
};

/// What [`answer`] needs from a node.
///
/// Deliberately narrow. A node has a mempool, peers, a keystore and a consensus
/// engine; none of that can influence a query, and the way to guarantee it is to
/// make it unreachable from here.
///
/// Every method is fallible so a storage failure stays distinguishable from an
/// absent value. Collapsing the two would let a node with a failing disk report
/// that accounts have no balance, which is the most damaging lie this API could
/// tell.
pub trait ChainView {
    /// The network this node serves.
    fn chain_id(&self) -> &ChainId;

    /// The height of the tip.
    ///
    /// # Errors
    /// Backend failures only.
    fn tip_height(&self) -> Result<Height, QueryError>;

    /// A signed header at `height`, if this node retains it.
    ///
    /// # Errors
    /// Backend failures only; a pruned or future height is `Ok(None)`.
    fn signed_header(&self, height: Height) -> Result<Option<SignedHeader>, QueryError>;

    /// Read a key from current state and prove the result, saying which height
    /// that state is.
    ///
    /// Returns the height, the value *and* its proof together because all three
    /// must come from the same tree. Two separate calls could straddle a commit
    /// and produce a value that its own proof rejects.
    ///
    /// **The height is part of that rule, not decoration.** A proof is only
    /// checkable against the header whose `app_hash` is the root it was built
    /// from, and a client is told which header to fetch by this number. Taking
    /// it from anywhere else — the store's block tip, say — hands the client a
    /// proof and points it at a header the proof cannot satisfy: not a stale
    /// answer but an unverifiable one, from a node that is behaving correctly.
    /// That is what [10 §18](../../../docs/10-network-hardening.md) turned out
    /// to be.
    ///
    /// # Errors
    /// Backend failures only. An absent key is `Ok((height, None, proof))` —
    /// absence is proved, not reported.
    fn prove(&self, key: &StoreKey) -> Result<(Height, Option<Vec<u8>>, Proof), QueryError>;

    /// A whole block, if this node retains it.
    ///
    /// # Errors
    /// Backend failures only; a pruned or future height is `Ok(None)`.
    fn block(&self, height: Height) -> Result<Option<Block>, QueryError>;

    /// Execution receipts for a block, in execution order.
    ///
    /// Returns `Ok(None)` when this node does not keep them — the same
    /// distinction as [`Self::history`]: not kept is not the same as empty.
    ///
    /// # Errors
    /// Backend failures only.
    fn receipts(&self, height: Height) -> Result<Option<Vec<TxReceipt>>, QueryError>;

    /// Where a transaction sits, as `(height, index)`.
    ///
    /// # Errors
    /// Backend failures only; an unknown id is `Ok(None)`.
    fn locate(&self, id: &Hash32) -> Result<Option<(Height, u32)>, QueryError>;

    /// An account's transactions, oldest first, and whether the scan was
    /// truncated by `limit`.
    ///
    /// Returns `Ok(None)` when this node **does not keep a history index** —
    /// which is not the same as an account having no history, and must not be
    /// collapsed into one. A node that answers "no payments" when it simply is
    /// not indexing has told a wallet something false.
    ///
    /// # Errors
    /// Backend failures only.
    fn history(
        &self,
        address: &Address,
        from: Height,
        limit: usize,
    ) -> Result<Option<(Vec<HistoryEntry>, bool)>, QueryError>;
}

/// Why a submitted transaction was not accepted.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// The node looked at it and said no — bad signature, wrong nonce, full
    /// mempool. The message is the submitter's own business and is safe to
    /// echo: it describes the transaction they sent, not the node's internals.
    #[error("{0}")]
    Rejected(String),
    /// This node does not accept transactions at all.
    ///
    /// A serving node with no consensus role is a legitimate deployment, and it
    /// should say so rather than silently dropping a payment.
    #[error("this node does not accept transactions")]
    NotAccepting,
    /// The node failed for its own reasons.
    #[error("backend error: {0}")]
    Backend(String),
}

/// A node that accepts transactions.
///
/// **Deliberately a separate trait from [`ChainView`].** That trait's own
/// documentation says a query must not be able to reach a node's mempool, and
/// the way to guarantee it is to make it unreachable — so the read path takes a
/// `ChainView` and cannot see this, whatever a future caller does.
///
/// Takes `&self` rather than `&mut self`: a server shares one node across
/// connection threads, so an implementor holds its own lock. Requiring `&mut`
/// here would force the whole read path to serialise behind writes.
pub trait Submit {
    /// Offer a transaction to the node.
    ///
    /// Returns the transaction's id, which is what a wallet polls on.
    ///
    /// # Errors
    /// [`SubmitError`] with a reason the submitter can act on.
    fn submit(&self, transaction: Transaction) -> Result<Hash32, SubmitError>;
}

/// A node that refuses every submission.
///
/// For a read-only deployment — an explorer's backend, an archive — and for
/// tests that have nothing to submit to. Explicit rather than implied: a server
/// built with this one cannot silently look like it accepted a payment.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOnly;

impl Submit for ReadOnly {
    fn submit(&self, _transaction: Transaction) -> Result<Hash32, SubmitError> {
        Err(SubmitError::NotAccepting)
    }
}

/// Answer one query.
///
/// # Errors
/// Returns [`QueryError`] when the node cannot answer — never when the answer
/// is simply "nothing is stored there", which is a proved absence.
pub fn answer<V: ChainView + ?Sized>(view: &V, query: &Query) -> Result<Response, QueryError> {
    match query {
        Query::Status => {
            let height = view.tip_height()?;
            let tip = view
                .signed_header(height)?
                .ok_or(QueryError::NoSuchHeight(height.0))?;
            Ok(Response::Status(Status {
                chain_id: view.chain_id().clone(),
                tip,
            }))
        }
        Query::Header { height } => {
            let header = view
                .signed_header(*height)?
                .ok_or(QueryError::NoSuchHeight(height.0))?;
            Ok(Response::Header(header))
        }
        Query::Block { height } => {
            let block = view
                .block(*height)?
                .ok_or(QueryError::NoSuchHeight(height.0))?;
            Ok(Response::Block(Box::new(block)))
        }
        Query::Transaction { id } => {
            let (height, index) = view
                .locate(id)?
                .ok_or_else(|| QueryError::NoSuchTransaction(id.to_hex()))?;

            // The index named a block. If the block is absent or shorter than
            // the index claims, the store is inconsistent with itself —
            // reporting "not found" would quietly hide that.
            let block = view.block(height)?.ok_or_else(|| {
                QueryError::Backend(format!("index points at missing block {height}"))
            })?;
            let transaction = block
                .transactions
                .get(index as usize)
                .cloned()
                .ok_or_else(|| {
                    QueryError::Backend(format!("index points past the end of block {height}"))
                })?;

            let total = u32::try_from(block.transactions.len())
                .map_err(|_| QueryError::Backend("block is longer than a u32".into()))?;
            let tree = MerkleTree::from_items(
                block
                    .transactions
                    .iter()
                    .map(|t| t.id().as_bytes().to_vec()),
            );
            let proof = tree
                .prove(index as usize)
                .map_err(|e| QueryError::Backend(e.to_string()))?;

            // The receipt is the half that carries the history links, so a node
            // holding the block but not its receipts cannot answer this at all.
            let receipts = view
                .receipts(height)?
                .ok_or(QueryError::NotIndexed("execution receipts"))?;
            if receipts.len() != block.transactions.len() {
                return Err(QueryError::Backend(format!(
                    "block {height} has {} transactions and {} receipts",
                    block.transactions.len(),
                    receipts.len()
                )));
            }
            let receipt = receipts
                .get(index as usize)
                .cloned()
                .ok_or_else(|| QueryError::Backend("receipt index out of range".into()))?;
            let receipt_tree = MerkleTree::from_items(receipts.iter().map(Encode::to_bytes));
            let receipt_proof = receipt_tree
                .prove(index as usize)
                .map_err(|e| QueryError::Backend(e.to_string()))?;

            Ok(Response::Transaction(Box::new(ProvedTransaction::new(
                height,
                index,
                total,
                transaction,
                proof.siblings,
                receipt,
                receipt_proof.siblings,
            ))))
        }
        Query::History {
            address,
            from,
            limit,
        } => {
            // Cap here rather than trusting the caller: the request travelled
            // over a network, and `limit` is the only field in it that costs
            // the server real work.
            let limit = (*limit).min(MAX_HISTORY) as usize;
            let (entries, truncated) = view
                .history(address, *from, limit)?
                .ok_or(QueryError::NotIndexed("a transaction history index"))?;
            Ok(Response::History(History::new(
                *address, entries, truncated,
            )))
        }
        _ => {
            let key = query
                .store_key()
                .ok_or_else(|| QueryError::Backend("query has no state key".into()))?;
            // The height comes back *with* the proof, from the same read of the
            // same tree. It used to come from `tip_height()`, which is a
            // question about the block store, while the proof is a question
            // about the state a node has published — two different things,
            // read separately, and stamped on each other.
            let (height, value, proof) = view.prove(&key)?;
            Ok(Response::Value(ProvedValue::new(height, value, proof)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_bank::Issuer;
    use afrolink_consensus::{Commit, CountryCode, Validator, ValidatorSet, Vote, VoteType};
    use afrolink_crypto::{Address, SecretKey};
    use afrolink_executor::{Allocation, Block, Genesis, GenesisLimits};
    use afrolink_light::LightClient;
    use afrolink_primitives::codec::{Encode, decode_exact};
    use afrolink_primitives::{Amount, Denom, Round, Timestamp};
    use afrolink_state::{KeyValueStore, MemoryStore};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-rpc-test").unwrap()
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").unwrap()
    }

    /// Four validators, so a quorum is a real threshold rather than a formality.
    fn validators() -> ValidatorSet {
        ValidatorSet::new(
            (1..=4u8)
                .map(|i| Validator::new(key(i).public_key(), 1, CountryCode::new("ke").unwrap()))
                .collect(),
        )
        .unwrap()
    }

    /// A node serving a real genesis block, with one funded account.
    struct TestNode {
        chain_id: ChainId,
        state: MemoryStore,
        block: Block,
        commit: Commit,
    }

    impl TestNode {
        fn new() -> Self {
            let genesis = Genesis {
                chain_id: chain(),
                genesis_time: Timestamp::from_millis(1_700_000_000_000),
                validators: validators(),
                issuers: vec![(kes(), Issuer::new(addr(100)))],
                attestors: Vec::new(),
                council: afrolink_executor::Council::devnet(addr(1)),
                params: afrolink_executor::ChainParams::devnet(),
                allocations: vec![Allocation {
                    address: addr(50),
                    denom: kes(),
                    amount: Amount::from_afri(1_000),
                }],
            };
            let mut state = MemoryStore::new();
            let block = genesis.apply(&mut state, GenesisLimits::devnet()).unwrap();
            let commit = sign_commit(&block, &[1, 2, 3, 4]);
            Self {
                chain_id: chain(),
                state,
                block,
                commit,
            }
        }
    }

    fn sign_commit(block: &Block, seeds: &[u8]) -> Commit {
        let block_id = block.header.id();
        let signatures = seeds
            .iter()
            .map(|s| {
                Vote {
                    chain_id: chain(),
                    height: block.header.height,
                    round: Round::ZERO,
                    vote_type: VoteType::Precommit,
                    block_id: Some(block_id),
                    validator: addr(*s),
                }
                .sign(&key(*s))
            })
            .collect();
        Commit::new(block.header.height, Round::ZERO, block_id, signatures)
    }

    impl ChainView for TestNode {
        fn chain_id(&self) -> &ChainId {
            &self.chain_id
        }

        fn tip_height(&self) -> Result<Height, QueryError> {
            Ok(self.block.header.height)
        }

        fn signed_header(&self, height: Height) -> Result<Option<SignedHeader>, QueryError> {
            if height != self.block.header.height {
                return Ok(None);
            }
            Ok(Some(SignedHeader {
                header: self.block.header.clone(),
                commit: self.commit.clone(),
            }))
        }

        fn prove(&self, key: &StoreKey) -> Result<(Height, Option<Vec<u8>>, Proof), QueryError> {
            let (value, proof) = self.state.get_with_proof(key);
            Ok((self.block.header.height, value, proof))
        }

        fn block(&self, height: Height) -> Result<Option<Block>, QueryError> {
            if height != self.block.header.height {
                return Ok(None);
            }
            Ok(Some(self.block.clone()))
        }

        fn receipts(&self, _height: Height) -> Result<Option<Vec<TxReceipt>>, QueryError> {
            // This fixture keeps no receipts, so `Query::Transaction` is
            // unavailable on it — reported as such rather than as an empty list.
            Ok(None)
        }

        fn locate(&self, id: &Hash32) -> Result<Option<(Height, u32)>, QueryError> {
            Ok(self
                .block
                .transactions
                .iter()
                .position(|t| t.id() == *id)
                .and_then(|i| u32::try_from(i).ok())
                .map(|i| (self.block.header.height, i)))
        }

        fn history(
            &self,
            _address: &Address,
            _from: Height,
            _limit: usize,
        ) -> Result<Option<(Vec<HistoryEntry>, bool)>, QueryError> {
            // This fixture keeps no index, which is the case
            // `a_node_without_an_index_says_so_rather_than_reporting_nothing`
            // exists to pin down.
            Ok(None)
        }
    }

    fn client(node: &TestNode) -> LightClient {
        LightClient::new(chain(), validators(), node.block.header.clone())
    }

    #[test]
    fn a_balance_answer_verifies_against_a_header_the_client_trusts() {
        let node = TestNode::new();
        let client = client(&node);
        let query = Query::Balance {
            address: addr(50),
            denom: kes(),
        };

        let response = answer(&node, &query).unwrap();
        let proved = response.as_value().unwrap();

        // The client rebuilds the key itself rather than taking one from the
        // server — see the crate docs.
        let key = query.store_key().unwrap();
        let balance = proved.verify_amount(&client, &key).unwrap();

        assert_eq!(balance, Amount::from_afri(1_000));
    }

    #[test]
    fn an_unfunded_account_gets_a_proof_of_absence_not_a_bare_zero() {
        let node = TestNode::new();
        let client = client(&node);
        let query = Query::Balance {
            address: addr(200),
            denom: kes(),
        };

        let response = answer(&node, &query).unwrap();
        let proved = response.as_value().unwrap();
        let key = query.store_key().unwrap();

        // Nothing is stored, and that fact is proved rather than asserted.
        assert!(proved.value_unverified().is_none());
        assert_eq!(proved.verify_amount(&client, &key).unwrap(), Amount::ZERO);
    }

    #[test]
    fn a_server_cannot_inflate_a_balance_it_reports() {
        let node = TestNode::new();
        let client = client(&node);
        let query = Query::Balance {
            address: addr(50),
            denom: kes(),
        };
        let key = query.store_key().unwrap();

        // Take an honest answer and swap the value for a larger one, keeping
        // the real proof. This is the whole attack the design exists to stop.
        let honest = answer(&node, &query).unwrap();
        let proof = honest.as_value().unwrap().proof().clone();
        let forged = ProvedValue::new(
            Height::GENESIS,
            Some(Amount::from_afri(999_999).to_bytes()),
            proof,
        );

        assert_eq!(
            forged.verify(&client, &key).unwrap_err(),
            afrolink_light::LightError::BadProof
        );
    }

    #[test]
    fn a_server_cannot_deny_a_balance_that_exists() {
        let node = TestNode::new();
        let client = client(&node);
        let query = Query::Balance {
            address: addr(50),
            denom: kes(),
        };
        let key = query.store_key().unwrap();

        // Claim absence while presenting the membership proof.
        let honest = answer(&node, &query).unwrap();
        let proof = honest.as_value().unwrap().proof().clone();
        let denial = ProvedValue::new(Height::GENESIS, None, proof);

        assert_eq!(
            denial.verify(&client, &key).unwrap_err(),
            afrolink_light::LightError::BadProof
        );
    }

    #[test]
    fn a_proof_for_one_account_cannot_be_replayed_for_another() {
        let node = TestNode::new();
        let client = client(&node);

        let funded = Query::Balance {
            address: addr(50),
            denom: kes(),
        };
        let other = Query::Balance {
            address: addr(200),
            denom: kes(),
        };

        let response = answer(&node, &funded).unwrap();
        let proved = response.as_value().unwrap();

        // Same proof, same value, different key: the leaf commits to the key,
        // so this cannot pass.
        assert_eq!(
            proved
                .verify(&client, &other.store_key().unwrap())
                .unwrap_err(),
            afrolink_light::LightError::BadProof
        );
    }

    #[test]
    fn a_status_answer_carries_a_tip_the_client_can_check() {
        let node = TestNode::new();
        let response = answer(&node, &Query::Status).unwrap();

        let Response::Status(status) = response else {
            panic!("expected a status response");
        };
        assert_eq!(status.chain_id, chain());
        status.tip.verify(&chain(), &validators()).unwrap();
    }

    #[test]
    fn a_header_paired_with_someone_elses_commit_is_rejected() {
        let node = TestNode::new();

        // A different header, validly signed — but presented with the commit
        // for the real one.
        let mut impostor = node.block.header.clone();
        impostor.time = Timestamp(99);

        let forged = SignedHeader {
            header: impostor,
            commit: node.commit.clone(),
        };

        assert_eq!(
            forged.verify(&chain(), &validators()).unwrap_err(),
            afrolink_light::LightError::HeaderMismatch
        );
    }

    #[test]
    fn a_commit_from_the_wrong_validator_set_does_not_reach_quorum() {
        let node = TestNode::new();
        let signed = SignedHeader {
            header: node.block.header.clone(),
            commit: node.commit.clone(),
        };

        // A set that shares no members with the signers.
        let strangers = ValidatorSet::new(
            (100u8..=103)
                .map(|i| Validator::new(key(i).public_key(), 10, CountryCode::new("ng").unwrap()))
                .collect(),
        )
        .unwrap();

        assert!(signed.verify(&chain(), &strangers).is_err());
    }

    #[test]
    fn a_missing_height_is_an_error_rather_than_an_empty_answer() {
        let node = TestNode::new();
        let err = answer(&node, &Query::Header { height: Height(42) }).unwrap_err();
        assert_eq!(err, QueryError::NoSuchHeight(42));
    }

    #[test]
    fn queries_and_responses_survive_a_round_trip_through_bytes() {
        let node = TestNode::new();
        let query = Query::Balance {
            address: addr(50),
            denom: kes(),
        };

        let query_bytes = query.to_bytes();
        assert_eq!(decode_exact::<Query>(&query_bytes).unwrap(), query);

        let response = answer(&node, &query).unwrap();
        let response_bytes = response.to_bytes();
        assert_eq!(decode_exact::<Response>(&response_bytes).unwrap(), response);
    }

    #[test]
    fn a_decoded_response_still_verifies() {
        // Encoding must not quietly drop or reorder anything the proof depends
        // on. Verifying after a round trip is what proves that.
        let node = TestNode::new();
        let client = client(&node);
        let query = Query::Balance {
            address: addr(50),
            denom: kes(),
        };

        let bytes = answer(&node, &query).unwrap().to_bytes();
        let decoded = decode_exact::<Response>(&bytes).unwrap();

        let balance = decoded
            .as_value()
            .unwrap()
            .verify_amount(&client, &query.store_key().unwrap())
            .unwrap();
        assert_eq!(balance, Amount::from_afri(1_000));
    }

    #[test]
    fn a_structurally_impossible_proof_is_rejected_at_decode() {
        // The tree is 256 bits deep, so 257 siblings cannot describe any path.
        // Rejecting it here means a phone never walks it.
        //
        // Note what this is *not* guarding: a server declaring a huge sibling
        // count without sending the hashes is already handled a layer down,
        // where `Vec::decode` refuses to pre-allocate from a length prefix. The
        // bound here catches the case where the bytes really are present.
        let mut bytes = vec![2u8]; // Response::Value
        Height::GENESIS.encode(&mut bytes);
        None::<Vec<u8>>.encode(&mut bytes);
        let siblings = vec![afrolink_crypto::hash::Hash32::from_bytes([7; 32]); 257];
        siblings.encode(&mut bytes);
        bytes.push(1); // ProofLeaf::Absent

        let err = decode_exact::<Response>(&bytes).unwrap_err();
        assert!(
            format!("{err}").contains("maximum is 256"),
            "expected a depth-bound rejection, got: {err}"
        );
    }

    #[test]
    fn a_proof_at_the_depth_limit_still_decodes() {
        // The bound must reject 257 without also rejecting 256.
        let mut bytes = vec![2u8];
        Height::GENESIS.encode(&mut bytes);
        None::<Vec<u8>>.encode(&mut bytes);
        vec![afrolink_crypto::hash::Hash32::from_bytes([7; 32]); 256].encode(&mut bytes);
        bytes.push(1);

        assert!(decode_exact::<Response>(&bytes).is_ok());
    }

    #[test]
    fn an_unknown_query_tag_is_rejected() {
        // Forward compatibility is not silent acceptance: a tag this node does
        // not know is an error, not a default.
        let err = decode_exact::<Query>(&[200]).unwrap_err();
        assert!(format!("{err}").contains("Query"), "got: {err}");
    }
}
