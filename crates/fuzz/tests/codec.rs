//! Adversarial input against every type that decodes bytes from a peer.
//!
//! The property that matters is **canonicality**: if bytes decode, re-encoding
//! must reproduce exactly those bytes. A type with two valid encodings of one
//! value is a chain split waiting to happen — two honest nodes handed the two
//! forms would hash the same logical object differently.
//!
//! Truncation and trailing-byte rejection are checked alongside, because both
//! are ways a peer takes control of a field nobody sent.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_bank::Issuer;
use afrolink_consensus::{Commit, CountryCode, Validator, ValidatorSet, Vote, VoteType};
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{Address, PublicKey, SecretKey, Signature};
use afrolink_executor::{Allocation, Block, BlockHeader, Genesis, GenesisLimits, ValidatorSets};
use afrolink_fuzz::hammer;
use afrolink_pay::PaymentReference;
use afrolink_primitives::{Amount, ChainId, Denom, Height, Round, Timestamp};
use afrolink_state::{KeyValueStore, MemoryStore, Proof, ProofLeaf, StoreKey};
use afrolink_types::{Account, AccountKind, Fee, Message, Transaction, TxBody};
use afrolink_witness::{Checkpoint, LogEntry, LogId, SignedTreeHead, TreeHead};

/// Mutations per fixture. Each also draws a pure-noise case, so this is 4 000
/// hostile inputs per type.
const ROUNDS: u64 = 2_000;

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
                    10,
                    CountryCode::new("ke").expect("valid"),
                )
            })
            .collect(),
    )
    .expect("valid set")
}

fn vote() -> Vote {
    Vote {
        chain_id: chain(),
        height: Height(7),
        round: Round::ZERO,
        vote_type: VoteType::Precommit,
        block_id: Some(Hash32::from_bytes([3u8; 32])),
        validator: addr(1),
    }
}

fn genesis_block() -> (MemoryStore, Block) {
    let genesis = Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators(),
        issuers: vec![(kes(), Issuer::new(addr(100)))],
        allocations: vec![Allocation {
            address: addr(50),
            denom: kes(),
            amount: Amount::from_afri(1_000),
        }],
    };
    let mut store = MemoryStore::new();
    let block = genesis
        .apply(&mut store, GenesisLimits::devnet())
        .expect("applies");
    (store, block)
}

fn tx_body() -> TxBody {
    TxBody {
        chain_id: chain(),
        sender: addr(50),
        nonce: 3,
        valid_until: Height(900),
        fee: Fee {
            amount: Amount::from_afri(1),
            denom: kes(),
            payer: Some(addr(51)),
        },
        messages: vec![Message::Transfer {
            to: addr(60),
            denom: kes(),
            amount: Amount::from_afri(25),
            reference: Some(PaymentReference(88)),
        }],
        memo: "school fees".to_owned(),
    }
}

#[test]
fn primitive_decoders_stay_canonical_under_attack() {
    hammer::<Amount>("Amount", &Amount::from_afri(1_234), ROUNDS);
    hammer::<Denom>("Denom", &kes(), ROUNDS);
    hammer::<ChainId>("ChainId", &chain(), ROUNDS);
    hammer::<Height>("Height", &Height(42), ROUNDS);
    hammer::<Round>("Round", &Round(9), ROUNDS);
    hammer::<Timestamp>(
        "Timestamp",
        &Timestamp::from_millis(1_700_000_000_000),
        ROUNDS,
    );
    hammer::<bool>("bool", &true, ROUNDS);
    hammer::<String>("String", &"amina".to_owned(), ROUNDS);
    hammer::<u64>("u64", &u64::MAX, ROUNDS);
}

#[test]
fn cryptographic_decoders_stay_canonical_under_attack() {
    // A signature or key that decodes two ways is worse than one that fails:
    // it means a signature could verify against bytes nobody signed.
    hammer::<Hash32>("Hash32", &Hash32::from_bytes([7u8; 32]), ROUNDS);
    hammer::<Address>("Address", &addr(1), ROUNDS);
    hammer::<PublicKey>("PublicKey", &key(1).public_key(), ROUNDS);
    hammer::<Signature>(
        "Signature",
        &key(1).sign(afrolink_crypto::hash::Domain::TxSignDoc, b"payload"),
        ROUNDS,
    );
}

#[test]
fn consensus_decoders_stay_canonical_under_attack() {
    // These are the ones a hostile validator sends directly.
    hammer::<VoteType>("VoteType", &VoteType::Prevote, ROUNDS);
    hammer::<Vote>("Vote", &vote(), ROUNDS);
    hammer::<afrolink_consensus::SignedVote>("SignedVote", &vote().sign(&key(1)), ROUNDS);
    hammer::<CountryCode>(
        "CountryCode",
        &CountryCode::new("ng").expect("valid"),
        ROUNDS,
    );
    hammer::<Validator>(
        "Validator",
        &Validator::new(
            key(1).public_key(),
            10,
            CountryCode::new("ke").expect("valid"),
        ),
        ROUNDS,
    );
    hammer::<ValidatorSet>("ValidatorSet", &validators(), ROUNDS);
    hammer::<Commit>(
        "Commit",
        &Commit::new(
            Height(7),
            Round::ZERO,
            Hash32::from_bytes([3u8; 32]),
            vec![vote().sign(&key(1)), vote().sign(&key(2))],
        ),
        ROUNDS,
    );
}

#[test]
fn block_decoders_stay_canonical_under_attack() {
    let (_, block) = genesis_block();
    hammer::<BlockHeader>("BlockHeader", &block.header, ROUNDS);
    hammer::<Block>("Block", &block, ROUNDS);
}

#[test]
fn transaction_decoders_stay_canonical_under_attack() {
    // The widest untrusted surface: anyone at all can submit one of these.
    let body = tx_body();
    hammer::<Fee>("Fee", &body.fee, ROUNDS);
    hammer::<Message>("Message", &body.messages[0].clone(), ROUNDS);
    hammer::<TxBody>("TxBody", &body, ROUNDS);
    hammer::<Transaction>(
        "Transaction",
        &Transaction {
            public_key: key(50).public_key(),
            signature: key(50).sign(afrolink_crypto::hash::Domain::TxSignDoc, &body.sign_doc()),
            body,
        },
        ROUNDS,
    );
}

#[test]
fn every_message_variant_stays_canonical_under_attack() {
    // Enum discriminants are where a decoder most often accepts something it
    // should not, so each variant is hammered rather than only the first.
    let variants = [
        Message::Transfer {
            to: addr(60),
            denom: kes(),
            amount: Amount::from_afri(25),
            reference: None,
        },
        Message::RegisterName {
            name: afrolink_alias::Username::new("amina").expect("valid"),
        },
        Message::SetPrimaryAlias {
            name: afrolink_alias::Username::new("amina").expect("valid"),
        },
        Message::RenewName {
            name: afrolink_alias::Username::new("amina").expect("valid"),
        },
    ];
    for (i, m) in variants.iter().enumerate() {
        hammer::<Message>(&format!("Message[{i}]"), m, ROUNDS);
    }
}

#[test]
fn account_decoders_stay_canonical_under_attack() {
    hammer::<Account>(
        "Account/Individual",
        &Account {
            address: addr(50),
            nonce: 4,
            kind: AccountKind::Individual {
                public_key: Some(key(50).public_key()),
            },
        },
        ROUNDS,
    );
    // `None` and `Some` take different decoder paths, and the empty case is
    // where a default is most tempting.
    hammer::<Account>(
        "Account/Unrevealed",
        &Account {
            address: addr(51),
            nonce: 0,
            kind: AccountKind::Individual { public_key: None },
        },
        ROUNDS,
    );
    hammer::<Account>(
        "Account/Module",
        &Account {
            address: addr(52),
            nonce: 0,
            kind: AccountKind::Module {
                name: "fee_pool".to_owned(),
            },
        },
        ROUNDS,
    );
}

#[test]
fn state_proof_decoders_stay_canonical_under_attack() {
    // A proof arrives from a server the wallet does not trust, so this is the
    // exact surface ADR-0006's absence proofs live on.
    let (store, _) = genesis_block();
    let (_, present) = store.get_with_proof(&StoreKey::balance(&addr(50), &kes()));
    let (_, absent) = store.get_with_proof(&StoreKey::balance(&addr(77), &kes()));

    hammer::<Proof>("Proof/Present", &present, ROUNDS);
    hammer::<Proof>("Proof/Absent", &absent, ROUNDS);
    hammer::<ProofLeaf>("ProofLeaf/Absent", &ProofLeaf::Absent, ROUNDS);
    hammer::<ProofLeaf>(
        "ProofLeaf/Present",
        &ProofLeaf::Present {
            value: vec![1, 2, 3],
        },
        ROUNDS,
    );
    hammer::<ProofLeaf>(
        "ProofLeaf/AbsentOccupied",
        &ProofLeaf::AbsentOccupied {
            other_key_hash: Hash32::from_bytes([9u8; 32]),
            other_value: vec![4, 5],
        },
        ROUNDS,
    );
}

#[test]
fn staking_decoders_stay_canonical_under_attack() {
    // These decide who signs blocks and whose money is destroyed, so a decoder
    // that accepts two forms of one value here is as serious as it gets.
    use afrolink_consensus::Equivocation;
    use afrolink_staking::{Bond, Unbonding};

    hammer::<Bond>(
        "Bond",
        &Bond::new(
            addr(1),
            key(1).public_key(),
            CountryCode::new("ke").expect("valid"),
            Amount::from_afri(50_000),
        ),
        ROUNDS,
    );
    hammer::<Unbonding>(
        "Unbonding",
        &Unbonding {
            amount: Amount::from_afri(1_000),
            started_at: Height(42),
            completes_at: Timestamp::from_millis(1_700_000_000_000),
        },
        ROUNDS,
    );
    hammer::<Equivocation>(
        "Equivocation",
        &Equivocation {
            validator: addr(1),
            first: vote().sign(&key(1)),
            second: Vote {
                block_id: Some(Hash32::from_bytes([9u8; 32])),
                ..vote()
            }
            .sign(&key(1)),
        },
        ROUNDS,
    );

    // And the transaction messages that reach them.
    for (label, msg) in [
        (
            "Message::Bond",
            Message::Bond {
                public_key: key(1).public_key(),
                country: CountryCode::new("ke").expect("valid"),
                amount: Amount::from_afri(50_000),
            },
        ),
        (
            "Message::Unbond",
            Message::Unbond {
                amount: Amount::from_afri(1_000),
            },
        ),
        (
            "Message::AddStake",
            Message::AddStake {
                amount: Amount::from_afri(1_000),
            },
        ),
        ("Message::WithdrawUnbonded", Message::WithdrawUnbonded),
    ] {
        hammer::<Message>(label, &msg, ROUNDS);
    }
}

#[test]
fn witness_decoders_stay_canonical_under_attack() {
    let head = TreeHead {
        log: LogId::from_public_key(&key(200).public_key()),
        chain_id: chain(),
        size: 512,
        root: Hash32::from_bytes([6u8; 32]),
        signed_at: Timestamp::from_millis(1_700_000_500_000),
    };
    hammer::<LogEntry>(
        "LogEntry",
        &LogEntry {
            height: Height(9),
            block_id: Hash32::from_bytes([2u8; 32]),
            observed_at: Timestamp::from_millis(1_700_000_009_000),
        },
        ROUNDS,
    );
    hammer::<TreeHead>("TreeHead", &head, ROUNDS);
    hammer::<SignedTreeHead>("SignedTreeHead", &head.sign(&key(200)), ROUNDS);
    hammer::<Checkpoint>(
        "Checkpoint",
        &Checkpoint {
            chain_id: chain(),
            height: Height(1_234),
            block_id: Hash32::from_bytes([5u8; 32]),
        },
        ROUNDS,
    );
}

#[test]
fn a_genesis_file_stays_canonical_under_attack() {
    // Genesis is the one input every node ingests before it can check anything
    // against a chain, so a decoder bug here is a bug nothing else catches.
    let (_, block) = genesis_block();
    let _ = block;
    hammer::<Allocation>(
        "Allocation",
        &Allocation {
            address: addr(50),
            denom: kes(),
            amount: Amount::from_afri(1_000),
        },
        ROUNDS,
    );
    hammer::<Genesis>(
        "Genesis",
        &Genesis {
            chain_id: chain(),
            genesis_time: Timestamp::from_millis(1_700_000_000_000),
            validators: validators(),
            issuers: vec![(kes(), Issuer::new(addr(100)))],
            allocations: vec![Allocation {
                address: addr(50),
                denom: kes(),
                amount: Amount::from_afri(1_000),
            }],
        },
        ROUNDS,
    );
}

#[test]
fn a_block_carrying_a_hostile_validator_set_still_decodes_canonically() {
    // ADR-0010 made headers commit to validator sets. A set that decodes two
    // ways would let an attacker present one form to satisfy the commitment and
    // another to satisfy the signature check.
    let (mut store, genesis) = genesis_block();
    let executor = afrolink_executor::Executor::new(chain());
    let (block, _) = executor.build_block(
        &mut store,
        Height(1),
        Timestamp::from_millis(1_700_000_001_000),
        genesis.header.id(),
        Vec::new(),
        ValidatorSets::unchanged(&validators()),
    );
    hammer::<BlockHeader>("BlockHeader/committed-sets", &block.header, ROUNDS);
}

#[test]
fn the_query_protocol_stays_canonical_under_attack() {
    // These are the types a hostile *client* sends and a hostile *server*
    // answers with — the only encodings on this chain that cross a socket in
    // both directions. They were outside this suite until payment history
    // added a reason to look.
    use afrolink_rpc::{HistoryEntry, Query};

    hammer::<Query>("Query/status", &Query::Status, ROUNDS);
    hammer::<Query>(
        "Query/header",
        &Query::Header {
            height: Height(4_711),
        },
        ROUNDS,
    );
    hammer::<Query>(
        "Query/balance",
        &Query::Balance {
            address: addr(50),
            denom: kes(),
        },
        ROUNDS,
    );
    hammer::<Query>(
        "Query/transaction",
        &Query::Transaction {
            id: Hash32::from_bytes([3u8; 32]),
        },
        ROUNDS,
    );
    hammer::<Query>(
        "Query/history",
        &Query::History {
            address: addr(50),
            from: Height(9),
            limit: 25,
        },
        ROUNDS,
    );
    hammer::<HistoryEntry>(
        "HistoryEntry",
        &HistoryEntry {
            height: Height(12),
            index: 3,
            tx_id: Hash32::from_bytes([5u8; 32]),
        },
        ROUNDS,
    );
}

#[test]
fn a_history_answer_cannot_be_re_encoded_two_ways() {
    // History is the one answer that carries no proof, so its *encoding* is the
    // only thing keeping two clients from reading one reply differently.
    use afrolink_rpc::{HistoryEntry, Query, Response, answer};

    let (store, block) = genesis_block();
    let view = Fixture { store, block };

    let response = answer(
        &view,
        &Query::History {
            address: addr(50),
            from: Height::GENESIS,
            limit: 10,
        },
    )
    .expect("the fixture indexes history");
    hammer::<Response>("Response/history", &response, ROUNDS);

    // And an empty page, which is the shape a client sees most often.
    let Response::History(history) = &response else {
        panic!("expected a history response");
    };
    assert_eq!(history.entries_unverified(), &[] as &[HistoryEntry]);
}

/// The smallest `ChainView` that answers the history and block queries.
struct Fixture {
    store: MemoryStore,
    block: Block,
}

impl afrolink_rpc::ChainView for Fixture {
    fn chain_id(&self) -> &ChainId {
        static ID: std::sync::OnceLock<ChainId> = std::sync::OnceLock::new();
        ID.get_or_init(chain)
    }
    fn tip_height(&self) -> Result<Height, afrolink_rpc::QueryError> {
        Ok(self.block.header.height)
    }
    fn signed_header(
        &self,
        _height: Height,
    ) -> Result<Option<afrolink_rpc::SignedHeader>, afrolink_rpc::QueryError> {
        Ok(None)
    }
    fn prove(
        &self,
        key: &afrolink_state::StoreKey,
    ) -> Result<(Option<Vec<u8>>, afrolink_state::Proof), afrolink_rpc::QueryError> {
        Ok(self.store.get_with_proof(key))
    }
    fn block(&self, height: Height) -> Result<Option<Block>, afrolink_rpc::QueryError> {
        if height == self.block.header.height {
            return Ok(Some(self.block.clone()));
        }
        Ok(None)
    }
    fn locate(&self, _id: &Hash32) -> Result<Option<(Height, u32)>, afrolink_rpc::QueryError> {
        Ok(None)
    }
    fn history(
        &self,
        _address: &Address,
        _from: Height,
        _limit: usize,
    ) -> Result<Option<(Vec<afrolink_rpc::HistoryEntry>, bool)>, afrolink_rpc::QueryError> {
        Ok(Some((Vec::new(), false)))
    }
}
