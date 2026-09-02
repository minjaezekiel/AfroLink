//! Catching up, and everything a peer might try instead of helping.
//!
//! Block sync is the one path where a node takes a whole block from somebody it
//! has no reason to trust, and the tempting way to build it is to treat the peer
//! as an authority: it says this is height nine, so this is height nine. Every
//! test here is an attempt to exploit exactly that reading.
//!
//! Two independent things make it safe, and they answer different questions:
//!
//! * **The certificate** proves the *network* finalised this block. Forging one
//!   needs more than two thirds of the validators' signing keys, and anyone
//!   holding those has no need to lie to a syncing node.
//! * **Re-execution** is how the node ends up *holding the state* rather than a
//!   root hash a stranger sent it.
//!
//! Neither replaces the other, and the last test in the first group is the proof:
//! a block with a genuine, fully valid certificate over a lying `app_hash` is
//! still refused, because the second check does not care what the first one said.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_consensus::{
    Commit, CommitError, CountryCode, SignedVote, Validator, ValidatorSet, Vote, VoteType,
};
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Allocation, Block, Genesis, GenesisLimits};
use afrolink_node::sim::Network;
use afrolink_node::{Node, SyncError};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Round, Timestamp};
use afrolink_state::MemoryStore;
use afrolink_types::{Fee, Message, Transaction, TxBody};

const COUNTRIES: [&str; 4] = ["ke", "ng", "za", "tz"];

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn account(seed: u8) -> Address {
    Address::from_public_key(&key(seed).public_key())
}

fn chain() -> ChainId {
    ChainId::new("afrolink-1").expect("valid")
}

fn validators() -> ValidatorSet {
    ValidatorSet::new(
        (1..=4u8)
            .map(|i| {
                Validator::new(
                    key(i).public_key(),
                    1,
                    CountryCode::new(COUNTRIES[(i as usize - 1) % 4]).expect("valid"),
                )
            })
            .collect(),
    )
    .expect("valid set")
}

fn genesis_state() -> (MemoryStore, Block) {
    let genesis = Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators(),
        issuers: Vec::new(),
        attestors: Vec::new(),
        council: afrolink_executor::Council::devnet(account(50)),
        params: afrolink_executor::ChainParams::devnet(),
        allocations: vec![Allocation {
            address: account(50),
            denom: Denom::native(),
            amount: Amount::from_afri(1_000_000),
        }],
    };
    let mut store = MemoryStore::new();
    let block = genesis
        .apply(&mut store, GenesisLimits::devnet())
        .expect("genesis applies");
    (store, block)
}

fn payment(nonce: u64) -> Transaction {
    TxBody {
        chain_id: chain(),
        sender: account(50),
        nonce,
        valid_until: Height(10_000),
        fee: Fee::new(Amount::from_units(1_000), Denom::native()),
        messages: vec![Message::Transfer {
            to: account(60),
            denom: Denom::native(),
            amount: Amount::from_afri(1),
            reference: None,
        }],
        memo: String::new(),
    }
    .sign(&key(50))
}

/// A real chain: `heights` blocks decided by a real validator set, each with the
/// certificate that finalised it.
///
/// Produced by running the consensus simulator rather than by hand-building
/// headers, so what the sync path is fed is exactly what the chain produces.
fn a_real_chain(heights: usize) -> Vec<(Block, Commit)> {
    let (store, genesis) = genesis_state();
    let keys: Vec<SecretKey> = (1..=4u8).map(key).collect();
    let mut network = Network::new(&chain(), &keys, &validators(), &store, &genesis);

    let mut chain_blocks = Vec::new();
    for n in 0..heights {
        // Real payments in the blocks, so re-execution has something to disagree
        // about if it is going to. Offered to every node, because the proposer for
        // a height is chosen by the validator set and not by this test — giving it
        // to one node only produces empty blocks whenever somebody else proposes.
        for node in &mut network.nodes {
            let _ = node.submit(payment(n as u64));
        }
        // One `start_round` is now one height: a round that commits resets to
        // round zero of the next height and waits to be begun, and a round that
        // does not commit begins the next one itself. Firing an extra propose
        // timeout here — which this fixture used to do to unstick a round that
        // could not end on its own — now commits a second block per iteration.
        network.start_round();
        network.run(8_000);

        let leader = &network.nodes[0];
        let Some(block) = leader.committed.last().cloned() else {
            panic!("height {n} did not commit");
        };
        let commit = leader.last_commit.clone().expect("a commit certificate");
        assert_eq!(
            block.header.height,
            Height(n as u64 + 1),
            "the fixture must produce exactly one height per round, in order"
        );
        chain_blocks.push((block, commit));
    }
    assert!(
        chain_blocks.len() >= heights,
        "the fixture chain must actually have blocks in it"
    );
    chain_blocks
}

/// A node that has seen nothing since genesis.
fn follower() -> Node {
    let (store, genesis) = genesis_state();
    Node::new(chain(), key(9), validators(), store, &genesis)
}

// -- the path that is supposed to work ---------------------------------------

#[test]
fn a_node_that_missed_everything_catches_up_and_agrees() {
    // The whole point. A node that took no part in deciding any of these heights
    // ends up at the same height, with the same state root, as the ones that did.
    let chain_blocks = a_real_chain(4);
    let mut node = follower();
    assert_eq!(node.height(), Height(1));

    for (block, commit) in &chain_blocks {
        node.apply_synced(block.clone(), commit.clone())
            .unwrap_or_else(|e| panic!("height {} refused: {e}", block.header.height.0));
    }

    let (tip, _) = chain_blocks.last().expect("blocks");
    assert_eq!(node.height(), tip.header.height.next());
    assert_eq!(
        node.app_hash(),
        tip.header.app_hash,
        "a synced node holds the state, not a promise about it"
    );
    assert_eq!(node.committed.len(), chain_blocks.len());
}

#[test]
fn a_synced_node_can_go_on_to_take_part() {
    // Syncing is not a read-only mode a node gets stuck in. Once caught up it has
    // to be indistinguishable from one that voted on every height — same state,
    // same nonces, able to accept the next payment in the sender's sequence.
    let chain_blocks = a_real_chain(3);
    let mut node = follower();
    for (block, commit) in &chain_blocks {
        node.apply_synced(block.clone(), commit.clone()).unwrap();
    }
    // The first three nonces were spent in the blocks it just applied, so only
    // the fourth is acceptable — which it can only know from having executed them.
    assert!(
        node.submit(payment(0)).is_err(),
        "a nonce spent in a synced block is spent"
    );
    assert!(node.submit(payment(3)).is_ok());
}

#[test]
fn receipts_come_with_the_block_that_was_applied() {
    // The header commits to their root. A node that stored the block without them
    // could prove a transaction ran but not what it did.
    let chain_blocks = a_real_chain(1);
    let mut node = follower();
    let (block, commit) = &chain_blocks[0];
    node.apply_synced(block.clone(), commit.clone()).unwrap();
    assert_eq!(node.last_receipts().len(), block.transactions.len());
}

// -- forging the certificate --------------------------------------------------

#[test]
fn a_block_with_no_certificate_at_all_is_refused() {
    let chain_blocks = a_real_chain(1);
    let (block, commit) = &chain_blocks[0];
    let naked = Commit::new(commit.height, commit.round, commit.block_id, Vec::new());
    assert_eq!(
        follower().apply_synced(block.clone(), naked),
        Err(SyncError::BadCommit(CommitError::Empty))
    );
}

#[test]
fn a_certificate_signed_by_strangers_proves_nothing() {
    // Anyone can produce signatures. The question is whose.
    let chain_blocks = a_real_chain(1);
    let (block, commit) = &chain_blocks[0];
    let outsiders: Vec<SignedVote> = (100..=104u8)
        .map(|seed| {
            let k = key(seed);
            Vote {
                chain_id: chain(),
                height: commit.height,
                round: commit.round,
                vote_type: VoteType::Precommit,
                block_id: Some(commit.block_id),
                validator: Address::from_public_key(&k.public_key()),
            }
            .sign(&k)
        })
        .collect();
    let forged = Commit::new(commit.height, commit.round, commit.block_id, outsiders);
    assert_eq!(
        follower().apply_synced(block.clone(), forged),
        Err(SyncError::BadCommit(CommitError::UnknownSigner))
    );
}

#[test]
fn one_honest_validator_is_not_two_thirds_of_four() {
    // A single validator's genuine precommit is a genuine signature and still not
    // a finalisation. This is the check that makes a *minority* of compromised
    // keys insufficient.
    let chain_blocks = a_real_chain(1);
    let (block, commit) = &chain_blocks[0];
    let one = Commit::new(
        commit.height,
        commit.round,
        commit.block_id,
        commit.signatures.iter().take(1).cloned().collect(),
    );
    assert!(matches!(
        follower().apply_synced(block.clone(), one),
        Err(SyncError::BadCommit(CommitError::InsufficientPower { .. }))
    ));
}

#[test]
fn the_same_validator_counted_twice_is_still_one_validator() {
    let chain_blocks = a_real_chain(1);
    let (block, commit) = &chain_blocks[0];
    let first = commit.signatures[0].clone();
    let doubled = Commit::new(
        commit.height,
        commit.round,
        commit.block_id,
        vec![first.clone(), first.clone(), first.clone(), first],
    );
    assert_eq!(
        follower().apply_synced(block.clone(), doubled),
        Err(SyncError::BadCommit(CommitError::DuplicateSigner))
    );
}

#[test]
fn a_certificate_for_one_block_cannot_finalise_another() {
    // Lifting a real, fully valid certificate off height one and attaching it to
    // the block from height two. Both halves are genuine; the pairing is not.
    //
    // The node is walked to height two first, so that the *height* check has
    // already passed when this is offered. Otherwise this would be a test of the
    // cheap check rather than of the pairing, and would keep passing if the
    // pairing check were deleted.
    let chain_blocks = a_real_chain(2);
    let (first_block, first_commit) = &chain_blocks[0];
    let (second_block, _) = &chain_blocks[1];
    let mut node = follower();
    node.apply_synced(first_block.clone(), first_commit.clone())
        .unwrap();
    assert_eq!(node.height(), second_block.header.height);
    assert_eq!(
        node.apply_synced(second_block.clone(), first_commit.clone()),
        Err(SyncError::CommitIsForAnotherBlock)
    );
}

// -- lying about what the block does ------------------------------------------

#[test]
fn a_genuine_certificate_over_a_false_state_root_is_still_refused() {
    // The sharpest case in this file, and the reason re-execution is not
    // redundant with certificate checking.
    //
    // Here the validator set really does sign the lying block: all four keys
    // produce genuine precommits over a header claiming an `app_hash` that its
    // transactions do not produce. The certificate verifies perfectly. That is
    // either a chain that has forked or a consensus-breaking bug in this build,
    // and in both cases the node must refuse rather than write a state nobody
    // else has — because a node that trusts the certificate alone would adopt it.
    let chain_blocks = a_real_chain(1);
    let (real, _) = &chain_blocks[0];

    let mut lying = real.clone();
    lying.header.app_hash = Hash32::from_bytes([0xAB; 32]);
    let lied_id = lying.header.id();

    let signatures: Vec<SignedVote> = (1..=4u8)
        .map(|seed| {
            let k = key(seed);
            Vote {
                chain_id: chain(),
                height: lying.header.height,
                round: Round(0),
                vote_type: VoteType::Precommit,
                block_id: Some(lied_id),
                validator: Address::from_public_key(&k.public_key()),
            }
            .sign(&k)
        })
        .collect();
    let real_certificate = Commit::new(lying.header.height, Round(0), lied_id, signatures);
    // The certificate is not the problem: it is valid.
    assert_eq!(real_certificate.verify(&chain(), &validators()), Ok(()));

    assert_eq!(
        follower().apply_synced(lying, real_certificate),
        Err(SyncError::AppHashMismatch),
        "the second check does not care what the first one said"
    );
}

#[test]
fn transactions_that_do_not_match_the_header_are_refused() {
    // Dropping a payment out of a block while keeping its header. Caught before
    // any signature is verified and before anything is executed, because it costs
    // one hash to catch.
    let chain_blocks = a_real_chain(3);
    let mut node = follower();
    for (block, commit) in &chain_blocks {
        if block.transactions.is_empty() {
            // Nothing to strip out of an empty block, so walk past it.
            node.apply_synced(block.clone(), commit.clone()).unwrap();
            continue;
        }
        let mut stripped = block.clone();
        stripped.transactions.clear();
        assert_eq!(
            node.apply_synced(stripped, commit.clone()),
            Err(SyncError::TxRootMismatch)
        );
        return;
    }
    panic!("the fixture chain must carry a payment for this to test anything");
}

// -- lying about where the block goes -----------------------------------------

#[test]
fn a_peer_cannot_make_a_node_skip_a_height() {
    // Offering height two to a node that needs height one. Accepting it would
    // leave a hole in a chain whose whole value is that there are none — the node
    // would hold a state derived from transactions it never saw.
    let chain_blocks = a_real_chain(2);
    let (second, second_commit) = &chain_blocks[1];
    assert_eq!(
        follower().apply_synced(second.clone(), second_commit.clone()),
        Err(SyncError::WrongHeight {
            expected: 1,
            got: second.header.height.0
        })
    );
}

#[test]
fn a_block_already_applied_is_refused_the_second_time() {
    let chain_blocks = a_real_chain(1);
    let (block, commit) = &chain_blocks[0];
    let mut node = follower();
    node.apply_synced(block.clone(), commit.clone()).unwrap();
    assert!(matches!(
        node.apply_synced(block.clone(), commit.clone()),
        Err(SyncError::WrongHeight { .. })
    ));
    assert_eq!(node.committed.len(), 1, "and it is not committed twice");
}

#[test]
fn a_block_from_another_chain_does_not_apply() {
    // The chain id is in the header and in every vote in the certificate, so this
    // fails twice over — but it must fail on the cheapest of the two.
    let chain_blocks = a_real_chain(1);
    let (real, commit) = &chain_blocks[0];
    let mut foreign = real.clone();
    foreign.header.chain_id = ChainId::new("some-other-chain").unwrap();
    assert!(matches!(
        follower().apply_synced(foreign, commit.clone()),
        Err(SyncError::WrongChain { .. })
    ));
}

#[test]
fn a_block_that_does_not_follow_our_tip_is_refused() {
    // Right height, wrong parent: the shape of a fork. Applying it is how a node
    // adopts a history it never verified the middle of.
    let chain_blocks = a_real_chain(1);
    let (real, commit) = &chain_blocks[0];
    let mut orphan = real.clone();
    orphan.header.parent = Hash32::from_bytes([0x77; 32]);
    assert_eq!(
        follower().apply_synced(orphan, commit.clone()),
        Err(SyncError::WrongParent)
    );
}

// -- what a refusal costs -----------------------------------------------------

#[test]
fn a_refused_block_leaves_the_node_exactly_where_it_was() {
    // Execution happens against a copy, so a block that fails the last check has
    // written nothing. A node that half-applied a block it then rejected would be
    // in a state no other node on the network shares — which is worse than being
    // behind, because being behind is recoverable.
    let chain_blocks = a_real_chain(2);
    let (real, _) = &chain_blocks[0];
    let mut node = follower();
    let before_height = node.height();
    let before_root = node.app_hash();

    let mut lying = real.clone();
    lying.header.app_hash = Hash32::from_bytes([0xCD; 32]);
    let lied_id = lying.header.id();
    let signatures: Vec<SignedVote> = (1..=4u8)
        .map(|seed| {
            let k = key(seed);
            Vote {
                chain_id: chain(),
                height: lying.header.height,
                round: Round(0),
                vote_type: VoteType::Precommit,
                block_id: Some(lied_id),
                validator: Address::from_public_key(&k.public_key()),
            }
            .sign(&k)
        })
        .collect();
    assert_eq!(
        node.apply_synced(lying, Commit::new(Height(1), Round(0), lied_id, signatures)),
        Err(SyncError::AppHashMismatch)
    );

    assert_eq!(node.height(), before_height);
    assert_eq!(node.app_hash(), before_root, "nothing was written");
    assert!(node.committed.is_empty());

    // And the node is still able to accept the real block afterwards.
    let (block, commit) = &chain_blocks[0];
    assert!(node.apply_synced(block.clone(), commit.clone()).is_ok());
}
