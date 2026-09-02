//! A node counts its own vote, and nothing outside it has to help.
//!
//! These tests drive [`Node`] with **no transport and no simulator**. That is the
//! whole point of the file: the defect they exist to prevent was a consensus
//! invariant that held only because something outside the state machine put it
//! there.
//!
//! `Node` returned its own votes as `Action::BroadcastVote` and never added them
//! to its own vote set. The deterministic simulator delivered every broadcast
//! back to its sender, so the rule was satisfied in every test in the workspace.
//! The transport did not, so it was satisfied nowhere in production. On four
//! validators the difference is invisible — three votes from three peers already
//! exceed two thirds of four — and on one validator it is total: a set of one can
//! never reach a quorum it is not counted in.
//!
//! The fix is CometBFT's `signAddVote`: sign, add to our own vote set through the
//! same path a peer's vote takes, *then* gossip. Gossip is downstream of
//! consensus state and never the mechanism by which it changes.
//!
//! Every test here would pass trivially if driven through the old simulator. They
//! are written against the bare state machine on purpose.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_consensus::{CountryCode, Validator, ValidatorSet, Vote, VoteType};
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Allocation, Genesis, GenesisLimits};
use afrolink_node::{Action, Event, Node};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Round, Timestamp};
use afrolink_state::MemoryStore;

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

fn set_of(n: u8) -> ValidatorSet {
    ValidatorSet::new(
        (1..=n)
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

/// A node holding `key(seed)`, in a validator set of `n`.
fn node(seed: u8, n: u8) -> Node {
    let validators = set_of(n);
    let genesis = Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators.clone(),
        issuers: Vec::new(),
        attestors: Vec::new(),
        council: afrolink_executor::Council::devnet(account(50)),
        params: afrolink_executor::ChainParams::devnet(),
        allocations: vec![Allocation {
            address: account(50),
            denom: Denom::native(),
            amount: Amount::from_afri(1_000),
        }],
    };
    let mut store = MemoryStore::new();
    let block = genesis
        .apply(&mut store, GenesisLimits::devnet())
        .expect("genesis applies");
    Node::new(chain(), key(seed), validators, store, &block)
}

/// Whose turn it is to propose at height 1, round 0.
///
/// Discovered rather than assumed: the proposer comes from the validator set's
/// own ordering, which is by address, and an address is a hash of a key. Writing
/// `key(1)` here and hoping would make this file test a coincidence.
fn proposer_seed(n: u8) -> u8 {
    let set = set_of(n);
    let proposer = set
        .proposer(Height(1), Round(0))
        .expect("some validator proposes")
        .address;
    (1..=n)
        .find(|seed| account(*seed) == proposer)
        .expect("the proposer is in the set")
}

/// Everyone but `seed`, in a set of `n`.
fn others(seed: u8, n: u8) -> Vec<u8> {
    (1..=n).filter(|s| *s != seed).collect()
}

fn now() -> Timestamp {
    Timestamp::from_millis(1_700_000_001_000)
}

fn committed(actions: &[Action]) -> bool {
    actions.iter().any(|a| matches!(a, Action::Committed(_, _)))
}

fn votes_broadcast(actions: &[Action]) -> Vec<(VoteType, Option<afrolink_crypto::hash::Hash32>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::BroadcastVote(v) => Some((v.vote.vote_type, v.vote.block_id)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_lone_validator_commits_with_no_network_at_all() {
    // The case that made the defect total. Nothing here delivers anything: one
    // call, one round, one block. A validator that is the whole set must be able
    // to commit, and it can only do that by counting itself.
    let mut node = node(1, 1);
    assert_eq!(node.height(), Height(1));

    let actions = node.start_round(now());

    assert!(
        committed(&actions),
        "a set of one committed nothing; actions were {actions:?}"
    );
    assert_eq!(node.height(), Height(2));
    assert_eq!(node.committed.len(), 1);
}

#[test]
fn one_round_produces_both_of_its_votes_in_order() {
    // Counting our own prevote completes the prevote quorum, which produces the
    // precommit, which completes the precommit quorum, which commits. All of it
    // has to come back out as actions — a vote this node cast and did not tell
    // anyone about is a vote the rest of the network never counts.
    let mut node = node(1, 1);
    let actions = node.start_round(now());
    let cast = votes_broadcast(&actions);

    assert_eq!(cast.len(), 2, "a prevote and a precommit; got {cast:?}");
    assert_eq!(cast[0].0, VoteType::Prevote);
    assert_eq!(cast[1].0, VoteType::Precommit);
    assert!(
        cast[0].1.is_some() && cast[0].1 == cast[1].1,
        "both votes must name the block that was proposed"
    );
}

#[test]
fn the_same_vote_arriving_from_the_network_changes_nothing() {
    // What makes it safe for the transport to have stopped looping votes back —
    // and what protects against a future transport that starts again. A node's
    // own vote returning to it must be idempotent, not double-counted, because
    // a vote counted twice is a quorum reached with less than a quorum.
    let mut node = node(1, 1);
    let actions = node.start_round(now());
    let height_after = node.height();
    let committed_after = node.committed.len();

    for action in &actions {
        if let Action::BroadcastVote(vote) = action {
            let echoed = node.handle(Event::Vote(vote.clone()));
            assert!(
                echoed.is_empty(),
                "a vote this node already holds must produce nothing; got {echoed:?}"
            );
        }
    }
    assert_eq!(node.height(), height_after);
    assert_eq!(node.committed.len(), committed_after);
}

#[test]
fn a_validator_still_needs_two_thirds_and_not_merely_itself() {
    // The other direction, and the reason the defect stayed hidden: counting our
    // own vote must not be enough on its own. One of four is not a quorum, and
    // neither is two.
    let me = proposer_seed(4);
    let peers = others(me, 4);
    let mut node = node(me, 4);
    let actions = node.start_round(now());
    assert!(
        !committed(&actions),
        "one validator of four committed a block by itself"
    );

    let Some(block_id) = votes_broadcast(&actions).first().and_then(|(_, id)| *id) else {
        panic!("the proposer must have prevoted for its own block");
    };

    // A second validator agrees: still short of three.
    let mut actions = node.handle(Event::Vote(Box::new(peer_vote(
        peers[0],
        VoteType::Prevote,
        Some(block_id),
    ))));
    assert!(!committed(&actions), "two of four is not two thirds");

    // A third completes the prevote quorum, which produces our precommit.
    actions = node.handle(Event::Vote(Box::new(peer_vote(
        peers[1],
        VoteType::Prevote,
        Some(block_id),
    ))));
    assert!(
        votes_broadcast(&actions)
            .iter()
            .any(|(kind, _)| *kind == VoteType::Precommit),
        "three prevotes of four should carry the prevote step"
    );

    // And the same again for precommits: ours plus two more.
    actions = node.handle(Event::Vote(Box::new(peer_vote(
        peers[0],
        VoteType::Precommit,
        Some(block_id),
    ))));
    assert!(!committed(&actions));
    actions = node.handle(Event::Vote(Box::new(peer_vote(
        peers[1],
        VoteType::Precommit,
        Some(block_id),
    ))));
    assert!(
        committed(&actions),
        "our own precommit plus two others is three of four, which is a quorum"
    );
    assert_eq!(node.height(), Height(2));
}

#[test]
fn a_node_that_is_not_the_proposer_still_counts_its_own_prevote() {
    // The proposer path is the easy one. A validator that merely *receives* a
    // proposal signs a prevote too, and that vote has to be counted here rather
    // than on its way back from somewhere.
    let proposer_at = proposer_seed(4);
    let mut proposer = node(proposer_at, 4);
    let actions = proposer.start_round(now());
    let Some(Action::BroadcastProposal(proposal)) = actions
        .iter()
        .find(|a| matches!(a, Action::BroadcastProposal(_)))
        .cloned()
    else {
        panic!("the round's proposer should propose");
    };

    // A different validator, hearing that proposal and nothing else.
    let followers = others(proposer_at, 4);
    let mut follower = node(followers[0], 4);
    let out = follower.handle(Event::Proposal(proposal));
    let cast = votes_broadcast(&out);
    assert_eq!(cast.len(), 1, "one prevote for the proposal");
    assert_eq!(cast[0].0, VoteType::Prevote);

    // Two more prevotes reach it. With its own already counted that is three of
    // four, so it must precommit — which it cannot do if its own was never added.
    let block_id = cast[0].1.expect("prevoted for the block");
    let mut carried = false;
    for signer in [proposer_at, followers[1]] {
        let out = follower.handle(Event::Vote(Box::new(peer_vote(
            signer,
            VoteType::Prevote,
            Some(block_id),
        ))));
        carried |= votes_broadcast(&out)
            .iter()
            .any(|(kind, _)| *kind == VoteType::Precommit);
    }
    assert!(
        carried,
        "a follower's own prevote must count towards its own precommit decision"
    );
}

/// A vote signed by another validator, as one would arrive from the network.
fn peer_vote(
    signer: u8,
    vote_type: VoteType,
    block_id: Option<afrolink_crypto::hash::Hash32>,
) -> afrolink_consensus::SignedVote {
    Vote {
        chain_id: chain(),
        height: Height(1),
        round: Round(0),
        vote_type,
        block_id,
        validator: account(signer),
    }
    .sign(&key(signer))
}

#[test]
fn beginning_the_same_round_twice_does_not_make_a_proposer_equivocate() {
    // The most dangerous defect this file guards, and it was not in the protocol
    // — it was in the driver.
    //
    // Every driver polls. A loop that called `start_round` again while still in
    // the same round made the proposer build a *second* block for that round: a
    // fresh timestamp gives a fresh header and a fresh block id, so the node
    // signed two different values for one `(height, round)`. That is exactly what
    // this chain slashes 5% of stake for, and the node would have done it to
    // itself, honestly, because of its own timer.
    //
    // It surfaced as a liveness failure rather than as a slashing: the node's own
    // vote set detected the conflict, withdrew its power from the tally, and a
    // three-of-four majority could no longer reach a quorum. A cluster stalled,
    // and the reason was that an honest validator had equivocated.
    let me = proposer_seed(4);
    let mut node = node(me, 4);

    let first = node.start_round(now());
    let proposals: Vec<_> = first
        .iter()
        .filter(|a| matches!(a, Action::BroadcastProposal(_)))
        .collect();
    assert_eq!(proposals.len(), 1, "the proposer proposes once");

    // Called again in the same round, as a polling driver will.
    let again = node.start_round(Timestamp::from_millis(1_700_000_009_000));
    assert!(
        again.is_empty(),
        "beginning a round already begun must do nothing; got {again:?}"
    );

    // And the vote this node cast is still the only one it has cast, with its
    // power intact — an equivocation would have withdrawn it.
    let cast = votes_broadcast(&first);
    assert_eq!(cast.len(), 1, "one prevote, for one block");
    let block_id = cast[0].1.expect("prevoted for its own block");

    // Two more validators agree, which with this node's own vote is three of
    // four. It can only carry the prevote step if its own vote still counts.
    let peers = others(me, 4);
    let mut carried = false;
    for signer in &peers[..2] {
        let out = node.handle(Event::Vote(Box::new(peer_vote(
            *signer,
            VoteType::Prevote,
            Some(block_id),
        ))));
        carried |= votes_broadcast(&out)
            .iter()
            .any(|(kind, _)| *kind == VoteType::Precommit);
    }
    assert!(
        carried,
        "the proposer's own vote was not counted — it equivocated against itself"
    );
}
