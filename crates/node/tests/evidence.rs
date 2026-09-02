//! A validator that equivocates is reported by whoever saw it.
//!
//! # The link that was missing
//!
//! Every other part of this worked and was tested. `VoteSet::add` detected a
//! validator signing two different values for one `(height, round)` and built
//! the `Equivocation`. `Message::ReportEquivocation` carried it. `Staking::slash`
//! applied the 5% and the jailing, with its own tests.
//!
//! And `Node::on_vote` threw the evidence away — `set.add(..).is_err()` discarded
//! the `Ok(VoteOutcome)` that carried it. So the only way a validator could ever
//! be slashed was for a human to notice, extract two votes, and hand-craft the
//! transaction. The entire economic security argument of
//! [ADR-0012](../../../docs/adr/0012-staking-and-slashing.md) rested on a caller
//! that did not exist: the same defect class as five before it, at the point
//! where it costs the most.
//!
//! These tests assert the link, and nothing else: that a node which sees the two
//! votes produces a signed transaction reporting them, holds it, and offers it to
//! the network.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_consensus::{CountryCode, Validator, ValidatorSet, Vote, VoteType};
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Allocation, Genesis, GenesisLimits};
use afrolink_node::{Action, Event, Node};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Round, Timestamp};
use afrolink_state::MemoryStore;
use afrolink_types::Message;

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

/// A node holding `key(seed)`, funded so it can pay to report what it sees.
fn node(seed: u8) -> Node {
    let validators = validators();
    let genesis = Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators.clone(),
        issuers: Vec::new(),
        attestors: Vec::new(),
        council: afrolink_executor::Council::devnet(account(50)),
        params: afrolink_executor::ChainParams::devnet(),
        // Every validator is funded. A validator that cannot pay a fee cannot
        // report an equivocation, which would make the chain's security depend on
        // somebody's balance — see the note in `Node::report_equivocation`.
        allocations: (1..=4u8)
            .map(|i| Allocation {
                address: account(i),
                denom: Denom::native(),
                amount: Amount::from_afri(1_000),
            })
            .collect(),
    };
    let mut store = MemoryStore::new();
    let block = genesis
        .apply(&mut store, GenesisLimits::devnet())
        .expect("genesis applies");
    Node::new(chain(), key(seed), validators, store, &block)
}

/// A vote from `signer` for `block_id`, as one would arrive from the network.
fn vote(signer: u8, kind: VoteType, block_id: Option<Hash32>) -> afrolink_consensus::SignedVote {
    Vote {
        chain_id: chain(),
        height: Height(1),
        round: Round(0),
        vote_type: kind,
        block_id,
        validator: account(signer),
    }
    .sign(&key(signer))
}

/// Every equivocation report in a batch of actions.
fn reports(actions: &[Action]) -> Vec<afrolink_consensus::Equivocation> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::BroadcastTransaction(tx) => tx.body.messages.iter().find_map(|m| match m {
                Message::ReportEquivocation { evidence } => Some((**evidence).clone()),
                _ => None,
            }),
            _ => None,
        })
        .collect()
}

#[test]
fn a_validator_that_votes_two_ways_is_reported_by_whoever_saw_it() {
    // The link that did not exist. Two conflicting prevotes from validator 2
    // reach an honest node, and the node must turn them into a transaction the
    // chain can act on — without anybody asking it to.
    let mut node = node(1);
    let first = Hash32::from_bytes([0xAA; 32]);
    let second = Hash32::from_bytes([0xBB; 32]);

    let quiet = node.handle(Event::Vote(Box::new(vote(
        2,
        VoteType::Prevote,
        Some(first),
    ))));
    assert!(
        reports(&quiet).is_empty(),
        "one vote is not evidence of anything"
    );

    let out = node.handle(Event::Vote(Box::new(vote(
        2,
        VoteType::Prevote,
        Some(second),
    ))));
    let filed = reports(&out);
    assert_eq!(filed.len(), 1, "the second, conflicting vote is evidence");
    assert_eq!(
        filed[0].validator,
        account(2),
        "and it names the validator that signed both"
    );
}

#[test]
fn the_evidence_reported_actually_proves_the_offence() {
    // A report the chain would refuse is worse than no report: it costs a fee and
    // achieves nothing. What is filed has to satisfy the same check the executor
    // will apply to it.
    let mut node = node(1);
    let out = node.handle(Event::Vote(Box::new(vote(
        3,
        VoteType::Precommit,
        Some(Hash32::from_bytes([1; 32])),
    ))));
    assert!(reports(&out).is_empty());
    let out = node.handle(Event::Vote(Box::new(vote(
        3,
        VoteType::Precommit,
        Some(Hash32::from_bytes([2; 32])),
    ))));

    let filed = reports(&out);
    assert_eq!(filed.len(), 1);
    assert!(
        afrolink_staking::proves_equivocation(&filed[0], &validators()),
        "the executor would refuse this evidence"
    );
}

#[test]
fn the_report_is_held_by_the_node_that_made_it() {
    // Broadcasting is not enough. If the reporter does not also hold the
    // transaction, then a reporter that happens to be the next proposer cannot
    // include the evidence it just found.
    let mut node = node(1);
    drop(node.handle(Event::Vote(Box::new(vote(
        2,
        VoteType::Prevote,
        Some(Hash32::from_bytes([1; 32])),
    )))));
    let out = node.handle(Event::Vote(Box::new(vote(
        2,
        VoteType::Prevote,
        Some(Hash32::from_bytes([2; 32])),
    ))));

    let Some(Action::BroadcastTransaction(tx)) = out
        .iter()
        .find(|a| matches!(a, Action::BroadcastTransaction(_)))
        .cloned()
    else {
        panic!("no report was broadcast");
    };
    assert!(
        node.is_pending(&tx.id()),
        "the reporter must hold its own report, or it cannot propose it"
    );
    assert_eq!(node.pending(), 1);
}

#[test]
fn one_offence_produces_one_report_however_many_votes_follow() {
    // Every conflicting vote after the first is more of the same offence. A
    // report per vote would be a fee per vote, paid by the honest node that
    // noticed — which is a way to punish the reporter for paying attention.
    let mut node = node(1);
    for n in 0..6u8 {
        drop(node.handle(Event::Vote(Box::new(vote(
            2,
            VoteType::Prevote,
            Some(Hash32::from_bytes([n; 32])),
        )))));
    }
    assert_eq!(node.pending(), 1, "one offence, one transaction");
}

#[test]
fn two_different_offenders_are_reported_separately() {
    let mut node = node(1);
    for offender in [2u8, 3u8] {
        for n in 0..2u8 {
            drop(node.handle(Event::Vote(Box::new(vote(
                offender,
                VoteType::Prevote,
                Some(Hash32::from_bytes([n.wrapping_add(offender); 32])),
            )))));
        }
    }
    assert_eq!(node.pending(), 2, "two offences, two transactions");
}

#[test]
fn an_honest_disagreement_is_not_reported() {
    // Different validators voting for different blocks is ordinary — it is what a
    // round with a slow network looks like, and it is what the prevote timeout
    // exists for. Only *one* validator signing two values is an offence.
    let mut node = node(1);
    let a = Hash32::from_bytes([0xAA; 32]);
    let b = Hash32::from_bytes([0xBB; 32]);
    drop(node.handle(Event::Vote(Box::new(vote(2, VoteType::Prevote, Some(a))))));
    drop(node.handle(Event::Vote(Box::new(vote(3, VoteType::Prevote, Some(b))))));
    drop(node.handle(Event::Vote(Box::new(vote(4, VoteType::Prevote, None)))));
    assert_eq!(node.pending(), 0, "disagreement is not equivocation");
}

#[test]
fn a_repeated_identical_vote_is_not_an_offence() {
    // A peer relaying the same vote twice is normal gossip, not a double-sign.
    let mut node = node(1);
    let same = Some(Hash32::from_bytes([7; 32]));
    for _ in 0..5 {
        drop(node.handle(Event::Vote(Box::new(vote(2, VoteType::Prevote, same)))));
    }
    assert_eq!(node.pending(), 0);
}
