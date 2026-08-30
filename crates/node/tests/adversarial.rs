//! Randomised consensus campaigns against a hostile scheduler.
//!
//! Every scenario here attacks one invariant and one only:
//!
//! > **Agreement — no two nodes commit different blocks at the same height.**
//!
//! Liveness is *expected* to break under most of these. A partitioned network
//! should stall; a network dropping half its packets should crawl. Confusing the
//! two is how a consensus test ends up asserting the wrong thing, so nothing
//! here requires progress except where progress is genuinely guaranteed.
//!
//! Each campaign is a pure function of its seed, so a failure reproduces exactly
//! rather than being retried until it goes away.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_bank::Issuer;
use afrolink_consensus::{CountryCode, Step, Validator, ValidatorSet, Vote, VoteType};
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Allocation, Block, Genesis, GenesisLimits};
use afrolink_node::Event;
use afrolink_node::sim::Network;
use afrolink_primitives::{Amount, ChainId, Denom, Height, Round, Timestamp};
use afrolink_state::MemoryStore;

const COUNTRIES: [&str; 7] = ["ke", "ng", "za", "tz", "gh", "ug", "rw"];

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

fn keys(n: u8) -> Vec<SecretKey> {
    (1..=n).map(key).collect()
}

fn network(n: u8) -> (Network, ValidatorSet) {
    let validators = ValidatorSet::new(
        (1..=n)
            .map(|i| {
                Validator::new(
                    key(i).public_key(),
                    1,
                    CountryCode::new(COUNTRIES[(i as usize - 1) % COUNTRIES.len()])
                        .expect("valid country"),
                )
            })
            .collect(),
    )
    .expect("valid set");

    let genesis = Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators.clone(),
        issuers: vec![(kes(), Issuer::new(addr(100)))],
        allocations: vec![Allocation {
            address: addr(50),
            denom: kes(),
            amount: Amount::from_afri(1_000),
        }],
    };
    let mut store = MemoryStore::new();
    let block: Block = genesis
        .apply(&mut store, GenesisLimits::devnet())
        .expect("applies");

    (
        Network::new(&chain(), &keys(n), &validators, &store, &block),
        validators,
    )
}

/// How many independent schedules a campaign explores.
///
/// Small by default so `cargo test` stays fast enough that people run it, and
/// multiplied by `AFROLINK_CAMPAIGN` for a deep run:
///
/// ```text
/// AFROLINK_CAMPAIGN=20 cargo test -p afrolink-node --test adversarial --release
/// ```
///
/// Breadth is the only thing that changes. Every schedule is still a pure
/// function of its seed, so a failure at any depth reproduces at that seed
/// alone.
fn campaign(base: u64) -> u64 {
    let factor = std::env::var("AFROLINK_CAMPAIGN")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1)
        .max(1);
    base.saturating_mul(factor)
}

/// Drive `rounds` rounds, firing every timeout so a stalled network still
/// advances its round number rather than deadlocking the test.
fn drive(net: &mut Network, rounds: usize) {
    for _ in 0..rounds {
        net.start_round();
        net.run(10_000);
        net.tick(Step::Propose, 10_000);
        net.tick(Step::Prevote, 10_000);
        net.tick(Step::Precommit, 10_000);
    }
}

#[test]
fn agreement_survives_every_schedule_the_adversary_can_pick() {
    // The headline campaign. 200 independent networks, each with a different
    // random delivery order and packet-loss rate, driven for 6 rounds.
    //
    // Progress is deliberately not asserted: with up to 60% loss most of these
    // stall, and demanding liveness here would be demanding something BFT does
    // not promise under an adversarial network.
    for seed in 0..campaign(20) {
        let (mut net, _) = network(4);
        net.seed(seed);
        net.reorder(true);
        net.drop_rate(seed % 61);
        drive(&mut net, 6);

        assert_eq!(
            net.agreement_violation(),
            None,
            "two nodes committed different blocks (seed {seed})"
        );
    }
}

#[test]
fn agreement_survives_the_maximum_tolerable_crash_faults() {
    // f = floor((n-1)/3). At n=7 that is 2 crashed nodes, and the remaining 5
    // still exceed the two-thirds threshold, so this network must both agree
    // *and* make progress.
    for seed in 0..campaign(6) {
        let (mut net, _) = network(7);
        net.seed(seed);
        net.reorder(true);
        net.crash(5);
        net.crash(6);
        drive(&mut net, 6);

        assert_eq!(net.agreement_violation(), None, "seed {seed}");
        assert!(
            !net.committed().is_empty(),
            "5 of 7 live is above quorum, so the chain must still commit (seed {seed})"
        );
    }
}

#[test]
fn a_partition_stalls_the_chain_but_never_splits_it() {
    // The case a crash cannot model: both sides stay up and both believe they
    // may still make progress. Neither side has a quorum, so neither may commit
    // — and crucially they must not commit *different* blocks.
    for seed in 0..campaign(6) {
        let (mut net, _) = network(6);
        net.seed(seed);
        net.reorder(true);
        net.partition(&[0, 1, 2]);
        drive(&mut net, 8);

        assert_eq!(
            net.agreement_violation(),
            None,
            "a partition must never produce two histories (seed {seed})"
        );
        assert!(
            net.committed().is_empty(),
            "neither side of a 3/3 split has a quorum, so nothing may commit (seed {seed})"
        );
    }
}

#[test]
fn a_healed_partition_leaves_one_history() {
    // Recovery, which is where a consensus bug most often shows: the minority
    // side must adopt the majority's history rather than keeping its own.
    for seed in 0..campaign(6) {
        let (mut net, _) = network(7);
        net.seed(seed);
        net.reorder(true);

        // 5 of 7 on one side: a quorum, so that side progresses alone.
        net.partition(&[0, 1, 2, 3, 4]);
        drive(&mut net, 4);
        let during = net.committed().len();

        net.heal();
        drive(&mut net, 6);

        assert_eq!(net.agreement_violation(), None, "seed {seed}");
        assert!(
            net.committed().len() >= during,
            "healing must not lose commits (seed {seed})"
        );
    }
}

#[test]
fn an_equivocating_validator_cannot_split_the_chain() {
    // The Byzantine case. Rather than modelling a dishonest node, this signs
    // conflicting precommits with a *real* validator key and hands one to each
    // half of the network — strictly stronger than anything the honest state
    // machine could be made to emit.
    for seed in 0..campaign(6) {
        let (mut net, _) = network(4);
        net.seed(seed);
        net.reorder(true);

        for round in 0..6u32 {
            net.start_round();
            net.run(10_000);

            // Validator 1 votes for two different blocks at the same height,
            // telling nodes {0,1} one story and {2,3} another.
            for (targets, block) in [
                (vec![0usize, 1], Hash32::from_bytes([0xAA; 32])),
                (vec![2usize, 3], Hash32::from_bytes([0xBB; 32])),
            ] {
                let vote = Vote {
                    chain_id: chain(),
                    height: Height(u64::from(round) + 1),
                    round: Round(round),
                    vote_type: VoteType::Precommit,
                    block_id: Some(block),
                    validator: addr(1),
                }
                .sign(&key(1));
                net.inject(&targets, Event::Vote(Box::new(vote)));
            }
            net.run(10_000);
            net.tick(Step::Propose, 10_000);
            net.tick(Step::Prevote, 10_000);
            net.tick(Step::Precommit, 10_000);
        }

        assert_eq!(
            net.agreement_violation(),
            None,
            "an equivocator must not produce two histories (seed {seed})"
        );
    }
}

#[test]
fn forged_votes_from_a_non_validator_are_ignored() {
    // A stranger with a valid signature over a well-formed vote is still not a
    // validator, and their voting power must be zero.
    for seed in 0..campaign(4) {
        let (mut net, _) = network(4);
        net.seed(seed);
        net.reorder(true);

        for round in 0..4u32 {
            net.start_round();
            net.run(10_000);

            // Twenty strangers all vote for the same fabricated block. That is
            // five times the real validator set.
            for stranger in 60..80u8 {
                let vote = Vote {
                    chain_id: chain(),
                    height: Height(u64::from(round) + 1),
                    round: Round(round),
                    vote_type: VoteType::Precommit,
                    block_id: Some(Hash32::from_bytes([0xCC; 32])),
                    validator: addr(stranger),
                }
                .sign(&key(stranger));
                net.inject(&[0, 1, 2, 3], Event::Vote(Box::new(vote)));
            }
            net.run(10_000);
            net.tick(Step::Propose, 10_000);
            net.tick(Step::Prevote, 10_000);
            net.tick(Step::Precommit, 10_000);
        }

        assert_eq!(net.agreement_violation(), None, "seed {seed}");
        assert!(
            !net.committed()
                .iter()
                .any(|(_, _, block)| *block == Hash32::from_bytes([0xCC; 32])),
            "a block only strangers voted for must never commit (seed {seed})"
        );
    }
}

#[test]
fn a_vote_from_another_chain_is_ignored() {
    // Cross-chain replay: the same validators, the same keys, a testnet
    // chain id. Without the chain binding in the sign doc these would count.
    let other = ChainId::new("afrolink-testnet").expect("valid");
    for seed in 0..campaign(4) {
        let (mut net, _) = network(4);
        net.seed(seed);

        for round in 0..4u32 {
            net.start_round();
            net.run(10_000);
            for v in 1..=4u8 {
                let vote = Vote {
                    chain_id: other.clone(),
                    height: Height(u64::from(round) + 1),
                    round: Round(round),
                    vote_type: VoteType::Precommit,
                    block_id: Some(Hash32::from_bytes([0xDD; 32])),
                    validator: addr(v),
                }
                .sign(&key(v));
                net.inject(&[0, 1, 2, 3], Event::Vote(Box::new(vote)));
            }
            net.run(10_000);
            net.tick(Step::Propose, 10_000);
            net.tick(Step::Prevote, 10_000);
            net.tick(Step::Precommit, 10_000);
        }

        assert_eq!(net.agreement_violation(), None, "seed {seed}");
        assert!(
            !net.committed()
                .iter()
                .any(|(_, _, block)| *block == Hash32::from_bytes([0xDD; 32])),
            "a full quorum from another chain must not commit here (seed {seed})"
        );
    }
}

#[test]
fn a_crashed_node_that_restarts_does_not_fork_the_chain() {
    // Restart is where state that outlives a process gets it wrong. The node
    // has missed everything sent while it was down.
    for seed in 0..campaign(6) {
        let (mut net, _) = network(7);
        net.seed(seed);
        net.reorder(true);

        net.crash(6);
        drive(&mut net, 4);
        net.restart(6);
        drive(&mut net, 6);

        assert_eq!(
            net.agreement_violation(),
            None,
            "a restarted node must not commit a different history (seed {seed})"
        );
    }
}

#[test]
fn total_message_loss_stalls_without_splitting() {
    // The degenerate case. Nothing is delivered between nodes at all, so each
    // sees only itself: no quorum, therefore no commits, and certainly no
    // conflicting ones.
    let (mut net, _) = network(4);
    net.seed(1);
    net.drop_rate(100);
    drive(&mut net, 10);

    assert_eq!(net.agreement_violation(), None);
    assert!(
        net.committed().is_empty(),
        "a node cannot reach a quorum by talking to itself"
    );
}
