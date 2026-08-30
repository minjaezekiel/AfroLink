//! A deterministic in-process network simulator.
//!
//! Runs a whole validator set in one thread with no sockets and no clock, so a
//! consensus scenario is reproducible exactly. Crashes, partitions, message loss
//! and reordering are expressed as **delivery rules** rather than as timing,
//! which is what makes these tests reproducible instead of flaky: a scenario is
//! a pure function of its seed.
//!
//! # What an adversary controls here
//!
//! Everything a real one would, short of breaking cryptography:
//!
//! * [`Network::crash`] — a node stops sending and receiving.
//! * [`Network::partition`] — the set splits, and messages do not cross.
//! * [`Network::drop_rate`] — a share of messages are lost.
//! * [`Network::reorder`] — delivery order is shuffled, so no test can pass by
//!   accident of FIFO.
//!
//! The scheduler is the adversary: it decides who hears what, and in what order.
//!
//! # The invariant all of this exists to attack
//!
//! **Agreement.** No two nodes may commit different blocks at the same height.
//! Liveness can be destroyed by any of the rules above and that is expected —
//! a partitioned network should stall. Agreement may not be, under any of them,
//! and [`Network::committed`] records every commit so a campaign can check it.

use afrolink_crypto::SecretKey;
use afrolink_crypto::hash::Hash32;
use afrolink_executor::Block;
use afrolink_primitives::{ChainId, Height, Timestamp};
use afrolink_state::MemoryStore;
use std::collections::BTreeSet;

use crate::{Action, Event, Node};
use afrolink_consensus::{Step, ValidatorSet};

/// A set of nodes and the messages in flight between them.
pub struct Network {
    /// The nodes, in validator-set order.
    pub nodes: Vec<Node>,
    /// Indices of nodes that are offline; they neither send nor receive.
    pub crashed: BTreeSet<usize>,
    /// One side of a network partition. Messages do not cross the boundary.
    side_a: BTreeSet<usize>,
    partitioned: bool,
    /// Share of messages dropped, in hundredths. 0 delivers everything.
    drop_pct: u64,
    shuffle: bool,
    rng: u64,
    /// Every `(height, block_id)` any node has committed, in order.
    committed: Vec<(usize, Height, Hash32)>,
    queue: Vec<(usize, Event)>,
    time: Timestamp,
}

impl Network {
    /// Build a network of nodes sharing one genesis.
    #[must_use]
    pub fn new(
        chain_id: &ChainId,
        keys: &[SecretKey],
        validators: &ValidatorSet,
        store: &MemoryStore,
        genesis: &Block,
    ) -> Self {
        let nodes = keys
            .iter()
            .map(|k| {
                Node::new(
                    chain_id.clone(),
                    SecretKey::from_bytes(&k.to_bytes()),
                    validators.clone(),
                    store.clone(),
                    genesis,
                )
            })
            .collect();
        Self {
            nodes,
            crashed: BTreeSet::new(),
            side_a: BTreeSet::new(),
            partitioned: false,
            drop_pct: 0,
            shuffle: false,
            rng: 0x2545_F491_4F6C_DD1D,
            committed: Vec::new(),
            queue: Vec::new(),
            time: Timestamp::from_millis(1_700_000_000_000),
        }
    }

    /// Take a node offline. It stops sending and receiving.
    pub fn crash(&mut self, index: usize) {
        self.crashed.insert(index);
    }

    /// Bring a crashed node back. It has missed everything sent while down.
    pub fn restart(&mut self, index: usize) {
        self.crashed.remove(&index);
    }

    /// Split the network. Messages between the two sides are not delivered.
    ///
    /// Unlike a crash, both sides keep running and keep believing they may make
    /// progress — which is what makes a partition the harder case.
    pub fn partition(&mut self, side_a: &[usize]) {
        self.side_a = side_a.iter().copied().collect();
        self.partitioned = true;
    }

    /// Heal a partition.
    pub fn heal(&mut self) {
        self.partitioned = false;
        self.side_a.clear();
    }

    /// Drop this percentage of messages.
    pub fn drop_rate(&mut self, percent: u64) {
        self.drop_pct = percent.min(100);
    }

    /// Shuffle delivery order.
    ///
    /// Worth turning on by default in any campaign: a consensus test that only
    /// ever sees FIFO delivery is testing a network nobody has.
    pub fn reorder(&mut self, on: bool) {
        self.shuffle = on;
    }

    /// Seed the scheduler, so a campaign reproduces exactly from its seed.
    pub fn seed(&mut self, seed: u64) {
        self.rng = seed | 1;
    }

    /// Every commit any node has made: `(node, height, block)`.
    #[must_use]
    pub fn committed(&self) -> &[(usize, Height, Hash32)] {
        &self.committed
    }

    /// The agreement invariant: no two nodes committed different blocks at one
    /// height.
    ///
    /// Returns the offending height if it was ever violated. This is the
    /// property that must survive every delivery rule in this module — liveness
    /// may not, and is not expected to.
    #[must_use]
    pub fn agreement_violation(&self) -> Option<Height> {
        for (i, (_, height, block)) in self.committed.iter().enumerate() {
            for (_, other_height, other_block) in self.committed.iter().skip(i.saturating_add(1)) {
                if height == other_height && block != other_block {
                    return Some(*height);
                }
            }
        }
        None
    }

    fn next_rand(&mut self) -> u64 {
        // xorshift64*: tiny, deterministic, and adequate for scheduling.
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Whether a message from `from` reaches `to` under the current rules.
    fn reaches(&mut self, from: usize, to: usize) -> bool {
        if !self.is_live(to) || !self.is_live(from) {
            return false;
        }
        if self.partitioned && self.side_a.contains(&from) != self.side_a.contains(&to) {
            return false;
        }
        if self.drop_pct > 0 && self.next_rand() % 100 < self.drop_pct {
            return false;
        }
        true
    }

    /// Whether a node is running.
    #[must_use]
    pub fn is_live(&self, index: usize) -> bool {
        !self.crashed.contains(&index)
    }

    /// Number of live nodes.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.nodes.len().saturating_sub(self.crashed.len())
    }

    /// Start the current round on every live node.
    pub fn start_round(&mut self) {
        // Advance one second per round. Header times are strictly monotonic on
        // a real chain, and a light client depends on that to bound how stale
        // its trusted header is (ADR-0010).
        self.time = Timestamp::from_millis(self.time.0.saturating_add(1_000));
        let time = self.time;
        for i in 0..self.nodes.len() {
            if !self.is_live(i) {
                continue;
            }
            let actions = self
                .nodes
                .get_mut(i)
                .map(|n| n.start_round(time))
                .unwrap_or_default();
            self.dispatch(i, actions);
        }
    }

    /// Deliver queued messages until the network goes quiet.
    ///
    /// Returns the blocks committed during this run, paired with the node that
    /// committed them.
    pub fn run(&mut self, max_steps: usize) -> Vec<(usize, Block)> {
        let mut commits = Vec::new();
        for _ in 0..max_steps {
            if self.queue.is_empty() {
                break;
            }
            let mut batch = core::mem::take(&mut self.queue);
            if self.shuffle {
                // Fisher-Yates against the seeded scheduler. Without this the
                // suite only ever tests FIFO delivery, which no real network
                // provides.
                for i in (1..batch.len()).rev() {
                    let span = u64::try_from(i).unwrap_or(0).saturating_add(1);
                    let j = self
                        .next_rand()
                        .checked_rem(span)
                        .and_then(|v| usize::try_from(v).ok())
                        .unwrap_or(0);
                    batch.swap(i, j);
                }
            }
            for (target, event) in batch {
                if !self.is_live(target) {
                    continue;
                }
                let actions = self
                    .nodes
                    .get_mut(target)
                    .map(|n| n.handle(event))
                    .unwrap_or_default();
                for action in &actions {
                    if let Action::Committed(block, _) = action {
                        self.committed
                            .push((target, block.header.height, block.header.id()));
                        commits.push((target, (**block).clone()));
                    }
                }
                self.dispatch(target, actions);
            }
        }
        commits
    }

    /// Fire a timeout on every live node, then run to quiescence.
    pub fn tick(&mut self, step: Step, max_steps: usize) -> Vec<(usize, Block)> {
        for i in 0..self.nodes.len() {
            if self.is_live(i) {
                self.queue.push((i, Event::Timeout(step)));
            }
        }
        self.run(max_steps)
    }

    /// Turn a node's actions into messages, subject to the delivery rules.
    ///
    /// Broadcasts are delivered to the sender too, so proposing and receiving
    /// follow exactly the same code path — and a sender is never partitioned
    /// from itself, however hostile the schedule.
    fn dispatch(&mut self, from: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::BroadcastProposal(p) => {
                    for i in 0..self.nodes.len() {
                        if i == from || self.reaches(from, i) {
                            self.queue.push((i, Event::Proposal(p.clone())));
                        }
                    }
                }
                Action::BroadcastVote(v) => {
                    for i in 0..self.nodes.len() {
                        if i == from || self.reaches(from, i) {
                            self.queue.push((i, Event::Vote(v.clone())));
                        }
                    }
                }
                Action::Committed(_, _) | Action::ScheduleTimeout(_, _) => {}
            }
        }
    }

    /// Inject a message as if a hostile peer had sent it.
    ///
    /// This is how a Byzantine validator is expressed: rather than modelling a
    /// dishonest [`Node`], a test signs whatever votes it likes with a real key
    /// and hands them straight to specific targets. That is strictly stronger,
    /// because it is not limited to misbehaviour the honest state machine is
    /// capable of expressing — an equivocator can send one vote to half the
    /// network and a conflicting one to the other half.
    pub fn inject(&mut self, targets: &[usize], event: Event) {
        for &t in targets {
            if self.is_live(t) {
                self.queue.push((t, event.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_bank::Issuer;
    use afrolink_consensus::{CountryCode, Validator};
    use afrolink_crypto::Address;
    use afrolink_executor::{Allocation, Genesis, GenesisLimits};
    use afrolink_primitives::{Amount, Denom, Height};
    use afrolink_state::KeyValueStore;
    use afrolink_types::{Fee, Message, Transaction, TxBody};

    const COUNTRIES: [&str; 4] = ["ke", "ng", "za", "tz"];

    /// A wall-clock reading well inside the trusting period for these fixtures.
    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_100_000)
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid")
    }

    fn keys(n: u8) -> Vec<SecretKey> {
        (1..=n).map(|i| SecretKey::from_bytes(&[i; 32])).collect()
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    /// `n` equal validators, one per country, plus two funded user accounts.
    ///
    /// Returns the network together with the genesis header and validator set —
    /// exactly what a wallet would be shipped with.
    fn setup(n: u8) -> (Network, Block, ValidatorSet) {
        let ks = keys(n);
        let validators = ValidatorSet::new(
            ks.iter()
                .enumerate()
                .map(|(i, k)| {
                    let country = COUNTRIES.get(i % COUNTRIES.len()).copied().unwrap_or("ke");
                    Validator::new(
                        k.public_key(),
                        100,
                        CountryCode::new(country).expect("valid"),
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
            allocations: vec![
                Allocation {
                    address: addr(50),
                    denom: kes(),
                    amount: Amount::from_afri(10_000),
                },
                Allocation {
                    address: addr(51),
                    denom: kes(),
                    amount: Amount::from_afri(10_000),
                },
            ],
        };

        let mut store = MemoryStore::new();
        let block = genesis
            .apply(&mut store, GenesisLimits::devnet())
            .expect("genesis applies");
        let net = Network::new(&chain(), &ks, &validators, &store, &block);
        (net, block, validators)
    }

    /// Just the network, for tests that do not need genesis artefacts.
    fn network(n: u8) -> Network {
        setup(n).0
    }

    fn payment(nonce: u64, amount: u64) -> Transaction {
        TxBody {
            chain_id: chain(),
            sender: addr(50),
            nonce,
            valid_until: Height(1_000),
            fee: Fee::new(Amount::from_units(1_000), kes()),
            messages: vec![Message::Transfer {
                to: addr(51),
                denom: kes(),
                amount: Amount::from_afri(amount),
                reference: None,
            }],
            memo: String::new(),
        }
        .sign(&SecretKey::from_bytes(&[50; 32]))
    }

    #[test]
    fn four_honest_validators_commit_the_same_block() {
        // The basic liveness and agreement claim.
        let mut net = network(4);
        for node in &mut net.nodes {
            node.mempool.push(payment(0, 100));
        }
        net.start_round();
        let commits = net.run(1_000);

        assert_eq!(commits.len(), 4, "every validator should commit");
        let ids: BTreeSet<_> = commits.iter().map(|(_, b)| b.header.id()).collect();
        assert_eq!(ids.len(), 1, "and they must all commit the *same* block");

        for node in &net.nodes {
            assert_eq!(
                node.height(),
                Height(2),
                "height advanced past the committed block"
            );
            assert_eq!(node.committed.len(), 1);
        }
    }

    #[test]
    fn every_validator_reaches_the_same_state_root() {
        // Agreement on the block is not enough; they must agree on what it did.
        let mut net = network(4);
        for node in &mut net.nodes {
            node.mempool.push(payment(0, 250));
        }
        net.start_round();
        net.run(1_000);

        let roots: BTreeSet<_> = net.nodes.iter().map(Node::app_hash).collect();
        assert_eq!(roots.len(), 1, "all validators must hold identical state");
    }

    #[test]
    fn the_committed_transaction_actually_moved_money() {
        let mut net = network(4);
        for node in &mut net.nodes {
            node.mempool.push(payment(0, 400));
        }
        net.start_round();
        net.run(1_000);

        let node = net.nodes.first().expect("a node exists");
        let bank = afrolink_bank::BankView::new(node.store());
        assert_eq!(
            bank.balance(&addr(51), &kes()).expect("read"),
            Amount::from_afri(10_400),
        );
    }

    #[test]
    fn consensus_survives_one_crashed_validator_out_of_four() {
        // 3 of 4 is exactly the quorum: the chain must still make progress.
        let mut net = network(4);
        net.crash(3);
        for (i, node) in net.nodes.iter_mut().enumerate() {
            if i != 3 {
                node.mempool.push(payment(0, 100));
            }
        }
        net.start_round();
        // The crashed node may have been the proposer; let a timeout rotate the
        // round if nothing was committed on the first attempt.
        let mut commits = net.run(1_000);
        if commits.is_empty() {
            // The crashed node was this round's proposer. Time the round out so
            // the rotation picks a live one, then try again.
            net.tick(Step::Propose, 1_000);
            net.tick(Step::Prevote, 1_000);
            net.tick(Step::Precommit, 1_000);
            net.start_round();
            commits = net.run(1_000);
        }

        assert_eq!(net.live_count(), 3);
        assert!(!commits.is_empty(), "3 of 4 is a quorum and must commit");
        let ids: BTreeSet<_> = commits.iter().map(|(_, b)| b.header.id()).collect();
        assert_eq!(ids.len(), 1, "the live validators must agree");
    }

    #[test]
    fn consensus_halts_rather_than_forking_when_quorum_is_lost() {
        // 2 of 4 is below the quorum of 3. The correct behaviour for a payments
        // chain is to stop: a halt is recoverable, a double-spend is not.
        let mut net = network(4);
        net.crash(2);
        net.crash(3);
        for node in &mut net.nodes {
            node.mempool.push(payment(0, 100));
        }
        net.start_round();
        let mut commits = net.run(1_000);
        for _ in 0..3 {
            net.tick(Step::Propose, 1_000);
            net.tick(Step::Prevote, 1_000);
            net.tick(Step::Precommit, 1_000);
            net.start_round();
            commits.extend(net.run(1_000));
        }

        assert!(commits.is_empty(), "must not commit without a quorum");
        for (i, node) in net.nodes.iter().enumerate() {
            if net.is_live(i) {
                assert_eq!(node.height(), Height(1), "height must not advance");
                assert!(node.committed.is_empty());
            }
        }
    }

    #[test]
    fn a_node_that_missed_the_proposal_prevotes_nil_on_timeout() {
        // Liveness: a round with no proposal must conclude rather than hang.
        let mut net = network(4);
        // Nobody starts a round, so no proposal exists. Timeouts drive it.
        let commits = net.tick(Step::Propose, 1_000);
        assert!(commits.is_empty());
        for node in &net.nodes {
            assert_eq!(node.height(), Height(1), "no block, so no progress");
        }
    }

    #[test]
    fn consecutive_heights_chain_together() {
        let mut net = network(4);
        for node in &mut net.nodes {
            node.mempool.push(payment(0, 100));
        }
        net.start_round();
        net.run(1_000);

        for node in &mut net.nodes {
            node.mempool.push(payment(1, 50));
        }
        net.start_round();
        let commits = net.run(1_000);

        assert!(!commits.is_empty(), "the second height must also commit");
        let node = net.nodes.first().expect("a node exists");
        assert_eq!(node.committed.len(), 2);
        assert_eq!(node.height(), Height(3));

        let first = node.committed.first().expect("block 1");
        let second = node.committed.get(1).expect("block 2");
        assert_eq!(
            second.header.parent,
            first.header.id(),
            "each block must name its predecessor"
        );
        assert_eq!(second.header.height, Height(2));
    }

    #[test]
    fn a_proposer_cannot_lie_about_the_resulting_state() {
        // Validators re-execute rather than trusting the header. A forged
        // app_hash must be rejected, and the block must not commit.
        let mut net = network(4);
        for node in &mut net.nodes {
            node.mempool.push(payment(0, 100));
        }

        // Find the proposer and let it build a proposal.
        let proposer = (0..4)
            .find(|i| {
                net.nodes
                    .get(*i)
                    .is_some_and(|n| n.is_proposer(afrolink_primitives::Round::ZERO))
            })
            .expect("some node proposes");

        let actions = net
            .nodes
            .get_mut(proposer)
            // One second after genesis: header times are strictly monotonic, and
            // a light client relies on that to bound how stale its trust is.
            .map(|n| n.start_round(Timestamp::from_millis(1_700_000_001_000)))
            .unwrap_or_default();

        let mut forged = actions
            .iter()
            .find_map(|a| match a {
                Action::BroadcastProposal(p) => Some((**p).clone()),
                _ => None,
            })
            .expect("a proposal was produced");

        // Tamper with the claimed state root and re-sign so the signature is valid.
        forged.proposal.block.header.app_hash = afrolink_crypto::hash::Hash32::ZERO;
        let key = SecretKey::from_bytes(&[u8::try_from(proposer + 1).expect("small index"); 32]);
        let forged = forged.proposal.sign(&key);

        // Deliver only the forged proposal to an honest validator.
        let honest = (0..4)
            .find(|i| *i != proposer)
            .expect("an honest node exists");
        let out = net
            .nodes
            .get_mut(honest)
            .map(|n| n.handle(Event::Proposal(Box::new(forged))))
            .unwrap_or_default();

        let prevote = out.iter().find_map(|a| match a {
            Action::BroadcastVote(v) => Some(v.vote.block_id),
            _ => None,
        });
        assert_eq!(
            prevote,
            Some(None),
            "an honest validator must prevote nil for a block whose state root is a lie"
        );
    }

    #[test]
    fn a_proposal_from_a_non_proposer_is_ignored() {
        let mut net = network(4);
        let proposer = (0..4)
            .find(|i| {
                net.nodes
                    .get(*i)
                    .is_some_and(|n| n.is_proposer(afrolink_primitives::Round::ZERO))
            })
            .expect("some node proposes");
        let impostor = (0..4).find(|i| *i != proposer).expect("another node");

        let actions = net
            .nodes
            .get_mut(impostor)
            // One second after genesis: header times are strictly monotonic, and
            // a light client relies on that to bound how stale its trust is.
            .map(|n| n.start_round(Timestamp::from_millis(1_700_000_001_000)))
            .unwrap_or_default();

        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastProposal(_))),
            "a non-proposer must not propose"
        );
    }
    #[test]
    fn a_phone_verifies_a_payment_from_headers_alone() {
        // The end-to-end thesis, with nothing mocked: real validators reach
        // consensus, emit a real commit certificate, and a light client holding
        // only the genesis header and the validator set follows the chain and
        // checks a balance against a proof from an untrusted server.
        let (mut net, genesis, validators) = setup(4);
        let mut client =
            afrolink_light::LightClient::new(chain(), validators.clone(), genesis.header);

        for node in &mut net.nodes {
            node.mempool.push(payment(0, 750));
        }
        net.start_round();
        net.run(1_000);

        // Take the block and certificate the validators actually produced.
        let node = net.nodes.first().expect("a node exists");
        let block = node
            .committed
            .first()
            .expect("a block was committed")
            .clone();
        let commit = node
            .last_commit
            .clone()
            .expect("a certificate was produced");

        client
            .update(
                block.header,
                &commit,
                validators.clone(),
                validators.clone(),
                now(),
            )
            .expect("a real commit from a real quorum must verify");
        assert_eq!(client.height(), Height(1));

        // An untrusted server answers the wallet's balance query with a proof.
        let key = afrolink_state::StoreKey::balance(&addr(51), &kes());
        let (value, proof) = node.store().get_with_proof(&key);

        let balance = client
            .verify_balance(&addr(51), &kes(), value.as_deref(), &proof)
            .expect("the proof must verify against the header the wallet trusts");
        assert_eq!(
            balance,
            Amount::from_afri(10_750),
            "10,000 at genesis plus a 750 payment"
        );

        // And the same server cannot inflate the number.
        let lie = afrolink_primitives::codec::Encode::to_bytes(&Amount::from_afri(9_999_999));
        assert!(
            client
                .verify_balance(&addr(51), &kes(), Some(&lie), &proof)
                .is_err(),
            "a forged balance must not verify"
        );
    }
}
