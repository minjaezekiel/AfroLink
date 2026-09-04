//! A real network: N nodes, N sockets, N databases, real consensus between them.
//!
//! # Why this exists
//!
//! Two suites already attack this system and neither can ask the question a
//! testnet asks.
//!
//! * `crates/node/src/sim.rs` attacks **agreement** with partitions, packet loss
//!   and injected equivocation — and has no network in it at all.
//! * `crates/p2p/tests/network.rs` attacks **the wire** with real sockets and a
//!   real handshake — and has no consensus in it at all.
//!
//! Everything that has gone wrong in this project recently went wrong in the seam
//! between them. A node's own vote was counted by the simulator and not by the
//! system. A commit was persisted on the transport's delivery path and not on the
//! driver's. Both passed every test in a suite of nearly a thousand, and both were
//! found by running the binary and noticing the log disagreed with the node's own
//! query endpoint.
//!
//! So this harness runs the thing. Each node here is assembled from exactly the
//! parts `afrolinkd` assembles — a `ChainStore` on disk, a `Transport` on a
//! loopback socket, a `SharedNode`, the same `Blocks` and `Persist` adapters —
//! and driven by the same loop shape. What is asserted is what an operator would
//! check: that the heights agree, that the state roots agree, and that a node
//! which fell behind is indistinguishable afterwards from one that never did.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afrolink_consensus::{CountryCode, Validator, ValidatorSet};
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{Address, SecretKey};
use afrolink_daemon::chain::{Blocks, Persist};
use afrolink_daemon::driver::{Driver, Timings};
use afrolink_executor::{Allocation, Genesis, GenesisLimits};
use afrolink_node::{Node, SharedNode};
use afrolink_p2p::addrbook::AddrBook;
use afrolink_p2p::manager::{Limits, Manager};
use afrolink_p2p::peer::{PeerAddr, PeerId};
use afrolink_p2p::transport::Transport;
use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
use afrolink_state::MemoryStore;
use afrolink_store::ChainStore;
use afrolink_types::{Fee, Message, Transaction, TxBody};

const COUNTRIES: [&str; 4] = ["ke", "ng", "za", "tz"];

/// Runs the cluster tests one at a time.
///
/// Each one starts four or five nodes, and each node holds a listener plus two
/// threads per peer. Run concurrently they contend for CPU badly enough that a
/// consensus timeout starts measuring the test runner rather than the protocol —
/// which shows up as an intermittent failure that looks like a liveness bug and
/// is not. A held lock is a clearer statement than a tuned timeout.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Take the lock, ignoring poisoning: a panic in one test has already failed it,
/// and there is no shared state here to be left inconsistent.
fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

/// Deliberately fast. A test that waits a second a block is a test nobody runs.
const BLOCK_INTERVAL: Duration = Duration::from_millis(120);
const TIMEOUT_PROPOSE: Duration = Duration::from_millis(600);
const TIMEOUT_STEP: Duration = Duration::from_millis(300);
const POLL: Duration = Duration::from_millis(5);
const PEER_TICK: Duration = Duration::from_millis(60);
/// How often a node re-dials from its address book.
///
/// `run::drive` does this every five seconds and this harness did not do it at
/// all, which is a harness *less* capable than the thing it is testing — and that
/// produces false failures rather than hiding real ones. A peer dropped for any
/// reason (a full outbox under load, a read timeout) was gone for good here,
/// while the real daemon would have reconnected within five seconds. Scaled to
/// this harness's compressed clock.
const DIAL_INTERVAL: Duration = Duration::from_millis(250);
/// How long to let a stopped cluster's threads wind down.
///
/// Longer than [`afrolink_p2p::transport::READ_TIMEOUT`], because that is when a
/// parked peer thread next looks at the shutdown flag. Without the wait, one
/// test's sockets and threads are still competing for the machine while the next
/// test's consensus timeouts are running — which shows up as an intermittent
/// liveness failure that has nothing to do with the protocol, and sends you
/// looking for a bug in the wrong place. It did.
const TEARDOWN: Duration = Duration::from_millis(400);

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn account(seed: u8) -> Address {
    Address::from_public_key(&key(seed).public_key())
}

fn chain() -> ChainId {
    ChainId::new("afrolink-cluster").unwrap()
}

fn validators(n: u8) -> ValidatorSet {
    ValidatorSet::new(
        (1..=n)
            .map(|i| {
                Validator::new(
                    key(i).public_key(),
                    1,
                    CountryCode::new(COUNTRIES[(i as usize - 1) % 4]).unwrap(),
                )
            })
            .collect(),
    )
    .unwrap()
}

fn genesis(n: u8) -> Genesis {
    Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators(n),
        issuers: Vec::new(),
        attestors: Vec::new(),
        council: afrolink_executor::Council::devnet(account(50)),
        params: afrolink_executor::ChainParams::devnet(),
        allocations: vec![Allocation {
            address: account(50),
            denom: Denom::native(),
            amount: Amount::from_afri(1_000_000),
        }],
    }
}

/// A directory that removes itself, so a failing test leaves no databases behind.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("afrolink-cluster-{label}-{unique}-{n}"));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One node: everything `afrolinkd` assembles, minus the argument parsing.
struct ClusterNode {
    seed: u8,
    shared: Arc<SharedNode>,
    transport: Transport,
    store: Arc<ChainStore>,
    /// The state a query would be answered from. Held so the sink has somewhere
    /// to publish; read by [`Cluster::assert_converged`] through the store.
    #[allow(
        dead_code,
        reason = "kept so the node is assembled exactly as the daemon assembles it"
    )]
    published: Arc<Mutex<MemoryStore>>,
    dir: TempDir,
    /// **The daemon's own loop**, not a copy of it.
    ///
    /// This harness used to reimplement `run::drive` — the timers, the round
    /// bookkeeping, `begin_round`, `schedule`. The two drifted, and the drift
    /// presented as defects in the network rather than in the harness: the copy
    /// never re-dialled, so a peer lost under load was gone for the run, and it
    /// dropped the `halted` flag, so a failed store write was silent. Both are
    /// gone by construction now: there is one loop, and this runs it.
    driver: Driver,
}

impl ClusterNode {
    fn start(seed: u8, n: u8, dir: TempDir) -> Self {
        let store = Arc::new(ChainStore::open(dir.0.join("chain.redb")).unwrap());
        let document = genesis(n);
        store.put_genesis(&document).unwrap();
        let (state, tip, _) = store.open_state(GenesisLimits::devnet()).unwrap();

        let node = Node::new(
            chain(),
            key(seed),
            document.validators.clone(),
            state.clone(),
            &tip,
        );
        let shared = Arc::new(SharedNode::new(node));
        let published = Arc::new(Mutex::new(state));
        // Kept, not dropped. `run::drive` treats this as fatal — a node that
        // cannot write its own chain stops rather than voting on a history only
        // it can see. Throwing it away here made the harness *less* capable than
        // the daemon: a failed store write left a node running with a store one
        // block behind, silently, and surfaced later as an unexplained sync
        // stall rather than as the write failure it was.
        let halted = Arc::new(Mutex::new(None));
        let sink = Arc::new(Persist::new(
            Arc::clone(&store),
            Arc::clone(&published),
            Arc::clone(&halted),
        ));

        // A distinct network key per node, and never the consensus key: a node
        // that relays blocks holds no stake, which is the whole reason they are
        // separate files in a real data directory.
        let network_key = key(100u8.wrapping_add(seed));
        let transport = Transport::start(
            chain(),
            SecretKey::from_bytes(&network_key.to_bytes()),
            Arc::clone(&shared),
            Manager::new(
                PeerId::new(network_key.public_key()),
                AddrBook::new(&network_key),
                Limits::default(),
            ),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(Blocks(Arc::clone(&store))),
            sink,
        )
        .unwrap();

        let now = Instant::now();
        Self {
            seed,
            shared,
            transport,
            store,
            published,
            dir,
            driver: Driver::new(
                Timings {
                    poll: POLL,
                    peer_tick: PEER_TICK,
                    dial: DIAL_INTERVAL,
                    block_interval: BLOCK_INTERVAL,
                    timeout_propose: TIMEOUT_PROPOSE,
                    timeout_prevote: TIMEOUT_STEP,
                    timeout_precommit: TIMEOUT_STEP,
                },
                halted,
                now,
            ),
        }
    }

    fn addr(&self) -> PeerAddr {
        PeerAddr::new(self.transport.peer_id(), self.transport.local_addr())
    }

    fn tip(&self) -> Height {
        Height(self.height().0.saturating_sub(1))
    }

    fn height(&self) -> Height {
        self.shared.lock().map_or(Height(0), |n| n.height())
    }

    fn app_hash(&self) -> Hash32 {
        self.shared
            .lock()
            .map_or(Hash32::from_bytes([0; 32]), |n| n.app_hash())
    }

    /// What the *store* holds, which is what a query would be answered from.
    ///
    /// Checked separately from the node's own height on purpose: the two
    /// disagreeing is exactly the defect that eighteen blocks and an empty
    /// database turned out to be.
    fn stored_height(&self) -> Height {
        self.store.height().unwrap_or(Height(0))
    }

    /// One iteration of the daemon's loop, for this node.
    ///
    /// `dial` is false only while a test is holding a deliberate partition open.
    ///
    /// A halt is a panic here, and deliberately: `run::drive` returns it and the
    /// node stops, so a harness that shrugged at it would be testing a node the
    /// daemon would never have kept running.
    fn step(&mut self, dial: bool) {
        match self
            .driver
            .step(Instant::now(), &self.transport, &self.shared, dial)
        {
            Ok(_) => {}
            Err(halted) => panic!("node {} could not write its own chain: {halted}", self.seed),
        }
    }
}

/// A running cluster.
struct Cluster {
    nodes: Vec<ClusterNode>,
    /// Whether nodes reconnect on their own, as they do in `run::drive`.
    ///
    /// Cleared only by [`Cluster::partition`], because a partition that peers
    /// could dial straight through is not a partition.
    autodial: bool,
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for node in &self.nodes {
            node.transport.handle().stop();
        }
        std::thread::sleep(TEARDOWN);
    }
}

impl Cluster {
    /// `n` validators, each dialling every other, all sharing one genesis.
    fn start(n: u8, label: &str) -> Self {
        let nodes: Vec<ClusterNode> = (1..=n)
            .map(|seed| ClusterNode::start(seed, n, TempDir::new(&format!("{label}-{seed}"))))
            .collect();
        let mut cluster = Self {
            nodes,
            autodial: true,
        };
        cluster.connect_all();
        cluster
    }

    /// Every node dials every node after it, so each pair has one connection.
    fn connect_all(&mut self) {
        let addrs: Vec<PeerAddr> = self.nodes.iter().map(ClusterNode::addr).collect();
        for (i, node) in self.nodes.iter().enumerate() {
            for addr in addrs.iter().skip(i + 1) {
                // A refusal here is a duplicate or a group clash, both of which
                // are the manager doing its job; the assertion is on connectivity
                // below, not on any individual dial.
                drop(node.transport.dial(*addr));
            }
        }
        assert!(
            self.wait_until(Duration::from_secs(5), |c| c
                .nodes
                .iter()
                .all(|n| !n.transport.peers().is_empty())),
            "the cluster never formed: peer counts {:?}",
            self.nodes
                .iter()
                .map(|n| n.transport.peers().len())
                .collect::<Vec<_>>()
        );
    }

    /// Cut one node off, and hold it off.
    ///
    /// Both halves matter. Dropping its connections is what a partition looks
    /// like from inside a node; suspending automatic re-dialling is what makes it
    /// *stay* a partition, since every other node holds this one in its address
    /// book and would otherwise reconnect within a quarter of a second.
    fn partition(&mut self, index: usize) {
        self.autodial = false;
        if let Some(node) = self.nodes.get(index) {
            node.transport.disconnect_all();
        }
    }

    /// Put the network back.
    fn heal(&mut self) {
        self.autodial = true;
        self.connect_all();
    }

    /// Drive every node until `done`, or give up.
    fn wait_until(&mut self, patience: Duration, done: impl Fn(&Self) -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < patience {
            if done(self) {
                return true;
            }
            let dial = self.autodial;
            for node in &mut self.nodes {
                node.step(dial);
            }
            std::thread::sleep(POLL);
        }
        done(self)
    }

    fn lowest_tip(&self) -> Height {
        self.nodes
            .iter()
            .map(ClusterNode::tip)
            .min()
            .unwrap_or(Height(0))
    }

    /// The highest height every node has on **disk**.
    ///
    /// Distinct from [`Self::lowest_tip`] on purpose. A node's height advances
    /// inside the consensus lock and the block is persisted after that lock is
    /// released, so there is a real window in which a node has decided a height
    /// its database does not yet hold. Agreement is asserted on this one, because
    /// the database is what a restart and a light client see.
    fn lowest_stored_tip(&self) -> Height {
        self.nodes
            .iter()
            .map(ClusterNode::stored_height)
            .min()
            .unwrap_or(Height(0))
    }

    /// Stop driving the cluster, and let everything already in flight land.
    ///
    /// Nodes only begin rounds when they are stepped, so *not stepping* is how
    /// this harness stops a chain that has no stop switch. What remains is
    /// deliveries already on their way, which finish in milliseconds — and the
    /// database catching up with what was decided, which happens just after the
    /// consensus lock is released.
    ///
    /// Asserting on a live chain instead is how a test measures a moving target:
    /// a node's height can advance between reading it and reading its database,
    /// and the assertion then reports a race as a defect.
    fn quiesce(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            // Peer housekeeping continues: a node that is still catching up needs
            // its block requests to go out. What stops is *beginning rounds*, so
            // the chain stops growing while everything already in motion lands.
            let dial = self.autodial;
            for node in &mut self.nodes {
                node.transport.tick();
                if dial {
                    // A node that is still catching up needs its peers as much as
                    // its ticks: without this, one connection lost under load
                    // leaves it short of the tip for the rest of the run.
                    node.transport.dial_out();
                }
            }
            std::thread::sleep(Duration::from_millis(50));
            for node in &self.nodes {
                assert!(
                    node.driver.halted().is_none(),
                    "node {} could not write its own chain: {}",
                    node.seed,
                    node.driver.halted().unwrap_or_default()
                );
            }
            let durable = self.nodes.iter().all(|n| n.stored_height() == n.tip());
            let level = self
                .nodes
                .first()
                .is_some_and(|first| self.nodes.iter().all(|n| n.tip() == first.tip()));
            if durable && level {
                return;
            }
            // `CLUSTER_DEBUG=1` prints the time series rather than only the
            // final state. Kept because the difference between "a node is slow"
            // and "a node is stuck" is only visible across samples, and both
            // present here as the same timeout.
            if std::env::var("CLUSTER_DEBUG").is_ok() {
                eprintln!(
                    "quiesce: {:?}",
                    self.nodes
                        .iter()
                        .map(|n| (
                            n.seed,
                            n.tip().0,
                            n.stored_height().0,
                            n.transport.peers().len(),
                            n.transport.is_behind(),
                            n.transport.synced(),
                        ))
                        .collect::<Vec<_>>()
                );
            }
            assert!(
                Instant::now() < deadline,
                "the cluster never settled — (node, decided, stored): {:?}",
                self.nodes
                    .iter()
                    .map(|n| (n.seed, n.tip().0, n.stored_height().0))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// **The invariant.** No two nodes hold different blocks at one height.
    ///
    /// Checked against the durable store rather than memory, because the store is
    /// what a restart and a light client see, and because a node whose memory and
    /// database disagree has already failed.
    fn assert_agreement(&self) {
        let common = self.lowest_stored_tip();
        assert!(common.0 > 0, "nothing was committed, so nothing was agreed");
        for h in 1..=common.0 {
            let height = Height(h);
            let mut seen: Option<(Hash32, u8)> = None;
            for node in &self.nodes {
                let Some(block) = node.store.block(height).unwrap() else {
                    panic!("node {} is missing height {h} it claims to hold", node.seed);
                };
                let id = block.header.id();
                match seen {
                    None => seen = Some((id, node.seed)),
                    Some((first, first_seed)) => assert_eq!(
                        first, id,
                        "AGREEMENT VIOLATED at height {h}: node {first_seed} and node {} \
                         committed different blocks",
                        node.seed
                    ),
                }
            }
        }
    }

    /// Every node holds the same state, and its store agrees with its memory.
    fn assert_converged(&self) {
        let first = &self.nodes[0];
        for node in &self.nodes {
            assert_eq!(
                node.height(),
                first.height(),
                "node {} is at a different height from node {}",
                node.seed,
                first.seed
            );
            assert_eq!(
                node.app_hash(),
                first.app_hash(),
                "node {} holds a different state from node {}",
                node.seed,
                first.seed
            );
            assert_eq!(
                node.stored_height(),
                node.tip(),
                "node {}'s database is at {:?} while the node itself is at {:?} — \
                 blocks are being decided and not persisted",
                node.seed,
                node.stored_height(),
                node.tip()
            );
        }
    }

    fn payment(&self, nonce: u64) -> Transaction {
        TxBody {
            chain_id: chain(),
            sender: account(50),
            nonce,
            valid_until: Height(100_000),
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
}

// -- the tests ---------------------------------------------------------------

#[test]
fn four_real_nodes_on_four_sockets_commit_the_same_chain() {
    let _serial = exclusive();
    // The question a testnet asks and neither existing suite could. Four
    // validators, four databases, four loopback sockets, one genesis, real
    // handshakes and real gossip between them.
    let mut cluster = Cluster::start(4, "agreement");

    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| c.lowest_tip() >= Height(5)),
        "the cluster did not reach height 5; tips are {:?}",
        cluster.nodes.iter().map(|n| n.tip().0).collect::<Vec<_>>()
    );

    cluster.quiesce();
    cluster.assert_agreement();
    cluster.assert_converged();
}

#[test]
fn a_payment_submitted_to_one_node_is_committed_by_all_of_them() {
    let _serial = exclusive();
    // End to end over the real network: a client hands a transaction to one node,
    // it is gossiped, included in a block, and every node's *database* can prove
    // where it landed.
    let mut cluster = Cluster::start(4, "payment");
    let payment = cluster.payment(0);
    let id = payment.id();
    cluster.nodes[0]
        .shared
        .lock()
        .unwrap()
        .submit(payment)
        .expect("a valid payment");

    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| c.nodes.iter().all(|n| n
            .store
            .locate(&id)
            .unwrap()
            .is_some())),
        "the payment never reached every node's store"
    );
    cluster.quiesce();
    cluster.assert_agreement();

    // And every node agrees on *where* it landed, which is what a receipt proves.
    let first = cluster.nodes[0].store.locate(&id).unwrap().unwrap();
    for node in &cluster.nodes {
        assert_eq!(
            node.store.locate(&id).unwrap().unwrap(),
            first,
            "node {} put the payment in a different block",
            node.seed
        );
    }
}

#[test]
fn a_partitioned_node_falls_behind_and_catches_up_when_healed() {
    let _serial = exclusive();
    // The property block sync exists for, asserted across the whole stack rather
    // than at the manager. One node is cut off, the others carry on without it,
    // and when it is reconnected it must reach the same state root — not merely
    // the same height.
    let mut cluster = Cluster::start(4, "partition");
    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| c.lowest_tip() >= Height(3)),
        "the cluster never got going"
    );

    // Cut node 3 off. The remaining three are still more than two thirds of four,
    // so the chain must keep committing without it.
    let isolated = 3;
    cluster.partition(isolated);
    let left_at = cluster.nodes[isolated].tip();

    let others_advanced = cluster.wait_until(Duration::from_secs(30), |c| {
        c.nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != isolated)
            .all(|(_, n)| n.tip().0 >= left_at.0 + 4)
    });
    assert!(
        others_advanced,
        "a three-of-four majority stalled when one node was partitioned away"
    );
    assert!(
        cluster.nodes[isolated].tip().0 <= left_at.0 + 1,
        "the partitioned node kept committing without a quorum it could reach"
    );

    // Heal. It has to catch up through block sync, verifying every certificate.
    cluster.heal();
    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| {
            let tip = c.nodes[0].tip();
            c.nodes[isolated].tip() >= tip && tip.0 > 0
        }),
        "the healed node never caught up: it is at {:?}, the others are at {:?}",
        cluster.nodes[isolated].tip(),
        cluster.nodes[0].tip()
    );

    cluster.quiesce();
    cluster.assert_agreement();
    cluster.assert_converged();
}

#[test]
fn a_node_that_joins_late_reaches_the_tip_from_genesis() {
    let _serial = exclusive();
    // A new validator joining a chain that is already running: it holds only
    // genesis, and must arrive at the same state as everybody else by asking for
    // blocks and verifying each one.
    let mut cluster = Cluster::start(4, "latecomer");
    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| c.lowest_tip() >= Height(5)),
        "the cluster never got going"
    );

    // A fifth node on the same genesis. It is not in the validator set — it is a
    // full node, which is the common case and the one nobody tests.
    let late = ClusterNode::start(9, 4, TempDir::new("latecomer-9"));
    let target = cluster.nodes[0].tip();
    for node in &cluster.nodes {
        drop(late.transport.dial(node.addr()));
    }
    cluster.nodes.push(late);

    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| {
            c.nodes.last().is_some_and(|n| n.tip() >= target)
        }),
        "the late node never caught up to {:?}",
        target
    );

    cluster.quiesce();
    let late = cluster.nodes.last().unwrap();
    let reference = &cluster.nodes[0];
    assert_eq!(
        late.store.block(target).unwrap().map(|b| b.header.id()),
        reference
            .store
            .block(target)
            .unwrap()
            .map(|b| b.header.id()),
        "the late node holds a different block at the height it caught up to"
    );
    cluster.assert_agreement();
}

#[test]
fn a_restarted_node_resumes_from_its_database_and_rejoins() {
    let _serial = exclusive();
    // What a real operator does: stop a node, start it again, and expect it back.
    // The store is reopened rather than rebuilt, so this also asserts that what
    // was persisted is enough to continue from — the property that was silently
    // false when eighteen blocks left the database empty.
    let mut cluster = Cluster::start(4, "restart");
    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| c.lowest_tip() >= Height(4)),
        "the cluster never got going"
    );

    let restarted = 2;
    let seed = cluster.nodes[restarted].seed;
    let before = cluster.nodes[restarted].tip();
    assert!(before.0 >= 1, "there must be something to resume from");

    // Stop it: drop the node, which stops its transport and closes its database.
    let dir = {
        let node = cluster.nodes.remove(restarted);
        node.transport.handle().stop();
        node.dir
    };
    // Let its threads go before asking the rest to carry on without it, so what
    // is measured is the protocol rather than the machine.
    std::thread::sleep(TEARDOWN);

    // The remaining three are still a quorum, so the chain must not stall.
    assert!(
        cluster.wait_until(Duration::from_secs(60), |c| c.lowest_tip().0 > before.0 + 2),
        "a three-of-four majority stalled: it was at {:?} when the fourth went \
         down and is at {:?} now",
        before,
        cluster.lowest_tip()
    );

    // Start it again on the same directory.
    let back = ClusterNode::start(seed, 4, dir);
    assert!(
        back.tip() >= before,
        "a restarted node came back at {:?} having committed {:?} — \
         its database did not hold what it had decided",
        back.tip(),
        before
    );
    for node in &cluster.nodes {
        drop(back.transport.dial(node.addr()));
    }
    cluster.nodes.push(back);

    let target = cluster.nodes[0].tip();
    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| c
            .nodes
            .last()
            .is_some_and(|n| n.tip() >= target)),
        "the restarted node never rejoined"
    );
    cluster.quiesce();
    cluster.assert_agreement();
}

#[test]
fn every_node_serves_the_same_answer_from_its_own_database() {
    let _serial = exclusive();
    // A wallet may talk to any node and must get the same chain. This is the
    // property that makes the query layer worth having, and it is checked against
    // the durable store rather than a node's memory, because that is what a
    // served query reads.
    let mut cluster = Cluster::start(4, "queries");
    assert!(
        cluster.wait_until(Duration::from_secs(30), |c| c.lowest_tip() >= Height(4)),
        "the cluster never got going"
    );

    cluster.quiesce();
    let common = cluster.lowest_stored_tip();
    for h in 1..=common.0 {
        let height = Height(h);
        let mut roots = Vec::new();
        for node in &cluster.nodes {
            let block = node.store.block(height).unwrap().expect("a stored block");
            let commit = node.store.commit(height).unwrap().expect("a certificate");
            // Every node's copy of a height must carry a certificate that
            // finalises the block it is stored beside.
            assert_eq!(
                commit.block_id,
                block.header.id(),
                "node {} stored a certificate for a different block at {h}",
                node.seed
            );
            assert_eq!(commit.verify(&chain(), &validators(4)), Ok(()));
            roots.push(block.header.app_hash);
        }
        assert!(
            roots.windows(2).all(|w| w[0] == w[1]),
            "nodes disagree about the state root at height {h}"
        );
    }
}
