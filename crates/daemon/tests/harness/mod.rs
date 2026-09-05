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
#![allow(
    dead_code,
    reason = "a shared harness: each test binary that includes it uses a different part of it"
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
use afrolink_state::{KeyValueStore, MemoryStore, StoreKey};
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
pub fn exclusive() -> std::sync::MutexGuard<'static, ()> {
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
pub const TEARDOWN: Duration = Duration::from_millis(400);

/// How long the whole cluster may make no progress at all before a wait gives up.
///
/// This, not a deadline, is what decides whether a test fails — see
/// [`Cluster::wait_until`]. Long enough to ride out a scheduler that has handed
/// the cores to another test binary for a while; far shorter than the ceiling,
/// so a genuinely stuck chain is reported quickly.
pub const STALL_WINDOW: Duration = Duration::from_secs(20);

/// The absolute ceiling on any wait.
///
/// A backstop against a wedged run rather than a judgement about speed: the
/// stall detector is what actually ends a failing test.
pub const CEILING: Duration = Duration::from_secs(180);

pub fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

pub fn account(seed: u8) -> Address {
    Address::from_public_key(&key(seed).public_key())
}

pub fn chain() -> ChainId {
    ChainId::new("afrolink-cluster").unwrap()
}

pub fn validators(n: u8) -> ValidatorSet {
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

pub fn genesis(n: u8) -> Genesis {
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
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
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
pub struct ClusterNode {
    pub seed: u8,
    pub shared: Arc<SharedNode>,
    pub transport: Transport,
    pub store: Arc<ChainStore>,
    /// The state a query would be answered from. Held so the sink has somewhere
    /// to publish; read by [`Cluster::assert_converged`] through the store.
    #[allow(
        dead_code,
        reason = "kept so the node is assembled exactly as the daemon assembles it"
    )]
    pub published: Arc<Mutex<MemoryStore>>,
    pub dir: TempDir,
    /// Held so a failure can ask what it was handed.
    pub sink: Arc<Persist>,
    /// **The daemon's own loop**, not a copy of it.
    ///
    /// This harness used to reimplement `run::drive` — the timers, the round
    /// bookkeeping, `begin_round`, `schedule`. The two drifted, and the drift
    /// presented as defects in the network rather than in the harness: the copy
    /// never re-dialled, so a peer lost under load was gone for the run, and it
    /// dropped the `halted` flag, so a failed store write was silent. Both are
    /// gone by construction now: there is one loop, and this runs it.
    pub driver: Driver,
}

impl ClusterNode {
    pub fn start(seed: u8, n: u8, dir: TempDir) -> Self {
        Self::start_with(seed, genesis(n), dir)
    }

    /// A node on a genesis the caller chose — how the load tests fund hundreds
    /// of accounts without a second copy of the assembly below.
    pub fn start_with(seed: u8, document: Genesis, dir: TempDir) -> Self {
        let store = Arc::new(ChainStore::open(dir.0.join("chain.redb")).unwrap());
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
            Arc::clone(&sink) as Arc<dyn afrolink_p2p::transport::CommitSink>,
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
            sink: Arc::clone(&sink),
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

    pub fn addr(&self) -> PeerAddr {
        PeerAddr::new(self.transport.peer_id(), self.transport.local_addr())
    }

    pub fn tip(&self) -> Height {
        Height(self.height().0.saturating_sub(1))
    }

    pub fn height(&self) -> Height {
        self.shared.lock().map_or(Height(0), |n| n.height())
    }

    pub fn app_hash(&self) -> Hash32 {
        self.shared
            .lock()
            .map_or(Hash32::from_bytes([0; 32]), |n| n.app_hash())
    }

    /// What the *store* holds, which is what a query would be answered from.
    ///
    /// Checked separately from the node's own height on purpose: the two
    /// disagreeing is exactly the defect that eighteen blocks and an empty
    /// database turned out to be.
    pub fn stored_height(&self) -> Height {
        self.store.height().unwrap_or(Height(0))
    }

    /// One iteration of the daemon's loop, for this node.
    ///
    /// `dial` is false only while a test is holding a deliberate partition open.
    ///
    /// A halt is a panic here, and deliberately: `run::drive` returns it and the
    /// node stops, so a harness that shrugged at it would be testing a node the
    /// daemon would never have kept running.
    pub fn step(&mut self, dial: bool) {
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
pub struct Cluster {
    pub nodes: Vec<ClusterNode>,
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
    pub fn start(n: u8, label: &str) -> Self {
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
    pub fn connect_all(&mut self) {
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
            self.wait_until(CEILING, |c| c
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
    pub fn partition(&mut self, index: usize) {
        self.autodial = false;
        if let Some(node) = self.nodes.get(index) {
            node.transport.disconnect_all();
        }
    }

    /// Put the network back.
    pub fn heal(&mut self) {
        self.autodial = true;
        self.connect_all();
    }

    /// Drive every node until `done`, or give up.
    /// Drive every node until `done`, giving up only when the cluster **stops
    /// making progress**.
    ///
    /// # Why this is not a deadline
    ///
    /// It was `while start.elapsed() < patience`, and that made every test here
    /// an assertion about *rate*: "commit four more heights within thirty
    /// seconds". The property under test is nothing of the sort — it is "a
    /// three-of-four majority keeps committing without the fourth" — and the
    /// rate is set by whatever else happens to be running. Under a full
    /// `cargo test --workspace`, twenty other test binaries compete for the same
    /// cores, the cluster suite slows by three to four times, and a healthy
    /// cluster misses a wall-clock deadline it would have made easily on its own.
    ///
    /// That produced exactly the failure mode a test must not have: a *different*
    /// cluster test failing on each run, on an unmodified tree, telling us
    /// nothing about the change in front of us. Verified rather than assumed —
    /// the same suite fails the same way with the state-tree work stashed.
    ///
    /// So the give-up condition is a **stall**: no node anywhere has advanced a
    /// height for [`STALL_WINDOW`]. A slow machine keeps waiting; a genuinely
    /// stuck chain fails, and fails *sooner* than a long deadline would. The
    /// absolute ceiling remains only so a wedged run cannot hang forever.
    pub fn wait_until(&mut self, ceiling: Duration, done: impl Fn(&Self) -> bool) -> bool {
        let start = Instant::now();
        let mut best = self.highest_tip();
        let mut last_progress = Instant::now();
        while start.elapsed() < ceiling {
            if done(self) {
                return true;
            }
            let dial = self.autodial;
            for node in &mut self.nodes {
                node.step(dial);
            }
            let now = self.highest_tip();
            if now > best {
                best = now;
                last_progress = Instant::now();
            } else if last_progress.elapsed() > STALL_WINDOW {
                // Nothing anywhere has committed for the whole window. Waiting
                // longer will not help, and saying so now gives a clearer
                // failure than a deadline that expires much later.
                return done(self);
            }
            std::thread::sleep(POLL);
        }
        done(self)
    }

    /// Why each node is or is not asking for the blocks it is missing.
    ///
    /// Only ever called from a failure message: see [`Manager::sync_snapshot`]
    /// for why this is pulled on failure rather than logged as it goes.
    pub fn why_stuck(&self) -> String {
        self.nodes
            .iter()
            .map(|n| format!("  node {}: {}", n.seed, n.transport.sync_snapshot()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The furthest any node has got. The progress signal for [`Self::wait_until`].
    pub fn highest_tip(&self) -> Height {
        self.nodes
            .iter()
            .map(ClusterNode::tip)
            .max()
            .unwrap_or(Height(0))
    }

    pub fn lowest_tip(&self) -> Height {
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
    pub fn lowest_stored_tip(&self) -> Height {
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
    pub fn quiesce(&mut self) {
        // Same reasoning as `wait_until`: settling is bounded by progress, not
        // by the clock. A node still pulling blocks under a loaded machine is
        // working, and cutting it off at a fixed deadline reports that as a
        // defect in block sync.
        let ceiling = Instant::now().checked_add(CEILING);
        let mut best = self.lowest_stored_tip();
        let mut last_progress = Instant::now();
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
            let now = self.lowest_stored_tip();
            if now > best {
                best = now;
                last_progress = Instant::now();
            }
            assert!(
                last_progress.elapsed() <= STALL_WINDOW
                    && ceiling.is_some_and(|at| Instant::now() < at),
                "the cluster never settled — (node, decided, stored): {:?}\n{}",
                self.nodes
                    .iter()
                    .map(|n| (n.seed, n.tip().0, n.stored_height().0))
                    .collect::<Vec<_>>(),
                self.why_stuck()
            );
        }
    }

    /// **The invariant.** No two nodes hold different blocks at one height.
    ///
    /// Checked against the durable store rather than memory, because the store is
    /// what a restart and a light client see, and because a node whose memory and
    /// database disagree has already failed.
    pub fn assert_agreement(&self) {
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
    pub fn assert_converged(&self) {
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

    pub fn payment(&self, nonce: u64) -> Transaction {
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

// -- many accounts, for the load tests ---------------------------------------

/// What every load-test sender starts with.
pub const ENDOWMENT: Amount = Amount::from_units(1_000_000_000_000);
/// The fee each payment pays, matching [`Cluster::transfer`].
pub const FEE: Amount = Amount::from_units(1_000);
/// Who every load-test payment is sent to.
///
/// One recipient on purpose: the expected total is then arithmetic rather than
/// bookkeeping, so a single lost payment shows up as an exact shortfall.
pub const RECIPIENT: u8 = 60;

/// A distinct signing key per load-test sender.
///
/// Not [`key`], because that takes a `u8` and the sustained test wants hundreds
/// of accounts — and because senders must not collide with the validator seeds
/// or with the faucet, or two tests would share a nonce sequence.
pub fn sender_key(i: usize) -> SecretKey {
    let mut seed = [0u8; 32];
    seed[0] = 0xA1;
    seed[1..9].copy_from_slice(&(i as u64).to_be_bytes());
    SecretKey::from_bytes(&seed)
}

/// The address belonging to load-test sender `i`.
pub fn sender(i: usize) -> Address {
    Address::from_public_key(&sender_key(i).public_key())
}

impl Cluster {
    /// A cluster whose genesis funds `senders` distinct accounts.
    ///
    /// The point of the load tests: a state tree with real breadth in it, so the
    /// cost of a commit is measured against a tree deep enough for its
    /// complexity class to matter.
    pub fn funded(n: u8, label: &str, senders: usize) -> Self {
        let document = funded_genesis(n, senders);
        let nodes: Vec<ClusterNode> = (1..=n)
            .map(|seed| {
                ClusterNode::start_with(
                    seed,
                    document.clone(),
                    TempDir::new(&format!("{label}-{seed}")),
                )
            })
            .collect();
        let mut cluster = Self {
            nodes,
            autodial: true,
        };
        cluster.connect_all();
        cluster
    }

    /// How many nodes are in this cluster.
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// A payment from load-test sender `i` to [`RECIPIENT`].
    pub fn transfer(&self, i: usize, nonce: u64, amount: Amount) -> Transaction {
        TxBody {
            chain_id: chain(),
            sender: sender(i),
            nonce,
            valid_until: Height(100_000),
            fee: Fee::new(FEE, Denom::native()),
            messages: vec![Message::Transfer {
                to: account(RECIPIENT),
                denom: Denom::native(),
                amount,
                reference: None,
            }],
            memo: String::new(),
        }
        .sign(&sender_key(i))
    }

    /// What the **ledger** says `who` holds, read from the durable store.
    ///
    /// Not from `published`, which is a *cache* of the last committed state kept
    /// for the query server. The two are meant to agree and
    /// [`Self::published_vs_decided`] shows they sometimes do not — see
    /// [10 §18](../../../docs/10-network-hardening.md). That is a real defect
    /// about what queries return, and it is a different question from "did the
    /// ledger move the money", which is what the load tests are asking. Asserting
    /// the second through the first conflated them.
    pub fn ledger_balance(&self, who: &Address) -> u128 {
        let key = StoreKey::balance(who, &Denom::native());
        // `open_state` rather than `tip_app_hash` + `load_state`: before the
        // first block there is no tip, and the earlier version of this helper
        // answered 0 for every account — which made a test that compares a
        // balance before and after conclude that money had appeared from nowhere.
        // This is the path the daemon itself starts from, so it is defined at
        // genesis as well as after it.
        let store = &self.nodes[0].store;
        let Ok((state, _, _)) = store.open_state(GenesisLimits::devnet()) else {
            return 0;
        };
        state
            .get(&key)
            .and_then(|raw| afrolink_primitives::codec::decode_exact::<Amount>(raw.as_slice()).ok())
            .unwrap_or(Amount::ZERO)
            .units()
    }

    /// What the committed state says `who` holds, in the smallest unit.
    ///
    /// Read from the first node's **published** state, which is what a query
    /// would be answered from — not from consensus memory.
    pub fn balance(&self, who: &Address) -> u128 {
        let key = StoreKey::balance(who, &Denom::native());
        self.nodes[0]
            .published
            .lock()
            .unwrap()
            .get(&key)
            .and_then(|raw| afrolink_primitives::codec::decode_exact::<Amount>(raw.as_slice()).ok())
            .unwrap_or(Amount::ZERO)
            .units()
    }

    /// What node `i`'s published state says `who` holds.
    pub fn balance_on(&self, i: usize, who: &Address) -> u128 {
        let key = StoreKey::balance(who, &Denom::native());
        self.nodes[i]
            .published
            .lock()
            .unwrap()
            .get(&key)
            .and_then(|raw| afrolink_primitives::codec::decode_exact::<Amount>(raw.as_slice()).ok())
            .unwrap_or(Amount::ZERO)
            .units()
    }

    /// Whether each node's *published* state matches the state it decided.
    ///
    /// A query is answered from the published view, so these two disagreeing is
    /// a node telling wallets something its own consensus does not believe. Not
    /// covered by `assert_agreement`, which compares nodes with each other: four
    /// nodes can agree perfectly and all four publish something stale.
    pub fn published_vs_decided(&self) -> String {
        self.nodes
            .iter()
            .map(|n| {
                let published = n.published.lock().unwrap().root();
                let decided = n.app_hash();
                let stored_tip = n
                    .store
                    .tip_app_hash()
                    .ok()
                    .flatten()
                    .map(|h| h.to_hex()[..12].to_owned())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "  node {}: node-state {} published {} stored-tip {} h={} stored={} halted={:?} {}",
                    n.seed,
                    &decided.to_hex()[..12],
                    &published.to_hex()[..12],
                    stored_tip,
                    n.tip().0,
                    n.stored_height().0,
                    n.driver.halted(),
                    if published == decided {
                        String::new()
                    } else {
                        format!("<-- STALE; sink saw [{}]", n.sink.recent())
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// What the chain did with each of `ids`, for a failure message.
    ///
    /// Pulled on failure, never logged as it goes — the same rule as
    /// `Manager::sync_snapshot`. "Committed" and "succeeded" are different
    /// questions, and a balance that is wrong cannot distinguish them on its own:
    /// a transaction can be in a block, findable by id, and still have been
    /// refused by the executor.
    pub fn outcomes_of(&self, ids: &[Hash32]) -> String {
        let mut codes: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut missing = 0usize;
        for id in ids {
            match self.nodes[0].store.locate(id).ok().flatten() {
                None => missing = missing.saturating_add(1),
                Some(found) => {
                    let receipt = self.nodes[0]
                        .store
                        .receipts(found.0)
                        .ok()
                        .flatten()
                        .unwrap_or_default()
                        .into_iter()
                        .find(|r| r.tx_id == *id);
                    let label = receipt
                        .map_or_else(|| "no receipt".to_owned(), |r| format!("{:?}", r.code));
                    *codes.entry(label).or_default() = codes.get(&label).copied().unwrap_or(0) + 1;
                }
            }
        }
        format!("not in any block: {missing}; receipts: {codes:?}")
    }

    /// How many entries the state tree holds. A proxy for how hard it is working.
    pub fn state_len(&self) -> usize {
        self.nodes[0].published.lock().unwrap().len()
    }

    /// A light client must still be able to prove this balance.
    ///
    /// Load must not break the proof path. A busy tree is a deeper tree, and a
    /// deeper tree is where an off-by-one in sibling ordering would show — a
    /// class of bug that leaves agreement intact while making every wallet
    /// unable to verify what it is told.
    pub fn assert_balance_provable(&self, who: &Address) {
        let key = StoreKey::balance(who, &Denom::native());
        let state = self.nodes[0].published.lock().unwrap();
        let root = state.root();
        let proof = state.tree().prove(key.as_bytes());
        let value = state.get(&key);
        assert!(
            proof.verify(root, key.as_bytes(), value.as_deref()),
            "a balance could not be proved against the state root under load"
        );
    }
}

/// Genesis funding `senders` load-test accounts alongside the usual faucet.
fn funded_genesis(n: u8, senders: usize) -> Genesis {
    let mut document = genesis(n);
    document
        .allocations
        .extend((0..senders).map(|i| Allocation {
            address: sender(i),
            denom: Denom::native(),
            amount: ENDOWMENT,
        }));
    document
}
