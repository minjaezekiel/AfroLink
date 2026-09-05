//! Sockets and threads, and nothing that decides anything.
//!
//! # The model, and why it is the same one `crates/http` uses
//!
//! Two blocking threads per peer — one reading, one writing — over a cloned
//! `TcpStream`. No async runtime, no executor, no dependency beyond `std`.
//!
//! A validator holds tens of peers, not tens of thousands of idle sockets. The
//! expensive work on this path is verifying signatures and re-executing a block,
//! which is CPU; thread-per-connection is the wrong model for a C10k problem and
//! an entirely reasonable one for forty peers. What it buys is that
//! `crates/node` stays synchronous — which is what makes the deterministic
//! Byzantine simulator possible at all — and that a payments network's
//! dependency tree does not grow by two orders of magnitude to open a socket.
//!
//! # Everything that decides anything is somewhere else
//!
//! This module opens connections, moves bytes and drops peers when told to. Whom
//! to dial, what to relay, whom to trust and when to ban all live in
//! [`crate::manager`], which has no sockets in it. That is the same seam as
//! `respond` in `crates/http`: the interesting rules are unit-tested without
//! binding a port, and the layer that binds ports has almost no logic left to be
//! wrong about.
//!
//! # Back pressure
//!
//! Each peer's outbox is a bounded channel. A peer that stops reading fills its
//! own queue and is then **dropped**, rather than being allowed to grow this
//! node's memory until it dies. Slowness is indistinguishable from an attack
//! here, and treating them the same is the safe direction: a genuinely slow peer
//! reconnects, whereas a node out of memory does not.
//!
//! # Shutdown
//!
//! [`Handle::stop`] sets a flag and connects to the listener once to wake the
//! blocked `accept`, the same trick `crates/http` uses. Peer threads notice the
//! flag on their next read timeout.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use afrolink_consensus::Commit;
use afrolink_executor::{Block, TxReceipt};
use afrolink_node::{Action, Event, SharedNode};
use afrolink_primitives::{ChainId, Height};
use afrolink_state::MemoryStore;

use crate::handshake::{Handshake, HandshakeError};
use crate::manager::{Directive, Manager, Refusal};
use crate::peer::{Misbehaviour, PeerAddr, PeerId};
use crate::secret::{Opener, Sealer, Session};
use crate::sync::{BlockSource, SyncBlock};
use crate::wire::{FrameError, PeerMessage, read_frame, write_frame};

/// Where finalised blocks go once a height is settled.
///
/// The transport is the only place that sees *both* ways a height becomes final —
/// decided here, or learned from a peer — so it is the only place that can
/// persist them uniformly. A trait rather than a store, for the same reason
/// [`BlockSource`] is one: this crate has no business knowing what a database is.
///
/// Receipts travel with the block because the header commits to their root, and
/// recovering them later means re-executing the block. So does the state, and for
/// a sharper reason: it is read while the node lock is still held, so what the
/// sink is given is the state *this* block produced. An implementation that went
/// back to the node for it could be handed the state after the following block
/// instead, and would then persist a root that its stored tip does not claim.
pub trait CommitSink: Send + Sync {
    /// Record a finalised block. Called once per height, in height order.
    fn committed(
        &self,
        block: &Block,
        commit: &Commit,
        receipts: &[TxReceipt],
        state: &MemoryStore,
    );
}

/// A sink that keeps nothing.
///
/// For a node with no durable store — a test, or a validator that has been told
/// to hold history in memory only. Named rather than an `Option` so that
/// discarding history is something somebody chose.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardCommits;

impl CommitSink for DiscardCommits {
    fn committed(
        &self,
        _block: &Block,
        _commit: &Commit,
        _receipts: &[TxReceipt],
        _state: &MemoryStore,
    ) {
    }
}

/// Messages queued for one peer before it is considered too slow to keep.
pub const OUTBOX_DEPTH: usize = 256;

/// How long a read may block before the thread re-checks the shutdown flag.
pub const READ_TIMEOUT: Duration = Duration::from_millis(250);

/// How long a handshake may take before the peer is dropped.
///
/// A connection that opens and then says nothing costs a thread and a file
/// descriptor. Without a deadline, opening thousands of them is a denial of
/// service that never sends a single byte.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the transport could not start or connect.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The socket failed.
    #[error("io: {0}")]
    Io(String),
    /// The handshake failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// The peer manager refused the connection.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// The node lock was poisoned by a previous panic.
    #[error("node lock is poisoned")]
    Poisoned,
}

impl From<std::io::Error> for TransportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Everything the peer threads share.
struct Shared {
    chain_id: ChainId,
    key: afrolink_crypto::SecretKey,
    ours: PeerId,
    node: Arc<SharedNode>,
    manager: Mutex<Manager>,
    outboxes: Mutex<BTreeMap<PeerId, SyncSender<PeerMessage>>>,
    /// A handle on each peer's socket, purely so it can be closed.
    ///
    /// Dropping a peer used to mean forgetting it: its outbox went and its
    /// manager entry went, and its **socket stayed open** with a thread parked on
    /// it. A banned peer kept a file descriptor and a thread for as long as it
    /// cared to hold them, kept sending frames this node then paid to decrypt and
    /// discard, and — worse — never learned it had been dropped, so neither side
    /// would ever re-establish. A disconnect that the other end cannot observe is
    /// not a disconnect.
    streams: Mutex<BTreeMap<PeerId, TcpStream>>,
    running: AtomicBool,
    /// Frames delivered to the node. Observable so a test can wait on progress
    /// rather than on a sleep.
    delivered: AtomicU64,
    /// Where committed blocks are read from, to serve peers that fell behind.
    blocks: Arc<dyn BlockSource>,
    /// Where committed blocks are written, however this node reached them.
    sink: Arc<dyn CommitSink>,
    /// Heights applied from peers rather than decided here. Observable so a test
    /// can wait on catching up rather than on a sleep.
    synced: AtomicU64,
    /// When peer housekeeping last ran, so rate limits are denominated in real
    /// time rather than in however often the caller happens to call.
    last_tick: Mutex<std::time::Instant>,
    /// Where this node tells peers it can be dialled, if anywhere.
    ///
    /// See [`Transport::start`] for how it is chosen and why it is optional.
    advertise: Option<SocketAddr>,
}

impl Shared {
    /// Send to one peer, dropping it if its outbox is full.
    fn send_to(&self, peer: &PeerId, message: PeerMessage) {
        let Ok(outboxes) = self.outboxes.lock() else {
            return;
        };
        let Some(tx) = outboxes.get(peer) else {
            return;
        };
        if tx.try_send(message).is_err() {
            // Full or closed. Either way this peer is not keeping up, and the
            // safe direction is to drop it: a slow peer reconnects, a node out
            // of memory does not.
            drop(outboxes);
            self.drop_peer(peer);
        }
    }

    /// Send to everyone except one.
    fn relay(&self, message: &PeerMessage, except: Option<PeerId>) {
        let targets: Vec<PeerId> = {
            let Ok(outboxes) = self.outboxes.lock() else {
                return;
            };
            outboxes
                .keys()
                .filter(|id| Some(**id) != except)
                .copied()
                .collect()
        };
        for target in targets {
            self.send_to(&target, message.clone());
        }
    }

    /// Record a misbehaviour against a peer and act on whatever that decides.
    fn punish(&self, peer: PeerId, what: Misbehaviour) {
        let directives = {
            let Ok(mut manager) = self.manager.lock() else {
                return;
            };
            manager.penalise(peer, what)
        };
        self.apply(directives);
    }

    fn drop_peer(&self, peer: &PeerId) {
        if let Ok(mut outboxes) = self.outboxes.lock() {
            outboxes.remove(peer);
        }
        // Close the socket, so the peer thread unblocks and the *other end*
        // finds out. Without this a dropped peer is only dropped locally: the
        // remote still believes it is connected and will refuse a fresh dial as a
        // duplicate, which makes a partition permanent rather than temporary.
        if let Ok(mut streams) = self.streams.lock()
            && let Some(stream) = streams.remove(peer)
        {
            drop(stream.shutdown(std::net::Shutdown::Both));
        }
        if let Ok(mut manager) = self.manager.lock() {
            manager.on_disconnect(peer);
        }
    }

    /// Carry out what the manager decided.
    fn apply(&self, directives: Vec<Directive>) {
        for directive in directives {
            match directive {
                Directive::Deliver(event) => self.deliver(*event),
                Directive::Send(peer, message) => self.send_to(&peer, *message),
                Directive::Relay(message, from) => self.relay(&message, Some(from)),
                Directive::Broadcast(message) => self.relay(&message, None),
                Directive::ServeBlock(peer, height) => {
                    // Read from the durable store, never from the running node's
                    // memory: a node serving from memory can only help peers who
                    // fell behind while it happened to be up, and would put every
                    // sync request behind the consensus lock.
                    let answer = self.blocks.block_at(height).map_or_else(
                        || PeerMessage::NoBlock(height),
                        |sync| PeerMessage::Block(Box::new(sync)),
                    );
                    self.send_to(&peer, answer);
                }
                Directive::ApplyBlock(from, sync) => self.apply_block(from, *sync),
                Directive::Disconnect(peer, _why) => self.drop_peer(&peer),
            }
        }
    }

    /// Hand a peer's message to consensus, and put whatever it decides on the wire.
    fn deliver(&self, event: Event) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
        drop(self.feed(event));
    }

    /// Hand an event to consensus and carry out everything that follows.
    fn feed(&self, event: Event) -> Vec<Action> {
        self.drive(|node| node.handle(event))
    }

    /// **The one path from a node's actions to their effects.**
    ///
    /// Every way of reaching the consensus driver — a peer's message, a synced
    /// block, a round beginning, a timer firing — comes through here, and here is
    /// the only place that persists what committed and gossips what did not.
    ///
    /// It is a single function on purpose. When a node's own votes were counted
    /// by the transport, commits could only happen on the *delivery* path, so
    /// hanging persistence off that path worked. Moving the vote into the state
    /// machine moved where a commit happens — a lone validator now commits inside
    /// `start_round` — and a caller driving the node directly persisted nothing:
    /// the chain ran, produced eighteen blocks, and its store stayed empty. Two
    /// entry points meant one of them could be forgotten. Now there is one.
    fn drive(&self, act: impl FnOnce(&mut afrolink_node::Node) -> Vec<Action>) -> Vec<Action> {
        let Some(mut node) = self.node.lock() else {
            return Vec::new();
        };
        let actions = act(&mut node);
        let receipts = node.last_receipts().to_vec();
        let height = node.height();
        let state = node.store().clone();
        // The lock is released before anything is written, so a slow socket
        // never holds up consensus. It is the same rule `SharedNode` states for
        // the submit path: the lock covers a mempool insertion, never I/O.
        drop(node);
        self.after_commit(&actions, &receipts, &state, height);
        // Relayed to everyone, including whoever sent the original. A node only
        // emits a broadcast action for something it *newly* accepted, so the
        // sender receiving it back costs one frame and is deduplicated there —
        // and suppressing it here would need the node to tell us where the
        // event came from, which is knowledge consensus has no reason to carry.
        self.broadcast(actions.clone(), None);
        actions
    }

    /// Apply a block a peer sent, and tell the manager where that left us.
    ///
    /// The manager advanced its own height optimistically when it handed this
    /// over. Reporting the node's *actual* height afterwards — whether the apply
    /// worked or not — is what makes that optimism safe: a refused block leaves
    /// the manager pointing at the height it stumbled on, and the next tick asks
    /// for it again, from somebody else.
    fn apply_block(&self, from: PeerId, sync: SyncBlock) {
        let Some(mut node) = self.node.lock() else {
            return;
        };
        let outcome = node.apply_synced(sync.block, sync.commit);
        let receipts = node.last_receipts().to_vec();
        let height = node.height();
        let state = node.store().clone();
        drop(node);

        match outcome {
            Ok(actions) => {
                self.synced.fetch_add(1, Ordering::Relaxed);
                self.after_commit(&actions, &receipts, &state, height);
            }
            Err(why) => {
                // Refused. Nothing was written and nothing is broadcast: a block
                // this node could not verify is not one it should be spreading.
                self.set_manager_height(height);
                // A certificate that does not verify is not a mistake anyone makes
                // by accident — it is a forgery attempt, and one is enough. The
                // rest are survivable disagreements: a peer on a fork sends real
                // blocks that do not fit here, and should cost its reputation
                // without being cut off on the first one.
                let what = match why {
                    afrolink_node::SyncError::BadCommit(_) => Misbehaviour::Unforgivable,
                    _ => Misbehaviour::BadBlock,
                };
                self.punish(from, what);
            }
        }
    }

    /// Persist what was finalised, and tell the manager the new height.
    fn after_commit(
        &self,
        actions: &[Action],
        receipts: &[TxReceipt],
        state: &MemoryStore,
        height: Height,
    ) {
        for action in actions {
            if let Action::Committed(block, commit) = action {
                self.sink.committed(block, commit, receipts, state);
            }
        }
        self.set_manager_height(height);
    }

    fn set_manager_height(&self, height: Height) {
        if let Ok(mut manager) = self.manager.lock() {
            manager.set_height(height);
        }
    }

    /// Put a node's outbound actions on the wire.
    ///
    /// **Send only.** A node counts its own vote inside `Node::emit_vote`, the
    /// way CometBFT's `signAddVote` does — signed, added to its own vote set
    /// through the same path a peer's vote takes, and only then gossiped. Gossip
    /// is downstream of consensus state, never the mechanism by which it changes.
    ///
    /// This transport used to loop a node's own votes back through the state
    /// machine to make quorum work, which meant a consensus invariant depended on
    /// a transport being present. It worked, and it left the trap set for the next
    /// caller that drove `Node` without one.
    fn broadcast(&self, actions: Vec<Action>, except: Option<PeerId>) {
        for action in actions {
            let message = match action {
                Action::BroadcastProposal(p) => PeerMessage::Proposal(p),
                Action::BroadcastVote(v) => PeerMessage::Vote(v),
                Action::BroadcastTransaction(t) => PeerMessage::Transaction(t),
                // Committing and scheduling a timeout are the node's own
                // business. Neither is something a peer is told about: a peer
                // learns a block committed by seeing the precommits, which it
                // already has — or, if it was not there to see them, by asking
                // for the block through the sync path.
                // The node's own business, and the driver's. A peer learns a
                // block committed by seeing the precommits, and nobody else has
                // any use for this node's round timers.
                Action::Committed(_, _) | Action::ScheduleTimeout(_, _) | Action::StartRound(_) => {
                    continue;
                }
            };
            self.relay(&message, except);
        }
    }
}

/// A running peer-to-peer network.
pub struct Transport {
    shared: Arc<Shared>,
    /// The address actually bound, which matters when the caller asked for port
    /// zero and let the operating system choose.
    local: SocketAddr,
}

/// A handle that stops a running transport.
pub struct Handle {
    shared: Arc<Shared>,
    local: SocketAddr,
}

impl Handle {
    /// Stop accepting, and let the peer threads wind down.
    pub fn stop(&self) {
        self.shared.running.store(false, Ordering::SeqCst);
        // One loopback connection to wake the blocked `accept`. Polling with a
        // timeout would cost either idle CPU or accept latency; this costs one
        // connection, once.
        drop(TcpStream::connect(self.local));
    }
}

/// Where a node listens, and where it tells peers to find it.
///
/// One value rather than two parameters because the second only makes sense
/// against the first: "advertise nothing" and "advertise something other than
/// what I bound" are both answers to a question the bind address raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// The socket to bind.
    pub listen: SocketAddr,
    /// What to tell peers, if that differs from the bound address.
    ///
    /// `None` means "work it out": the bound address if it names one
    /// interface, and nothing at all if it does not. See [`Binding::of`].
    pub advertise: Option<SocketAddr>,
}

impl Binding {
    /// Listen here, and let the node work out what to advertise.
    #[must_use]
    pub const fn of(listen: SocketAddr) -> Self {
        Self {
            listen,
            advertise: None,
        }
    }

    /// Listen here, and tell peers to use `advertise` instead.
    ///
    /// For a node behind NAT, a load balancer or a port mapping — the cases
    /// where no amount of inspecting the socket finds the right answer.
    #[must_use]
    pub const fn advertising(listen: SocketAddr, advertise: Option<SocketAddr>) -> Self {
        Self { listen, advertise }
    }
}

impl Transport {
    /// Bind a listener and start accepting peers.
    ///
    /// # Errors
    /// [`TransportError::Io`] if the address cannot be bound.
    pub fn start(
        chain_id: ChainId,
        key: afrolink_crypto::SecretKey,
        node: Arc<SharedNode>,
        mut manager: Manager,
        binding: Binding,
        blocks: Arc<dyn BlockSource>,
        sink: Arc<dyn CommitSink>,
    ) -> Result<Self, TransportError> {
        let Binding { listen, advertise } = binding;
        let listener = TcpListener::bind(listen)?;
        let local = listener.local_addr()?;
        // What this node tells peers about itself, in order of authority:
        //
        // 1. What the operator configured. A node behind NAT or a load balancer
        //    is the only one who knows its own public address, and no amount of
        //    inspecting the socket will find it.
        // 2. Otherwise the bound address, which is right for a node listening on
        //    one concrete interface and for every devnet.
        // 3. Nothing, if that address is unspecified — `0.0.0.0` means "every
        //    interface" to a listener and nothing to a dialler, and advertising
        //    it would put an unreachable entry in every peer's book.
        //
        // CometBFT's `external_address` and Bitcoin's `-externalip` are the same
        // knob for the same reason.
        let advertise = advertise
            .or(Some(local))
            .filter(|a| !a.ip().is_unspecified());
        let ours = PeerId::new(key.public_key());
        // The manager's idea of where the chain is comes from the node, once,
        // here — and is corrected after every commit. A manager that started at
        // genesis while the node was at height nine thousand would ask its peers
        // for nine thousand blocks it already has.
        if let Some(node) = node.lock() {
            manager.set_height(node.height());
        }
        let shared = Arc::new(Shared {
            chain_id,
            key,
            ours,
            node,
            manager: Mutex::new(manager),
            outboxes: Mutex::new(BTreeMap::new()),
            streams: Mutex::new(BTreeMap::new()),
            running: AtomicBool::new(true),
            delivered: AtomicU64::new(0),
            blocks,
            sink,
            synced: AtomicU64::new(0),
            last_tick: Mutex::new(std::time::Instant::now()),
            advertise,
        });

        let accepting = Arc::clone(&shared);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if !accepting.running.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let shared = Arc::clone(&accepting);
                std::thread::spawn(move || {
                    // An inbound peer is whoever answers; the handshake decides
                    // who they are and the manager decides whether to keep them.
                    drop(establish(&shared, stream, None));
                });
            }
        });

        Ok(Self { shared, local })
    }

    /// The address this transport is listening on.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// This node's network identity.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.shared.ours
    }

    /// A handle that can stop this transport.
    #[must_use]
    pub fn handle(&self) -> Handle {
        Handle {
            shared: Arc::clone(&self.shared),
            local: self.local,
        }
    }

    /// How many peer messages have reached the consensus engine.
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.shared.delivered.load(Ordering::Relaxed)
    }

    /// How many blocks this node applied from peers rather than deciding itself.
    #[must_use]
    pub fn synced(&self) -> u64 {
        self.shared.synced.load(Ordering::Relaxed)
    }

    /// Whether some peer claims a height this node does not have.
    ///
    /// What a node consults before it bothers proposing: a validator that is
    /// behind should be catching up, not offering blocks built on a state the
    /// rest of the network has already moved past.
    #[must_use]
    pub fn is_behind(&self) -> bool {
        self.shared
            .manager
            .lock()
            .is_ok_and(|manager| manager.is_behind())
    }

    /// Why this node is or is not asking anyone for a block.
    ///
    /// For failure messages only — see [`Manager::sync_snapshot`].
    #[must_use]
    pub fn sync_snapshot(&self) -> String {
        self.shared.manager.lock().map_or_else(
            |_| "manager lock poisoned".to_owned(),
            |m| m.sync_snapshot(),
        )
    }

    /// Who is connected right now.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerId> {
        self.shared
            .manager
            .lock()
            .map(|m| m.peers())
            .unwrap_or_default()
    }

    /// The outbound peers worth writing down for the next run.
    ///
    /// Read at shutdown. See [`Manager::anchors`] for why there are only two of
    /// them and why they are dialled first.
    #[must_use]
    pub fn anchors(&self) -> Vec<PeerAddr> {
        self.shared
            .manager
            .lock()
            .map(|m| m.anchors())
            .unwrap_or_default()
    }

    /// Where this node believes `peer` can be reached.
    ///
    /// See [`Manager::learned`]. An inbound peer appears here only because it
    /// advertised itself in the handshake, which is the whole of §7.
    #[must_use]
    pub fn learned(&self, peer: &PeerId) -> Option<PeerAddr> {
        self.shared
            .manager
            .lock()
            .ok()
            .and_then(|m| m.learned(peer))
    }

    /// Drop every peer, keeping the listener open.
    ///
    /// What a partition looks like from inside one node: connections go away, the
    /// node keeps running, and it will re-dial from its address book when asked.
    /// An operator uses it to shed a bad peer set without a restart; a test uses
    /// it to cut a node off from a network that carries on without it, which is
    /// the only way to ask whether it can catch up afterwards.
    pub fn disconnect_all(&self) {
        for peer in self.peers() {
            self.shared.drop_peer(&peer);
        }
    }

    /// Connect to a peer, refusing anyone but the identity named.
    ///
    /// # Errors
    /// Returns the first [`TransportError`] encountered.
    pub fn dial(&self, addr: PeerAddr) -> Result<(), TransportError> {
        let stream = TcpStream::connect(addr.addr)?;
        // Synchronous through the handshake and the manager's decision, so the
        // caller learns *why* a dial failed, and asynchronous from there on: a
        // dial that blocked for the life of the connection would be a dial that
        // never returns.
        establish(&self.shared, stream, Some(addr))
    }

    /// Dial whatever the address book suggests, up to the outbound limit.
    ///
    /// Returns how many connections were made. Every candidate comes from
    /// [`Manager::wants_outbound`], so the group-diversity rule is applied here
    /// without this function knowing what a group is.
    pub fn dial_out(&self) -> usize {
        let mut made = 0;
        loop {
            let candidate = {
                let Ok(mut manager) = self.shared.manager.lock() else {
                    return made;
                };
                manager.wants_outbound()
            };
            let Some(candidate) = candidate else {
                return made;
            };
            if self.dial(candidate).is_ok() {
                made = made.saturating_add(1);
            } else {
                if let Ok(mut manager) = self.shared.manager.lock() {
                    manager.on_dial_failed(&candidate.id);
                }
                return made;
            }
        }
    }

    /// Run one tick of peer housekeeping.
    ///
    /// How often this is called is the caller's business and affects only how
    /// promptly a node announces itself and asks for addresses. It does **not**
    /// change what any rate limit means: the elapsed time since the last tick is
    /// measured here and handed to the policy, so a limit of a thousand messages
    /// a second is a thousand messages a second whether this runs at 2 Hz or 50.
    pub fn tick(&self) {
        let elapsed = {
            let Ok(mut last) = self.shared.last_tick.lock() else {
                return;
            };
            let now = std::time::Instant::now();
            let elapsed = now.saturating_duration_since(*last);
            *last = now;
            elapsed
        };
        let directives = {
            let Ok(mut manager) = self.shared.manager.lock() else {
                return;
            };
            manager.on_tick(elapsed)
        };
        self.shared.apply(directives);
    }

    /// Begin a round on the node, and carry out whatever it decides.
    ///
    /// A driver calls this rather than reaching for the node itself, because
    /// "what a node decided" and "what has to happen as a result" must not be two
    /// steps a caller can get half right. A lone validator commits inside this
    /// call; that block has to reach the store, and it does so here rather than
    /// depending on the driver to remember.
    ///
    /// Returns the actions so a driver can read `ScheduleTimeout` out of them.
    /// Broadcasting and persistence have already happened.
    pub fn start_round(&self, time: afrolink_primitives::Timestamp) -> Vec<Action> {
        self.shared.drive(|node| node.start_round(time))
    }

    /// Fire a step's timer on the node, and carry out whatever it decides.
    pub fn timeout(&self, step: afrolink_consensus::Step) -> Vec<Action> {
        self.shared.feed(Event::Timeout(step))
    }

    /// Put a node's own actions on the wire, without touching the node.
    ///
    /// For a caller that already has actions in hand and wants only the gossip.
    /// **Nothing is persisted.** Prefer [`Self::start_round`] and
    /// [`Self::timeout`], which do the whole job.
    pub fn broadcast(&self, actions: Vec<Action>) {
        self.shared.broadcast(actions, None);
    }
}

/// Shake hands, register the peer, and hand the connection to its own threads.
///
/// Returns as soon as the peer is established, not when it goes away. The
/// handshake and the manager's decision happen on the calling thread so a dial
/// can report why it failed; everything after that is two threads, because a
/// thread blocked in `read_exact` cannot also be writing.
fn establish(
    shared: &Arc<Shared>,
    stream: TcpStream,
    expected: Option<PeerAddr>,
) -> Result<(), TransportError> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    // A write timeout for the life of the connection, not only the handshake: a
    // peer that stops reading would otherwise block this node's writer thread
    // forever, which is a resource an attacker can take with a single socket.
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_nodelay(true)?;

    let mut hs_reader = stream.try_clone()?;
    let mut hs_writer = stream.try_clone()?;
    let (peer, claimed, session) =
        shake(shared, &mut hs_reader, &mut hs_writer, expected.as_ref())?;

    // Where the peer says it is, if we dialled; otherwise where the socket says
    // it came from. A peer's own claim about its listening address is never
    // taken on trust, which is why an inbound peer's address does not reach the
    // tried table until this node has itself reached it.
    let addr = expected.unwrap_or_else(|| PeerAddr::new(peer, remote_of(&stream)));
    let outbound = expected.is_some();
    let consequences = {
        let mut manager = shared
            .manager
            .lock()
            .map_err(|_| TransportError::Poisoned)?;
        if outbound {
            manager.on_outbound(addr)?
        } else {
            manager.on_inbound(addr)?
        }
    };
    // Outside the lock, always: admitting an inbound peer can evict another one,
    // and carrying that out reaches `drop_peer`, which takes the manager lock
    // itself. Applying it while still holding the guard would deadlock the
    // listener thread on the first eviction — which is to say, the first time an
    // attacker filled the inbound slots.
    shared.apply(consequences);

    // **Only now, and only for an inbound peer.** A peer that dialled us told us
    // where it listens; the socket it arrived on cannot say, because an inbound
    // connection carries an ephemeral source port that dials nothing. Recording
    // the claim is what lets the topology grow past whoever ran the seeds — and
    // it is recorded as a *claim*: the address book puts it in `new`, and only a
    // dial this node chose to make and completed can promote it to `tried`.
    //
    // Nothing is recorded for an outbound peer: we already have its real
    // address, and it is already promoted by `on_outbound`. Taking a claim there
    // too would let a peer overwrite the address we successfully reached with
    // one we have not.
    if !outbound
        && let Some(claimed) = claimed
        && let Ok(mut manager) = shared.manager.lock()
    {
        manager.advertised(peer, claimed, addr.group());
    }

    let (tx, rx) = sync_channel::<PeerMessage>(OUTBOX_DEPTH);
    if let Ok(mut outboxes) = shared.outboxes.lock() {
        outboxes.insert(peer, tx);
    }
    if let Ok(mut streams) = shared.streams.lock() {
        streams.insert(peer, stream.try_clone()?);
    }

    let (mut sealer, mut opener) = session.split();

    let mut writer = stream.try_clone()?;
    let write_shared = Arc::clone(shared);
    std::thread::spawn(move || {
        pump(&write_shared, &mut writer, &rx, &mut sealer, peer);
    });

    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let mut reader = stream.try_clone()?;
    let read_shared = Arc::clone(shared);
    std::thread::spawn(move || {
        read_loop(&read_shared, &mut reader, &mut opener, peer);
        read_shared.drop_peer(&peer);
        // The reader owns the socket, so closing it is unambiguous: the writer
        // notices when its channel goes and stops.
        drop(stream.shutdown(std::net::Shutdown::Both));
    });
    Ok(())
}

/// Both halves of the handshake, over a socket.
fn shake(
    shared: &Arc<Shared>,
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    expected: Option<&PeerAddr>,
) -> Result<(PeerId, Option<SocketAddr>, Session), TransportError> {
    use std::io::{Read, Write};

    let (handshake, hello) = Handshake::start(shared.chain_id.clone())?;
    writer.write_all(&hello)?;
    writer.flush()?;

    let mut theirs = [0u8; crate::handshake::HELLO_LEN];
    reader.read_exact(&mut theirs)?;
    let pending = handshake.respond(&theirs, &shared.key, shared.advertise)?;

    // The identity frame is length-prefixed like any other, so the same bound
    // applies: a peer cannot announce a gigabyte of authentication.
    let frame = pending.auth_frame.clone();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "an auth frame is a key, a signature and a tag"
    )]
    let header = (frame.len() as u32).to_le_bytes();
    writer.write_all(&header)?;
    writer.write_all(&frame)?;
    writer.flush()?;

    let mut their_header = [0u8; 4];
    reader.read_exact(&mut their_header)?;
    let len = u32::from_le_bytes(their_header) as usize;
    if len > crate::wire::MAX_FRAME_LEN {
        return Err(TransportError::Handshake(HandshakeError::NotAuthentic));
    }
    let mut their_frame = vec![0u8; len];
    reader.read_exact(&mut their_frame)?;

    let established = pending.finish(&their_frame, &shared.ours, expected.map(|a| &a.id))?;
    Ok((established.peer, established.listen, established.session))
}

/// The socket's own view of where the peer is.
fn remote_of(stream: &TcpStream) -> SocketAddr {
    stream
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
}

/// Write queued messages until the peer or the node goes away.
fn pump(
    shared: &Arc<Shared>,
    writer: &mut TcpStream,
    rx: &Receiver<PeerMessage>,
    sealer: &mut Sealer,
    peer: PeerId,
) {
    loop {
        match rx.recv_timeout(READ_TIMEOUT) {
            Ok(message) => {
                if write_frame(writer, sealer, &message).is_err() {
                    shared.drop_peer(&peer);
                    return;
                }
            }
            // Idle. The timeout exists so this thread notices a shutdown; on an
            // otherwise quiet connection it is the normal case.
            Err(RecvTimeoutError::Timeout) => {
                if !shared.running.load(Ordering::SeqCst) {
                    return;
                }
            }
            // The peer was dropped and its outbox with it. Spinning here rather
            // than returning is how a "harmless" cleanup path becomes a core
            // pegged at 100%.
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Read frames until the peer or the node goes away.
fn read_loop(shared: &Arc<Shared>, reader: &mut TcpStream, opener: &mut Opener, peer: PeerId) {
    while shared.running.load(Ordering::SeqCst) {
        match read_frame(reader, opener) {
            Ok((message, bytes)) => {
                let directives = {
                    let Ok(mut manager) = shared.manager.lock() else {
                        return;
                    };
                    // What it actually cost on the wire, so the byte-rate limit
                    // is spent from the resource it is protecting.
                    manager.on_message_sized(peer, message, bytes)
                };
                shared.apply(directives);
            }
            // The read timeout, which exists so this thread notices a
            // shutdown. Not an error and not the peer's fault.
            Err(FrameError::TimedOut) => {}
            Err(FrameError::Closed) => return,
            Err(FrameError::TooLarge { .. } | FrameError::TooShort { .. }) => {
                penalise(shared, peer, Misbehaviour::Oversized);
                return;
            }
            Err(FrameError::Malformed(_)) => {
                penalise(shared, peer, Misbehaviour::Undecodable);
                return;
            }
            Err(FrameError::Session(_)) => {
                // A failed authentication tag. Somebody edited a frame in flight,
                // or the counters have diverged and nothing after this will
                // authenticate either. Unforgivable, and one is enough.
                penalise(shared, peer, Misbehaviour::Unforgivable);
                return;
            }
            Err(FrameError::Io(_)) => {
                // **The wire broke. That is not misbehaviour.**
                //
                // A reset connection, a router that rebooted, a peer that was
                // killed — none of it is a protocol violation and none of it is
                // anything the peer chose. Scoring it as one, which this used to
                // do by lumping it in with a failed tag, permanently bans any
                // peer whose link drops: a node that restarts is banned by
                // everyone who saw the reset, and can never rejoin.
                //
                // On the links this chain is built for, where connectivity is
                // assumed to be intermittent ([ADR-0005]), that is not an edge
                // case — it is a node quietly banning the entire network over the
                // course of a bad afternoon.
                //
                // [ADR-0005]: ../../../docs/adr/0005-african-first-design.md
                return;
            }
        }
    }
}

fn penalise(shared: &Arc<Shared>, peer: PeerId, what: Misbehaviour) {
    shared.punish(peer, what);
}

/// Wait for a condition, or give up.
///
/// Test helper in production code on purpose: a test that sleeps a fixed
/// interval is a test that is either slow or flaky, and every integration test
/// in this crate needs the same loop.
///
/// # Errors
/// Returns `false` if the deadline passed without the condition holding.
#[must_use]
pub fn wait_for(deadline: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    condition()
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.handle().stop();
    }
}
