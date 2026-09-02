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

use afrolink_node::{Action, Event, SharedNode};
use afrolink_primitives::ChainId;

use crate::handshake::{Handshake, HandshakeError};
use crate::manager::{Directive, Manager, Refusal};
use crate::peer::{Misbehaviour, PeerAddr, PeerId};
use crate::secret::{Opener, Sealer, Session};
use crate::wire::{FrameError, PeerMessage, read_frame, write_frame};

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
    running: AtomicBool,
    /// Frames delivered to the node. Observable so a test can wait on progress
    /// rather than on a sleep.
    delivered: AtomicU64,
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

    fn drop_peer(&self, peer: &PeerId) {
        if let Ok(mut outboxes) = self.outboxes.lock() {
            outboxes.remove(peer);
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
                Directive::Disconnect(peer, _why) => self.drop_peer(&peer),
            }
        }
    }

    /// Hand an event to consensus, and put whatever it decides back on the wire.
    fn deliver(&self, event: Event) {
        let Some(mut node) = self.node.lock() else {
            return;
        };
        let actions = node.handle(event);
        // The lock is released before anything is written, so a slow socket
        // never holds up consensus. It is the same rule `SharedNode` states for
        // the submit path: the lock covers a mempool insertion, never I/O.
        drop(node);
        self.delivered.fetch_add(1, Ordering::Relaxed);
        // Relayed to everyone, including whoever sent the original. A node only
        // emits a broadcast action for something it *newly* accepted, so the
        // sender receiving it back costs one frame and is deduplicated there —
        // and suppressing it here would need the node to tell us where the
        // event came from, which is knowledge consensus has no reason to carry.
        self.broadcast(actions, None);
    }

    /// Put a node's outbound actions on the wire.
    fn broadcast(&self, actions: Vec<Action>, except: Option<PeerId>) {
        for action in actions {
            let message = match action {
                Action::BroadcastProposal(p) => PeerMessage::Proposal(p),
                Action::BroadcastVote(v) => PeerMessage::Vote(v),
                Action::BroadcastTransaction(t) => PeerMessage::Transaction(t),
                // Committing and scheduling a timeout are the node's own
                // business. Neither is something a peer is told about: a peer
                // learns a block committed by seeing the precommits, which it
                // already has.
                Action::Committed(_, _) | Action::ScheduleTimeout(_, _) => continue,
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

impl Transport {
    /// Bind a listener and start accepting peers.
    ///
    /// # Errors
    /// [`TransportError::Io`] if the address cannot be bound.
    pub fn start(
        chain_id: ChainId,
        key: afrolink_crypto::SecretKey,
        node: Arc<SharedNode>,
        manager: Manager,
        listen: SocketAddr,
    ) -> Result<Self, TransportError> {
        let listener = TcpListener::bind(listen)?;
        let local = listener.local_addr()?;
        let ours = PeerId::new(key.public_key());
        let shared = Arc::new(Shared {
            chain_id,
            key,
            ours,
            node,
            manager: Mutex::new(manager),
            outboxes: Mutex::new(BTreeMap::new()),
            running: AtomicBool::new(true),
            delivered: AtomicU64::new(0),
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

    /// Who is connected right now.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerId> {
        self.shared
            .manager
            .lock()
            .map(|m| m.peers())
            .unwrap_or_default()
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
    pub fn tick(&self) {
        let directives = {
            let Ok(mut manager) = self.shared.manager.lock() else {
                return;
            };
            manager.on_tick()
        };
        self.shared.apply(directives);
    }

    /// Put a node's own actions on the wire.
    ///
    /// The path a proposer's block takes: consensus produces
    /// `Action::BroadcastProposal`, and this is what turns it into frames.
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
    let (peer, session) = shake(shared, &mut hs_reader, &mut hs_writer, expected.as_ref())?;

    // Where the peer says it is, if we dialled; otherwise where the socket says
    // it came from. A peer's own claim about its listening address is never
    // taken on trust, which is why an inbound peer's address does not reach the
    // tried table until this node has itself reached it.
    let addr = expected.unwrap_or_else(|| PeerAddr::new(peer, remote_of(&stream)));
    let outbound = expected.is_some();
    {
        let mut manager = shared
            .manager
            .lock()
            .map_err(|_| TransportError::Poisoned)?;
        if outbound {
            manager.on_outbound(addr)?;
        } else {
            manager.on_inbound(addr)?;
        }
    }

    let (tx, rx) = sync_channel::<PeerMessage>(OUTBOX_DEPTH);
    if let Ok(mut outboxes) = shared.outboxes.lock() {
        outboxes.insert(peer, tx);
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
) -> Result<(PeerId, Session), TransportError> {
    use std::io::{Read, Write};

    let (handshake, hello) = Handshake::start(shared.chain_id.clone())?;
    writer.write_all(&hello)?;
    writer.flush()?;

    let mut theirs = [0u8; crate::handshake::HELLO_LEN];
    reader.read_exact(&mut theirs)?;
    let pending = handshake.respond(&theirs, &shared.key)?;

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
    Ok((established.peer, established.session))
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
            Ok(message) => {
                let directives = {
                    let Ok(mut manager) = shared.manager.lock() else {
                        return;
                    };
                    manager.on_message(peer, message)
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
            Err(FrameError::Session(_) | FrameError::Io(_)) => {
                // A failed tag is unrecoverable: the frame counters have
                // diverged and nothing after this will authenticate either.
                penalise(shared, peer, Misbehaviour::Unforgivable);
                return;
            }
        }
    }
}

fn penalise(shared: &Arc<Shared>, peer: PeerId, what: Misbehaviour) {
    let directives = {
        let Ok(mut manager) = shared.manager.lock() else {
            return;
        };
        manager.penalise(peer, what)
    };
    shared.apply(directives);
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
