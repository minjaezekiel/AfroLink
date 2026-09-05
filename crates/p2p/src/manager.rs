//! Who to connect to, what to believe, and what to pass on.
//!
//! # The seam
//!
//! Everything here is a pure function of `(state, event) → directives`. No
//! sockets, no threads, no clock — time arrives as [`Manager::on_tick`] the same
//! way it arrives at `Node` as `Event::Timeout`. That is the same seam
//! `crates/http` draws at `respond` and `crates/node` draws at `Node::handle`,
//! and it is what makes an eclipse attempt or a gossip storm a unit test rather
//! than a flaky integration run.
//!
//! # Three rules that keep gossip from eating the network
//!
//! **A message is relayed once.** The seen-set is keyed on the canonical
//! encoding of the message, which is why the codec refusing second spellings
//! matters here and not only in a block: two encodings of one vote would be two
//! ids, and a node would relay both.
//!
//! **A message is never relayed to whoever sent it.** Obvious, and the omission
//! is how a two-node network turns one vote into an infinite loop.
//!
//! **A peer that talks too fast is slowed, then dropped.** Two token buckets per
//! peer — messages and bytes — refilled by *elapsed time handed in* rather than
//! by a clock this module reads. So the policy still has no clock in it, and the
//! limit means the same thing however often the caller ticks.
//!
//! # And the rules that keep the network from being captured
//!
//! **No two outbound connections into the same [`AddrGroup`].** The address book
//! makes an eclipse expensive to *set up*; this makes it expensive to *use*,
//! because owning a subnet buys exactly one of a node's outbound slots. Inbound
//! connections are capped but not group-restricted, because refusing inbound by
//! group is itself a way for an attacker to deny honest peers a seat.
//!
//! **A full inbound set evicts rather than refuses.** The cap alone was the same
//! denial with extra steps: an attacker who opens forty cheap connections holds
//! every slot until they choose to leave, and every honest peer is answered
//! `NoRoom`. Bitcoin's `AttemptToEvictConnection` accepts the newcomer and
//! removes somebody, choosing the victim so that an attacker cannot occupy the
//! protected set — *favour the diversity of peer connections*. The shape of that
//! is in [`Manager::eviction_candidate`], and it protects exactly one peer per
//! group, so a subnet buys one inbound seat as well as one outbound one.
//!
//! **A ban expires.** [`BAN_DURATION`] of accumulated tick time, and deliberately
//! not persisted — see [`Manager::penalise`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use afrolink_crypto::hash::Hash32;
use afrolink_node::Event;
use afrolink_primitives::Height;

use crate::addrbook::AddrBook;
use crate::peer::{AddrGroup, Misbehaviour, PeerAddr, PeerId, Reputation};
use crate::sync::{MAX_BLOCKS_IN_FLIGHT, MAX_STAGED_BLOCKS, REQUEST_TIMEOUT_TICKS, SyncBlock};
use crate::wire::{MAX_ADDRS, PeerMessage};
use afrolink_primitives::codec::Encode;

/// How many peers a node keeps, and how fast they may talk.
///
/// # Rates are per second, not per tick
///
/// A limit denominated in *ticks* means nothing without knowing how often the
/// caller ticks, and the caller is free to change that. This limit was written
/// as "512 messages per tick", and a daemon that ticked its peer manager on the
/// same 20 Hz schedule as its consensus poll quietly turned it into ten thousand
/// messages a second — a tenfold loosening of a security bound, caused by an
/// unrelated decision about loop latency, with nothing to notice it.
///
/// CometBFT denominates the same thing as `SendRate`/`RecvRate` in **bytes per
/// second**, enforced against a real clock. That is the model here, with one
/// addition: a message rate as well, because a flood of tiny frames costs CPU
/// and lock contention rather than bandwidth, and neither limit implies the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Connections this node makes. The eclipse-relevant number.
    pub max_outbound: usize,
    /// Connections this node accepts.
    pub max_inbound: usize,
    /// Gossip ids remembered, for deduplication.
    pub seen_capacity: usize,
    /// Messages one peer may send per second, sustained.
    pub messages_per_second: u64,
    /// Bytes one peer may send per second, sustained.
    ///
    /// The limit that actually bounds a link. A peer within any message budget
    /// can still send maximum-size frames as fast as its socket allows.
    pub bytes_per_second: u64,
    /// How much unused allowance a quiet peer may bank.
    ///
    /// Traffic here is bursty by nature — a round's votes arrive together, and a
    /// sync reply arrives all at once — so a limiter with no burst allowance
    /// punishes the normal case. It is bounded because an unbounded one is not a
    /// limit.
    pub burst: Duration,
}

impl Default for Limits {
    /// Eight out, forty in — Bitcoin's shape and for its reasons.
    ///
    /// Outbound is small because each one must be into a distinct group, and
    /// because they are the connections an attacker has to capture *all* of to
    /// eclipse a node. Inbound is generous because refusing inbound cheaply is
    /// how a network stops new nodes joining.
    ///
    /// The rates are deliberately below CometBFT's 20 MB/s default. A validator
    /// here is expected on a link that costs money by the gigabyte, and a limit
    /// no real connection can reach is not a limit — it is a number that will be
    /// discovered to be wrong during an incident.
    fn default() -> Self {
        Self {
            max_outbound: 8,
            max_inbound: 40,
            seen_capacity: 8_192,
            // What the old "512 per tick" came to at the rate the daemon actually
            // ticked. Stated in the unit that makes it checkable.
            messages_per_second: 1_024,
            bytes_per_second: 5 * 1024 * 1024,
            burst: Duration::from_secs(2),
        }
    }
}

/// How long a ban lasts, measured in the tick time the manager is handed.
///
/// Bounded because the alternative is exile forever for one bad afternoon, and
/// several of the things that earn a penalty are reachable by a peer that is
/// merely overloaded. An hour is long enough that a flooder gains nothing by
/// reconnecting and short enough that an honest peer is not lost to a partition.
pub const BAN_DURATION: Duration = Duration::from_secs(3_600);

/// How many outbound peers are kept as anchors across a restart.
///
/// Two, out of eight outbound slots, following Bitcoin PR #17428. Anchoring
/// *every* slot would mean an attacker who captured this node once keeps it;
/// anchoring two means an attacker who had not captured it before the restart
/// cannot capture it during the restart, which is when a fresh draw at every
/// slot is cheapest for them.
pub const ANCHOR_COUNT: usize = 2;

/// A token bucket, refilled by elapsed time rather than by a clock it reads.
///
/// Time arrives as data, exactly as it does at `Node::handle` as
/// `Event::Timeout`. That is what keeps this module testable without a clock
/// while giving the limit a meaning that does not depend on the caller's loop.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u64,
    capacity: u64,
    per_second: u64,
}

impl Bucket {
    /// A bucket that sustains `per_second` and may bank `burst` worth of it.
    ///
    /// `floor` is the smallest capacity that must be allowed whatever the rate
    /// says — for the byte bucket that is one maximum-size frame, because a
    /// limiter that cannot pass a single legal message is a limiter that stops
    /// the chain rather than an attacker.
    fn new(per_second: u64, burst: Duration, floor: u64) -> Self {
        let banked =
            per_second.saturating_mul(burst.as_millis().try_into().unwrap_or(u64::MAX)) / 1_000;
        let capacity = banked.max(floor).max(1);
        Self {
            tokens: capacity,
            capacity,
            per_second,
        }
    }

    fn refill(&mut self, elapsed: Duration) {
        let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let gained = self.per_second.saturating_mul(millis) / 1_000;
        self.tokens = self.tokens.saturating_add(gained).min(self.capacity);
    }

    /// Spend `n`, or report that the peer has outrun its allowance.
    fn take(&mut self, n: u64) -> bool {
        match self.tokens.checked_sub(n) {
            Some(left) => {
                self.tokens = left;
                true
            }
            None => false,
        }
    }
}

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The inbound slots are full.
    #[error("no inbound slots free")]
    NoRoom,
    /// This peer is banned.
    #[error("peer is banned")]
    Banned,
    /// Already connected to this peer.
    #[error("already connected")]
    Duplicate,
    /// The peer is this node.
    #[error("that is this node")]
    SelfConnection,
    /// An outbound connection into a group already used.
    #[error("a connection into that group already exists")]
    GroupInUse,
}

/// Something the transport should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// Hand this to the consensus engine.
    Deliver(Box<Event>),
    /// Send this to one peer.
    Send(PeerId, Box<PeerMessage>),
    /// Send this to every peer except the one named.
    Relay(Box<PeerMessage>, PeerId),
    /// Send this to every peer.
    Broadcast(Box<PeerMessage>),
    /// Read this height from the durable store and send it to this peer.
    ///
    /// A directive rather than a lookup, because the manager has no store in it
    /// and is not going to acquire one: what to serve is policy, where it is kept
    /// is the transport's business.
    ServeBlock(PeerId, Height),
    /// Apply this committed block, verifying its certificate first.
    ///
    /// Emitted only in contiguous height order, because a block cannot be applied
    /// before its parent has been.
    ///
    /// The peer that supplied it travels with it, because verification happens
    /// after staging and a block that fails it is evidence about *somebody*.
    /// Without this the sender is anonymous by the time the failure is known, and
    /// a peer could feed a node unverifiable blocks indefinitely for free.
    ApplyBlock(PeerId, Box<SyncBlock>),
    /// Close this connection.
    Disconnect(PeerId, &'static str),
}

/// One connected peer.
#[derive(Debug, Clone)]
struct Connected {
    addr: PeerAddr,
    outbound: bool,
    reputation: Reputation,
    /// What this peer may still send before the next refill.
    messages: Bucket,
    bytes: Bucket,
    /// Whether we have asked this peer for addresses and not yet been answered.
    awaiting_addrs: bool,
    /// The highest height this peer has claimed, if it has said.
    tip: Option<Height>,
    /// The height we asked this peer for and have not been answered on.
    ///
    /// At most one. A peer that is slow then costs one outstanding request rather
    /// than a whole batch window, and a peer that is fast is asked again the
    /// moment it answers.
    awaiting_block: Option<Height>,
    /// Ticks since that request went out.
    request_age: u32,
    /// A height this node asked this peer for and then stopped waiting on.
    ///
    /// Kept so a late answer is recognised as an answer rather than as an
    /// unsolicited block. At most one, and cleared as it is used, so it cannot
    /// become a standing licence to send whatever the peer likes.
    abandoned: Option<Height>,
    /// The node's accumulated uptime when this connection was admitted.
    ///
    /// Held as a stamp rather than a duration so that "longest-connected" is a
    /// comparison of two numbers and never a clock this module reads. A smaller
    /// stamp is an older connection.
    since: Duration,
    /// Whether this peer has ever answered a block request.
    ///
    /// The one piece of evidence a node has that a connection is worth something,
    /// and an attacker filling inbound slots has not produced it. Used only to
    /// break ties in [`Manager::eviction_candidate`], never to protect outright —
    /// serving one block is cheap enough that protection would be for sale.
    served: bool,
}

/// A bounded set of recently seen gossip ids.
///
/// A `BTreeSet` for the membership test and a queue for the eviction order.
/// Bounded on purpose: an unbounded seen-set is a memory leak with a peer
/// holding the tap, and "we have seen everything ever" is not a property a node
/// needs — only "we have seen this recently enough that relaying it again would
/// be noise".
struct Seen {
    ids: BTreeSet<Hash32>,
    order: VecDeque<Hash32>,
    capacity: usize,
}

impl Seen {
    fn new(capacity: usize) -> Self {
        Self {
            ids: BTreeSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record an id, returning whether it was new.
    fn insert(&mut self, id: Hash32) -> bool {
        if !self.ids.insert(id) {
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
        true
    }
}

/// The peer set, the address book, and the policy over both.
pub struct Manager {
    ours: PeerId,
    book: AddrBook,
    peers: BTreeMap<PeerId, Connected>,
    /// Banned peers, and the uptime stamp their ban expires at.
    banned: BTreeMap<PeerId, Duration>,
    /// Addresses to dial before consulting the book — the anchors from the last
    /// run. Drained, never refilled from here, because an anchor that is dialled
    /// and kept becomes an ordinary outbound peer and an anchor that fails should
    /// not be retried forever.
    anchors: VecDeque<PeerAddr>,
    seen: Seen,
    limits: Limits,
    cursor: u64,
    /// Tick time accumulated since this manager was made.
    ///
    /// The only notion of time here, and it arrives as data. Connection age and
    /// ban expiry are both denominated in it, so neither depends on a clock and
    /// both mean the same thing however often the caller ticks.
    uptime: Duration,
    /// The next height this node needs — one past its committed tip.
    height: Height,
    /// Blocks that arrived before their parent did.
    ///
    /// Requests go out in parallel and replies come back in whatever order the
    /// network delivers them. Bounded, because a peer answering only with
    /// far-future heights would otherwise fill memory with blocks that can never
    /// be applied.
    staged: BTreeMap<Height, (PeerId, SyncBlock)>,
}

impl Manager {
    /// A manager for a node with this identity and address book.
    #[must_use]
    pub fn new(ours: PeerId, book: AddrBook, limits: Limits) -> Self {
        Self {
            ours,
            book,
            peers: BTreeMap::new(),
            banned: BTreeMap::new(),
            anchors: VecDeque::new(),
            seen: Seen::new(limits.seen_capacity),
            limits,
            cursor: 0,
            uptime: Duration::ZERO,
            height: Height(0),
            staged: BTreeMap::new(),
        }
    }

    /// Start from a known height, rather than assuming genesis.
    #[must_use]
    pub fn at_height(mut self, height: Height) -> Self {
        self.height = height;
        self
    }

    /// The next height this node needs.
    #[must_use]
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Tell the manager where the node actually is.
    ///
    /// Called after every commit, local or synced — and after a **failed** apply,
    /// which is what makes the optimistic advance in [`Self::drain_staged`] safe:
    /// the manager assumes the block it handed over was applied, and this is how
    /// it is corrected when that was wrong. The node re-requests the height it
    /// stumbled on rather than silently skipping it.
    pub fn set_height(&mut self, height: Height) {
        self.height = height;
        // Anything at or below the tip is dead weight; anything a peer sent for a
        // height we have passed is not an attack, just a slow reply.
        self.staged.retain(|staged, _| *staged >= height);
    }

    /// The highest height this node has committed.
    ///
    /// One below [`Self::height`], which is the height being worked on. Every
    /// number that crosses the wire is this one, so that both ends of a `Status`
    /// mean the same thing by it.
    #[must_use]
    pub const fn committed_tip(&self) -> Height {
        Height(self.height.0.saturating_sub(1))
    }

    /// The highest height any connected peer claims to hold.
    #[must_use]
    pub fn best_peer_height(&self) -> Option<Height> {
        self.peers.values().filter_map(|p| p.tip).max()
    }

    /// Whether some peer claims a height this node does not have.
    #[must_use]
    pub fn is_behind(&self) -> bool {
        self.best_peer_height()
            .is_some_and(|best| best >= self.height)
    }

    /// The address book, for seeding and inspection.
    #[must_use]
    pub fn book(&self) -> &AddrBook {
        &self.book
    }

    /// The address book, mutably, so an operator can seed it.
    pub fn book_mut(&mut self) -> &mut AddrBook {
        &mut self.book
    }

    /// Everyone currently connected.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    /// Everything that decides whether this node will ask for a block.
    ///
    /// # Pulled on failure, never pushed
    ///
    /// Written for [10 §17](../../../docs/10-network-hardening.md): a node that
    /// joins late sometimes stops one height short with peers connected and
    /// `is_behind()` true. The obvious way to chase that — print the scheduler's
    /// state every tick — slows the loop enough that the bug stops happening, and
    /// six runs of it in a row all passed.
    ///
    /// So this costs nothing until something has already gone wrong: a test that
    /// is about to fail asks for it and puts it in the failure message. Cheap
    /// enough to leave in, because it is only ever called by the code reporting
    /// the failure.
    #[must_use]
    pub fn sync_snapshot(&self) -> String {
        let peers: Vec<String> = self
            .peers
            .iter()
            .map(|(id, p)| {
                format!(
                    "{}{}{} tip={:?} awaiting={:?} age={} score={}",
                    id.short(),
                    if p.outbound { " out" } else { " in " },
                    if p.served { " served" } else { "       " },
                    p.tip.map(|t| t.0),
                    p.awaiting_block.map(|h| h.0),
                    p.request_age,
                    p.reputation.score(),
                )
            })
            .collect();
        format!(
            "need={} best={:?} behind={} staged={:?} banned={} peers=[{}]",
            self.height.0,
            self.best_peer_height().map(|h| h.0),
            self.is_behind(),
            self.staged.keys().map(|h| h.0).collect::<Vec<_>>(),
            self.banned.len(),
            peers.join(" | ")
        )
    }

    /// How many connections this node made.
    #[must_use]
    pub fn outbound_count(&self) -> usize {
        self.peers.values().filter(|p| p.outbound).count()
    }

    /// How many connections this node accepted.
    #[must_use]
    pub fn inbound_count(&self) -> usize {
        self.peers.values().filter(|p| !p.outbound).count()
    }

    /// How many penalty points this peer has accumulated.
    ///
    /// `None` if it is not connected. Exposed because "was this peer punished"
    /// is otherwise only observable once it has been punished *enough*, which
    /// makes a test for "we stopped punishing honest peers" unable to fail until
    /// the score crosses [`crate::peer::BAN_THRESHOLD`] — five separate
    /// offences. It is also the number an operator wants when a peer set is
    /// mysteriously shrinking.
    #[must_use]
    pub fn reputation(&self, peer: &PeerId) -> Option<i32> {
        self.peers.get(peer).map(|p| p.reputation.score())
    }

    /// Whether this peer is refused on sight.
    ///
    /// Bans expire, so this is a comparison rather than a membership test. The
    /// entry is left behind until the next tick sweeps it; a ban that has run out
    /// is not a ban, whether or not the sweep has happened yet.
    #[must_use]
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.banned
            .get(peer)
            .is_some_and(|until| *until > self.uptime)
    }

    /// The outbound peers worth dialling first after a restart.
    ///
    /// The longest-connected ones, because a connection that has survived is
    /// evidence and a connection that was just made is not. Read at shutdown and
    /// handed back to the next process through [`Self::seed_anchors`].
    #[must_use]
    pub fn anchors(&self) -> Vec<PeerAddr> {
        let mut outbound: Vec<&Connected> = self.peers.values().filter(|p| p.outbound).collect();
        outbound.sort_by_key(|p| (p.since, p.addr.id));
        outbound
            .into_iter()
            .take(ANCHOR_COUNT)
            .map(|p| p.addr)
            .collect()
    }

    /// Dial these before anything the address book offers.
    ///
    /// The anchor half of the eclipse defence: on restart a node's book is
    /// whatever a seed list plus hours of gossip made it, and an attacker who has
    /// been feeding it addresses gets a fresh draw at every outbound slot at the
    /// moment the node is most exposed. Dialling last run's peers first means at
    /// least [`ANCHOR_COUNT`] of those slots are not on offer.
    ///
    /// They are dialled, not trusted: each still passes the ban check, the
    /// self-connection check and the group-diversity rule, and each still has to
    /// complete the handshake as the identity it claims.
    pub fn seed_anchors(&mut self, addrs: impl IntoIterator<Item = PeerAddr>) {
        self.anchors.extend(addrs.into_iter().take(ANCHOR_COUNT));
    }

    /// The groups this node already has outbound connections into.
    fn outbound_groups(&self) -> Vec<AddrGroup> {
        self.peers
            .values()
            .filter(|p| p.outbound)
            .map(|p| p.addr.group())
            .collect()
    }

    /// A peer worth dialling, or `None` if the node is content.
    ///
    /// The group rule lives here, and it is the whole eclipse defence at
    /// connection time: a subnet holding ten thousand addresses is offered
    /// exactly one outbound slot, because the second candidate from it is
    /// filtered before it is ever returned.
    pub fn wants_outbound(&mut self) -> Option<PeerAddr> {
        if self.outbound_count() >= self.limits.max_outbound {
            return None;
        }
        let mut avoid = self.outbound_groups();
        // Also avoid a group we are already *inbound* from when choosing whom to
        // dial: dialling back into a subnet that already reached us spends a
        // scarce outbound slot on a peer that costs the network nothing new.
        avoid.extend(self.peers.values().map(|p| p.addr.group()));

        // Anchors first, and each is *consumed* whether or not it is usable. An
        // anchor that has become unreachable, banned or group-conflicted must not
        // be retried on every pass — a node that kept re-offering a dead anchor
        // would spend its dial budget on it instead of finding new peers.
        while let Some(anchor) = self.anchors.pop_front() {
            if anchor.id != self.ours
                && !self.is_banned(&anchor.id)
                && !self.peers.contains_key(&anchor.id)
                && !avoid.contains(&anchor.group())
            {
                return Some(anchor);
            }
        }

        self.cursor = self.cursor.wrapping_add(1);
        let cursor = self.cursor;
        let candidate = self.book.select(&avoid, cursor)?;
        (candidate.id != self.ours && !self.is_banned(&candidate.id)).then_some(candidate)
    }

    /// Accept a connection this node made.
    ///
    /// # Errors
    /// Returns why the connection should be dropped instead.
    pub fn on_outbound(&mut self, addr: PeerAddr) -> Result<Vec<Directive>, Refusal> {
        self.admit(addr, true)
    }

    /// Accept a connection a peer made to this node, evicting someone if full.
    ///
    /// Returns whatever the transport must do as a consequence — at most one
    /// [`Directive::Disconnect`], for the peer that made room.
    ///
    /// # Errors
    /// Returns why the connection should be dropped instead.
    pub fn on_inbound(&mut self, addr: PeerAddr) -> Result<Vec<Directive>, Refusal> {
        self.admit(addr, false)
    }

    /// Which inbound peer to remove to make room, if there is a seat to take back.
    ///
    /// Bitcoin's `AttemptToEvictConnection`, reduced to the property that matters
    /// on a network whose whole consensus argument is geographic spread:
    /// *favour the diversity of peer connections.* There is no protected-set
    /// constant here and deliberately so — a fixed number of protected slots is a
    /// number an attacker can count, and an unbounded one (say, one peer per
    /// group) closes a diverse node to newcomers forever.
    ///
    /// The rule is written in terms of the thing being defended instead:
    ///
    /// * **If any [`AddrGroup`] holds two or more inbound peers, evict from the
    ///   largest one.** A subnet that has more than one seat is over-represented
    ///   by definition, and taking the seat back costs it nothing it was entitled
    ///   to. Applied repeatedly, this is what bounds an attacker holding one
    ///   subnet to exactly one inbound seat, however many connections they open.
    /// * **Otherwise every group holds exactly one peer**, the set is as diverse
    ///   as it can be, and the newcomer is **refused**.
    ///
    /// That second branch is the one worth arguing about, because Bitcoin does
    /// the opposite: it evicts something almost always, so that a new listening
    /// node can always find a slot somewhere. Evicting here would mean a
    /// saturated node throws out a good peer on *every* arrival — and since
    /// `Transport::dial_out` refills its outbound slots twice a second, the peer
    /// it threw out re-dials immediately and displaces another. The result is a
    /// permanent rotation among honest peers on any healthy network, which costs
    /// a handshake and a TCP connection each time on links that are metered by
    /// the gigabyte, and destroys the very thing the rest of this function treats
    /// as evidence: that a long-lived connection means something.
    ///
    /// The cost of refusing is real and is recorded rather than hidden: a network
    /// whose nodes are all saturated stops accepting new *inbound* peers, so a
    /// new node can dial out but is not itself reachable. The fix for that is
    /// dial-side backoff and address advertisement (§7), not eviction — see
    /// [10-network-hardening.md](../../../docs/10-network-hardening.md) §3.
    ///
    /// Within the eligible group the victim is the **youngest**, and a peer that
    /// has served a block goes after one that has not. A connection that just
    /// arrived has demonstrated nothing; one that answered a sync request has.
    /// Serving is a tiebreak and never protection, because one block is cheap and
    /// anything an attacker can buy for one block is not a defence.
    ///
    /// Outbound peers are never candidates: they are the eclipse-relevant
    /// connections and *this node* chose them, so letting a stranger's arrival
    /// displace one would hand that choice back to whoever dialled in.
    fn eviction_candidate(&self) -> Option<PeerId> {
        let mut population: BTreeMap<AddrGroup, usize> = BTreeMap::new();
        for peer in self.peers.values().filter(|p| !p.outbound) {
            let seats = population.entry(peer.addr.group()).or_insert(0usize);
            *seats = seats.saturating_add(1);
        }
        let largest = *population.values().max()?;
        if largest < 2 {
            // Nothing is over-represented, so there is no seat to take back.
            return None;
        }

        self.peers
            .iter()
            .filter(|(_, peer)| !peer.outbound)
            // Only the over-represented group is eligible.
            .filter(|(_, peer)| population.get(&peer.addr.group()).copied() == Some(largest))
            // Largest key wins, so order the *most* evictable highest.
            .max_by_key(|(id, peer)| (!peer.served, peer.since, **id))
            .map(|(id, _)| *id)
    }

    fn admit(&mut self, addr: PeerAddr, outbound: bool) -> Result<Vec<Directive>, Refusal> {
        if addr.id == self.ours {
            return Err(Refusal::SelfConnection);
        }
        if self.is_banned(&addr.id) {
            return Err(Refusal::Banned);
        }
        if self.peers.contains_key(&addr.id) {
            return Err(Refusal::Duplicate);
        }
        let mut out = Vec::new();
        if outbound {
            if self.outbound_count() >= self.limits.max_outbound {
                return Err(Refusal::NoRoom);
            }
            if self.outbound_groups().contains(&addr.group()) {
                // Checked again here, not only in `wants_outbound`: a dial can
                // be started by an operator or a seed list, and the rule has to
                // hold however the connection was begun.
                return Err(Refusal::GroupInUse);
            }
        } else if self.inbound_count() >= self.limits.max_inbound {
            let victim = self.eviction_candidate().ok_or(Refusal::NoRoom)?;
            self.peers.remove(&victim);
            out.push(Directive::Disconnect(victim, "evicted to make room"));
        }

        if outbound {
            // **Only a peer this node dialled enters the address book.** An
            // inbound connection tells us its *source* port, which is ephemeral
            // and dials nothing; recording it would put an address in the tried
            // table that no one can reach, and then recommend it to everyone who
            // asks. It also closes a whole class of address poisoning: an
            // attacker cannot get into a node's tried table — and so into the
            // samples it gossips — merely by connecting to it. They have to be
            // reachable, and this node has to have chosen to reach them.
            self.book.add(addr, addr.group());
            self.book.mark_good(&addr.id);
        }
        self.peers.insert(
            addr.id,
            Connected {
                addr,
                outbound,
                reputation: Reputation::new(),
                messages: Bucket::new(self.limits.messages_per_second, self.limits.burst, 1),
                bytes: Bucket::new(
                    self.limits.bytes_per_second,
                    self.limits.burst,
                    // One maximum-size frame, always. Otherwise a node configured
                    // with a modest byte rate would drop every peer that sent it
                    // a large block — which is to say, every peer it syncs from.
                    crate::wire::MAX_FRAME_LEN as u64,
                ),
                awaiting_addrs: false,
                tip: None,
                awaiting_block: None,
                request_age: 0,
                abandoned: None,
                since: self.uptime,
                served: false,
            },
        );
        Ok(out)
    }

    /// Forget a peer that has gone away.
    pub fn on_disconnect(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    /// Record that a dial did not work.
    pub fn on_dial_failed(&mut self, peer: &PeerId) {
        self.book.mark_failed(peer);
    }

    /// Refresh budgets, announce where we are, ask for addresses, and catch up.
    ///
    /// The clock enters the policy here and nowhere else. What "a tick" is worth
    /// is the transport's business; whether a peer has spent its budget, and
    /// whether a block request has waited long enough to be given to somebody
    /// else, is this module's.
    pub fn on_tick(&mut self, elapsed: Duration) -> Vec<Directive> {
        self.uptime = self.uptime.saturating_add(elapsed);
        // A ban that has run out is forgotten rather than merely ignored, so the
        // set does not grow without bound on a node an attacker keeps poking.
        let now = self.uptime;
        self.banned.retain(|_, until| *until > now);
        for peer in self.peers.values_mut() {
            peer.messages.refill(elapsed);
            peer.bytes.refill(elapsed);
        }
        self.cursor = self.cursor.wrapping_add(1);
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        if ids.is_empty() {
            return Vec::new();
        }

        // A request that has gone unanswered long enough is abandoned rather than
        // punished. A peer that does not answer may be slow, or may genuinely not
        // hold the block despite what it claimed; neither is misbehaviour, and
        // both are fixed by asking somebody else.
        for peer in self.peers.values_mut() {
            if peer.awaiting_block.is_some() {
                peer.request_age = peer.request_age.saturating_add(1);
                if peer.request_age >= REQUEST_TIMEOUT_TICKS {
                    // Remembered, so that if this peer answers after all it is
                    // treated as the late reply it is rather than as an attack.
                    peer.abandoned = peer.awaiting_block;
                    peer.awaiting_block = None;
                    peer.request_age = 0;
                }
            }
        }

        // What this node *has*, which is one below the height it is working on.
        // Announcing the working height would have every peer ask for a block
        // that does not exist yet, on every tick, for as long as they are
        // connected.
        let mut out = vec![Directive::Broadcast(Box::new(PeerMessage::Status(
            self.committed_tip(),
        )))];

        // Ask exactly one peer per tick for addresses, in rotation. Asking
        // everyone at once makes a node's address book a reflection of whoever
        // answers fastest, which is the peer closest to it — and closeness is
        // something an attacker on the path controls.
        if let Some(target) = self.rotate(&ids, 0) {
            if let Some(peer) = self.peers.get_mut(&target) {
                peer.awaiting_addrs = true;
            }
            out.push(Directive::Send(target, Box::new(PeerMessage::GetAddrs)));
        }

        // **Release anything already held that can now be applied, before asking
        // for more.**
        //
        // `drain_staged` used to have exactly one caller, inside `on_block`, so a
        // staged block was only ever released by the arrival of *another* block.
        // Every other way the height moves — `set_height`, called after every
        // apply, succeeded or failed — left applicable blocks sitting in the
        // buffer. And `schedule_sync` counts staged heights as already claimed,
        // so it then asked for nothing, so nothing arrived, so `on_block` never
        // ran again: a node with the blocks it needed, in its own hands, waiting
        // forever for a message that could not come.
        //
        // That is [10 §17](../../../docs/10-network-hardening.md), seen in the
        // wild as `need=7 best=8 behind=true staged=[7, 8]` on a node that had
        // stopped one height short with four healthy peers.
        //
        // Draining on the tick makes the release depend on the height being
        // right, which is the actual condition, rather than on a message
        // happening to arrive.
        out.extend(self.drain_staged());
        out.extend(self.schedule_sync(&ids));
        out
    }

    /// Pick from `ids` by the rotating cursor, so the same peer is not always first.
    fn rotate(&self, ids: &[PeerId], offset: u64) -> Option<PeerId> {
        let len = u64::try_from(ids.len()).ok()?;
        let index = self.cursor.wrapping_add(offset).checked_rem(len)?;
        ids.get(usize::try_from(index).ok()?).copied()
    }

    /// Hand out the heights this node is missing, one request per peer.
    ///
    /// The whole catch-up policy, and it is deliberately unclever: ask for the
    /// lowest heights first, never more than [`MAX_BLOCKS_IN_FLIGHT`] at a time,
    /// never twice for the same height, and never from a peer that has not
    /// claimed to hold it. Asking for the lowest first is what keeps the staging
    /// buffer small — a syncer that requests the *tip* first holds every block it
    /// receives and applies none of them.
    fn schedule_sync(&mut self, ids: &[PeerId]) -> Vec<Directive> {
        let Some(best) = self.best_peer_height() else {
            return Vec::new();
        };
        if best < self.height {
            return Vec::new();
        }

        let mut in_flight = self
            .peers
            .values()
            .filter(|p| p.awaiting_block.is_some())
            .count();
        // A height already asked for, or already sitting in the staging buffer,
        // is not asked for again: duplicate requests spend the in-flight budget
        // on work already done.
        let mut claimed: BTreeSet<Height> = self
            .peers
            .values()
            .filter_map(|p| p.awaiting_block)
            .collect();
        claimed.extend(self.staged.keys().copied());

        // Never request past what the staging buffer can hold. Otherwise a gap at
        // the bottom — one peer stalled on the height everything else waits for —
        // turns into blocks arriving that must be thrown away.
        let ceiling = Height(self.ceiling().0.min(best.0));

        let mut out = Vec::new();
        let mut want = self.height;
        while in_flight < MAX_BLOCKS_IN_FLIGHT && want <= ceiling {
            if claimed.contains(&want) {
                want = want.next();
                continue;
            }
            let Some(target) = self.free_peer_holding(ids, want) else {
                // Nobody free claims this height. Stop rather than skip: the
                // heights above it cannot be applied until this one is, so
                // spending requests on them buys nothing.
                break;
            };
            if let Some(peer) = self.peers.get_mut(&target) {
                peer.awaiting_block = Some(want);
                peer.request_age = 0;
            }
            out.push(Directive::Send(
                target,
                Box::new(PeerMessage::GetBlock(want)),
            ));
            claimed.insert(want);
            in_flight = in_flight.saturating_add(1);
            want = want.next();
        }
        out
    }

    /// The highest height this node has room to hold.
    ///
    /// One definition, used both when deciding what to *ask* for and when
    /// deciding whether an unasked-for block is worth keeping. Two copies of that
    /// rule would be two chances for a node to punish a peer for sending exactly
    /// what it would have requested a moment later.
    fn ceiling(&self) -> Height {
        Height(self.height.0.saturating_add(MAX_STAGED_BLOCKS as u64))
    }

    /// A peer with no outstanding request that claims to hold `height`.
    fn free_peer_holding(&self, ids: &[PeerId], height: Height) -> Option<PeerId> {
        for offset in 0..u64::try_from(ids.len()).ok()? {
            let candidate = self.rotate(ids, offset)?;
            if self.peers.get(&candidate).is_some_and(|peer| {
                peer.awaiting_block.is_none() && peer.tip.is_some_and(|tip| tip >= height)
            }) {
                return Some(candidate);
            }
        }
        None
    }

    /// Handle one message from one peer.
    ///
    /// `bytes` is what the message cost on the wire, which is what the byte-rate
    /// limit is spent from. A caller that does not know — a test constructing a
    /// message directly — can use [`Self::on_message`].
    #[must_use]
    pub fn on_message_sized(
        &mut self,
        from: PeerId,
        message: PeerMessage,
        bytes: usize,
    ) -> Vec<Directive> {
        let Some(peer) = self.peers.get_mut(&from) else {
            // A message from someone we are not connected to. Nothing to do and
            // nothing to punish: the connection is already gone.
            return Vec::new();
        };
        // Both limits, because neither implies the other: a flood of tiny frames
        // costs CPU and lock contention, and one enormous frame costs a link.
        if !peer.messages.take(1) || !peer.bytes.take(bytes as u64) {
            return self.penalise(from, Misbehaviour::TooFast);
        }

        // Deduplicate before anything else. A message we have already relayed is
        // not evidence of misbehaviour — every peer we have will send us the
        // same vote — it is simply nothing to do.
        if let Some(id) = message.gossip_id()
            && !self.seen.insert(id)
        {
            return Vec::new();
        }

        match message {
            PeerMessage::Proposal(proposal) => vec![
                Directive::Deliver(Box::new(Event::Proposal(proposal.clone()))),
                Directive::Relay(Box::new(PeerMessage::Proposal(proposal)), from),
            ],
            PeerMessage::Vote(vote) => vec![
                Directive::Deliver(Box::new(Event::Vote(vote.clone()))),
                Directive::Relay(Box::new(PeerMessage::Vote(vote)), from),
            ],
            PeerMessage::Transaction(tx) => {
                // Not relayed here. The node relays a transaction only when it
                // was *newly accepted* into the mempool, which is what stops one
                // submission becoming a storm — so the decision belongs there,
                // and repeating it here would relay transactions the node
                // refused.
                vec![Directive::Deliver(Box::new(Event::Transaction(tx)))]
            }
            PeerMessage::GetAddrs => {
                let cursor = self.cursor;
                let sample = self.book.sample(MAX_ADDRS, cursor);
                if sample.is_empty() {
                    Vec::new()
                } else {
                    vec![Directive::Send(from, Box::new(PeerMessage::Addrs(sample)))]
                }
            }
            PeerMessage::Addrs(addrs) => self.on_addrs(from, &addrs),
            PeerMessage::Ping(nonce) => {
                vec![Directive::Send(from, Box::new(PeerMessage::Pong(nonce)))]
            }
            // Nothing to do. A pong's only job is to have arrived, and the
            // transport notices that by resetting its idle timer.
            PeerMessage::Pong(_) => Vec::new(),
            PeerMessage::Status(height) => {
                // Recorded, believed only as far as it is useful. A peer that
                // overstates its tip earns a request it cannot answer; one that
                // understates it is never asked. What makes a block acceptable is
                // the certificate on it, never this.
                if let Some(peer) = self.peers.get_mut(&from) {
                    peer.tip = Some(height);
                }
                Vec::new()
            }
            PeerMessage::GetBlock(height) => vec![Directive::ServeBlock(from, height)],
            PeerMessage::Block(sync) => self.on_block(from, *sync),
            PeerMessage::NoBlock(height) => {
                if let Some(peer) = self.peers.get_mut(&from)
                    && peer.awaiting_block == Some(height)
                {
                    peer.awaiting_block = None;
                    peer.request_age = 0;
                    // It claimed this height and does not have it. Believe the
                    // newer, worse claim — otherwise this node asks the same peer
                    // for the same gap on every tick for as long as they are
                    // connected.
                    peer.tip = Some(Height(height.0.saturating_sub(1)));
                }
                Vec::new()
            }
        }
    }

    /// Take a block that was asked for, and release what can now be applied.
    fn on_block(&mut self, from: PeerId, sync: SyncBlock) -> Vec<Directive> {
        let height = sync.height();
        let Some(peer) = self.peers.get_mut(&from) else {
            return Vec::new();
        };
        if peer.awaiting_block != Some(height) {
            // Not the outstanding question. Forgivable in exactly one case: this
            // node **did** ask this peer for this height, and then gave up.
            //
            // A request is abandoned after `REQUEST_TIMEOUT_TICKS` and handed to
            // somebody else; the original peer's reply then lands against a
            // cleared slot. Scoring that as `BadBlock` — twenty points, five of
            // them a ban — punishes a peer for being slow on a link this network
            // *assumes* is slow. It was seen doing exactly that: a node stuck on
            // [10 §17](../../../docs/10-network-hardening.md) re-asked
            // repeatedly and drove all four of its honest peers to a score of 40,
            // three answers short of banning the only nodes it could have caught
            // up from.
            //
            // Deliberately narrow. The rule the tests below state is untouched —
            // a peer must not get to choose which heights this node holds in
            // memory — because only a height *this node chose to ask this peer
            // for* is forgiven, once, with the record cleared as it is used.
            if peer.abandoned != Some(height) {
                return self.penalise(from, Misbehaviour::BadBlock);
            }
            peer.abandoned = None;
        }
        peer.awaiting_block = None;
        peer.request_age = 0;
        peer.served = true;
        peer.tip = Some(peer.tip.map_or(height, |tip| tip.max(height)));

        // A reply that raced this node's own commit. Not an attack and not worth
        // keeping.
        if height < self.height {
            return Vec::new();
        }
        if self.staged.len() >= MAX_STAGED_BLOCKS {
            return Vec::new();
        }
        self.staged.insert(height, (from, sync));
        self.drain_staged()
    }

    /// Release staged blocks in contiguous order, and only in contiguous order.
    ///
    /// The height is advanced **optimistically**, on the assumption the transport
    /// applies what it is handed. That is what lets the next tick request the
    /// heights beyond without waiting a round trip for confirmation — and it is
    /// safe because a failed apply is reported back through
    /// [`Self::set_height`], which winds the manager back to the truth.
    fn drain_staged(&mut self) -> Vec<Directive> {
        let mut out = Vec::new();
        while let Some((from, sync)) = self.staged.remove(&self.height) {
            self.height = self.height.next();
            out.push(Directive::ApplyBlock(from, Box::new(sync)));
        }
        out
    }

    /// Handle one message whose wire cost is not known.
    ///
    /// Charges the byte budget for the message's encoded length, which is what it
    /// would have cost had it arrived over a socket.
    #[must_use]
    pub fn on_message(&mut self, from: PeerId, message: PeerMessage) -> Vec<Directive> {
        let bytes = message.to_bytes().len();
        self.on_message_sized(from, message, bytes)
    }

    fn on_addrs(&mut self, from: PeerId, addrs: &[PeerAddr]) -> Vec<Directive> {
        let Some(peer) = self.peers.get_mut(&from) else {
            return Vec::new();
        };
        if !peer.awaiting_addrs {
            // Unsolicited. This is the injection point for an eclipse: a peer
            // that can push addresses whenever it likes can fill a table at its
            // own pace rather than at ours.
            return self.penalise(from, Misbehaviour::BadAddrs);
        }
        peer.awaiting_addrs = false;
        let source = peer.addr.group();
        for addr in addrs {
            if addr.id == self.ours {
                continue;
            }
            // Bucketed by the group that *told* us, not the group being
            // described. That is the whole point: an attacker's reach into the
            // table is bounded by how many source groups they speak from.
            self.book.add(*addr, source);
        }
        Vec::new()
    }

    /// Record a misbehaviour, disconnecting if it was one too many.
    ///
    /// The ban lasts [`BAN_DURATION`] and **is not written to disk**, which is
    /// the one place this crate departs from Bitcoin, whose `banlist.dat`
    /// survives a restart. A persisted ban list is a persisted mistake: a bug in
    /// our own scoring, or a peer wrongly punished during a partition, becomes
    /// permanent and — because nothing here logs a ban to an operator — invisible.
    /// The reason `banlist.dat` exists is that a restart is when an eclipse is
    /// cheapest, and anchors ([`Self::seed_anchors`]) answer that directly.
    pub fn penalise(&mut self, from: PeerId, what: Misbehaviour) -> Vec<Directive> {
        let Some(peer) = self.peers.get_mut(&from) else {
            return Vec::new();
        };
        if peer.reputation.penalise(what) {
            self.banned
                .insert(from, self.uptime.saturating_add(BAN_DURATION));
            self.peers.remove(&from);
            return vec![Directive::Disconnect(from, "banned")];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::MAX_FRAME_LEN;
    use afrolink_crypto::SecretKey;
    use std::net::SocketAddr;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn id(n: u32) -> PeerId {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        seed[4] = 0x5A;
        PeerId::new(SecretKey::from_bytes(&seed).public_key())
    }

    fn addr(n: u32, ip: &str) -> PeerAddr {
        PeerAddr::new(id(n), SocketAddr::new(ip.parse().expect("valid"), 26656))
    }

    fn manager() -> Manager {
        Manager::new(
            PeerId::new(key(200).public_key()),
            AddrBook::new(&key(1)),
            Limits::default(),
        )
    }

    /// One second per tick, so a rate written "per second" reads as itself.
    const TICK: Duration = Duration::from_secs(1);

    fn ping(n: u64) -> PeerMessage {
        PeerMessage::Ping(n)
    }

    #[test]
    fn a_subnet_buys_exactly_one_outbound_slot() {
        // The eclipse defence at connection time. The address book makes the
        // attack expensive to set up; this makes it useless once set up.
        let mut m = manager();
        let first = addr(1, "198.51.100.1");
        assert!(m.on_outbound(first).is_ok());
        assert_eq!(
            m.on_outbound(addr(2, "198.51.100.2")),
            Err(Refusal::GroupInUse)
        );
        assert_eq!(
            m.on_outbound(addr(3, "198.51.200.9")),
            Err(Refusal::GroupInUse),
            "a different /24 in the same /16 is the same group"
        );
        assert!(m.on_outbound(addr(4, "203.0.113.1")).is_ok());
        assert_eq!(m.outbound_count(), 2);
    }

    #[test]
    fn the_dial_policy_never_offers_a_group_already_used() {
        let mut m = manager();
        let mine = addr(1, "198.51.100.1");
        m.book_mut().add(mine, mine.group());
        m.book_mut().mark_good(&mine.id);
        let other = addr(2, "198.51.100.99");
        m.book_mut().add(other, other.group());
        m.book_mut().mark_good(&other.id);

        assert!(m.wants_outbound().is_some());
        m.on_outbound(mine).expect("connects");
        for _ in 0..50 {
            assert_eq!(
                m.wants_outbound(),
                None,
                "the only other peer known shares a group with one already connected"
            );
        }
    }

    #[test]
    fn outbound_and_inbound_slots_are_capped_separately() {
        let limits = Limits {
            max_outbound: 2,
            max_inbound: 3,
            ..Limits::default()
        };
        let mut m = Manager::new(
            PeerId::new(key(200).public_key()),
            AddrBook::new(&key(1)),
            limits,
        );
        assert!(m.on_outbound(addr(1, "203.0.1.1")).is_ok());
        assert!(m.on_outbound(addr(2, "203.1.1.1")).is_ok());
        assert_eq!(m.on_outbound(addr(3, "203.2.1.1")), Err(Refusal::NoRoom));

        // Inbound has its own budget, and is deliberately not group-restricted:
        // refusing inbound by group is a way for an attacker to deny honest
        // peers a seat.
        //
        // Each from a different /16, so the set is already as diverse as three
        // slots can be, and the fourth arrival is from a subnet that already
        // holds a seat. *That* is what makes it a refusal rather than an
        // eviction: it adds no diversity, so evicting for it would be pure loss —
        // and would hand a stranger a way to disconnect a good peer on demand.
        assert!(m.on_inbound(addr(10, "198.51.100.1")).is_ok());
        assert!(m.on_inbound(addr(11, "198.52.100.2")).is_ok());
        assert!(m.on_inbound(addr(12, "198.53.100.3")).is_ok());
        assert_eq!(m.on_inbound(addr(13, "198.51.100.4")), Err(Refusal::NoRoom));
        assert_eq!(m.inbound_count(), 3);
    }

    /// A manager with `max_inbound` slots and nothing else changed.
    fn with_inbound_cap(cap: usize) -> Manager {
        Manager::new(
            PeerId::new(key(200).public_key()),
            AddrBook::new(&key(1)),
            Limits {
                max_inbound: cap,
                ..Limits::default()
            },
        )
    }

    /// Every peer this manager has evicted, from a batch of directives.
    fn evicted(directives: &[Directive]) -> Vec<PeerId> {
        directives
            .iter()
            .filter_map(|d| match d {
                Directive::Disconnect(peer, _) => Some(*peer),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn forty_connections_from_one_subnet_do_not_keep_an_honest_peer_out() {
        // **The attack this exists for**, and the cheapest one there was: the
        // inbound cap alone meant anybody who could open forty sockets held every
        // slot until they chose to leave, and every honest peer was answered
        // `NoRoom`. That is an inbound cap of zero, arrived at by an attacker
        // rather than by configuration.
        let mut m = with_inbound_cap(40);
        for n in 0..40u32 {
            m.on_tick(TICK);
            assert!(
                m.on_inbound(addr(n, &format!("203.0.{}.{}", n / 250, n % 250 + 1)))
                    .is_ok(),
                "the attacker fills the slots, as they are free to do"
            );
        }
        assert_eq!(m.inbound_count(), 40);

        m.on_tick(TICK);
        let honest = addr(900, "198.51.100.7");
        let out = m.on_inbound(honest).expect("an honest peer still gets in");

        assert_eq!(
            evicted(&out).len(),
            1,
            "one peer made room, not none and not many"
        );
        assert!(m.peers().contains(&honest.id));
        assert_eq!(m.inbound_count(), 40, "and the cap still holds");
    }

    #[test]
    fn a_subnet_keeps_exactly_one_inbound_seat_however_many_it_opens() {
        // The eviction rule is the inbound half of the group rule. An attacker
        // who fills the slots from one /16 is protected in exactly one of them,
        // so honest peers from distinct groups displace the rest one by one.
        let mut m = with_inbound_cap(4);
        for n in 0..4u32 {
            m.on_tick(TICK);
            // 203.0.x.y — one /16, four addresses.
            assert!(m.on_inbound(addr(n, &format!("203.0.{n}.1"))).is_ok());
        }
        for n in 0..3u32 {
            m.on_tick(TICK);
            let honest = addr(500 + n, &format!("198.{}.100.1", 51 + n));
            m.on_inbound(honest).expect("displaces an attacker");
            assert!(m.peers().contains(&honest.id));
        }
        // One attacker survives: the longest-connected of their group.
        let attackers = (0..4u32).filter(|n| m.peers().contains(&id(*n))).count();
        assert_eq!(attackers, 1, "a subnet buys one seat, not four");
    }

    #[test]
    fn the_longest_connected_peer_in_a_group_is_the_one_protected() {
        // Protecting the *oldest* rather than the newest is what makes the
        // protected set unoccupiable: an attacker arriving later cannot displace
        // whoever was already there, however many connections they open.
        let mut m = with_inbound_cap(3);
        let established = addr(1, "203.0.1.1");
        m.on_inbound(established).expect("first");
        m.on_tick(TICK);
        m.on_inbound(addr(2, "203.0.2.1"))
            .expect("same group, later");
        m.on_tick(TICK);
        m.on_inbound(addr(3, "203.0.3.1"))
            .expect("same group, later still");

        m.on_tick(TICK);
        let out = m.on_inbound(addr(9, "198.51.100.1")).expect("honest peer");
        assert_eq!(evicted(&out), vec![id(3)], "the youngest goes first");
        assert!(
            m.peers().contains(&established.id),
            "the oldest is protected"
        );
    }

    #[test]
    fn a_peer_that_served_a_block_outlives_one_that_has_served_nothing() {
        // The only evidence a node has that an inbound connection is worth
        // anything. It breaks ties and does no more than that: protecting on it
        // outright would put protection on sale for the price of one block.
        let mut m = with_inbound_cap(3);
        m.set_height(Height(1));
        for n in 1..=3u32 {
            m.on_inbound(addr(n, &format!("203.0.{n}.1"))).expect("in");
            drop(m.on_message(id(n), PeerMessage::Status(Height(9))));
        }
        // One of them is asked for a block and answers it.
        let asked = requested(&m.on_tick(TICK));
        let (server, height) = asked.first().copied().expect("somebody was asked");
        drop(m.on_message(
            server,
            PeerMessage::Block(Box::new(sync_block(height.0, [1; 32]))),
        ));

        let out = m.on_inbound(addr(9, "198.51.100.1")).expect("honest peer");
        assert_eq!(evicted(&out).len(), 1);
        assert!(
            m.peers().contains(&server),
            "a peer that answered a sync request is not the one thrown out"
        );
    }

    #[test]
    fn an_outbound_peer_is_never_evicted_by_a_stranger_dialling_in() {
        // Outbound connections are the eclipse-relevant ones and *this node*
        // chose them. Letting an inbound arrival displace one would hand that
        // choice to whoever dialled in — which is the attack the group rule on
        // outbound slots exists to prevent, reintroduced through the back door.
        // The outbound peer is put in the same group as the inbound pair *and*
        // dialled last, so it is both eligible by group and the youngest — which
        // is to say, exactly what the rule would pick if outbound connections
        // were candidates at all. It survives because they are not.
        let mut m = with_inbound_cap(2);
        m.on_inbound(addr(2, "203.0.2.1"))
            .expect("first inbound slot");
        m.on_tick(TICK);
        m.on_inbound(addr(3, "203.0.3.1"))
            .expect("second inbound slot");
        m.on_tick(TICK);
        let ours = addr(1, "203.0.1.1");
        m.on_outbound(ours)
            .expect("we dialled this one, last of all");
        m.on_tick(TICK);

        let out = m
            .on_inbound(addr(4, "203.0.4.1"))
            .expect("displaces an inbound peer, never the outbound one");
        assert_eq!(evicted(&out), vec![id(3)], "the youngest *inbound* peer");
        assert!(m.peers().contains(&ours.id), "the outbound peer stays");
        assert_eq!(m.outbound_count(), 1);
    }

    #[test]
    fn a_node_refuses_itself_and_its_existing_peers() {
        let mut m = manager();
        let ours = PeerAddr::new(
            PeerId::new(key(200).public_key()),
            "203.0.113.1:26656".parse().expect("valid"),
        );
        assert_eq!(m.on_inbound(ours), Err(Refusal::SelfConnection));

        let peer = addr(1, "203.0.113.7");
        assert!(m.on_inbound(peer).is_ok());
        assert_eq!(m.on_inbound(peer), Err(Refusal::Duplicate));
    }

    #[test]
    fn a_ban_expires_rather_than_lasting_forever() {
        // A permanent ban is a permanent mistake. Several of the things that earn
        // a penalty — a malformed frame, a burst that outran the limit — are
        // reachable by a peer that is merely overloaded or mid-upgrade, and on
        // links that drop out by design that is a Tuesday rather than an attack.
        let mut m = manager();
        let a = addr(1, "203.0.113.1");
        m.on_inbound(a).expect("connects");
        m.penalise(a.id, Misbehaviour::Unforgivable);
        assert!(m.is_banned(&a.id));
        assert_eq!(m.on_inbound(a), Err(Refusal::Banned));

        // Just short of the hour, still out.
        m.on_tick(BAN_DURATION - Duration::from_secs(1));
        assert!(m.is_banned(&a.id));

        m.on_tick(Duration::from_secs(2));
        assert!(!m.is_banned(&a.id), "an hour is a ban, not an exile");
        assert!(m.on_inbound(a).is_ok(), "and the peer may come back");
    }

    #[test]
    fn an_expired_ban_is_forgotten_rather_than_merely_ignored() {
        // Otherwise the set grows for as long as an attacker keeps poking, which
        // is a memory cost with somebody else holding the tap.
        let mut m = manager();
        for n in 0..64u32 {
            let a = addr(n, &format!("203.0.{}.{}", n / 250, n % 250 + 1));
            m.on_inbound(a).expect("connects");
            m.penalise(a.id, Misbehaviour::Unforgivable);
        }
        assert_eq!(m.banned.len(), 64);
        m.on_tick(BAN_DURATION + Duration::from_secs(1));
        assert!(m.banned.is_empty());
    }

    #[test]
    fn a_ban_does_not_reset_when_the_peer_is_penalised_again_from_nowhere() {
        // `penalise` on a peer that is no longer connected does nothing, so a
        // banned peer cannot have its clock restarted by a stray message that
        // arrives after the disconnect.
        let mut m = manager();
        let a = addr(1, "203.0.113.1");
        m.on_inbound(a).expect("connects");
        m.penalise(a.id, Misbehaviour::Unforgivable);
        m.on_tick(BAN_DURATION - Duration::from_secs(1));
        assert!(m.penalise(a.id, Misbehaviour::Unforgivable).is_empty());
        m.on_tick(Duration::from_secs(2));
        assert!(!m.is_banned(&a.id));
    }

    #[test]
    fn an_anchor_is_dialled_before_anything_the_address_book_offers() {
        // The whole point of an anchor. On a restart every outbound slot is on
        // offer at once, drawn from a book an attacker has had hours to shape;
        // dialling last run's peers first keeps two of them off the table at the
        // moment they are cheapest to take.
        let mut m = manager();
        let known = addr(1, "203.0.113.1");
        m.book_mut().add(known, known.group());
        let anchor = addr(2, "198.51.100.1");
        m.seed_anchors([anchor]);

        assert_eq!(m.wants_outbound(), Some(anchor), "the anchor comes first");
        m.on_outbound(anchor).expect("dialled");
        assert_eq!(m.wants_outbound(), Some(known), "then the book as usual");
    }

    #[test]
    fn an_anchor_is_dialled_but_never_trusted() {
        // An anchor is a hint about who to try, not a licence. It passes the same
        // checks as any other candidate — otherwise a file on disk would be a way
        // around the ban list, and an attacker who could write one would have a
        // way around the group rule too.
        let mut m = manager();
        let banned = addr(1, "203.0.113.1");
        m.on_inbound(banned).expect("connects");
        m.penalise(banned.id, Misbehaviour::Unforgivable);
        assert!(m.is_banned(&banned.id));

        let good = addr(2, "198.51.100.1");
        m.seed_anchors([banned, good]);
        assert_eq!(
            m.wants_outbound(),
            Some(good),
            "a banned anchor is skipped, not dialled because a file said so"
        );
    }

    #[test]
    fn a_dead_anchor_is_consumed_rather_than_retried_forever() {
        // An anchor that cannot be used must not be re-offered on every pass: a
        // node that kept proposing a dead anchor would spend its whole dial
        // budget on it instead of finding peers that answer.
        let mut m = manager();
        let known = addr(1, "203.0.113.1");
        m.book_mut().add(known, known.group());
        // Same group as a peer already connected, so it can never be dialled.
        m.on_outbound(addr(3, "198.51.100.3")).expect("connects");
        let clashing = addr(2, "198.51.100.2");
        let usable = addr(4, "192.0.2.1");
        m.seed_anchors([clashing, usable]);

        assert_eq!(
            m.wants_outbound(),
            Some(usable),
            "the unusable anchor is passed over rather than returned"
        );
        m.on_outbound(usable).expect("dialled");
        assert_eq!(
            m.wants_outbound(),
            Some(known),
            "and it is gone: the queue is empty and the book takes over"
        );
    }

    #[test]
    fn at_most_two_anchors_are_kept_however_many_peers_there_are() {
        // Anchoring every outbound slot would mean an attacker who captured this
        // node once keeps it. Two means an attacker who had not captured it
        // before the restart cannot capture it during the restart.
        let mut m = manager();
        for n in 1..=5u32 {
            m.on_outbound(addr(n, &format!("203.{n}.1.1")))
                .expect("out");
            m.on_tick(TICK);
        }
        m.on_inbound(addr(90, "198.51.100.1")).expect("in");
        let anchors = m.anchors();
        assert_eq!(anchors.len(), ANCHOR_COUNT);
        assert!(
            anchors.iter().all(|a| a.id != id(90)),
            "an inbound peer is not an anchor: we did not choose it and cannot dial it"
        );
        assert_eq!(
            anchors.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![id(1), id(2)],
            "the longest-connected outbound peers, because survival is evidence"
        );
    }

    #[test]
    fn a_message_is_relayed_once_and_never_back_to_its_sender() {
        // Without the first rule a gossip network amplifies; without the second
        // a two-node network loops forever on one vote.
        let mut m = manager();
        let a = addr(1, "203.0.1.1");
        let b = addr(2, "203.0.2.1");
        m.on_inbound(a).expect("connects");
        m.on_inbound(b).expect("connects");

        let tx = sample_transaction();
        let message = PeerMessage::Transaction(Box::new(tx));
        let first = m.on_message(a.id, message.clone());
        assert_eq!(first.len(), 1, "delivered to the node, not relayed by us");
        assert!(matches!(first.first(), Some(Directive::Deliver(_))));

        assert!(
            m.on_message(b.id, message).is_empty(),
            "the second copy is already known and produces nothing"
        );
    }

    #[test]
    fn a_relay_excludes_the_peer_that_sent_it() {
        let mut m = manager();
        let a = addr(1, "203.0.1.1");
        m.on_inbound(a).expect("connects");
        let vote = sample_vote();
        let out = m.on_message(a.id, PeerMessage::Vote(Box::new(vote)));
        let relayed = out
            .iter()
            .find_map(|d| match d {
                Directive::Relay(_, excluded) => Some(*excluded),
                _ => None,
            })
            .expect("a vote is relayed");
        assert_eq!(relayed, a.id);
    }

    #[test]
    fn the_seen_set_is_bounded() {
        // An unbounded seen-set is a memory leak with a peer holding the tap.
        let mut seen = Seen::new(4);
        for i in 0..100u8 {
            assert!(seen.insert(Hash32::from_bytes([i; 32])));
        }
        assert!(seen.ids.len() <= 4);
        assert!(seen.order.len() <= 4);
        // And the most recent are the ones kept.
        assert!(!seen.insert(Hash32::from_bytes([99; 32])));
    }

    #[test]
    fn a_peer_that_floods_is_slowed_then_dropped() {
        let limits = Limits {
            messages_per_second: 3,
            burst: Duration::from_secs(1),
            ..Limits::default()
        };
        let mut m = Manager::new(
            PeerId::new(key(200).public_key()),
            AddrBook::new(&key(1)),
            limits,
        );
        let a = addr(1, "203.0.1.1");
        m.on_inbound(a).expect("connects");

        for n in 0..3 {
            assert!(!m.on_message(a.id, ping(n)).is_empty(), "inside the budget");
        }
        // Past the budget the messages stop being answered and start costing.
        for _ in 0..30 {
            drop(m.on_message(a.id, ping(9)));
        }
        assert!(
            m.is_banned(&a.id),
            "a peer that will not slow down is dropped"
        );
        assert!(!m.peers().contains(&a.id));

        // And it stays refused.
        assert_eq!(m.on_inbound(a), Err(Refusal::Banned));
    }

    #[test]
    fn elapsed_time_refills_the_allowance() {
        let limits = Limits {
            messages_per_second: 2,
            burst: Duration::from_secs(1),
            ..Limits::default()
        };
        let mut m = Manager::new(
            PeerId::new(key(200).public_key()),
            AddrBook::new(&key(1)),
            limits,
        );
        let a = addr(1, "203.0.1.1");
        m.on_inbound(a).expect("connects");
        assert!(!m.on_message(a.id, ping(1)).is_empty());
        assert!(!m.on_message(a.id, ping(2)).is_empty());
        assert!(m.on_message(a.id, ping(3)).is_empty(), "allowance spent");
        m.on_tick(TICK);
        assert!(
            !m.on_message(a.id, ping(4)).is_empty(),
            "a second buys two more"
        );
    }

    #[test]
    fn an_unsolicited_address_list_is_penalised() {
        // The injection point for an eclipse: a peer that can push addresses
        // whenever it likes fills a table at its own pace rather than at ours.
        let mut m = manager();
        let a = addr(1, "203.0.1.1");
        m.on_inbound(a).expect("connects");
        let offered = addr(50, "198.51.100.9");

        drop(m.on_message(a.id, PeerMessage::Addrs(vec![offered])));
        assert!(
            m.book().get(&offered.id).is_none(),
            "nothing unsolicited enters the book"
        );

        // Once asked, the same list is accepted.
        m.on_tick(TICK);
        let solicited = m.on_message(a.id, PeerMessage::Addrs(vec![offered]));
        assert!(solicited.is_empty());
        assert!(m.book().get(&offered.id).is_some());
    }

    #[test]
    fn addresses_are_bucketed_by_who_told_us_not_by_what_was_described() {
        // An attacker describing ten thousand addresses from one connection
        // reaches only the buckets their own group can reach.
        let mut m = manager();
        let a = addr(1, "198.51.100.1");
        m.on_inbound(a).expect("connects");
        m.on_tick(TICK);
        let offered: Vec<PeerAddr> = (0..MAX_ADDRS)
            .map(|n| {
                #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_ADDRS")]
                let host = n as u8;
                addr(1_000 + n as u32, &format!("192.0.2.{host}"))
            })
            .collect();
        drop(m.on_message(a.id, PeerMessage::Addrs(offered.clone())));
        let learned = offered
            .iter()
            .filter(|p| m.book().get(&p.id).is_some())
            .count();
        assert!(
            learned < offered.len(),
            "one source group must not be able to place every address it names: \
             {learned} of {} landed",
            offered.len()
        );
        assert!(learned > 0, "and it must be able to place some");
    }

    #[test]
    fn a_ping_is_always_answered_and_never_deduplicated() {
        // A ping is supposed to be repeated. If it entered the seen-set a peer
        // could probe us exactly once, and every later probe would look like a
        // dead connection.
        let mut m = manager();
        let a = addr(1, "203.0.1.1");
        m.on_inbound(a).expect("connects");
        for _ in 0..5 {
            let out = m.on_message(a.id, PeerMessage::Ping(7));
            assert_eq!(
                out,
                vec![Directive::Send(a.id, Box::new(PeerMessage::Pong(7)))]
            );
        }
    }

    #[test]
    fn a_message_from_a_stranger_is_ignored_rather_than_acted_on() {
        let mut m = manager();
        assert!(m.on_message(id(999), ping(1)).is_empty());
    }

    #[test]
    fn an_inbound_peer_is_never_recorded_as_an_address() {
        // What arrives on an inbound connection is an *ephemeral source port*,
        // which dials nothing. Recording it would fill the tried table with
        // addresses nobody can reach and then recommend them to every peer that
        // asks — and it would let an attacker into a node's gossip sample for
        // the price of one outgoing connection.
        let mut m = manager();
        let caller = addr(1, "203.0.113.7");
        m.on_inbound(caller).expect("connects");
        assert!(m.peers().contains(&caller.id), "it is a peer");
        assert!(
            m.book().get(&caller.id).is_none(),
            "but not an address this node will hand out"
        );

        // A peer this node dialled is different: that address demonstrably works.
        let dialled = addr(2, "198.51.100.9");
        m.on_outbound(dialled).expect("connects");
        assert!(m.book().get(&dialled.id).is_some());
        assert_eq!(m.book().tried_addresses(), vec![dialled]);
    }

    #[test]
    fn a_disconnected_peer_frees_its_slot_and_its_group() {
        let mut m = manager();
        let a = addr(1, "198.51.100.1");
        m.on_outbound(a).expect("connects");
        assert_eq!(
            m.on_outbound(addr(2, "198.51.100.2")),
            Err(Refusal::GroupInUse)
        );
        m.on_disconnect(&a.id);
        assert_eq!(m.outbound_count(), 0);
        assert!(m.on_outbound(addr(2, "198.51.100.2")).is_ok());
    }

    /// Whether a peer offering `offered` messages a second, evenly spread,
    /// survives one second when the manager is ticked `ticks` times across it.
    ///
    /// Survival rather than a count, because a count conflates two things: how
    /// much the limiter let through, and how much reputation the refusals cost.
    /// Ticking more often means more refusals for the same offered load, so
    /// counting accepted messages measures the ban policy and not the rate.
    fn survives_one_second(ticks: u32, offered: u64, limits: Limits) -> bool {
        let mut m = Manager::new(
            PeerId::new(key(200).public_key()),
            AddrBook::new(&key(1)),
            limits,
        );
        let a = addr(1, "203.0.1.1");
        m.on_inbound(a).expect("connects");
        let ticks = ticks.max(1);
        let slice = Duration::from_millis(u64::from(1_000 / ticks));
        let per_slice = offered / u64::from(ticks);

        for _ in 0..ticks {
            m.on_tick(slice);
            for n in 0..per_slice {
                drop(m.on_message(a.id, ping(n)));
            }
        }
        !m.is_banned(&a.id) && m.peers().contains(&a.id)
    }

    #[test]
    fn a_rate_limit_means_the_same_thing_however_often_the_caller_ticks() {
        // The defect this replaces, stated as a property. The limit used to be
        // "512 messages per tick", so a daemon that ticked at 20 Hz instead of
        // 2 Hz silently granted its peers ten times the traffic — a security
        // bound loosened tenfold by an unrelated decision about loop latency,
        // with nothing anywhere to notice it.
        //
        // Now the same offered load gets the same verdict however finely the
        // second is sliced.
        let limits = Limits {
            messages_per_second: 100,
            burst: Duration::from_secs(1),
            ..Limits::default()
        };
        for ticks in [1u32, 2, 10, 50] {
            assert!(
                survives_one_second(ticks, 100, limits),
                "a peer sending exactly the limit was dropped at {ticks} ticks a second"
            );
            assert!(
                !survives_one_second(ticks, 5_000, limits),
                "a peer sending fifty times the limit survived at {ticks} ticks a second"
            );
        }
    }

    #[test]
    fn one_enormous_frame_a_second_is_still_a_flood() {
        // A peer well inside any message budget can still saturate a link, which
        // is why CometBFT denominates its limit in bytes. Ours does both, because
        // neither implies the other.
        let limits = Limits {
            messages_per_second: 1_000_000,
            bytes_per_second: 1_024,
            burst: Duration::from_secs(1),
            ..Limits::default()
        };
        let mut m = Manager::new(
            PeerId::new(key(200).public_key()),
            AddrBook::new(&key(1)),
            limits,
        );
        let a = addr(1, "203.0.1.1");
        m.on_inbound(a).expect("connects");

        // The byte bucket's floor admits one maximum-size frame however tight the
        // rate is: a limiter that cannot pass a legal block stops the chain
        // rather than an attacker.
        assert!(
            !m.on_message_sized(a.id, ping(1), MAX_FRAME_LEN).is_empty(),
            "one maximum-size frame must always be affordable"
        );
        // The next one is refused on bytes alone, with the message count barely
        // touched — one of a million.
        assert!(
            m.on_message_sized(a.id, ping(2), MAX_FRAME_LEN).is_empty(),
            "the byte allowance is spent even though the message allowance is not"
        );
        // And a peer that keeps it up is dropped.
        for n in 0..40u64 {
            drop(m.on_message_sized(a.id, ping(n), MAX_FRAME_LEN));
        }
        assert!(
            m.is_banned(&a.id) || !m.peers().contains(&a.id),
            "a peer sending maximum-size frames without pause must be dropped"
        );
    }

    #[test]
    fn a_quiet_peer_may_bank_a_burst_but_not_an_unbounded_one() {
        // Votes for a round arrive together and a sync reply arrives all at once,
        // so a limiter with no burst allowance punishes the normal case. The
        // bound is what keeps it a limit.
        let limits = Limits {
            messages_per_second: 10,
            burst: Duration::from_secs(2),
            ..Limits::default()
        };
        let mut m = Manager::new(
            PeerId::new(key(200).public_key()),
            AddrBook::new(&key(1)),
            limits,
        );
        let a = addr(1, "203.0.1.1");
        m.on_inbound(a).expect("connects");

        // An hour of silence banks the burst window and not an hour.
        m.on_tick(Duration::from_secs(3_600));
        let mut accepted = 0;
        for n in 0..1_000u64 {
            if m.on_message(a.id, ping(n)).is_empty() {
                break;
            }
            accepted += 1;
        }
        assert_eq!(
            accepted, 20,
            "two seconds of burst at ten a second, not an hour of it"
        );
    }

    // -- catching up --------------------------------------------------------

    /// A manager with `count` peers connected, all claiming height `tip`.
    fn syncing(ours: Height, peers: u32, tip: u64) -> (Manager, Vec<PeerAddr>) {
        let mut m = manager();
        m.set_height(ours);
        let addrs: Vec<PeerAddr> = (0..peers)
            .map(|n| addr(n, &format!("203.0.{n}.1")))
            .collect();
        for a in &addrs {
            m.on_inbound(*a).expect("connects");
            drop(m.on_message(a.id, PeerMessage::Status(Height(tip))));
        }
        (m, addrs)
    }

    /// Every height a tick asked for, in the order asked.
    fn requested(directives: &[Directive]) -> Vec<(PeerId, Height)> {
        directives
            .iter()
            .filter_map(|d| match d {
                Directive::Send(peer, message) => match message.as_ref() {
                    PeerMessage::GetBlock(height) => Some((*peer, *height)),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    fn applied(directives: &[Directive]) -> Vec<Height> {
        directives
            .iter()
            .filter_map(|d| match d {
                Directive::ApplyBlock(_, sync) => Some(sync.height()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_node_at_the_tip_asks_for_nothing() {
        // The common case, and the one that must cost nothing: a node level with
        // its peers should not be issuing a request every tick forever.
        let (mut m, _) = syncing(Height(9), 3, 8);
        assert!(requested(&m.on_tick(TICK)).is_empty());
        assert!(!m.is_behind());
    }

    #[test]
    fn a_node_that_is_behind_asks_for_the_heights_it_is_missing() {
        // Lowest first, and never twice for the same height. Asking for the *tip*
        // first is the tempting mistake: every reply then has to be held, because
        // none of them can be applied until the bottom of the gap arrives.
        let (mut m, _) = syncing(Height(5), 4, 100);
        let asked = requested(&m.on_tick(TICK));
        let heights: Vec<u64> = asked.iter().map(|(_, h)| h.0).collect();
        assert_eq!(heights, vec![5, 6, 7, 8], "lowest first, one per peer");

        let mut peers: Vec<PeerId> = asked.iter().map(|(p, _)| *p).collect();
        peers.sort_unstable();
        peers.dedup();
        assert_eq!(peers.len(), 4, "one request per peer, spread across them");
    }

    #[test]
    fn no_more_requests_are_outstanding_than_the_limit_allows() {
        // Each outstanding request is a promise to hold a reply in memory.
        let (mut m, _) = syncing(Height(1), 32, 10_000);
        let first = requested(&m.on_tick(TICK));
        assert_eq!(first.len(), MAX_BLOCKS_IN_FLIGHT);
        // And a second tick, with nothing answered, adds none.
        assert!(requested(&m.on_tick(TICK)).is_empty());
    }

    #[test]
    fn a_peer_is_never_asked_for_a_height_it_has_not_claimed() {
        // A peer's status is not trusted for correctness, but it is respected for
        // routing: asking a node at height 3 for height 900 wastes a request slot
        // that a peer who has it could have used.
        let mut m = manager();
        m.set_height(Height(1));
        let low = addr(1, "203.0.1.1");
        let high = addr(2, "203.0.2.1");
        m.on_inbound(low).expect("connects");
        m.on_inbound(high).expect("connects");
        drop(m.on_message(low.id, PeerMessage::Status(Height(1))));
        drop(m.on_message(high.id, PeerMessage::Status(Height(50))));

        let asked = requested(&m.on_tick(TICK));
        for (peer, height) in &asked {
            if *peer == low.id {
                assert_eq!(height.0, 1, "the shallow peer is only asked what it has");
            }
        }
        assert!(asked.iter().any(|(p, _)| *p == high.id));
    }

    #[test]
    fn a_staged_block_is_released_when_the_height_reaches_it() {
        // **[10 §17](../../../docs/10-network-hardening.md).** `drain_staged` had
        // exactly one caller, inside `on_block`, so a staged block was only ever
        // released by the arrival of *another* block. Every other way the height
        // moves — `set_height`, called after every apply, succeeded or failed —
        // left applicable blocks sitting in the buffer, and `schedule_sync`
        // counts staged heights as already claimed, so it asked for nothing, so
        // nothing arrived, so `on_block` never ran again.
        //
        // A node with the blocks it needed, in its own hands, waiting forever for
        // a message that could not come. Seen in a real cluster as
        // `need=7 best=8 behind=true staged=[7, 8]`.
        let (mut m, addrs) = syncing(Height(1), 2, 10);
        m.on_tick(TICK);

        // Two blocks arrive out of order: 2 first, so it cannot be applied yet.
        let out = m.on_message(
            addrs[0].id,
            PeerMessage::Block(Box::new(sync_block(2, [2; 32]))),
        );
        assert!(applied(&out).is_empty(), "height 2 cannot precede height 1");

        // Now the node reaches height 2 by some other route — the apply of
        // height 1 landing, which reports back through `set_height`.
        m.set_height(Height(2));
        assert_eq!(
            applied(&m.on_tick(TICK)),
            vec![Height(2)],
            "a staged block the node can now apply must be released by the tick, \
             not only by the arrival of another block"
        );
    }

    #[test]
    fn a_node_holding_what_it_needs_does_not_wait_for_a_message_to_notice() {
        // The deadlock stated as its own property. Once a needed height is
        // staged, `schedule_sync` will not request it again — correctly, since
        // asking twice for a block already held is waste — so if nothing else
        // drains the buffer the node is stuck with the answer in its hands.
        let (mut m, addrs) = syncing(Height(5), 2, 10);
        m.on_tick(TICK);
        drop(m.on_message(
            addrs[0].id,
            PeerMessage::Block(Box::new(sync_block(6, [6; 32]))),
        ));
        m.set_height(Height(6));

        // No further messages. Only ticks.
        let released: Vec<Height> = (0..3).flat_map(|_| applied(&m.on_tick(TICK))).collect();
        assert_eq!(released, vec![Height(6)]);
    }

    #[test]
    fn a_peer_that_answers_late_is_not_treated_as_an_attacker() {
        // A request abandoned on timeout is handed to somebody else, and the
        // original peer's reply then lands against a cleared slot. Twenty points
        // for that — five of them a ban — punishes a peer for being slow on links
        // this network *assumes* are slow. Observed driving all four of a stuck
        // node's honest peers to a score of 40, three answers short of banning
        // the only nodes it could have caught up from.
        //
        // The state is set up directly rather than by waiting for a timeout and
        // hoping the re-request lands on a different peer: whether it does is a
        // matter of rotation, and two earlier versions of this test passed with
        // the fix reverted because the peer simply got asked again.
        let (mut m, addrs) = syncing(Height(1), 2, 10);
        let slow = addrs[0].id;
        {
            let peer = m.peers.get_mut(&slow).expect("connected");
            peer.awaiting_block = None;
            peer.abandoned = Some(Height(1));
        }
        assert_eq!(m.reputation(&slow), Some(0));

        drop(m.on_message(slow, PeerMessage::Block(Box::new(sync_block(1, [7; 32])))));
        assert_eq!(
            m.reputation(&slow),
            Some(0),
            "a late answer to a question this node asked must cost the peer nothing"
        );
        assert!(
            m.staged.contains_key(&Height(1)) || m.height() > Height(1),
            "and the block it sent is used rather than thrown away"
        );
    }

    #[test]
    fn a_timed_out_request_is_remembered_as_abandoned() {
        // The other half: the forgiveness above is only reachable because the
        // timeout records what it gave up on.
        let (mut m, addrs) = syncing(Height(1), 1, 10);
        let asked = requested(&m.on_tick(TICK));
        let (peer, height) = *asked.first().expect("a request went out");
        assert_eq!(peer, addrs[0].id);
        for _ in 0..=REQUEST_TIMEOUT_TICKS {
            m.on_tick(TICK);
        }
        assert_eq!(
            m.peers.get(&peer).and_then(|p| p.abandoned),
            Some(height),
            "a request given up on must be remembered, or its answer looks unsolicited"
        );
    }

    #[test]
    fn only_the_height_this_node_asked_for_is_forgiven() {
        // The narrowness is the point: the rule the next two tests state — a peer
        // must not get to choose which heights this node holds in memory — has to
        // survive. Only the height this node actually asked *this* peer for is
        // forgiven; anything else is still unsolicited and still costs.
        let (mut m, addrs) = syncing(Height(1), 2, 10);
        let slow = addrs[0].id;
        {
            let peer = m.peers.get_mut(&slow).expect("connected");
            peer.awaiting_block = None;
            peer.abandoned = Some(Height(1));
        }

        drop(m.on_message(slow, PeerMessage::Block(Box::new(sync_block(4, [9; 32])))));
        assert_eq!(
            m.reputation(&slow),
            Some(Misbehaviour::BadBlock.penalty()),
            "a height nobody asked this peer for is still unsolicited"
        );
        assert!(!m.staged.contains_key(&Height(4)), "and it is not kept");
    }

    #[test]
    fn a_block_nobody_asked_for_is_penalised() {
        // An unsolicited block is up to four mebibytes a peer decided this node
        // should spend memory and a certificate verification on. Same rule as an
        // unsolicited address list, at a heavier price.
        let (mut m, addrs) = syncing(Height(1), 1, 10);
        let out = m.on_message(
            addrs[0].id,
            PeerMessage::Block(Box::new(sync_block(1, [7; 32]))),
        );
        assert!(applied(&out).is_empty(), "and it is certainly not applied");
        assert!(m.staged.is_empty());
    }

    #[test]
    fn an_answer_to_a_different_question_is_refused() {
        // Asked for height 1, sent height 2. Accepting it would let a peer choose
        // which heights this node holds in memory rather than this node choosing.
        let (mut m, addrs) = syncing(Height(1), 1, 10);
        m.on_tick(TICK);
        let out = m.on_message(
            addrs[0].id,
            PeerMessage::Block(Box::new(sync_block(2, [7; 32]))),
        );
        assert!(applied(&out).is_empty());
        assert!(m.staged.is_empty());
    }

    #[test]
    fn blocks_are_released_only_in_contiguous_order() {
        // Requests go out in parallel, so replies arrive in whatever order the
        // network delivers them — and a block cannot be applied before its
        // parent. This is the buffer that makes the difference survivable.
        let (mut m, _addrs) = syncing(Height(1), 3, 10);
        let asked = requested(&m.on_tick(TICK));
        assert_eq!(asked.len(), 3);

        // The middle one comes back first: nothing may be applied.
        let (peer_of_2, _) = asked
            .iter()
            .find(|(_, h)| h.0 == 2)
            .copied()
            .expect("asked");
        let out = m.on_message(
            peer_of_2,
            PeerMessage::Block(Box::new(sync_block(2, [2; 32]))),
        );
        assert!(
            applied(&out).is_empty(),
            "height 2 cannot be applied before height 1"
        );

        // Then the bottom of the gap, which releases both, in order.
        let (peer_of_1, _) = asked
            .iter()
            .find(|(_, h)| h.0 == 1)
            .copied()
            .expect("asked");
        let out = m.on_message(
            peer_of_1,
            PeerMessage::Block(Box::new(sync_block(1, [1; 32]))),
        );
        assert_eq!(
            applied(&out),
            vec![Height(1), Height(2)],
            "the parent first, then the child that was waiting on it"
        );
        assert_eq!(m.height(), Height(3));
    }

    #[test]
    fn the_staging_buffer_is_bounded() {
        // Otherwise a peer answering only with far-future heights fills a node's
        // memory with blocks it can never apply.
        let (mut m, addrs) = syncing(Height(1), 1, 10_000);
        for n in 2..(MAX_STAGED_BLOCKS as u64 + 40) {
            // Force the request so each reply is "solicited", then answer it.
            m.peers
                .get_mut(&addrs[0].id)
                .expect("connected")
                .awaiting_block = Some(Height(n));
            #[expect(clippy::cast_possible_truncation, reason = "test fixture")]
            let seed = n as u8;
            drop(m.on_message(
                addrs[0].id,
                PeerMessage::Block(Box::new(sync_block(n, [seed; 32]))),
            ));
        }
        assert!(m.staged.len() <= MAX_STAGED_BLOCKS);
    }

    #[test]
    fn nothing_is_requested_beyond_what_the_buffer_can_hold() {
        // A gap at the bottom must not turn into blocks arriving that have to be
        // thrown away.
        let (mut m, _) = syncing(Height(1), 32, 1_000_000);
        for (_, height) in requested(&m.on_tick(TICK)) {
            assert!(height.0 <= 1 + MAX_STAGED_BLOCKS as u64);
        }
    }

    #[test]
    fn a_stalled_peer_loses_its_request_to_someone_else() {
        // A peer that does not answer may be slow rather than malicious. The
        // request is abandoned rather than punished, and the height goes to
        // somebody who will answer it.
        let (mut m, addrs) = syncing(Height(1), 1, 10);
        let first = requested(&m.on_tick(TICK));
        assert_eq!(first.len(), 1);
        let asked_again = (0..=REQUEST_TIMEOUT_TICKS).any(|_| requested(&m.on_tick(TICK)) == first);
        assert!(asked_again, "the same height, asked again");
        assert!(!m.is_banned(&addrs[0].id), "being slow is not misbehaviour");
    }

    #[test]
    fn a_refusal_stops_this_node_asking_that_peer_for_that_gap() {
        // Silence and "I do not have it" are different facts. A node that cannot
        // tell them apart wastes a request window on every pruned peer it meets,
        // every tick, for as long as they stay connected.
        let (mut m, addrs) = syncing(Height(1), 1, 10);
        let asked = requested(&m.on_tick(TICK));
        assert_eq!(asked.len(), 1);
        drop(m.on_message(addrs[0].id, PeerMessage::NoBlock(Height(1))));
        assert!(
            requested(&m.on_tick(TICK)).is_empty(),
            "it said it does not have this, so it is not asked again"
        );
    }

    #[test]
    fn a_block_that_could_not_be_applied_is_asked_for_again() {
        // The manager advances optimistically when it hands a block over. This is
        // what makes that safe: the transport reports the node's real height back,
        // and the height that failed is requested afresh rather than skipped.
        let (mut m, addrs) = syncing(Height(1), 1, 10);
        m.on_tick(TICK);
        let out = m.on_message(
            addrs[0].id,
            PeerMessage::Block(Box::new(sync_block(1, [1; 32]))),
        );
        assert_eq!(applied(&out), vec![Height(1)]);
        assert_eq!(
            m.height(),
            Height(2),
            "advanced on the assumption it applied"
        );

        // It did not apply. The node is still at height 1.
        m.set_height(Height(1));
        assert_eq!(requested(&m.on_tick(TICK)), vec![(addrs[0].id, Height(1))]);
    }

    #[test]
    fn a_request_for_a_block_is_a_directive_rather_than_a_lookup() {
        // The manager has no store in it and is not going to acquire one: what to
        // serve is policy, where it is kept is the transport's business.
        let (mut m, addrs) = syncing(Height(9), 1, 8);
        assert_eq!(
            m.on_message(addrs[0].id, PeerMessage::GetBlock(Height(3))),
            vec![Directive::ServeBlock(addrs[0].id, Height(3))]
        );
    }

    #[test]
    fn a_node_announces_what_it_has_rather_than_what_it_is_working_on() {
        // Peers cannot ask this node for blocks they do not know it has, so a node
        // that never announces is a node nobody ever syncs from. And the number
        // has to be the *committed* height: announcing the working height, 42,
        // would have every peer ask for a block that does not exist yet, on every
        // tick, for as long as they stay connected.
        let (mut m, _) = syncing(Height(42), 1, 41);
        assert!(
            m.on_tick(TICK)
                .contains(&Directive::Broadcast(Box::new(PeerMessage::Status(
                    Height(41)
                ))))
        );
    }

    // -- fixtures -----------------------------------------------------------

    fn sync_block(height: u64, app: [u8; 32]) -> SyncBlock {
        use afrolink_executor::{Block, BlockHeader};
        use afrolink_primitives::{ChainId, Round, Timestamp};
        let header = BlockHeader {
            chain_id: ChainId::new("afrolink-1").expect("valid"),
            height: Height(height),
            time: Timestamp::from_millis(1_700_000_000_000),
            parent: Hash32::from_bytes([0; 32]),
            tx_root: Block::tx_root(&[]),
            app_hash: Hash32::from_bytes(app),
            outcome_root: Hash32::from_bytes([0; 32]),
            validators_hash: Hash32::from_bytes([0; 32]),
            next_validators_hash: Hash32::from_bytes([0; 32]),
        };
        let block_id = header.id();
        SyncBlock {
            block: Block {
                header,
                transactions: Vec::new(),
            },
            // Deliberately unverifiable. Nothing in this module checks a
            // certificate — that is `Node::apply_synced`'s job, and a fixture that
            // implied otherwise would be claiming a guarantee this layer does not
            // give.
            commit: afrolink_consensus::Commit::new(Height(height), Round(0), block_id, Vec::new()),
        }
    }

    fn sample_transaction() -> afrolink_types::Transaction {
        use afrolink_primitives::{Amount, ChainId, Denom, Height};
        use afrolink_types::{Fee, Message, TxBody};
        TxBody {
            chain_id: ChainId::new("afrolink-1").expect("valid"),
            sender: afrolink_crypto::Address::from_public_key(&key(1).public_key()),
            nonce: 0,
            valid_until: Height(1_000),
            fee: Fee::new(Amount::from_units(1_000), Denom::native()),
            messages: vec![Message::Transfer {
                to: afrolink_crypto::Address::from_public_key(&key(2).public_key()),
                denom: Denom::native(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
            memo: String::new(),
        }
        .sign(&key(1))
    }

    fn sample_vote() -> afrolink_consensus::SignedVote {
        use afrolink_consensus::{Vote, VoteType};
        use afrolink_primitives::{ChainId, Height, Round};
        Vote {
            chain_id: ChainId::new("afrolink-1").expect("valid"),
            height: Height(7),
            round: Round(0),
            vote_type: VoteType::Prevote,
            block_id: Some(Hash32::from_bytes([9; 32])),
            validator: afrolink_crypto::Address::from_public_key(&key(1).public_key()),
        }
        .sign(&key(1))
    }
}
