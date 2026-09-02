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
//! **A peer that talks too fast is slowed, then dropped.** The limit is counted
//! per tick rather than per second, so the policy has no clock in it.
//!
//! # And the rule that keeps the network from being captured
//!
//! **No two outbound connections into the same [`AddrGroup`].** The address book
//! makes an eclipse expensive to *set up*; this makes it expensive to *use*,
//! because owning a subnet buys exactly one of a node's outbound slots. Inbound
//! connections are capped but not group-restricted, because refusing inbound by
//! group is itself a way for an attacker to deny honest peers a seat.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use afrolink_crypto::hash::Hash32;
use afrolink_node::Event;

use crate::addrbook::AddrBook;
use crate::peer::{AddrGroup, Misbehaviour, PeerAddr, PeerId, Reputation};
use crate::wire::{MAX_ADDRS, PeerMessage};

/// How many peers a node keeps, and how fast they may talk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Connections this node makes. The eclipse-relevant number.
    pub max_outbound: usize,
    /// Connections this node accepts.
    pub max_inbound: usize,
    /// Gossip ids remembered, for deduplication.
    pub seen_capacity: usize,
    /// Messages one peer may send between ticks.
    pub messages_per_tick: u32,
}

impl Default for Limits {
    /// Eight out, forty in — Bitcoin's shape and for its reasons.
    ///
    /// Outbound is small because each one must be into a distinct group, and
    /// because they are the connections an attacker has to capture *all* of to
    /// eclipse a node. Inbound is generous because refusing inbound cheaply is
    /// how a network stops new nodes joining.
    fn default() -> Self {
        Self {
            max_outbound: 8,
            max_inbound: 40,
            seen_capacity: 8_192,
            messages_per_tick: 512,
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
    /// Close this connection.
    Disconnect(PeerId, &'static str),
}

/// One connected peer.
#[derive(Debug, Clone)]
struct Connected {
    addr: PeerAddr,
    outbound: bool,
    reputation: Reputation,
    /// Messages received since the last tick.
    budget: u32,
    /// Whether we have asked this peer for addresses and not yet been answered.
    awaiting_addrs: bool,
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
    banned: BTreeSet<PeerId>,
    seen: Seen,
    limits: Limits,
    cursor: u64,
}

impl Manager {
    /// A manager for a node with this identity and address book.
    #[must_use]
    pub fn new(ours: PeerId, book: AddrBook, limits: Limits) -> Self {
        Self {
            ours,
            book,
            peers: BTreeMap::new(),
            banned: BTreeSet::new(),
            seen: Seen::new(limits.seen_capacity),
            limits,
            cursor: 0,
        }
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

    /// Whether this peer is refused on sight.
    #[must_use]
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.banned.contains(peer)
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
        self.cursor = self.cursor.wrapping_add(1);
        let cursor = self.cursor;
        self.book
            .select(&avoid, cursor)
            .filter(|candidate| !self.banned.contains(&candidate.id) && candidate.id != self.ours)
    }

    /// Accept a connection this node made.
    ///
    /// # Errors
    /// Returns why the connection should be dropped instead.
    pub fn on_outbound(&mut self, addr: PeerAddr) -> Result<(), Refusal> {
        self.admit(addr, true)
    }

    /// Accept a connection a peer made to this node.
    ///
    /// # Errors
    /// Returns why the connection should be dropped instead.
    pub fn on_inbound(&mut self, addr: PeerAddr) -> Result<(), Refusal> {
        self.admit(addr, false)
    }

    fn admit(&mut self, addr: PeerAddr, outbound: bool) -> Result<(), Refusal> {
        if addr.id == self.ours {
            return Err(Refusal::SelfConnection);
        }
        if self.banned.contains(&addr.id) {
            return Err(Refusal::Banned);
        }
        if self.peers.contains_key(&addr.id) {
            return Err(Refusal::Duplicate);
        }
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
            return Err(Refusal::NoRoom);
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
                budget: self.limits.messages_per_tick,
                awaiting_addrs: false,
            },
        );
        Ok(())
    }

    /// Forget a peer that has gone away.
    pub fn on_disconnect(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    /// Record that a dial did not work.
    pub fn on_dial_failed(&mut self, peer: &PeerId) {
        self.book.mark_failed(peer);
    }

    /// Refresh every peer's message budget, and ask a peer for addresses.
    ///
    /// The clock enters the policy here and nowhere else. What "a tick" is worth
    /// is the transport's business; whether a peer has spent its budget is this
    /// module's.
    pub fn on_tick(&mut self) -> Vec<Directive> {
        for peer in self.peers.values_mut() {
            peer.budget = self.limits.messages_per_tick;
        }
        self.cursor = self.cursor.wrapping_add(1);
        // Ask exactly one peer per tick, in rotation. Asking everyone at once
        // makes a node's address book a reflection of whoever answers fastest,
        // which is the peer closest to it — and closeness is something an
        // attacker on the path controls.
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        if ids.is_empty() {
            return Vec::new();
        }
        let Ok(index) = usize::try_from(self.cursor.checked_rem(ids.len() as u64).unwrap_or(0))
        else {
            return Vec::new();
        };
        let Some(target) = ids.get(index).copied() else {
            return Vec::new();
        };
        if let Some(peer) = self.peers.get_mut(&target) {
            peer.awaiting_addrs = true;
        }
        vec![Directive::Send(target, Box::new(PeerMessage::GetAddrs))]
    }

    /// Handle one message from one peer.
    #[must_use]
    pub fn on_message(&mut self, from: PeerId, message: PeerMessage) -> Vec<Directive> {
        let Some(peer) = self.peers.get_mut(&from) else {
            // A message from someone we are not connected to. Nothing to do and
            // nothing to punish: the connection is already gone.
            return Vec::new();
        };
        match peer.budget.checked_sub(1) {
            Some(left) => peer.budget = left,
            None => return self.penalise(from, Misbehaviour::TooFast),
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
        }
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
    pub fn penalise(&mut self, from: PeerId, what: Misbehaviour) -> Vec<Directive> {
        let Some(peer) = self.peers.get_mut(&from) else {
            return Vec::new();
        };
        if peer.reputation.penalise(what) {
            self.banned.insert(from);
            self.peers.remove(&from);
            return vec![Directive::Disconnect(from, "banned")];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn ping(n: u64) -> PeerMessage {
        PeerMessage::Ping(n)
    }

    #[test]
    fn a_subnet_buys_exactly_one_outbound_slot() {
        // The eclipse defence at connection time. The address book makes the
        // attack expensive to set up; this makes it useless once set up.
        let mut m = manager();
        let first = addr(1, "198.51.100.1");
        assert_eq!(m.on_outbound(first), Ok(()));
        assert_eq!(
            m.on_outbound(addr(2, "198.51.100.2")),
            Err(Refusal::GroupInUse)
        );
        assert_eq!(
            m.on_outbound(addr(3, "198.51.200.9")),
            Err(Refusal::GroupInUse),
            "a different /24 in the same /16 is the same group"
        );
        assert_eq!(m.on_outbound(addr(4, "203.0.113.1")), Ok(()));
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
        assert!(m.on_inbound(addr(10, "198.51.100.1")).is_ok());
        assert!(m.on_inbound(addr(11, "198.51.100.2")).is_ok());
        assert!(m.on_inbound(addr(12, "198.51.100.3")).is_ok());
        assert_eq!(m.on_inbound(addr(13, "198.51.100.4")), Err(Refusal::NoRoom));
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
            messages_per_tick: 3,
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
    fn a_tick_refreshes_the_budget() {
        let limits = Limits {
            messages_per_tick: 2,
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
        assert!(m.on_message(a.id, ping(3)).is_empty(), "budget spent");
        m.on_tick();
        assert!(!m.on_message(a.id, ping(4)).is_empty(), "budget refreshed");
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
        m.on_tick();
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
        m.on_tick();
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

    // -- fixtures -----------------------------------------------------------

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
