//! Which peers a node knows about, and why an attacker cannot become all of
//! them.
//!
//! # The attack this exists for
//!
//! An **eclipse attack** does not break cryptography. It fills a victim's
//! address book with addresses the attacker controls, waits for a restart, and
//! then owns every connection the victim makes. From inside an eclipse, a
//! validator can be shown a partial view of the network, fed a stale height, or
//! partitioned from the two thirds it needs — and every message it receives is
//! perfectly well signed.
//!
//! [Heilman et al. (USENIX Security 2015)][heilman] did this to Bitcoin with a
//! few thousand addresses. The defences Bitcoin adopted afterwards are the ones
//! implemented here, because they are the ones that worked.
//!
//! # Three rules, and each is doing separate work
//!
//! **1. Addresses are bucketed by the *group* that told us about them.** An
//! attacker with 65 000 addresses in one /16 can reach only as many buckets as
//! they have distinct source groups, not as many as they have addresses. Filling
//! the table therefore costs address *diversity*, which costs money and
//! relationships, rather than address *count*, which costs nothing.
//!
//! **2. Bucket placement is salted with a secret only this node holds.** Without
//! that, an attacker computes offline exactly which addresses land in which
//! bucket and crafts a set that fills the table with the minimum possible
//! effort. With it, they have to guess.
//!
//! **3. Tried and new are separate tables.** An address only reaches *tried* by
//! having actually completed a handshake with us. Flooding costs nothing;
//! answering costs an attacker a real host, and the table a node prefers to dial
//! from is the one that is expensive to enter.
//!
//! And above all of them, in [`crate::manager`], the rule that makes the rest
//! matter: **no two outbound connections into the same group.**
//!
//! # Where this is weaker than Bitcoin's, deliberately
//!
//! * **An address occupies one new bucket, not up to eight.** Bitcoin's
//!   multi-bucket placement makes an address more expensive to evict. It also
//!   makes the table's occupancy much harder to reason about, and at this
//!   network's size the simpler rule is the one that can be checked by reading.
//! * **Groups are `/16` and `/32`, never ASNs.** The [Erebus attack][erebus] is
//!   mounted by a network-level adversary that already holds many prefixes, and
//!   grouping by prefix does nothing against it. Bitcoin's answer is a shipped
//!   IP-to-ASN map; that is a data-distribution problem this project has not
//!   solved, and pretending a /16 is an AS would be worse than saying so.
//!
//! [heilman]: https://dl.acm.org/doi/10.5555/2831143.2831152
//! [erebus]: https://erebus-attack.comp.nus.edu.sg/

use std::collections::BTreeMap;

use afrolink_crypto::SecretKey;
use afrolink_crypto::hash::{Domain, Hash32, hash_parts};

use crate::peer::{AddrGroup, PeerAddr, PeerId};

/// Buckets in the new table.
pub const NEW_BUCKETS: u64 = 256;
/// Buckets in the tried table.
pub const TRIED_BUCKETS: u64 = 64;
/// Entries one bucket holds.
pub const BUCKET_SIZE: usize = 8;

/// New buckets any one source group may place addresses into.
///
/// The number that decides what an eclipse costs. A source controlling one group
/// can reach at most this many of [`NEW_BUCKETS`], so filling the table takes
/// `NEW_BUCKETS / NEW_BUCKETS_PER_SOURCE` distinct source groups at the very
/// least — and each of those has to actually talk to us.
pub const NEW_BUCKETS_PER_SOURCE: u64 = 32;

/// Tried buckets any one address group may occupy.
pub const TRIED_BUCKETS_PER_GROUP: u64 = 4;

/// What the book remembers about one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Where to reach it.
    pub addr: PeerAddr,
    /// Consecutive failed attempts since it last worked.
    pub failures: u32,
    /// Whether a handshake with it has ever completed.
    pub tried: bool,
}

/// A node's knowledge of the network.
pub struct AddrBook {
    /// Everything known, by identity. An address exists here exactly once.
    entries: BTreeMap<PeerId, Entry>,
    /// New-table buckets, holding identities.
    new: BTreeMap<u64, Vec<PeerId>>,
    /// Tried-table buckets.
    tried: BTreeMap<u64, Vec<PeerId>>,
    /// The per-node secret that salts bucket placement.
    salt: Hash32,
}

impl AddrBook {
    /// An empty book, salted from this node's own key.
    ///
    /// Derived from the **secret** key rather than the public one, on purpose.
    /// A salt an attacker can compute is not a salt: they would work out offline
    /// which addresses collide in which bucket and craft the cheapest possible
    /// flood. Deriving it deterministically also means the layout survives a
    /// restart, so a node does not re-shuffle its whole view of the network
    /// every time it is upgraded.
    #[must_use]
    pub fn new(key: &SecretKey) -> Self {
        Self {
            entries: BTreeMap::new(),
            new: BTreeMap::new(),
            tried: BTreeMap::new(),
            salt: hash_parts(Domain::P2pAddrBucket, &[b"salt", &key.to_bytes()]),
        }
    }

    /// How many addresses are known.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is known yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// What is known about one peer.
    #[must_use]
    pub fn get(&self, id: &PeerId) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// Every address in the tried table.
    #[must_use]
    pub fn tried_addresses(&self) -> Vec<PeerAddr> {
        self.entries
            .values()
            .filter(|e| e.tried)
            .map(|e| e.addr)
            .collect()
    }

    fn hash(&self, parts: &[&[u8]]) -> u64 {
        let mut all: Vec<&[u8]> = Vec::with_capacity(parts.len().saturating_add(1));
        all.push(self.salt.as_bytes());
        all.extend_from_slice(parts);
        let digest = hash_parts(Domain::P2pAddrBucket, &all);
        u64::from_le_bytes(*digest.as_bytes().first_chunk::<8>().unwrap_or(&[0; 8]))
    }

    /// Which new bucket an address learned from `source` belongs in.
    ///
    /// Two hashes, following Bitcoin Core: the first mixes the address group
    /// with the source group and is reduced to a small index; the second maps
    /// *that* to a bucket. The reduction in between is what bounds a single
    /// source to [`NEW_BUCKETS_PER_SOURCE`] buckets, and it is the whole reason
    /// this is two hashes rather than one.
    fn new_bucket(&self, addr: &PeerAddr, source: AddrGroup) -> u64 {
        let addr_group = addr.group();
        let first = self.hash(&[b"new1", addr_group.as_bytes(), source.as_bytes()]);
        let index = first % NEW_BUCKETS_PER_SOURCE;
        self.hash(&[b"new2", source.as_bytes(), &index.to_le_bytes()]) % NEW_BUCKETS
    }

    /// Which tried bucket an address belongs in.
    ///
    /// Keyed on the address itself, then narrowed by its group — so a peer that
    /// has genuinely served us gets a slot chosen by its identity, while an
    /// attacker who has served us from a thousand hosts in one /16 still reaches
    /// only [`TRIED_BUCKETS_PER_GROUP`] buckets.
    fn tried_bucket(&self, addr: &PeerAddr) -> u64 {
        let first = self.hash(&[b"tried1", &addr.id.key().to_bytes()]);
        let index = first % TRIED_BUCKETS_PER_GROUP;
        self.hash(&[b"tried2", addr.group().as_bytes(), &index.to_le_bytes()]) % TRIED_BUCKETS
    }

    /// Record an address, learned from a peer in `source`.
    ///
    /// Returns whether it was new to us.
    pub fn add(&mut self, addr: PeerAddr, source: AddrGroup) -> bool {
        if self.entries.contains_key(&addr.id) {
            return false;
        }
        let bucket = self.new_bucket(&addr, source);
        let slot = self.new.entry(bucket).or_default();
        if slot.len() >= BUCKET_SIZE {
            // The bucket is full. Evict the entry with the most failures, and if
            // nothing there has ever failed, refuse the newcomer rather than
            // dropping something that might be good. An attacker filling a
            // bucket must therefore outlast what is already in it rather than
            // simply arriving later.
            let Some(worst) = Self::worst(&self.entries, slot) else {
                return false;
            };
            let Some(worst_entry) = self.entries.get(&worst) else {
                return false;
            };
            if worst_entry.failures == 0 {
                return false;
            }
            slot.retain(|id| id != &worst);
            self.entries.remove(&worst);
        }
        slot.push(addr.id);
        self.entries.insert(
            addr.id,
            Entry {
                addr,
                failures: 0,
                tried: false,
            },
        );
        true
    }

    /// The identity in `slot` with the most failures.
    fn worst(entries: &BTreeMap<PeerId, Entry>, slot: &[PeerId]) -> Option<PeerId> {
        slot.iter()
            .max_by_key(|id| entries.get(id).map_or(0, |e| e.failures))
            .copied()
    }

    /// Record that a handshake with this peer completed.
    ///
    /// Promotes it to the tried table. This is the only way in, and it is why
    /// the tried table is worth preferring: entering it costs an attacker a host
    /// that answers, whereas entering the new table costs them a sentence.
    pub fn mark_good(&mut self, id: &PeerId) {
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        entry.failures = 0;
        if entry.tried {
            return;
        }
        entry.tried = true;
        let addr = entry.addr;
        for slot in self.new.values_mut() {
            slot.retain(|held| held != id);
        }
        let bucket = self.tried_bucket(&addr);
        let slot = self.tried.entry(bucket).or_default();
        if slot.len() >= BUCKET_SIZE {
            // A full tried bucket demotes its worst occupant rather than
            // refusing the newcomer: everything here has served us at some
            // point, so recency is the only thing left to sort on.
            if let Some(worst) = Self::worst(&self.entries, slot) {
                slot.retain(|held| held != &worst);
                if let Some(demoted) = self.entries.get_mut(&worst) {
                    demoted.tried = false;
                }
            }
        }
        slot.push(*id);
    }

    /// Record that we could not reach this peer.
    pub fn mark_failed(&mut self, id: &PeerId) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.failures = entry.failures.saturating_add(1);
        }
    }

    /// Choose a peer to dial, avoiding groups already connected to.
    ///
    /// `cursor` walks the buckets deterministically, so a node does not favour
    /// low-numbered buckets and a test can enumerate the whole selection space.
    ///
    /// Tried is preferred two times in three. Preferring it always would let a
    /// node that has been eclipsed once stay eclipsed, since the attacker's
    /// hosts are the only ones it has ever successfully reached; never
    /// preferring it would throw away the one signal that costs an attacker
    /// anything.
    #[must_use]
    pub fn select(&self, avoid: &[AddrGroup], cursor: u64) -> Option<PeerAddr> {
        let prefer_tried = !cursor.is_multiple_of(3);
        let order: [bool; 2] = if prefer_tried {
            [true, false]
        } else {
            [false, true]
        };
        for from_tried in order {
            let (table, count) = if from_tried {
                (&self.tried, TRIED_BUCKETS)
            } else {
                (&self.new, NEW_BUCKETS)
            };
            for step in 0..count {
                let bucket = cursor.wrapping_add(step).checked_rem(count).unwrap_or(0);
                let Some(slot) = table.get(&bucket) else {
                    continue;
                };
                // Start at a different offset each time, so a node does not
                // always try the same occupant of a bucket first.
                let offset = usize::try_from(cursor.checked_rem(BUCKET_SIZE as u64).unwrap_or(0))
                    .unwrap_or(0);
                for (i, id) in slot.iter().enumerate() {
                    let at = i.wrapping_add(offset).checked_rem(slot.len()).unwrap_or(0);
                    let pick = slot.get(at).unwrap_or(id);
                    let Some(entry) = self.entries.get(pick) else {
                        continue;
                    };
                    if avoid.contains(&entry.addr.group()) {
                        continue;
                    }
                    return Some(entry.addr);
                }
            }
        }
        None
    }

    /// A sample of addresses to answer a peer's request with.
    ///
    /// Only tried addresses, and never more than `limit`. Relaying the new table
    /// would make a node an amplifier for whatever it was last flooded with,
    /// which is how one attacker's address list reaches the whole network from a
    /// single injection point.
    #[must_use]
    pub fn sample(&self, limit: usize, cursor: u64) -> Vec<PeerAddr> {
        let tried = self.tried_addresses();
        if tried.is_empty() {
            return Vec::new();
        }
        let start =
            usize::try_from(cursor.checked_rem(tried.len() as u64).unwrap_or(0)).unwrap_or(0);
        tried
            .iter()
            .cycle()
            .skip(start)
            .take(limit.min(tried.len()))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::SocketAddr;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    /// A peer identity that is a pure function of `n`, so tests can make many.
    fn id(n: u32) -> PeerId {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_le_bytes());
        seed[4] = 0xA5;
        PeerId::new(SecretKey::from_bytes(&seed).public_key())
    }

    fn addr(n: u32, ip: &str) -> PeerAddr {
        PeerAddr::new(id(n), SocketAddr::new(ip.parse().expect("valid ip"), 26656))
    }

    fn group(ip: &str) -> AddrGroup {
        AddrGroup::of(SocketAddr::new(ip.parse().expect("valid ip"), 26656))
    }

    /// `count` attacker addresses, all inside one /16, all announced by one
    /// source in that same /16 — the cheapest flood there is.
    fn flood(book: &mut AddrBook, count: u32) {
        let source = group("198.51.0.1");
        for n in 0..count {
            #[expect(clippy::cast_possible_truncation, reason = "bounded by the loop")]
            let (a, b) = ((n / 256) as u8, (n % 256) as u8);
            book.add(addr(n, &format!("198.51.{a}.{b}")), source);
        }
    }

    #[test]
    fn an_attacker_holding_one_subnet_gets_one_outbound_slot() {
        // The eclipse attack, and the answer to it. Ten thousand attacker
        // addresses against eight honest ones: the diversity rule means the
        // attacker's entire /16 is worth a single connection, because the second
        // one would be into a group already used.
        let mut book = AddrBook::new(&key(1));
        flood(&mut book, 10_000);
        for n in 0..8u32 {
            let honest = addr(900_000 + n, &format!("203.{n}.113.5"));
            book.add(honest, group("203.0.113.1"));
            book.mark_good(&honest.id);
        }

        let mut chosen: Vec<PeerAddr> = Vec::new();
        let mut used: Vec<AddrGroup> = Vec::new();
        for cursor in 0..64u64 {
            if chosen.len() >= 8 {
                break;
            }
            if let Some(pick) = book.select(&used, cursor) {
                used.push(pick.group());
                chosen.push(pick);
            }
        }

        let attacker = group("198.51.0.1");
        let captured = chosen.iter().filter(|p| p.group() == attacker).count();
        assert!(
            captured <= 1,
            "10 000 addresses in one /16 took {captured} of {} outbound slots",
            chosen.len()
        );
        assert!(
            chosen.len() >= 4,
            "the rule must still leave a node able to connect: only {} slots filled",
            chosen.len()
        );
    }

    #[test]
    fn one_source_group_reaches_only_a_fraction_of_the_table() {
        // The property that makes flooding cost address *diversity* rather than
        // address *count*: however many addresses arrive from one source group,
        // they land in at most NEW_BUCKETS_PER_SOURCE of NEW_BUCKETS buckets.
        let book = AddrBook::new(&key(1));
        let source = group("198.51.0.1");
        let mut buckets = BTreeSet::new();
        for n in 0..5_000u32 {
            #[expect(clippy::cast_possible_truncation, reason = "bounded by the loop")]
            let (a, b) = ((n / 256) as u8, (n % 256) as u8);
            let peer = addr(n, &format!("192.0.{a}.{b}"));
            buckets.insert(book.new_bucket(&peer, source));
        }
        assert!(
            buckets.len() as u64 <= NEW_BUCKETS_PER_SOURCE,
            "one source reached {} buckets, the bound is {NEW_BUCKETS_PER_SOURCE}",
            buckets.len()
        );
        assert!(
            (buckets.len() as u64) < NEW_BUCKETS / 4,
            "and that is a small fraction of the {NEW_BUCKETS} buckets in the table"
        );
    }

    #[test]
    fn two_nodes_lay_out_their_books_differently() {
        // The salt. Without it an attacker computes the layout offline and
        // crafts the cheapest set of addresses that fills it; with it, the same
        // address sits somewhere different at every node.
        let alice = AddrBook::new(&key(1));
        let bob = AddrBook::new(&key(2));
        let source = group("203.0.113.1");
        let differing = (0..200u32)
            .filter(|n| {
                let peer = addr(*n, "192.0.2.7");
                alice.new_bucket(&peer, source) != bob.new_bucket(&peer, source)
            })
            .count();
        assert!(
            differing > 150,
            "only {differing} of 200 addresses landed differently; the salt is not working"
        );
    }

    #[test]
    fn a_node_reproduces_its_own_layout_across_a_restart() {
        // The other half of deriving the salt deterministically: a node that
        // re-shuffled its whole view on every restart would forget which peers
        // it had already found, which is itself a way to be eclipsed.
        let before = AddrBook::new(&key(1));
        let after = AddrBook::new(&key(1));
        let peer = addr(1, "192.0.2.7");
        let source = group("203.0.113.1");
        assert_eq!(
            before.new_bucket(&peer, source),
            after.new_bucket(&peer, source)
        );
    }

    #[test]
    fn only_a_completed_handshake_reaches_the_tried_table() {
        let mut book = AddrBook::new(&key(1));
        let peer = addr(1, "203.0.113.7");
        assert!(book.add(peer, group("203.0.113.1")));
        assert!(!book.get(&peer.id).expect("known").tried);
        assert!(book.tried_addresses().is_empty());

        book.mark_good(&peer.id);
        assert!(book.get(&peer.id).expect("known").tried);
        assert_eq!(book.tried_addresses(), vec![peer]);
    }

    #[test]
    fn a_full_bucket_does_not_evict_a_peer_that_has_never_failed() {
        // Otherwise arriving later is enough to displace something good, and an
        // attacker with a steady trickle of addresses empties the table.
        let mut book = AddrBook::new(&key(1));
        let source = group("198.51.0.1");
        let mut placed: Vec<PeerAddr> = Vec::new();
        for n in 0..5_000u32 {
            #[expect(clippy::cast_possible_truncation, reason = "bounded by the loop")]
            let (a, b) = ((n / 256) as u8, (n % 256) as u8);
            let peer = addr(n, &format!("198.51.{a}.{b}"));
            if book.add(peer, source) {
                placed.push(peer);
            }
        }
        assert!(
            placed.len() <= BUCKET_SIZE * NEW_BUCKETS_PER_SOURCE as usize,
            "one source placed {} addresses; the ceiling is {}",
            placed.len(),
            BUCKET_SIZE * NEW_BUCKETS_PER_SOURCE as usize
        );
        // And every one that got in is still there: nothing displaced anything.
        for peer in &placed {
            assert!(book.get(&peer.id).is_some());
        }
    }

    #[test]
    fn a_peer_is_never_recorded_twice() {
        let mut book = AddrBook::new(&key(1));
        let peer = addr(1, "203.0.113.7");
        assert!(book.add(peer, group("203.0.113.1")));
        assert!(!book.add(peer, group("198.51.100.1")), "already known");
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn a_sample_offers_only_peers_this_node_has_actually_reached() {
        // Relaying the new table would make every node an amplifier for whatever
        // it was last flooded with, which is how one injection point reaches a
        // whole network.
        let mut book = AddrBook::new(&key(1));
        flood(&mut book, 500);
        assert!(
            book.sample(50, 0).is_empty(),
            "nothing has been reached, so there is nothing to recommend"
        );

        let good = addr(900_001, "203.0.113.9");
        book.add(good, group("203.0.113.1"));
        book.mark_good(&good.id);
        assert_eq!(book.sample(50, 0), vec![good]);
    }

    #[test]
    fn selection_refuses_a_group_already_connected_to() {
        let mut book = AddrBook::new(&key(1));
        let peer = addr(1, "203.0.113.7");
        book.add(peer, group("203.0.113.1"));
        book.mark_good(&peer.id);
        assert_eq!(book.select(&[], 1), Some(peer));
        assert_eq!(
            book.select(&[peer.group()], 1),
            None,
            "the only peer known is in a group already used"
        );
    }

    #[test]
    fn an_empty_book_offers_nothing_rather_than_panicking() {
        let book = AddrBook::new(&key(1));
        assert!(book.is_empty());
        assert_eq!(book.select(&[], 0), None);
        assert!(book.sample(10, 0).is_empty());
    }

    #[test]
    fn failures_are_counted_and_a_success_clears_them() {
        let mut book = AddrBook::new(&key(1));
        let peer = addr(1, "203.0.113.7");
        book.add(peer, group("203.0.113.1"));
        book.mark_failed(&peer.id);
        book.mark_failed(&peer.id);
        assert_eq!(book.get(&peer.id).expect("known").failures, 2);
        book.mark_good(&peer.id);
        assert_eq!(book.get(&peer.id).expect("known").failures, 0);
    }
}
