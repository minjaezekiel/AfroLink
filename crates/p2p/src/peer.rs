//! Who a peer is, where it is, and how much of the network it counts as.
//!
//! # Identity is a key, not an address
//!
//! A [`PeerId`] is a node's long-term Ed25519 public key. It is deliberately
//! **not** an account address and not a validator's consensus key: a node that
//! relays blocks holds no money and signs no votes, and giving it a separate
//! identity means running one does not require either.
//!
//! The key itself rather than a hash of it, because the handshake has to verify
//! a signature from it anyway. A shortened id would only add a lookup, and a
//! lookup is a place for a node to be confused about who it is talking to.
//!
//! # A group is the unit of Sybil resistance
//!
//! Counting *addresses* is meaningless — anyone renting a subnet has thousands.
//! Bitcoin's answer, after [Heilman et al.'s eclipse attack][heilman], is to
//! count **groups**: an IPv4 /16 or an IPv6 /32, on the reasoning that holding
//! addresses in many groups costs real money and real relationships while
//! holding many addresses in one group costs almost nothing.
//!
//! Every diversity rule in this crate is written in terms of [`AddrGroup`], and
//! that is the whole eclipse defence in one sentence: *no two outbound
//! connections into the same group.*
//!
//! It is an imperfect proxy and worth being honest about. A large ISP or a cloud
//! provider holds many /16s, so the Erebus attack — a network-level adversary
//! positioned on the path — is not addressed by grouping at all. Bitcoin's
//! answer there is ASN-aware bucketing from a downloaded map, which is better
//! and which we do not have; see [ADR-0023](../../../docs/adr/0023-peer-to-peer.md).
//!
//! [heilman]: https://dl.acm.org/doi/10.5555/2831143.2831152

use std::net::{IpAddr, SocketAddr};

use afrolink_crypto::PublicKey;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

/// A node's network identity: its long-term signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(PublicKey);

impl PeerId {
    /// The identity belonging to a public key.
    #[must_use]
    pub const fn new(key: PublicKey) -> Self {
        Self(key)
    }

    /// The key behind this identity.
    #[must_use]
    pub const fn key(&self) -> &PublicKey {
        &self.0
    }

    /// A short prefix, for logs.
    ///
    /// Eight hex characters. Enough to follow one peer through a log and far too
    /// few to be treated as an identifier — which is deliberate, because a
    /// truncated key that looks usable is a key somebody will compare.
    #[must_use]
    pub fn short(&self) -> String {
        self.0
            .to_bytes()
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

impl core::fmt::Display for PeerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "peer:{}", self.short())
    }
}

impl Encode for PeerId {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for PeerId {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(PublicKey::decode(r)?))
    }
}

/// The slice of address space an address is counted under.
///
/// An IPv4 /16 or an IPv6 /32, held as raw bytes so both fit one type and so the
/// value can be hashed and compared without branching on the family at every
/// use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddrGroup([u8; 8]);

impl AddrGroup {
    /// The group a socket address belongs to.
    ///
    /// **The port is ignored for every routable address, and that is the point.**
    /// An attacker who could split one subnet into many groups by opening many
    /// ports would have the diversity rule for nothing, since ports are free and
    /// address space is not.
    ///
    /// Loopback is the single exception, and it is a carve-out for a devnet
    /// rather than a weakening of the rule. `127.0.0.0/8` carries no information
    /// about network diversity at all: treating it as one group would make a
    /// single-machine test network unable to form its second connection, and
    /// treating each socket as its own group is exactly as meaningful, which is
    /// to say not at all. Nothing an attacker reaches over a real network is
    /// loopback to the node they are attacking.
    #[must_use]
    pub fn of(addr: SocketAddr) -> Self {
        let port = addr.port().to_be_bytes();
        match addr.ip() {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                if v4.is_loopback() {
                    Self([1, o[2], o[3], port[0], port[1], 0, 0, 0])
                } else {
                    Self([0, o[0], o[1], 0, 0, 0, 0, 0])
                }
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                if v6.is_loopback() {
                    Self([1, 0, 0, port[0], port[1], 0, 0, 0])
                } else {
                    Self([2, o[0], o[1], o[2], o[3], 0, 0, 0])
                }
            }
        }
    }

    /// The raw group bytes, for hashing into a bucket.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

/// A peer's identity together with where to reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerAddr {
    /// Who we expect to find there. The handshake refuses anyone else.
    pub id: PeerId,
    /// Where to dial.
    pub addr: SocketAddr,
}

impl PeerAddr {
    /// A peer at an address.
    #[must_use]
    pub const fn new(id: PeerId, addr: SocketAddr) -> Self {
        Self { id, addr }
    }

    /// The group this peer is counted under.
    #[must_use]
    pub fn group(&self) -> AddrGroup {
        AddrGroup::of(self.addr)
    }
}

impl Encode for PeerAddr {
    fn encode(&self, out: &mut Vec<u8>) {
        self.id.encode(out);
        match self.addr.ip() {
            IpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.octets());
            }
        }
        self.addr.port().encode(out);
    }
}

impl Decode for PeerAddr {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let id = PeerId::decode(r)?;
        let ip = match u8::decode(r)? {
            4 => IpAddr::from(r.take_array::<4>()?),
            6 => IpAddr::from(r.take_array::<16>()?),
            tag => {
                return Err(CodecError::UnknownDiscriminant {
                    tag,
                    type_name: "PeerAddr/family",
                });
            }
        };
        let port = u16::decode(r)?;
        if port == 0 {
            // Port zero means "any port" to a listener and nothing at all to a
            // dialler. Refused rather than stored, so the address book never
            // holds an entry nothing can connect to.
            return Err(CodecError::Invalid("peer port must not be zero".to_owned()));
        }
        Ok(Self {
            id,
            addr: SocketAddr::new(ip, port),
        })
    }
}

/// Something a peer did that a node should hold against it.
///
/// Scored rather than instantly fatal, because several of these are reachable by
/// accident — a peer mid-upgrade, a race at a height boundary — and disconnecting
/// on the first one would let an attacker sever honest peers by provoking a
/// single mistake. Only [`Self::Unforgivable`] ends a connection at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misbehaviour {
    /// A frame larger than the protocol allows.
    Oversized,
    /// Bytes that did not decode as a peer message.
    Undecodable,
    /// A message whose signature did not verify.
    BadSignature,
    /// More messages than the rate limit allows.
    TooFast,
    /// An address list that was empty, over-long, or unasked for.
    BadAddrs,
    /// A protocol violation that cannot be a mistake.
    Unforgivable,
}

impl Misbehaviour {
    /// What this costs the peer.
    #[must_use]
    pub const fn penalty(self) -> i32 {
        match self {
            Self::TooFast | Self::BadAddrs => 5,
            Self::Undecodable | Self::Oversized => 20,
            Self::BadSignature => 50,
            Self::Unforgivable => BAN_THRESHOLD,
        }
    }
}

/// The score at which a peer is disconnected and refused.
pub const BAN_THRESHOLD: i32 = 100;

/// What a node remembers about how a peer has behaved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reputation {
    score: i32,
}

impl Reputation {
    /// A peer that has done nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { score: 0 }
    }

    /// The accumulated penalty.
    #[must_use]
    pub const fn score(&self) -> i32 {
        self.score
    }

    /// Record a misbehaviour, returning whether the peer is now banned.
    pub fn penalise(&mut self, what: Misbehaviour) -> bool {
        self.score = self.score.saturating_add(what.penalty());
        self.is_banned()
    }

    /// Whether this peer has spent its credit.
    #[must_use]
    pub const fn is_banned(&self) -> bool {
        self.score >= BAN_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::codec::decode_exact;
    use std::net::Ipv4Addr;

    fn peer(seed: u8) -> PeerId {
        PeerId::new(SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    fn at(ip: &str, port: u16) -> PeerAddr {
        PeerAddr::new(
            peer(1),
            SocketAddr::new(ip.parse().expect("valid ip"), port),
        )
    }

    #[test]
    fn a_subnet_is_one_group_however_many_addresses_it_holds() {
        // The whole eclipse defence rests on this: an attacker renting a /16 has
        // 65 536 addresses and, as far as every diversity rule in this crate is
        // concerned, one seat.
        let first = at("203.0.113.1", 26656).group();
        for host in [2u8, 7, 99, 254] {
            assert_eq!(
                at(&format!("203.0.113.{host}"), 26656).group(),
                first,
                "the same /24 must be the same group"
            );
        }
        assert_eq!(at("203.0.99.1", 26656).group(), first, "and the same /16");
        assert_ne!(
            at("203.1.113.1", 26656).group(),
            first,
            "a different /16 is a different group"
        );
    }

    #[test]
    fn a_port_never_splits_a_routable_group() {
        // The rule that keeps the whole defence from being free to evade: an
        // attacker who could turn one subnet into many groups by opening many
        // ports would have bought diversity with nothing, since ports cost
        // nothing and address space does not.
        let first = at("203.0.113.1", 26656).group();
        for port in [1u16, 80, 26657, 65535] {
            assert_eq!(at("203.0.113.1", port).group(), first);
        }
    }

    #[test]
    fn loopback_sockets_are_each_their_own_group() {
        // The one carve-out, and it is for devnets rather than against
        // attackers: 127.0.0.0/8 carries no information about network diversity,
        // so treating it as one group would stop a single-machine test network
        // forming its second connection. Nothing an attacker reaches over a real
        // network is loopback to its victim.
        assert_ne!(at("127.0.0.1", 1).group(), at("127.0.0.1", 2).group());
        assert_ne!(at("127.0.0.1", 1).group(), at("127.0.0.2", 1).group());
    }

    #[test]
    fn a_port_of_zero_is_refused_rather_than_stored() {
        let good = at("203.0.113.1", 26656);
        assert_eq!(decode_exact::<PeerAddr>(&good.to_bytes()), Ok(good));

        let mut bytes = Vec::new();
        peer(1).encode(&mut bytes);
        bytes.push(4);
        bytes.extend_from_slice(&Ipv4Addr::new(203, 0, 113, 1).octets());
        0u16.encode(&mut bytes);
        assert!(
            decode_exact::<PeerAddr>(&bytes).is_err(),
            "an address nothing can dial must not enter the address book"
        );
    }

    #[test]
    fn an_unknown_address_family_does_not_decode() {
        let mut bytes = Vec::new();
        peer(1).encode(&mut bytes);
        bytes.push(5);
        bytes.extend_from_slice(&[0; 4]);
        26656u16.encode(&mut bytes);
        assert!(decode_exact::<PeerAddr>(&bytes).is_err());
    }

    #[test]
    fn a_peer_is_banned_only_after_spending_its_credit() {
        // One malformed message is a bug in a peer mid-upgrade; a steady stream
        // of them is an attack. Disconnecting on the first would let an attacker
        // sever honest peers by provoking one mistake.
        let mut rep = Reputation::new();
        assert!(!rep.penalise(Misbehaviour::Undecodable));
        assert!(!rep.penalise(Misbehaviour::Undecodable));
        assert!(!rep.is_banned());

        // A forged signature is not a mistake, and two of them is enough.
        let mut rep = Reputation::new();
        assert!(!rep.penalise(Misbehaviour::BadSignature));
        assert!(rep.penalise(Misbehaviour::BadSignature));
        assert!(rep.is_banned());
    }

    #[test]
    fn an_unforgivable_act_bans_immediately() {
        let mut rep = Reputation::new();
        assert!(rep.penalise(Misbehaviour::Unforgivable));
    }

    #[test]
    fn a_score_cannot_be_wrapped_around_into_good_standing() {
        let mut rep = Reputation::new();
        for _ in 0..1_000_000 {
            rep.penalise(Misbehaviour::Unforgivable);
        }
        assert!(rep.is_banned(), "saturating, not wrapping");
    }

    #[test]
    fn peer_addresses_round_trip() {
        for addr in [at("203.0.113.9", 26656), at("2001:db8::1", 26657)] {
            assert_eq!(decode_exact::<PeerAddr>(&addr.to_bytes()), Ok(addr));
        }
    }
}
