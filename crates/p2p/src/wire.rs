//! What peers say to each other, and how it is put on a socket.
//!
//! # Framing
//!
//! ```text
//! frame = u32 length (little-endian) || sealed payload
//! ```
//!
//! The length is in the clear, because a reader has to know how many bytes to
//! take before it can decrypt anything. It is passed to the AEAD as associated
//! data, so an on-path attacker who edits it gets a failed tag and a dead
//! connection rather than a reader that goes looking for the wrong number of
//! bytes. TLS record headers are in the clear for the same reason.
//!
//! What that costs, stated rather than glossed: **message sizes are visible.**
//! An observer can tell a block from a vote by length alone. Fixed-size padded
//! frames are the fix and Tendermint uses them; the cost is bandwidth on exactly
//! the links that have least of it, which is not a trade this network should
//! make by default.
//!
//! # The length limit is a memory limit
//!
//! [`MAX_FRAME_LEN`] is checked **before** anything is allocated. The alternative
//! — read the length, allocate, then discover the peer lied — is a one-packet
//! remote out-of-memory, and it is the oldest bug in network code.
//!
//! # Decoding is canonical
//!
//! A peer message decodes exactly one way or not at all, through the same codec
//! the ledger uses. Two encodings of one vote would mean two message ids for one
//! vote, and the deduplication that keeps gossip from amplifying is keyed on
//! that id.

use std::io::{Read, Write};

use afrolink_consensus::SignedVote;
use afrolink_crypto::hash::{Domain, Hash32, hash};
use afrolink_executor::MAX_BLOCK_BYTES;
use afrolink_node::SignedProposal;
use afrolink_primitives::Height;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_types::Transaction;

use crate::peer::PeerAddr;
use crate::secret::{Opener, Sealer, SessionError, TAG_LEN};
use crate::sync::SyncBlock;

/// What a frame may carry beyond the block itself.
///
/// A block travels wrapped: as a proposal it gains a chain id, a height, a
/// round, a proposer and a signature; as a [`SyncBlock`] it gains a whole commit
/// certificate, which is one precommit — a vote and a 64-byte signature, about
/// 130 bytes — per validator. A mebibyte of headroom covers a certificate from
/// some eight thousand validators, which is an order of magnitude beyond any set
/// this chain will carry, and it costs nothing when unused.
pub const FRAME_HEADROOM: usize = 1024 * 1024;

/// Largest frame this protocol accepts, sealed bytes included.
///
/// **Derived from `MAX_BLOCK_BYTES` rather than restating it.** The two were
/// independently written as `4 * 1024 * 1024` and were therefore exactly equal,
/// which meant a block at the consensus limit could be *built* and *voted on* but
/// never *sent*: every wrapper a block travels in — a proposal, a sync response —
/// is strictly larger than the block, so `write_frame` would refuse it. A
/// proposer could have produced a legal block that no peer could receive. Two
/// constants that must not drift apart should not be two numbers.
pub const MAX_FRAME_LEN: usize = MAX_BLOCK_BYTES.saturating_add(FRAME_HEADROOM);

/// How much of a frame is read at a time.
///
/// The unit in which a reader's buffer grows, so the memory a peer can make this
/// node hold is bounded by what it has actually sent plus one of these — never by
/// the length it claimed in the header.
pub const READ_CHUNK: usize = 16 * 1024;

/// Most addresses one `Addrs` message may carry.
///
/// Bounded because an address list is the one message a peer can make arbitrarily
/// large out of nothing. A thousand entries would let a single peer hand a node
/// a table's worth of attacker addresses in one frame.
pub const MAX_ADDRS: usize = 64;

/// Why a frame could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The peer closed cleanly.
    #[error("connection closed")]
    Closed,
    /// The socket failed.
    #[error("io: {0}")]
    Io(String),
    /// The read timed out with no frame in progress.
    ///
    /// Its own variant rather than a shade of [`Self::Io`], because it is the
    /// *expected* outcome on an idle connection — the read timeout exists so a
    /// peer thread notices a shutdown — and a caller that cannot tell it apart
    /// either spins or drops idle peers. Matched on the error *kind* rather
    /// than on the operating system's wording, which differs per platform.
    #[error("read timed out")]
    TimedOut,
    /// The announced length exceeds [`MAX_FRAME_LEN`].
    ///
    /// Refused before allocating, which is the entire point of checking it.
    #[error("frame announces {len} bytes, the limit is {MAX_FRAME_LEN}")]
    TooLarge {
        /// What the peer claimed.
        len: usize,
    },
    /// A frame too short to hold an authentication tag.
    #[error("frame of {len} bytes cannot hold a {TAG_LEN}-byte tag")]
    TooShort {
        /// What the peer claimed.
        len: usize,
    },
    /// The frame did not authenticate.
    #[error(transparent)]
    Session(#[from] SessionError),
    /// The plaintext was not a canonical peer message.
    #[error("not a canonical peer message: {0}")]
    Malformed(String),
}

/// One thing a peer says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMessage {
    /// A block on offer for a height and round.
    Proposal(Box<SignedProposal>),
    /// A prevote or precommit.
    Vote(Box<SignedVote>),
    /// A transaction to relay.
    Transaction(Box<Transaction>),
    /// Ask for addresses of other peers.
    GetAddrs,
    /// Offer addresses of other peers.
    Addrs(Vec<PeerAddr>),
    /// Liveness probe, carrying a nonce to be echoed.
    Ping(u64),
    /// The echo of a [`Self::Ping`].
    Pong(u64),
    /// The highest height this peer has **committed** — not the one it is working on.
    ///
    /// The distinction is the whole meaning of the message and it is easy to get
    /// backwards: a node driving consensus at height 42 has committed 41, and
    /// announcing 42 would have peers asking it for a block that does not exist
    /// yet, every tick, forever.
    ///
    /// A claim and nothing more. Claiming too high earns the peer requests it
    /// cannot answer; claiming too low means it is never asked. Neither buys
    /// anything, because what makes a synced block acceptable is the certificate
    /// attached to it, not the peer's account of itself.
    Status(Height),
    /// Ask for one committed block and its certificate.
    GetBlock(Height),
    /// One committed block and the certificate that finalised it.
    Block(Box<SyncBlock>),
    /// A refusal to serve a height: not held, or beyond this peer's tip.
    ///
    /// Its own message rather than silence, so a node that asked can ask
    /// somebody else at once instead of waiting out a timeout. Silence and
    /// "I do not have it" are different facts and a syncer that cannot tell them
    /// apart wastes a request window on every pruned peer it meets.
    NoBlock(Height),
}

impl PeerMessage {
    /// The identifier deduplication is keyed on.
    ///
    /// Only the gossiped messages have one. A `Ping` is *supposed* to be sent
    /// repeatedly, and an address list is answered rather than relayed, so
    /// neither belongs in the seen-set: putting them there would mean a peer
    /// could never probe us twice.
    ///
    /// The sync messages are excluded for a sharper reason. They are a
    /// request/response exchange, not gossip, and a node that fails to apply a
    /// block must be able to ask for the same height again. If a `Block` were
    /// deduplicated, the second copy would be dropped before it was looked at and
    /// the node would stall for good at the first height it stumbled on.
    #[must_use]
    pub fn gossip_id(&self) -> Option<Hash32> {
        let bytes = match self {
            Self::Proposal(p) => p.to_bytes(),
            Self::Vote(v) => v.to_bytes(),
            Self::Transaction(t) => t.to_bytes(),
            Self::GetAddrs
            | Self::Addrs(_)
            | Self::Ping(_)
            | Self::Pong(_)
            | Self::Status(_)
            | Self::GetBlock(_)
            | Self::Block(_)
            | Self::NoBlock(_) => return None,
        };
        Some(hash(Domain::P2pTranscript, &bytes))
    }

    /// A short label, for logs and coverage counting.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Proposal(_) => "proposal",
            Self::Vote(_) => "vote",
            Self::Transaction(_) => "transaction",
            Self::GetAddrs => "getaddrs",
            Self::Addrs(_) => "addrs",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::Status(_) => "status",
            Self::GetBlock(_) => "getblock",
            Self::Block(_) => "block",
            Self::NoBlock(_) => "noblock",
        }
    }
}

impl Encode for PeerMessage {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Proposal(p) => {
                out.push(1);
                p.encode(out);
            }
            Self::Vote(v) => {
                out.push(2);
                v.encode(out);
            }
            Self::Transaction(t) => {
                out.push(3);
                t.encode(out);
            }
            Self::GetAddrs => out.push(4),
            Self::Addrs(addrs) => {
                out.push(5);
                addrs.encode(out);
            }
            Self::Ping(nonce) => {
                out.push(6);
                nonce.encode(out);
            }
            Self::Pong(nonce) => {
                out.push(7);
                nonce.encode(out);
            }
            Self::Status(height) => {
                out.push(8);
                height.encode(out);
            }
            Self::GetBlock(height) => {
                out.push(9);
                height.encode(out);
            }
            Self::Block(sync) => {
                out.push(10);
                sync.encode(out);
            }
            Self::NoBlock(height) => {
                out.push(11);
                height.encode(out);
            }
        }
    }
}

impl Decode for PeerMessage {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(match u8::decode(r)? {
            1 => Self::Proposal(Box::new(SignedProposal::decode(r)?)),
            2 => Self::Vote(Box::new(SignedVote::decode(r)?)),
            3 => Self::Transaction(Box::new(Transaction::decode(r)?)),
            4 => Self::GetAddrs,
            5 => {
                let addrs = Vec::<PeerAddr>::decode(r)?;
                if addrs.is_empty() || addrs.len() > MAX_ADDRS {
                    // An empty list is a wasted frame; an over-long one is a
                    // table's worth of attacker addresses in a single message.
                    // Refused rather than truncated, because truncating decides
                    // silently which addresses a node gets to learn.
                    return Err(CodecError::Invalid(format!(
                        "an address list must carry 1..={MAX_ADDRS} entries, got {}",
                        addrs.len()
                    )));
                }
                Self::Addrs(addrs)
            }
            6 => Self::Ping(u64::decode(r)?),
            7 => Self::Pong(u64::decode(r)?),
            8 => Self::Status(Height::decode(r)?),
            9 => Self::GetBlock(Height::decode(r)?),
            10 => Self::Block(Box::new(SyncBlock::decode(r)?)),
            11 => Self::NoBlock(Height::decode(r)?),
            tag => {
                return Err(CodecError::UnknownDiscriminant {
                    tag,
                    type_name: "PeerMessage",
                });
            }
        })
    }
}

/// Seal a message and write it as one frame.
///
/// # Errors
/// [`FrameError::TooLarge`] if the sealed message exceeds [`MAX_FRAME_LEN`], or
/// [`FrameError::Io`] if the socket fails.
pub fn write_frame<W: Write>(
    writer: &mut W,
    sealer: &mut Sealer,
    message: &PeerMessage,
) -> Result<(), FrameError> {
    let plaintext = message.to_bytes();
    let sealed_len = plaintext.len().saturating_add(TAG_LEN);
    if sealed_len > MAX_FRAME_LEN {
        // Refused here rather than at the peer, so a node cannot be made to
        // send something the protocol says it must not.
        return Err(FrameError::TooLarge { len: sealed_len });
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "checked against MAX_FRAME_LEN immediately above"
    )]
    let header = (sealed_len as u32).to_le_bytes();
    let sealed = sealer.seal(&plaintext, &header)?;
    writer
        .write_all(&header)
        .and_then(|()| writer.write_all(&sealed))
        .and_then(|()| writer.flush())
        .map_err(|e| FrameError::Io(e.to_string()))
}

/// Read one frame and open it, returning the message and what it cost on the wire.
///
/// The byte count is returned rather than discarded because it is what the rate
/// limiter is denominated in: a peer sending one enormous frame a second is
/// within any *message* budget, and bytes are the resource that actually runs
/// out. CometBFT's `RecvRate` counts the same thing for the same reason.
///
/// # Errors
/// Returns the first [`FrameError`] encountered. Every one of them is fatal to
/// the connection: there is no resynchronising a stream whose frame counter has
/// diverged.
pub fn read_frame<R: Read>(
    reader: &mut R,
    opener: &mut Opener,
) -> Result<(PeerMessage, usize), FrameError> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) => return Err(from_io(&e)),
    }
    let len = u32::from_le_bytes(header) as usize;
    // Before the allocation, not after. A peer that announces four gigabytes
    // must cost this node one comparison, not four gigabytes.
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge { len });
    }
    if len < TAG_LEN {
        return Err(FrameError::TooShort { len });
    }

    // **Allocate what has arrived, never what was announced.**
    //
    // `vec![0u8; len]` here would hand a stranger a five-mebibyte allocation for
    // the price of a four-byte header: announce the maximum, send nothing, and a
    // node with forty inbound slots is holding two hundred mebibytes it will
    // never receive. Growing as the bytes actually turn up makes the attack cost
    // the attacker exactly as much bandwidth as it costs this node memory, which
    // is the property that makes it not worth mounting.
    //
    // CometBFT reaches the same place from the other end: `MaxPacketMsgPayloadSize`
    // means a peer never announces more than one small packet, and a block is a
    // `PartSet` of 64 KiB parts rather than one message — so the largest thing a
    // peer can ask a node to hold is a constant. Doing that here would mean
    // splitting proposals and sync responses into parts with their own Merkle
    // root, which is the right long-term shape and a change to the consensus wire
    // format; this is the bound that does not need one.
    let mut sealed: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    while sealed.len() < len {
        let want = READ_CHUNK.min(len.saturating_sub(sealed.len()));
        // Past the header, a timeout is not "idle" — it is a peer that announced
        // a frame and then stopped talking half way through it, which is a
        // stalled connection rather than a quiet one.
        let read = match reader.read(chunk.get_mut(..want).unwrap_or(&mut [])) {
            Ok(0) => return Err(FrameError::Closed),
            Ok(read) => read,
            Err(e) => {
                return Err(match from_io(&e) {
                    FrameError::TimedOut => FrameError::Io("stalled mid-frame".to_owned()),
                    other => other,
                });
            }
        };
        sealed.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
    }

    let plaintext = opener.open(&sealed, &header)?;
    let message = afrolink_primitives::codec::decode_exact::<PeerMessage>(&plaintext)
        .map_err(|e| FrameError::Malformed(e.to_string()))?;
    Ok((message, len.saturating_add(header.len())))
}

/// Classify a socket error by kind, never by the operating system's wording.
fn from_io(error: &std::io::Error) -> FrameError {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof => FrameError::Closed,
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => FrameError::TimedOut,
        _ => FrameError::Io(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Session;
    use afrolink_primitives::codec::decode_exact;
    use std::net::SocketAddr;

    fn pair() -> (Sealer, Opener) {
        let a = [3u8; 32];
        let b = [4u8; 32];
        let (sealer, _) = Session::new(a, b).split();
        let (_, opener) = Session::new(b, a).split();
        (sealer, opener)
    }

    fn peer_addr(n: u8) -> PeerAddr {
        PeerAddr::new(
            crate::peer::PeerId::new(afrolink_crypto::SecretKey::from_bytes(&[n; 32]).public_key()),
            SocketAddr::new("203.0.113.7".parse().expect("valid"), 26656),
        )
    }

    #[test]
    fn a_message_survives_the_round_trip_through_a_socket() {
        let (mut send, mut recv) = pair();
        let message = PeerMessage::Ping(42);
        let mut wire: Vec<u8> = Vec::new();
        write_frame(&mut wire, &mut send, &message).expect("writes");
        let (back, bytes) = read_frame(&mut wire.as_slice(), &mut recv).expect("reads");
        assert_eq!(back, message);
        assert_eq!(
            bytes,
            wire.len(),
            "the cost reported is the cost on the wire"
        );
    }

    #[test]
    fn several_messages_stream_in_order() {
        let (mut send, mut recv) = pair();
        let messages = [
            PeerMessage::Ping(1),
            PeerMessage::GetAddrs,
            PeerMessage::Addrs(vec![peer_addr(1), peer_addr(2)]),
            PeerMessage::Pong(1),
        ];
        let mut wire: Vec<u8> = Vec::new();
        for message in &messages {
            write_frame(&mut wire, &mut send, message).expect("writes");
        }
        let mut cursor = wire.as_slice();
        for message in &messages {
            assert_eq!(
                read_frame(&mut cursor, &mut recv).expect("reads").0,
                *message
            );
        }
    }

    #[test]
    fn an_absurd_length_costs_one_comparison_and_no_memory() {
        // The oldest bug in network code: read the length, allocate, then find
        // out the peer lied. Four gigabytes announced, nothing allocated.
        let (_, mut recv) = pair();
        let mut wire = Vec::new();
        wire.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            read_frame(&mut wire.as_slice(), &mut recv),
            Err(FrameError::TooLarge {
                len: u32::MAX as usize
            })
        );
    }

    #[test]
    fn a_frame_too_short_to_hold_a_tag_is_refused() {
        let (_, mut recv) = pair();
        let mut wire = Vec::new();
        wire.extend_from_slice(&4u32.to_le_bytes());
        wire.extend_from_slice(&[0; 4]);
        assert_eq!(
            read_frame(&mut wire.as_slice(), &mut recv),
            Err(FrameError::TooShort { len: 4 })
        );
    }

    #[test]
    fn a_rewritten_length_kills_the_connection_rather_than_desynchronising_it() {
        // The length is in the clear, so it is authenticated instead. An on-path
        // attacker who edits it cannot make the reader take a different number
        // of bytes and stay in step — the tag fails first.
        let (mut send, mut recv) = pair();
        let mut wire: Vec<u8> = Vec::new();
        write_frame(&mut wire, &mut send, &PeerMessage::Ping(7)).expect("writes");
        wire[0] = wire[0].wrapping_add(0);
        // Re-announce the same bytes under a length one larger, with a padding
        // byte so the read still completes.
        let mut tampered = Vec::new();
        #[expect(clippy::cast_possible_truncation, reason = "test fixture is small")]
        let bigger = (wire.len() as u32 - 4 + 1).to_le_bytes();
        tampered.extend_from_slice(&bigger);
        tampered.extend_from_slice(&wire[4..]);
        tampered.push(0);
        assert!(matches!(
            read_frame(&mut tampered.as_slice(), &mut recv),
            Err(FrameError::Session(SessionError::NotAuthentic))
        ));
    }

    #[test]
    fn a_truncated_stream_reads_as_a_close_rather_than_an_error() {
        let (mut send, mut recv) = pair();
        let mut wire: Vec<u8> = Vec::new();
        write_frame(&mut wire, &mut send, &PeerMessage::Ping(7)).expect("writes");
        wire.truncate(wire.len() - 1);
        assert_eq!(
            read_frame(&mut wire.as_slice(), &mut recv),
            Err(FrameError::Closed)
        );
        assert_eq!(
            read_frame(&mut [].as_slice(), &mut recv),
            Err(FrameError::Closed)
        );
    }

    #[test]
    fn an_over_long_address_list_is_refused_rather_than_truncated() {
        // Truncating would decide silently which addresses a node gets to learn,
        // which hands the choice to whoever sent the list.
        let addrs: Vec<PeerAddr> = (0..=MAX_ADDRS)
            .map(|n| {
                #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_ADDRS")]
                let seed = n as u8;
                peer_addr(seed.wrapping_add(1))
            })
            .collect();
        let bytes = PeerMessage::Addrs(addrs).to_bytes();
        assert!(decode_exact::<PeerMessage>(&bytes).is_err());
    }

    #[test]
    fn an_empty_address_list_is_refused() {
        let bytes = PeerMessage::Addrs(Vec::new()).to_bytes();
        assert!(decode_exact::<PeerMessage>(&bytes).is_err());
    }

    #[test]
    fn an_unknown_message_tag_does_not_decode() {
        assert!(decode_exact::<PeerMessage>(&[99]).is_err());
    }

    #[test]
    fn a_block_at_the_consensus_limit_still_fits_in_a_frame() {
        // These two constants were written independently and came out exactly
        // equal, which made a legal block unsendable: a proposer could build and
        // vote on a block that no peer could ever receive, because every wrapper
        // a block travels in is strictly larger than the block. The frame bound
        // is now derived from the block bound, and this is what keeps them from
        // drifting apart again.
        const {
            assert!(
                MAX_FRAME_LEN > MAX_BLOCK_BYTES,
                "a frame must hold a maximum-size block plus what wraps it"
            );
            assert!(
                MAX_FRAME_LEN - MAX_BLOCK_BYTES >= FRAME_HEADROOM,
                "the headroom is what a commit certificate travels in"
            );
        }
    }

    /// A reader that counts the largest buffer it was ever asked to fill.
    ///
    /// Standing in for memory: a reader asked for one 16 KiB chunk at a time
    /// cannot be holding five mebibytes, however large a number the header named.
    struct Trickle {
        remaining: usize,
        /// Shared with the test, so the count survives the reader being moved
        /// into a `Chain`. A plain `Cell` cloned out would copy the value and
        /// leave the assertion looking at a zero that never changes — which is
        /// how this test first passed against the very implementation it exists
        /// to catch.
        largest_ask: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.largest_ask.set(self.largest_ask.get().max(buf.len()));
            if self.remaining == 0 {
                return Ok(0);
            }
            let n = buf.len().min(self.remaining).min(64);
            self.remaining -= n;
            Ok(n)
        }
    }

    #[test]
    fn an_announced_length_costs_what_arrives_rather_than_what_was_claimed() {
        // The oldest bug in network code, in its second form. Refusing an absurd
        // length is not enough: a length that is *legal* and never delivered is
        // a five-mebibyte allocation for the price of a four-byte header, and a
        // node with forty inbound slots holds two hundred mebibytes of nothing.
        let (_, mut recv) = pair();
        let mut wire = Vec::new();
        #[expect(clippy::cast_possible_truncation, reason = "MAX_FRAME_LEN fits u32")]
        let announced = (MAX_FRAME_LEN as u32).to_le_bytes();
        wire.extend_from_slice(&announced);

        // The header, then a hundred bytes, then silence.
        let mut reader = std::io::Read::chain(
            wire.as_slice(),
            Trickle {
                remaining: 100,
                largest_ask: std::rc::Rc::new(std::cell::Cell::new(0)),
            },
        );
        let outcome = read_frame(&mut reader, &mut recv);
        assert!(
            matches!(outcome, Err(FrameError::Closed)),
            "a peer that stops talking mid-frame is a closed connection, got {outcome:?}"
        );
    }

    #[test]
    fn a_reader_never_asks_for_more_than_one_chunk_at_a_time() {
        // The mechanism behind the test above, asserted directly: the buffer
        // grows in `READ_CHUNK` steps as bytes arrive, so the peak is bounded by
        // what the peer actually sent and not by what it announced.
        let (_, mut recv) = pair();
        let mut wire = Vec::new();
        #[expect(clippy::cast_possible_truncation, reason = "MAX_FRAME_LEN fits u32")]
        let announced = (MAX_FRAME_LEN as u32).to_le_bytes();
        wire.extend_from_slice(&announced);

        let asked = std::rc::Rc::new(std::cell::Cell::new(0));
        let trickle = Trickle {
            remaining: 200,
            largest_ask: std::rc::Rc::clone(&asked),
        };
        let mut reader = std::io::Read::chain(wire.as_slice(), trickle);
        drop(read_frame(&mut reader, &mut recv));

        assert!(
            asked.get() <= READ_CHUNK,
            "the reader asked for {} bytes at once; the chunk size is {READ_CHUNK}",
            asked.get()
        );
    }

    #[test]
    fn a_sync_reply_is_never_deduplicated() {
        // A block is a *response*, not gossip. If it entered the seen-set, a node
        // that failed to apply a height could never be sent that height again,
        // and would stall there for good.
        assert!(PeerMessage::GetBlock(Height(7)).gossip_id().is_none());
        assert!(PeerMessage::NoBlock(Height(7)).gossip_id().is_none());
        assert!(PeerMessage::Status(Height(7)).gossip_id().is_none());
    }

    #[test]
    fn only_gossiped_messages_carry_an_identity() {
        // A ping is supposed to be repeated. Putting one in the seen-set would
        // mean a peer could never probe us twice.
        assert!(PeerMessage::Ping(1).gossip_id().is_none());
        assert!(PeerMessage::GetAddrs.gossip_id().is_none());
        assert!(PeerMessage::Addrs(vec![peer_addr(1)]).gossip_id().is_none());
    }

    #[test]
    fn messages_round_trip_canonically() {
        for message in [
            PeerMessage::GetAddrs,
            PeerMessage::Ping(u64::MAX),
            PeerMessage::Pong(0),
            PeerMessage::Addrs(vec![peer_addr(1), peer_addr(2)]),
        ] {
            let bytes = message.to_bytes();
            let back = decode_exact::<PeerMessage>(&bytes).expect("decodes");
            assert_eq!(back, message);
            assert_eq!(back.to_bytes(), bytes, "one encoding per value");
        }
    }
}
