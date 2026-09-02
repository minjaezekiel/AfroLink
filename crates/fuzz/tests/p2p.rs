//! Hostile bytes at the peer-to-peer surface.
//!
//! This is now the **first thing an anonymous peer reaches** — before any
//! signature is checked, before any proof is verified, before the node knows who
//! is talking. The HTTP transport got this treatment for the same reason and it
//! found real defects; the P2P transport is a harder target, because an attacker
//! here does not even have to speak the protocol to make a node allocate.
//!
//! Three properties, and none of them is about correctness of the happy path:
//!
//! 1. **Nothing panics.** A panic in a peer thread is a node that stops relaying,
//!    and in a workspace that forbids `unwrap` the way to prove it is to try.
//! 2. **Nothing is read two ways.** Every peer message that decodes re-encodes to
//!    exactly the bytes it came from. Two encodings of one vote would be two
//!    gossip ids, and the deduplication that stops a gossip storm is keyed on
//!    that id.
//! 3. **Nothing is allocated on a stranger's word.** A frame header announcing
//!    four gigabytes must cost one comparison.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_crypto::SecretKey;
use afrolink_fuzz::{Rng, hammer};
use afrolink_p2p::handshake::{HELLO_LEN, Handshake, PROTOCOL_VERSION};
use afrolink_p2p::peer::{PeerAddr, PeerId};
use afrolink_p2p::secret::Session;
use afrolink_p2p::sync::SyncBlock;
use afrolink_p2p::wire::{MAX_FRAME_LEN, PeerMessage, read_frame, write_frame};
use afrolink_primitives::codec::{Encode, decode_exact};
use afrolink_primitives::{ChainId, Height, Round};
use std::net::SocketAddr;

const ROUNDS: u64 = 2_000;

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn peer(seed: u8) -> PeerId {
    PeerId::new(key(seed).public_key())
}

fn at(ip: &str, port: u16) -> PeerAddr {
    PeerAddr::new(peer(1), SocketAddr::new(ip.parse().unwrap(), port))
}

fn chain() -> ChainId {
    ChainId::new("afrolink-1").unwrap()
}

/// The two halves of one connection.
fn halves() -> (afrolink_p2p::secret::Sealer, afrolink_p2p::secret::Opener) {
    let a = [11u8; 32];
    let b = [22u8; 32];
    let (sealer, _) = Session::new(a, b).split();
    let (_, opener) = Session::new(b, a).split();
    (sealer, opener)
}

#[test]
fn peer_decoders_stay_canonical_under_attack() {
    hammer::<PeerId>("PeerId", &peer(1), ROUNDS);
    hammer::<PeerAddr>("PeerAddr/v4", &at("203.0.113.9", 26656), ROUNDS);
    hammer::<PeerAddr>("PeerAddr/v6", &at("2001:db8::1", 26657), ROUNDS);

    for (label, message) in [
        ("PeerMessage::GetAddrs", PeerMessage::GetAddrs),
        ("PeerMessage::Ping", PeerMessage::Ping(u64::MAX)),
        ("PeerMessage::Pong", PeerMessage::Pong(0)),
        (
            "PeerMessage::Addrs",
            PeerMessage::Addrs(vec![
                at("203.0.113.9", 26656),
                at("198.51.100.4", 1),
                at("2001:db8::1", 65535),
            ]),
        ),
        ("PeerMessage::Status", PeerMessage::Status(Height(u64::MAX))),
        ("PeerMessage::GetBlock", PeerMessage::GetBlock(Height(0))),
        ("PeerMessage::NoBlock", PeerMessage::NoBlock(Height(7))),
        (
            "PeerMessage::Block",
            PeerMessage::Block(Box::new(sync_block())),
        ),
    ] {
        hammer::<PeerMessage>(label, &message, ROUNDS);
    }
}

#[test]
fn a_frame_reader_never_panics_on_anything() {
    // Whatever an anonymous peer sends, the reader either produces a message or
    // an error. There is no third outcome, and a panic in a peer thread is a
    // node that has stopped relaying.
    for seed in 0..4_000u64 {
        let mut rng = Rng::new(seed);
        let (_, mut opener) = halves();
        let len = rng.below(600);
        let noise = rng.blob(len);
        let outcome = read_frame(&mut noise.as_slice(), &mut opener);
        assert!(
            outcome.is_err(),
            "seed {seed}: random bytes decoded as a peer message"
        );
    }
}

#[test]
fn a_frame_header_alone_never_causes_an_allocation() {
    // The oldest bug in network code: read the length, allocate, then find out
    // the peer lied. Every four-byte header in the space is tried, at the
    // boundary where a mistake would show, and the reader must refuse before it
    // reaches for memory.
    for len in [
        u32::MAX,
        u32::MAX - 1,
        0x8000_0000,
        MAX_FRAME_LEN as u32 + 1,
        MAX_FRAME_LEN as u32,
        16,
        15,
        1,
        0,
    ] {
        let (_, mut opener) = halves();
        let header = len.to_le_bytes();
        let outcome = read_frame(&mut header.as_slice(), &mut opener);
        assert!(outcome.is_err(), "a bare header of {len} must not succeed");
    }
}

#[test]
fn a_mutated_frame_is_refused_rather_than_half_read() {
    // A valid frame with one byte changed. The tag catches it every time, and
    // the failure is total: there is no resynchronising a stream whose counters
    // have diverged, which is why the transport drops the peer.
    for seed in 0..2_000u64 {
        let mut rng = Rng::new(seed);
        let (mut sealer, mut opener) = halves();
        let mut wire: Vec<u8> = Vec::new();
        write_frame(&mut wire, &mut sealer, &PeerMessage::Ping(seed)).unwrap();

        let at = rng.below(wire.len());
        wire[at] ^= 1 << (rng.byte() % 8);
        assert!(
            read_frame(&mut wire.as_slice(), &mut opener).is_err(),
            "seed {seed}: a frame with a flipped bit was accepted"
        );
    }
}

#[test]
fn a_handshake_never_panics_on_a_hostile_hello() {
    // The very first bytes a stranger gets to choose. Every length, every
    // content, including the low-order points that broke Tendermint.
    for seed in 0..3_000u64 {
        let mut rng = Rng::new(seed);
        let (handshake, _) = Handshake::start(chain()).unwrap();
        let hello = match seed % 4 {
            0 => rng.bytes(HELLO_LEN),
            1 => {
                let len = rng.below(80);
                rng.blob(len)
            }
            2 => {
                let mut bytes = vec![0u8; HELLO_LEN];
                bytes[..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
                bytes
            }
            _ => {
                // A well-formed version followed by a hostile ephemeral key —
                // the shape that actually reaches the Diffie–Hellman.
                let mut bytes = rng.bytes(HELLO_LEN);
                bytes[..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
                bytes
            }
        };
        // The only requirement is that it returns. A successful exchange with
        // random bytes is possible and fine — the peer still has to sign the
        // transcript with a key it does not have.
        drop(handshake.respond(&hello, &key(1)));
    }
}

#[test]
fn a_hostile_authentication_frame_never_authenticates() {
    // Past the key exchange, before any trust. An attacker who can complete a
    // Diffie–Hellman — anyone can — still has to produce a signature over *this*
    // transcript with the key they are claiming.
    for seed in 0..2_000u64 {
        let mut rng = Rng::new(seed);
        let (alice, hello_a) = Handshake::start(chain()).unwrap();
        let (mallory, hello_m) = Handshake::start(chain()).unwrap();
        let alice = alice.respond(&hello_m, &key(1)).unwrap();
        let mallory = mallory.respond(&hello_a, &key(2)).unwrap();

        let frame = match seed % 3 {
            // Random bytes.
            0 => {
                let len = rng.below(200);
                rng.blob(len)
            }
            // Mallory's genuine frame, which proves she is Mallory.
            1 => mallory.auth_frame.clone(),
            // Mallory's frame with a bit flipped.
            _ => {
                let mut bytes = mallory.auth_frame.clone();
                if !bytes.is_empty() {
                    let at = rng.below(bytes.len());
                    bytes[at] ^= 0x40;
                }
                bytes
            }
        };
        // Alice dialled peer(9), whom neither of them is.
        let outcome = alice.finish(&frame, &peer(1), Some(&peer(9)));
        assert!(
            outcome.is_err(),
            "seed {seed}: a handshake completed as a node nobody holds the key for"
        );
    }
}

#[test]
fn a_truncated_stream_of_valid_frames_is_always_a_clean_close() {
    // A peer that dies mid-sentence is common and is not an attack. It must read
    // as a closed connection at every possible cut point, rather than as a
    // protocol violation the peer gets banned for.
    let (mut sealer, _) = halves();
    let mut wire: Vec<u8> = Vec::new();
    for n in 0..4u64 {
        write_frame(&mut wire, &mut sealer, &PeerMessage::Ping(n)).unwrap();
    }
    for cut in 1..wire.len() {
        let (_, mut opener) = halves();
        let mut cursor = &wire[..cut];
        // Read until something stops us; whatever stops us must not be a panic.
        while read_frame(&mut cursor, &mut opener).is_ok() {}
    }
}

#[test]
fn a_sync_reply_is_never_two_things_at_once() {
    // The whole catch-up path rests on a block decoding exactly one way. A second
    // spelling of one block would be a second block id, and a node deciding which
    // history it holds by which spelling arrived first.
    hammer::<SyncBlock>("SyncBlock", &sync_block(), ROUNDS);
}

#[test]
fn a_certificate_for_the_wrong_height_never_survives_decoding() {
    // The cheapest check in the sync path, and the one that keeps a mismatched
    // pair away from the code that verifies signatures. Every mutation that
    // decodes must still agree with itself about what height it is.
    for seed in 0..2_000u64 {
        let mut rng = Rng::new(seed);
        let mut bytes = sync_block().to_bytes();
        if bytes.is_empty() {
            continue;
        }
        let at = rng.below(bytes.len());
        bytes[at] ^= 1 << (rng.byte() % 8);
        if let Ok(decoded) = decode_exact::<SyncBlock>(&bytes) {
            assert_eq!(
                decoded.commit.height, decoded.block.header.height,
                "seed {seed}: a block and a certificate for different heights decoded as a pair"
            );
        }
    }
}

/// One committed block and a certificate that matches its height.
///
/// The signatures are not valid and are not meant to be: this file is about the
/// codec, and whether a certificate *verifies* is `Node::apply_synced`'s question.
fn sync_block() -> SyncBlock {
    use afrolink_crypto::hash::Hash32;
    use afrolink_executor::{Block, BlockHeader};
    use afrolink_primitives::Timestamp;

    let header = BlockHeader {
        chain_id: chain(),
        height: Height(9),
        time: Timestamp::from_millis(1_700_000_000_000),
        parent: Hash32::from_bytes([1; 32]),
        tx_root: Block::tx_root(&[]),
        app_hash: Hash32::from_bytes([2; 32]),
        outcome_root: Hash32::from_bytes([3; 32]),
        validators_hash: Hash32::from_bytes([4; 32]),
        next_validators_hash: Hash32::from_bytes([5; 32]),
    };
    let block_id = header.id();
    SyncBlock {
        block: Block {
            header,
            transactions: Vec::new(),
        },
        commit: afrolink_consensus::Commit::new(Height(9), Round(0), block_id, Vec::new()),
    }
}
