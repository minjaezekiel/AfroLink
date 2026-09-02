//! Proving to a peer who you are, before either side says anything else.
//!
//! # The shape, and whose mistake it avoids
//!
//! Station-to-station: an ephemeral X25519 exchange for secrecy, then each side
//! signs the **transcript** with its long-term key to prove the exchange was
//! with *it* and not with someone in the middle. Tendermint's Secret Connection
//! is the same shape, and this follows it including the fix it needed.
//!
//! Tendermint 0.32 and earlier were vulnerable to an ephemeral-key malleability
//! attack: *"if the connection is intercepted and an ephemeral key consisting of
//! all zeros is injected then the secret from `computeDHSecret` will be the same
//! for both parties for every handshake with any key"* — both sides derive a
//! secret the attacker also knows. Two defences, and this has both:
//!
//! 1. **The shared secret must be contributory.** A peer's key that drives the
//!    exchange to a known constant is refused outright, which is what
//!    `was_contributory` checks.
//! 2. **The transcript covers both ephemeral keys, sorted.** Sorting is what
//!    makes it a single agreed value rather than one each side computes its own
//!    way, and it is exactly the fix Tendermint applied. A signature over the
//!    transcript is therefore a signature over *which* exchange this was.
//!
//! The transcript also covers the protocol version and the **chain id**, so a
//! handshake recorded on a testnet cannot be replayed at a mainnet node. That is
//! the same reasoning `TxBody` uses for signing over `chain_id`.
//!
//! # What is signed, and what is not
//!
//! The signature is over a transcript *hash* under
//! [`Domain::P2pHandshakeSignDoc`] — a domain nothing else uses, so a handshake
//! signature can never be replayed as a consensus vote and a vote can never be
//! presented here.
//!
//! Identities travel **inside** the encrypted channel. A passive observer sees
//! two ephemeral keys and learns nothing about which nodes they belong to, which
//! is the property that makes mapping the validator topology cost an active
//! attack rather than a packet capture.
//!
//! # Not solved here
//!
//! Forward secrecy holds for the session keys — the ephemerals are discarded —
//! but a node's long-term key still authenticates it, so compromising that key
//! lets an attacker impersonate the node *in future* handshakes. It does not let
//! them read past ones.

use afrolink_crypto::hash::{Domain, Hash32, hash_parts};
use afrolink_crypto::{PublicKey, SecretKey, Signature};
use afrolink_primitives::ChainId;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader, decode_exact};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::peer::PeerId;
use crate::secret::Session;

/// The wire protocol this build speaks.
///
/// Part of the transcript, so a version mismatch fails authentication rather
/// than being silently negotiated down.
pub const PROTOCOL_VERSION: u16 = 1;

/// Bytes in the first message: version, then the ephemeral public key.
pub const HELLO_LEN: usize = 2 + 32;

/// Why a handshake failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// The peer speaks a different protocol version.
    #[error("peer speaks protocol version {theirs}, this node speaks {PROTOCOL_VERSION}")]
    Version {
        /// The version the peer announced.
        theirs: u16,
    },
    /// The opening message was the wrong length.
    #[error("hello must be exactly {HELLO_LEN} bytes, got {0}")]
    MalformedHello(usize),
    /// The Diffie–Hellman exchange produced a value the peer could have forced.
    ///
    /// The Tendermint bug, refused. See the module documentation.
    #[error("peer's ephemeral key does not contribute to the shared secret")]
    NonContributory,
    /// The peer's authentication frame did not decode.
    #[error("malformed authentication frame: {0}")]
    MalformedAuth(String),
    /// The peer's authentication frame did not decrypt.
    #[error("authentication frame failed to decrypt")]
    NotAuthentic,
    /// The peer's signature over the transcript did not verify.
    ///
    /// Either it does not hold the key it claimed, or something between the two
    /// of us ran its own exchange with each side.
    #[error("peer did not prove it holds the key it claimed")]
    BadSignature,
    /// The peer presented an identity we did not dial.
    #[error("dialled {expected} but reached {found}")]
    WrongPeer {
        /// Who we meant to reach.
        expected: String,
        /// Who answered.
        found: String,
    },
    /// The peer presented our own identity.
    #[error("peer presented this node's own identity")]
    SelfConnection,
    /// The operating system's entropy source failed.
    ///
    /// Fatal, and never fallen back from: a predictable ephemeral key is a
    /// readable session, so no handshake at all is the safe outcome.
    #[error("entropy unavailable; refusing to hand shake with a guessable key")]
    EntropyUnavailable,
}

/// The transcript both sides must agree on, or nothing verifies.
fn transcript(chain_id: &ChainId, ours: &[u8; 32], theirs: &[u8; 32]) -> Hash32 {
    // Sorted, so both sides hash the same bytes in the same order without
    // needing to agree on who is the dialler. This is the Tendermint fix: an
    // ordering that depends on the role is an ordering an attacker in the middle
    // can exploit by playing a different role to each side.
    let (lower, upper) = if ours <= theirs {
        (ours, theirs)
    } else {
        (theirs, ours)
    };
    hash_parts(
        Domain::P2pTranscript,
        &[
            &PROTOCOL_VERSION.to_le_bytes(),
            &chain_id.to_bytes(),
            lower,
            upper,
        ],
    )
}

/// Derive one directional key.
fn direction_key(label: &[u8], shared: &[u8; 32], transcript: &Hash32) -> [u8; 32] {
    *hash_parts(
        Domain::P2pSessionKey,
        &[label, shared, transcript.as_bytes()],
    )
    .as_bytes()
}

/// What each side sends, encrypted, to prove who it is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Auth {
    key: PublicKey,
    signature: Signature,
}

impl Encode for Auth {
    fn encode(&self, out: &mut Vec<u8>) {
        self.key.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for Auth {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            key: PublicKey::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

/// A handshake in progress: the ephemeral secret, waiting for a peer's hello.
///
/// Consumed by [`Self::respond`], because an ephemeral secret used twice is not
/// ephemeral. The type system enforces that rather than a comment.
pub struct Handshake {
    chain_id: ChainId,
    ephemeral: StaticSecret,
    ours: [u8; 32],
}

/// A handshake past the key exchange, waiting to check who the peer is.
pub struct Pending {
    session: Session,
    transcript: Hash32,
    /// The frame to send, proving our own identity.
    pub auth_frame: Vec<u8>,
}

/// A completed handshake.
pub struct Established {
    /// The encrypted channel.
    pub session: Session,
    /// Who is on the other end, proven rather than claimed.
    pub peer: PeerId,
}

impl Handshake {
    /// Begin a handshake, returning the bytes to send first.
    ///
    /// The ephemeral secret is 32 bytes straight from the operating system,
    /// seeded the way `SecretKey::generate` is and for the same reason: it keeps
    /// this crate off whichever `rand_core` major version `x25519-dalek` happens
    /// to depend on, and an X25519 secret *is* 32 uniform random bytes.
    ///
    /// It is deliberately not seedable from a test. A predictable ephemeral key
    /// is a readable session, and a constructor that accepts one is a
    /// constructor somebody eventually calls in production.
    ///
    /// # Errors
    /// [`HandshakeError::EntropyUnavailable`] if the OS entropy source fails.
    /// There is no weaker fallback.
    pub fn start(chain_id: ChainId) -> Result<(Self, [u8; HELLO_LEN]), HandshakeError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| HandshakeError::EntropyUnavailable)?;
        let ephemeral = StaticSecret::from(seed);
        let ours = X25519Public::from(&ephemeral).to_bytes();
        let mut hello = [0u8; HELLO_LEN];
        hello[..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        hello[2..].copy_from_slice(&ours);
        Ok((
            Self {
                chain_id,
                ephemeral,
                ours,
            },
            hello,
        ))
    }

    /// Consume the peer's hello and produce the encrypted channel.
    ///
    /// # Errors
    /// [`HandshakeError::Version`], [`HandshakeError::MalformedHello`] or
    /// [`HandshakeError::NonContributory`].
    pub fn respond(self, hello: &[u8], key: &SecretKey) -> Result<Pending, HandshakeError> {
        if hello.len() != HELLO_LEN {
            return Err(HandshakeError::MalformedHello(hello.len()));
        }
        let mut version = [0u8; 2];
        version.copy_from_slice(hello.get(..2).ok_or(HandshakeError::MalformedHello(0))?);
        let theirs_version = u16::from_le_bytes(version);
        if theirs_version != PROTOCOL_VERSION {
            return Err(HandshakeError::Version {
                theirs: theirs_version,
            });
        }
        let mut theirs = [0u8; 32];
        theirs.copy_from_slice(hello.get(2..).ok_or(HandshakeError::MalformedHello(0))?);

        let shared = self.ephemeral.diffie_hellman(&X25519Public::from(theirs));
        if !shared.was_contributory() {
            // The Tendermint bug: a peer whose key drives the exchange to a
            // constant makes both sides derive a secret the attacker also holds.
            return Err(HandshakeError::NonContributory);
        }

        let transcript = transcript(&self.chain_id, &self.ours, &theirs);
        let shared = shared.to_bytes();

        // Direction is decided by the sorted order of the ephemeral keys, so
        // both sides agree without either announcing a role.
        let (send_label, recv_label): (&[u8], &[u8]) = if self.ours <= theirs {
            (b"lower-to-upper", b"upper-to-lower")
        } else {
            (b"upper-to-lower", b"lower-to-upper")
        };
        let mut session = Session::new(
            direction_key(send_label, &shared, &transcript),
            direction_key(recv_label, &shared, &transcript),
        );

        let auth = Auth {
            key: key.public_key(),
            signature: key.sign(Domain::P2pHandshakeSignDoc, transcript.as_bytes()),
        };
        let auth_frame = session
            .seal(&auth.to_bytes(), &[])
            .map_err(|_| HandshakeError::NotAuthentic)?;

        Ok(Pending {
            session,
            transcript,
            auth_frame,
        })
    }
}

impl Pending {
    /// Check the peer's authentication frame and finish.
    ///
    /// `expected` is the identity we dialled, if we dialled. An inbound
    /// connection passes `None` — anyone may call, and who they turn out to be
    /// is decided by the address book and the peer limits, not here.
    ///
    /// # Errors
    /// Returns the first [`HandshakeError`] encountered.
    pub fn finish(
        mut self,
        frame: &[u8],
        ours: &PeerId,
        expected: Option<&PeerId>,
    ) -> Result<Established, HandshakeError> {
        let plaintext = self
            .session
            .open(frame, &[])
            .map_err(|_| HandshakeError::NotAuthentic)?;
        let auth = decode_exact::<Auth>(&plaintext)
            .map_err(|e| HandshakeError::MalformedAuth(e.to_string()))?;

        auth.key
            .verify(
                Domain::P2pHandshakeSignDoc,
                self.transcript.as_bytes(),
                &auth.signature,
            )
            .map_err(|_| HandshakeError::BadSignature)?;

        let peer = PeerId::new(auth.key);
        if &peer == ours {
            // Either a misconfiguration pointing a node at itself, or an
            // attacker reflecting our own handshake back at us. Both waste a
            // connection slot, and a node that eclipses itself is still
            // eclipsed.
            return Err(HandshakeError::SelfConnection);
        }
        if let Some(expected) = expected
            && expected != &peer
        {
            return Err(HandshakeError::WrongPeer {
                expected: expected.short(),
                found: peer.short(),
            });
        }
        Ok(Established {
            session: self.session,
            peer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn id(seed: u8) -> PeerId {
        PeerId::new(key(seed).public_key())
    }

    /// Run a full handshake between two nodes, returning both established ends.
    fn shake(
        a: &SecretKey,
        b: &SecretKey,
        chain_a: &ChainId,
        chain_b: &ChainId,
        expected: Option<&PeerId>,
    ) -> Result<(Established, Established), HandshakeError> {
        let (alice, hello_a) = Handshake::start(chain_a.clone())?;
        let (bob, hello_b) = Handshake::start(chain_b.clone())?;
        let alice = alice.respond(&hello_b, a)?;
        let bob = bob.respond(&hello_a, b)?;
        let alice_frame = alice.auth_frame.clone();
        let bob_frame = bob.auth_frame.clone();
        let alice = alice.finish(&bob_frame, &PeerId::new(a.public_key()), expected)?;
        let bob = bob.finish(&alice_frame, &PeerId::new(b.public_key()), None)?;
        Ok((alice, bob))
    }

    #[test]
    fn two_nodes_end_up_knowing_who_the_other_is() {
        let (alice, bob) = shake(&key(1), &key(2), &chain(), &chain(), None).expect("shakes");
        assert_eq!(alice.peer, id(2));
        assert_eq!(bob.peer, id(1));
    }

    #[test]
    fn the_channel_works_in_both_directions_afterwards() {
        let (mut alice, mut bob) = shake(&key(1), &key(2), &chain(), &chain(), None).expect("ok");
        let frame = alice.session.seal(b"prevote", b"7").expect("seals");
        assert_eq!(bob.session.open(&frame, b"7").expect("opens"), b"prevote");
        let back = bob.session.seal(b"precommit", b"9").expect("seals");
        assert_eq!(
            alice.session.open(&back, b"9").expect("opens"),
            b"precommit"
        );
    }

    #[test]
    fn dialling_one_node_and_reaching_another_is_refused() {
        // Without this the address book is decorative: an attacker who can
        // answer at a known address would inherit the reputation of whoever was
        // supposed to be there.
        let error = shake(&key(1), &key(2), &chain(), &chain(), Some(&id(3)))
            .err()
            .expect("must fail");
        assert!(matches!(error, HandshakeError::WrongPeer { .. }));
    }

    #[test]
    fn a_handshake_from_another_chain_does_not_authenticate() {
        // The transcript covers the chain id, so a testnet peer — or a recorded
        // testnet handshake replayed at a mainnet node — fails rather than
        // becoming a peer that gossips the wrong blocks.
        //
        // It fails at `NotAuthentic` rather than `BadSignature`, and that is the
        // stronger outcome: the chain id feeds the *key derivation*, not only
        // the signature, so the two sides never share a key and the peer's
        // identity frame does not even decrypt. There is nothing to check a
        // signature on.
        let other = ChainId::new("afrolink-test").expect("valid");
        let error = shake(&key(1), &key(2), &chain(), &other, None)
            .err()
            .expect("must fail");
        assert_eq!(error, HandshakeError::NotAuthentic);
    }

    #[test]
    fn a_node_refuses_to_shake_hands_with_itself() {
        let error = shake(&key(1), &key(1), &chain(), &chain(), None)
            .err()
            .expect("must fail");
        assert_eq!(error, HandshakeError::SelfConnection);
    }

    #[test]
    fn an_all_zero_ephemeral_key_is_refused() {
        // The Tendermint 0.32 bug. An injected zero key drives the exchange to a
        // constant, so both sides derive a secret the injector also knows. It has
        // to be refused at the exchange, because by the time a signature is
        // checked the attacker is already reading.
        let (alice, _) = Handshake::start(chain()).expect("entropy");
        let mut hello = [0u8; HELLO_LEN];
        hello[..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        // hello[2..] stays all zero.
        assert_eq!(
            alice.respond(&hello, &key(1)).err(),
            Some(HandshakeError::NonContributory)
        );
    }

    #[test]
    fn every_low_order_ephemeral_key_is_refused() {
        // The full small-subgroup blacklist for Curve25519 — the same set
        // libsodium refuses. Each one forces the shared secret to a value the
        // sender knows in advance, so refusing only the all-zero key would leave
        // the Tendermint bug reachable by six other spellings.
        const LOW_ORDER: [[u8; 32]; 7] = [
            // Order 1 and 2.
            [0; 32],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            // Order 8.
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
            // p - 1, p, p + 1: the same three points written the long way round.
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ];
        for (i, bad) in LOW_ORDER.iter().enumerate() {
            let (alice, _) = Handshake::start(chain()).expect("entropy");
            let mut hello = [0u8; HELLO_LEN];
            hello[..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
            hello[2..].copy_from_slice(bad);
            assert_eq!(
                alice.respond(&hello, &key(1)).err(),
                Some(HandshakeError::NonContributory),
                "low-order point {i} must be refused"
            );
        }
    }

    #[test]
    fn a_peer_speaking_another_version_is_told_so_rather_than_left_hanging() {
        let (alice, _) = Handshake::start(chain()).expect("entropy");
        let mut hello = [0u8; HELLO_LEN];
        hello[..2].copy_from_slice(&(PROTOCOL_VERSION + 1).to_le_bytes());
        hello[2..].copy_from_slice(&[7u8; 32]);
        assert_eq!(
            alice.respond(&hello, &key(1)).err(),
            Some(HandshakeError::Version {
                theirs: PROTOCOL_VERSION + 1
            })
        );
    }

    #[test]
    fn a_truncated_hello_is_refused_rather_than_padded() {
        let (alice, _) = Handshake::start(chain()).expect("entropy");
        assert_eq!(
            alice.respond(&[0u8; 8], &key(1)).err(),
            Some(HandshakeError::MalformedHello(8))
        );
    }

    #[test]
    fn a_signature_over_someone_elses_transcript_does_not_verify() {
        // The man in the middle, stated directly: an attacker who runs one
        // exchange with each side holds two sessions and can read both, but
        // cannot produce a signature over *our* transcript with the identity key
        // of the node we wanted. So the handshake fails and the connection dies
        // before a single message crosses it.
        let (alice, hello_a) = Handshake::start(chain()).expect("entropy");
        let (mallory_to_alice, hello_m) = Handshake::start(chain()).expect("entropy");
        // Alice completes with Mallory, believing she reached Bob.
        let alice = alice.respond(&hello_m, &key(1)).expect("exchange");
        // Mallory, holding no key of Bob's, can only sign as herself.
        let mallory = mallory_to_alice
            .respond(&hello_a, &key(66))
            .expect("exchange");
        let error = alice
            .finish(&mallory.auth_frame, &id(1), Some(&id(2)))
            .err()
            .expect("must fail");
        assert!(matches!(error, HandshakeError::WrongPeer { .. }));
    }

    #[test]
    fn an_edited_authentication_frame_does_not_decrypt() {
        let (alice, hello_a) = Handshake::start(chain()).expect("entropy");
        let (bob, hello_b) = Handshake::start(chain()).expect("entropy");
        let alice = alice.respond(&hello_b, &key(1)).expect("exchange");
        let bob = bob.respond(&hello_a, &key(2)).expect("exchange");
        let mut frame = bob.auth_frame.clone();
        frame[0] ^= 0x80;
        assert_eq!(
            alice.finish(&frame, &id(1), None).err(),
            Some(HandshakeError::NotAuthentic)
        );
    }

    #[test]
    fn two_handshakes_between_the_same_pair_share_no_keys() {
        // Forward secrecy for the session: the ephemerals are discarded, so
        // recording today's traffic and stealing an identity key tomorrow does
        // not decrypt it.
        let (a1, b1) = shake(&key(1), &key(2), &chain(), &chain(), None).expect("first");
        let (mut a2, _) = shake(&key(1), &key(2), &chain(), &chain(), None).expect("second");
        let mut b1 = b1;
        let frame = a2.session.seal(b"secret", b"").expect("seals");
        assert!(
            b1.session.open(&frame, b"").is_err(),
            "a frame from one session must not open in another"
        );
        assert_eq!(a1.peer, id(2));
    }
}
