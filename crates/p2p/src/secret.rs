//! The encrypted, authenticated channel two peers share once they have shaken
//! hands.
//!
//! # What encryption buys on a public ledger
//!
//! Not confidentiality of content: everything gossiped here is public and
//! signed, and will be in a block within a second. Three other things, and they
//! are why Bitcoin adopted [BIP324][bip324] after fifteen years without it:
//!
//! * **Authenticity of the channel.** Without it, dialling a peer proves nothing
//!   about who answered, and an address book of node ids means nothing.
//! * **Tamper-evidence.** An on-path ISP can drop and delay packets whatever we
//!   do. Encryption stops it *editing* them — swapping one vote for another,
//!   truncating a block — without the connection dying.
//! * **Resistance to topology mapping.** A passive observer who can read the
//!   gossip learns who is connected to whom and who proposed first, which is the
//!   reconnaissance step of an eclipse attack. It does not remove that — packet
//!   sizes and timing remain — but it removes the easy version.
//!
//! # Construction
//!
//! ChaCha20-Poly1305 with a 96-bit nonce, one key per direction, a counter that
//! never repeats. The counter is 64 bits and the connection is closed rather
//! than allowed to wrap: a repeated nonce under one key destroys the security of
//! both messages that used it, so "cannot happen" has to be enforced rather than
//! assumed.
//!
//! There is no rekeying. At one frame per millisecond a connection would need
//! half a billion years to exhaust the counter, and a rekey schedule is a second
//! state machine to get wrong.
//!
//! [bip324]: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Bytes the AEAD tag adds to every frame.
pub const TAG_LEN: usize = 16;

/// Why a sealed frame could not be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The frame did not authenticate.
    ///
    /// Either the peer is not who it claimed, something on the path edited the
    /// bytes, or the two sides have lost count of frames. All three are fatal to
    /// the connection and none of them is distinguishable from the others — by
    /// design, since telling an attacker *which* would help them.
    #[error("frame failed authentication")]
    NotAuthentic,
    /// The frame counter is exhausted.
    #[error("session frame counter exhausted; the connection must be reopened")]
    Exhausted,
}

/// One direction of an encrypted channel.
struct Direction {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Direction {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(key)),
            counter: 0,
        }
    }

    /// The nonce for the next frame, and the counter advanced past it.
    fn next_nonce(&mut self) -> Result<Nonce, SessionError> {
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.checked_add(1).ok_or(SessionError::Exhausted)?;
        Ok(Nonce::from(bytes))
    }
}

/// An encrypted, authenticated channel with one peer.
///
/// Deliberately holds no socket. Sealing and opening are pure functions of the
/// session state, so the whole cryptographic surface is testable and fuzzable
/// without binding a port — the same seam `crates/http` draws at `respond`.
pub struct Session {
    send: Direction,
    recv: Direction,
}

impl Session {
    /// Build a session from the two directional keys.
    ///
    /// Both sides derive the same pair and swap which is which, so a key is
    /// never used to both send and receive. Using one key in both directions
    /// would let an attacker reflect a peer's own frame back at it and have it
    /// authenticate.
    #[must_use]
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send: Direction::new(send_key),
            recv: Direction::new(recv_key),
        }
    }

    /// Encrypt one frame.
    ///
    /// `associated` is authenticated but not encrypted — it carries the frame
    /// length, which travels in the clear because a reader must know how many
    /// bytes to take before it can decrypt anything. Binding it here means an
    /// edited length is a failed tag rather than a reader that goes looking for
    /// the wrong number of bytes forever.
    ///
    /// # Errors
    /// [`SessionError::Exhausted`] once the counter is spent.
    pub fn seal(&mut self, plaintext: &[u8], associated: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.send.next_nonce()?;
        self.send
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: associated,
                },
            )
            .map_err(|_| SessionError::NotAuthentic)
    }

    /// Decrypt one frame.
    ///
    /// # Errors
    /// [`SessionError::NotAuthentic`] if the frame was edited, replayed, or
    /// delivered out of order; [`SessionError::Exhausted`] once the counter is
    /// spent.
    pub fn open(&mut self, ciphertext: &[u8], associated: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.recv.next_nonce()?;
        self.recv
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: associated,
                },
            )
            .map_err(|_| SessionError::NotAuthentic)
    }

    /// How many frames this session has sent.
    #[must_use]
    pub const fn frames_sent(&self) -> u64 {
        self.send.counter
    }

    /// Split into the two independent halves of the connection.
    ///
    /// A socket's directions genuinely are independent — one thread blocked in
    /// `read_exact` cannot also be writing — and the two halves share no
    /// mutable state, so splitting them is the honest shape rather than a
    /// concession to threading. The type system then makes it impossible to
    /// seal with the receiving key, which is the mistake that would let a frame
    /// be reflected back at its sender.
    #[must_use]
    pub fn split(self) -> (Sealer, Opener) {
        (Sealer(self.send), Opener(self.recv))
    }
}

/// The sending half of a connection.
pub struct Sealer(Direction);

impl Sealer {
    /// Encrypt one frame.
    ///
    /// # Errors
    /// [`SessionError::Exhausted`] once the counter is spent.
    pub fn seal(&mut self, plaintext: &[u8], associated: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.0.next_nonce()?;
        self.0
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: associated,
                },
            )
            .map_err(|_| SessionError::NotAuthentic)
    }
}

/// The receiving half of a connection.
pub struct Opener(Direction);

impl Opener {
    /// Decrypt one frame.
    ///
    /// # Errors
    /// [`SessionError::NotAuthentic`] if the frame was edited, replayed or
    /// reordered; [`SessionError::Exhausted`] once the counter is spent.
    pub fn open(&mut self, ciphertext: &[u8], associated: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce = self.0.next_nonce()?;
        self.0
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: associated,
                },
            )
            .map_err(|_| SessionError::NotAuthentic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two sides of one connection.
    fn pair() -> (Session, Session) {
        let a = [7u8; 32];
        let b = [9u8; 32];
        (Session::new(a, b), Session::new(b, a))
    }

    #[test]
    fn what_one_side_seals_the_other_opens() {
        let (mut alice, mut bob) = pair();
        let frame = alice.seal(b"a vote", b"6").expect("seals");
        assert_ne!(frame, b"a vote", "the wire does not carry the plaintext");
        assert_eq!(bob.open(&frame, b"6").expect("opens"), b"a vote");
    }

    #[test]
    fn an_edited_frame_does_not_open() {
        let (mut alice, mut bob) = pair();
        let mut frame = alice.seal(b"prevote for block A", b"19").expect("seals");
        frame[0] ^= 0x01;
        assert_eq!(bob.open(&frame, b"19"), Err(SessionError::NotAuthentic));
    }

    #[test]
    fn an_edited_length_does_not_open() {
        // The length travels in the clear, so it is authenticated instead. An
        // on-path attacker who rewrites it gets a dead connection rather than a
        // reader that takes the wrong number of bytes.
        let (mut alice, mut bob) = pair();
        let frame = alice.seal(b"payload", b"7").expect("seals");
        assert_eq!(bob.open(&frame, b"8"), Err(SessionError::NotAuthentic));
    }

    #[test]
    fn a_replayed_frame_does_not_open() {
        // The counter is the replay defence: the second delivery of one frame is
        // decrypted under the *next* nonce and fails. Without it, a recorded
        // prevote could be pushed back at a node forever.
        let (mut alice, mut bob) = pair();
        let frame = alice.seal(b"precommit", b"9").expect("seals");
        assert!(bob.open(&frame, b"9").is_ok());
        assert_eq!(bob.open(&frame, b"9"), Err(SessionError::NotAuthentic));
    }

    #[test]
    fn frames_delivered_out_of_order_do_not_open() {
        // TCP gives us ordering; the session does not assume it. Reordering is
        // indistinguishable from tampering here, and both are fatal.
        let (mut alice, mut bob) = pair();
        let first = alice.seal(b"one", b"3").expect("seals");
        let second = alice.seal(b"two", b"3").expect("seals");
        assert_eq!(bob.open(&second, b"3"), Err(SessionError::NotAuthentic));
        // And having consumed a counter on the failure, the stream is finished:
        // there is no resynchronising, which is why the caller drops the peer.
        assert_eq!(bob.open(&first, b"3"), Err(SessionError::NotAuthentic));
    }

    #[test]
    fn a_frame_cannot_be_reflected_back_at_its_sender() {
        // One key per direction. With a single shared key, an attacker could
        // echo Alice's own frame at her and have it authenticate as Bob's.
        let (mut alice, _bob) = pair();
        let frame = alice.seal(b"proposal", b"8").expect("seals");
        let mut alice_again = Session::new([7u8; 32], [9u8; 32]);
        assert_eq!(
            alice_again.open(&frame, b"8"),
            Err(SessionError::NotAuthentic)
        );
    }

    #[test]
    fn a_session_refuses_to_reuse_a_nonce() {
        // A repeated nonce under one key destroys both messages that used it, so
        // exhaustion has to end the connection rather than wrap.
        let mut session = Session::new([1u8; 32], [2u8; 32]);
        session.send.counter = u64::MAX;
        assert_eq!(session.seal(b"last", b""), Err(SessionError::Exhausted));
    }

    #[test]
    fn a_split_session_is_the_same_session() {
        // The halves have to keep the counters they started with, or the first
        // frame after a split fails to open.
        let (alice, bob) = pair();
        let (mut seal, _) = alice.split();
        let (_, mut open) = bob.split();
        let frame = seal.seal(b"proposal", b"8").expect("seals");
        assert_eq!(open.open(&frame, b"8").expect("opens"), b"proposal");
    }

    #[test]
    fn a_long_conversation_stays_in_step() {
        let (mut alice, mut bob) = pair();
        for i in 0..500u32 {
            let payload = i.to_le_bytes();
            let frame = alice.seal(&payload, b"").expect("seals");
            assert_eq!(bob.open(&frame, b"").expect("opens"), payload);
        }
        assert_eq!(alice.frames_sent(), 500);
    }
}
