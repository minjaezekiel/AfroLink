//! Domain-separated hashing.
//!
//! Every hash in the protocol is computed over `len(domain) || domain || data`.
//! Without this, a structure hashed in one context could be reinterpreted in
//! another — the classic example being a transaction body that also parses as a
//! block header, letting a signature be replayed across the two. Prefixing the
//! domain with its length makes the encoding injective, so no two distinct
//! (domain, data) pairs can ever produce the same input to the compression
//! function.

use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

/// A 256-bit BLAKE3 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    /// The all-zero hash, used as the parent of the genesis block.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Wrap raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex rendering.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Whether bit `i` (counting from the most significant bit of byte 0) is set.
    ///
    /// Used by the sparse Merkle tree to walk a key down the trie.
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "`offset` is `i % 8`, so `7 - offset` is in 0..=7 and cannot underflow; \
                  the byte index is bounds-checked by `get`"
    )]
    pub fn bit(&self, i: usize) -> bool {
        // Out-of-range indices return false rather than panicking: this is called
        // from consensus code where a panic would halt the node.
        let (byte, offset) = (i / 8, i % 8);
        self.0
            .get(byte)
            .is_some_and(|b| (b >> (7 - offset)) & 1 == 1)
    }
}

impl core::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Short form: full 64-char hashes make logs unreadable.
        write!(f, "{}…", &self.to_hex().get(..12).unwrap_or_default())
    }
}

impl core::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Encode for Hash32 {
    fn encode(&self, out: &mut Vec<u8>) {
        // Fixed 32 bytes: no length prefix needed, and omitting it keeps headers small.
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Hash32 {
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        Ok(Self(r.take_array::<32>()?))
    }
}

/// A hashing context. Each variant is a distinct, non-overlapping namespace.
///
/// Adding a variant is a consensus change: never reuse or renumber a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// Derives an [`crate::Address`] from a public key.
    Address,
    /// The bytes a transaction signature commits to.
    TxSignDoc,
    /// A transaction's identifier.
    TxId,
    /// A block header's identifier.
    BlockId,
    /// A leaf in a binary Merkle tree.
    MerkleLeaf,
    /// An internal node in a binary Merkle tree.
    MerkleNode,
    /// A leaf in the sparse Merkle state tree.
    StateLeaf,
    /// An internal node in the sparse Merkle state tree.
    StateNode,
    /// The bytes a consensus vote signature commits to.
    VoteSignDoc,
    /// A validator's identifier within a validator set.
    ValidatorId,
    /// Derives the address of a group account from its creator and nonce.
    GroupAddress,
    /// A module-owned account address, derived from the module's name.
    ModuleAddress,
    /// Commits to a validator set, so a header can name who may sign the next
    /// block without carrying the whole set.
    ValidatorSetHash,
    /// Commits to a phone number or email address without revealing it.
    ///
    /// The identifier never reaches the chain; only this commitment does. The
    /// domain keeps a contact commitment from ever colliding with an address or
    /// a state leaf, so a commitment can never be mistaken for one.
    ContactCommitment,
    /// Derives a witness log's identifier from its public key.
    ///
    /// Binding the identifier to the key means a log cannot be impersonated by
    /// claiming someone else's name.
    WitnessLogId,
    /// The bytes a witness signs when it publishes a tree head.
    ///
    /// Separate from every other signing domain so a tree head can never be
    /// replayed as a vote, a transaction, or a contact attestation.
    TreeHeadSignDoc,
    /// A leaf in a witness log: one observation of the chain.
    WitnessEntry,
    /// The handshake transcript two peers must agree on before they trust each
    /// other.
    ///
    /// Covers the protocol version, the chain id, and both ephemeral public
    /// keys in sorted order. Sorting is the fix for the malleability class that
    /// broke Tendermint's Secret Connection before 0.33: without it, an
    /// attacker who injects an ephemeral key can make both sides derive a
    /// transcript it also knows.
    P2pTranscript,
    /// Derives a directional session key from the Diffie–Hellman secret and the
    /// transcript.
    P2pSessionKey,
    /// The bytes a node's long-term key signs to prove it holds the identity it
    /// claims.
    ///
    /// Separate from every other signing domain, so a handshake signature can
    /// never be presented as a consensus vote and a vote can never be replayed
    /// into a handshake.
    P2pHandshakeSignDoc,
    /// Identifies a genesis document, so operators can compare one string.
    ///
    /// Every node on a chain must agree byte for byte on its genesis — the
    /// validator set, the allocations, the council, the parameters. This is what
    /// turns that agreement into something two people can check over a phone
    /// call, rather than a diff of a file neither of them can read aloud.
    GenesisId,
    /// Places an address into an address-book bucket.
    ///
    /// Salted with a secret only the node knows, so an attacker cannot compute
    /// in advance which bucket an address of theirs will occupy — which is what
    /// makes filling a specific bucket expensive rather than free.
    P2pAddrBucket,
}

impl Domain {
    /// The stable, human-readable separator string written into the hash input.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Address => "afrolink/v1/address",
            Self::TxSignDoc => "afrolink/v1/tx-sign-doc",
            Self::TxId => "afrolink/v1/tx-id",
            Self::BlockId => "afrolink/v1/block-id",
            Self::MerkleLeaf => "afrolink/v1/merkle-leaf",
            Self::MerkleNode => "afrolink/v1/merkle-node",
            Self::StateLeaf => "afrolink/v1/state-leaf",
            Self::StateNode => "afrolink/v1/state-node",
            Self::VoteSignDoc => "afrolink/v1/vote-sign-doc",
            Self::ValidatorId => "afrolink/v1/validator-id",
            Self::GroupAddress => "afrolink/v1/group-address",
            Self::ModuleAddress => "afrolink/v1/module-address",
            Self::ValidatorSetHash => "afrolink/v1/validator-set-hash",
            Self::ContactCommitment => "afrolink/v1/contact-commitment",
            Self::WitnessLogId => "afrolink/v1/witness-log-id",
            Self::TreeHeadSignDoc => "afrolink/v1/tree-head-sign-doc",
            Self::WitnessEntry => "afrolink/v1/witness-entry",
            Self::P2pTranscript => "afrolink/v1/p2p-transcript",
            Self::P2pSessionKey => "afrolink/v1/p2p-session-key",
            Self::P2pHandshakeSignDoc => "afrolink/v1/p2p-handshake-sign-doc",
            Self::GenesisId => "afrolink/v1/genesis-id",
            Self::P2pAddrBucket => "afrolink/v1/p2p-addr-bucket",
        }
    }
}

/// Hash `data` within `domain`.
#[must_use]
pub fn hash(domain: Domain, data: &[u8]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    absorb_domain(&mut hasher, domain);
    hasher.update(data);
    Hash32(*hasher.finalize().as_bytes())
}

/// Hash the concatenation of several parts within `domain`.
///
/// The parts are *not* individually length-prefixed, so callers must only pass
/// fixed-width pieces (hashes, integers) or encode variable-length data with the
/// canonical codec first.
#[must_use]
pub fn hash_parts(domain: Domain, parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    absorb_domain(&mut hasher, domain);
    for part in parts {
        hasher.update(part);
    }
    Hash32(*hasher.finalize().as_bytes())
}

fn absorb_domain(hasher: &mut blake3::Hasher, domain: Domain) {
    let d = domain.as_str().as_bytes();
    // Length-prefixed so that (domain, data) → bytes is injective.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "domain strings are short constants"
    )]
    let len = d.len() as u32;
    hasher.update(&len.to_le_bytes());
    hasher.update(d);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_separate_identical_payloads() {
        let data = b"same bytes";
        assert_ne!(hash(Domain::TxId, data), hash(Domain::BlockId, data));
    }

    #[test]
    fn hashing_is_deterministic() {
        assert_eq!(hash(Domain::TxId, b"abc"), hash(Domain::TxId, b"abc"));
    }

    #[test]
    fn length_prefix_makes_domain_encoding_injective() {
        // Without the length prefix, a domain "ab" + data "c" and a domain "abc"
        // with empty data would hash identically. They must not.
        let a = hash_parts(Domain::MerkleLeaf, &[b"x"]);
        let b = hash_parts(Domain::MerkleNode, &[b"x"]);
        assert_ne!(a, b);
    }

    #[test]
    fn bit_indexing_reads_msb_first() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0b1000_0000;
        let h = Hash32::from_bytes(bytes);
        assert!(h.bit(0), "bit 0 is the most significant bit of byte 0");
        assert!(!h.bit(1));
    }

    #[test]
    fn out_of_range_bit_does_not_panic() {
        assert!(!Hash32::ZERO.bit(10_000));
    }

    #[test]
    fn hash_round_trips_through_codec() {
        let h = hash(Domain::TxId, b"payload");
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 32, "hashes encode without a length prefix");
        assert_eq!(
            afrolink_primitives::codec::decode_exact::<Hash32>(&bytes),
            Ok(h)
        );
    }
}
