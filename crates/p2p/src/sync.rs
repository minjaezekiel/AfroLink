//! Catching up: how a node that fell behind gets the blocks it missed.
//!
//! # A synced block is proved, not trusted
//!
//! This is the one place where a node takes a whole block from a stranger, and
//! the temptation is to treat the peer as an authority. It is not one. What
//! travels here is a [`SyncBlock`] — a block **and the commit certificate that
//! finalised it** — and the receiving node checks that certificate against its
//! own validator set exactly as [`afrolink_light`] does for a phone. A peer that
//! invents a block cannot produce more than two thirds of the validators'
//! precommits over it, so the block dies at the receiver.
//!
//! Then the receiver re-executes it anyway. The certificate proves the *network*
//! agreed; re-execution is how this node ends up with the state rather than
//! taking somebody's word for a root hash. The two checks answer different
//! questions and neither replaces the other.
//!
//! # One block per frame, and why that is not a choice
//!
//! `MAX_BLOCK_BYTES` and [`crate::wire::MAX_FRAME_LEN`] are within one headroom
//! of each other, so a maximum-size block plus its certificate fills a frame on
//! its own. Batching several blocks into one response is therefore not available
//! to us, and the parallelism has to come from somewhere else: **one request in
//! flight per peer, across many peers**. That is slower than a batching protocol
//! on a fast link and considerably more robust on a slow one, because a stalled
//! peer costs one outstanding request rather than a whole batch window.
//!
//! # What is deliberately not here
//!
//! **State sync.** A new node replays every block from genesis. Tendermint and
//! Cosmos offer a snapshot path so a node can start near the tip without the
//! history; that is a real gap at scale and it is a separate piece of work, since
//! it needs the state tree served in verifiable chunks rather than blocks served
//! whole.
//!
//! **Validator set transitions.** [`Node::apply_synced`](afrolink_node::Node) checks
//! a commit against the validator set the node currently holds. That is sound
//! today because the set is fixed at genesis and every block carries it forward
//! unchanged. The moment validator set changes exist, this path needs what
//! `crates/light` already has — verification that walks the set forward across
//! the heights it is skipping — and until then a node syncing across a set change
//! would refuse the blocks rather than accept the wrong ones, which is the safe
//! direction to be wrong in.

use afrolink_consensus::Commit;
use afrolink_executor::Block;
use afrolink_primitives::Height;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

/// Outstanding block requests a node keeps across all its peers.
///
/// Bounded because each one is a promise to hold a reply in memory, and because
/// requesting a hundred heights at once from eight peers only means waiting on
/// the slowest of them for a window that is a hundred blocks wide.
pub const MAX_BLOCKS_IN_FLIGHT: usize = 8;

/// Blocks held aside because they arrived before their parent did.
///
/// Requests go out in parallel, so replies come back out of order, and a block
/// cannot be applied until the one before it has been. This is the buffer that
/// makes that difference survivable — and it is bounded, because otherwise a peer
/// that answers only with far-future heights fills a node's memory with blocks it
/// can never apply.
pub const MAX_STAGED_BLOCKS: usize = 16;

/// Ticks a block request may go unanswered before the height is asked elsewhere.
///
/// A peer that does not answer is not necessarily misbehaving — it may simply be
/// slow, or genuinely lack the block despite what it claimed. So the request is
/// abandoned rather than punished, and the height goes to somebody else.
pub const REQUEST_TIMEOUT_TICKS: u32 = 8;

/// A finalised block travelling between peers, with the proof that it is final.
///
/// The certificate is not an optional extra and is never separated from the
/// block in transit: a block without its commit is an unsupported claim, and a
/// commit without its block proves something about bytes nobody has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBlock {
    /// The block.
    pub block: Block,
    /// The precommits that finalised it.
    pub commit: Commit,
}

impl SyncBlock {
    /// The height this block claims to be.
    ///
    /// A claim, not a fact — `apply_synced` is what turns it into one.
    #[must_use]
    pub const fn height(&self) -> Height {
        self.block.header.height
    }
}

impl Encode for SyncBlock {
    fn encode(&self, out: &mut Vec<u8>) {
        self.block.encode(out);
        self.commit.encode(out);
    }
}

impl Decode for SyncBlock {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let block = Block::decode(r)?;
        let commit = Commit::decode(r)?;
        // Refused here rather than deeper in, so a mismatched pair never reaches
        // the code that verifies signatures — that check is expensive and this
        // one is free.
        if commit.height != block.header.height {
            return Err(CodecError::Invalid(format!(
                "a commit for height {} cannot finalise a block at height {}",
                commit.height.0, block.header.height.0
            )));
        }
        Ok(Self { block, commit })
    }
}

/// Where a node keeps the blocks it has already committed.
///
/// A trait rather than a concrete store, so this crate never learns what a
/// database is. `crates/store` implements it over redb; a test implements it over
/// a `Vec`. It is the same shape `crates/rpc` uses for `Submit`, and for the same
/// reason: the layer that decides is separable from the layer that persists.
///
/// **Served from the durable store, not from the running node's memory.** A node
/// serving from memory can only help peers who fell behind while it was up, which
/// is precisely the case where they needed the least help; and it would put every
/// sync request behind the same lock as consensus.
pub trait BlockSource: Send + Sync {
    /// The block at `height` with its certificate, if it is held.
    ///
    /// `None` covers both "beyond my tip" and "pruned", and the caller answers
    /// both with the same [`NoBlock`](crate::wire::PeerMessage::NoBlock) — a peer
    /// has no business learning which of the two it is, and the asker only needs
    /// to know to ask elsewhere.
    fn block_at(&self, height: Height) -> Option<SyncBlock>;
}

/// A source that holds nothing.
///
/// For a node that keeps no durable history: it can still sync *from* peers and
/// take part in consensus, it simply cannot help anyone else catch up. Stated as
/// a type rather than an `Option` so that "serves no blocks" is a decision
/// somebody made rather than a field somebody forgot.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBlocks;

impl BlockSource for NoBlocks {
    fn block_at(&self, _height: Height) -> Option<SyncBlock> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_consensus::{SignedVote, Vote, VoteType};
    use afrolink_crypto::SecretKey;
    use afrolink_crypto::hash::Hash32;
    use afrolink_executor::BlockHeader;
    use afrolink_primitives::codec::decode_exact;
    use afrolink_primitives::{ChainId, Round, Timestamp};

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").unwrap()
    }

    fn block(height: u64) -> Block {
        Block {
            header: BlockHeader {
                chain_id: chain(),
                height: Height(height),
                time: Timestamp::from_millis(1_700_000_000_000),
                parent: Hash32::from_bytes([1; 32]),
                tx_root: Block::tx_root(&[]),
                app_hash: Hash32::from_bytes([2; 32]),
                outcome_root: Hash32::from_bytes([4; 32]),
                validators_hash: Hash32::from_bytes([3; 32]),
                next_validators_hash: Hash32::from_bytes([3; 32]),
            },
            transactions: Vec::new(),
        }
    }

    fn commit(height: u64, block_id: Hash32) -> Commit {
        let key = SecretKey::from_bytes(&[1; 32]);
        let vote: SignedVote = Vote {
            chain_id: chain(),
            height: Height(height),
            round: Round(0),
            vote_type: VoteType::Precommit,
            block_id: Some(block_id),
            validator: afrolink_crypto::Address::from_public_key(&key.public_key()),
        }
        .sign(&key);
        Commit::new(Height(height), Round(0), block_id, vec![vote])
    }

    #[test]
    fn a_sync_block_round_trips_canonically() {
        let b = block(7);
        let sync = SyncBlock {
            commit: commit(7, b.header.id()),
            block: b,
        };
        let bytes = sync.to_bytes();
        let back = decode_exact::<SyncBlock>(&bytes).unwrap();
        assert_eq!(back, sync);
        assert_eq!(back.to_bytes(), bytes, "one encoding per value");
    }

    #[test]
    fn a_commit_for_a_different_height_does_not_even_decode() {
        // The cheapest of the checks, so it happens first. A pair this mismatched
        // must never reach the code that verifies eighty signatures.
        let b = block(7);
        let mut bytes = Vec::new();
        b.encode(&mut bytes);
        commit(9, b.header.id()).encode(&mut bytes);
        assert!(decode_exact::<SyncBlock>(&bytes).is_err());
    }
}
