//! Block and header types.

use afrolink_crypto::hash::{Domain, Hash32, hash};
use afrolink_crypto::merkle::MerkleTree;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{ChainId, Height, Timestamp};
use afrolink_types::Transaction;

/// A block header.
///
/// Small on purpose: this is what a phone syncs. Everything a light client needs
/// to verify a claim about the ledger is in here — `tx_root` proves a
/// transaction was included, `app_hash` proves what the state became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// Network this block belongs to.
    pub chain_id: ChainId,
    /// This block's height. Genesis is 0.
    pub height: Height,
    /// Consensus timestamp, agreed by the validator set rather than read from a
    /// local clock.
    pub time: Timestamp,
    /// Identifier of the parent block. Zero at genesis.
    pub parent: Hash32,
    /// Merkle root over the block's transactions.
    pub tx_root: Hash32,
    /// State root *after* this block is applied.
    pub app_hash: Hash32,
}

impl BlockHeader {
    /// The block's identifier.
    #[must_use]
    pub fn id(&self) -> Hash32 {
        hash(Domain::BlockId, &self.to_bytes())
    }
}

/// A block: a header and the transactions it commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The header.
    pub header: BlockHeader,
    /// Transactions, in execution order. Order is consensus-critical.
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Compute the Merkle root over a transaction list.
    ///
    /// Leaves are transaction *ids*, so a light client can prove inclusion of a
    /// transaction it knows the id of without holding the block.
    #[must_use]
    pub fn tx_root(transactions: &[Transaction]) -> Hash32 {
        MerkleTree::from_items(transactions.iter().map(|tx| tx.id().as_bytes().to_vec())).root()
    }

    /// Whether the header's `tx_root` matches the transactions carried.
    #[must_use]
    pub fn tx_root_matches(&self) -> bool {
        self.header.tx_root == Self::tx_root(&self.transactions)
    }
}

impl Encode for BlockHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.height.encode(out);
        self.time.encode(out);
        self.parent.encode(out);
        self.tx_root.encode(out);
        self.app_hash.encode(out);
    }
}

impl Decode for BlockHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: ChainId::decode(r)?,
            height: Height::decode(r)?,
            time: Timestamp::decode(r)?,
            parent: Hash32::decode(r)?,
            tx_root: Hash32::decode(r)?,
            app_hash: Hash32::decode(r)?,
        })
    }
}

impl Encode for Block {
    fn encode(&self, out: &mut Vec<u8>) {
        self.header.encode(out);
        self.transactions.encode(out);
    }
}

impl Decode for Block {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            header: BlockHeader::decode(r)?,
            transactions: Vec::<Transaction>::decode(r)?,
        })
    }
}
