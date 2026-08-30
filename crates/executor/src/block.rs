//! Block and header types.

use afrolink_consensus::ValidatorSet;
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
    /// Merkle root over the block's transaction receipts.
    ///
    /// `tx_root` says *what ran*; this says *what happened*. Without it a node
    /// can claim a payment failed when it succeeded, and a phone holding only
    /// headers has no way to check — the resulting state contradicts the lie,
    /// but only to someone willing to diff two whole states.
    ///
    /// It is also what makes an account's history walkable backwards: a receipt
    /// names the previous history pointer of every account the transaction
    /// touched, so a committed receipt is a committed link
    /// ([09](../../../docs/09-what-xrpl-answers.md) §2.1).
    pub outcome_root: Hash32,
    /// Commitment to the validator set that signed **this** block.
    ///
    /// Lets a light client check that a set handed to it is the one the chain
    /// committed to, rather than one an attacker chose.
    pub validators_hash: Hash32,
    /// Commitment to the validator set that will sign the **next** block.
    ///
    /// This is the field that makes skipping verification possible: a client
    /// verifying header `h` learns, from `h` itself, who is entitled to sign
    /// `h+1`. Without it a client must download every intervening header to
    /// follow validator set changes, which is the difference between syncing a
    /// phone in seconds and syncing it in hours
    /// ([ADR-0010](../../../docs/adr/0010-long-range-attacks.md)).
    pub next_validators_hash: Hash32,
}

impl BlockHeader {
    /// The block's identifier.
    #[must_use]
    pub fn id(&self) -> Hash32 {
        hash(Domain::BlockId, &self.to_bytes())
    }
}

/// The validator sets a header commits to.
///
/// Bundled rather than passed loose so the two can never be swapped at a call
/// site — reversing them would make a light client verify the wrong set and
/// silently break skipping verification.
#[derive(Debug, Clone, Copy)]
pub struct ValidatorSets<'a> {
    /// The set signing this block.
    pub current: &'a ValidatorSet,
    /// The set entitled to sign the next one.
    pub next: &'a ValidatorSet,
}

impl<'a> ValidatorSets<'a> {
    /// Both sets are the same — the common case, since the set changes rarely.
    #[must_use]
    pub fn unchanged(set: &'a ValidatorSet) -> Self {
        Self {
            current: set,
            next: set,
        }
    }
}

/// The height and time a block is being executed at.
///
/// Bundled rather than passed as two arguments for the same reason as
/// [`ValidatorSets`]: they are both scalars that a caller can silently swap, and
/// the compiler will not notice. Staking needs both — height decides what a
/// slash reaches, time decides when stake is released — so this is now the
/// execution context rather than an incidental pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContext {
    /// Height being executed.
    pub height: Height,
    /// The block's consensus timestamp.
    pub time: Timestamp,
}

/// Most transactions a block may carry.
///
/// **A consensus rule, not a policy knob.** Every validator re-executes every
/// proposal before voting on it, so without a bound a single proposer can make
/// the whole network do unbounded work for the cost of one message. There is no
/// signature or stake check that catches this, because the proposer is entitled
/// to propose — the only defence is a limit both sides agree on.
///
/// At ~1s blocks this is roughly 10 000 transactions a second, which is far more
/// than the network will see and far less than a machine can be made to choke on.
pub const MAX_BLOCK_TRANSACTIONS: usize = 10_000;

/// Largest encoded size of a block's transactions, in bytes.
///
/// A companion to [`MAX_BLOCK_TRANSACTIONS`], because the two bound different
/// attacks: a count limit alone still admits ten thousand maximum-size
/// transactions, and a byte limit alone still admits a million tiny ones.
pub const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;

/// A block: a header and the transactions it commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The header.
    pub header: BlockHeader,
    /// Transactions, in execution order. Order is consensus-critical.
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Whether this block is within the size a validator will execute.
    ///
    /// Checked **before** execution, never after: the point is to refuse the
    /// work, and a check that runs afterwards has already paid for it.
    #[must_use]
    pub fn within_size_limits(&self) -> bool {
        if self.transactions.len() > MAX_BLOCK_TRANSACTIONS {
            return false;
        }
        let mut bytes = 0usize;
        for transaction in &self.transactions {
            bytes = bytes.saturating_add(transaction.to_bytes().len());
            if bytes > MAX_BLOCK_BYTES {
                return false;
            }
        }
        true
    }

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
        self.outcome_root.encode(out);
        self.validators_hash.encode(out);
        self.next_validators_hash.encode(out);
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
            outcome_root: Hash32::decode(r)?,
            validators_hash: Hash32::decode(r)?,
            next_validators_hash: Hash32::decode(r)?,
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
