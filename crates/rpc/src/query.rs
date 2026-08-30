//! Request and response types, and their canonical wire encoding.

use afrolink_alias::{ContactCommitment, Username};
use afrolink_consensus::{Commit, ValidatorSet};
use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::merkle::{MerkleProof, leaf_hash};
use afrolink_executor::{Block, BlockHeader, TxReceipt};
use afrolink_light::{LightClient, LightError};
use afrolink_primitives::codec::decode_exact;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Amount, ChainId, Denom, Height};
use afrolink_state::{Proof, StoreKey};
use afrolink_types::Transaction;
use thiserror::Error;

/// Why a query could not be answered.
///
/// Note what is **not** here: there is no "trust me" failure mode. A server
/// either produces a proof or reports that it cannot answer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// The node does not have that height — pruned, or not yet reached.
    #[error("height {0} is not available on this node")]
    NoSuchHeight(u64),
    /// The node has the block but not the commit that finalises it.
    #[error("no commit stored for height {0}")]
    NoCommit(u64),
    /// No transaction with that id, on this node.
    #[error("no transaction {0} on this node")]
    NoSuchTransaction(String),
    /// This node does not keep the index the query needs.
    ///
    /// Distinct from an empty answer, and the distinction is the point: a node
    /// that does not index history must not reply *"you have no payments"*. A
    /// serving node keeps the index; a validator with pruning on may not.
    #[error("this node does not maintain {0}")]
    NotIndexed(&'static str),
    /// The storage layer failed.
    ///
    /// Distinct from "not found" on purpose: a disk error that reads as an
    /// absent account would let a failing node silently report zero balances.
    #[error("backend error: {0}")]
    Backend(String),
}

/// What a client is asking for.
///
/// Every variant that touches state is answered with a [`ProvedValue`]. The
/// typed variants exist so a client never has to build raw key bytes and a
/// server never has to parse them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// The node's current tip, with the commit that finalises it.
    Status,
    /// One header and its commit.
    Header {
        /// Height wanted.
        height: Height,
    },
    /// An account's balance in one denomination.
    Balance {
        /// Account to look up.
        address: Address,
        /// Denomination.
        denom: Denom,
    },
    /// An account record: nonce, and public key once revealed.
    Account {
        /// Account to look up.
        address: Address,
    },
    /// Total supply of a denomination.
    Supply {
        /// Denomination.
        denom: Denom,
    },
    /// The registered issuer of a sovereign denomination.
    Issuer {
        /// Denomination.
        denom: Denom,
    },
    /// Whether an issuer has frozen an account for its own denomination.
    Frozen {
        /// Denomination.
        denom: Denom,
        /// Account to check.
        address: Address,
    },

    // -- Human-readable addressing (ADR-0008) --------------------------------
    /// Which account a username points at.
    ResolveName {
        /// The name to look up.
        name: Username,
    },
    /// Which account a phone or email commitment points at.
    ///
    /// Takes a commitment, so a node serving this query never learns the
    /// identifier and a chain scrape never reveals one.
    ResolveContact {
        /// Commitment to the identifier.
        commitment: ContactCommitment,
    },
    /// The name a wallet should display for an address.
    PrimaryAlias {
        /// The address to name.
        address: Address,
    },

    // -- Payment history ([ADR-0014](../../../docs/adr/0014-payment-history-and-the-mempool.md)) --
    /// A whole block, transactions included.
    ///
    /// The fully-verifiable form: a client that has the header can recompute
    /// `tx_root` over what it received and know it has *all* of the block, not
    /// a chosen subset.
    Block {
        /// Height wanted.
        height: Height,
    },
    /// One transaction, with an inclusion proof against its block's `tx_root`.
    ///
    /// The compact form, for a phone that knows a transaction id and does not
    /// want the block it sits in.
    Transaction {
        /// The transaction's id.
        id: Hash32,
    },
    /// Which transactions touched an account, oldest first.
    ///
    /// **The one query whose answer is not proved.** See [`History`].
    History {
        /// Account to look up.
        address: Address,
        /// Lowest height to consider. Paging resumes from the last height seen.
        from: Height,
        /// Most entries to return, capped at [`MAX_HISTORY`].
        limit: u32,
    },
}

/// Largest number of history entries one query may return.
///
/// A cap rather than a courtesy: without one, `limit: u32::MAX` against a busy
/// exchange address is a cheap way to make a node build an enormous response.
pub const MAX_HISTORY: u32 = 200;

impl Query {
    /// The state key this query resolves to, if it is a state query.
    ///
    /// A client calls this to know what to verify against; a server calls it to
    /// know what to prove. Both derive the key from the *same* function, so a
    /// mismatch is impossible by construction rather than by convention.
    #[must_use]
    pub fn store_key(&self) -> Option<StoreKey> {
        match self {
            Self::Status
            | Self::Header { .. }
            | Self::Block { .. }
            | Self::Transaction { .. }
            | Self::History { .. } => None,
            Self::Balance { address, denom } => Some(StoreKey::balance(address, denom)),
            Self::Account { address } => Some(StoreKey::account(address)),
            Self::Supply { denom } => Some(StoreKey::supply(denom)),
            Self::Issuer { denom } => Some(StoreKey::issuer(denom)),
            Self::Frozen { denom, address } => Some(StoreKey::frozen(denom, address)),
            Self::ResolveName { name } => Some(StoreKey::alias(name.as_str())),
            Self::ResolveContact { commitment } => Some(StoreKey::contact(commitment.as_hash())),
            Self::PrimaryAlias { address } => Some(StoreKey::alias_reverse(address)),
        }
    }
}

/// A header together with the commit that finalises it.
///
/// The two always travel together. A header on its own is an unsupported claim,
/// and bundling them means a server cannot hand out one without the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeader {
    /// The block header.
    pub header: BlockHeader,
    /// Precommit signatures from more than two thirds of voting power.
    pub commit: Commit,
}

impl SignedHeader {
    /// Check that the commit finalises *this* header and carries a quorum.
    ///
    /// Two separate claims, and both matter. A commit can be perfectly valid
    /// and finalise a different block; checking only the signatures would let a
    /// server pair a real commit with a header of its choosing.
    ///
    /// This does not advance any trust state — see
    /// [`LightClient::update`](afrolink_light::LightClient::update) for that.
    ///
    /// # Errors
    /// Returns [`LightError::HeaderMismatch`] if the commit is for another
    /// block, or the underlying [`CommitError`](afrolink_consensus::CommitError)
    /// if the signatures do not reach a quorum.
    pub fn verify(&self, chain_id: &ChainId, validators: &ValidatorSet) -> Result<(), LightError> {
        if self.commit.block_id != self.header.id() || self.commit.height != self.header.height {
            return Err(LightError::HeaderMismatch);
        }
        self.commit.verify(chain_id, validators)?;
        Ok(())
    }
}

/// A node's view of its own tip.
///
/// Carries the tip as a [`SignedHeader`] rather than a bare height so that even
/// "how far along are you?" is an answer a client can check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The network this node believes it is on.
    pub chain_id: ChainId,
    /// The tip, with its commit.
    pub tip: SignedHeader,
}

/// A state value with the proof that it belongs to a committed state root.
///
/// **The value is not readable without verifying it.** See the crate docs for
/// why that is a type-level guarantee here rather than a convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvedValue {
    height: Height,
    value: Option<Vec<u8>>,
    proof: Proof,
}

impl ProvedValue {
    /// Build an answer. Callable only inside this crate, by a server that has
    /// just produced the proof from the same tree it read the value from.
    pub(crate) fn new(height: Height, value: Option<Vec<u8>>, proof: Proof) -> Self {
        Self {
            height,
            value,
            proof,
        }
    }

    /// The height whose state root this proof is against.
    #[must_use]
    pub fn height(&self) -> Height {
        self.height
    }

    /// The proof itself.
    #[must_use]
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Check the proof against a trusted header and return the value.
    ///
    /// `key` must be the client's *own* reconstruction — normally
    /// [`Query::store_key`] on the query it sent. Passing a key taken from the
    /// server would defeat the check.
    ///
    /// A `None` result is a proved absence, not a missing answer.
    ///
    /// # Errors
    /// Returns [`LightError::BadProof`] if the proof does not reconstruct the
    /// trusted `app_hash`.
    pub fn verify(
        &self,
        client: &LightClient,
        key: &StoreKey,
    ) -> Result<Option<&[u8]>, LightError> {
        client.verify_value(key, self.value.as_deref(), &self.proof)?;
        Ok(self.value.as_deref())
    }

    /// Verify and decode as an [`Amount`], treating a proved absence as zero.
    ///
    /// An unfunded account and a zero balance are the same thing, and here both
    /// are proved rather than assumed.
    ///
    /// # Errors
    /// Returns [`LightError::BadProof`] or [`LightError::MalformedValue`].
    pub fn verify_amount(
        &self,
        client: &LightClient,
        key: &StoreKey,
    ) -> Result<Amount, LightError> {
        match self.verify(client, key)? {
            None => Ok(Amount::ZERO),
            Some(bytes) => decode_exact::<Amount>(bytes).map_err(|_| LightError::MalformedValue),
        }
    }

    /// Read the value without checking the proof.
    ///
    /// Deliberately verbose. Legitimate for a node reading its own state or for
    /// diagnostics; in a wallet it is a bug, and the name is meant to make that
    /// visible in review.
    #[must_use]
    pub fn value_unverified(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

/// A transaction with an inclusion proof against its block's `tx_root`.
///
/// # What is proved, and what is not
///
/// **Proved:** this transaction is in the block whose header you hold. The leaf
/// is the transaction's own id, so a server cannot substitute a different
/// transaction and keep the proof.
///
/// **Not proved:** *where* in the block it sits. The verifier knows the
/// `tx_root` and the transaction id; it does not independently know the index
/// or how many transactions the block held, so both come from the prover. A
/// server can therefore claim a truthful inclusion at a false position.
///
/// That is a display detail rather than a value bug — the inclusion claim holds
/// either way — but it is recorded here rather than glossed, for the same
/// reason `MerkleProof::verify` was changed to take sizes as parameters
/// ([08](../../../docs/08-adversarial-testing.md) §3 & 4). A client that needs
/// the position to be verified should ask for [`Query::Block`] and recompute
/// the root itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvedTransaction {
    height: Height,
    index: u32,
    total: u32,
    transaction: Transaction,
    siblings: Vec<Hash32>,
    receipt: TxReceipt,
    receipt_siblings: Vec<Hash32>,
}

/// What a verified [`ProvedTransaction`] yields: the transaction and what it did.
///
/// Both or neither. Returning them together is what stops a caller proving
/// inclusion and then reading the receipt as though it had been proved too —
/// the receipt is the half that carries the history links, so an unverified one
/// is a chain an attacker chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvedEffects<'a> {
    /// The transaction, proved against the header's `tx_root`.
    pub transaction: &'a Transaction,
    /// What it did, proved against the header's `outcome_root`.
    pub receipt: &'a TxReceipt,
}

impl ProvedTransaction {
    pub(crate) fn new(
        height: Height,
        index: u32,
        total: u32,
        transaction: Transaction,
        siblings: Vec<Hash32>,
        receipt: TxReceipt,
        receipt_siblings: Vec<Hash32>,
    ) -> Self {
        Self {
            height,
            index,
            total,
            transaction,
            siblings,
            receipt,
            receipt_siblings,
        }
    }

    /// The block this transaction is claimed to be in.
    #[must_use]
    pub fn height(&self) -> Height {
        self.height
    }

    /// The position claimed by the server. Advisory — see the type docs.
    #[must_use]
    pub fn index_unverified(&self) -> u32 {
        self.index
    }

    /// Check the inclusion proof against a header, and return the transaction.
    ///
    /// `header` must be one the caller has already verified — normally through
    /// [`SignedHeader::verify`] or
    /// [`LightClient::update`](afrolink_light::LightClient::update). The height
    /// is checked against it, so a proof for another block cannot be presented
    /// against this one.
    ///
    /// # Errors
    /// [`LightError::HeaderMismatch`] if the header is for another height, or
    /// [`LightError::BadProof`] if the proof does not reconstruct `tx_root`.
    pub fn verify(&self, header: &BlockHeader) -> Result<ProvedEffects<'_>, LightError> {
        if header.height != self.height {
            return Err(LightError::HeaderMismatch);
        }
        let index = self.index as usize;
        let total = self.total as usize;

        self.check(
            &self.siblings,
            header.tx_root,
            leaf_hash(self.transaction.id().as_bytes()),
            index,
            total,
        )?;

        // The two trees have the same leaves in the same order — one receipt per
        // transaction, in execution order — so one position serves both. A
        // receipt proved at a different index than its transaction would be a
        // receipt for someone else's payment.
        self.check(
            &self.receipt_siblings,
            header.outcome_root,
            leaf_hash(&self.receipt.to_bytes()),
            index,
            total,
        )?;

        // The receipt must be about this transaction. Both proofs can succeed
        // against a well-formed block while describing different rows if a
        // server pairs them wrongly, and this is the check that catches it.
        if self.receipt.tx_id != self.transaction.id() {
            return Err(LightError::BadProof);
        }

        Ok(ProvedEffects {
            transaction: &self.transaction,
            receipt: &self.receipt,
        })
    }

    fn check(
        &self,
        siblings: &[Hash32],
        root: Hash32,
        leaf: Hash32,
        index: usize,
        total: usize,
    ) -> Result<(), LightError> {
        MerkleProof {
            index,
            total,
            siblings: siblings.to_vec(),
        }
        .verify(root, leaf, index, total)
        .map_err(|_| LightError::BadProof)
    }

    /// Read the transaction without checking the proof.
    ///
    /// Named like [`ProvedValue::value_unverified`], and for the same reason.
    #[must_use]
    pub fn transaction_unverified(&self) -> &Transaction {
        &self.transaction
    }

    /// Read the receipt without checking the proof.
    #[must_use]
    pub fn receipt_unverified(&self) -> &TxReceipt {
        &self.receipt
    }
}

/// One entry in an account's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Block the transaction was included in.
    pub height: Height,
    /// Position within that block.
    pub index: u32,
    /// The transaction's id.
    pub tx_id: Hash32,
}

/// Which transactions touched an account — **a hint, not a proof.**
///
/// # Read this before using it
///
/// Every other answer in this crate is verifiable. This one cannot be, and
/// pretending otherwise would be worse than not offering it.
///
/// A transaction index is a node's private convenience. It is not in the state
/// tree, no header commits to it, and two honest nodes are free to keep
/// different ones. So a server can **omit entries** — it can hide a payment from
/// you — and nothing in the response reveals that.
///
/// What it *cannot* do is invent one. Every entry names a transaction id, and
/// [`Query::Transaction`] turns that into a proof against a header you trust. So
/// the safe pattern is:
///
/// > Use the history to learn **where to look**. Use an inclusion proof to learn
/// > **what is true**.
///
/// A client that needs completeness rather than convenience has to scan blocks
/// itself over the range it cares about, or compare several independent nodes —
/// the same shape of answer as [`crates/witness`](afrolink_rpc), where
/// corroboration substitutes for a proof that cannot exist.
///
/// The accessor is [`Self::entries_unverified`], spelled that way on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    address: Address,
    entries: Vec<HistoryEntry>,
    truncated: bool,
}

impl History {
    /// Build a history answer.
    pub(crate) fn new(address: Address, entries: Vec<HistoryEntry>, truncated: bool) -> Self {
        Self {
            address,
            entries,
            truncated,
        }
    }

    /// The account this history is for.
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Whether the scan stopped at the limit rather than at the end.
    ///
    /// A caller that ignores this and shows the result as a complete history
    /// will silently truncate a busy account, which is why it is not merely
    /// implied by `entries.len() == limit`.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// The entries. **Unverified**, by construction — see the type docs.
    #[must_use]
    pub fn entries_unverified(&self) -> &[HistoryEntry] {
        &self.entries
    }
}

/// What a server sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Answer to [`Query::Status`].
    Status(Status),
    /// Answer to [`Query::Header`].
    Header(SignedHeader),
    /// Answer to any state query.
    Value(ProvedValue),
    /// Answer to [`Query::Block`].
    Block(Box<Block>),
    /// Answer to [`Query::Transaction`].
    Transaction(Box<ProvedTransaction>),
    /// Answer to [`Query::History`].
    History(History),
}

impl Response {
    /// The proved value, if this response carries one.
    #[must_use]
    pub fn as_value(&self) -> Option<&ProvedValue> {
        match self {
            Self::Value(v) => Some(v),
            Self::Status(_)
            | Self::Header(_)
            | Self::Block(_)
            | Self::Transaction(_)
            | Self::History(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

impl Encode for Query {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Status => out.push(0),
            Self::Header { height } => {
                out.push(1);
                height.encode(out);
            }
            Self::Balance { address, denom } => {
                out.push(2);
                address.encode(out);
                denom.encode(out);
            }
            Self::Account { address } => {
                out.push(3);
                address.encode(out);
            }
            Self::Supply { denom } => {
                out.push(4);
                denom.encode(out);
            }
            Self::Issuer { denom } => {
                out.push(5);
                denom.encode(out);
            }
            Self::Frozen { denom, address } => {
                out.push(6);
                denom.encode(out);
                address.encode(out);
            }
            Self::ResolveName { name } => {
                out.push(7);
                name.encode(out);
            }
            Self::ResolveContact { commitment } => {
                out.push(8);
                commitment.encode(out);
            }
            Self::PrimaryAlias { address } => {
                out.push(9);
                address.encode(out);
            }
            Self::Block { height } => {
                out.push(10);
                height.encode(out);
            }
            Self::Transaction { id } => {
                out.push(11);
                id.encode(out);
            }
            Self::History {
                address,
                from,
                limit,
            } => {
                out.push(12);
                address.encode(out);
                from.encode(out);
                limit.encode(out);
            }
        }
    }
}

impl Decode for Query {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Status),
            1 => Ok(Self::Header {
                height: Height::decode(r)?,
            }),
            2 => Ok(Self::Balance {
                address: Address::decode(r)?,
                denom: Denom::decode(r)?,
            }),
            3 => Ok(Self::Account {
                address: Address::decode(r)?,
            }),
            4 => Ok(Self::Supply {
                denom: Denom::decode(r)?,
            }),
            5 => Ok(Self::Issuer {
                denom: Denom::decode(r)?,
            }),
            6 => Ok(Self::Frozen {
                denom: Denom::decode(r)?,
                address: Address::decode(r)?,
            }),
            7 => Ok(Self::ResolveName {
                name: Username::decode(r)?,
            }),
            8 => Ok(Self::ResolveContact {
                commitment: ContactCommitment::decode(r)?,
            }),
            9 => Ok(Self::PrimaryAlias {
                address: Address::decode(r)?,
            }),
            10 => Ok(Self::Block {
                height: Height::decode(r)?,
            }),
            11 => Ok(Self::Transaction {
                id: Hash32::decode(r)?,
            }),
            12 => Ok(Self::History {
                address: Address::decode(r)?,
                from: Height::decode(r)?,
                limit: u32::decode(r)?,
            }),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "Query",
            }),
        }
    }
}

impl Encode for SignedHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        self.header.encode(out);
        self.commit.encode(out);
    }
}

impl Decode for SignedHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            header: BlockHeader::decode(r)?,
            commit: Commit::decode(r)?,
        })
    }
}

impl Encode for Status {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.tip.encode(out);
    }
}

impl Decode for Status {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: ChainId::decode(r)?,
            tip: SignedHeader::decode(r)?,
        })
    }
}

impl Encode for ProvedValue {
    fn encode(&self, out: &mut Vec<u8>) {
        self.height.encode(out);
        self.value.encode(out);
        self.proof.encode(out);
    }
}

impl Decode for ProvedValue {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::decode(r)?,
            value: Option::<Vec<u8>>::decode(r)?,
            proof: Proof::decode(r)?,
        })
    }
}

impl Encode for Response {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Status(status) => {
                out.push(0);
                status.encode(out);
            }
            Self::Header(header) => {
                out.push(1);
                header.encode(out);
            }
            Self::Value(value) => {
                out.push(2);
                value.encode(out);
            }
            Self::Block(block) => {
                out.push(3);
                block.encode(out);
            }
            Self::Transaction(proved) => {
                out.push(4);
                proved.encode(out);
            }
            Self::History(history) => {
                out.push(5);
                history.encode(out);
            }
        }
    }
}

impl Decode for Response {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Status(Status::decode(r)?)),
            1 => Ok(Self::Header(SignedHeader::decode(r)?)),
            2 => Ok(Self::Value(ProvedValue::decode(r)?)),
            3 => Ok(Self::Block(Box::new(Block::decode(r)?))),
            4 => Ok(Self::Transaction(Box::new(ProvedTransaction::decode(r)?))),
            5 => Ok(Self::History(History::decode(r)?)),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "Response",
            }),
        }
    }
}

impl Encode for ProvedTransaction {
    fn encode(&self, out: &mut Vec<u8>) {
        // `index` and `total` appear exactly once. The `MerkleProof` this
        // rebuilds also carries them, and encoding both copies would be two
        // sources of truth for one fact — the defect shape recorded in
        // [08](../../../docs/08-adversarial-testing.md) §3 & 4.
        self.height.encode(out);
        self.index.encode(out);
        self.total.encode(out);
        self.transaction.encode(out);
        self.siblings.encode(out);
        self.receipt.encode(out);
        self.receipt_siblings.encode(out);
    }
}

impl Decode for ProvedTransaction {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::decode(r)?,
            index: u32::decode(r)?,
            total: u32::decode(r)?,
            transaction: Transaction::decode(r)?,
            siblings: Vec::<Hash32>::decode(r)?,
            receipt: TxReceipt::decode(r)?,
            receipt_siblings: Vec::<Hash32>::decode(r)?,
        })
    }
}

impl Encode for HistoryEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        self.height.encode(out);
        self.index.encode(out);
        self.tx_id.encode(out);
    }
}

impl Decode for HistoryEntry {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::decode(r)?,
            index: u32::decode(r)?,
            tx_id: Hash32::decode(r)?,
        })
    }
}

impl Encode for History {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.entries.encode(out);
        self.truncated.encode(out);
    }
}

impl Decode for History {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            entries: Vec::<HistoryEntry>::decode(r)?,
            truncated: bool::decode(r)?,
        })
    }
}
