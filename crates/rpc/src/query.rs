//! Request and response types, and their canonical wire encoding.

use afrolink_consensus::{Commit, ValidatorSet};
use afrolink_crypto::Address;
use afrolink_executor::BlockHeader;
use afrolink_light::{LightClient, LightError};
use afrolink_primitives::codec::decode_exact;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Amount, ChainId, Denom, Height};
use afrolink_state::{Proof, StoreKey};
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
}

impl Query {
    /// The state key this query resolves to, if it is a state query.
    ///
    /// A client calls this to know what to verify against; a server calls it to
    /// know what to prove. Both derive the key from the *same* function, so a
    /// mismatch is impossible by construction rather than by convention.
    #[must_use]
    pub fn store_key(&self) -> Option<StoreKey> {
        match self {
            Self::Status | Self::Header { .. } => None,
            Self::Balance { address, denom } => Some(StoreKey::balance(address, denom)),
            Self::Account { address } => Some(StoreKey::account(address)),
            Self::Supply { denom } => Some(StoreKey::supply(denom)),
            Self::Issuer { denom } => Some(StoreKey::issuer(denom)),
            Self::Frozen { denom, address } => Some(StoreKey::frozen(denom, address)),
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

/// What a server sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Answer to [`Query::Status`].
    Status(Status),
    /// Answer to [`Query::Header`].
    Header(SignedHeader),
    /// Answer to any state query.
    Value(ProvedValue),
}

impl Response {
    /// The proved value, if this response carries one.
    #[must_use]
    pub fn as_value(&self) -> Option<&ProvedValue> {
        match self {
            Self::Value(v) => Some(v),
            Self::Status(_) | Self::Header(_) => None,
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
        }
    }
}

impl Decode for Response {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Status(Status::decode(r)?)),
            1 => Ok(Self::Header(SignedHeader::decode(r)?)),
            2 => Ok(Self::Value(ProvedValue::decode(r)?)),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "Response",
            }),
        }
    }
}
