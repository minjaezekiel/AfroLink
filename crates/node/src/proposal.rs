//! Block proposals.

use afrolink_crypto::hash::{Domain, Hash32};
use afrolink_crypto::{Address, SecretKey, Signature};
use afrolink_executor::Block;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{ChainId, Height, Round};

/// A proposer's offer of a block for one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Network binding.
    pub chain_id: ChainId,
    /// Height proposed for.
    pub height: Height,
    /// Round proposed in.
    pub round: Round,
    /// The block on offer.
    pub block: Block,
    /// The round in which this value already achieved a prevote quorum, if any.
    ///
    /// This is the proposer's *proof of freshness*. A validator locked on some
    /// other value will only release its lock for a proposal carrying proof from
    /// a round later than its lock — see [`afrolink_consensus::RoundState`].
    pub valid_round: Option<Round>,
    /// Who proposed it.
    pub proposer: Address,
}

impl Proposal {
    /// The bytes a proposal signature commits to.
    #[must_use]
    pub fn sign_doc(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// The identifier of the proposed block.
    #[must_use]
    pub fn block_id(&self) -> Hash32 {
        self.block.header.id()
    }

    /// Sign this proposal.
    #[must_use]
    pub fn sign(self, key: &SecretKey) -> SignedProposal {
        let signature = key.sign(Domain::BlockId, &self.sign_doc());
        SignedProposal {
            proposal: self,
            signature,
        }
    }
}

/// A proposal with its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProposal {
    /// The proposal.
    pub proposal: Proposal,
    /// Signature over [`Proposal::sign_doc`].
    pub signature: Signature,
}

impl Encode for Proposal {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.height.encode(out);
        self.round.encode(out);
        self.block.encode(out);
        self.valid_round.encode(out);
        self.proposer.encode(out);
    }
}

impl Decode for Proposal {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: ChainId::decode(r)?,
            height: Height::decode(r)?,
            round: Round::decode(r)?,
            block: Block::decode(r)?,
            valid_round: Option::<Round>::decode(r)?,
            proposer: Address::decode(r)?,
        })
    }
}

impl Encode for SignedProposal {
    fn encode(&self, out: &mut Vec<u8>) {
        self.proposal.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for SignedProposal {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            proposal: Proposal::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}
