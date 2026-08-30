//! Consensus votes and vote accounting.
//!
//! A [`VoteSet`] collects votes for one `(height, round, type)` and reports when
//! a quorum is reached. Two properties matter more than anything else here:
//!
//! * **A validator's power is counted once.** Counting a duplicate twice would
//!   let a small set manufacture a quorum.
//! * **Equivocation is detected and retained as evidence.** A validator signing
//!   two different values at the same height and round is the attack that breaks
//!   BFT safety. It is exactly what slashing exists to punish, so the two
//!   conflicting signatures are kept rather than the second simply being
//!   dropped.

use afrolink_crypto::hash::{Domain, Hash32};
use afrolink_crypto::{Address, SecretKey, Signature};
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{ChainId, Height, Round};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::validator::ValidatorSet;

/// Which phase of the round a vote belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoteType {
    /// First voting phase: "I believe this value is acceptable."
    Prevote,
    /// Second voting phase: "I am willing to commit this value."
    Precommit,
}

/// A vote for a block, or for nil.
///
/// `block_id` of `None` is a **nil vote** — an explicit "I saw no acceptable
/// proposal". Nil votes are what let a round conclude and move on rather than
/// hanging, so they are a first-class value, not an absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    /// Network binding, so a vote cannot be replayed onto another chain.
    pub chain_id: ChainId,
    /// Height voted at.
    pub height: Height,
    /// Round voted in.
    pub round: Round,
    /// Which phase.
    pub vote_type: VoteType,
    /// The block voted for, or `None` for nil.
    pub block_id: Option<Hash32>,
    /// Who voted.
    pub validator: Address,
}

impl Vote {
    /// The bytes a vote signature commits to.
    #[must_use]
    pub fn sign_doc(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Sign this vote.
    #[must_use]
    pub fn sign(self, key: &SecretKey) -> SignedVote {
        let signature = key.sign(Domain::VoteSignDoc, &self.sign_doc());
        SignedVote {
            vote: self,
            signature,
        }
    }
}

/// A vote with its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedVote {
    /// The vote.
    pub vote: Vote,
    /// Signature over [`Vote::sign_doc`] in [`Domain::VoteSignDoc`].
    pub signature: Signature,
}

/// Proof that one validator signed two conflicting votes.
///
/// This is slashing evidence: both signatures are valid, they are for the same
/// height, round and phase, and they name different values. There is no
/// innocent explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    /// The offending validator.
    pub validator: Address,
    /// The first vote seen.
    pub first: SignedVote,
    /// The conflicting vote.
    pub second: SignedVote,
}

/// Why a vote was not accepted.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VoteError {
    /// The vote is for a different height, round or phase than this set tracks.
    #[error("vote does not belong to this vote set")]
    WrongSet,
    /// The vote was signed for a different network.
    #[error("vote is for chain {0}, not this one")]
    WrongChain(String),
    /// The signer is not in the validator set.
    #[error("signer is not a validator in this set")]
    NotAValidator,
    /// The signature did not verify.
    #[error("invalid vote signature")]
    InvalidSignature,
}

/// What happened when a vote was added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteOutcome {
    /// The vote was recorded.
    Added,
    /// An identical vote was already held; nothing changed.
    Duplicate,
    /// The validator had already voted differently. Evidence is returned and
    /// the validator's power is withdrawn from the tally.
    Equivocated(Box<Equivocation>),
}

/// Votes for one `(height, round, type)`.
#[derive(Debug, Clone)]
pub struct VoteSet {
    chain_id: ChainId,
    height: Height,
    round: Round,
    vote_type: VoteType,
    /// One vote per validator — the first one seen.
    votes: BTreeMap<Address, SignedVote>,
    /// Validators caught equivocating. Their power counts toward nothing.
    equivocators: BTreeMap<Address, Box<Equivocation>>,
    /// Power accumulated per voted value.
    power_by_value: BTreeMap<Option<Hash32>, u64>,
    /// Total power that has voted, excluding equivocators.
    total_voted: u64,
}

impl VoteSet {
    /// An empty vote set for one phase of one round.
    #[must_use]
    pub fn new(chain_id: ChainId, height: Height, round: Round, vote_type: VoteType) -> Self {
        Self {
            chain_id,
            height,
            round,
            vote_type,
            votes: BTreeMap::new(),
            equivocators: BTreeMap::new(),
            power_by_value: BTreeMap::new(),
            total_voted: 0,
        }
    }

    /// Add a vote, verifying it against `validators`.
    ///
    /// # Errors
    /// Returns [`VoteError`] if the vote does not belong here, is unsigned by a
    /// member, or fails signature verification.
    pub fn add(
        &mut self,
        validators: &ValidatorSet,
        signed: SignedVote,
    ) -> Result<VoteOutcome, VoteError> {
        let vote = &signed.vote;

        if vote.height != self.height
            || vote.round != self.round
            || vote.vote_type != self.vote_type
        {
            return Err(VoteError::WrongSet);
        }
        if vote.chain_id != self.chain_id {
            return Err(VoteError::WrongChain(vote.chain_id.to_string()));
        }

        let validator = validators
            .get(&vote.validator)
            .ok_or(VoteError::NotAValidator)?;

        validator
            .public_key
            .verify(Domain::VoteSignDoc, &vote.sign_doc(), &signed.signature)
            .map_err(|_| VoteError::InvalidSignature)?;

        // Already known to be dishonest: keep ignoring them.
        if self.equivocators.contains_key(&vote.validator) {
            return Ok(VoteOutcome::Duplicate);
        }

        if let Some(existing) = self.votes.get(&vote.validator) {
            if existing.vote.block_id == vote.block_id {
                return Ok(VoteOutcome::Duplicate);
            }

            // Two different values, same validator, same height/round/phase.
            let evidence = Box::new(Equivocation {
                validator: vote.validator,
                first: existing.clone(),
                second: signed.clone(),
            });

            // Withdraw their power entirely — a validator that has demonstrably
            // lied should not help either value reach a quorum.
            let power = validator.voting_power;
            let previous_value = existing.vote.block_id;
            if let Some(slot) = self.power_by_value.get_mut(&previous_value) {
                *slot = slot.saturating_sub(power);
            }
            self.total_voted = self.total_voted.saturating_sub(power);
            self.votes.remove(&vote.validator);
            self.equivocators.insert(vote.validator, evidence.clone());

            return Ok(VoteOutcome::Equivocated(evidence));
        }

        let power = validator.voting_power;
        self.votes.insert(vote.validator, signed.clone());
        *self.power_by_value.entry(vote.block_id).or_insert(0) = self
            .power_by_value
            .get(&vote.block_id)
            .copied()
            .unwrap_or(0)
            .saturating_add(power);
        self.total_voted = self.total_voted.saturating_add(power);

        Ok(VoteOutcome::Added)
    }

    /// Power accumulated for one value.
    #[must_use]
    pub fn power_for(&self, block_id: Option<Hash32>) -> u64 {
        self.power_by_value.get(&block_id).copied().unwrap_or(0)
    }

    /// Total power that has voted, excluding equivocators.
    #[must_use]
    pub fn total_voted(&self) -> u64 {
        self.total_voted
    }

    /// Number of votes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.votes.len()
    }

    /// Whether no votes are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    /// Equivocation evidence gathered so far, for slashing.
    #[must_use]
    pub fn equivocations(&self) -> Vec<&Equivocation> {
        self.equivocators.values().map(AsRef::as_ref).collect()
    }

    /// Every vote held for one value, in canonical validator order.
    ///
    /// This is how a [`crate::Commit`] is assembled: the precommits that carried
    /// a block over the quorum line become the portable proof that it was
    /// finalised, which is what a light client checks.
    #[must_use]
    pub fn votes_for(&self, block_id: Option<Hash32>) -> Vec<SignedVote> {
        self.votes
            .values()
            .filter(|v| v.vote.block_id == block_id)
            .cloned()
            .collect()
    }

    /// The value that has reached a quorum, if any.
    ///
    /// The outer `Option` is "did anything reach a quorum"; the inner is the
    /// value, where `None` means nil reached a quorum.
    #[must_use]
    pub fn quorum_value(&self, validators: &ValidatorSet) -> Option<Option<Hash32>> {
        self.power_by_value
            .iter()
            .find(|(_, power)| validators.has_quorum(**power))
            .map(|(value, _)| *value)
    }

    /// Whether a quorum has voted at all, regardless of what for.
    ///
    /// This is the "+2/3 any" condition that lets a round time out and advance
    /// rather than waiting forever for agreement that will not come.
    #[must_use]
    pub fn has_quorum_any(&self, validators: &ValidatorSet) -> bool {
        validators.has_quorum(self.total_voted)
    }
}

impl Encode for VoteType {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(match self {
            Self::Prevote => 0,
            Self::Precommit => 1,
        });
    }
}

impl Decode for VoteType {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Prevote),
            1 => Ok(Self::Precommit),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "VoteType",
            }),
        }
    }
}

impl Encode for Vote {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.height.encode(out);
        self.round.encode(out);
        self.vote_type.encode(out);
        self.block_id.encode(out);
        self.validator.encode(out);
    }
}

impl Decode for Vote {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: ChainId::decode(r)?,
            height: Height::decode(r)?,
            round: Round::decode(r)?,
            vote_type: VoteType::decode(r)?,
            block_id: Option::<Hash32>::decode(r)?,
            validator: Address::decode(r)?,
        })
    }
}

impl Encode for Equivocation {
    fn encode(&self, out: &mut Vec<u8>) {
        self.validator.encode(out);
        self.first.encode(out);
        self.second.encode(out);
    }
}

impl Decode for Equivocation {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            validator: Address::decode(r)?,
            first: SignedVote::decode(r)?,
            second: SignedVote::decode(r)?,
        })
    }
}

impl Encode for SignedVote {
    fn encode(&self, out: &mut Vec<u8>) {
        self.vote.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for SignedVote {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            vote: Vote::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::{CountryCode, Validator};
    use afrolink_crypto::hash::{Domain as HashDomain, hash};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    /// Four validators of equal power: quorum is 3.
    fn validators() -> ValidatorSet {
        ValidatorSet::new(
            (1..=4u8)
                .map(|i| {
                    Validator::new(
                        key(i).public_key(),
                        1,
                        CountryCode::new("ke").expect("valid"),
                    )
                })
                .collect(),
        )
        .expect("valid set")
    }

    fn block(tag: &str) -> Hash32 {
        hash(HashDomain::BlockId, tag.as_bytes())
    }

    fn vote_for(seed: u8, block_id: Option<Hash32>) -> SignedVote {
        Vote {
            chain_id: chain(),
            height: Height(1),
            round: Round::ZERO,
            vote_type: VoteType::Precommit,
            block_id,
            validator: Address::from_public_key(&key(seed).public_key()),
        }
        .sign(&key(seed))
    }

    fn empty_set() -> VoteSet {
        VoteSet::new(chain(), Height(1), Round::ZERO, VoteType::Precommit)
    }

    #[test]
    fn a_quorum_is_reached_at_two_thirds_plus_one() {
        let vs = validators();
        let mut votes = empty_set();
        let b = block("A");

        for seed in 1..=2u8 {
            votes.add(&vs, vote_for(seed, Some(b))).expect("accepted");
        }
        assert_eq!(votes.quorum_value(&vs), None, "2 of 4 is not a quorum");

        votes.add(&vs, vote_for(3, Some(b))).expect("accepted");
        assert_eq!(votes.quorum_value(&vs), Some(Some(b)), "3 of 4 is a quorum");
    }

    #[test]
    fn a_duplicate_vote_does_not_count_twice() {
        // Otherwise two validators could manufacture a quorum by resending.
        let vs = validators();
        let mut votes = empty_set();
        let b = block("A");

        assert_eq!(votes.add(&vs, vote_for(1, Some(b))), Ok(VoteOutcome::Added));
        assert_eq!(
            votes.add(&vs, vote_for(1, Some(b))),
            Ok(VoteOutcome::Duplicate)
        );
        assert_eq!(
            votes.add(&vs, vote_for(1, Some(b))),
            Ok(VoteOutcome::Duplicate)
        );

        assert_eq!(
            votes.power_for(Some(b)),
            1,
            "one validator, one unit of power"
        );
        assert_eq!(votes.total_voted(), 1);
    }

    #[test]
    fn equivocation_is_detected_and_evidence_retained() {
        // The attack BFT safety rests on preventing.
        let vs = validators();
        let mut votes = empty_set();

        votes
            .add(&vs, vote_for(1, Some(block("A"))))
            .expect("accepted");
        let outcome = votes
            .add(&vs, vote_for(1, Some(block("B"))))
            .expect("processed");

        match outcome {
            VoteOutcome::Equivocated(evidence) => {
                assert_eq!(evidence.validator, vote_for(1, None).vote.validator);
                assert_ne!(evidence.first.vote.block_id, evidence.second.vote.block_id);
            }
            other => panic!("expected equivocation, got {other:?}"),
        }
        assert_eq!(
            votes.equivocations().len(),
            1,
            "evidence must be kept for slashing"
        );
    }

    #[test]
    fn an_equivocators_power_counts_for_nothing() {
        // A validator that has demonstrably lied must not help either value.
        let vs = validators();
        let mut votes = empty_set();
        let (a, b) = (block("A"), block("B"));

        votes.add(&vs, vote_for(1, Some(a))).expect("accepted");
        assert_eq!(votes.power_for(Some(a)), 1);

        votes.add(&vs, vote_for(1, Some(b))).expect("processed");
        assert_eq!(
            votes.power_for(Some(a)),
            0,
            "withdrawn from the first value"
        );
        assert_eq!(
            votes.power_for(Some(b)),
            0,
            "and never credited to the second"
        );
        assert_eq!(votes.total_voted(), 0);
    }

    #[test]
    fn one_byzantine_validator_cannot_produce_two_quorums() {
        // The whole point: with 4 validators and 1 liar, no two different values
        // can both reach a quorum of 3.
        let vs = validators();
        let (a, b) = (block("A"), block("B"));
        let mut votes = empty_set();

        // Honest 2 and 3 back A; honest 4 backs B; validator 1 tries both.
        votes.add(&vs, vote_for(2, Some(a))).expect("ok");
        votes.add(&vs, vote_for(3, Some(a))).expect("ok");
        votes.add(&vs, vote_for(4, Some(b))).expect("ok");
        votes.add(&vs, vote_for(1, Some(a))).expect("ok");
        votes.add(&vs, vote_for(1, Some(b))).expect("processed");

        assert!(votes.power_for(Some(a)) < vs.quorum_threshold());
        assert!(votes.power_for(Some(b)) < vs.quorum_threshold());
        assert_eq!(votes.quorum_value(&vs), None, "no value may reach a quorum");
    }

    #[test]
    fn nil_votes_can_reach_a_quorum_so_a_round_can_conclude() {
        let vs = validators();
        let mut votes = empty_set();
        for seed in 1..=3u8 {
            votes.add(&vs, vote_for(seed, None)).expect("accepted");
        }
        assert_eq!(votes.quorum_value(&vs), Some(None), "nil is a real outcome");
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let vs = validators();
        let mut votes = empty_set();
        // Validator 2's address, signed by validator 3's key.
        let mut forged = vote_for(3, Some(block("A")));
        forged.vote.validator = Address::from_public_key(&key(2).public_key());
        assert_eq!(votes.add(&vs, forged), Err(VoteError::InvalidSignature));
    }

    #[test]
    fn a_non_validator_cannot_vote() {
        let vs = validators();
        let mut votes = empty_set();
        assert_eq!(
            votes.add(&vs, vote_for(99, Some(block("A")))),
            Err(VoteError::NotAValidator)
        );
    }

    #[test]
    fn votes_for_another_round_or_chain_are_rejected() {
        let vs = validators();
        let mut votes = empty_set();

        let mut wrong_round = vote_for(1, Some(block("A")));
        wrong_round.vote.round = Round(5);
        assert_eq!(votes.add(&vs, wrong_round), Err(VoteError::WrongSet));

        let mut wrong_chain = Vote {
            chain_id: ChainId::new("afrolink-testnet-3").expect("valid"),
            height: Height(1),
            round: Round::ZERO,
            vote_type: VoteType::Precommit,
            block_id: Some(block("A")),
            validator: Address::from_public_key(&key(1).public_key()),
        }
        .sign(&key(1));
        wrong_chain.vote.chain_id = ChainId::new("afrolink-testnet-3").expect("valid");
        assert!(matches!(
            votes.add(&vs, wrong_chain),
            Err(VoteError::WrongChain(_))
        ));
    }

    #[test]
    fn a_prevote_signature_is_not_valid_as_a_precommit() {
        // Without vote_type in the signed bytes, a prevote could be replayed as
        // a precommit and commit a block nobody agreed to commit.
        let mut prevote = Vote {
            chain_id: chain(),
            height: Height(1),
            round: Round::ZERO,
            vote_type: VoteType::Prevote,
            block_id: Some(block("A")),
            validator: Address::from_public_key(&key(1).public_key()),
        }
        .sign(&key(1));

        prevote.vote.vote_type = VoteType::Precommit;
        let vs = validators();
        let mut votes = empty_set();
        assert_eq!(votes.add(&vs, prevote), Err(VoteError::InvalidSignature));
    }

    #[test]
    fn quorum_any_reports_participation_regardless_of_agreement() {
        let vs = validators();
        let mut votes = empty_set();
        votes.add(&vs, vote_for(1, Some(block("A")))).expect("ok");
        votes.add(&vs, vote_for(2, Some(block("B")))).expect("ok");
        assert!(!votes.has_quorum_any(&vs));
        votes.add(&vs, vote_for(3, None)).expect("ok");
        assert!(
            votes.has_quorum_any(&vs),
            "3 of 4 voted, even though they disagree"
        );
        assert_eq!(
            votes.quorum_value(&vs),
            None,
            "but nothing reached a quorum"
        );
    }

    #[test]
    fn signed_votes_round_trip() {
        let signed = vote_for(1, Some(block("A")));
        assert_eq!(
            afrolink_primitives::codec::decode_exact::<SignedVote>(&signed.to_bytes()),
            Ok(signed)
        );
    }
}
