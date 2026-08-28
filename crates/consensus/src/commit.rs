//! Commit certificates — portable proof that a block was finalised.
//!
//! A [`Commit`] is the set of precommit signatures that carried a block past the
//! quorum line. It is the single most important object for anyone who is not
//! running a full node, because it turns "this validator set finalised block X"
//! into something checkable offline from 32-byte headers and a list of public
//! keys.
//!
//! A phone that holds the validator set can verify a commit without holding the
//! chain, without trusting the server that sent it, and without executing a
//! single transaction.

use afrolink_crypto::hash::{Domain, Hash32};
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{ChainId, Height, Round};
use std::collections::BTreeSet;
use thiserror::Error;

use crate::validator::ValidatorSet;
use crate::vote::{SignedVote, VoteType};

/// Why a commit certificate was rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitError {
    /// The commit carries no signatures.
    #[error("commit has no signatures")]
    Empty,
    /// A signature was not a precommit, or not for this commit's block.
    #[error("commit contains a vote for the wrong block, height, round or phase")]
    MismatchedVote,
    /// The same validator signed twice.
    #[error("commit contains a duplicate signature")]
    DuplicateSigner,
    /// A signer is not in the validator set.
    #[error("commit contains a signature from a non-validator")]
    UnknownSigner,
    /// A signature did not verify.
    #[error("commit contains an invalid signature")]
    InvalidSignature,
    /// The signatures do not add up to more than two thirds of voting power.
    #[error("commit has {got} of {needed} voting power required")]
    InsufficientPower {
        /// Power actually signed.
        got: u64,
        /// Power required.
        needed: u64,
    },
}

/// The precommits that finalised one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// Height finalised.
    pub height: Height,
    /// Round in which it was finalised.
    pub round: Round,
    /// The block finalised.
    pub block_id: Hash32,
    /// Precommit signatures backing it.
    pub signatures: Vec<SignedVote>,
}

impl Commit {
    /// Assemble a commit from precommits for `block_id`.
    #[must_use]
    pub fn new(
        height: Height,
        round: Round,
        block_id: Hash32,
        signatures: Vec<SignedVote>,
    ) -> Self {
        Self {
            height,
            round,
            block_id,
            signatures,
        }
    }

    /// Verify that more than two thirds of `validators` precommitted this block.
    ///
    /// Every signature is checked individually — a commit is only as good as the
    /// signatures in it, and an unverified one proves nothing at all.
    ///
    /// # Errors
    /// Returns the first [`CommitError`] encountered.
    pub fn verify(&self, chain_id: &ChainId, validators: &ValidatorSet) -> Result<(), CommitError> {
        if self.signatures.is_empty() {
            return Err(CommitError::Empty);
        }

        let mut seen = BTreeSet::new();
        let mut power: u64 = 0;

        for signed in &self.signatures {
            let vote = &signed.vote;

            if vote.height != self.height
                || vote.round != self.round
                || vote.vote_type != VoteType::Precommit
                || vote.block_id != Some(self.block_id)
                || &vote.chain_id != chain_id
            {
                return Err(CommitError::MismatchedVote);
            }

            // Counting one validator twice is the cheapest way to fake a quorum.
            if !seen.insert(vote.validator) {
                return Err(CommitError::DuplicateSigner);
            }

            let validator = validators
                .get(&vote.validator)
                .ok_or(CommitError::UnknownSigner)?;

            validator
                .public_key
                .verify(Domain::VoteSignDoc, &vote.sign_doc(), &signed.signature)
                .map_err(|_| CommitError::InvalidSignature)?;

            power = power.saturating_add(validator.voting_power);
        }

        if !validators.has_quorum(power) {
            return Err(CommitError::InsufficientPower {
                got: power,
                needed: validators.quorum_threshold(),
            });
        }

        Ok(())
    }

    /// Total voting power backing this commit, without verifying signatures.
    ///
    /// For display only. Never gate a decision on this — use [`Self::verify`].
    #[must_use]
    pub fn claimed_power(&self, validators: &ValidatorSet) -> u64 {
        self.signatures
            .iter()
            .map(|s| validators.power_of(&s.vote.validator))
            .fold(0u64, u64::saturating_add)
    }
}

impl Encode for Commit {
    fn encode(&self, out: &mut Vec<u8>) {
        self.height.encode(out);
        self.round.encode(out);
        self.block_id.encode(out);
        self.signatures.encode(out);
    }
}

impl Decode for Commit {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::decode(r)?,
            round: Round::decode(r)?,
            block_id: Hash32::decode(r)?,
            signatures: Vec::<SignedVote>::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::{CountryCode, Validator};
    use crate::vote::Vote;
    use afrolink_crypto::hash::hash;
    use afrolink_crypto::{Address, SecretKey};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

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

    fn block() -> Hash32 {
        hash(Domain::BlockId, b"block-1")
    }

    fn precommit(seed: u8, block_id: Option<Hash32>) -> SignedVote {
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

    fn commit_of(seeds: &[u8]) -> Commit {
        Commit::new(
            Height(1),
            Round::ZERO,
            block(),
            seeds.iter().map(|s| precommit(*s, Some(block()))).collect(),
        )
    }

    #[test]
    fn a_quorum_backed_commit_verifies() {
        let commit = commit_of(&[1, 2, 3]);
        assert_eq!(commit.verify(&chain(), &validators()), Ok(()));
    }

    #[test]
    fn a_commit_below_quorum_is_rejected() {
        // 2 of 4 is not a quorum, and a light client must not accept it.
        let commit = commit_of(&[1, 2]);
        assert!(matches!(
            commit.verify(&chain(), &validators()),
            Err(CommitError::InsufficientPower { got: 2, needed: 3 })
        ));
    }

    #[test]
    fn a_duplicated_signer_cannot_fake_a_quorum() {
        // The cheapest forgery: repeat one honest signature until it looks like
        // three validators signed.
        let mut commit = commit_of(&[1]);
        commit.signatures.push(precommit(1, Some(block())));
        commit.signatures.push(precommit(1, Some(block())));
        assert_eq!(
            commit.verify(&chain(), &validators()),
            Err(CommitError::DuplicateSigner)
        );
    }

    #[test]
    fn a_signature_from_a_non_validator_is_rejected() {
        let mut commit = commit_of(&[1, 2]);
        commit.signatures.push(precommit(99, Some(block())));
        assert_eq!(
            commit.verify(&chain(), &validators()),
            Err(CommitError::UnknownSigner)
        );
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let mut commit = commit_of(&[1, 2, 3]);
        // Re-point validator 3's vote at a different block without re-signing.
        if let Some(last) = commit.signatures.last_mut() {
            last.vote.block_id = Some(hash(Domain::BlockId, b"other"));
        }
        assert_eq!(
            commit.verify(&chain(), &validators()),
            Err(CommitError::MismatchedVote)
        );
    }

    #[test]
    fn a_signature_re_signed_for_another_block_does_not_transfer() {
        // Valid signatures, but for a different block than the commit claims.
        let other = hash(Domain::BlockId, b"other");
        let commit = Commit::new(
            Height(1),
            Round::ZERO,
            block(),
            (1..=3u8).map(|s| precommit(s, Some(other))).collect(),
        );
        assert_eq!(
            commit.verify(&chain(), &validators()),
            Err(CommitError::MismatchedVote)
        );
    }

    #[test]
    fn a_commit_from_another_chain_is_rejected() {
        let commit = commit_of(&[1, 2, 3]);
        let other_chain = ChainId::new("afrolink-testnet-3").expect("valid");
        assert_eq!(
            commit.verify(&other_chain, &validators()),
            Err(CommitError::MismatchedVote)
        );
    }

    #[test]
    fn an_empty_commit_is_rejected() {
        let commit = Commit::new(Height(1), Round::ZERO, block(), Vec::new());
        assert_eq!(
            commit.verify(&chain(), &validators()),
            Err(CommitError::Empty)
        );
    }

    #[test]
    fn nil_precommits_cannot_back_a_commit() {
        let commit = Commit::new(
            Height(1),
            Round::ZERO,
            block(),
            (1..=3u8).map(|s| precommit(s, None)).collect(),
        );
        assert_eq!(
            commit.verify(&chain(), &validators()),
            Err(CommitError::MismatchedVote)
        );
    }

    #[test]
    fn commits_round_trip() {
        let commit = commit_of(&[1, 2, 3]);
        assert_eq!(
            afrolink_primitives::codec::decode_exact::<Commit>(&commit.to_bytes()),
            Ok(commit)
        );
    }
}
