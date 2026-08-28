//! The light client — the whole design thesis, in one small crate.
//!
//! Research §5: ~600 million people in Africa have no electricity, entry-level
//! smartphones cost a quarter of monthly GDP per capita, and only mobile *data*
//! is genuinely affordable. A chain for this context cannot ask users to store
//! it or to trust whoever serves it to them.
//!
//! So a wallet here holds two things:
//!
//! * the **validator set**, and
//! * one **32-byte block header** per height it cares about.
//!
//! Everything else — balances, group records, issuance history — is fetched from
//! an untrusted server *with a proof*, and checked locally. The server can be
//! hostile, compromised, or a state actor; it can withhold an answer, but it
//! cannot forge one.
//!
//! # The two verifications
//!
//! 1. **Is this header real?** A [`Commit`] carries the precommit signatures of
//!    more than two thirds of voting power. Checking them is pure signature
//!    arithmetic — no chain, no execution.
//! 2. **Is this value in that state?** The header commits to an `app_hash`, the
//!    root of the sparse Merkle state tree. A proof either reconstructs that
//!    root or it does not.
//!
//! Crucially the second also proves **absence**, so a server cannot lie by
//! omission — "you have no balance" is a claim it must prove like any other.

#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
    )
)]

use afrolink_consensus::{Commit, CommitError, ValidatorSet};
use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_executor::BlockHeader;
use afrolink_primitives::codec::decode_exact;
use afrolink_primitives::{Amount, ChainId, Denom, Height};
use afrolink_state::{Proof, StoreKey};
use thiserror::Error;

/// Why a light-client check failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LightError {
    /// The commit did not verify against the validator set.
    #[error(transparent)]
    Commit(#[from] CommitError),
    /// The commit finalises a different block than the header presented.
    #[error("commit is for a different block than this header")]
    HeaderMismatch,
    /// The header belongs to another network.
    #[error("header is for chain {got}, expected {expected}")]
    WrongChain {
        /// Chain named in the header.
        got: String,
        /// Chain this client follows.
        expected: String,
    },
    /// The header does not extend the trusted one.
    #[error("header at height {got} does not follow the trusted height {trusted}")]
    NonSequential {
        /// Height offered.
        got: u64,
        /// Height currently trusted.
        trusted: u64,
    },
    /// The header's parent is not the trusted block.
    #[error("header does not name the trusted block as its parent")]
    BrokenChain,
    /// A state proof did not reconstruct the header's `app_hash`.
    #[error("state proof does not verify against the trusted app hash")]
    BadProof,
    /// A proved value did not decode.
    #[error("proved value is malformed")]
    MalformedValue,
}

/// A wallet's view of the chain: a validator set and one trusted header.
#[derive(Debug, Clone)]
pub struct LightClient {
    chain_id: ChainId,
    validators: ValidatorSet,
    trusted: BlockHeader,
}

impl LightClient {
    /// Start from a genesis header and the genesis validator set.
    ///
    /// This is the client's only act of trust, and it is unavoidable: every
    /// verification system needs a root. Here it is a public, auditable file
    /// whose hash operators publish before launch.
    #[must_use]
    pub fn new(chain_id: ChainId, validators: ValidatorSet, genesis_header: BlockHeader) -> Self {
        Self {
            chain_id,
            validators,
            trusted: genesis_header,
        }
    }

    /// The header currently trusted.
    #[must_use]
    pub fn trusted_header(&self) -> &BlockHeader {
        &self.trusted
    }

    /// The height currently trusted.
    #[must_use]
    pub fn height(&self) -> Height {
        self.trusted.height
    }

    /// The state root the client will check proofs against.
    #[must_use]
    pub fn app_hash(&self) -> Hash32 {
        self.trusted.app_hash
    }

    /// Verify `header` and its `commit`, and adopt it as the new trusted head.
    ///
    /// Requires the header to be the direct successor of the trusted one. That
    /// is the strict form; skipping ahead over many heights is a later
    /// optimisation and needs its own trust argument about validator-set drift,
    /// so it is deliberately not offered yet.
    ///
    /// # Errors
    /// Returns the first [`LightError`] encountered. The trusted header is left
    /// unchanged on any failure.
    pub fn update(&mut self, header: BlockHeader, commit: &Commit) -> Result<(), LightError> {
        if header.chain_id != self.chain_id {
            return Err(LightError::WrongChain {
                got: header.chain_id.to_string(),
                expected: self.chain_id.to_string(),
            });
        }
        if header.height != self.trusted.height.next() {
            return Err(LightError::NonSequential {
                got: header.height.0,
                trusted: self.trusted.height.0,
            });
        }
        if header.parent != self.trusted.id() {
            return Err(LightError::BrokenChain);
        }
        // The commit must finalise *this* header, not merely be well-formed.
        if commit.block_id != header.id() || commit.height != header.height {
            return Err(LightError::HeaderMismatch);
        }

        commit.verify(&self.chain_id, &self.validators)?;

        self.trusted = header;
        Ok(())
    }

    /// Verify a value the server claims is at `key`, against the trusted root.
    ///
    /// # Errors
    /// Returns [`LightError::BadProof`] if the proof does not reconstruct the
    /// trusted `app_hash`.
    pub fn verify_value(
        &self,
        key: &StoreKey,
        value: Option<&[u8]>,
        proof: &Proof,
    ) -> Result<(), LightError> {
        if proof.verify(self.app_hash(), key.as_bytes(), value) {
            Ok(())
        } else {
            Err(LightError::BadProof)
        }
    }

    /// Verify a balance a server reported.
    ///
    /// Returns the verified balance, which is [`Amount::ZERO`] when the proof
    /// shows the key is absent — an unfunded account and a zero balance are the
    /// same thing, and both are *proved*, not assumed.
    ///
    /// # Errors
    /// Returns [`LightError::BadProof`] or [`LightError::MalformedValue`].
    pub fn verify_balance(
        &self,
        address: &Address,
        denom: &Denom,
        claimed: Option<&[u8]>,
        proof: &Proof,
    ) -> Result<Amount, LightError> {
        let key = StoreKey::balance(address, denom);
        self.verify_value(&key, claimed, proof)?;
        match claimed {
            None => Ok(Amount::ZERO),
            Some(bytes) => decode_exact::<Amount>(bytes).map_err(|_| LightError::MalformedValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_bank::{Bank, Issuer};
    use afrolink_consensus::{CountryCode, Validator, Vote, VoteType};
    use afrolink_crypto::SecretKey;
    use afrolink_executor::{Allocation, Block, Executor, Genesis, GenesisLimits};
    use afrolink_primitives::codec::Encode;
    use afrolink_primitives::{Round, Timestamp};
    use afrolink_state::{KeyValueStore, MemoryStore};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid")
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

    /// Genesis with one funded account, and the resulting state.
    fn genesis_chain() -> (MemoryStore, Block) {
        let genesis = Genesis {
            chain_id: chain(),
            genesis_time: Timestamp::from_millis(1_700_000_000_000),
            validators: validators(),
            issuers: vec![(kes(), Issuer::new(addr(100)))],
            allocations: vec![Allocation {
                address: addr(50),
                denom: kes(),
                amount: Amount::from_afri(1_000),
            }],
        };
        let mut store = MemoryStore::new();
        let block = genesis
            .apply(&mut store, GenesisLimits::devnet())
            .expect("applies");
        (store, block)
    }

    /// Produce the next block over `store` and a commit signed by `seeds`.
    fn next_block(store: &mut MemoryStore, parent: &Block, seeds: &[u8]) -> (Block, Commit) {
        let executor = Executor::new(chain());
        let (block, _) = executor.build_block(
            store,
            parent.header.height.next(),
            Timestamp::from_millis(1_700_000_001_000),
            parent.header.id(),
            Vec::new(),
        );
        let block_id = block.header.id();
        let signatures = seeds
            .iter()
            .map(|s| {
                Vote {
                    chain_id: chain(),
                    height: block.header.height,
                    round: Round::ZERO,
                    vote_type: VoteType::Precommit,
                    block_id: Some(block_id),
                    validator: addr(*s),
                }
                .sign(&key(*s))
            })
            .collect();
        let commit = Commit::new(block.header.height, Round::ZERO, block_id, signatures);
        (block, commit)
    }

    #[test]
    fn a_wallet_verifies_a_balance_from_a_header_it_holds() {
        // The headline claim: a phone holding 32 bytes checks its money.
        let (store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header);

        // An untrusted server answers a balance query with a proof.
        let key = StoreKey::balance(&addr(50), &kes());
        let (value, proof) = store.get_with_proof(&key);

        let balance = client
            .verify_balance(&addr(50), &kes(), value.as_deref(), &proof)
            .expect("proof must verify");
        assert_eq!(balance, Amount::from_afri(1_000));
    }

    #[test]
    fn a_lying_server_cannot_inflate_a_balance() {
        let (store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header);

        let key = StoreKey::balance(&addr(50), &kes());
        let (_, proof) = store.get_with_proof(&key);

        // The server keeps the real proof but reports a bigger number.
        let lie = Amount::from_afri(999_999).to_bytes();
        assert_eq!(
            client.verify_balance(&addr(50), &kes(), Some(&lie), &proof),
            Err(LightError::BadProof)
        );
    }

    #[test]
    fn a_lying_server_cannot_deny_a_funded_account() {
        // Lying by omission: claiming the account does not exist.
        let (store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header);

        let key = StoreKey::balance(&addr(50), &kes());
        let (_, proof) = store.get_with_proof(&key);

        assert_eq!(
            client.verify_balance(&addr(50), &kes(), None, &proof),
            Err(LightError::BadProof)
        );
    }

    #[test]
    fn an_absent_balance_is_proved_not_assumed() {
        let (store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header);

        let stranger = addr(77);
        let key = StoreKey::balance(&stranger, &kes());
        let (value, proof) = store.get_with_proof(&key);
        assert!(value.is_none());

        let balance = client
            .verify_balance(&stranger, &kes(), None, &proof)
            .expect("absence must be provable");
        assert_eq!(balance, Amount::ZERO);
    }

    #[test]
    fn a_quorum_backed_header_is_adopted() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, commit) = next_block(&mut store, &genesis, &[1, 2, 3]);

        client
            .update(block.header.clone(), &commit)
            .expect("valid commit");
        assert_eq!(client.height(), Height(1));
        assert_eq!(client.app_hash(), block.header.app_hash);
    }

    #[test]
    fn a_header_without_a_quorum_is_refused_and_the_client_does_not_move() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, commit) = next_block(&mut store, &genesis, &[1, 2]); // 2 of 4

        assert!(client.update(block.header, &commit).is_err());
        assert_eq!(
            client.trusted_header(),
            &genesis.header,
            "a rejected update must leave the trusted header untouched"
        );
    }

    #[test]
    fn a_commit_for_a_different_block_does_not_certify_this_header() {
        // A server pairing a real header with a real commit for another block.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (block, mut commit) = next_block(&mut store, &genesis, &[1, 2, 3]);
        commit.block_id = Hash32::ZERO;

        assert_eq!(
            client.update(block.header, &commit),
            Err(LightError::HeaderMismatch)
        );
    }

    #[test]
    fn a_header_that_skips_a_height_is_refused() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (mut block, commit) = next_block(&mut store, &genesis, &[1, 2, 3]);
        block.header.height = Height(5);

        assert!(matches!(
            client.update(block.header, &commit),
            Err(LightError::NonSequential { .. })
        ));
    }

    #[test]
    fn a_header_not_descending_from_the_trusted_block_is_refused() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (mut block, commit) = next_block(&mut store, &genesis, &[1, 2, 3]);
        block.header.parent = Hash32::ZERO;

        assert_eq!(
            client.update(block.header, &commit),
            Err(LightError::BrokenChain)
        );
    }

    #[test]
    fn a_header_from_another_chain_is_refused() {
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());
        let (mut block, commit) = next_block(&mut store, &genesis, &[1, 2, 3]);
        block.header.chain_id = ChainId::new("afrolink-testnet-3").expect("valid");

        assert!(matches!(
            client.update(block.header, &commit),
            Err(LightError::WrongChain { .. })
        ));
    }

    #[test]
    fn following_the_chain_keeps_balances_verifiable() {
        // A wallet tracks heights and keeps checking its money as state moves.
        let (mut store, genesis) = genesis_chain();
        let mut client = LightClient::new(chain(), validators(), genesis.header.clone());

        let mut parent = genesis;
        for _ in 0..3 {
            let (block, commit) = next_block(&mut store, &parent, &[1, 2, 3, 4]);
            client.update(block.header.clone(), &commit).expect("valid");
            parent = block;
        }
        assert_eq!(client.height(), Height(3));

        // Move money, then verify against the newest trusted header.
        {
            let mut bank = Bank::new(&mut store);
            bank.transfer(&addr(50), &addr(51), &kes(), Amount::from_afri(400))
                .expect("transfers");
        }
        let (block, commit) = next_block(&mut store, &parent, &[1, 2, 3, 4]);
        client.update(block.header, &commit).expect("valid");

        let key = StoreKey::balance(&addr(51), &kes());
        let (value, proof) = store.get_with_proof(&key);
        let balance = client
            .verify_balance(&addr(51), &kes(), value.as_deref(), &proof)
            .expect("proof verifies against the latest header");
        assert_eq!(balance, Amount::from_afri(400));
    }

    #[test]
    fn a_proof_against_a_stale_header_does_not_verify() {
        // A server replaying an old proof after state has moved on.
        let (mut store, genesis) = genesis_chain();
        let client = LightClient::new(chain(), validators(), genesis.header.clone());

        let key = StoreKey::balance(&addr(50), &kes());
        let (old_value, old_proof) = store.get_with_proof(&key);

        {
            let mut bank = Bank::new(&mut store);
            bank.transfer(&addr(50), &addr(51), &kes(), Amount::from_afri(100))
                .expect("transfers");
        }

        // The old proof still matches the old root the client trusts.
        assert!(
            client
                .verify_balance(&addr(50), &kes(), old_value.as_deref(), &old_proof)
                .is_ok()
        );

        // But the *new* value does not verify against that stale header, so a
        // wallet that has not updated cannot be shown post-transfer state.
        let (new_value, _) = store.get_with_proof(&key);
        assert_eq!(
            client.verify_balance(&addr(50), &kes(), new_value.as_deref(), &old_proof),
            Err(LightError::BadProof)
        );
    }
}
