//! Adversarial input against every proof a client verifies.
//!
//! The security claim these back is the one the whole design rests on: a wallet
//! holding 32 bytes can be *withheld from*, but cannot be *lied to*. That claim
//! is only as good as the soundness of the verifiers, and soundness is a
//! negative property — no forged proof verifies — which unit tests with
//! hand-picked fixtures are poorly suited to.
//!
//! So each verifier is handed tens of thousands of proofs derived from a real
//! one by mutation. Not one may verify.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_bank::Issuer;
use afrolink_consensus::{Commit, CountryCode, Validator, ValidatorSet, Vote, VoteType};
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{Address, MerkleTree, SecretKey};
use afrolink_executor::{Allocation, Block, Genesis, GenesisLimits};
use afrolink_fuzz::{Rng, mutate};
use afrolink_light::LightClient;
use afrolink_primitives::codec::{Encode, decode_exact};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Round, Timestamp};
use afrolink_state::{KeyValueStore, MemoryStore, Proof, StoreKey};
use afrolink_witness::{LogEntry, LogId, WitnessLog};

const ROUNDS: u64 = 5_000;

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
                    10,
                    CountryCode::new("ke").expect("valid"),
                )
            })
            .collect(),
    )
    .expect("valid set")
}

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

#[test]
fn no_mutated_state_proof_verifies_a_balance() {
    // The headline claim: a server can refuse to answer, but cannot forge one.
    let (store, genesis) = genesis_chain();
    let client = LightClient::new(chain(), validators(), genesis.header);

    let store_key = StoreKey::balance(&addr(50), &kes());
    let (value, honest) = store.get_with_proof(&store_key);
    let value = value.expect("account is funded");

    // The honest proof verifies, so a blanket rejection would not pass.
    assert!(
        client
            .verify_balance(&addr(50), &kes(), Some(&value), &honest)
            .is_ok()
    );

    let encoded = honest.to_bytes();
    let mut accepted_variants = 0u64;
    for seed in 0..ROUNDS {
        let mut rng = Rng::new(seed);
        let bytes = mutate(&mut rng, &encoded);
        let Ok(forged) = decode_exact::<Proof>(&bytes) else {
            continue;
        };
        if forged == honest {
            continue;
        }
        accepted_variants += 1;
        assert!(
            client
                .verify_balance(&addr(50), &kes(), Some(&value), &forged)
                .is_err(),
            "a mutated proof verified (seed {seed})"
        );
    }
    assert!(
        accepted_variants > 0,
        "no mutated proof even decoded — the test would be vacuous"
    );
}

#[test]
fn no_proof_lets_a_server_invent_a_balance() {
    // Lying about the *value* rather than the proof. The honest proof plus a
    // fabricated amount must fail for every amount that is not the real one.
    let (store, genesis) = genesis_chain();
    let client = LightClient::new(chain(), validators(), genesis.header);
    let (_, honest) = store.get_with_proof(&StoreKey::balance(&addr(50), &kes()));

    for seed in 0..ROUNDS {
        let mut rng = Rng::new(seed);
        let claimed = Amount::from_afri(rng.next_u64() % 1_000_000);
        if claimed == Amount::from_afri(1_000) {
            continue;
        }
        assert!(
            client
                .verify_balance(&addr(50), &kes(), Some(&claimed.to_bytes()), &honest)
                .is_err(),
            "a fabricated balance verified (seed {seed})"
        );
    }
}

#[test]
fn no_proof_lets_a_server_deny_a_funded_account() {
    // Lying by omission is the failure mode absence proofs exist to close.
    let (store, genesis) = genesis_chain();
    let client = LightClient::new(chain(), validators(), genesis.header);

    let (_, funded) = store.get_with_proof(&StoreKey::balance(&addr(50), &kes()));
    assert!(
        client
            .verify_balance(&addr(50), &kes(), None, &funded)
            .is_err()
    );

    // And an absence proof for one key must not carry over to another.
    let (_, absent) = store.get_with_proof(&StoreKey::balance(&addr(77), &kes()));
    assert!(
        client
            .verify_balance(&addr(50), &kes(), None, &absent)
            .is_err(),
        "an absence proof for a stranger must not deny a funded account"
    );
}

#[test]
fn no_mutated_merkle_proof_verifies() {
    let tree = MerkleTree::from_items((0..64).map(|i| format!("tx-{i}")));
    let root = tree.root();
    let leaf = afrolink_crypto::merkle::leaf_hash(b"tx-17");
    let honest = tree.prove(17).expect("in range");
    assert!(honest.verify(root, leaf, 17, 64).is_ok());

    let mut exercised = 0u64;
    for seed in 0..ROUNDS {
        let mut rng = Rng::new(seed);
        let mut forged = honest.clone();
        match rng.below(4) {
            0 => forged.index = rng.below(128),
            1 => forged.total = rng.below(128),
            2 => {
                if !forged.siblings.is_empty() {
                    let i = rng.below(forged.siblings.len());
                    forged.siblings[i] = Hash32::from_bytes([rng.byte(); 32]);
                }
            }
            _ => {
                forged
                    .siblings
                    .truncate(rng.below(forged.siblings.len() + 1));
            }
        }
        if forged == honest {
            continue;
        }
        exercised += 1;
        // The caller's own knowledge of position and size is what the proof
        // is checked against — the proof's own fields are prover-chosen.
        assert!(
            forged.verify(root, leaf, 17, 64).is_err(),
            "a mutated inclusion proof verified (seed {seed})"
        );
    }
    assert!(exercised > 0);
}

#[test]
fn no_mutated_consistency_proof_reconciles_two_roots() {
    // The mechanism ADR-0011 rests on. If a forged consistency proof could
    // verify, a witness could rewrite history and still satisfy a returning
    // wallet.
    let old = MerkleTree::from_items((0..9).map(|i| format!("e-{i}")));
    let new = MerkleTree::from_items((0..40).map(|i| format!("e-{i}")));
    let honest = new.prove_consistency(9).expect("in range");
    assert!(honest.verify(old.root(), new.root(), 9, 40).is_ok());

    let mut exercised = 0u64;
    for seed in 0..ROUNDS {
        let mut rng = Rng::new(seed);
        let mut forged = honest.clone();
        match rng.below(4) {
            0 => forged.old_size = rng.below(64),
            1 => forged.new_size = rng.below(64),
            2 => {
                if !forged.nodes.is_empty() {
                    let i = rng.below(forged.nodes.len());
                    forged.nodes[i] = Hash32::from_bytes([rng.byte(); 32]);
                }
            }
            _ => forged.nodes.truncate(rng.below(forged.nodes.len() + 1)),
        }
        if forged == honest {
            continue;
        }
        exercised += 1;
        assert!(
            forged.verify(old.root(), new.root(), 9, 40).is_err(),
            "a mutated consistency proof verified (seed {seed})"
        );
    }
    assert!(exercised > 0);
}

#[test]
fn no_mutated_commit_certifies_a_header() {
    // A commit is what a light client checks a header against, so forging one
    // is forging the chain.
    let (_, genesis) = genesis_chain();
    let block_id = genesis.header.id();
    let signatures = [1u8, 2, 3, 4]
        .iter()
        .map(|s| {
            Vote {
                chain_id: chain(),
                height: Height::GENESIS,
                round: Round::ZERO,
                vote_type: VoteType::Precommit,
                block_id: Some(block_id),
                validator: addr(*s),
            }
            .sign(&key(*s))
        })
        .collect();
    let honest = Commit::new(Height::GENESIS, Round::ZERO, block_id, signatures);
    assert!(honest.verify(&chain(), &validators()).is_ok());

    let encoded = honest.to_bytes();
    let mut exercised = 0u64;
    for seed in 0..ROUNDS {
        let mut rng = Rng::new(seed);
        let bytes = mutate(&mut rng, &encoded);
        let Ok(forged) = decode_exact::<Commit>(&bytes) else {
            continue;
        };
        if forged == honest {
            continue;
        }
        exercised += 1;
        assert!(
            forged.verify(&chain(), &validators()).is_err(),
            "a mutated commit verified (seed {seed})"
        );
    }
    assert!(exercised > 0);
}

#[test]
fn no_mutated_tree_head_verifies_under_a_witnesss_key() {
    // A signed head is a witness's public commitment. If one could be forged,
    // the whole corroboration argument collapses.
    let mut log = WitnessLog::new(chain(), LogId::from_public_key(&key(200).public_key()));
    for h in 1..=30u64 {
        log.append(LogEntry {
            height: Height(h),
            block_id: Hash32::from_bytes([u8::try_from(h % 251).unwrap_or(0); 32]),
            observed_at: Timestamp::from_millis(1_700_000_000_000 + h * 1_000),
        })
        .expect("monotonic");
    }
    let honest = log
        .sign_head(&key(200), Timestamp::from_millis(1_700_000_100_000))
        .expect("own key");
    let public = key(200).public_key();
    assert!(honest.verify(&public).is_ok());

    let encoded = honest.to_bytes();
    let mut exercised = 0u64;
    for seed in 0..ROUNDS {
        let mut rng = Rng::new(seed);
        let bytes = mutate(&mut rng, &encoded);
        let Ok(forged) = decode_exact::<afrolink_witness::SignedTreeHead>(&bytes) else {
            continue;
        };
        if forged == honest {
            continue;
        }
        exercised += 1;
        assert!(
            forged.verify(&public).is_err(),
            "a mutated tree head verified (seed {seed})"
        );
    }
    assert!(exercised > 0);
}

#[test]
fn no_mutated_signature_verifies() {
    // Ed25519 with `verify_strict`, exercised rather than assumed. The strict
    // variant is what rejects the small-order and non-canonical points that
    // make a signature verify under more than one key.
    let secret = key(5);
    let public = secret.public_key();
    let message = b"pay 250 KES to amina";
    let honest = secret.sign(afrolink_crypto::hash::Domain::TxSignDoc, message);
    assert!(
        public
            .verify(afrolink_crypto::hash::Domain::TxSignDoc, message, &honest)
            .is_ok()
    );

    let bytes = honest.to_bytes();
    for seed in 0..ROUNDS {
        let mut rng = Rng::new(seed);
        let mut forged_bytes = bytes;
        let i = rng.below(64);
        forged_bytes[i] ^= 1u8 << rng.below(8);
        if forged_bytes == bytes {
            continue;
        }
        if let Ok(forged) = afrolink_crypto::Signature::from_bytes(&forged_bytes) {
            assert!(
                public
                    .verify(afrolink_crypto::hash::Domain::TxSignDoc, message, &forged)
                    .is_err(),
                "a mutated signature verified (seed {seed})"
            );
        }
    }
}

#[test]
fn a_signature_does_not_carry_across_domains() {
    // Domain separation, exercised. Without it a vote signature could be
    // replayed as a transaction signature.
    let secret = key(5);
    let public = secret.public_key();
    let message = b"same bytes, different meaning";
    let signed = secret.sign(afrolink_crypto::hash::Domain::VoteSignDoc, message);
    assert!(
        public
            .verify(afrolink_crypto::hash::Domain::TxSignDoc, message, &signed)
            .is_err(),
        "a vote signature must not verify as a transaction signature"
    );
}
