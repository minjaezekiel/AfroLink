//! End to end: a phone with nothing but a scanned checkpoint reaches a verified
//! balance, and an attacker with a perfect forged history does not.
//!
//! This is the claim ADR-0011 makes, exercised against real blocks, real
//! commits and a real state tree rather than fixtures. Everything the wallet
//! receives here beyond 32 bytes is treated as hostile.

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
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Allocation, Block, Executor, Genesis, GenesisLimits, ValidatorSets};
use afrolink_light::LightClient;
use afrolink_primitives::codec::{Encode, decode_exact};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Round, Timestamp};
use afrolink_state::{KeyValueStore, MemoryStore, StoreKey};
use afrolink_witness::{
    Checkpoint, LogEntry, LogId, Observation, Policy, Remembered, Witness, WitnessError,
    WitnessLog, WitnessSet, corroborate,
};

const GENESIS_MS: u64 = 1_700_000_000_000;

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

/// A short chain crediting `funded` to one account, and every block's commit.
///
/// Execution is deterministic, so two chains only differ if their history does —
/// which is why the forgery test varies the allocation rather than replaying
/// the same call twice.
fn run_chain(blocks: u64, funded: u64) -> (MemoryStore, Vec<(Block, Option<Commit>)>) {
    let genesis = Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(GENESIS_MS),
        validators: validators(),
        issuers: vec![(kes(), Issuer::new(addr(100)))],
        allocations: vec![Allocation {
            address: addr(50),
            denom: kes(),
            amount: Amount::from_afri(funded),
        }],
    };
    let mut store = MemoryStore::new();
    let first = genesis
        .apply(&mut store, GenesisLimits::devnet())
        .expect("applies");

    let mut chain_blocks = vec![(first.clone(), None)];
    let executor = Executor::new(chain());
    let mut parent = first;
    for _ in 0..blocks {
        let height = parent.header.height.next();
        let (block, _) = executor.build_block(
            &mut store,
            height,
            Timestamp::from_millis(GENESIS_MS + height.0 * 1_000),
            parent.header.id(),
            Vec::new(),
            ValidatorSets::unchanged(&validators()),
        );
        let block_id = block.header.id();
        let signatures = [1u8, 2, 3, 4]
            .iter()
            .map(|s| {
                Vote {
                    chain_id: chain(),
                    height,
                    round: Round::ZERO,
                    vote_type: VoteType::Precommit,
                    block_id: Some(block_id),
                    validator: addr(*s),
                }
                .sign(&key(*s))
            })
            .collect();
        let commit = Commit::new(height, Round::ZERO, block_id, signatures);
        parent = block.clone();
        chain_blocks.push((block, Some(commit)));
    }
    (store, chain_blocks)
}

fn witness_set() -> WitnessSet {
    WitnessSet::new(vec![
        Witness::new(key(200).public_key(), *b"ke", "Safaricom"),
        Witness::new(key(201).public_key(), *b"ng", "Lagos Bank"),
        Witness::new(key(202).public_key(), *b"za", "SARB"),
    ])
    .expect("valid")
}

/// Build a witness's log over `blocks`, then have it prove the entry at
/// `target_height`. `tamper` rewrites what the witness claims it saw.
fn observe(
    set: &WitnessSet,
    seed: u8,
    blocks: &[(Block, Option<Commit>)],
    target_height: Height,
    tamper: Option<Hash32>,
) -> Observation {
    let mut log = WitnessLog::new(chain(), LogId::from_public_key(&key(seed).public_key()));
    let mut index = 0u64;
    for (i, (block, _)) in blocks.iter().enumerate().skip(1) {
        let block_id = if block.header.height == target_height {
            index = (i - 1) as u64;
            tamper.unwrap_or_else(|| block.header.id())
        } else {
            block.header.id()
        };
        log.append(LogEntry {
            height: block.header.height,
            block_id,
            observed_at: Timestamp::from_millis(GENESIS_MS + block.header.height.0 * 1_000),
        })
        .expect("monotonic");
    }
    let sth = log
        .sign_head(&key(seed), Timestamp::from_millis(GENESIS_MS + 100_000))
        .expect("own key");
    let proof = log.prove_inclusion(index).expect("in range");
    set.observe(
        &chain(),
        &sth,
        index,
        log.entry(index).expect("in range"),
        &proof,
    )
    .expect("the witness proved its own record")
}

#[test]
fn a_phone_goes_from_a_scanned_checkpoint_to_a_verified_balance() {
    let (store, blocks) = run_chain(8, 1_000);
    let target = Height(8);
    let set = witness_set();

    // 1. Three witnesses in three jurisdictions independently report the tip.
    let observations = vec![
        observe(&set, 200, &blocks, target, None),
        observe(&set, 201, &blocks, target, None),
        observe(&set, 202, &blocks, target, None),
    ];
    let checkpoint =
        corroborate(&chain(), &observations, Policy::BASELINE).expect("witnesses agree");

    // 2. The wallet keeps only this. Small enough to scan off a screen or a
    //    printed slip, which is the whole point.
    let scanned = checkpoint.to_bytes();
    assert!(scanned.len() < 128, "checkpoint is {} bytes", scanned.len());
    let Checkpoint {
        height, block_id, ..
    } = decode_exact::<Checkpoint>(&scanned).expect("round trips");
    assert_eq!(height, target);

    // 3. Everything else arrives from an untrusted server and is checked
    //    against those 32 bytes.
    let (block, _) = blocks
        .iter()
        .find(|(b, _)| b.header.height == height)
        .expect("height exists");
    let client = LightClient::from_block_id(
        chain(),
        block_id,
        block.header.clone(),
        validators(),
        validators(),
    )
    .expect("the header matches the corroborated block");

    // 4. And the wallet reads its money, proved against a root it derived
    //    itself rather than one it was handed.
    let store_key = StoreKey::balance(&addr(50), &kes());
    let (value, proof) = store.get_with_proof(&store_key);
    let balance = client
        .verify_balance(&addr(50), &kes(), value.as_deref(), &proof)
        .expect("proof verifies against the checkpointed state");
    assert_eq!(balance, Amount::from_afri(1_000));
}

#[test]
fn a_forged_history_with_perfect_signatures_never_reaches_the_wallet() {
    // The attack ADR-0011 exists for. The forged chain is *cryptographically
    // flawless*: every block is real, every commit reaches a full quorum of the
    // set that signed it, and in it the attacker credits themselves a thousand
    // times over. A client checking only signature arithmetic accepts it. What
    // stops it is that no witness ever recorded it.
    let (_, real) = run_chain(8, 1_000);
    let (forged_store, forged) = run_chain(8, 1_000_000);
    let set = witness_set();

    // Confirm the forgery really would pass every check the light client makes
    // on its own, or this test proves nothing.
    let (forged_block, forged_commit) = &forged[8];
    let commit = forged_commit.as_ref().expect("built with a commit");
    assert!(
        commit.verify(&chain(), &validators()).is_ok(),
        "the forged commit must reach a full quorum"
    );
    let forged_client = LightClient::from_checkpoint(
        chain(),
        forged_block.header.clone(),
        validators(),
        validators(),
    )
    .expect("the forged chain is internally consistent");
    let (value, proof) = forged_store.get_with_proof(&StoreKey::balance(&addr(50), &kes()));
    assert_eq!(
        forged_client
            .verify_balance(&addr(50), &kes(), value.as_deref(), &proof)
            .expect("the forged state proves its own lie"),
        Amount::from_afri(1_000_000),
        "believing the forged checkpoint would show a fabricated balance"
    );

    // Witnesses report the real chain; the attacker's tip is not in any log.
    let observations = vec![
        observe(&set, 200, &real, Height(8), None),
        observe(&set, 201, &real, Height(8), None),
    ];
    let checkpoint = corroborate(&chain(), &observations, Policy::BASELINE).expect("agreed");

    assert_ne!(
        checkpoint.block_id,
        forged_block.header.id(),
        "witnesses recorded a different block at this height"
    );
    assert_eq!(
        LightClient::from_block_id(
            chain(),
            checkpoint.block_id,
            forged_block.header.clone(),
            validators(),
            validators(),
        )
        .err(),
        Some(afrolink_light::LightError::WrongBlock),
        "a signature-perfect forgery is still not the block anyone witnessed"
    );
}

#[test]
fn one_dishonest_witness_stops_the_wallet_rather_than_misleading_it() {
    // Two witnesses tell the truth and would satisfy the policy by themselves.
    // The third lies. The wallet refuses outright instead of outvoting the liar,
    // because deciding which history is real is not a judgement it can make.
    let (_, blocks) = run_chain(8, 1_000);
    let set = witness_set();

    let observations = vec![
        observe(&set, 200, &blocks, Height(8), None),
        observe(&set, 201, &blocks, Height(8), None),
        observe(
            &set,
            202,
            &blocks,
            Height(8),
            Some(Hash32::from_bytes([0xEE; 32])),
        ),
    ];

    assert_eq!(
        corroborate(&chain(), &observations, Policy::BASELINE),
        Err(WitnessError::SplitView { height: 8 })
    );
}

#[test]
fn a_wallet_returning_months_later_detects_a_witness_that_rewrote_history() {
    // The long-absence case, which is the one ADR-0010 could not answer. The
    // wallet holds forty bytes from its last session; that is enough.
    let (_, blocks) = run_chain(30, 1_000);
    let set = witness_set();

    let mut honest = WitnessLog::new(chain(), LogId::from_public_key(&key(200).public_key()));
    for (block, _) in blocks.iter().skip(1).take(10) {
        honest
            .append(LogEntry {
                height: block.header.height,
                block_id: block.header.id(),
                observed_at: Timestamp::from_millis(GENESIS_MS + block.header.height.0 * 1_000),
            })
            .expect("monotonic");
    }
    let remembered = Remembered::from_head(
        &honest
            .sign_head(&key(200), Timestamp::from_millis(GENESIS_MS + 10_000))
            .expect("own key"),
    );

    // Months pass. The witness grows its log — and quietly changes block 4,
    // which the wallet saw before it went offline.
    let mut rewritten = WitnessLog::new(chain(), LogId::from_public_key(&key(200).public_key()));
    for (block, _) in blocks.iter().skip(1) {
        let block_id = if block.header.height == Height(4) {
            Hash32::from_bytes([0xEE; 32])
        } else {
            block.header.id()
        };
        rewritten
            .append(LogEntry {
                height: block.header.height,
                block_id,
                observed_at: Timestamp::from_millis(GENESIS_MS + block.header.height.0 * 1_000),
            })
            .expect("monotonic");
    }
    let sth = rewritten
        .sign_head(&key(200), Timestamp::from_millis(GENESIS_MS + 900_000))
        .expect("own key");
    let proof = rewritten
        .prove_consistency(remembered.size)
        .expect("in range");

    assert_eq!(
        set.check_continuity(&remembered, &sth, &proof),
        Err(WitnessError::BadConsistencyProof),
        "forty remembered bytes catch a rewrite months later"
    );

    // And an honest continuation of the same log passes, so the check is
    // discriminating rather than merely strict.
    let mut grown = WitnessLog::new(chain(), LogId::from_public_key(&key(200).public_key()));
    for (block, _) in blocks.iter().skip(1) {
        grown
            .append(LogEntry {
                height: block.header.height,
                block_id: block.header.id(),
                observed_at: Timestamp::from_millis(GENESIS_MS + block.header.height.0 * 1_000),
            })
            .expect("monotonic");
    }
    let good_sth = grown
        .sign_head(&key(200), Timestamp::from_millis(GENESIS_MS + 900_000))
        .expect("own key");
    let good_proof = grown.prove_consistency(remembered.size).expect("in range");
    assert!(
        set.check_continuity(&remembered, &good_sth, &good_proof)
            .is_ok()
    );
}
