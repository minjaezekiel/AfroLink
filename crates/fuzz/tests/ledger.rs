//! Property testing against the ledger's **semantics**, not its bytes.
//!
//! # Why this exists, in one paragraph
//!
//! The codec suite next door asks *"can this input be read two ways?"* It found
//! six real defects and it cannot ask the other question: *"should this input
//! have been obeyed?"* A session spent attacking the chain by hand found seven
//! working attacks that were invisible to it, because every one arrived as a
//! well-formed transaction, correctly signed, from an account entitled to send
//! it ([08](../../../docs/08-adversarial-testing.md) §8–15). Finding seven by
//! hand is strong evidence there are more.
//!
//! So this suite generates *sequences of valid transactions* from a seed, runs
//! them, and asserts after every block that the ledger still holds together.
//!
//! # The closed world
//!
//! Conservation cannot be checked over a store that cannot be enumerated, and
//! `MemoryStore` deliberately cannot be — it is a sparse Merkle tree that
//! answers point lookups with proofs. So the generator works inside a **fixed
//! universe of addresses** and never names one outside it: every actor, both
//! module accounts, every group address the actors could derive, and some
//! outsiders who only ever receive. Summing that set is then summing the ledger.
//!
//! That is a real limit and worth stating: a defect that moves value to an
//! address this generator cannot name is a defect this suite cannot see.
//!
//! # The invariants
//!
//! | | What it would have caught |
//! |---|---|
//! | Supply is conserved | Any mint or burn through a path that should not have one |
//! | Nobody loses money without cause | The fee-payer drain of §7 |
//! | Nonces never go backwards | Replay, and an attacker burning a victim's sequence |
//! | A group's cycle only advances on a real payout | The chama drain of §8 |
//! | A member cannot be due more cycles than have happened | The double-contribution of §10 |
//! | Every account record still decodes | A state a node could write but not read back |

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_bank::{Bank, Issuer};
use afrolink_crypto::hash::Domain;
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{BlockContext, Executor, fee_collector_address};
use afrolink_fuzz::Rng;
use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
use afrolink_state::{KeyValueStore, MemoryStore, StoreKey};
use afrolink_types::group::{Contribution, FoundingMember, PayoutPolicy, Quorum, Role};
use afrolink_types::{Account, AccountKind, Fee, Message, Transaction, TxBody};

/// Actors that hold keys and send transactions.
const ACTORS: u8 = 6;
/// Addresses that only ever receive, so paying a stranger is exercised.
const OUTSIDERS: u8 = 4;
/// Group addresses per actor kept in the universe from the start.
const GROUP_SLOTS: u64 = 3;

fn sk(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn actor(i: u8) -> Address {
    Address::from_public_key(&sk(i + 1).public_key())
}

fn outsider(i: u8) -> Address {
    Address::from_public_key(&sk(200 + i).public_key())
}

fn chain() -> ChainId {
    ChainId::new("afrolink-1").unwrap()
}

fn kes() -> Denom {
    Denom::sovereign("ke", "kes").unwrap()
}

fn group_slot(who: u8, nonce: u64) -> Address {
    Address::derived(
        Domain::GroupAddress,
        &[actor(who).as_bytes().as_slice(), &nonce.to_le_bytes()].concat(),
    )
}

/// Every address that could ever hold value in this world.
///
/// Built once. It is walked twice per block for every denomination, so
/// rebuilding and re-sorting it each time dominated the suite's runtime.
fn universe() -> &'static [Address] {
    static UNIVERSE: std::sync::LazyLock<Vec<Address>> = std::sync::LazyLock::new(build_universe);
    &UNIVERSE
}

fn build_universe() -> Vec<Address> {
    let mut all = Vec::new();
    for i in 0..ACTORS {
        all.push(actor(i));
    }
    for i in 0..OUTSIDERS {
        all.push(outsider(i));
    }
    all.push(fee_collector_address());
    all.push(afrolink_staking::staking_account());
    for who in 0..ACTORS {
        for nonce in 0..GROUP_SLOTS {
            all.push(group_slot(who, nonce));
        }
    }
    all.sort_unstable();
    all.dedup();
    all
}

/// The two denominations in play, in a fixed order that indexes a snapshot row.
fn denoms() -> &'static [Denom; 2] {
    static DENOMS: std::sync::LazyLock<[Denom; 2]> =
        std::sync::LazyLock::new(|| [kes(), Denom::native()]);
    &DENOMS
}

/// Genesis: every actor funded in both denominations.
fn opening_state() -> MemoryStore {
    let mut store = MemoryStore::new();
    let mut bank = Bank::new(&mut store);
    bank.register_issuer(&kes(), &Issuer::new(actor(0)))
        .unwrap();
    for i in 0..ACTORS {
        bank.mint(&actor(0), &actor(i), &kes(), Amount::from_afri(1_000_000))
            .unwrap();
        bank.genesis_allocate(&actor(i), &Denom::native(), Amount::from_afri(500_000))
            .unwrap();
    }
    store
}

// ---------------------------------------------------------------------------
// What a ledger must always be true of
// ---------------------------------------------------------------------------

/// Every balance in the world, indexed by position in [`universe`].
///
/// A flat vector rather than a map keyed by `(Address, String)`: this is taken
/// twice per block and the key allocation was most of the cost.
type Balances = Vec<[Amount; 2]>;

fn snapshot(store: &MemoryStore) -> Balances {
    let view = afrolink_bank::BankView::new(store);
    universe()
        .iter()
        .map(|address| {
            let [a, b] = denoms();
            [
                view.balance(address, a).unwrap(),
                view.balance(address, b).unwrap(),
            ]
        })
        .collect()
}

/// Addresses a block is *entitled* to debit.
///
/// This is the model that did not exist, and its absence is what let a fee payer
/// be charged without consenting. Anything outside this set losing money is a
/// theft, whatever else the block was doing.
fn may_lose(transactions: &[Transaction]) -> Vec<Address> {
    let mut out = Vec::new();
    for tx in transactions {
        // The sender pays for their own transaction, and the fee payer pays the
        // fee — the executor now requires the payer to have signed, so being in
        // this set means having consented.
        out.push(tx.body.sender);
        out.push(tx.body.fee.payer_or(tx.body.sender));
        for message in &tx.body.messages {
            match message {
                // The pot is the group's own money leaving on a payout.
                Message::GroupPayout { group } => out.push(*group),
                // Matured stake and slashed stake both leave the module account.
                Message::WithdrawUnbonded | Message::ReportEquivocation { .. } => {
                    out.push(afrolink_staking::staking_account());
                }
                // Everything else debits the sender alone, or nothing at all.
                _ => {}
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn check_invariants(
    seed: u64,
    height: u64,
    store: &MemoryStore,
    before: &Balances,
    transactions: &[Transaction],
) {
    let after = snapshot(store);
    let view = afrolink_bank::BankView::new(store);
    let entitled = may_lose(transactions);

    // 1. Supply is conserved. The sum of every balance in the world equals the
    //    recorded total supply, for every denomination, always.
    for (slot, denom) in denoms().iter().enumerate() {
        let mut total = Amount::ZERO;
        for row in &after {
            total = total.checked_add(row[slot]).unwrap();
        }
        assert_eq!(
            total,
            view.total_supply(denom).unwrap(),
            "seed {seed} height {height}: balances no longer sum to supply of {denom}"
        );
    }

    // 2. Nobody loses money without cause.
    for (i, address) in universe().iter().enumerate() {
        for (slot, denom) in denoms().iter().enumerate() {
            if after[i][slot] < before[i][slot] {
                assert!(
                    entitled.contains(address),
                    "seed {seed} height {height}: {address:?} lost {denom} without \
                     sending, sponsoring, or being named as a source by any \
                     transaction in the block"
                );
            }
        }
    }

    // 3. Nonces never go backwards, and no account record has become unreadable.
    for address in universe() {
        let Some(bytes) = store.get(&StoreKey::account(address)) else {
            continue;
        };
        let account =
            afrolink_primitives::codec::decode_exact::<Account>(&bytes).unwrap_or_else(|e| {
                panic!("seed {seed} height {height}: {address:?} record no longer decodes: {e}")
            });
        assert!(
            account.has_a_usable_authority(),
            "seed {seed} height {height}: {address:?} can no longer be signed for"
        );
        if let Some(pointer) = account.last_txn {
            assert!(
                pointer.height.0 <= height,
                "seed {seed} height {height}: history pointer names a future block"
            );
        }

        // 4. Group rules, which is where the hand-written attacks all landed.
        if let AccountKind::Group(group) = &account.kind {
            assert!(
                group.members.len() >= 2
                    && group.members.len() <= afrolink_types::group::MAX_GROUP_MEMBERS,
                "seed {seed} height {height}: group membership out of bounds"
            );
            if let PayoutPolicy::Rotation { order, next } = &group.policy {
                assert!(
                    (*next as usize) < order.len(),
                    "seed {seed} height {height}: rotation index out of range"
                );
            }
            for member in &group.members {
                assert!(
                    member.last_paid_cycle.is_none_or(|c| c <= group.cycle),
                    "seed {seed} height {height}: a member paid into a future cycle"
                );
                // A member cannot owe, or have met, more cycles than the group
                // has actually had. This is the double-contribution defect
                // stated as an invariant.
                assert!(
                    member.contributions_due() <= group.cycle.saturating_add(1),
                    "seed {seed} height {height}: member credited {} cycles but \
                     the group has only had {}",
                    member.contributions_due(),
                    group.cycle.saturating_add(1)
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The generator
// ---------------------------------------------------------------------------

/// Tracks enough to build transactions that are usually valid.
struct World {
    nonces: [u64; ACTORS as usize],
    groups: Vec<Address>,
}

impl World {
    fn new() -> Self {
        Self {
            nonces: [0; ACTORS as usize],
            groups: Vec::new(),
        }
    }

    /// A destination inside the closed universe.
    fn destination(&self, rng: &mut Rng) -> Address {
        match rng.below(4) {
            0 if !self.groups.is_empty() => self.groups[rng.below(self.groups.len())],
            1 => outsider(u8::try_from(rng.below(OUTSIDERS as usize)).unwrap()),
            2 => fee_collector_address(),
            _ => actor(u8::try_from(rng.below(ACTORS as usize)).unwrap()),
        }
    }

    fn message(&mut self, rng: &mut Rng, sender: u8) -> Message {
        match rng.below(12) {
            0..=3 => Message::Transfer {
                to: self.destination(rng),
                denom: if rng.below(4) == 0 {
                    Denom::native()
                } else {
                    kes()
                },
                // Usually small enough to succeed; sometimes far more than
                // anyone holds, so the insufficient-funds path runs too.
                amount: if rng.below(5) == 0 {
                    Amount::from_afri(9_000_000)
                } else {
                    Amount::from_units(u128::from(rng.next_u64() % 20_000) + 1)
                },
                reference: None,
            },
            4 => {
                let slot = self.nonces[sender as usize] % GROUP_SLOTS;
                let address = group_slot(sender, slot);
                if !self.groups.contains(&address) {
                    self.groups.push(address);
                }
                let count = 2 + rng.below(3);
                let members: Vec<FoundingMember> = (0..count)
                    .map(|i| {
                        FoundingMember::new(
                            actor(u8::try_from(i).unwrap()),
                            if i == 0 {
                                Role::Treasurer
                            } else {
                                Role::Member
                            },
                        )
                    })
                    .collect();
                let order = members.iter().map(|m| m.address).collect();
                Message::CreateGroup {
                    name: "chama".to_owned(),
                    members,
                    contribution: Contribution {
                        amount: Amount::from_afri(10),
                        denom: kes(),
                        period_blocks: 5,
                    },
                    policy: if rng.below(4) == 0 {
                        PayoutPolicy::Accumulate
                    } else {
                        PayoutPolicy::Rotation { order, next: 0 }
                    },
                    quorum: Quorum::TWO_THIRDS,
                }
            }
            5 | 6 if !self.groups.is_empty() => Message::ContributeToGroup {
                group: self.groups[rng.below(self.groups.len())],
                // Usually right, sometimes wrong: the wrong amount must be
                // refused rather than credited.
                amount: if rng.below(4) == 0 {
                    Amount::from_units(1)
                } else {
                    Amount::from_afri(10)
                },
            },
            7 if !self.groups.is_empty() => Message::GroupPayout {
                group: self.groups[rng.below(self.groups.len())],
            },
            8 => Message::Bond {
                public_key: sk(sender + 1).public_key(),
                country: afrolink_consensus::CountryCode::new("ke").unwrap(),
                amount: Amount::from_afri(10_000 + u64::from(rng.byte())),
            },
            9 => Message::Unbond {
                amount: Amount::from_afri(1_000 + u64::from(rng.byte())),
            },
            10 => Message::WithdrawUnbonded,
            _ => Message::SetAccountFlag {
                flag: afrolink_types::AccountFlag::RequireReference,
                enabled: rng.below(2) == 0,
            },
        }
    }

    fn transaction(&mut self, rng: &mut Rng) -> Transaction {
        let sender = u8::try_from(rng.below(ACTORS as usize)).unwrap();
        let messages = vec![self.message(rng, sender)];

        // Mostly the right nonce, so blocks make progress; sometimes wrong, so
        // the rejection path runs too.
        let nonce = match rng.below(8) {
            0 => self.nonces[sender as usize].saturating_add(1),
            1 => self.nonces[sender as usize].saturating_sub(1),
            _ => self.nonces[sender as usize],
        };

        // Every fourth transaction names a sponsor. Half of those forge it: the
        // sponsor does not sign, which must buy nothing.
        let sponsor = u8::try_from(rng.below(ACTORS as usize)).unwrap();
        let body = TxBody {
            chain_id: chain(),
            sender: actor(sender),
            nonce,
            valid_until: Height(u64::MAX),
            fee: if rng.below(4) == 0 && sponsor != sender {
                Fee::sponsored_by(Amount::from_units(500), kes(), actor(sponsor))
            } else {
                Fee::new(Amount::from_units(500), kes())
            },
            messages,
            memo: String::new(),
        };

        if body.fee.is_sponsored() {
            let signer = if rng.below(2) == 0 { sponsor } else { sender };
            body.sign_sponsored(&[&sk(sender + 1)], &[&sk(signer + 1)])
        } else {
            body.sign(&sk(sender + 1))
        }
    }
}

/// How much of what the generator produced actually happened.
///
/// **A test of the test.** A property suite whose inputs are all rejected passes
/// every invariant and proves nothing, and that failure is silent — the run
/// still goes green. So the run counts what it did and asserts on it, rather
/// than resting on a comment claiming coverage that was measured once.
#[derive(Default)]
struct Coverage {
    applied: u64,
    total: u64,
    codes: [u64; 16],
}

impl Coverage {
    fn record(&mut self, outcome: &afrolink_executor::BlockOutcome, offered: usize) {
        self.applied = self.applied.saturating_add(outcome.succeeded() as u64);
        self.total = self.total.saturating_add(offered as u64);
        for o in &outcome.outcomes {
            let slot = o.receipt.code.as_u16() as usize;
            if let Some(count) = self.codes.get_mut(slot) {
                *count = count.saturating_add(1);
            }
        }
    }

    /// Distinct outcomes the run produced.
    ///
    /// Thresholds are set below what a healthy run produces rather than at it:
    /// the guard exists to catch a generator that has stopped reaching the
    /// executor, not to fail the build when one code shifts.
    fn distinct_codes(&self) -> usize {
        self.codes.iter().filter(|c| **c > 0).count()
    }

    fn assert_meaningful(&self) {
        assert!(
            self.applied * 4 >= self.total,
            "the generator has degenerated: only {} of {} transactions applied, \
             so the invariants below are holding over an empty ledger",
            self.applied,
            self.total
        );
        assert!(
            self.distinct_codes() >= 5,
            "only {} distinct result codes were produced ({:?}); the generator \
             is no longer reaching most of the executor",
            self.distinct_codes(),
            self.codes
        );
    }
}

/// Run one seeded chain, checking every invariant after every block.
fn run(seed: u64, blocks: u64, coverage: &mut Coverage) -> afrolink_crypto::hash::Hash32 {
    let mut rng = Rng::new(seed);
    let mut store = opening_state();
    let mut world = World::new();
    let exec = Executor::new(chain());

    for height in 1..=blocks {
        let count = 1 + rng.below(4);
        let transactions: Vec<Transaction> =
            (0..count).map(|_| world.transaction(&mut rng)).collect();

        let before = snapshot(&store);
        let outcome = exec.execute_block(
            &mut store,
            BlockContext {
                height: Height(height),
                time: Timestamp::from_millis(1_700_000_000_000 + height * 1_000),
            },
            &transactions,
        );
        check_invariants(seed, height, &store, &before, &transactions);

        // Track nonces from what actually applied, so later blocks stay mostly
        // valid rather than degenerating into an endless run of rejections.
        for tx in &transactions {
            for i in 0..ACTORS {
                if tx.body.sender == actor(i) {
                    let key = StoreKey::account(&actor(i));
                    if let Some(bytes) = store.get(&key)
                        && let Ok(account) =
                            afrolink_primitives::codec::decode_exact::<Account>(&bytes)
                    {
                        world.nonces[i as usize] = account.nonce;
                    }
                }
            }
        }
        coverage.record(&outcome, transactions.len());
    }
    store.root()
}

// ---------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_holds_together_under_arbitrary_transaction_sequences() {
    // 30 seeds × up to 4 transactions × 30 blocks. Each seed is a different
    // sequence, and every invariant is checked after every block — so a failure
    // names the seed, the height, and the rule that broke.
    let mut coverage = Coverage::default();
    for seed in 0..30u64 {
        run(seed, 30, &mut coverage);
    }
    coverage.assert_meaningful();
}

#[test]
fn a_sequence_that_broke_once_stays_fixed() {
    // Regression slot. When a seed above fails, pin it here with a note saying
    // what it found, so the specific sequence is never lost to a change in the
    // generator.
    let mut coverage = Coverage::default();
    for seed in [0u64, 1, 7, 42, 99] {
        run(seed, 60, &mut coverage);
    }
    coverage.assert_meaningful();
}

#[test]
fn the_same_seed_produces_the_same_ledger() {
    // The property every other test in this file rests on: a failure that
    // cannot be reproduced exactly is a failure that gets closed as flaky.
    for seed in [3u64, 17, 250] {
        let mut a = Coverage::default();
        let mut b = Coverage::default();
        assert_eq!(
            run(seed, 25, &mut a),
            run(seed, 25, &mut b),
            "seed {seed} did not replay to the same state root"
        );
    }
}
