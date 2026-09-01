//! Attacks on the chain's money, run as an attacker would run them.
//!
//! Every test here is written from the outside: it builds a chain, submits
//! ordinary signed transactions, and tries to end up with money it is not
//! entitled to. Nothing reaches into state to arrange an impossible starting
//! position, because an attacker cannot.
//!
//! A test that **passes** here is an attack that fails. When one of these is
//! first written it is expected to fail, and the fix is what makes it pass.

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
use afrolink_primitives::{Amount, ChainId, CountryCode, Denom, Height, Timestamp};
use afrolink_state::MemoryStore;
use afrolink_types::group::{Contribution, FoundingMember, PayoutPolicy, Quorum, Role, ShareRules};
use afrolink_types::{Fee, Message, Transaction, TxBody};

fn sk(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn addr(seed: u8) -> Address {
    Address::from_public_key(&sk(seed).public_key())
}

fn chain() -> ChainId {
    ChainId::new("afrolink-1").unwrap()
}

fn kes() -> Denom {
    Denom::sovereign("ke", "kes").unwrap()
}

fn ctx(height: u64) -> BlockContext {
    BlockContext {
        height: Height(height),
        time: Timestamp::from_millis(1_700_000_000_000 + height * 1_000),
    }
}

/// Accounts 1..=4 hold 10,000 KES each, as do the attestor (90) and the
/// attacker (66) — an attacker with no money is not a threat model.
fn funded() -> MemoryStore {
    let mut store = MemoryStore::new();
    let mut bank = Bank::new(&mut store);
    bank.register_issuer(
        &kes(),
        &Issuer::new(addr(100)).with_minter(addr(100), Amount::from_afri(1_000_000_000)),
    )
    .unwrap();
    for i in [1u8, 2, 3, 4, 66, 90] {
        bank.mint(&addr(100), &addr(i), &kes(), Amount::from_afri(10_000))
            .unwrap();
    }
    store
}

fn tx(sender: u8, nonce: u64, messages: Vec<Message>) -> Transaction {
    fee_tx(
        sender,
        nonce,
        Fee::new(Amount::from_units(1_000), kes()),
        messages,
    )
}

fn fee_tx(sender: u8, nonce: u64, fee: Fee, messages: Vec<Message>) -> Transaction {
    TxBody {
        chain_id: chain(),
        sender: addr(sender),
        nonce,
        valid_until: Height(u64::MAX),
        fee,
        messages,
        memo: String::new(),
    }
    .sign(&sk(sender))
}

fn balance(store: &mut MemoryStore, who: Address) -> Amount {
    Bank::new(store).view().balance(&who, &kes()).unwrap()
}

// ---------------------------------------------------------------------------
// The savings group — the feature the whole project leads with
// ---------------------------------------------------------------------------

/// A three-member chama: 1,000 KES a cycle, rotating to 1, then 2, then 3.
fn chama(store: &mut MemoryStore, exec: &Executor) -> Address {
    let create = Message::CreateGroup {
        name: "Mama Mboga Chama".to_owned(),
        members: vec![
            FoundingMember::new(addr(1), Role::Treasurer),
            FoundingMember::new(addr(2), Role::Member),
            FoundingMember::new(addr(3), Role::Member),
        ],
        contribution: Contribution {
            amount: Amount::from_afri(1_000),
            denom: kes(),
            period_blocks: 604_800,
        },
        policy: PayoutPolicy::Rotation {
            order: vec![addr(1), addr(2), addr(3)],
            next: 0,
        },
        quorum: Quorum::TWO_THIRDS,
    };
    let group = Address::derived(
        Domain::GroupAddress,
        &[addr(1).as_bytes().as_slice(), &0u64.to_le_bytes()].concat(),
    );
    let out = exec.execute_block(store, ctx(1), &[tx(1, 0, vec![create])]);
    assert_eq!(out.succeeded(), 1, "{:?}", out.outcomes[0].result);
    group
}

#[test]
fn a_member_cannot_be_credited_a_contribution_they_did_not_make() {
    // The group records *that* you contributed, never *how much*. If the
    // executor does not compare the amount against the group's agreed
    // contribution, a member pays one shilling, is credited a full cycle, and
    // collects everyone else's thousand when the rotation reaches them.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = chama(&mut store, &exec);

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            2,
            0,
            vec![Message::ContributeToGroup {
                group,
                amount: Amount::from_units(1), // one unit, not 1,000 KES
            }],
        )],
    );

    assert_eq!(
        out.succeeded(),
        0,
        "a token payment must not buy a full cycle's credit"
    );
}

#[test]
fn a_member_cannot_spin_the_rotation_to_bring_their_own_turn_around() {
    // `GroupPayout` pays the pot and advances the rotation. If any member may
    // call it at any time, and an empty pot still advances the cycle, then a
    // member can call it repeatedly until `next` points at themselves — for the
    // price of a few fees — and then collect the whole pot every cycle.
    //
    // This is the chama drained by one participant.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = chama(&mut store, &exec);

    // Account 3 is last in the order. It calls payout twice against an empty
    // pot to skip accounts 1 and 2.
    let mut spun = 0;
    for nonce in 0..2u64 {
        let out = exec.execute_block(
            &mut store,
            ctx(2 + nonce),
            &[tx(3, nonce, vec![Message::GroupPayout { group }])],
        );
        spun += out.succeeded();
    }

    assert_eq!(
        spun, 0,
        "a member must not be able to advance the rotation at will"
    );
}

#[test]
fn an_empty_payout_does_not_advance_the_cycle() {
    // The narrower half of the same defect: whatever the authorisation rule
    // ends up being, paying out nothing must not consume a cycle. Otherwise
    // the rotation is a counter anyone who can pay a fee may increment.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = chama(&mut store, &exec);

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(1, 1, vec![Message::GroupPayout { group }])],
    );
    assert_eq!(out.succeeded(), 0, "an empty pot is nothing to pay out");
}

#[test]
fn creating_a_group_cannot_erase_an_account_that_already_exists() {
    // A group's address is derived from `(creator, nonce)`, so anyone can
    // compute it before the group exists and send money to it. If `CreateGroup`
    // overwrites whatever account record is there, it resets `last_txn` — and
    // the provable-history chain of ADR-0015 is broken at that account, with
    // every earlier payment made unreachable.
    let mut store = funded();
    let exec = Executor::new(chain());

    let group = Address::derived(
        Domain::GroupAddress,
        &[addr(1).as_bytes().as_slice(), &0u64.to_le_bytes()].concat(),
    );

    // Someone pays the future group address first.
    let paid = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            2,
            0,
            vec![Message::Transfer {
                to: group,
                denom: kes(),
                amount: Amount::from_afri(5),
                reference: None,
            }],
        )],
    );
    assert_eq!(paid.succeeded(), 1, "{:?}", paid.outcomes[0].result);

    let before = afrolink_state::KeyValueStore::get_decoded::<afrolink_types::Account>(
        &store,
        &afrolink_state::StoreKey::account(&group),
    )
    .unwrap()
    .expect("the payment created a record");
    assert!(before.last_txn.is_some(), "with a history pointer");

    // Now account 1 creates its group at that very address.
    let create = Message::CreateGroup {
        name: "Chama".to_owned(),
        members: vec![
            FoundingMember::new(addr(1), Role::Treasurer),
            FoundingMember::new(addr(2), Role::Member),
        ],
        contribution: Contribution {
            amount: Amount::from_afri(1_000),
            denom: kes(),
            period_blocks: 604_800,
        },
        policy: PayoutPolicy::Accumulate(ShareRules {
            required_guarantors: 1,
            ..ShareRules::vicoba(Amount::ZERO)
        }),
        quorum: Quorum::TWO_THIRDS,
    };
    exec.execute_block(&mut store, ctx(2), &[tx(1, 0, vec![create])]);

    let after = afrolink_state::KeyValueStore::get_decoded::<afrolink_types::Account>(
        &store,
        &afrolink_state::StoreKey::account(&group),
    )
    .unwrap()
    .expect("still a record");
    assert!(
        after.last_txn.is_some(),
        "the history pointer must survive: erasing it orphans every payment \
         made to this address before the group existed"
    );
}

#[test]
fn one_fee_cannot_mint_account_records_for_a_crowd_of_strangers() {
    // ADR-0015 states the property plainly: "a spammer cannot mint state
    // entries for addresses it merely names." `CreateGroup` names its members,
    // and every member is filed in `touched_addresses` — so if the member list
    // is unbounded, one fee buys unbounded state.
    let mut store = funded();
    let exec = Executor::new(chain());

    let members: Vec<FoundingMember> =
        std::iter::once(FoundingMember::new(addr(1), Role::Treasurer))
            .chain((0..600u16).map(|i| {
                let seed = [(i % 251 + 4) as u8, (i / 251) as u8, 0xAB];
                let mut bytes = [0u8; 32];
                bytes[..3].copy_from_slice(&seed);
                FoundingMember::new(
                    Address::from_public_key(&SecretKey::from_bytes(&bytes).public_key()),
                    Role::Member,
                )
            }))
            .collect();

    let create = Message::CreateGroup {
        name: "Crowd".to_owned(),
        members,
        contribution: Contribution {
            amount: Amount::from_afri(1),
            denom: kes(),
            period_blocks: 1,
        },
        policy: PayoutPolicy::Accumulate(ShareRules {
            required_guarantors: 1,
            ..ShareRules::vicoba(Amount::ZERO)
        }),
        quorum: Quorum::TWO_THIRDS,
    };

    let out = exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![create])]);
    assert_eq!(
        out.succeeded(),
        0,
        "a group larger than any real savings group must be refused"
    );
}

// ---------------------------------------------------------------------------
// Fees — the only thing that makes an attack cost anything
// ---------------------------------------------------------------------------

#[test]
fn a_transaction_offering_no_fee_is_not_executed_for_free() {
    // The fee is the entire cost of making a validator work, and it is the only
    // punishment a failed transaction carries. At zero, failure is free and a
    // single account can make the whole network re-execute forever.
    let mut store = funded();
    let exec = Executor::new(chain());

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[fee_tx(
            1,
            0,
            Fee::new(Amount::ZERO, kes()),
            vec![Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
        )],
    );

    assert_eq!(out.succeeded(), 0, "a free transaction must not apply");
}

#[test]
fn a_fee_cannot_be_paid_in_something_nobody_agreed_to_accept() {
    // The design says "any *governance-whitelisted* stablecoin". The registry of
    // issuers is that whitelist, and it is populated only by genesis.
    //
    // This is defence in depth rather than a live hole: an attacker cannot get
    // units of a denom with no issuer, because minting needs one. It is the
    // check that keeps the claim true once issuers can be registered by
    // transaction, which the roadmap intends.
    //
    // The balance is written directly precisely because no transaction could
    // produce it — the point is that even *given* the tokens, they buy nothing.
    let mut store = funded();
    let junk = Denom::sovereign("zz", "zzz").unwrap();
    afrolink_state::KeyValueStore::set_encoded(
        &mut store,
        &afrolink_state::StoreKey::balance(&addr(1), &junk),
        &Amount::from_afri(1_000_000),
    );
    let exec = Executor::new(chain());

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[fee_tx(
            1,
            0,
            Fee::new(Amount::from_units(1_000), junk),
            vec![Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
        )],
    );

    assert_eq!(
        out.succeeded(),
        0,
        "a fee in an unaccepted denomination must not buy execution"
    );
}

#[test]
fn naming_the_fee_collector_as_the_payer_does_not_buy_a_free_transaction() {
    // The fee collector holds every fee ever paid. A self-transfer is a no-op
    // that still reports success, so naming the collector as fee payer would
    // charge nobody and execute anyway.
    let mut store = funded();
    let exec = Executor::new(chain());

    // Put something in the collector first, so a balance check would pass.
    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            1,
            0,
            vec![Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
        )],
    );
    let collected = balance(&mut store, fee_collector_address());
    assert!(!collected.is_zero(), "the collector holds fees");

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[fee_tx(
            1,
            1,
            Fee::sponsored_by(Amount::from_units(1_000), kes(), fee_collector_address()),
            vec![Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
        )],
    );

    assert_eq!(out.succeeded(), 0, "the fee pool must not fund strangers");
    assert_eq!(
        balance(&mut store, fee_collector_address()),
        collected,
        "and must not have lost a unit"
    );
}

// ---------------------------------------------------------------------------
// Conservation — the property everything else exists to protect
// ---------------------------------------------------------------------------

#[test]
fn no_sequence_of_transactions_changes_the_total_supply() {
    // Laundering, in the sense that matters to a ledger, is value appearing
    // where none was destroyed. Whatever else a transaction does, the sum of
    // every balance must still equal the recorded supply.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = chama(&mut store, &exec);

    let holders = [
        addr(1),
        addr(2),
        addr(3),
        addr(4),
        group,
        fee_collector_address(),
    ];
    let supply_before = Bank::new(&mut store).view().total_supply(&kes()).unwrap();

    // A deliberately messy sequence: contributions, payouts, transfers,
    // overspends, self-payments, and payments to accounts that do not exist.
    let mut nonces = [0u64; 5];
    for (height, round) in (2u64..8).zip(0..6u64) {
        let mut batch = Vec::new();
        for who in 1..=3u8 {
            let n = &mut nonces[who as usize];
            batch.push(tx(
                who,
                *n,
                vec![Message::ContributeToGroup {
                    group,
                    amount: Amount::from_afri(1_000),
                }],
            ));
            *n += 1;
        }
        batch.push(tx(4, nonces[4], vec![Message::GroupPayout { group }]));
        nonces[4] += 1;
        batch.push(tx(
            1,
            nonces[1],
            vec![Message::Transfer {
                to: addr(1),
                denom: kes(),
                amount: Amount::from_afri(3),
                reference: None,
            }],
        ));
        nonces[1] += 1;
        batch.push(tx(
            2,
            nonces[2],
            vec![Message::Transfer {
                to: addr(200 - round as u8),
                denom: kes(),
                amount: Amount::from_afri(999_999_999),
                reference: None,
            }],
        ));
        nonces[2] += 1;

        exec.execute_block(&mut store, ctx(height), &batch);
    }

    let mut total = Amount::ZERO;
    for holder in holders {
        total = total.checked_add(balance(&mut store, holder)).unwrap();
    }
    // Anything that left the six named holders went to an address the sequence
    // paid; sum those too by asking the bank for the recorded supply.
    let supply_after = Bank::new(&mut store).view().total_supply(&kes()).unwrap();

    assert_eq!(
        supply_after, supply_before,
        "no transaction may change the recorded supply of a sovereign asset"
    );
    assert!(
        total <= supply_after,
        "the accounts we can see must never hold more than exists: {total:?} > {supply_after:?}"
    );
}

// ---------------------------------------------------------------------------
// The SIM-swap defence, exercised the way a chain would have to run it
// ---------------------------------------------------------------------------

/// Register an attestor directly, to keep this fixture short.
///
/// It used to be the only way: nothing populated the registry, so on a real
/// chain the whole contact-binding feature was inert. Genesis licenses attestors
/// now ([ADR-0021](../../../docs/adr/0021-licensing-attestors.md)), and
/// `tests/contacts.rs` drives the lifecycle that way. These tests keep the
/// direct write because they are about the *attack*, not the licensing.
fn licensed_attestor(store: &mut MemoryStore, who: Address) {
    use afrolink_alias::{Attestor, Bindings};
    Bindings::new(store).register_attestor(
        &who,
        &Attestor {
            country: CountryCode::new("ke").expect("valid country"),
            name: "MNO".to_owned(),
            active: true,
        },
    );
}

fn commitment(seed: u8) -> afrolink_alias::ContactCommitment {
    afrolink_alias::ContactCommitment::new(
        afrolink_alias::ContactKind::Phone,
        "+254700000000",
        &[seed; 32],
    )
    .unwrap()
}

#[test]
fn a_stolen_sim_cannot_move_a_binding_the_owner_refuses() {
    // The claim ADR-0008 makes: possession of the number is not possession of
    // the account. An attacker who swaps the SIM persuades the operator to
    // request a rebind; the real owner, who still holds the key, refuses it.
    let mut store = funded();
    let exec = Executor::new(chain());
    licensed_attestor(&mut store, addr(90));
    let phone = commitment(7);

    let bind = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            90,
            0,
            vec![Message::AttestContact {
                commitment: phone,
                address: addr(1),
            }],
        )],
    );
    assert_eq!(bind.succeeded(), 1, "{:?}", bind.outcomes[0].result);

    // The attacker holds the SIM and gets the operator to ask for a move.
    let asked = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            90,
            1,
            vec![Message::RequestRebind {
                commitment: phone,
                new_address: addr(66),
            }],
        )],
    );
    assert_eq!(asked.succeeded(), 1, "{:?}", asked.outcomes[0].result);

    // The real owner refuses, with the key the attacker does not have.
    let vetoed = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(1, 0, vec![Message::VetoRebind { commitment: phone }])],
    );
    assert_eq!(vetoed.succeeded(), 1, "{:?}", vetoed.outcomes[0].result);

    // Long after the delay would have elapsed, the move still cannot be pushed
    // through: there is nothing pending.
    let forced = exec.execute_block(
        &mut store,
        ctx(2_000_000),
        &[tx(66, 0, vec![Message::ApplyRebind { commitment: phone }])],
    );
    assert_eq!(forced.succeeded(), 0, "a vetoed rebind must stay dead");
}

#[test]
fn a_genuine_recovery_completes_once_the_delay_has_run() {
    // The other half, and the one that was unreachable: nothing could apply a
    // matured rebinding, so a user who really had lost their key waited
    // forever. An owner who cannot veto is precisely the case this exists for.
    let mut store = funded();
    let exec = Executor::new(chain());
    licensed_attestor(&mut store, addr(90));
    let phone = commitment(8);

    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            90,
            0,
            vec![Message::AttestContact {
                commitment: phone,
                address: addr(1),
            }],
        )],
    );
    let asked = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            90,
            1,
            vec![Message::RequestRebind {
                commitment: phone,
                new_address: addr(4),
            }],
        )],
    );
    assert_eq!(asked.succeeded(), 1, "{:?}", asked.outcomes[0].result);

    // Too early is refused.
    let early = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(4, 0, vec![Message::ApplyRebind { commitment: phone }])],
    );
    assert_eq!(early.succeeded(), 0, "the delay must be respected");

    // After the window, it completes.
    let done = exec.execute_block(
        &mut store,
        ctx(2_000_000),
        &[tx(4, 1, vec![Message::ApplyRebind { commitment: phone }])],
    );
    assert_eq!(done.succeeded(), 1, "{:?}", done.outcomes[0].result);

    let record = afrolink_alias::Bindings::new(&mut store)
        .resolve(&phone)
        .unwrap()
        .expect("still bound");
    assert_eq!(record.address, addr(4), "recovery must actually move it");
}
