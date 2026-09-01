//! Sovereign issuance, driven the way a central bank would drive it.
//!
//! Until now no transaction could create money. `Bank::mint` existed, was
//! tested, and was reachable from nothing but genesis — so the total supply of
//! every denomination was fixed forever at block zero, and the chain's stated
//! purpose could not happen. These tests are the other half: the messages that
//! make issuance real, and the limits that make it safe to hand a hot key to
//! somebody.
//!
//! Three keys, deliberately different ([ADR-0020](../../../docs/adr/0020-sovereign-issuance.md)):
//!
//! * the **authority** — cold, a central bank — configures and never issues;
//! * a **minter** — hot, a licensed intermediary — issues up to a finite
//!   allowance and configures nothing;
//! * a **freezer** — compliance — does neither.
//!
//! The test that matters most is
//! [`a_stolen_minter_key_can_only_mint_what_was_left_on_it`]. Everything else
//! here is a rule; that one is the reason the rules are shaped this way.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_bank::{Bank, BankView, Issuer};
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{BlockContext, Executor, fee_collector_address};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
use afrolink_state::{KeyValueStore, MemoryStore, StoreKey};
use afrolink_types::{Account, Fee, Message, Transaction, TxBody};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The central bank: cold key, governs `sov/ke/kes`, cannot mint.
const AUTHORITY: u8 = 100;
/// A licensed intermediary holding the hot minting key.
const MINTER: u8 = 101;
/// The compliance key.
const FREEZER: u8 = 102;
/// Somebody with no role at all.
const STRANGER: u8 = 66;

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

/// Genesis: the issuer registered, the minter authorised for 10,000, and every
/// participant holding enough AFRI-denominated KES to pay fees.
///
/// The fee float is genesis-allocated rather than minted, so a test that counts
/// what issuance created is counting only what issuance created.
fn genesis(minter_allowance: u64) -> MemoryStore {
    let mut store = MemoryStore::new();
    let mut bank = Bank::new(&mut store);
    bank.register_issuer(
        &kes(),
        &Issuer::new(addr(AUTHORITY))
            .with_minter(addr(MINTER), Amount::from_afri(minter_allowance)),
    )
    .unwrap();
    for who in [AUTHORITY, MINTER, FREEZER, STRANGER, 1, 2, 3] {
        bank.genesis_allocate(&addr(who), &kes(), Amount::from_afri(10))
            .unwrap();
    }
    store
}

fn tx(sender: u8, nonce: u64, messages: Vec<Message>) -> Transaction {
    fee_tx(sender, nonce, kes(), messages)
}

fn fee_tx(sender: u8, nonce: u64, fee_denom: Denom, messages: Vec<Message>) -> Transaction {
    TxBody {
        chain_id: chain(),
        sender: addr(sender),
        nonce,
        valid_until: Height(u64::MAX),
        fee: Fee::new(Amount::from_units(1_000), fee_denom),
        messages,
        memo: String::new(),
    }
    .sign(&sk(sender))
}

fn balance(store: &MemoryStore, who: u8) -> Amount {
    BankView::new(store).balance(&addr(who), &kes()).unwrap()
}

fn supply(store: &MemoryStore) -> Amount {
    BankView::new(store).total_supply(&kes()).unwrap()
}

fn issuer(store: &MemoryStore) -> Issuer {
    BankView::new(store)
        .issuer(&kes())
        .unwrap()
        .expect("registered")
}

fn account(store: &MemoryStore, who: u8) -> Option<Account> {
    store
        .get_decoded::<Account>(&StoreKey::account(&addr(who)))
        .unwrap()
}

/// Sum every balance in this closed world, including the fee collector.
fn total_held(store: &MemoryStore) -> u128 {
    [AUTHORITY, MINTER, FREEZER, STRANGER, 1, 2, 3]
        .iter()
        .map(|w| balance(store, *w).units())
        .sum::<u128>()
        + BankView::new(store)
            .balance(&fee_collector_address(), &kes())
            .unwrap()
            .units()
}

// ---------------------------------------------------------------------------
// Issuance works at all
// ---------------------------------------------------------------------------

#[test]
fn a_minter_puts_money_into_circulation_and_the_supply_records_it() {
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());
    let opening = supply(&store);

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            MINTER,
            0,
            vec![Message::Mint {
                denom: kes(),
                to: addr(1),
                amount: Amount::from_afri(500),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "a minter may mint");

    assert_eq!(balance(&store, 1).units(), Amount::from_afri(510).units());
    assert_eq!(
        supply(&store).units() - opening.units(),
        Amount::from_afri(500).units(),
        "supply rose by exactly what was created"
    );
    assert_eq!(
        issuer(&store).allowance_of(&addr(MINTER)),
        Amount::from_afri(9_500),
        "and the minter's allowance fell by the same"
    );
}

#[test]
fn the_recipient_of_new_money_finds_it_in_their_own_history() {
    // A holder must be able to see money arriving without trusting a node to
    // volunteer it. Minting credits an account that did not send the
    // transaction, so if it were not filed the recipient would have a balance
    // change with no event behind it.
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());
    let mint = tx(
        MINTER,
        0,
        vec![Message::Mint {
            denom: kes(),
            to: addr(1),
            amount: Amount::from_afri(500),
        }],
    );
    assert!(
        mint.touched_addresses().contains(&addr(1)),
        "the recipient must be indexed"
    );
    exec.execute_block(&mut store, ctx(1), &[mint]);
    assert!(
        account(&store, 1).expect("record").last_txn.is_some(),
        "and the history pointer must name the block that credited them"
    );
}

// ---------------------------------------------------------------------------
// Who may mint — the highest-severity question in any stablecoin
// ---------------------------------------------------------------------------

#[test]
fn a_stolen_minter_key_can_only_mint_what_was_left_on_it() {
    // The reason the allowance exists, stated as the attack it bounds.
    //
    // A minter's key lives on a machine that signs every day; the authority's
    // does not. Take the hot key and you can mint what remained on it and then
    // nothing — not because anybody noticed, but because the ledger stops you.
    // Without an allowance the same theft mints until a human intervenes, and
    // the peg is gone long before that.
    let mut store = genesis(1_000);
    let exec = Executor::new(chain());
    let thief = MINTER; // the attacker now signs with the minter's key

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            thief,
            0,
            vec![Message::Mint {
                denom: kes(),
                to: addr(STRANGER),
                amount: Amount::from_afri(1_000_000_000),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0, "far past the allowance: refused whole");
    assert_eq!(balance(&store, STRANGER), Amount::from_afri(10));

    // So the attacker takes what they can, which is the point: it is bounded.
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            thief,
            1,
            vec![Message::Mint {
                denom: kes(),
                to: addr(STRANGER),
                amount: Amount::from_afri(1_000),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);

    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            thief,
            2,
            vec![Message::Mint {
                denom: kes(),
                to: addr(STRANGER),
                amount: Amount::from_units(1),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0, "and then the key is worth nothing");
    assert!(issuer(&store).minter(&addr(thief)).is_none());
    assert_eq!(
        balance(&store, STRANGER),
        Amount::from_afri(1_010),
        "the whole theft is the allowance and not a unit more"
    );
}

#[test]
fn one_block_of_small_mints_cannot_add_up_to_more_than_the_allowance() {
    // The bypass a stablecoin audit looks for. A limit checked per message and
    // never written back is a per-transaction cap wearing a total's name, and
    // batching defeats it inside a single block.
    let mut store = genesis(100);
    let exec = Executor::new(chain());

    let batch: Vec<Transaction> = (0..20)
        .map(|i| {
            tx(
                MINTER,
                i,
                vec![Message::Mint {
                    denom: kes(),
                    to: addr(1),
                    amount: Amount::from_afri(10),
                }],
            )
        })
        .collect();
    let out = exec.execute_block(&mut store, ctx(1), &batch);
    assert_eq!(
        out.succeeded(),
        10,
        "ten of twenty fit inside the allowance"
    );
    assert_eq!(
        supply(&store).units(),
        Amount::from_afri(170).units(),
        "70 allocated at genesis plus exactly the 100 that was authorised"
    );
}

#[test]
fn the_authority_cannot_mint_and_a_stranger_can_do_nothing_at_all() {
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());
    let before = supply(&store);

    let attempts = vec![
        // The cold key configures; it does not issue. A key that could do both
        // would be the most valuable target on the network.
        tx(
            AUTHORITY,
            0,
            vec![Message::Mint {
                denom: kes(),
                to: addr(AUTHORITY),
                amount: Amount::from_afri(1),
            }],
        ),
        tx(
            STRANGER,
            0,
            vec![Message::Mint {
                denom: kes(),
                to: addr(STRANGER),
                amount: Amount::from_afri(1),
            }],
        ),
        tx(
            STRANGER,
            1,
            vec![Message::SetMinterAllowance {
                denom: kes(),
                minter: addr(STRANGER),
                allowance: Amount::from_afri(1_000_000),
            }],
        ),
        tx(
            STRANGER,
            2,
            vec![Message::SetSupplyCap {
                denom: kes(),
                cap: Amount::MAX,
            }],
        ),
        tx(
            STRANGER,
            3,
            vec![Message::SetFreezer {
                denom: kes(),
                freezer: Some(addr(STRANGER)),
            }],
        ),
        tx(
            STRANGER,
            4,
            vec![Message::SetFrozen {
                denom: kes(),
                account: addr(1),
                frozen: true,
            }],
        ),
    ];
    let out = exec.execute_block(&mut store, ctx(1), &attempts);
    assert_eq!(out.succeeded(), 0, "every one of them must be refused");
    assert_eq!(supply(&store), before, "and none of it created a shilling");
    assert!(!BankView::new(&store).is_frozen(&addr(1), &kes()));
}

#[test]
fn the_authority_granting_itself_an_allowance_is_an_event_on_the_chain() {
    // Not a loophole, and worth stating plainly: a central bank *may* issue
    // directly. What the split buys is that it cannot do so silently — the
    // grant is a signed, ordered, provable transaction, and the difference
    // between "the authority minted" and "the authority authorised itself and
    // then minted" is the difference between an unexplained supply change and
    // an auditable one.
    let mut store = genesis(0);
    let exec = Executor::new(chain());

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            0,
            vec![Message::SetMinterAllowance {
                denom: kes(),
                minter: addr(AUTHORITY),
                allowance: Amount::from_afri(50),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            AUTHORITY,
            1,
            vec![Message::Mint {
                denom: kes(),
                to: addr(1),
                amount: Amount::from_afri(50),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert!(issuer(&store).minter(&addr(AUTHORITY)).is_none());
}

#[test]
fn revoking_a_minter_takes_effect_immediately() {
    // The response to a suspected compromise of one key, without touching
    // anybody else's ability to issue or anybody's ability to spend.
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[
            tx(
                AUTHORITY,
                0,
                vec![Message::SetMinterAllowance {
                    denom: kes(),
                    minter: addr(MINTER),
                    allowance: Amount::ZERO,
                }],
            ),
            tx(
                MINTER,
                0,
                vec![Message::Mint {
                    denom: kes(),
                    to: addr(1),
                    amount: Amount::from_afri(1),
                }],
            ),
        ],
    );
    assert_eq!(
        out.succeeded(),
        1,
        "the revocation applies; the mint behind it does not"
    );
    assert!(issuer(&store).minter(&addr(MINTER)).is_none());
}

// ---------------------------------------------------------------------------
// Taking money out of circulation
// ---------------------------------------------------------------------------

#[test]
fn redemption_takes_a_holders_signature_and_no_message_burns_their_balance() {
    // The asymmetry that makes a balance mean something. `Burn` carries no
    // `from`, so there is no way to spell "destroy that account's money" — a
    // holder redeems by signing a transfer to the minter, and the minter burns
    // what it then owns. The consent is on the chain as a signature.
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());

    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            MINTER,
            0,
            vec![Message::Mint {
                denom: kes(),
                to: addr(1),
                amount: Amount::from_afri(500),
            }],
        )],
    );
    let peak = supply(&store);

    // The minter cannot reach into the holder's account, so it must be handed
    // the money first.
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            1,
            0,
            vec![Message::Transfer {
                to: addr(MINTER),
                denom: kes(),
                amount: Amount::from_afri(500),
                reference: None,
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);

    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            MINTER,
            1,
            vec![Message::Burn {
                denom: kes(),
                amount: Amount::from_afri(500),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert_eq!(
        peak.units() - supply(&store).units(),
        Amount::from_afri(500).units(),
        "the money is gone from the supply, not moved somewhere"
    );
}

#[test]
fn a_minter_cannot_burn_more_than_it_holds_and_a_stranger_cannot_burn_at_all() {
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());
    let before = supply(&store);

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[
            tx(
                MINTER,
                0,
                vec![Message::Burn {
                    denom: kes(),
                    amount: Amount::from_afri(1_000_000),
                }],
            ),
            tx(
                STRANGER,
                0,
                vec![Message::Burn {
                    denom: kes(),
                    amount: Amount::from_afri(1),
                }],
            ),
        ],
    );
    assert_eq!(out.succeeded(), 0);
    assert_eq!(supply(&store), before);
}

#[test]
fn burning_does_not_hand_the_allowance_back() {
    // Otherwise a mint-and-burn cycle turns a ceiling on the damage a stolen key
    // can do into a rate limit on *net* issuance, which is a different and much
    // weaker promise.
    let mut store = genesis(100);
    let exec = Executor::new(chain());

    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            MINTER,
            0,
            vec![Message::Mint {
                denom: kes(),
                to: addr(MINTER),
                amount: Amount::from_afri(100),
            }],
        )],
    );
    exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            MINTER,
            1,
            vec![Message::Burn {
                denom: kes(),
                amount: Amount::from_afri(100),
            }],
        )],
    );
    assert_eq!(
        issuer(&store).allowance_of(&addr(MINTER)),
        Amount::ZERO,
        "the allowance is spent, and a burn does not refill it"
    );
}

// ---------------------------------------------------------------------------
// Binding the issuer: the cap ratchet, and the circuit breaker
// ---------------------------------------------------------------------------

#[test]
fn a_supply_cap_can_be_tightened_and_never_loosened() {
    // The ratchet. A cap holders can verify from the chain is worth something
    // only because the issuer cannot take it back — the same reasoning Stellar
    // uses to let an issuer clear a clawback flag but never set one, and XRPL
    // to refuse enabling clawback once any of an asset has been issued.
    let mut store = genesis(1_000_000);
    let exec = Executor::new(chain());

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            0,
            vec![Message::SetSupplyCap {
                denom: kes(),
                cap: Amount::from_afri(1_000),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "binding yourself is always allowed");

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[
            tx(
                AUTHORITY,
                1,
                vec![Message::SetSupplyCap {
                    denom: kes(),
                    cap: Amount::from_afri(1_001),
                }],
            ),
            tx(
                AUTHORITY,
                2,
                vec![Message::SetSupplyCap {
                    denom: kes(),
                    cap: Amount::MAX,
                }],
            ),
        ],
    );
    assert_eq!(out.succeeded(), 0, "not by one unit, and not by any amount");
    assert_eq!(issuer(&store).max_supply, Some(Amount::from_afri(1_000)));

    // And the cap actually binds the minter.
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            MINTER,
            0,
            vec![Message::Mint {
                denom: kes(),
                to: addr(1),
                amount: Amount::from_afri(2_000),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0);
    assert!(supply(&store) <= Amount::from_afri(1_000));
}

#[test]
fn a_cap_of_zero_winds_the_currency_down_without_stranding_anybody() {
    // No more may be created; everything already in circulation keeps working.
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());

    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            0,
            vec![Message::SetSupplyCap {
                denom: kes(),
                cap: Amount::ZERO,
            }],
        )],
    );
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[
            tx(
                MINTER,
                0,
                vec![Message::Mint {
                    denom: kes(),
                    to: addr(1),
                    amount: Amount::from_units(1),
                }],
            ),
            tx(
                1,
                0,
                vec![Message::Transfer {
                    to: addr(2),
                    denom: kes(),
                    amount: Amount::from_afri(5),
                    reference: None,
                }],
            ),
        ],
    );
    assert_eq!(out.succeeded(), 1, "the transfer, not the mint");
}

#[test]
fn pausing_stops_new_money_without_stopping_payments() {
    // The response to a suspected compromise must not be a payments outage for
    // everyone holding the currency. Pausing and freezing are different tools
    // and this is the difference.
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());

    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            0,
            vec![Message::SetIssuerPaused {
                denom: kes(),
                paused: true,
            }],
        )],
    );
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[
            tx(
                MINTER,
                0,
                vec![Message::Mint {
                    denom: kes(),
                    to: addr(1),
                    amount: Amount::from_afri(1),
                }],
            ),
            tx(
                1,
                0,
                vec![Message::Transfer {
                    to: addr(2),
                    denom: kes(),
                    amount: Amount::from_afri(1),
                    reference: None,
                }],
            ),
        ],
    );
    assert_eq!(
        out.succeeded(),
        1,
        "payments continue while issuance is held"
    );
    assert_eq!(
        issuer(&store).allowance_of(&addr(MINTER)),
        Amount::from_afri(10_000),
        "and a refused mint does not spend the allowance"
    );

    exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            AUTHORITY,
            1,
            vec![Message::SetIssuerPaused {
                denom: kes(),
                paused: false,
            }],
        )],
    );
    let out = exec.execute_block(
        &mut store,
        ctx(4),
        &[tx(
            MINTER,
            1,
            vec![Message::Mint {
                denom: kes(),
                to: addr(1),
                amount: Amount::from_afri(1),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "and it resumes");
}

// ---------------------------------------------------------------------------
// Freezing: the compliance power, and its limits
// ---------------------------------------------------------------------------

#[test]
fn a_freeze_reaches_one_denomination_and_the_holder_can_see_who_did_it() {
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());
    Bank::new(&mut store)
        .emit_native(&addr(1), Amount::from_afri(100))
        .unwrap();

    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            0,
            vec![Message::SetFreezer {
                denom: kes(),
                freezer: Some(addr(FREEZER)),
            }],
        )],
    );

    // Once a freezer is named the authority no longer holds the power. Separate
    // keys, because freezing is a compliance decision made under a court order
    // by different people on a different timescale than issuance.
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            AUTHORITY,
            1,
            vec![Message::SetFrozen {
                denom: kes(),
                account: addr(1),
                frozen: true,
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0);

    let freeze = tx(
        FREEZER,
        0,
        vec![Message::SetFrozen {
            denom: kes(),
            account: addr(1),
            frozen: true,
        }],
    );
    assert!(
        freeze.touched_addresses().contains(&addr(1)),
        "being frozen is the most consequential thing that can happen to a \
         holder and they did not send it — it must reach their history"
    );
    let out = exec.execute_block(&mut store, ctx(3), &[freeze]);
    assert_eq!(out.succeeded(), 1);
    assert!(BankView::new(&store).is_frozen(&addr(1), &kes()));

    // The frozen asset does not move.
    let out = exec.execute_block(
        &mut store,
        ctx(4),
        &[tx(
            1,
            0,
            vec![Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_units(1),
                reference: None,
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0);

    // Nor does anything else, *while the fee is offered in the frozen asset* —
    // paying a fee is itself a movement of that asset, so a freeze on the
    // currency an account uses for fees stops it acting at all. Worth asserting
    // rather than discovering: it is the difference between "your shillings are
    // held" and "your account is dead", and an issuer should know which one it
    // is doing.
    let out = exec.execute_block(
        &mut store,
        ctx(5),
        &[tx(
            1,
            0,
            vec![Message::Transfer {
                to: addr(2),
                denom: Denom::native(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0, "the KES fee cannot be paid");

    // And the way out, which is why fee abstraction matters here: pay in an
    // asset this issuer has no power over, and AFRI moves. An issuer's reach
    // ends at its own denomination.
    let out = exec.execute_block(
        &mut store,
        ctx(6),
        &[fee_tx(
            1,
            0,
            Denom::native(),
            vec![Message::Transfer {
                to: addr(2),
                denom: Denom::native(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
        )],
    );
    assert_eq!(
        out.succeeded(),
        1,
        "a KES freeze must never be able to immobilise AFRI"
    );
}

#[test]
fn a_frozen_account_cannot_be_credited_by_a_mint_either() {
    // A freeze must mean one thing. If minting could still credit a frozen
    // account, an issuer could inflate a balance it has declared immobile —
    // and the holder would have no way to spend it or to object.
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());
    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            0,
            vec![Message::SetFrozen {
                denom: kes(),
                account: addr(1),
                frozen: true,
            }],
        )],
    );
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            MINTER,
            0,
            vec![Message::Mint {
                denom: kes(),
                to: addr(1),
                amount: Amount::from_afri(1),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0);
}

#[test]
fn a_freeze_can_be_lifted() {
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());
    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            0,
            vec![Message::SetFrozen {
                denom: kes(),
                account: addr(1),
                frozen: true,
            }],
        )],
    );
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            AUTHORITY,
            1,
            vec![Message::SetFrozen {
                denom: kes(),
                account: addr(1),
                frozen: false,
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert!(!BankView::new(&store).is_frozen(&addr(1), &kes()));
}

// ---------------------------------------------------------------------------
// The native coin, and conservation
// ---------------------------------------------------------------------------

#[test]
fn no_issuer_can_reach_the_native_coin() {
    // AFRI is created by protocol emission alone. An issuer able to mint it
    // could buy validators with money it invented.
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());
    let before = BankView::new(&store)
        .total_supply(&Denom::native())
        .unwrap();

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[
            tx(
                MINTER,
                0,
                vec![Message::Mint {
                    denom: Denom::native(),
                    to: addr(MINTER),
                    amount: Amount::from_afri(1_000_000),
                }],
            ),
            tx(
                AUTHORITY,
                0,
                vec![Message::SetMinterAllowance {
                    denom: Denom::native(),
                    minter: addr(AUTHORITY),
                    allowance: Amount::MAX,
                }],
            ),
        ],
    );
    assert_eq!(out.succeeded(), 0);
    assert_eq!(
        BankView::new(&store)
            .total_supply(&Denom::native())
            .unwrap(),
        before
    );
}

#[test]
fn every_balance_still_sums_to_the_supply_after_a_full_issuance_lifecycle() {
    // The invariant the whole ledger rests on, across the only two operations
    // that are *allowed* to change supply. If issuance can break it, nothing
    // else about the chain matters.
    let mut store = genesis(10_000);
    let exec = Executor::new(chain());

    let blocks: Vec<(u64, Vec<Transaction>)> = vec![
        (
            1,
            vec![tx(
                MINTER,
                0,
                vec![Message::Mint {
                    denom: kes(),
                    to: addr(1),
                    amount: Amount::from_afri(400),
                }],
            )],
        ),
        (
            2,
            vec![
                tx(
                    MINTER,
                    1,
                    vec![Message::Mint {
                        denom: kes(),
                        to: addr(2),
                        amount: Amount::from_afri(600),
                    }],
                ),
                tx(
                    1,
                    0,
                    vec![Message::Transfer {
                        to: addr(3),
                        denom: kes(),
                        amount: Amount::from_afri(150),
                        reference: None,
                    }],
                ),
            ],
        ),
        (
            3,
            vec![tx(
                2,
                0,
                vec![Message::Transfer {
                    to: addr(MINTER),
                    denom: kes(),
                    amount: Amount::from_afri(600),
                    reference: None,
                }],
            )],
        ),
        (
            4,
            vec![tx(
                MINTER,
                2,
                vec![Message::Burn {
                    denom: kes(),
                    amount: Amount::from_afri(600),
                }],
            )],
        ),
    ];

    for (height, transactions) in blocks {
        exec.execute_block(&mut store, ctx(height), &transactions);
        assert_eq!(
            total_held(&store),
            supply(&store).units(),
            "after block {height}: balances must sum to the recorded supply"
        );
    }
    assert_eq!(
        supply(&store).units(),
        Amount::from_afri(470).units(),
        "70 at genesis, 1,000 minted, 600 burned"
    );
}
