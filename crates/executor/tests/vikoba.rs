//! A *vikoba* run end to end: shares bought, a loan made and repaid, a social
//! grant, and a round shared out.
//!
//! Tanzanians call three different things by three different names, and only one
//! of them is a rotation. *Upatu* (or *mchezo*) rotates a fixed pot. **Vikoba**
//! — Village Community Banking — accumulates savings as shares, lends them to
//! members at a service charge, and divides everything at the end of the round
//! in proportion to what each member saved. The second is not a variation on the
//! first: a rotation redistributes, a vikoba *earns*.
//!
//! These tests drive the whole arrangement through ordinary signed transactions,
//! because the arithmetic that matters is the arithmetic a member's money
//! actually passes through. The numbers are the ones the field research
//! describes: 1–5 shares a cycle, a 10% service charge, one-third cover, two
//! guarantors, a 10% late fine.
//!
//! See [ADR-0019](../../../docs/adr/0019-vikoba-accumulating-savings.md).

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
use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
use afrolink_state::{KeyValueStore, MemoryStore, StoreKey};
use afrolink_types::group::{
    Contribution, FoundingMember, GroupAccount, PayoutPolicy, ProposalKind, Quorum, Role,
    ShareRules,
};
use afrolink_types::{Account, Fee, Message, Transaction, TxBody};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const SHARE: u64 = 1_000;
const PERIOD: u64 = 100;

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

/// Members 1..=4 and an outsider (9), each holding 100,000 KES.
fn funded() -> MemoryStore {
    let mut store = MemoryStore::new();
    let mut bank = Bank::new(&mut store);
    bank.register_issuer(&kes(), &Issuer::new(addr(100)))
        .unwrap();
    for i in [1u8, 2, 3, 4, 9] {
        bank.mint(&addr(100), &addr(i), &kes(), Amount::from_afri(100_000))
            .unwrap();
    }
    store
}

fn tx(sender: u8, nonce: u64, messages: Vec<Message>) -> Transaction {
    TxBody {
        chain_id: chain(),
        sender: addr(sender),
        nonce,
        valid_until: Height(u64::MAX),
        fee: Fee::new(Amount::from_units(1_000), kes()),
        messages,
        memo: String::new(),
    }
    .sign(&sk(sender))
}

fn balance(store: &mut MemoryStore, who: Address) -> Amount {
    Bank::new(store).view().balance(&who, &kes()).unwrap()
}

fn group_record(store: &MemoryStore, group: &Address) -> GroupAccount {
    store
        .get_decoded::<Account>(&StoreKey::account(group))
        .unwrap()
        .expect("group account exists")
        .as_group()
        .expect("the record is a group")
        .clone()
}

/// The VICOBA defaults from the research, with the round length as a parameter
/// so a test does not have to drive twelve cycles to reach a share-out.
fn rules(cycles_per_round: u64) -> ShareRules {
    ShareRules {
        min_shares: 1,
        max_shares: 5,
        cycles_per_round,
        service_charge_bps: 1_000, // 10% of principal, flat
        cover_bps: 3_334,          // the borrower's savings cover a third
        loan_term_cycles: 1,
        late_fine_bps: 1_000, // 10% of what is outstanding
        required_guarantors: 2,
        social_contribution: Amount::from_afri(100),
    }
}

/// A four-member vikoba, created by account 1 at nonce 0.
fn vikoba(store: &mut MemoryStore, exec: &Executor, cycles_per_round: u64) -> Address {
    let members = vec![
        FoundingMember::new(addr(1), Role::Treasurer),
        FoundingMember::new(addr(2), Role::Member),
        FoundingMember::new(addr(3), Role::Member),
        FoundingMember::new(addr(4), Role::Member),
    ];
    let create = Message::CreateGroup {
        name: "Vikoba vya Mama Lishe".to_owned(),
        members,
        contribution: Contribution {
            amount: Amount::from_afri(SHARE),
            denom: kes(),
            period_blocks: PERIOD,
        },
        policy: PayoutPolicy::Accumulate(rules(cycles_per_round)),
        quorum: Quorum::TWO_THIRDS,
    };
    let address = Address::derived(
        Domain::GroupAddress,
        &[addr(1).as_bytes().as_slice(), &0u64.to_le_bytes()].concat(),
    );
    let out = exec.execute_block(store, ctx(1), &[tx(1, 0, vec![create])]);
    assert_eq!(out.succeeded(), 1, "the group must form");
    address
}

/// Every member buys `shares` in the cycle now open.
fn everyone_buys(
    store: &mut MemoryStore,
    exec: &Executor,
    group: Address,
    height: u64,
    nonces: &mut [u64; 5],
    shares: u32,
) {
    let transactions: Vec<Transaction> = (1u8..=4)
        .map(|who| {
            let t = tx(
                who,
                nonces[who as usize],
                vec![Message::BuyShares { group, shares }],
            );
            nonces[who as usize] += 1;
            t
        })
        .collect();
    let out = exec.execute_block(store, ctx(height), &transactions);
    assert_eq!(out.succeeded(), 4, "every member's purchase must apply");
}

// ---------------------------------------------------------------------------
// Saving: shares, not a fixed sum
// ---------------------------------------------------------------------------

#[test]
fn a_member_buys_shares_and_the_fund_holds_exactly_what_they_paid() {
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);

    let before = balance(&mut store, addr(2));
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(2, 0, vec![Message::BuyShares { group, shares: 3 }])],
    );
    assert_eq!(out.succeeded(), 1);

    let cost = Amount::from_afri(SHARE * 3);
    assert_eq!(
        balance(&mut store, group),
        cost,
        "the fund holds three shares' worth and not a unit more"
    );
    assert_eq!(
        balance(&mut store, addr(2)).units(),
        before.units() - cost.units() - 1_000,
        "the member paid for three shares plus the fee"
    );
    assert_eq!(
        group_record(&store, &group)
            .member(&addr(2))
            .unwrap()
            .shares,
        3
    );
}

#[test]
fn a_member_cannot_buy_past_the_ceiling_the_group_agreed() {
    // The VSLA rule is one to five shares. The ceiling is not a formality: the
    // share-out divides the fund *in proportion to shares*, so without it the
    // member who can afford the most takes a growing slice of a fund that
    // everybody's repayments built.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(2, 0, vec![Message::BuyShares { group, shares: 6 }])],
    );
    assert_eq!(out.succeeded(), 0, "six shares where five is the ceiling");
    assert!(
        balance(&mut store, group).is_zero(),
        "and the refused purchase must not have taken the money first"
    );
}

#[test]
fn shares_bought_in_instalments_are_capped_across_the_whole_cycle() {
    // The interesting case: two purchases that are each legal and together are
    // not. Checking only the message would let a member buy the ceiling as many
    // times as they can pay a fee.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[
            tx(2, 0, vec![Message::BuyShares { group, shares: 4 }]),
            tx(2, 1, vec![Message::BuyShares { group, shares: 4 }]),
        ],
    );
    assert_eq!(out.succeeded(), 1, "the first fits, the second does not");
    assert_eq!(
        group_record(&store, &group)
            .member(&addr(2))
            .unwrap()
            .shares,
        4
    );
}

#[test]
fn the_share_allowance_refreshes_when_the_cycle_closes() {
    // Otherwise the ceiling would be a lifetime limit rather than a per-meeting
    // one, and saving would stop after a single cycle.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 4);
    let mut nonces = [0u64; 5];
    nonces[1] = 1; // account 1 created the group

    everyone_buys(&mut store, &exec, group, 2, &mut nonces, 5);
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
    );
    assert_eq!(out.succeeded(), 1, "everyone paid, so the cycle may close");
    nonces[1] += 1;

    everyone_buys(&mut store, &exec, group, 4, &mut nonces, 5);
    assert_eq!(
        group_record(&store, &group)
            .member(&addr(3))
            .unwrap()
            .shares,
        10,
        "ten shares over two cycles, five in each"
    );
}

#[test]
fn buying_shares_in_a_rotating_group_is_refused() {
    // The two instruments do not mix. Selling shares in a pot that is about to
    // be handed to one member would give the recipient a claim on money that is
    // already promised to them.
    let mut store = funded();
    let exec = Executor::new(chain());
    let members = vec![
        FoundingMember::new(addr(1), Role::Treasurer),
        FoundingMember::new(addr(2), Role::Member),
    ];
    let order = vec![addr(1), addr(2)];
    let create = Message::CreateGroup {
        name: "Upatu".to_owned(),
        members,
        contribution: Contribution {
            amount: Amount::from_afri(SHARE),
            denom: kes(),
            period_blocks: PERIOD,
        },
        policy: PayoutPolicy::Rotation { order, next: 0 },
        quorum: Quorum::TWO_THIRDS,
    };
    let group = Address::derived(
        Domain::GroupAddress,
        &[addr(1).as_bytes().as_slice(), &0u64.to_le_bytes()].concat(),
    );
    exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![create])]);

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(2, 0, vec![Message::BuyShares { group, shares: 1 }])],
    );
    assert_eq!(out.succeeded(), 0, "a rotation does not sell shares");
}

// ---------------------------------------------------------------------------
// Lending: the thing a vikoba exists to do
// ---------------------------------------------------------------------------

/// Everyone buys five shares, so each member holds 5,000 KES of savings and the
/// fund holds 20,000. Returns the nonce table.
fn funded_round(store: &mut MemoryStore, exec: &Executor, group: Address) -> [u64; 5] {
    let mut nonces = [0u64; 5];
    nonces[1] = 1; // account 1 created the group
    everyone_buys(store, exec, group, 2, &mut nonces, 5);
    nonces
}

#[test]
fn a_loan_reaches_the_borrower_only_when_the_group_has_agreed() {
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let mut nonces = funded_round(&mut store, &exec, group);

    let principal = Amount::from_afri(9_000);
    let propose = Message::ProposeGroupAction {
        group,
        beneficiary: addr(2),
        kind: ProposalKind::Loan {
            principal,
            guarantors: vec![addr(3), addr(4)],
        },
    };
    let out = exec.execute_block(&mut store, ctx(3), &[tx(2, nonces[2], vec![propose])]);
    assert_eq!(out.succeeded(), 1, "a member may put a loan to the group");
    nonces[2] += 1;

    let before = balance(&mut store, addr(2));
    // Four members, a two-thirds quorum: three approvals.
    let out = exec.execute_block(
        &mut store,
        ctx(4),
        &[
            tx(1, nonces[1], vec![Message::ApproveGroupAction { group }]),
            tx(3, nonces[3], vec![Message::ApproveGroupAction { group }]),
        ],
    );
    assert_eq!(out.succeeded(), 2);
    nonces[1] += 1;
    nonces[3] += 1;
    assert_eq!(
        balance(&mut store, addr(2)),
        before,
        "two of four is not the two-thirds the group agreed: no money moves"
    );

    let out = exec.execute_block(
        &mut store,
        ctx(5),
        &[tx(
            4,
            nonces[4],
            vec![Message::ApproveGroupAction { group }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert_eq!(
        balance(&mut store, addr(2)).units(),
        before.units() + principal.units(),
        "the approval that reaches the quorum is the one that advances the loan"
    );

    let record = group_record(&store, &group);
    let loan = record.member(&addr(2)).unwrap().loan.as_ref().unwrap();
    assert_eq!(loan.principal, principal);
    assert_eq!(
        loan.service_charge,
        Amount::from_afri(900),
        "10% of principal, fixed at issue and not compounding"
    );
    assert!(record.pending.is_none(), "the question is settled");
}

#[test]
fn a_member_cannot_borrow_more_than_their_own_savings_cover() {
    // The one-third rule. It is what lets a group lend with no court behind it:
    // the worst case is already in the group's hands.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let nonces = funded_round(&mut store, &exec, group);

    // Account 2 holds 5,000 in shares. A third of 20,000 is 6,668 — more than
    // they have saved.
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(20_000),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0, "the borrower's savings do not cover it");
}

#[test]
fn a_loan_needs_the_guarantors_the_group_agreed_and_they_must_be_other_members() {
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let mut nonces = funded_round(&mut store, &exec, group);

    let attempts = [
        // Too few.
        vec![addr(3)],
        // Standing behind your own loan is not a guarantee.
        vec![addr(2), addr(3)],
        // One member counted twice is one guarantor, not two.
        vec![addr(3), addr(3)],
        // A stranger cannot guarantee a loan they have no stake in.
        vec![addr(3), addr(9)],
    ];
    for guarantors in attempts {
        let out = exec.execute_block(
            &mut store,
            ctx(3),
            &[tx(
                2,
                nonces[2],
                vec![Message::ProposeGroupAction {
                    group,
                    beneficiary: addr(2),
                    kind: ProposalKind::Loan {
                        principal: Amount::from_afri(9_000),
                        guarantors: guarantors.clone(),
                    },
                }],
            )],
        );
        assert_eq!(
            out.succeeded(),
            0,
            "guarantors {guarantors:?} must be refused"
        );
        nonces[2] += 1;
    }
}

#[test]
fn one_member_cannot_reach_a_quorum_by_approving_repeatedly() {
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let mut nonces = funded_round(&mut store, &exec, group);

    exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(9_000),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    nonces[2] += 1;

    let before = balance(&mut store, addr(2));
    let out = exec.execute_block(
        &mut store,
        ctx(4),
        &[
            tx(3, nonces[3], vec![Message::ApproveGroupAction { group }]),
            tx(
                3,
                nonces[3] + 1,
                vec![Message::ApproveGroupAction { group }],
            ),
            tx(
                3,
                nonces[3] + 2,
                vec![Message::ApproveGroupAction { group }],
            ),
        ],
    );
    assert_eq!(out.succeeded(), 1, "only the first approval counts");
    assert_eq!(
        balance(&mut store, addr(2)),
        before,
        "one member must not be able to vote a loan to themselves"
    );
}

#[test]
fn an_outsider_cannot_put_a_question_to_a_group_or_answer_one() {
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let nonces = funded_round(&mut store, &exec, group);

    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            9,
            0,
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(9),
                kind: ProposalKind::SocialGrant {
                    amount: Amount::from_afri(1),
                },
            }],
        )],
    );
    assert_eq!(
        out.succeeded(),
        0,
        "a stranger has no standing in this group"
    );

    exec.execute_block(
        &mut store,
        ctx(4),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(9_000),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    let out = exec.execute_block(
        &mut store,
        ctx(5),
        &[tx(9, 1, vec![Message::ApproveGroupAction { group }])],
    );
    assert_eq!(out.succeeded(), 0, "nor a vote in it");
}

#[test]
fn a_repaid_loan_returns_the_principal_and_the_charge_to_the_fund() {
    // This is how a vikoba *earns*. The service charge is not the group's
    // revenue in some separate account — it lands in the same fund every member
    // owns a share of, which is why the share-out can exceed what was paid in.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let mut nonces = funded_round(&mut store, &exec, group);

    exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(6_000),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    nonces[2] += 1;
    let approvals: Vec<Transaction> = [1u8, 3, 4]
        .iter()
        .map(|&who| {
            let t = tx(
                who,
                nonces[who as usize],
                vec![Message::ApproveGroupAction { group }],
            );
            nonces[who as usize] += 1;
            t
        })
        .collect();
    exec.execute_block(&mut store, ctx(4), &approvals);
    assert_eq!(balance(&mut store, group), Amount::from_afri(14_000));

    // 6,000 principal plus a 10% charge.
    let owed = Amount::from_afri(6_600);
    let out = exec.execute_block(
        &mut store,
        ctx(5),
        &[tx(
            2,
            nonces[2],
            vec![Message::RepayLoan {
                group,
                amount: owed,
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);

    assert_eq!(
        balance(&mut store, group),
        Amount::from_afri(20_600),
        "the fund is 600 richer than the 20,000 that was paid into it"
    );
    let record = group_record(&store, &group);
    let member = record.member(&addr(2)).unwrap();
    assert!(member.loan.is_none(), "the debt is settled");
    assert_eq!(member.loans_repaid, 1);
    assert_eq!(
        member.repayment_bps(),
        Some(10_000),
        "one loan taken, one repaid"
    );
}

#[test]
fn a_borrower_cannot_repay_more_than_they_owe() {
    // Refused rather than truncated. A group is not a place to leave a tip, and
    // quietly keeping the excess would be the group taking money nobody voted
    // to take — out of the account of the member least able to argue.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let mut nonces = funded_round(&mut store, &exec, group);

    exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(6_000),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    nonces[2] += 1;
    for who in [1u8, 3, 4] {
        exec.execute_block(
            &mut store,
            ctx(4),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::ApproveGroupAction { group }],
            )],
        );
        nonces[who as usize] += 1;
    }

    let before = balance(&mut store, addr(2));
    let out = exec.execute_block(
        &mut store,
        ctx(5),
        &[tx(
            2,
            nonces[2],
            vec![Message::RepayLoan {
                group,
                amount: Amount::from_afri(7_000),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0);
    assert_eq!(
        balance(&mut store, addr(2)).units(),
        before.units() - 1_000,
        "nothing but the fee left the borrower's account"
    );
}

#[test]
fn a_late_debt_is_fined_once_and_not_once_every_cycle() {
    // The group agreed a fine on the debt, not a second interest rate that
    // compounds while a member is already struggling to pay the first.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 8);
    let mut nonces = funded_round(&mut store, &exec, group);

    exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(6_000),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    nonces[2] += 1;
    for who in [1u8, 3, 4] {
        exec.execute_block(
            &mut store,
            ctx(4),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::ApproveGroupAction { group }],
            )],
        );
        nonces[who as usize] += 1;
    }

    // Three cycles pass with nothing repaid. The term was one cycle.
    let mut height = 5;
    for _ in 0..3 {
        height += PERIOD + 1;
        let out = exec.execute_block(
            &mut store,
            ctx(height),
            &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
        );
        assert_eq!(
            out.succeeded(),
            1,
            "the agreed period expiring closes a cycle"
        );
        nonces[1] += 1;
    }

    let record = group_record(&store, &group);
    let member = record.member(&addr(2)).unwrap();
    assert_eq!(
        member.fines_owed,
        Amount::from_afri(660),
        "10% of the 6,600 outstanding, levied exactly once across three late cycles"
    );
    assert!(member.loan.as_ref().unwrap().fined);
}

#[test]
fn a_loan_is_refused_when_the_round_would_close_before_it_falls_due() {
    // Found by the property suite in `crates/fuzz`, not by hand, and it is the
    // nastiest kind of defect: nothing fails at the time. The loan is granted,
    // the borrower does everything the group asked, and then the share-out
    // arrives before the term does — so the debt is outstanding, their savings
    // are seized to settle it, and they are recorded as a **defaulter** for a
    // term the group itself granted. That record is the thing a lender reads.
    //
    // Refusing the rules that describe it was not enough: `ShareRules::validate`
    // already forbids a term longer than a round, which is necessary and not
    // sufficient. A term that fits still runs past the share-out if the loan is
    // granted late enough in the round. A real VSLA stops lending in the weeks
    // before a share-out for exactly this reason.
    let mut store = funded();
    let exec = Executor::new(chain());
    // Two cycles to a round, a one-cycle loan term: a loan is fine in cycle 0,
    // fine in cycle 1, and out of time from cycle 2.
    let group = vikoba(&mut store, &exec, 2);
    let mut nonces = funded_round(&mut store, &exec, group);

    let ask = || Message::ProposeGroupAction {
        group,
        beneficiary: addr(2),
        kind: ProposalKind::Loan {
            principal: Amount::from_afri(6_000),
            guarantors: vec![addr(3), addr(4)],
        },
    };

    let out = exec.execute_block(&mut store, ctx(3), &[tx(2, nonces[2], vec![ask()])]);
    assert_eq!(out.succeeded(), 1, "in the first cycle there is time");
    nonces[2] += 1;

    // Let the round run out without the proposal being agreed.
    let mut height = 4;
    for _ in 0..2 {
        height += PERIOD + 1;
        exec.execute_block(
            &mut store,
            ctx(height),
            &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
        );
        nonces[1] += 1;
    }
    assert!(group_record(&store, &group).round_complete());

    let out = exec.execute_block(
        &mut store,
        ctx(height + 1),
        &[tx(2, nonces[2], vec![ask()])],
    );
    assert_eq!(
        out.succeeded(),
        0,
        "the round closes before the term would end: the group must not lend"
    );
    nonces[2] += 1;

    // And once the round is shared out, lending is possible again.
    exec.execute_block(
        &mut store,
        ctx(height + 2),
        &[tx(1, nonces[1], vec![Message::ShareOut { group }])],
    );
    nonces[1] += 1;
    everyone_buys(&mut store, &exec, group, height + 3, &mut nonces, 5);
    let out = exec.execute_block(
        &mut store,
        ctx(height + 4),
        &[tx(2, nonces[2], vec![ask()])],
    );
    assert_eq!(out.succeeded(), 1, "a fresh round has room again");
}

// ---------------------------------------------------------------------------
// The social fund: insurance, not saving
// ---------------------------------------------------------------------------

#[test]
fn the_social_fund_is_never_lent_and_never_shared_out() {
    // The whole reason it is tracked separately. A group that lends its funeral
    // money has no funeral money, and the member who finds out is the one
    // burying somebody.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 1);
    let mut nonces = funded_round(&mut store, &exec, group);

    for who in 1u8..=4 {
        exec.execute_block(
            &mut store,
            ctx(3),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::PaySocialFund { group }],
            )],
        );
        nonces[who as usize] += 1;
    }
    assert_eq!(
        group_record(&store, &group).social_fund,
        Amount::from_afri(400),
        "four members at 100 each"
    );
    assert_eq!(balance(&mut store, group), Amount::from_afri(20_400));

    // 20,400 is in the account but only 20,000 is lendable. A third of 20,300
    // is 6,768 — under account 2's 5,000 of savings, so cover is not what
    // refuses this. The fund is.
    let out = exec.execute_block(
        &mut store,
        ctx(4),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(20_300),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0, "the social fund is not lendable");
    nonces[2] += 1;

    // Close the round and share out; the social fund must survive it.
    let out = exec.execute_block(
        &mut store,
        ctx(5 + PERIOD),
        &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
    );
    assert_eq!(out.succeeded(), 1);
    nonces[1] += 1;
    let out = exec.execute_block(
        &mut store,
        ctx(6 + PERIOD),
        &[tx(1, nonces[1], vec![Message::ShareOut { group }])],
    );
    assert_eq!(out.succeeded(), 1);

    assert_eq!(
        balance(&mut store, group),
        Amount::from_afri(400),
        "the savings are divided and the insurance is not"
    );
    assert_eq!(
        group_record(&store, &group).social_fund,
        Amount::from_afri(400)
    );
}

#[test]
fn a_social_grant_is_paid_out_of_the_social_fund_and_nothing_else() {
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let mut nonces = funded_round(&mut store, &exec, group);

    for who in 1u8..=4 {
        exec.execute_block(
            &mut store,
            ctx(3),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::PaySocialFund { group }],
            )],
        );
        nonces[who as usize] += 1;
    }

    // More than the fund holds, even though the group's balance covers it.
    let out = exec.execute_block(
        &mut store,
        ctx(4),
        &[tx(
            3,
            nonces[3],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(3),
                kind: ProposalKind::SocialGrant {
                    amount: Amount::from_afri(500),
                },
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0, "a grant cannot reach into the savings");
    nonces[3] += 1;

    exec.execute_block(
        &mut store,
        ctx(5),
        &[tx(
            3,
            nonces[3],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(3),
                kind: ProposalKind::SocialGrant {
                    amount: Amount::from_afri(300),
                },
            }],
        )],
    );
    nonces[3] += 1;

    let before = balance(&mut store, addr(3));
    for who in [1u8, 2, 4] {
        exec.execute_block(
            &mut store,
            ctx(6),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::ApproveGroupAction { group }],
            )],
        );
        nonces[who as usize] += 1;
    }
    assert_eq!(
        balance(&mut store, addr(3)),
        before.checked_add(Amount::from_afri(300)).unwrap()
    );
    assert_eq!(
        group_record(&store, &group).social_fund,
        Amount::from_afri(100),
        "the grant came out of the fund, and no repayment is owed on it"
    );
}

#[test]
fn a_member_pays_the_social_contribution_once_a_cycle() {
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 2);
    let nonces = funded_round(&mut store, &exec, group);

    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[
            tx(2, nonces[2], vec![Message::PaySocialFund { group }]),
            tx(2, nonces[2] + 1, vec![Message::PaySocialFund { group }]),
        ],
    );
    assert_eq!(out.succeeded(), 1, "an equal premium, once a meeting");
    assert_eq!(
        group_record(&store, &group).social_fund,
        Amount::from_afri(100)
    );
}

// ---------------------------------------------------------------------------
// The share-out: how people earn
// ---------------------------------------------------------------------------

#[test]
fn the_share_out_divides_the_fund_in_proportion_to_shares_including_the_earnings() {
    // The moment the whole arrangement exists for. Account 2 buys twice what
    // account 4 does, so account 2 leaves with twice as much — and everybody
    // leaves with more than they put in, because a borrower's service charge
    // returned to the fund they all own.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 1);
    let mut nonces = [0u64; 5];
    nonces[1] = 1;

    // 4 + 4 + 2 + 2 = 12 shares, so the fund holds 12,000.
    for (who, shares) in [(1u8, 4u32), (2, 4), (3, 2), (4, 2)] {
        exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::BuyShares { group, shares }],
            )],
        );
        nonces[who as usize] += 1;
    }
    assert_eq!(balance(&mut store, group), Amount::from_afri(12_000));

    // Account 1 borrows 3,000 and repays 3,300, leaving 300 of earnings.
    exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            1,
            nonces[1],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(1),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(3_000),
                    guarantors: vec![addr(2), addr(3)],
                },
            }],
        )],
    );
    nonces[1] += 1;
    for who in [2u8, 3, 4] {
        exec.execute_block(
            &mut store,
            ctx(4),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::ApproveGroupAction { group }],
            )],
        );
        nonces[who as usize] += 1;
    }
    exec.execute_block(
        &mut store,
        ctx(5),
        &[tx(
            1,
            nonces[1],
            vec![Message::RepayLoan {
                group,
                amount: Amount::from_afri(3_300),
            }],
        )],
    );
    nonces[1] += 1;
    assert_eq!(balance(&mut store, group), Amount::from_afri(12_300));

    exec.execute_block(
        &mut store,
        ctx(6 + PERIOD),
        &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
    );
    nonces[1] += 1;

    let before: Vec<Amount> = (1u8..=4).map(|w| balance(&mut store, addr(w))).collect();
    let out = exec.execute_block(
        &mut store,
        ctx(7 + PERIOD),
        &[tx(1, nonces[1], vec![Message::ShareOut { group }])],
    );
    assert_eq!(out.succeeded(), 1);

    let gained: Vec<u128> = (1u8..=4)
        .map(|w| balance(&mut store, addr(w)).units() - before[(w - 1) as usize].units())
        .collect();

    // 12,300 over 12 shares is 1,025 a share.
    assert_eq!(
        gained[0],
        Amount::from_afri(4_100).units() - 1_000,
        "4 shares, less the fee"
    );
    assert_eq!(gained[1], Amount::from_afri(4_100).units());
    assert_eq!(gained[2], Amount::from_afri(2_050).units());
    assert_eq!(gained[3], Amount::from_afri(2_050).units());
    assert!(
        gained[2] > Amount::from_afri(2_000).units(),
        "every member takes out more than the 2,000 they paid in: the service \
         charge one of them paid is income to all of them"
    );

    let record = group_record(&store, &group);
    assert_eq!(record.round, 1, "the round is closed");
    assert_eq!(
        record.total_shares(),
        0,
        "and everyone starts the next one level"
    );
}

#[test]
fn a_defaulters_savings_are_applied_to_their_debt_at_the_share_out() {
    // How a real VICOBA settles: the savings a member invested over the round
    // are used to pay the loan they did not. The loss falls on the whole
    // membership in proportion, because the money simply never came back to the
    // fund everybody's shares divide.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 1);
    let mut nonces = funded_round(&mut store, &exec, group);

    exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(4_000),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    nonces[2] += 1;
    for who in [1u8, 3, 4] {
        exec.execute_block(
            &mut store,
            ctx(4),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::ApproveGroupAction { group }],
            )],
        );
        nonces[who as usize] += 1;
    }

    // Nothing is repaid. The cycle closes, the debt is fined, the round ends.
    exec.execute_block(
        &mut store,
        ctx(5 + PERIOD),
        &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
    );
    nonces[1] += 1;

    let before = balance(&mut store, addr(2));
    let out = exec.execute_block(
        &mut store,
        ctx(6 + PERIOD),
        &[tx(1, nonces[1], vec![Message::ShareOut { group }])],
    );
    assert_eq!(out.succeeded(), 1);

    // 16,000 in the fund over 20 shares is 800 a share, so account 2's gross is
    // 4,000. They owe 4,400 plus a 440 fine — more than the gross, so they take
    // nothing.
    assert_eq!(
        balance(&mut store, addr(2)),
        before,
        "a defaulter's whole entitlement goes to their debt"
    );
    let record = group_record(&store, &group);
    let member = record.member(&addr(2)).unwrap();
    assert_eq!(member.loans_defaulted, 1);
    assert_eq!(member.loans_repaid, 0);
    assert_eq!(
        member.repayment_bps(),
        Some(0),
        "and the record says so, where a flattering one would say nothing"
    );
    assert!(
        member.loan.is_none(),
        "the debt is written off, not carried"
    );
}

#[test]
fn a_round_cannot_be_shared_out_early() {
    // Otherwise any member could end the round the moment the fund was fattest,
    // which is exactly when the members who had not yet bought their shares
    // would lose the most.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 3);
    let mut nonces = funded_round(&mut store, &exec, group);

    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(2, nonces[2], vec![Message::ShareOut { group }])],
    );
    assert_eq!(out.succeeded(), 0, "no cycle has even closed yet");
    nonces[2] += 1;

    let mut height = 4;
    for _ in 0..2 {
        height += PERIOD + 1;
        exec.execute_block(
            &mut store,
            ctx(height),
            &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
        );
        nonces[1] += 1;
    }
    let out = exec.execute_block(
        &mut store,
        ctx(height + 1),
        &[tx(2, nonces[2], vec![Message::ShareOut { group }])],
    );
    assert_eq!(out.succeeded(), 0, "two of three cycles is not the round");
    nonces[2] += 1;

    height += PERIOD + 1;
    exec.execute_block(
        &mut store,
        ctx(height),
        &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
    );
    nonces[1] += 1;
    let out = exec.execute_block(
        &mut store,
        ctx(height + 1),
        &[tx(2, nonces[2], vec![Message::ShareOut { group }])],
    );
    assert_eq!(
        out.succeeded(),
        1,
        "and now the round the group agreed is over"
    );
}

#[test]
fn a_second_share_out_takes_nothing() {
    // The obvious replay: run it twice and collect twice. It fails on the round
    // clock rather than on the empty fund, which is the check that would still
    // hold if somebody had paid the group in between.
    let mut store = funded();
    let exec = Executor::new(chain());
    let group = vikoba(&mut store, &exec, 1);
    let mut nonces = funded_round(&mut store, &exec, group);

    exec.execute_block(
        &mut store,
        ctx(3 + PERIOD),
        &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
    );
    nonces[1] += 1;
    let out = exec.execute_block(
        &mut store,
        ctx(4 + PERIOD),
        &[
            tx(1, nonces[1], vec![Message::ShareOut { group }]),
            tx(1, nonces[1] + 1, vec![Message::ShareOut { group }]),
        ],
    );
    assert_eq!(out.succeeded(), 1, "the second share-out must be refused");
    assert!(balance(&mut store, group).is_zero());
}

// ---------------------------------------------------------------------------
// Conservation
// ---------------------------------------------------------------------------

#[test]
fn a_whole_round_moves_no_money_that_did_not_exist() {
    // The arithmetic above is a lot of multiplication and truncated division on
    // people's savings. This asserts the only property that makes any of it
    // safe: at every step, the money in the world is the money that started
    // there.
    let mut store = funded();
    let exec = Executor::new(chain());

    let everyone = [addr(1), addr(2), addr(3), addr(4), addr(9)];
    let total = |store: &mut MemoryStore, group: Option<Address>| -> u128 {
        let mut sum = everyone
            .iter()
            .map(|a| balance(store, *a).units())
            .sum::<u128>();
        sum += balance(store, fee_collector_address()).units();
        if let Some(g) = group {
            sum += balance(store, g).units();
        }
        sum
    };
    let opening = total(&mut store, None);

    let group = vikoba(&mut store, &exec, 1);
    let mut nonces = funded_round(&mut store, &exec, group);
    assert_eq!(total(&mut store, Some(group)), opening, "after the shares");

    for who in 1u8..=4 {
        exec.execute_block(
            &mut store,
            ctx(3),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::PaySocialFund { group }],
            )],
        );
        nonces[who as usize] += 1;
    }
    assert_eq!(
        total(&mut store, Some(group)),
        opening,
        "after the premiums"
    );

    exec.execute_block(
        &mut store,
        ctx(4),
        &[tx(
            2,
            nonces[2],
            vec![Message::ProposeGroupAction {
                group,
                beneficiary: addr(2),
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(5_000),
                    guarantors: vec![addr(3), addr(4)],
                },
            }],
        )],
    );
    nonces[2] += 1;
    for who in [1u8, 3, 4] {
        exec.execute_block(
            &mut store,
            ctx(5),
            &[tx(
                who,
                nonces[who as usize],
                vec![Message::ApproveGroupAction { group }],
            )],
        );
        nonces[who as usize] += 1;
    }
    assert_eq!(total(&mut store, Some(group)), opening, "after the loan");

    exec.execute_block(
        &mut store,
        ctx(6),
        &[tx(
            2,
            nonces[2],
            vec![Message::RepayLoan {
                group,
                amount: Amount::from_afri(5_500),
            }],
        )],
    );
    nonces[2] += 1;
    assert_eq!(
        total(&mut store, Some(group)),
        opening,
        "after the repayment"
    );

    exec.execute_block(
        &mut store,
        ctx(7 + PERIOD),
        &[tx(1, nonces[1], vec![Message::CloseCycle { group }])],
    );
    nonces[1] += 1;
    exec.execute_block(
        &mut store,
        ctx(8 + PERIOD),
        &[tx(1, nonces[1], vec![Message::ShareOut { group }])],
    );
    assert_eq!(
        total(&mut store, Some(group)),
        opening,
        "and after the whole fund has been divided"
    );
}
