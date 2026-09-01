//! Governance, driven end to end through signed transactions.
//!
//! Until now every trusted role on this chain was fixed at genesis and could not
//! be rotated, added or revoked. An issuer authority whose key was lost stayed
//! lost; an attestor whose regulator withdrew its licence stayed licensed
//! on-chain; every parameter was a `const`, so tuning one meant a flag day.
//! [ADR-0020](../../../docs/adr/0020-sovereign-issuance.md) and
//! [ADR-0021](../../../docs/adr/0021-licensing-attestors.md) both named that gap
//! and declined to invent an authority in passing.
//!
//! What is being tested here is not really "voting works". It is the **line
//! between the two tracks**:
//!
//! * the council governs the *network* — parameters, attestor licences, the
//!   admission of a new currency — and every one of those waits out a timelock;
//! * the council governs *no money at all*. It cannot mint, freeze, spend, or
//!   replace the authority of a currency already admitted. A sovereign's
//!   authority moves only by the two-step handover in `crates/bank`, signed at
//!   both ends.
//!
//! The tests that matter most are
//! [`the_council_cannot_take_a_currency_from_its_sovereign`] and
//! [`a_handover_to_a_key_nobody_holds_never_completes`].

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_alias::contact::{Attestor, ContactCommitment, ContactKind};
use afrolink_alias::rebind::Bindings;
use afrolink_bank::{Bank, BankView, Issuer};
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{BlockContext, Executor, ResultCode};
use afrolink_gov::params::MIN_REBIND_DELAY_BLOCKS;
use afrolink_gov::{Action, ChainParams, Council, GovView, Seat};
use afrolink_primitives::{Amount, ChainId, CountryCode, Denom, Height, Timestamp};
use afrolink_state::MemoryStore;
use afrolink_types::{Fee, Message, Transaction, TxBody};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Four council seats, one per jurisdiction. Three of the four pass a proposal.
const SEATS: [u8; 4] = [10, 11, 12, 13];
const COUNTRIES: [&str; 4] = ["ke", "ng", "za", "gh"];
/// The central bank governing `sov/ke/kes`.
const AUTHORITY: u8 = 100;
/// The account a handover is offered to.
const SUCCESSOR: u8 = 101;
/// A licensed mobile network operator.
const MNO: u8 = 20;
/// Somebody with no role at all.
const STRANGER: u8 = 66;

const PEPPER: &[u8] = b"a-sixteen-byte-pepper-or-longer";

fn sk(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn addr(seed: u8) -> Address {
    Address::from_public_key(&sk(seed).public_key())
}

fn chain() -> ChainId {
    ChainId::new("afrolink-1").unwrap()
}

fn cc(s: &str) -> CountryCode {
    CountryCode::new(s).unwrap()
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

fn council() -> Council {
    let mut seats: Vec<Seat> = SEATS
        .iter()
        .zip(COUNTRIES)
        .map(|(seed, country)| Seat::new(addr(*seed), 10, cc(country)))
        .collect();
    seats.sort_by_key(|seat| seat.holder);
    Council::new(seats, afrolink_gov::MIN_COUNCIL_THRESHOLD_BPS).unwrap()
}

/// Parameters short enough to drive in a test, still clearing every floor.
fn params() -> ChainParams {
    ChainParams {
        voting_period_blocks: 10_000,
        timelock_blocks: 5_000,
        rebind_delay_blocks: MIN_REBIND_DELAY_BLOCKS,
        ..ChainParams::default()
    }
}

/// A chain with a seated council, one registered currency, and everybody funded.
fn chain_state() -> MemoryStore {
    let mut store = MemoryStore::new();
    afrolink_gov::Governance::new(&mut store)
        .install(&council(), &params())
        .unwrap();

    let mut bank = Bank::new(&mut store);
    bank.register_issuer(&kes(), &Issuer::new(addr(AUTHORITY)))
        .unwrap();
    for who in SEATS
        .iter()
        .copied()
        .chain([AUTHORITY, SUCCESSOR, MNO, STRANGER, 1, 2])
    {
        bank.genesis_allocate(&addr(who), &kes(), Amount::from_afri(10))
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

/// Nonces, so a test that sends several transactions from one account does not
/// have to count.
struct Nonces(Vec<u64>);

impl Default for Nonces {
    fn default() -> Self {
        Self(vec![0; 256])
    }
}

impl Nonces {
    fn next(&mut self, sender: u8) -> u64 {
        let n = self.0[sender as usize];
        self.0[sender as usize] += 1;
        n
    }
}

/// Open a proposal and vote it to the threshold, returning its id.
///
/// Three of four seats, because two thirds of four equal seats is three.
fn pass(
    store: &mut MemoryStore,
    nonces: &mut Nonces,
    exec: &Executor,
    at: u64,
    action: Action,
) -> u64 {
    let proposer = SEATS[0];
    let out = exec.execute_block(
        store,
        ctx(at),
        &[tx(
            proposer,
            nonces.next(proposer),
            vec![Message::ProposeGovAction {
                action: Box::new(action),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "a seated member may open a proposal");
    let id = GovView::new(store).open_proposals().unwrap().pop().unwrap();

    let votes: Vec<Transaction> = SEATS[..3]
        .iter()
        .map(|seat| {
            tx(
                *seat,
                nonces.next(*seat),
                vec![Message::VoteGovAction { proposal: id }],
            )
        })
        .collect();
    let out = exec.execute_block(store, ctx(at + 1), &votes);
    assert_eq!(out.succeeded(), 3, "three of four seats is two thirds");
    id
}

/// Pass a proposal, wait out the timelock, and execute it.
fn enact(store: &mut MemoryStore, nonces: &mut Nonces, exec: &Executor, at: u64, action: Action) {
    let id = pass(store, nonces, exec, at, action);
    let ready = at + 1 + params().timelock_blocks;
    let out = exec.execute_block(
        store,
        ctx(ready),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ExecuteGovAction { proposal: id }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "the timelock has run");
}

fn issuer(store: &MemoryStore) -> Issuer {
    BankView::new(store).issuer(&kes()).unwrap().unwrap()
}

fn attestor(store: &mut MemoryStore, who: u8) -> Option<Attestor> {
    Bindings::new(store).attestor(&addr(who)).unwrap()
}

fn safaricom() -> Attestor {
    Attestor {
        country: cc("ke"),
        name: "Safaricom".to_owned(),
        active: true,
    }
}

fn license_mno() -> Action {
    Action::LicenseAttestor {
        address: addr(MNO),
        attestor: safaricom(),
    }
}

// ---------------------------------------------------------------------------
// The gap ADR-0021 named: an attestor set that could never change
// ---------------------------------------------------------------------------

#[test]
fn governance_licenses_an_attestor_and_the_licence_immediately_works() {
    // Before this, an attestor could only be named in a genesis file. A network
    // that shipped without one had no way to ever bind a phone number, and one
    // that shipped with the wrong one had no way to correct it.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    assert_eq!(attestor(&mut store, MNO), None, "nobody is licensed yet");
    enact(&mut store, &mut nonces, &exec, 1, license_mno());
    assert_eq!(attestor(&mut store, MNO), Some(safaricom()));

    // And the licence is not decorative: the attestor can bind a number now.
    let commitment = ContactCommitment::new(ContactKind::Phone, "+254712345678", PEPPER).unwrap();
    let out = exec.execute_block(
        &mut store,
        ctx(100_000),
        &[tx(
            MNO,
            nonces.next(MNO),
            vec![Message::AttestContact {
                commitment,
                address: addr(1),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert_eq!(
        Bindings::new(&mut store)
            .resolve(&commitment)
            .unwrap()
            .unwrap()
            .address,
        addr(1)
    );
}

#[test]
fn a_suspended_attestor_stops_binding_but_its_bindings_keep_resolving() {
    // Why `Attestor::active` exists, and why governance suspends rather than
    // deletes. A telco losing its licence must not make every phone number it
    // ever bound stop resolving — that would turn a regulatory action into an
    // outage for people who did nothing.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    enact(&mut store, &mut nonces, &exec, 1, license_mno());

    let commitment = ContactCommitment::new(ContactKind::Phone, "+254712345678", PEPPER).unwrap();
    exec.execute_block(
        &mut store,
        ctx(100_000),
        &[tx(
            MNO,
            nonces.next(MNO),
            vec![Message::AttestContact {
                commitment,
                address: addr(1),
            }],
        )],
    );

    enact(
        &mut store,
        &mut nonces,
        &exec,
        200_000,
        Action::SetAttestorActive {
            address: addr(MNO),
            active: false,
        },
    );
    assert!(!attestor(&mut store, MNO).unwrap().active);

    // The existing binding still resolves, with its provenance intact.
    let record = Bindings::new(&mut store)
        .resolve(&commitment)
        .unwrap()
        .unwrap();
    assert_eq!(record.address, addr(1));
    assert_eq!(record.issuer, addr(MNO));

    // But no new one can be made.
    let second = ContactCommitment::new(ContactKind::Phone, "+254700000000", PEPPER).unwrap();
    let out = exec.execute_block(
        &mut store,
        ctx(300_000),
        &[tx(
            MNO,
            nonces.next(MNO),
            vec![Message::AttestContact {
                commitment: second,
                address: addr(2),
            }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Binding);
    assert_eq!(Bindings::new(&mut store).resolve(&second).unwrap(), None);
}

// ---------------------------------------------------------------------------
// The line between the two tracks
// ---------------------------------------------------------------------------

#[test]
fn the_council_cannot_take_a_currency_from_its_sovereign() {
    // The single most important property here. A central bank will not issue on
    // rails where a vote elsewhere can reach its money — which is why, on BIS's
    // mBridge, each central bank is the exclusive issuer of its own CBDC while a
    // separate body governs the platform.
    //
    // `AdmitDenom` registers only. Re-admitting a currency that already has an
    // issuer would be a path by which the council replaces an authority without
    // the sovereign's consent, so it is refused.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    let id = pass(
        &mut store,
        &mut nonces,
        &exec,
        1,
        Action::AdmitDenom {
            denom: kes(),
            authority: addr(STRANGER),
        },
    );
    let out = exec.execute_block(
        &mut store,
        ctx(1 + 1 + params().timelock_blocks),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ExecuteGovAction { proposal: id }],
        )],
    );
    assert_eq!(
        out.outcomes[0].receipt.code,
        ResultCode::Bank,
        "a currency already has an authority, and the council is not it"
    );
    assert_eq!(
        issuer(&store).authority,
        addr(AUTHORITY),
        "the sovereign still governs its own currency"
    );
}

#[test]
fn governance_admits_a_currency_the_chain_has_never_seen() {
    // The half that *is* the council's business: a new jurisdiction joining.
    // After admission the currency governs itself and the council is done.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    let ngn = Denom::sovereign("ng", "ngn").unwrap();

    assert_eq!(BankView::new(&store).issuer(&ngn).unwrap(), None);
    enact(
        &mut store,
        &mut nonces,
        &exec,
        1,
        Action::AdmitDenom {
            denom: ngn.clone(),
            authority: addr(SUCCESSOR),
        },
    );

    let admitted = BankView::new(&store).issuer(&ngn).unwrap().unwrap();
    assert_eq!(admitted.authority, addr(SUCCESSOR));
    assert!(
        admitted.minters.is_empty() && !admitted.paused && admitted.max_supply.is_none(),
        "admission names an authority and decides nothing else on its behalf"
    );
}

// ---------------------------------------------------------------------------
// The sovereign handover: two steps, both signed
// ---------------------------------------------------------------------------

#[test]
fn a_currencys_authority_moves_only_when_the_successor_accepts() {
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            nonces.next(AUTHORITY),
            vec![Message::TransferIssuerAuthority {
                denom: kes(),
                to: Some(addr(SUCCESSOR)),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert_eq!(
        issuer(&store).authority,
        addr(AUTHORITY),
        "offering changes nothing; the old authority keeps every power it had"
    );
    assert_eq!(issuer(&store).pending_authority, Some(addr(SUCCESSOR)));

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            SUCCESSOR,
            nonces.next(SUCCESSOR),
            vec![Message::AcceptIssuerAuthority { denom: kes() }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert_eq!(issuer(&store).authority, addr(SUCCESSOR));
    assert_eq!(issuer(&store).pending_authority, None);

    // And the old authority is now nobody.
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            AUTHORITY,
            nonces.next(AUTHORITY),
            vec![Message::SetIssuerPaused {
                denom: kes(),
                paused: true,
            }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Bank);
    assert!(!issuer(&store).paused);
}

#[test]
fn a_handover_to_a_key_nobody_holds_never_completes() {
    // The reason the handover is two steps. A one-step transfer to a mistyped
    // address ends a currency's governance permanently: nothing could ever mint
    // it, unpause it, or name a minter again. Here the offer simply sits there,
    // and the authority that made the mistake withdraws it.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    // An address derived from a key that exists nowhere in this test.
    let typo = Address::from_public_key(&SecretKey::from_bytes(&[0xAB; 32]).public_key());

    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            AUTHORITY,
            nonces.next(AUTHORITY),
            vec![Message::TransferIssuerAuthority {
                denom: kes(),
                to: Some(typo),
            }],
        )],
    );
    assert_eq!(issuer(&store).authority, addr(AUTHORITY), "still governed");

    // Nobody else can accept on the offer's behalf.
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::AcceptIssuerAuthority { denom: kes() }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Bank);

    // And the offer is withdrawable.
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            AUTHORITY,
            nonces.next(AUTHORITY),
            vec![Message::TransferIssuerAuthority {
                denom: kes(),
                to: None,
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert_eq!(issuer(&store).pending_authority, None);
}

#[test]
fn a_stranger_cannot_offer_away_a_currency_that_is_not_theirs() {
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::TransferIssuerAuthority {
                denom: kes(),
                to: Some(addr(STRANGER)),
            }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Bank);
    assert_eq!(issuer(&store).pending_authority, None);
}

// ---------------------------------------------------------------------------
// The timelock, and who may do what
// ---------------------------------------------------------------------------

#[test]
fn a_passed_proposal_cannot_be_executed_before_its_timelock() {
    // The whole value of a timelock is the window between "decided" and
    // "binding", in which everyone who has to live with the decision can see it
    // coming. A timelock that can be skipped is not a window.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    let id = pass(&mut store, &mut nonces, &exec, 1, license_mno());

    let out = exec.execute_block(
        &mut store,
        ctx(params().timelock_blocks),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ExecuteGovAction { proposal: id }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Governance);
    assert_eq!(attestor(&mut store, MNO), None, "nothing has taken effect");
}

#[test]
fn a_stranger_can_neither_propose_nor_vote_but_may_execute() {
    // Execution is permissionless on purpose, exactly like `ApplyRebind`: the
    // vote is taken and the timelock has run, so the outcome is already settled
    // and whoever pays the fee to finish the job changes nothing about it.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ProposeGovAction {
                action: Box::new(license_mno()),
            }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Governance);

    let id = pass(&mut store, &mut nonces, &exec, 2, license_mno());
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::VoteGovAction { proposal: id }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Governance);

    // But a stranger may pay to finish a decided question.
    let out = exec.execute_block(
        &mut store,
        ctx(3 + params().timelock_blocks),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ExecuteGovAction { proposal: id }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    assert_eq!(attestor(&mut store, MNO), Some(safaricom()));
}

#[test]
fn two_of_four_seats_are_not_two_thirds() {
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    let proposer = SEATS[0];
    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            proposer,
            nonces.next(proposer),
            vec![Message::ProposeGovAction {
                action: Box::new(license_mno()),
            }],
        )],
    );
    let id = GovView::new(&store)
        .open_proposals()
        .unwrap()
        .pop()
        .unwrap();

    let votes: Vec<Transaction> = SEATS[..2]
        .iter()
        .map(|seat| {
            tx(
                *seat,
                nonces.next(*seat),
                vec![Message::VoteGovAction { proposal: id }],
            )
        })
        .collect();
    assert_eq!(
        exec.execute_block(&mut store, ctx(2), &votes).succeeded(),
        2
    );

    let out = exec.execute_block(
        &mut store,
        ctx(2 + params().timelock_blocks),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ExecuteGovAction { proposal: id }],
        )],
    );
    assert_eq!(
        out.outcomes[0].receipt.code,
        ResultCode::Governance,
        "a proposal short of the threshold is never scheduled"
    );
}

#[test]
fn a_council_can_withdraw_its_own_decision_inside_the_timelock() {
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    let id = pass(&mut store, &mut nonces, &exec, 1, license_mno());

    // A withdrawal clears the same two-thirds bar, and takes effect at once:
    // returning to the state everyone already expects gives nobody notice they
    // need.
    enact_cancel(&mut store, &mut nonces, &exec, 3, id);

    let out = exec.execute_block(
        &mut store,
        ctx(3 + params().timelock_blocks),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ExecuteGovAction { proposal: id }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Governance);
    assert_eq!(attestor(&mut store, MNO), None);
}

/// Pass a `Cancel`, which needs no execution step of its own.
fn enact_cancel(
    store: &mut MemoryStore,
    nonces: &mut Nonces,
    exec: &Executor,
    at: u64,
    target: u64,
) {
    pass(store, nonces, exec, at, Action::Cancel { proposal: target });
    assert_eq!(
        GovView::new(store).proposal(target).unwrap(),
        None,
        "a withdrawal takes effect the moment it passes"
    );
}

// ---------------------------------------------------------------------------
// Parameters that are voted on are parameters that take effect
// ---------------------------------------------------------------------------

#[test]
fn a_changed_parameter_changes_what_the_chain_does() {
    // The defect this phase had to avoid repeating: a value written to state and
    // read by nothing is the same as code reachable from no transaction. So the
    // test is not "the parameter was stored" but "the rebinding the chain
    // schedules moved".
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    enact(&mut store, &mut nonces, &exec, 1, license_mno());

    let commitment = ContactCommitment::new(ContactKind::Phone, "+254712345678", PEPPER).unwrap();
    exec.execute_block(
        &mut store,
        ctx(100_000),
        &[tx(
            MNO,
            nonces.next(MNO),
            vec![Message::AttestContact {
                commitment,
                address: addr(1),
            }],
        )],
    );

    let longer = ChainParams {
        rebind_delay_blocks: MIN_REBIND_DELAY_BLOCKS * 3,
        ..params()
    };
    enact(
        &mut store,
        &mut nonces,
        &exec,
        200_000,
        Action::SetParams(longer.clone()),
    );
    assert_eq!(GovView::new(&store).params().unwrap(), longer);

    let at = 400_000;
    exec.execute_block(
        &mut store,
        ctx(at),
        &[tx(
            MNO,
            nonces.next(MNO),
            vec![Message::RequestRebind {
                commitment,
                new_address: addr(2),
            }],
        )],
    );
    let pending = Bindings::new(&mut store)
        .resolve(&commitment)
        .unwrap()
        .unwrap()
        .rebind
        .unwrap();
    assert_eq!(
        pending.effective_at,
        Height(at + MIN_REBIND_DELAY_BLOCKS * 3),
        "the delay the council voted for is the delay the chain uses"
    );
}

#[test]
fn governance_cannot_shorten_unbonding_below_what_light_clients_assume() {
    // A light client compiles in a trusting period derived from UNBONDING_MS.
    // Voting the chain's period below it would leave every deployed client
    // trusting headers signed by stake that is already withdrawn — the
    // long-range attack of ADR-0010, arrived at by vote rather than by force.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    let mut unsafe_params = params();
    unsafe_params.staking.unbonding_ms = 1;
    let proposer = SEATS[0];
    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            proposer,
            nonces.next(proposer),
            vec![Message::ProposeGovAction {
                action: Box::new(Action::SetParams(unsafe_params)),
            }],
        )],
    );
    assert_eq!(
        out.outcomes[0].receipt.code,
        ResultCode::Governance,
        "refused when it is opened, not after a voting period is spent on it"
    );
    assert!(GovView::new(&store).open_proposals().unwrap().is_empty());
}

#[test]
fn governance_cannot_raise_its_own_concentration_cap() {
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    // Tightening is allowed: four equal jurisdictions sit at 2500 bps.
    let tighter = ChainParams {
        max_council_country_share_bps: 2_500,
        ..params()
    };
    enact(
        &mut store,
        &mut nonces,
        &exec,
        1,
        Action::SetParams(tighter.clone()),
    );
    assert_eq!(
        GovView::new(&store)
            .params()
            .unwrap()
            .max_council_country_share_bps,
        2_500
    );

    // Going back is not. A cap the capped party can widen is not a cap.
    let proposer = SEATS[0];
    let out = exec.execute_block(
        &mut store,
        ctx(200_000),
        &[tx(
            proposer,
            nonces.next(proposer),
            vec![Message::ProposeGovAction {
                action: Box::new(Action::SetParams(params())),
            }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Governance);
}

// ---------------------------------------------------------------------------
// Governance changing itself
// ---------------------------------------------------------------------------

#[test]
fn the_council_can_reseat_itself_but_not_into_one_jurisdiction() {
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    // Refused when it is opened: a council that one jurisdiction could block.
    let mut captured = vec![
        Seat::new(addr(SEATS[0]), 10, cc("ke")),
        Seat::new(addr(SEATS[1]), 10, cc("ke")),
        Seat::new(addr(SEATS[2]), 10, cc("ng")),
    ];
    captured.sort_by_key(|seat| seat.holder);
    let captured = Council::new(captured, afrolink_gov::MIN_COUNCIL_THRESHOLD_BPS).unwrap();

    let proposer = SEATS[0];
    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            proposer,
            nonces.next(proposer),
            vec![Message::ProposeGovAction {
                action: Box::new(Action::SetCouncil(captured)),
            }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Governance);

    // A lawful reseat: a fifth jurisdiction joins.
    let mut widened: Vec<Seat> = SEATS
        .iter()
        .zip(COUNTRIES)
        .map(|(seed, country)| Seat::new(addr(*seed), 10, cc(country)))
        .collect();
    widened.push(Seat::new(addr(STRANGER), 10, cc("tz")));
    widened.sort_by_key(|seat| seat.holder);
    let widened = Council::new(widened, afrolink_gov::MIN_COUNCIL_THRESHOLD_BPS).unwrap();

    enact(
        &mut store,
        &mut nonces,
        &exec,
        2,
        Action::SetCouncil(widened.clone()),
    );
    assert_eq!(GovView::new(&store).council().unwrap(), Some(widened));

    // And the new seat can now vote, while four of five is the new bar.
    let out = exec.execute_block(
        &mut store,
        ctx(500_000),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ProposeGovAction {
                action: Box::new(license_mno()),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "a newly seated member may propose");
}

#[test]
fn a_removed_seat_stops_counting_at_once() {
    // Any other reading makes removing a compromised seat pointless: its votes
    // would keep landing on every proposal opened before it left.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    // The fourth seat is replaced rather than merely dropped: three equal
    // jurisdictions would put each of them at a third, which the concentration
    // rule refuses precisely because a third can block a two-thirds threshold.
    let removed = SEATS[3];
    let mut reseated: Vec<Seat> = SEATS[..3]
        .iter()
        .zip(COUNTRIES)
        .map(|(seed, country)| Seat::new(addr(*seed), 10, cc(country)))
        .collect();
    reseated.push(Seat::new(addr(SUCCESSOR), 10, cc("gh")));
    reseated.sort_by_key(|seat| seat.holder);
    let reseated = Council::new(reseated, afrolink_gov::MIN_COUNCIL_THRESHOLD_BPS).unwrap();
    enact(
        &mut store,
        &mut nonces,
        &exec,
        1,
        Action::SetCouncil(reseated),
    );

    let out = exec.execute_block(
        &mut store,
        ctx(200_000),
        &[tx(
            removed,
            nonces.next(removed),
            vec![Message::ProposeGovAction {
                action: Box::new(license_mno()),
            }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Governance);
}

// ---------------------------------------------------------------------------
// What governance is not
// ---------------------------------------------------------------------------

#[test]
fn no_proposal_can_move_anybodys_money() {
    // There is no `Action::Custom`, no encoded call, no arbitrary message the
    // council can wrap and execute as itself — which is a deliberate departure
    // from Polkadot, where governance dispatches a runtime `Call`, and from
    // Cosmos, where it executes any message the module has authority over. In
    // both, "what can governance do?" answers "anything the chain can do."
    //
    // Here it is six items, and this asserts the consequence: a full governance
    // cycle changes no balance anywhere.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());

    let watched = [AUTHORITY, MNO, STRANGER, 1, 2, SEATS[0]];
    let before: Vec<u128> = watched
        .iter()
        .map(|w| {
            BankView::new(&store)
                .balance(&addr(*w), &kes())
                .unwrap()
                .units()
        })
        .collect();
    let supply_before = BankView::new(&store).total_supply(&kes()).unwrap();

    enact(&mut store, &mut nonces, &exec, 1, license_mno());
    enact(
        &mut store,
        &mut nonces,
        &exec,
        200_000,
        Action::AdmitDenom {
            denom: Denom::sovereign("ng", "ngn").unwrap(),
            authority: addr(SUCCESSOR),
        },
    );

    let after: Vec<u128> = watched
        .iter()
        .map(|w| {
            BankView::new(&store)
                .balance(&addr(*w), &kes())
                .unwrap()
                .units()
        })
        .collect();
    for (i, who) in watched.iter().enumerate() {
        // Fees are the only movement, and only for accounts that sent something.
        assert!(
            after[i] <= before[i],
            "account {who} gained money from a governance cycle"
        );
    }
    assert_eq!(
        BankView::new(&store).total_supply(&kes()).unwrap(),
        supply_before,
        "governance created and destroyed nothing"
    );
}

#[test]
fn an_attestor_cannot_be_licensed_already_suspended() {
    // The same rule genesis enforces: a registry row nothing could ever turn on,
    // because activation is governance's job and this action is that job.
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    let proposer = SEATS[0];
    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            proposer,
            nonces.next(proposer),
            vec![Message::ProposeGovAction {
                action: Box::new(Action::LicenseAttestor {
                    address: addr(MNO),
                    attestor: Attestor {
                        active: false,
                        ..safaricom()
                    },
                }),
            }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Governance);
}

#[test]
fn suspending_an_attestor_that_was_never_licensed_is_refused() {
    let mut store = chain_state();
    let mut nonces = Nonces::default();
    let exec = Executor::new(chain());
    let id = pass(
        &mut store,
        &mut nonces,
        &exec,
        1,
        Action::SetAttestorActive {
            address: addr(STRANGER),
            active: false,
        },
    );
    let out = exec.execute_block(
        &mut store,
        ctx(2 + params().timelock_blocks),
        &[tx(
            STRANGER,
            nonces.next(STRANGER),
            vec![Message::ExecuteGovAction { proposal: id }],
        )],
    );
    assert_eq!(out.outcomes[0].receipt.code, ResultCode::Binding);
}
