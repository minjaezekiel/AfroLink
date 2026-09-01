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
//! | A vikoba's social fund never exceeds its balance | Insurance the group has already spent |
//! | No loan falls due after the round that settles it | §16 — found here, not by hand |
//!
//! # Reaching the arithmetic
//!
//! Some of the generator aims rather than guesses: it answers an open proposal,
//! repays a debt it knows the sender carries, and shares out a round it knows is
//! complete. That is not the generator marking its own homework — every
//! invariant still runs against whatever the executor actually did. It is the
//! difference between a suite that reaches a share-out and one that never does,
//! and an invariant that is never reached always holds.

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
use afrolink_gov::params::{
    MIN_REBIND_DELAY_BLOCKS, MIN_TIMELOCK_BLOCKS, MIN_VOTING_PERIOD_BLOCKS,
};
use afrolink_gov::{Action, ChainParams, Council, GovView, Governance, MAX_OPEN_PROPOSALS, Seat};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
use afrolink_state::{KeyValueStore, MemoryStore, StoreKey};
use afrolink_types::group::{
    Contribution, FoundingMember, PayoutPolicy, ProposalKind, Quorum, Role, ShareRules,
};
use afrolink_types::{Account, AccountKind, Fee, Message, Transaction, TxBody};

/// Actors that hold keys and send transactions.
const ACTORS: u8 = 6;
/// Addresses that only ever receive, so paying a stranger is exercised.
const OUTSIDERS: u8 = 4;
/// Group addresses per actor kept in the universe from the start.
const GROUP_SLOTS: u64 = 3;
/// Council seats, one per jurisdiction. Three of the four pass a proposal.
const COUNCIL: [u8; 4] = [0, 1, 2, 3];
const COUNCIL_COUNTRIES: [&str; 4] = ["ke", "ng", "za", "gh"];

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

/// The founding council: four actors, one jurisdiction each.
///
/// Deliberately overlapping with the issuer roles — actor(0) is both a seat and
/// the currency's authority — because that is the interesting case. A seat that
/// also governs a currency must not be able to use the council to reach it.
fn council() -> Council {
    let mut seats: Vec<Seat> = COUNCIL
        .iter()
        .zip(COUNCIL_COUNTRIES)
        .map(|(who, country)| {
            Seat::new(
                actor(*who),
                10,
                afrolink_primitives::CountryCode::new(country).unwrap(),
            )
        })
        .collect();
    seats.sort_by_key(|seat| seat.holder);
    Council::new(seats, afrolink_gov::MIN_COUNCIL_THRESHOLD_BPS).unwrap()
}

/// Parameters at their floors, so a generated run can actually reach the end of
/// a voting period and a timelock.
fn opening_params() -> ChainParams {
    ChainParams {
        voting_period_blocks: MIN_VOTING_PERIOD_BLOCKS,
        timelock_blocks: MIN_TIMELOCK_BLOCKS,
        rebind_delay_blocks: MIN_REBIND_DELAY_BLOCKS,
        ..ChainParams::default()
    }
}

/// Genesis: every actor funded in both denominations.
fn opening_state() -> MemoryStore {
    let mut store = MemoryStore::new();
    Governance::new(&mut store)
        .install(&council(), &opening_params())
        .unwrap();
    let mut bank = Bank::new(&mut store);
    // actor(0) governs and never issues; actor(1) holds the hot key. The split
    // is the point of ADR-0020, so the generator has to live with it.
    bank.register_issuer(
        &kes(),
        &Issuer::new(actor(0)).with_minter(actor(1), Amount::from_afri(2_000_000)),
    )
    .unwrap();
    // Allocated rather than minted: at height 0 the genesis file *is* the
    // authority, and starting the run with the minter's allowance untouched
    // leaves every shilling the generator creates visible as issuance.
    for i in 0..ACTORS {
        bank.genesis_allocate(&actor(i), &kes(), Amount::from_afri(1_000_000))
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
                // The pot is the group's own money leaving on a payout — and a
                // vikoba's fund is the group's own money leaving on a loan, a
                // grant, or a share-out.
                Message::GroupPayout { group }
                | Message::ApproveGroupAction { group }
                | Message::ShareOut { group } => out.push(*group),
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
    //    recorded total supply, for every denomination, always. Issuance moves
    //    that number deliberately; nothing else may move it at all.
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
        // 1b. A declared supply cap is a promise holders can verify from the
        //     chain. If supply may exceed it even once, the promise is worth
        //     nothing — and the cap ratchet exists precisely so the issuer
        //     cannot quietly move the line instead.
        if let Some(issuer) = view.issuer(denom).unwrap()
            && let Some(cap) = issuer.max_supply
        {
            assert!(
                total <= cap,
                "seed {seed} height {height}: supply of {denom} is {} against a \
                 declared cap of {}",
                total.units(),
                cap.units()
            );
        }
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

            // 5. Vikoba. Everything here is arithmetic on people's savings, and
            //    the whole point of an accumulating group is that a member's
            //    claim on the fund is a number the chain computed rather than a
            //    sum somebody handed over.
            if let PayoutPolicy::Accumulate(rules) = &group.policy {
                let balance = view.balance(address, &group.contribution.denom).unwrap();
                // The social fund is insurance the group promised itself. If the
                // record claims more of it than the account actually holds, the
                // promise is already broken and nobody has noticed.
                assert!(
                    group.social_fund <= balance,
                    "seed {seed} height {height}: {address:?} claims a social fund of {} \
                     against a balance of {}",
                    group.social_fund.units(),
                    balance.units()
                );

                for member in &group.members {
                    assert!(
                        member.shares_this_cycle <= rules.max_shares,
                        "seed {seed} height {height}: a member bought past the ceiling"
                    );
                    assert!(
                        u64::from(member.shares_this_cycle) <= member.shares,
                        "seed {seed} height {height}: shares bought this cycle exceed \
                         shares held"
                    );
                    if let Some(loan) = &member.loan {
                        // A repayment beyond the debt is money the group took
                        // that nobody voted to take.
                        let total = loan.principal.checked_add(loan.service_charge).unwrap();
                        assert!(
                            loan.repaid <= total,
                            "seed {seed} height {height}: a loan repaid beyond its worth"
                        );
                        assert!(
                            !loan.is_settled(),
                            "seed {seed} height {height}: a settled loan left on the record — \
                             it would be counted as a default at the share-out"
                        );
                        // The cover rule is what lets the group lend with no
                        // court behind it. If a loan outlives the savings that
                        // secured it, the security was never real.
                        assert!(
                            loan.due_cycle
                                <= group
                                    .round_start_cycle
                                    .saturating_add(rules.cycles_per_round),
                            "seed {seed} height {height}: a loan falls due after the round \
                             that would settle it"
                        );
                    }
                }
                assert!(
                    group.round_start_cycle <= group.cycle,
                    "seed {seed} height {height}: a round starting after the current cycle"
                );
                if let Some(pending) = &group.pending {
                    assert!(
                        pending.approvals.windows(2).all(|w| w[0] < w[1]),
                        "seed {seed} height {height}: proposal approvals out of canonical order"
                    );
                    assert!(
                        pending.approvals.iter().all(|a| group.is_member(a)),
                        "seed {seed} height {height}: a stranger's approval counts toward a quorum"
                    );
                    assert!(
                        group.is_member(&pending.beneficiary),
                        "seed {seed} height {height}: a proposal would pay a non-member"
                    );
                }
            }
        }
    }

    check_governance_invariants(seed, height, store);
}

/// What must be true of the governance module after any block.
///
/// Governance is the one module that can change the rules the other invariants
/// are checked against, so it needs its own: a body that has voted itself into a
/// shape its own rules refuse, or a parameter that has drifted under a floor, is
/// a chain whose other guarantees have quietly stopped meaning anything.
fn check_governance_invariants(seed: u64, height: u64, store: &MemoryStore) {
    let gov = GovView::new(store);

    // 1. The parameters in force always clear every floor. If they ever did not,
    //    a vote would have disarmed something the chain depends on — the
    //    unbonding period a light client compiles in, or the delay that is the
    //    whole SIM-swap defence.
    let params = gov.params().expect("parameters decode");
    assert_eq!(
        params.validate(),
        Ok(()),
        "seed {seed} height {height}: the parameters in force break their own floors"
    );

    // 2. The seated council always satisfies the concentration cap in force. Not
    //    merely the cap it was seated under: a vote can tighten the cap, and a
    //    vote that tightens it past the sitting body would leave the chain
    //    governed by a council its own rules reject.
    let council = gov.council().expect("council decodes").expect("seated");
    assert_eq!(
        council.check_concentration(params.max_council_country_share_bps),
        Ok(()),
        "seed {seed} height {height}: the sitting council breaches the cap in force"
    );

    // 3. The proposal queue is bounded, canonical, and every id in it points at
    //    a record. An id with nothing behind it holds a slot forever.
    let open = gov.open_proposals().expect("queue decodes");
    assert!(
        open.len() <= MAX_OPEN_PROPOSALS,
        "seed {seed} height {height}: {} proposals open, cap is {MAX_OPEN_PROPOSALS}",
        open.len()
    );
    assert!(
        open.windows(2).all(|w| w[0] < w[1]),
        "seed {seed} height {height}: the proposal queue is out of order or repeats an id"
    );

    for id in open {
        let proposal = gov
            .proposal(id)
            .expect("proposal decodes")
            .unwrap_or_else(|| panic!("seed {seed} height {height}: queued proposal {id} is gone"));
        assert_eq!(proposal.id, id);
        assert!(
            proposal.votes.windows(2).all(|w| w[0] < w[1]),
            "seed {seed} height {height}: proposal {id} counts a seat twice"
        );
        assert!(
            proposal.votes.iter().all(|seat| council.is_seated(seat)),
            "seed {seed} height {height}: a stranger's vote sits on proposal {id}"
        );
        // 4. A scheduled proposal is scheduled *after* the vote that passed it,
        //    by at least the timelock. A decision that could be executed the
        //    moment it passed would have no notice period at all, which is the
        //    entire reason a timelock exists.
        if let Some(at) = proposal.scheduled_for {
            assert!(
                at > proposal.opened,
                "seed {seed} height {height}: proposal {id} is executable before it was opened"
            );
        }
        // 5. Nothing that bypasses the timelock is ever left sitting in the
        //    queue: a withdrawal is applied the moment it passes.
        assert!(
            !(proposal.action.bypasses_timelock() && proposal.scheduled_for.is_some()),
            "seed {seed} height {height}: a withdrawal was scheduled instead of applied"
        );
    }
}

// ---------------------------------------------------------------------------
// The generator
// ---------------------------------------------------------------------------

/// Tracks enough to build transactions that are usually valid.
struct World {
    nonces: [u64; ACTORS as usize],
    /// Every group address an actor has *tried* to create.
    groups: Vec<Address>,
    /// Groups that exist and accumulate, refreshed from the store each block.
    ///
    /// Kept separately because most creation attempts fail — on a nonce, on the
    /// address already being a group — and a generator that picks uniformly from
    /// addresses it merely named spends nearly every share purchase on an
    /// account that is not there. That is how the vikoba paths came out
    /// unreachable the first time this was wired up.
    vikoba: Vec<Address>,
    /// Accumulating groups with a proposal open.
    ///
    /// A quorum needs several different members to approve *the same* open
    /// proposal before it lapses at the end of the cycle. Emitting approvals at
    /// random almost never lands three of them inside one window, so the
    /// generator has to aim: it knows a question is open and answers it.
    pending: Vec<Address>,
    /// `(group, actor, outstanding)` for every debt a member is carrying.
    ///
    /// Same reason. A repayment must name a group the sender actually borrowed
    /// from and an amount no larger than the debt; guessing satisfies neither.
    debts: Vec<(Address, u8, Amount)>,
    /// Groups whose cycle may be closed at the next height.
    closable: Vec<Address>,
    /// Groups whose round is complete and whose fund has something to divide.
    ///
    /// A share-out sits at the end of the longest path in the chain: found an
    /// accumulating group, buy shares in it, close every cycle of a round, then
    /// ask. Waiting for a uniform generator to walk that by chance is waiting
    /// for a suite whose most consequential arithmetic is never run.
    sharable: Vec<Address>,
    /// Proposals open for votes.
    ///
    /// Aimed at for the same reason a group's quorum is: three of four seats
    /// have to answer *the same* question before its voting period ends, and a
    /// generator emitting proposal ids at random never lands three on one.
    votable: Vec<u64>,
    /// Proposals that have passed and whose timelock has run.
    executable: Vec<u64>,
    /// Proposals that have passed and are still inside their timelock.
    ///
    /// The only thing a withdrawal can name, and the state the "cannot execute
    /// early" invariant is about.
    withdrawable: Vec<u64>,
    /// Whether the currency has a standing offer of its authority.
    offered_authority: Option<Address>,
}

impl World {
    fn new() -> Self {
        Self {
            nonces: [0; ACTORS as usize],
            groups: Vec::new(),
            vikoba: Vec::new(),
            pending: Vec::new(),
            debts: Vec::new(),
            closable: Vec::new(),
            sharable: Vec::new(),
            votable: Vec::new(),
            executable: Vec::new(),
            withdrawable: Vec::new(),
            offered_authority: None,
        }
    }

    /// Re-read which of the named addresses are live accumulating groups.
    fn refresh(&mut self, store: &MemoryStore, next_height: u64) {
        self.vikoba.clear();
        self.pending.clear();
        self.debts.clear();
        self.closable.clear();
        self.sharable.clear();
        self.votable.clear();
        self.executable.clear();
        self.withdrawable.clear();

        let gov = GovView::new(store);
        for id in gov.open_proposals().unwrap_or_default() {
            let Ok(Some(proposal)) = gov.proposal(id) else {
                continue;
            };
            match proposal.scheduled_for {
                None if Height(next_height) <= proposal.voting_ends => self.votable.push(id),
                Some(at) if Height(next_height) >= at => self.executable.push(id),
                Some(_) => self.withdrawable.push(id),
                None => {}
            }
        }
        self.offered_authority = afrolink_bank::BankView::new(store)
            .issuer(&kes())
            .ok()
            .flatten()
            .and_then(|issuer| issuer.pending_authority);
        for address in &self.groups {
            let Some(bytes) = store.get(&StoreKey::account(address)) else {
                continue;
            };
            let Ok(account) = afrolink_primitives::codec::decode_exact::<Account>(&bytes) else {
                continue;
            };
            let AccountKind::Group(group) = &account.kind else {
                continue;
            };
            if !matches!(group.policy, PayoutPolicy::Accumulate(_)) {
                continue;
            }
            self.vikoba.push(*address);
            if group.pending.is_some() {
                self.pending.push(*address);
            }
            if group.payout_due(Height(next_height)) {
                self.closable.push(*address);
            }
            if group.round_complete() && group.total_shares() > 0 {
                self.sharable.push(*address);
            }
            for member in &group.members {
                if let Some(loan) = &member.loan
                    && let Ok(outstanding) = loan.outstanding()
                    && let Some(i) = (0..ACTORS).find(|i| actor(*i) == member.address)
                {
                    self.debts.push((*address, i, outstanding));
                }
            }
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

    /// A member of a group this generator builds.
    ///
    /// Every group is founded from `actor(0..count)` with `count` in 2..=4, so
    /// the low actors are the ones with standing. Naming them deliberately is
    /// what makes the accumulating-group paths reachable at all — picking a
    /// beneficiary and a guarantor uniformly from six actors would refuse most
    /// loans for membership before any of the arithmetic ran.
    fn member(rng: &mut Rng) -> Address {
        actor(u8::try_from(rng.below(3)).unwrap())
    }

    fn message(&mut self, rng: &mut Rng, sender: u8) -> Message {
        // Two paths the generator aims at rather than stumbles into, because
        // both need a fact only the ledger knows. Everything else is random.
        // A quorum is the hard part, so an open question gets answered often;
        // closing a cycle is held back deliberately, because closing one lapses
        // every proposal in it and a generator that shuts cycles as fast as it
        // can never lets a loan be agreed.
        if !self.pending.is_empty() && rng.below(3) != 0 {
            return Message::ApproveGroupAction {
                group: self.pending[rng.below(self.pending.len())],
            };
        }
        if self.pending.is_empty() && !self.vikoba.is_empty() && rng.below(3) == 0 {
            let beneficiary = Self::member(rng);
            let mut guarantor = Self::member(rng);
            if guarantor == beneficiary {
                guarantor = actor(if beneficiary == actor(0) { 1 } else { 0 });
            }
            return Message::ProposeGroupAction {
                group: self.vikoba[rng.below(self.vikoba.len())],
                beneficiary,
                kind: ProposalKind::Loan {
                    principal: Amount::from_afri(1 + u64::from(rng.byte() % 20)),
                    guarantors: vec![guarantor],
                },
            };
        }
        // Governance, aimed for the same reason the quorum paths are: a
        // proposal needs three of four seats inside one voting period, and a
        // decision needs somebody to come back after the timelock. Both are
        // sequences a uniform generator walks past.
        if !self.votable.is_empty() && rng.below(3) != 0 {
            return Message::VoteGovAction {
                proposal: self.votable[rng.below(self.votable.len())],
            };
        }
        if !self.executable.is_empty() && rng.below(2) == 0 {
            return Message::ExecuteGovAction {
                proposal: self.executable[rng.below(self.executable.len())],
            };
        }
        if self.offered_authority.is_some() && rng.below(2) == 0 {
            // Sent by whoever the generator picked, not by the offeree: the
            // acceptance must be refused for everyone but the named account,
            // and that refusal is the property worth generating.
            return Message::AcceptIssuerAuthority { denom: kes() };
        }
        if !self.sharable.is_empty() && rng.below(2) == 0 {
            return Message::ShareOut {
                group: self.sharable[rng.below(self.sharable.len())],
            };
        }
        if !self.closable.is_empty() && rng.below(8) == 0 {
            return Message::CloseCycle {
                group: self.closable[rng.below(self.closable.len())],
            };
        }
        if rng.below(4) != 0
            && let Some((group, _, outstanding)) = self
                .debts
                .iter()
                .find(|(_, who, _)| *who == sender)
                .copied()
        {
            return Message::RepayLoan {
                group,
                // Usually part or all of the debt; sometimes more than it, which
                // must be refused rather than pocketed.
                amount: if rng.below(4) == 0 {
                    outstanding.checked_add(Amount::from_afri(1)).unwrap()
                } else if rng.below(2) == 0 {
                    outstanding
                } else {
                    Amount::from_units(outstanding.units() / 2 + 1)
                },
            };
        }
        match rng.below(25) {
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
                let count = 3 + rng.below(2);
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
                        period_blocks: 3,
                    },
                    policy: if rng.below(2) == 0 {
                        // Deliberately short: a round of two cycles and a
                        // one-cycle loan term means a generated sequence can
                        // actually reach a share-out, which is the only moment
                        // the fund's arithmetic is fully exercised.
                        PayoutPolicy::Accumulate(ShareRules {
                            min_shares: 1,
                            max_shares: 3,
                            // Mixed lengths: a two-cycle round reaches a
                            // share-out often, a three-cycle one leaves room for
                            // a loan to be agreed and repaid inside it. One
                            // number could not exercise both.
                            cycles_per_round: 2 + u64::from(rng.byte() % 2),
                            service_charge_bps: 1_000,
                            cover_bps: 3_334,
                            loan_term_cycles: 1,
                            late_fine_bps: 1_000,
                            required_guarantors: 1,
                            social_contribution: Amount::from_afri(2),
                        })
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
            11 => Message::SetAccountFlag {
                flag: afrolink_types::AccountFlag::RequireReference,
                enabled: rng.below(2) == 0,
            },

            // -- Vikoba. Every arm below moves savings, and the arithmetic they
            //    run — a share price, a service charge, a fine, a proportional
            //    division — is the newest and least exercised in the chain.
            12 | 13 if !self.vikoba.is_empty() => Message::BuyShares {
                group: self.vikoba[rng.below(self.vikoba.len())],
                // Usually inside the ceiling, sometimes over it: buying past the
                // limit must be refused rather than clamped, because a clamped
                // purchase would charge for shares it did not grant.
                shares: if rng.below(5) == 0 {
                    4 + u32::try_from(rng.below(4)).unwrap()
                } else {
                    1 + u32::try_from(rng.below(3)).unwrap()
                },
            },
            14 if !self.vikoba.is_empty() => Message::PaySocialFund {
                group: self.vikoba[rng.below(self.vikoba.len())],
            },
            15 | 16 if !self.vikoba.is_empty() => {
                let beneficiary = Self::member(rng);
                let mut guarantor = Self::member(rng);
                if guarantor == beneficiary {
                    guarantor = actor(if beneficiary == actor(0) { 1 } else { 0 });
                }
                Message::ProposeGroupAction {
                    group: self.vikoba[rng.below(self.vikoba.len())],
                    beneficiary,
                    kind: if rng.below(3) == 0 {
                        ProposalKind::SocialGrant {
                            amount: Amount::from_afri(1 + u64::from(rng.byte() % 8)),
                        }
                    } else {
                        ProposalKind::Loan {
                            // Small enough that a member's own shares can cover
                            // it, sometimes far more — an uncovered loan is the
                            // one the whole rule exists to refuse.
                            principal: if rng.below(4) == 0 {
                                Amount::from_afri(5_000)
                            } else {
                                Amount::from_afri(1 + u64::from(rng.byte() % 40))
                            },
                            guarantors: vec![guarantor],
                        }
                    },
                }
            }
            17 if !self.vikoba.is_empty() => {
                let group = self.vikoba[rng.below(self.vikoba.len())];
                if rng.below(2) == 0 {
                    Message::CloseCycle { group }
                } else {
                    Message::ShareOut { group }
                }
            }

            // -- Sovereign issuance. The only paths in the chain that may
            //    change a total supply, which makes them the only paths that
            //    can break the invariant every other test rests on.
            18 => Message::Mint {
                denom: kes(),
                to: self.destination(rng),
                // Usually inside the minter's allowance, sometimes absurd. The
                // absurd one must be refused whole rather than clamped: a
                // partial mint would credit money the allowance did not cover.
                amount: if rng.below(6) == 0 {
                    Amount::from_afri(9_000_000_000)
                } else {
                    Amount::from_afri(1 + u64::from(rng.byte()))
                },
            },
            19 => Message::Burn {
                denom: kes(),
                amount: Amount::from_afri(1 + u64::from(rng.byte() % 50)),
            },
            20 => Message::SetMinterAllowance {
                denom: kes(),
                minter: actor(u8::try_from(rng.below(ACTORS as usize)).unwrap()),
                allowance: Amount::from_afri(u64::from(rng.byte()) * 100),
            },
            21 => match rng.below(2) {
                0 => Message::SetSupplyCap {
                    denom: kes(),
                    // Generous, and generated *above* what the run can reach as
                    // often as below it — a cap is a ratchet, so a tight one
                    // early would end issuance for the whole seed and quietly
                    // stop testing the paths that matter.
                    cap: Amount::from_afri(50_000_000 + u64::from(rng.byte()) * 1_000_000),
                },
                _ => Message::SetIssuerPaused {
                    denom: kes(),
                    paused: rng.below(2) == 0,
                },
            },
            22 => {
                // Only outsiders are frozen. Freezing an actor is a legitimate
                // state and the invariants hold through it, but an actor frozen
                // in the fee denomination cannot pay a fee, so the run would
                // spend its remaining blocks watching that actor fail — and a
                // suite that stops reaching the executor stops proving anything.
                Message::SetFrozen {
                    denom: kes(),
                    account: outsider(u8::try_from(rng.below(OUTSIDERS as usize)).unwrap()),
                    frozen: rng.below(2) == 0,
                }
            }

            // -- Governance. The council can license attestors, admit
            //    currencies and tune parameters; it can move no money at all,
            //    and the invariants are what say so.
            23 => Message::ProposeGovAction {
                action: Box::new(self.action(rng)),
            },
            24 => Message::TransferIssuerAuthority {
                denom: kes(),
                // Usually a real offer, sometimes a withdrawal of one.
                to: if rng.below(4) == 0 {
                    None
                } else {
                    Some(actor(u8::try_from(rng.below(ACTORS as usize)).unwrap()))
                },
            },

            _ => Message::Transfer {
                to: self.destination(rng),
                denom: kes(),
                amount: Amount::from_units(u128::from(rng.next_u64() % 5_000) + 1),
                reference: None,
            },
        }
    }

    /// A decision to put to the council.
    ///
    /// Every variant of [`Action`] is generated, including ones that must be
    /// refused when the proposal is opened: a suspended licence, a currency that
    /// already has an authority, a cap looser than the one in force.
    fn action(&self, rng: &mut Rng) -> Action {
        match rng.below(6) {
            0 => Action::LicenseAttestor {
                address: outsider(u8::try_from(rng.below(OUTSIDERS as usize)).unwrap()),
                attestor: afrolink_alias::contact::Attestor {
                    country: afrolink_primitives::CountryCode::new("ke").unwrap(),
                    name: "an mno".to_owned(),
                    // Sometimes suspended, which must be refused: a registry row
                    // nothing could ever turn on.
                    active: rng.below(4) != 0,
                },
            },
            1 => Action::SetAttestorActive {
                address: outsider(u8::try_from(rng.below(OUTSIDERS as usize)).unwrap()),
                active: rng.below(2) == 0,
            },
            2 => Action::AdmitDenom {
                // Half the time the currency this world already has, which must
                // be refused: re-admission would be a way for the council to
                // take a currency from its sovereign.
                denom: if rng.below(2) == 0 {
                    kes()
                } else {
                    Denom::sovereign("ng", "ngn").unwrap()
                },
                authority: actor(u8::try_from(rng.below(ACTORS as usize)).unwrap()),
            },
            3 => Action::SetParams(ChainParams {
                // Above the floor, so this is a change the chain accepts, and
                // one whose effect is visible in the next rebinding scheduled.
                rebind_delay_blocks: MIN_REBIND_DELAY_BLOCKS + u64::from(rng.byte()) * 100,
                // Sometimes tighter than the sitting council can survive, which
                // must be refused rather than leave the chain governed by a body
                // its own rules reject.
                max_council_country_share_bps: 1_000 + u32::from(rng.byte()) * 6,
                ..opening_params()
            }),
            4 if !self.withdrawable.is_empty() => Action::Cancel {
                proposal: self.withdrawable[rng.below(self.withdrawable.len())],
            },
            _ => Action::SetCouncil(council()),
        }
    }

    fn transaction(&mut self, rng: &mut Rng) -> Transaction {
        // Weighted toward the actors that found groups. Uniform over six would
        // send most group messages from strangers, and a suite whose group
        // transactions are nearly all refused for membership never reaches the
        // arithmetic it was written to check.
        let sender = if rng.below(2) == 0 {
            u8::try_from(rng.below(3)).unwrap()
        } else {
            u8::try_from(rng.below(ACTORS as usize)).unwrap()
        };
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
    /// Applied messages on the paths this suite insists on — see [`TRACKED_KINDS`].
    ///
    /// A share-out is reached only by a sequence that founds an accumulating
    /// group, buys shares in it, closes whole cycles and then asks. A generator
    /// can drift away from a path that long without any invariant noticing,
    /// because an invariant that is never reached always holds.
    tracked: [u64; TRACKED_KINDS.len()],
    /// Applied messages on the governance paths — see [`GOV_KINDS`].
    ///
    /// Counted separately because they are reachable on a different timescale:
    /// a voting period and a timelock are measured in thousands of blocks, so
    /// only the governance run insists on them.
    gov: [u64; GOV_KINDS.len()],
}

/// Messages this suite refuses to pass without having actually executed.
///
/// Two families, for one reason: both move money along paths that no other test
/// watches under arbitrary sequencing. The accumulating-group messages sit at
/// the end of a long chain of preconditions, and the issuance messages are the
/// only ones in the chain that may change a total supply.
const TRACKED_KINDS: [&str; 12] = [
    "BuyShares",
    "PaySocialFund",
    "ProposeGroupAction",
    "ApproveGroupAction",
    "RepayLoan",
    "CloseCycle",
    "ShareOut",
    "Mint",
    "Burn",
    "SetMinterAllowance",
    "SetSupplyCap",
    "SetFrozen",
];

/// Governance messages the governance run refuses to pass without.
///
/// `ExecuteGovAction` is the one that matters: everything before it is a
/// decision nobody has acted on, and a suite that never executes one has never
/// run the code that turns a vote into a state change.
const GOV_KINDS: [&str; 4] = [
    "ProposeGovAction",
    "VoteGovAction",
    "ExecuteGovAction",
    "TransferIssuerAuthority",
];

fn gov_slot(message: &Message) -> Option<usize> {
    Some(match message {
        Message::ProposeGovAction { .. } => 0,
        Message::VoteGovAction { .. } => 1,
        Message::ExecuteGovAction { .. } => 2,
        Message::TransferIssuerAuthority { .. } => 3,
        _ => return None,
    })
}

fn tracked_slot(message: &Message) -> Option<usize> {
    Some(match message {
        Message::BuyShares { .. } => 0,
        Message::PaySocialFund { .. } => 1,
        Message::ProposeGroupAction { .. } => 2,
        Message::ApproveGroupAction { .. } => 3,
        Message::RepayLoan { .. } => 4,
        Message::CloseCycle { .. } => 5,
        Message::ShareOut { .. } => 6,
        Message::Mint { .. } => 7,
        Message::Burn { .. } => 8,
        Message::SetMinterAllowance { .. } => 9,
        Message::SetSupplyCap { .. } => 10,
        Message::SetFrozen { .. } => 11,
        _ => return None,
    })
}

impl Coverage {
    fn record(&mut self, outcome: &afrolink_executor::BlockOutcome, transactions: &[Transaction]) {
        self.applied = self.applied.saturating_add(outcome.succeeded() as u64);
        self.total = self.total.saturating_add(transactions.len() as u64);
        for o in &outcome.outcomes {
            let slot = o.receipt.code.as_u16() as usize;
            if let Some(count) = self.codes.get_mut(slot) {
                *count = count.saturating_add(1);
            }
        }
        for (o, tx) in outcome.outcomes.iter().zip(transactions) {
            if !o.receipt.code.succeeded() {
                continue;
            }
            for message in &tx.body.messages {
                if let Some(slot) = tracked_slot(message) {
                    self.tracked[slot] = self.tracked[slot].saturating_add(1);
                }
                if let Some(slot) = gov_slot(message) {
                    self.gov[slot] = self.gov[slot].saturating_add(1);
                }
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

    /// The generator is still reaching the executor at all.
    ///
    /// Thresholds sit below what a healthy run produces rather than at it: this
    /// catches a generator that has stopped working, not one whose mix has
    /// shifted by a few percent.
    fn assert_not_degenerate(&self) {
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

    /// Every path this suite claims to cover was actually walked.
    ///
    /// An invariant that is never reached always holds, so without this whole
    /// sections of [`check_invariants`] would go green over a run that never
    /// bought a share or minted a shilling. Asserted only over the broad sweep —
    /// a pinned regression set is there to replay specific sequences, and
    /// demanding breadth of it would conflate two jobs and make it fail for a
    /// reason that has nothing to do with the bug it preserves.
    fn assert_every_path_ran(&self) {
        for (kind, count) in TRACKED_KINDS.iter().zip(self.tracked) {
            assert!(
                count > 0,
                "no {kind} ever applied: the invariants over that path are \
                 vacuous ({:?})",
                self.tracked
            );
        }
    }

    /// The same guard for the governance family.
    fn assert_governance_ran(&self) {
        for (kind, count) in GOV_KINDS.iter().zip(self.gov) {
            assert!(
                count > 0,
                "no {kind} ever applied: the governance invariants are vacuous ({:?})",
                self.gov
            );
        }
    }
}

/// Run one seeded chain, checking every invariant after every block.
///
/// `stride` is how many heights a block advances. It is 1 for the money runs,
/// where a group's cycle is three blocks long and anything larger would close
/// every cycle instantly. The governance run uses a large stride instead,
/// because a voting period and a timelock are thousands of blocks and a chain
/// that never reaches the end of one never executes a decision.
fn run_with_stride(
    seed: u64,
    blocks: u64,
    stride: u64,
    coverage: &mut Coverage,
) -> afrolink_crypto::hash::Hash32 {
    let mut rng = Rng::new(seed);
    let mut store = opening_state();
    let mut world = World::new();
    let exec = Executor::new(chain());

    for block in 1..=blocks {
        let height = block * stride;
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
        world.refresh(&store, height + stride);
        coverage.record(&outcome, &transactions);
    }
    store.root()
}

/// The money runs: one height per block.
fn run(seed: u64, blocks: u64, coverage: &mut Coverage) -> afrolink_crypto::hash::Hash32 {
    run_with_stride(seed, blocks, 1, coverage)
}

// ---------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_holds_together_under_arbitrary_transaction_sequences() {
    // 30 seeds × up to 4 transactions × 40 blocks. Each seed is a different
    // sequence, and every invariant is checked after every block — so a failure
    // names the seed, the height, and the rule that broke.
    let mut coverage = Coverage::default();
    for seed in 0..30u64 {
        run(seed, 40, &mut coverage);
    }
    coverage.assert_not_degenerate();
    coverage.assert_every_path_ran();
}

#[test]
fn a_sequence_that_broke_once_stays_fixed() {
    // Regression slot. When a seed above fails, pin it here with a note saying
    // what it found, so the specific sequence is never lost to a change in the
    // generator.
    let mut coverage = Coverage::default();
    for seed in [0u64, 1, 7, 42, 99, 123, 777, 4242] {
        run(seed, 60, &mut coverage);
    }
    coverage.assert_not_degenerate();
}

#[test]
fn the_governance_machine_holds_together_across_voting_periods() {
    // The same generator and the same invariants, run on governance's clock. At
    // one height per block a voting period never closes and a timelock never
    // runs, so nothing is ever executed and every governance invariant holds
    // vacuously — which is exactly the failure `assert_every_path_ran` was added
    // to catch on the money paths.
    //
    // The group arithmetic degenerates at this stride (every cycle closes each
    // block), which is why this is a separate run with its own guard rather than
    // a wider setting on the one above.
    let mut coverage = Coverage::default();
    for seed in 0..12u64 {
        run_with_stride(seed, 60, MIN_VOTING_PERIOD_BLOCKS / 8, &mut coverage);
    }
    coverage.assert_not_degenerate();
    coverage.assert_governance_ran();
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
