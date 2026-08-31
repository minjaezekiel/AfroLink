//! Group accounts — chama, susu, stokvel, tontine, equb, ajo, VSLA.
//!
//! See [ADR-0005](../../../docs/adr/0005-african-first-design.md). This is a
//! **native account type**, not a smart contract, because rotating savings
//! associations are how a very large share of the continent actually saves and
//! borrows, and modelling them as a multi-signature wallet throws away
//! everything that makes them work.
//!
//! A multisig expresses *joint custody*: N of M keys authorise a spend. A chama
//! has a contribution schedule, a rotation order, a treasurer, joining and exit
//! rules, and a member-by-member record of who paid on time. That record is the
//! most valuable thing here — for someone with no credit bureau file, a
//! multi-year history of honoured contributions is the best creditworthiness
//! signal that exists, and on this network it belongs to the member rather than
//! to an operator's database.
//!
//! # Two instruments, not one
//!
//! [`PayoutPolicy`] is the fork, and the two branches are genuinely different
//! financial products rather than settings on one.
//!
//! [`PayoutPolicy::Rotation`] is *upatu* or *mchezo* in Tanzania, a chama in
//! Kenya: everyone pays the same fixed sum each cycle and the whole pot goes to
//! one member in turn. It **redistributes** — what one member takes, the others
//! paid in, and the total never grows.
//!
//! [`PayoutPolicy::Accumulate`] is *vikoba* — Village Community Banking, the
//! VSLA methodology. Members buy **shares**; the savings are **lent to members**
//! at a service charge; and at the end of a round the fund is divided **in
//! proportion to shares**. It **earns**: the charge a borrower pays returns to
//! the fund every member owns a share of, so a member takes out more than they
//! put in. It also carries a separate **social fund** — a flat premium, equal
//! for everyone, spent on a funeral or an illness — which is insurance rather
//! than saving and is therefore neither lent nor shared out.
//!
//! Modelling the second as a variation on the first would throw away the part
//! that makes it banking. See
//! [ADR-0019](../../../docs/adr/0019-vikoba-accumulating-savings.md).

use afrolink_crypto::Address;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Amount, Denom, Height};
use thiserror::Error;

/// Most members one group may hold.
///
/// A bound rather than a preference. Every founding member is filed in the
/// transaction's `touched_addresses`, and being filed **creates an account
/// record** — so without a cap, one fee buys unbounded state written for
/// addresses that never asked to be named
/// ([ADR-0015](../../../docs/adr/0015-committed-outcomes-and-provable-history.md)
/// states the property this protects).
///
/// 100 is far above any real savings group: a VSLA is 15–30 people by design,
/// because the model depends on members knowing one another.
pub const MAX_GROUP_MEMBERS: usize = 100;

/// Most shares one member may buy in a single cycle, whatever the group agrees.
///
/// The VSLA methodology says one to five. The ceiling here is deliberately
/// looser than practice and exists for a different reason: the share-out divides
/// the fund *in proportion to shares*, so an unbounded per-cycle purchase would
/// let one member's stake grow without limit relative to members who cannot
/// afford to match it — which is the failure the 1-to-5 rule was invented to
/// prevent.
pub const MAX_SHARES_PER_CYCLE: u32 = 10;

/// One hundred percent, in basis points.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Errors from group account operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GroupError {
    /// Fewer than two members. A group of one is not a group.
    #[error("a group needs at least 2 members, got {0}")]
    TooFewMembers(usize),
    /// The same address appears twice in the membership.
    #[error("duplicate member in group")]
    DuplicateMember,
    /// No member holds the treasurer role.
    #[error("a group must have exactly one treasurer, found {0}")]
    TreasurerCount(usize),
    /// The rotation order is not a permutation of the membership.
    #[error("rotation order must list every member exactly once")]
    InvalidRotationOrder,
    /// A quorum with a zero denominator, or requiring more than everyone.
    #[error("invalid quorum {numerator}/{denominator}")]
    InvalidQuorum {
        /// Required share numerator.
        numerator: u32,
        /// Required share denominator.
        denominator: u32,
    },
    /// The named address is not a member of this group.
    #[error("address is not a member of this group")]
    NotAMember,
    /// The contribution amount was zero.
    #[error("contribution amount must be greater than zero")]
    ZeroContribution,
    /// The group name was empty or too long.
    #[error("group name must be 1..=64 bytes")]
    InvalidName,
    /// More than [`MAX_GROUP_MEMBERS`].
    #[error("a group may hold at most {MAX_GROUP_MEMBERS} members, got {0}")]
    TooManyMembers(usize),
    /// A second contribution in one cycle.
    ///
    /// Not merely redundant: crediting it would let a member buy reliability
    /// they did not earn, and the record is what a lender reads.
    #[error("this member has already contributed for this cycle")]
    AlreadyContributed,
    /// The amount offered is not the amount the group agreed.
    #[error("this group's contribution is {expected}, not {got}")]
    WrongContributionAmount {
        /// What the group agreed.
        expected: String,
        /// What was offered.
        got: String,
    },
    /// A payout was requested before the cycle was due.
    #[error("the cycle is not due: not every member has paid and the period has not elapsed")]
    CycleNotDue,
    /// A payout was requested with nothing to pay out.
    #[error("there is nothing in the pot to pay out")]
    EmptyPot,

    // -- Accumulating groups: shares, loans, the social fund -----------------
    /// A share operation on a group whose pot rotates instead.
    #[error("this group rotates its pot and does not sell shares")]
    NotAccumulating,
    /// A rotation operation on a group whose fund accumulates instead.
    #[error("this group accumulates its fund and has no rotation")]
    NotRotating,
    /// The share rules a group was created with do not hold together.
    #[error("invalid share rules: {0}")]
    InvalidShareRules(&'static str),
    /// A purchase of zero shares.
    #[error("a share purchase must be at least one share")]
    ZeroShares,
    /// More shares than the group allows in one cycle.
    #[error("this group allows at most {max} shares per cycle; that would make {requested}")]
    ShareLimit {
        /// The group's per-cycle ceiling.
        max: u32,
        /// What the purchase would bring the member's cycle total to.
        requested: u32,
    },
    /// A member with a loan outstanding asked for another.
    #[error("this member already has a loan outstanding")]
    AlreadyBorrowing,
    /// The borrower's own savings do not cover the required share of the loan.
    #[error("this loan needs {required} of the borrower's own savings behind it, they hold {held}")]
    InsufficientCover {
        /// Savings the group's rules require.
        required: String,
        /// Savings the borrower actually holds.
        held: String,
    },
    /// The loan fund does not hold the principal.
    ///
    /// Distinct from an ordinary insufficient balance: the group's balance also
    /// carries the social fund, which is not lendable.
    #[error("the loan fund does not hold enough to advance this loan")]
    LoanFundShort,
    /// A repayment against a member with no loan.
    #[error("this member has no loan outstanding")]
    NoLoan,
    /// A repayment larger than the debt.
    ///
    /// Refused rather than truncated: a group is not a place to leave a tip, and
    /// silently keeping the excess would be the group taking money nobody voted
    /// to take.
    #[error("that is more than the {owed} still owed")]
    Overpayment {
        /// What remains to be repaid.
        owed: String,
    },
    /// A guarantor who is not a member, or is the borrower, or is repeated.
    #[error("a guarantor must be another member of the group, named once")]
    BadGuarantor,
    /// The wrong number of guarantors.
    #[error("this group requires {need} guarantors, got {got}")]
    GuarantorCount {
        /// What the group's rules require.
        need: u32,
        /// What was offered.
        got: u32,
    },
    /// A second proposal while one is still open.
    ///
    /// One at a time, because a real group decides loans one at a time at a
    /// meeting — and because a hundred members each holding an open proposal is
    /// unbounded state bought with one fee.
    #[error("this group already has a proposal open")]
    ProposalPending,
    /// An approval, or a withdrawal, with no proposal open.
    #[error("this group has no proposal open")]
    NoProposal,
    /// A member approving twice.
    #[error("this member has already approved the open proposal")]
    AlreadyApproved,
    /// A loan whose term would run past the share-out that settles it.
    ///
    /// A real VSLA stops lending in the weeks before a share-out for exactly
    /// this reason, and the reason is not tidiness: a loan still outstanding
    /// when the round closes is settled against the borrower's savings and
    /// recorded as a **default** — so granting it would be the group punishing a
    /// member for a term the group itself agreed to.
    #[error("this loan would fall due in cycle {due} but the round closes at {round_ends}")]
    TooLateInRound {
        /// When the debt would be due.
        due: u64,
        /// When the round closes.
        round_ends: u64,
    },
    /// A share-out before the round is over.
    #[error("the savings round is not complete: {done} of {needed} cycles")]
    RoundNotComplete {
        /// Cycles closed so far this round.
        done: u64,
        /// Cycles the group agreed to run.
        needed: u64,
    },
    /// A grant larger than the social fund holds.
    #[error("the social fund does not hold that much")]
    SocialFundShort,
    /// A share-out of a fund that holds nothing.
    #[error("there is nothing in the fund to share out")]
    EmptyFund,
    /// Nobody bought a share this round, so there is no denominator to divide by.
    #[error("no shares were bought this round")]
    NoShares,
    /// Arithmetic on amounts overflowed.
    #[error("group arithmetic overflowed")]
    Overflow,
}

/// A member's role within the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Holds operational responsibility for the pot. Exactly one per group.
    Treasurer,
    /// An ordinary contributing member.
    Member,
}

/// A member as named at group creation, before any history exists.
///
/// A named struct rather than an `(Address, Role)` tuple so the wire format has
/// one obvious meaning and cannot be silently reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundingMember {
    /// The prospective member's account.
    pub address: Address,
    /// The role they take on.
    pub role: Role,
}

impl FoundingMember {
    /// Name a founding member.
    #[must_use]
    pub const fn new(address: Address, role: Role) -> Self {
        Self { address, role }
    }

    /// Promote to a full [`Member`] record joining at `cycle`.
    #[must_use]
    pub fn into_member(self, cycle: u64) -> Member {
        Member::new(self.address, self.role, cycle)
    }
}

impl Encode for FoundingMember {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.role.encode(out);
    }
}

impl Decode for FoundingMember {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            role: Role::decode(r)?,
        })
    }
}

/// One member and their standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The member's account.
    pub address: Address,
    /// Their role.
    pub role: Role,
    /// Cycle number at which they joined.
    pub joined_cycle: u64,
    /// Contributions made on time.
    pub contributions_made: u64,
    /// Contributions missed.
    pub contributions_missed: u64,
    /// The cycle this member last paid into, if any.
    ///
    /// Cumulative counters cannot answer *"has this member paid for the cycle
    /// now open?"* — which is the only question that decides whether a payout
    /// is due, and whether a second payment is a duplicate.
    pub last_paid_cycle: Option<u64>,

    // -- Accumulating groups only --------------------------------------------
    /// Shares held in the round now open.
    ///
    /// The share-out divides the fund in proportion to this, so it *is* the
    /// member's claim on the group. Reset to zero when the round is shared out.
    pub shares: u64,
    /// Shares bought in the cycle now open, against the per-cycle ceiling.
    pub shares_this_cycle: u32,
    /// The loan this member is carrying, if any.
    pub loan: Option<Loan>,
    /// Fines accrued and not yet settled.
    ///
    /// Never collected as a payment. It is deducted from the member's share-out,
    /// which is the only moment a group reliably has the money in hand — the
    /// same reason a real VSLA settles fines against savings rather than
    /// chasing them.
    pub fines_owed: Amount,
    /// The cycle this member last paid the social contribution into.
    pub social_paid_cycle: Option<u64>,
    /// Loans repaid in full, across every round.
    pub loans_repaid: u64,
    /// Loans that reached a share-out unpaid and were settled against savings.
    pub loans_defaulted: u64,
}

impl Member {
    /// A new member joining at `cycle` with a clean record.
    #[must_use]
    pub fn new(address: Address, role: Role, cycle: u64) -> Self {
        Self {
            address,
            role,
            joined_cycle: cycle,
            contributions_made: 0,
            contributions_missed: 0,
            last_paid_cycle: None,
            shares: 0,
            shares_this_cycle: 0,
            loan: None,
            fines_owed: Amount::ZERO,
            social_paid_cycle: None,
            loans_repaid: 0,
            loans_defaulted: 0,
        }
    }

    /// Whether this member has already paid into `cycle`.
    #[must_use]
    pub fn has_paid(&self, cycle: u64) -> bool {
        self.last_paid_cycle == Some(cycle)
    }

    /// Whether this member has paid the social contribution for `cycle`.
    #[must_use]
    pub fn has_paid_social(&self, cycle: u64) -> bool {
        self.social_paid_cycle == Some(cycle)
    }

    /// Everything this member owes the group: loan balance plus unsettled fines.
    ///
    /// # Errors
    /// Returns [`GroupError::Overflow`] if the sum wraps.
    pub fn owed(&self) -> Result<Amount, GroupError> {
        let loan = self
            .loan
            .as_ref()
            .map_or(Ok(Amount::ZERO), Loan::outstanding)?;
        loan.checked_add(self.fines_owed)
            .map_err(|_| GroupError::Overflow)
    }

    /// Loans this member has finished, one way or the other.
    #[must_use]
    pub fn loans_concluded(&self) -> u64 {
        self.loans_repaid.saturating_add(self.loans_defaulted)
    }

    /// Share of loans repaid rather than defaulted, in basis points.
    ///
    /// The borrowing counterpart to [`Self::reliability_bps`], and the number a
    /// lender outside the group actually wants: paying into a pot proves
    /// discipline, but repaying a loan proves the thing being predicted.
    /// `None` for a member who has never borrowed — which is not the same as a
    /// member who has never defaulted.
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "`concluded` is checked non-zero immediately above, and the multiplication saturates"
    )]
    pub fn repayment_bps(&self) -> Option<u32> {
        let concluded = self.loans_concluded();
        if concluded == 0 {
            return None;
        }
        let bps = self.loans_repaid.saturating_mul(10_000) / concluded;
        u32::try_from(bps).ok()
    }

    /// Contributions this member was due, on time or not.
    #[must_use]
    pub fn contributions_due(&self) -> u64 {
        self.contributions_made
            .saturating_add(self.contributions_missed)
    }

    /// On-time contribution rate in basis points (0–10,000).
    ///
    /// Returns `None` for a member with no obligations yet, which is different
    /// from a member with a perfect record and must not be reported as 100%.
    /// This is the portable credit signal described in ADR-0005 §C.
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "`due` is checked non-zero immediately above, and the multiplication saturates"
    )]
    pub fn reliability_bps(&self) -> Option<u32> {
        let due = self.contributions_due();
        if due == 0 {
            return None;
        }
        let bps = self.contributions_made.saturating_mul(10_000) / due;
        u32::try_from(bps).ok()
    }
}

/// A loan advanced to a member out of the group's own fund.
///
/// The service charge is computed **once, at issue, on the principal**, and does
/// not compound. That is not a simplification — it is how a VICOBA quotes a
/// loan ("10% of what you borrow"), and a member who cannot read a repayment
/// schedule can still check a single number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loan {
    /// What was advanced.
    pub principal: Amount,
    /// The group's charge on top, fixed at issue.
    ///
    /// This is the group's *earnings*: it returns to the fund and is shared out
    /// in proportion to shares, so the interest a borrower pays is income to
    /// every member including themselves.
    pub service_charge: Amount,
    /// Repaid so far, against principal and charge together.
    pub repaid: Amount,
    /// The cycle by which the whole debt must be settled.
    pub due_cycle: u64,
    /// Members who stood behind this loan.
    ///
    /// Recorded rather than enforced: the chain cannot make a guarantor pay, and
    /// pretending otherwise would be worse than naming the limit. What it *can*
    /// do is make the guarantee a matter of public record, which is precisely
    /// the sanction a real group relies on.
    pub guarantors: Vec<Address>,
    /// Whether the late fine has already been levied.
    ///
    /// Once, not once per cycle: the group agreed a fine on the debt, not a
    /// second interest rate that grows while a member is struggling.
    pub fined: bool,
}

impl Loan {
    /// What remains to be repaid.
    ///
    /// # Errors
    /// Returns [`GroupError::Overflow`] if the total wraps.
    pub fn outstanding(&self) -> Result<Amount, GroupError> {
        let total = self
            .principal
            .checked_add(self.service_charge)
            .map_err(|_| GroupError::Overflow)?;
        Ok(Amount::from_units(
            total.units().saturating_sub(self.repaid.units()),
        ))
    }

    /// Whether the debt is settled in full.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.outstanding().is_ok_and(Amount::is_zero)
    }

    /// Whether the loan is past its due cycle and still unpaid.
    #[must_use]
    pub fn is_overdue(&self, cycle: u64) -> bool {
        cycle >= self.due_cycle && !self.is_settled()
    }
}

/// The constitution of an accumulating group: how members save, borrow and earn.
///
/// Every field here is a rule a real VICOBA writes into its own constitution and
/// signs. None of them is a protocol constant, because groups genuinely differ —
/// a weekly urban group and a seasonal farming group agree different numbers for
/// the same reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRules {
    /// Fewest shares a member must buy each cycle to be counted as having paid.
    pub min_shares: u32,
    /// Most a member may buy in one cycle. The VSLA standard is five.
    ///
    /// A ceiling rather than a preference: without it the wealthiest member
    /// takes an unbounded share of a fund the whole group's repayments built.
    pub max_shares: u32,
    /// Cycles in one savings round, after which the fund is shared out.
    ///
    /// The second clock. `period_blocks` says how often a meeting falls; this
    /// says how many meetings make a year. Nine to twelve months is the norm.
    pub cycles_per_round: u64,
    /// The group's charge on a loan, in basis points of the principal.
    pub service_charge_bps: u32,
    /// Share of a loan the borrower's own savings must already cover.
    ///
    /// The one-third rule, in basis points. It is what makes a member's savings
    /// their collateral, and it is why a group can lend without any court.
    pub cover_bps: u32,
    /// Cycles a borrower has to repay.
    pub loan_term_cycles: u64,
    /// Fine on an overdue debt, in basis points of what is outstanding.
    pub late_fine_bps: u32,
    /// How many other members must stand behind a loan.
    pub required_guarantors: u32,
    /// Flat contribution to the social fund each cycle.
    ///
    /// The same for everyone, unlike shares — this is insurance, not saving, and
    /// an equal premium is what makes it insurance. Zero is allowed: the
    /// methodology says a group *may* decide to have one.
    pub social_contribution: Amount,
}

impl ShareRules {
    /// Check the rules hold together.
    ///
    /// # Errors
    /// Returns [`GroupError::InvalidShareRules`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), GroupError> {
        if self.min_shares == 0 {
            return Err(GroupError::InvalidShareRules(
                "a member must buy at least one share per cycle",
            ));
        }
        if self.max_shares < self.min_shares {
            return Err(GroupError::InvalidShareRules(
                "the share ceiling is below the floor",
            ));
        }
        if self.max_shares > MAX_SHARES_PER_CYCLE {
            return Err(GroupError::InvalidShareRules(
                "the share ceiling exceeds the protocol maximum",
            ));
        }
        if self.cycles_per_round == 0 {
            return Err(GroupError::InvalidShareRules(
                "a round must run at least one cycle",
            ));
        }
        if self.loan_term_cycles == 0 {
            return Err(GroupError::InvalidShareRules(
                "a loan must have at least one cycle to run",
            ));
        }
        // A loan that outlives the round it was made in would still be
        // outstanding at the share-out, so it would be settled against the
        // borrower's savings as a default — punishing a member for a term the
        // group itself agreed. The rules must not be able to promise that.
        if self.loan_term_cycles > self.cycles_per_round {
            return Err(GroupError::InvalidShareRules(
                "a loan term cannot outlast the round it is made in",
            ));
        }
        if self.service_charge_bps > BPS_DENOMINATOR {
            return Err(GroupError::InvalidShareRules(
                "a service charge above 100% of principal",
            ));
        }
        if self.late_fine_bps > BPS_DENOMINATOR {
            return Err(GroupError::InvalidShareRules(
                "a late fine above 100% of the debt",
            ));
        }
        if self.cover_bps == 0 || self.cover_bps > BPS_DENOMINATOR {
            return Err(GroupError::InvalidShareRules(
                "loan cover must be between 1 basis point and 100%",
            ));
        }
        Ok(())
    }

    /// The VICOBA defaults the research describes: 1–5 shares, twelve monthly
    /// cycles, 10% service charge, one-third cover, a three-cycle term, a 10%
    /// late fine and two guarantors.
    #[must_use]
    pub fn vicoba(social_contribution: Amount) -> Self {
        Self {
            min_shares: 1,
            max_shares: 5,
            cycles_per_round: 12,
            service_charge_bps: 1_000,
            cover_bps: 3_334,
            loan_term_cycles: 3,
            late_fine_bps: 1_000,
            required_guarantors: 2,
            social_contribution,
        }
    }

    /// The charge this group would levy on `principal`.
    ///
    /// # Errors
    /// Returns [`GroupError::Overflow`] if the product wraps.
    pub fn service_charge_on(&self, principal: Amount) -> Result<Amount, GroupError> {
        principal
            .mul_ratio(
                u128::from(self.service_charge_bps),
                u128::from(BPS_DENOMINATOR),
            )
            .map_err(|_| GroupError::Overflow)
    }

    /// The savings a borrower must already hold to be advanced `principal`.
    ///
    /// # Errors
    /// Returns [`GroupError::Overflow`] if the product wraps.
    pub fn cover_required_for(&self, principal: Amount) -> Result<Amount, GroupError> {
        principal
            .mul_ratio(u128::from(self.cover_bps), u128::from(BPS_DENOMINATOR))
            .map_err(|_| GroupError::Overflow)
    }
}

/// What a group is being asked to agree to.
///
/// Both kinds move money out of the fund to one member, which is exactly the
/// class of act [`Quorum`] was always documented to govern and never did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalKind {
    /// Advance a loan from the savings fund.
    Loan {
        /// How much to advance.
        principal: Amount,
        /// Members standing behind it.
        guarantors: Vec<Address>,
    },
    /// Pay out of the social fund — a funeral, an illness, a school fee.
    ///
    /// No repayment and no service charge. That is the difference between the
    /// two funds, and the reason they cannot share one balance.
    SocialGrant {
        /// How much to grant.
        amount: Amount,
    },
}

/// An open question before the group, and who has said yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Who receives the money if it passes.
    pub beneficiary: Address,
    /// What is being asked.
    pub kind: ProposalKind,
    /// Members who have approved, sorted and unique.
    ///
    /// Sorted because the record is hashed into the state root: one set of
    /// approvals must have exactly one encoding. Unique because otherwise one
    /// member reaches a quorum alone by approving repeatedly.
    pub approvals: Vec<Address>,
    /// The cycle the proposal was opened in.
    ///
    /// A proposal lapses when its cycle closes, so a question the group declined
    /// to answer does not block every later one forever.
    pub opened_cycle: u64,
}

impl Proposal {
    /// Whether `member` has already approved.
    #[must_use]
    pub fn approved_by(&self, member: &Address) -> bool {
        self.approvals.binary_search(member).is_ok()
    }

    /// Record an approval, keeping the list canonical.
    ///
    /// # Errors
    /// Returns [`GroupError::AlreadyApproved`] if this member has approved.
    pub fn approve(&mut self, member: Address) -> Result<(), GroupError> {
        match self.approvals.binary_search(&member) {
            Ok(_) => Err(GroupError::AlreadyApproved),
            Err(at) => {
                self.approvals.insert(at, member);
                Ok(())
            }
        }
    }
}

/// What happens to the pot at the end of each cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayoutPolicy {
    /// ROSCA: the whole pot goes to one member per cycle, in a fixed order.
    ///
    /// This is the chama/susu/tontine/equb pattern.
    Rotation {
        /// Payout order — a permutation of the membership.
        order: Vec<Address>,
        /// Index into `order` of the next recipient.
        next: u32,
    },
    /// ASCA/VICOBA/VSLA: savings accumulate as shares, are lent to members at a
    /// service charge, and are shared out in proportion to shares at the end of
    /// the round.
    ///
    /// This is what *vikoba* means in Tanzania, and it is a different instrument
    /// from a rotation, not a variation on one. A rotation redistributes a fixed
    /// sum on a schedule; this one **earns**, because the service charges and
    /// fines a member pays return to the fund every member owns a share of.
    Accumulate(ShareRules),
}

/// The recurring obligation each member takes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    /// What one unit of participation costs each cycle.
    ///
    /// For a rotation this is the fixed contribution every member owes — VICOBA
    /// mandatory savings are quoted exactly this way, *"5,000 to 100,000 TSh per
    /// month, and every member must pay that amount"*. For an accumulating group
    /// it is the **value of one share**, and a member buys between
    /// [`ShareRules::min_shares`] and [`ShareRules::max_shares`] of them.
    ///
    /// One field rather than two, so the exact-amount rule and the share price
    /// can never disagree about what a cycle costs.
    pub amount: Amount,
    /// Denomination — typically a local sovereign stablecoin, not AFRI.
    pub denom: Denom,
    /// Cycle length in blocks.
    pub period_blocks: u64,
}

/// The share of members required to authorise an extraordinary withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quorum {
    /// Numerator of the required share.
    pub numerator: u32,
    /// Denominator of the required share.
    pub denominator: u32,
}

impl Quorum {
    /// A two-thirds quorum, the common default.
    pub const TWO_THIRDS: Self = Self {
        numerator: 2,
        denominator: 3,
    };

    /// Validate the ratio.
    ///
    /// # Errors
    /// Returns [`GroupError::InvalidQuorum`] for a zero denominator or a
    /// requirement exceeding unanimity.
    pub fn validate(self) -> Result<Self, GroupError> {
        if self.denominator == 0 || self.numerator > self.denominator || self.numerator == 0 {
            return Err(GroupError::InvalidQuorum {
                numerator: self.numerator,
                denominator: self.denominator,
            });
        }
        Ok(self)
    }

    /// Number of approvals needed out of `total`, rounded up.
    #[must_use]
    pub fn required_of(self, total: usize) -> usize {
        if self.denominator == 0 {
            return total;
        }
        let total = total as u128;
        let n = u128::from(self.numerator);
        let d = u128::from(self.denominator);
        // Ceiling division so a 2/3 quorum of 4 members is 3, not 2.
        let needed = total.saturating_mul(n).div_ceil(d);
        usize::try_from(needed)
            .unwrap_or(usize::MAX)
            .min(usize::try_from(total).unwrap_or(usize::MAX))
    }
}

/// A savings group holding a shared pot under agreed rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAccount {
    /// Human-readable name, as the group knows itself.
    pub name: String,
    /// Members and their standing.
    pub members: Vec<Member>,
    /// The recurring obligation.
    pub contribution: Contribution,
    /// What happens to the pot each cycle.
    pub policy: PayoutPolicy,
    /// Approval share for extraordinary withdrawals.
    pub quorum: Quorum,
    /// Cycles completed since formation. Monotonic across rounds.
    ///
    /// Deliberately never reset at a share-out. `Member::last_paid_cycle` and
    /// `Loan::due_cycle` are cycle numbers, and a counter that restarts would
    /// make a stale record read as current.
    pub cycle: u64,
    /// Height at which the cycle now open began.
    ///
    /// Without it `Contribution::period_blocks` is a number nobody reads, and
    /// "the cycle is over" has no definition the chain can check — which is what
    /// let any member advance the rotation at will.
    pub cycle_started: Height,
    /// Savings rounds shared out so far.
    pub round: u64,
    /// The cycle number the round now open began at.
    pub round_start_cycle: u64,
    /// The part of this group's balance that belongs to the social fund.
    ///
    /// Tracked rather than held at a second address, because a group must be
    /// able to see one balance and one history. The rule that makes it a fund
    /// rather than a label is enforced everywhere money leaves: a loan may only
    /// be advanced from *balance minus this*, and a share-out divides *balance
    /// minus this*. It is insurance, so it is neither lent nor shared.
    pub social_fund: Amount,
    /// The question currently before the group, if any.
    pub pending: Option<Proposal>,
}

impl GroupAccount {
    /// Create a group, validating every structural rule.
    ///
    /// # Errors
    /// Returns the specific [`GroupError`] for the first rule violated.
    pub fn new(
        name: impl Into<String>,
        members: Vec<Member>,
        contribution: Contribution,
        policy: PayoutPolicy,
        quorum: Quorum,
        opened_at: Height,
    ) -> Result<Self, GroupError> {
        let name = name.into();
        if name.is_empty() || name.len() > 64 {
            return Err(GroupError::InvalidName);
        }
        if members.len() < 2 {
            return Err(GroupError::TooFewMembers(members.len()));
        }
        if members.len() > MAX_GROUP_MEMBERS {
            return Err(GroupError::TooManyMembers(members.len()));
        }
        if contribution.amount.is_zero() {
            return Err(GroupError::ZeroContribution);
        }

        // Duplicate members would let one person collect two payouts per cycle.
        let mut seen: Vec<&Address> = members.iter().map(|m| &m.address).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        if seen.len() != before {
            return Err(GroupError::DuplicateMember);
        }

        let treasurers = members.iter().filter(|m| m.role == Role::Treasurer).count();
        if treasurers != 1 {
            return Err(GroupError::TreasurerCount(treasurers));
        }

        let quorum = quorum.validate()?;

        match &policy {
            PayoutPolicy::Rotation { order, next } => {
                // Every member must appear exactly once, or somebody never gets paid.
                if order.len() != members.len() {
                    return Err(GroupError::InvalidRotationOrder);
                }
                let mut sorted_order: Vec<&Address> = order.iter().collect();
                sorted_order.sort_unstable();
                sorted_order.dedup();
                if sorted_order.len() != order.len() || sorted_order != seen {
                    return Err(GroupError::InvalidRotationOrder);
                }
                if (*next as usize) >= order.len() {
                    return Err(GroupError::InvalidRotationOrder);
                }
            }
            PayoutPolicy::Accumulate(rules) => {
                rules.validate()?;
                // A guarantee requirement no membership can satisfy would make
                // the group unable to lend — which is the only thing an
                // accumulating group exists to do.
                if usize::try_from(rules.required_guarantors).unwrap_or(usize::MAX) >= members.len()
                {
                    return Err(GroupError::InvalidShareRules(
                        "more guarantors required than the group has other members",
                    ));
                }
            }
        }

        Ok(Self {
            name,
            members,
            contribution,
            policy,
            quorum,
            cycle: 0,
            cycle_started: opened_at,
            round: 0,
            round_start_cycle: 0,
            social_fund: Amount::ZERO,
            pending: None,
        })
    }

    /// Look up a member.
    #[must_use]
    pub fn member(&self, address: &Address) -> Option<&Member> {
        self.members.iter().find(|m| &m.address == address)
    }

    /// Whether `address` belongs to this group.
    #[must_use]
    pub fn is_member(&self, address: &Address) -> bool {
        self.member(address).is_some()
    }

    /// The treasurer's address.
    ///
    /// Construction guarantees exactly one treasurer, but this returns `Option`
    /// rather than panicking — a corrupt record read from disk must not halt a node.
    #[must_use]
    pub fn treasurer(&self) -> Option<Address> {
        self.members
            .iter()
            .find(|m| m.role == Role::Treasurer)
            .map(|m| m.address)
    }

    /// The total due into the pot each cycle.
    ///
    /// # Errors
    /// Returns [`GroupError::ZeroContribution`] only if the multiplication
    /// overflows, which requires an absurd membership size.
    pub fn pot_per_cycle(&self) -> Result<Amount, GroupError> {
        self.contribution
            .amount
            .checked_mul(self.members.len() as u128)
            .map_err(|_| GroupError::ZeroContribution)
    }

    /// Record that `address` met this cycle's obligation.
    ///
    /// # Errors
    /// Returns [`GroupError::NotAMember`] if the address is not in the group.
    pub fn record_contribution(&mut self, address: &Address) -> Result<(), GroupError> {
        let cycle = self.cycle;
        let member = self
            .members
            .iter_mut()
            .find(|m| &m.address == address)
            .ok_or(GroupError::NotAMember)?;
        // One contribution per member per cycle. Without this a member could
        // pay ten times in one cycle and buy a reliability record they did not
        // earn — and that record is what a lender reads.
        if member.has_paid(cycle) {
            return Err(GroupError::AlreadyContributed);
        }
        member.contributions_made = member.contributions_made.saturating_add(1);
        member.last_paid_cycle = Some(cycle);
        Ok(())
    }

    // -- Accumulating groups: shares, loans, the social fund -----------------

    /// This group's savings constitution, if it accumulates.
    #[must_use]
    pub fn share_rules(&self) -> Option<&ShareRules> {
        match &self.policy {
            PayoutPolicy::Accumulate(rules) => Some(rules),
            PayoutPolicy::Rotation { .. } => None,
        }
    }

    /// The rules, or the error a rotation should give.
    ///
    /// # Errors
    /// Returns [`GroupError::NotAccumulating`] for a rotating group.
    pub fn require_share_rules(&self) -> Result<&ShareRules, GroupError> {
        self.share_rules().ok_or(GroupError::NotAccumulating)
    }

    /// Total shares held across the membership in the round now open.
    ///
    /// The denominator of the share-out, and therefore the number that decides
    /// what everybody's savings are worth.
    #[must_use]
    pub fn total_shares(&self) -> u64 {
        self.members
            .iter()
            .fold(0u64, |sum, m| sum.saturating_add(m.shares))
    }

    /// Cycles closed since the round now open began.
    #[must_use]
    pub fn cycles_this_round(&self) -> u64 {
        self.cycle.saturating_sub(self.round_start_cycle)
    }

    /// Whether the round has run its agreed length and is ready to share out.
    #[must_use]
    pub fn round_complete(&self) -> bool {
        self.share_rules()
            .is_some_and(|rules| self.cycles_this_round() >= rules.cycles_per_round)
    }

    /// The cycle at which the round now open closes.
    #[must_use]
    pub fn round_ends_at_cycle(&self) -> u64 {
        self.share_rules().map_or(self.cycle, |rules| {
            self.round_start_cycle
                .saturating_add(rules.cycles_per_round)
        })
    }

    /// Check a loan could be repaid before the round that would settle it closes.
    ///
    /// `ShareRules::validate` already refuses a *term* longer than a round. That
    /// is necessary and not sufficient: a term that fits still runs past the
    /// share-out if the loan is granted late enough in the round. Found by the
    /// property suite in `crates/fuzz`, not by hand.
    fn check_term_fits(&self, rules: &ShareRules) -> Result<u64, GroupError> {
        let due = self.cycle.saturating_add(rules.loan_term_cycles);
        let round_ends = self.round_ends_at_cycle();
        if due > round_ends {
            return Err(GroupError::TooLateInRound { due, round_ends });
        }
        Ok(due)
    }

    /// Buy `shares` for `address`, returning what they cost.
    ///
    /// A member may buy in several instalments within one cycle, so long as the
    /// cycle total stays inside the group's ceiling. Meeting the floor is what
    /// marks the cycle paid — and it is marked at most once, so buying more
    /// shares later in the same cycle is a purchase, not a second credit entry.
    ///
    /// # Errors
    /// Returns [`GroupError::NotAccumulating`], [`GroupError::NotAMember`],
    /// [`GroupError::ZeroShares`], [`GroupError::ShareLimit`] or
    /// [`GroupError::Overflow`].
    pub fn buy_shares(&mut self, address: &Address, shares: u32) -> Result<Amount, GroupError> {
        let rules = self.require_share_rules()?;
        let (min_shares, max_shares) = (rules.min_shares, rules.max_shares);
        if shares == 0 {
            return Err(GroupError::ZeroShares);
        }
        let price = self.contribution.amount;
        let cycle = self.cycle;
        let member = self
            .members
            .iter_mut()
            .find(|m| &m.address == address)
            .ok_or(GroupError::NotAMember)?;

        let after = member.shares_this_cycle.saturating_add(shares);
        if after > max_shares {
            return Err(GroupError::ShareLimit {
                max: max_shares,
                requested: after,
            });
        }

        let cost = price
            .checked_mul(u128::from(shares))
            .map_err(|_| GroupError::Overflow)?;
        member.shares_this_cycle = after;
        member.shares = member.shares.saturating_add(u64::from(shares));
        if after >= min_shares && !member.has_paid(cycle) {
            member.contributions_made = member.contributions_made.saturating_add(1);
            member.last_paid_cycle = Some(cycle);
        }
        Ok(cost)
    }

    /// Record this cycle's social contribution for `address`, returning the amount.
    ///
    /// # Errors
    /// Returns [`GroupError::NotAccumulating`], [`GroupError::NotAMember`] or
    /// [`GroupError::AlreadyContributed`].
    pub fn pay_social(&mut self, address: &Address) -> Result<Amount, GroupError> {
        let rules = self.require_share_rules()?;
        let amount = rules.social_contribution;
        if amount.is_zero() {
            // A group that agreed no social fund has nothing to pay into. Taking
            // the money anyway would put it somewhere no rule can get it out of.
            return Err(GroupError::SocialFundShort);
        }
        let cycle = self.cycle;
        let member = self
            .members
            .iter_mut()
            .find(|m| &m.address == address)
            .ok_or(GroupError::NotAMember)?;
        if member.has_paid_social(cycle) {
            return Err(GroupError::AlreadyContributed);
        }
        member.social_paid_cycle = Some(cycle);
        self.social_fund = self
            .social_fund
            .checked_add(amount)
            .map_err(|_| GroupError::Overflow)?;
        Ok(amount)
    }

    /// The part of the group's balance that may be lent or shared out.
    ///
    /// # Errors
    /// Returns [`GroupError::Overflow`] if the social fund exceeds the balance,
    /// which would mean the record and the ledger disagree.
    pub fn lendable(&self, balance: Amount) -> Result<Amount, GroupError> {
        balance
            .checked_sub(self.social_fund)
            .map_err(|_| GroupError::Overflow)
    }

    /// Open a question for the group to approve.
    ///
    /// # Errors
    /// Returns [`GroupError::ProposalPending`] if one is already open,
    /// [`GroupError::NotAMember`] if the beneficiary is a stranger, or the
    /// specific rule the request breaks.
    pub fn open_proposal(
        &mut self,
        beneficiary: Address,
        kind: ProposalKind,
        balance: Amount,
    ) -> Result<(), GroupError> {
        let rules = self.require_share_rules()?.clone();
        if self.pending.is_some() {
            return Err(GroupError::ProposalPending);
        }
        let member = self.member(&beneficiary).ok_or(GroupError::NotAMember)?;

        match &kind {
            ProposalKind::Loan {
                principal,
                guarantors,
            } => {
                if principal.is_zero() {
                    return Err(GroupError::ZeroContribution);
                }
                if member.loan.is_some() {
                    return Err(GroupError::AlreadyBorrowing);
                }
                // The borrower's own savings are the collateral. This is the
                // one-third rule, and it is why a group can lend with no court
                // behind it: the worst case is already in the group's hands.
                let held = self
                    .contribution
                    .amount
                    .checked_mul(u128::from(member.shares))
                    .map_err(|_| GroupError::Overflow)?;
                let required = rules.cover_required_for(*principal)?;
                if held < required {
                    return Err(GroupError::InsufficientCover {
                        required: required.units().to_string(),
                        held: held.units().to_string(),
                    });
                }
                self.check_guarantors(&beneficiary, guarantors, rules.required_guarantors)?;
                self.check_term_fits(&rules)?;
                // Checked when the proposal opens *and* again when it passes:
                // the fund can shrink to another loan in between.
                if self.lendable(balance)? < *principal {
                    return Err(GroupError::LoanFundShort);
                }
            }
            ProposalKind::SocialGrant { amount } => {
                if amount.is_zero() {
                    return Err(GroupError::ZeroContribution);
                }
                if *amount > self.social_fund {
                    return Err(GroupError::SocialFundShort);
                }
            }
        }

        self.pending = Some(Proposal {
            beneficiary,
            kind,
            approvals: Vec::new(),
            opened_cycle: self.cycle,
        });
        Ok(())
    }

    /// Every guarantor must be a different member, and the borrower is not one.
    fn check_guarantors(
        &self,
        borrower: &Address,
        guarantors: &[Address],
        required: u32,
    ) -> Result<(), GroupError> {
        let got = u32::try_from(guarantors.len()).unwrap_or(u32::MAX);
        if got != required {
            return Err(GroupError::GuarantorCount {
                need: required,
                got,
            });
        }
        let mut seen: Vec<&Address> = guarantors.iter().collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        if seen.len() != before {
            return Err(GroupError::BadGuarantor);
        }
        for guarantor in guarantors {
            // Standing behind your own loan is not a guarantee.
            if guarantor == borrower || !self.is_member(guarantor) {
                return Err(GroupError::BadGuarantor);
            }
        }
        Ok(())
    }

    /// Record `member`'s approval of the open proposal.
    ///
    /// Returns whether the quorum has now been reached, which is the caller's
    /// signal to carry the proposal out.
    ///
    /// # Errors
    /// Returns [`GroupError::NoProposal`], [`GroupError::NotAMember`] or
    /// [`GroupError::AlreadyApproved`].
    pub fn approve(&mut self, member: Address) -> Result<bool, GroupError> {
        if !self.is_member(&member) {
            return Err(GroupError::NotAMember);
        }
        let needed = self.approvals_required();
        let proposal = self.pending.as_mut().ok_or(GroupError::NoProposal)?;
        proposal.approve(member)?;
        Ok(proposal.approvals.len() >= needed)
    }

    /// Advance the approved loan, returning the principal to transfer.
    ///
    /// # Errors
    /// Returns the rule the loan breaks. Every check from
    /// [`Self::open_proposal`] runs again, because the fund and the borrower's
    /// standing can both have changed while the group was deciding.
    pub fn issue_loan(&mut self, balance: Amount) -> Result<(Address, Amount), GroupError> {
        let rules = self.require_share_rules()?.clone();
        let proposal = self.pending.as_ref().ok_or(GroupError::NoProposal)?;
        let ProposalKind::Loan {
            principal,
            guarantors,
        } = &proposal.kind
        else {
            return Err(GroupError::NoProposal);
        };
        let (borrower, principal, guarantors) =
            (proposal.beneficiary, *principal, guarantors.clone());

        if self.lendable(balance)? < principal {
            return Err(GroupError::LoanFundShort);
        }
        self.check_guarantors(&borrower, &guarantors, rules.required_guarantors)?;
        let service_charge = rules.service_charge_on(principal)?;
        // Re-checked here and not only at the proposal: cycles close while a
        // group is deciding, so a loan that had time when it was asked for may
        // have none by the time it is agreed.
        let due_cycle = self.check_term_fits(&rules)?;
        let held_price = self.contribution.amount;
        let required = rules.cover_required_for(principal)?;

        let member = self
            .members
            .iter_mut()
            .find(|m| m.address == borrower)
            .ok_or(GroupError::NotAMember)?;
        if member.loan.is_some() {
            return Err(GroupError::AlreadyBorrowing);
        }
        let held = held_price
            .checked_mul(u128::from(member.shares))
            .map_err(|_| GroupError::Overflow)?;
        if held < required {
            return Err(GroupError::InsufficientCover {
                required: required.units().to_string(),
                held: held.units().to_string(),
            });
        }
        member.loan = Some(Loan {
            principal,
            service_charge,
            repaid: Amount::ZERO,
            due_cycle,
            guarantors,
            fined: false,
        });
        self.pending = None;
        Ok((borrower, principal))
    }

    /// Pay out the approved social grant, returning who receives what.
    ///
    /// # Errors
    /// Returns [`GroupError::NoProposal`] or [`GroupError::SocialFundShort`].
    pub fn issue_grant(&mut self) -> Result<(Address, Amount), GroupError> {
        let proposal = self.pending.as_ref().ok_or(GroupError::NoProposal)?;
        let ProposalKind::SocialGrant { amount } = &proposal.kind else {
            return Err(GroupError::NoProposal);
        };
        let (beneficiary, amount) = (proposal.beneficiary, *amount);
        self.social_fund = self
            .social_fund
            .checked_sub(amount)
            .map_err(|_| GroupError::SocialFundShort)?;
        self.pending = None;
        Ok((beneficiary, amount))
    }

    /// Credit a repayment against `address`'s loan.
    ///
    /// A loan settled in full is cleared and counted, which is what makes
    /// [`Member::repayment_bps`] mean anything.
    ///
    /// # Errors
    /// Returns [`GroupError::NoLoan`], [`GroupError::Overpayment`] or
    /// [`GroupError::ZeroContribution`].
    pub fn repay(&mut self, address: &Address, amount: Amount) -> Result<(), GroupError> {
        if amount.is_zero() {
            return Err(GroupError::ZeroContribution);
        }
        let member = self
            .members
            .iter_mut()
            .find(|m| &m.address == address)
            .ok_or(GroupError::NotAMember)?;
        let loan = member.loan.as_mut().ok_or(GroupError::NoLoan)?;
        let owed = loan.outstanding()?;
        if amount > owed {
            return Err(GroupError::Overpayment {
                owed: owed.units().to_string(),
            });
        }
        loan.repaid = loan
            .repaid
            .checked_add(amount)
            .map_err(|_| GroupError::Overflow)?;
        if loan.is_settled() {
            member.loan = None;
            member.loans_repaid = member.loans_repaid.saturating_add(1);
        }
        Ok(())
    }

    /// Close the round: work out what every member is owed and reset for the next.
    ///
    /// `fund` is the group's balance **less the social fund**, which the caller
    /// reads from the ledger. The returned payments are what the caller must
    /// transfer, and they always sum to no more than `fund`, so none of them can
    /// fail for want of money.
    ///
    /// Each member's gross entitlement is their share of the fund. Anything they
    /// still owe — an unpaid loan, unsettled fines — comes off it, which is
    /// exactly how a real VICOBA settles a defaulter: *the savings they invested
    /// over the year are used to pay the loan*. The difference stays in the
    /// group and opens the next round, so a default is a loss the whole
    /// membership carries in proportion, not a hole in one member's payout.
    ///
    /// # Errors
    /// Returns [`GroupError::NotAccumulating`], [`GroupError::RoundNotComplete`],
    /// [`GroupError::NoShares`] or [`GroupError::EmptyFund`].
    pub fn share_out(&mut self, fund: Amount) -> Result<Vec<(Address, Amount)>, GroupError> {
        let rules = self.require_share_rules()?;
        let needed = rules.cycles_per_round;
        if !self.round_complete() {
            return Err(GroupError::RoundNotComplete {
                done: self.cycles_this_round(),
                needed,
            });
        }
        if fund.is_zero() {
            return Err(GroupError::EmptyFund);
        }
        let total = self.total_shares();
        if total == 0 {
            return Err(GroupError::NoShares);
        }

        let mut payments = Vec::with_capacity(self.members.len());
        for member in &mut self.members {
            let gross = fund
                .mul_ratio(u128::from(member.shares), u128::from(total))
                .map_err(|_| GroupError::Overflow)?;
            let owed = {
                let loan = member
                    .loan
                    .as_ref()
                    .map_or(Ok(Amount::ZERO), Loan::outstanding)?;
                loan.checked_add(member.fines_owed)
                    .map_err(|_| GroupError::Overflow)?
            };
            let net = Amount::from_units(gross.units().saturating_sub(owed.units()));

            if member.loan.is_some() {
                member.loans_defaulted = member.loans_defaulted.saturating_add(1);
            }
            member.loan = None;
            member.fines_owed = Amount::ZERO;
            member.shares = 0;
            member.shares_this_cycle = 0;
            if !net.is_zero() {
                payments.push((member.address, net));
            }
        }

        self.round = self.round.saturating_add(1);
        self.round_start_cycle = self.cycle;
        // A question asked in the old round is not a question for the new one.
        self.pending = None;
        Ok(payments)
    }

    /// Whether every member has paid into the cycle now open.
    #[must_use]
    pub fn everyone_has_paid(&self) -> bool {
        self.members.iter().all(|m| m.has_paid(self.cycle))
    }

    /// Whether a payout may be taken at `now`.
    ///
    /// Either every member has met the obligation, or the agreed period has
    /// elapsed and the cycle closes with whatever was collected. **Both are
    /// needed:** requiring only full payment lets one member hold the group
    /// hostage by never paying, and requiring only the period would make an
    /// early payout impossible even when everybody has paid.
    #[must_use]
    pub fn payout_due(&self, now: Height) -> bool {
        self.everyone_has_paid() || now.0 >= self.period_ends().0
    }

    /// The height at which the current cycle's period expires.
    #[must_use]
    pub fn period_ends(&self) -> Height {
        Height(
            self.cycle_started
                .0
                .saturating_add(self.contribution.period_blocks),
        )
    }

    /// Record that `address` missed this cycle's obligation.
    ///
    /// # Errors
    /// Returns [`GroupError::NotAMember`] if the address is not in the group.
    pub fn record_missed(&mut self, address: &Address) -> Result<(), GroupError> {
        let member = self
            .members
            .iter_mut()
            .find(|m| &m.address == address)
            .ok_or(GroupError::NotAMember)?;
        member.contributions_missed = member.contributions_missed.saturating_add(1);
        Ok(())
    }

    /// Who receives this cycle's pot, if the policy rotates.
    #[must_use]
    pub fn next_recipient(&self) -> Option<Address> {
        match &self.policy {
            PayoutPolicy::Rotation { order, next } => order.get(*next as usize).copied(),
            PayoutPolicy::Accumulate(_) => None,
        }
    }

    /// Close the cycle, advancing the rotation.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "`len` is forced to at least 1 by `.max(1)`, so the modulo cannot divide by zero"
    )]
    pub fn advance_cycle(&mut self, at: Height) {
        // Anyone who did not pay into the cycle just closed missed it. Nothing
        // called `record_missed` before this, so `contributions_missed` was
        // always zero and `reliability_bps` reported a perfect record for every
        // member who had ever paid once — a credit signal that could only ever
        // flatter.
        let closing = self.cycle;
        let late_fine_bps = self.share_rules().map(|r| r.late_fine_bps);
        for member in &mut self.members {
            if !member.has_paid(closing) {
                member.contributions_missed = member.contributions_missed.saturating_add(1);
            }
            // A fresh cycle is a fresh allowance of shares.
            member.shares_this_cycle = 0;

            // A debt that has run past its term is fined once, on what is still
            // outstanding. Once and not once per cycle: the group agreed a fine
            // on the debt, not a second interest rate that compounds while a
            // member is already struggling to pay the first.
            if let (Some(bps), Some(loan)) = (late_fine_bps, member.loan.as_mut())
                && !loan.fined
                && loan.is_overdue(closing)
                && let Ok(outstanding) = loan.outstanding()
                && let Ok(fine) =
                    outstanding.mul_ratio(u128::from(bps), u128::from(BPS_DENOMINATOR))
            {
                loan.fined = true;
                member.fines_owed = member.fines_owed.checked_add(fine).unwrap_or(Amount::MAX);
            }
        }
        // A proposal the group did not decide within its own cycle lapses.
        // Otherwise one member holding an open question blocks every later one,
        // and a group can be frozen for the price of a single fee.
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.opened_cycle <= closing)
        {
            self.pending = None;
        }
        self.cycle_started = at;
        self.cycle = self.cycle.saturating_add(1);
        if let PayoutPolicy::Rotation { order, next } = &mut self.policy {
            let len = u32::try_from(order.len()).unwrap_or(1).max(1);
            *next = next.saturating_add(1) % len;
        }
    }

    /// Approvals needed for an extraordinary withdrawal.
    #[must_use]
    pub fn approvals_required(&self) -> usize {
        self.quorum.required_of(self.members.len())
    }
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

impl Encode for Role {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(match self {
            Self::Treasurer => 0,
            Self::Member => 1,
        });
    }
}

impl Decode for Role {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Treasurer),
            1 => Ok(Self::Member),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "Role",
            }),
        }
    }
}

impl Encode for Loan {
    fn encode(&self, out: &mut Vec<u8>) {
        self.principal.encode(out);
        self.service_charge.encode(out);
        self.repaid.encode(out);
        self.due_cycle.encode(out);
        self.guarantors.encode(out);
        self.fined.encode(out);
    }
}

impl Decode for Loan {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let loan = Self {
            principal: Amount::decode(r)?,
            service_charge: Amount::decode(r)?,
            repaid: Amount::decode(r)?,
            due_cycle: u64::decode(r)?,
            guarantors: Vec::<Address>::decode(r)?,
            fined: bool::decode(r)?,
        };
        // A repayment larger than the debt cannot arise from any sequence this
        // chain will execute, so a record carrying one came from somewhere else.
        let total = loan
            .principal
            .checked_add(loan.service_charge)
            .map_err(|_| CodecError::Invalid("loan total overflows".into()))?;
        if loan.repaid > total {
            return Err(CodecError::Invalid(
                "a loan repaid beyond what it was worth".into(),
            ));
        }
        if usize::try_from(u32::MAX).unwrap_or(usize::MAX) < loan.guarantors.len()
            || loan.guarantors.len() >= MAX_GROUP_MEMBERS
        {
            return Err(CodecError::Invalid(
                "more guarantors than a group can hold".into(),
            ));
        }
        Ok(loan)
    }
}

impl Encode for ShareRules {
    fn encode(&self, out: &mut Vec<u8>) {
        self.min_shares.encode(out);
        self.max_shares.encode(out);
        self.cycles_per_round.encode(out);
        self.service_charge_bps.encode(out);
        self.cover_bps.encode(out);
        self.loan_term_cycles.encode(out);
        self.late_fine_bps.encode(out);
        self.required_guarantors.encode(out);
        self.social_contribution.encode(out);
    }
}

impl Decode for ShareRules {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let rules = Self {
            min_shares: u32::decode(r)?,
            max_shares: u32::decode(r)?,
            cycles_per_round: u64::decode(r)?,
            service_charge_bps: u32::decode(r)?,
            cover_bps: u32::decode(r)?,
            loan_term_cycles: u64::decode(r)?,
            late_fine_bps: u32::decode(r)?,
            required_guarantors: u32::decode(r)?,
            social_contribution: Amount::decode(r)?,
        };
        // The constructor refuses these, so accepting them from a database or a
        // peer would let a record exist that this chain could never have made.
        rules
            .validate()
            .map_err(|e| CodecError::Invalid(e.to_string()))?;
        Ok(rules)
    }
}

impl Encode for ProposalKind {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Loan {
                principal,
                guarantors,
            } => {
                out.push(0);
                principal.encode(out);
                guarantors.encode(out);
            }
            Self::SocialGrant { amount } => {
                out.push(1);
                amount.encode(out);
            }
        }
    }
}

impl Decode for ProposalKind {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Loan {
                principal: Amount::decode(r)?,
                guarantors: Vec::<Address>::decode(r)?,
            }),
            1 => Ok(Self::SocialGrant {
                amount: Amount::decode(r)?,
            }),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "ProposalKind",
            }),
        }
    }
}

impl Encode for Proposal {
    fn encode(&self, out: &mut Vec<u8>) {
        self.beneficiary.encode(out);
        self.kind.encode(out);
        self.approvals.encode(out);
        self.opened_cycle.encode(out);
    }
}

impl Decode for Proposal {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let proposal = Self {
            beneficiary: Address::decode(r)?,
            kind: ProposalKind::decode(r)?,
            approvals: Vec::<Address>::decode(r)?,
            opened_cycle: u64::decode(r)?,
        };
        // Refused, never repaired. The approvals decide whether money leaves the
        // fund, and this record is hashed into the state root: a second spelling
        // of one set of approvals would be a second state root for one state.
        // Sorting it here instead would also quietly turn a repeated approval —
        // one member reaching a quorum alone — into a valid one.
        if !proposal.approvals.is_sorted_by(|a, b| a < b) {
            return Err(CodecError::Invalid(
                "proposal approvals must be sorted and unique".into(),
            ));
        }
        if proposal.approvals.len() > MAX_GROUP_MEMBERS {
            return Err(CodecError::Invalid(
                "more approvals than a group can hold".into(),
            ));
        }
        Ok(proposal)
    }
}

impl Encode for Member {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.role.encode(out);
        self.joined_cycle.encode(out);
        self.contributions_made.encode(out);
        self.contributions_missed.encode(out);
        self.last_paid_cycle.encode(out);
        self.shares.encode(out);
        self.shares_this_cycle.encode(out);
        self.loan.encode(out);
        self.fines_owed.encode(out);
        self.social_paid_cycle.encode(out);
        self.loans_repaid.encode(out);
        self.loans_defaulted.encode(out);
    }
}

impl Decode for Member {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            role: Role::decode(r)?,
            joined_cycle: u64::decode(r)?,
            contributions_made: u64::decode(r)?,
            contributions_missed: u64::decode(r)?,
            last_paid_cycle: Option::<u64>::decode(r)?,
            shares: u64::decode(r)?,
            shares_this_cycle: u32::decode(r)?,
            loan: Option::<Loan>::decode(r)?,
            fines_owed: Amount::decode(r)?,
            social_paid_cycle: Option::<u64>::decode(r)?,
            loans_repaid: u64::decode(r)?,
            loans_defaulted: u64::decode(r)?,
        })
    }
}

impl Encode for Contribution {
    fn encode(&self, out: &mut Vec<u8>) {
        self.amount.encode(out);
        self.denom.encode(out);
        self.period_blocks.encode(out);
    }
}

impl Decode for Contribution {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            amount: Amount::decode(r)?,
            denom: Denom::decode(r)?,
            period_blocks: u64::decode(r)?,
        })
    }
}

impl Encode for Quorum {
    fn encode(&self, out: &mut Vec<u8>) {
        self.numerator.encode(out);
        self.denominator.encode(out);
    }
}

impl Decode for Quorum {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            numerator: u32::decode(r)?,
            denominator: u32::decode(r)?,
        })
    }
}

impl Encode for PayoutPolicy {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Rotation { order, next } => {
                out.push(0);
                order.encode(out);
                next.encode(out);
            }
            Self::Accumulate(rules) => {
                out.push(1);
                rules.encode(out);
            }
        }
    }
}

impl Decode for PayoutPolicy {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Rotation {
                order: Vec::<Address>::decode(r)?,
                next: u32::decode(r)?,
            }),
            1 => Ok(Self::Accumulate(ShareRules::decode(r)?)),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "PayoutPolicy",
            }),
        }
    }
}

impl Encode for GroupAccount {
    fn encode(&self, out: &mut Vec<u8>) {
        self.name.encode(out);
        self.members.encode(out);
        self.contribution.encode(out);
        self.policy.encode(out);
        self.quorum.encode(out);
        self.cycle.encode(out);
        self.cycle_started.encode(out);
        self.round.encode(out);
        self.round_start_cycle.encode(out);
        self.social_fund.encode(out);
        self.pending.encode(out);
    }
}

impl Decode for GroupAccount {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let group = Self {
            name: String::decode(r)?,
            members: Vec::<Member>::decode(r)?,
            contribution: Contribution::decode(r)?,
            policy: PayoutPolicy::decode(r)?,
            quorum: Quorum::decode(r)?,
            cycle: u64::decode(r)?,
            cycle_started: Height::decode(r)?,
            round: u64::decode(r)?,
            round_start_cycle: u64::decode(r)?,
            social_fund: Amount::decode(r)?,
            pending: Option::<Proposal>::decode(r)?,
        };
        // The cap is a consensus rule, so it has to hold at the decode boundary
        // too: a record this chain could never have produced must not be
        // accepted from a database or a peer just because it parses.
        if group.members.len() > MAX_GROUP_MEMBERS {
            return Err(CodecError::Invalid(format!(
                "a group may hold at most {MAX_GROUP_MEMBERS} members, got {}",
                group.members.len()
            )));
        }
        // A round that started after the cycle it is counted from would make
        // `cycles_this_round` saturate to zero and the round never complete —
        // savings that can be paid in and never shared out.
        if group.round_start_cycle > group.cycle {
            return Err(CodecError::Invalid(
                "a round starting after the current cycle".into(),
            ));
        }
        Ok(group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::codec::decode_exact;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid denom")
    }

    fn contribution() -> Contribution {
        Contribution {
            amount: Amount::from_afri(500),
            denom: kes(),
            period_blocks: 604_800,
        }
    }

    /// A five-member chama with a rotating pot — the canonical shape.
    fn chama(n: u8) -> GroupAccount {
        let members: Vec<Member> = (0..n)
            .map(|i| {
                let role = if i == 0 {
                    Role::Treasurer
                } else {
                    Role::Member
                };
                Member::new(addr(i + 1), role, 0)
            })
            .collect();
        let order: Vec<Address> = members.iter().map(|m| m.address).collect();
        GroupAccount::new(
            "Mama Mboga Chama",
            members,
            contribution(),
            PayoutPolicy::Rotation { order, next: 0 },
            Quorum::TWO_THIRDS,
            Height(0),
        )
        .expect("valid chama")
    }

    #[test]
    fn a_rotation_pays_every_member_exactly_once_per_full_cycle() {
        // The defining property of a ROSCA. If it fails, somebody's savings vanish.
        let mut group = chama(5);
        let mut paid = Vec::new();
        for _ in 0..5 {
            paid.push(group.next_recipient().expect("rotation has a recipient"));
            group.advance_cycle(Height(0));
        }
        let mut sorted = paid.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            5,
            "each member must be paid exactly once: {paid:?}"
        );
        assert_eq!(
            group.next_recipient(),
            Some(addr(1)),
            "rotation must wrap back to the first member"
        );
    }

    #[test]
    fn the_pot_equals_every_members_contribution() {
        let group = chama(5);
        assert_eq!(
            group.pot_per_cycle().expect("no overflow"),
            Amount::from_afri(2_500)
        );
    }

    #[test]
    fn duplicate_members_are_rejected() {
        // Otherwise one person collects two payouts per rotation.
        let members = vec![
            Member::new(addr(1), Role::Treasurer, 0),
            Member::new(addr(1), Role::Member, 0),
        ];
        let order = vec![addr(1), addr(1)];
        assert_eq!(
            GroupAccount::new(
                "dup",
                members,
                contribution(),
                PayoutPolicy::Rotation { order, next: 0 },
                Quorum::TWO_THIRDS,
                Height(0)
            ),
            Err(GroupError::DuplicateMember)
        );
    }

    #[test]
    fn a_rotation_order_omitting_a_member_is_rejected() {
        // The subtle failure: a well-formed group where one member pays in every
        // cycle and is never paid out.
        let members: Vec<Member> = (0..3)
            .map(|i| {
                Member::new(
                    addr(i + 1),
                    if i == 0 {
                        Role::Treasurer
                    } else {
                        Role::Member
                    },
                    0,
                )
            })
            .collect();
        let short_order = vec![addr(1), addr(2)];
        assert_eq!(
            GroupAccount::new(
                "short",
                members,
                contribution(),
                PayoutPolicy::Rotation {
                    order: short_order,
                    next: 0
                },
                Quorum::TWO_THIRDS,
                Height(0)
            ),
            Err(GroupError::InvalidRotationOrder)
        );
    }

    #[test]
    fn a_rotation_order_naming_a_non_member_is_rejected() {
        let members: Vec<Member> = (0..3)
            .map(|i| {
                Member::new(
                    addr(i + 1),
                    if i == 0 {
                        Role::Treasurer
                    } else {
                        Role::Member
                    },
                    0,
                )
            })
            .collect();
        let stranger_order = vec![addr(1), addr(2), addr(99)];
        assert_eq!(
            GroupAccount::new(
                "stranger",
                members,
                contribution(),
                PayoutPolicy::Rotation {
                    order: stranger_order,
                    next: 0
                },
                Quorum::TWO_THIRDS,
                Height(0)
            ),
            Err(GroupError::InvalidRotationOrder)
        );
    }

    #[test]
    fn groups_need_two_members_and_exactly_one_treasurer() {
        let solo = vec![Member::new(addr(1), Role::Treasurer, 0)];
        assert_eq!(
            GroupAccount::new(
                "solo",
                solo,
                contribution(),
                PayoutPolicy::Accumulate(ShareRules {
                    required_guarantors: 1,
                    ..ShareRules::vicoba(Amount::ZERO)
                }),
                Quorum::TWO_THIRDS,
                Height(0)
            ),
            Err(GroupError::TooFewMembers(1))
        );

        let no_treasurer = vec![
            Member::new(addr(1), Role::Member, 0),
            Member::new(addr(2), Role::Member, 0),
        ];
        assert_eq!(
            GroupAccount::new(
                "none",
                no_treasurer,
                contribution(),
                PayoutPolicy::Accumulate(ShareRules {
                    required_guarantors: 1,
                    ..ShareRules::vicoba(Amount::ZERO)
                }),
                Quorum::TWO_THIRDS,
                Height(0)
            ),
            Err(GroupError::TreasurerCount(0))
        );

        let two_treasurers = vec![
            Member::new(addr(1), Role::Treasurer, 0),
            Member::new(addr(2), Role::Treasurer, 0),
        ];
        assert_eq!(
            GroupAccount::new(
                "two",
                two_treasurers,
                contribution(),
                PayoutPolicy::Accumulate(ShareRules {
                    required_guarantors: 1,
                    ..ShareRules::vicoba(Amount::ZERO)
                }),
                Quorum::TWO_THIRDS,
                Height(0)
            ),
            Err(GroupError::TreasurerCount(2))
        );
    }

    #[test]
    fn quorum_rounds_up_so_a_minority_cannot_move_the_pot() {
        // 2/3 of 4 is 2.67 — requiring 2 would let a minority withdraw.
        assert_eq!(Quorum::TWO_THIRDS.required_of(4), 3);
        assert_eq!(Quorum::TWO_THIRDS.required_of(3), 2);
        assert_eq!(Quorum::TWO_THIRDS.required_of(5), 4);
        assert_eq!(Quorum::TWO_THIRDS.required_of(0), 0);
    }

    #[test]
    fn invalid_quorums_are_rejected() {
        assert!(
            Quorum {
                numerator: 1,
                denominator: 0
            }
            .validate()
            .is_err()
        );
        assert!(
            Quorum {
                numerator: 4,
                denominator: 3
            }
            .validate()
            .is_err()
        );
        assert!(
            Quorum {
                numerator: 0,
                denominator: 3
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn contribution_history_becomes_a_credit_signal() {
        // Driven through real cycles rather than by poking the counters,
        // because that is the part that was broken: nothing called
        // `record_missed`, so every member who had ever paid once scored a
        // perfect 100% forever — a credit signal that could only ever flatter
        // the borrower, in a feature written to help a lender trust them.
        let mut group = chama(3);
        let member = addr(2);
        for cycle in 0..10u64 {
            if cycle != 4 {
                group.record_contribution(&member).expect("member exists");
            }
            group.advance_cycle(Height(cycle));
        }

        let m = group.member(&member).expect("member exists");
        assert_eq!(m.contributions_due(), 10);
        assert_eq!(m.reliability_bps(), Some(9_000), "9 of 10 on time = 90%");
    }

    #[test]
    fn a_member_cannot_pay_twice_in_one_cycle_to_inflate_their_record() {
        // The record is what a lender reads, so buying it is buying credit.
        let mut group = chama(3);
        let member = addr(2);
        group.record_contribution(&member).expect("member exists");
        assert_eq!(
            group.record_contribution(&member),
            Err(GroupError::AlreadyContributed)
        );
        assert_eq!(group.member(&member).expect("exists").contributions_made, 1);
    }

    #[test]
    fn a_cycle_is_due_when_everyone_has_paid_or_the_period_runs_out() {
        // Both halves are needed. Requiring only full payment lets one member
        // hold the group hostage by never paying; requiring only the period
        // would stop a group that has all paid from closing early.
        let mut group = chama(3);
        let opened = group.cycle_started;
        let deadline = group.period_ends();

        assert!(!group.payout_due(opened), "nobody has paid yet");
        assert!(
            group.payout_due(deadline),
            "the agreed period expiring closes the cycle regardless"
        );

        for who in [addr(1), addr(2), addr(3)] {
            group.record_contribution(&who).expect("member exists");
        }
        assert!(
            group.payout_due(opened),
            "and everyone paying closes it immediately"
        );
    }

    #[test]
    fn a_group_larger_than_any_real_one_is_refused() {
        let members: Vec<Member> = (0..=u8::try_from(MAX_GROUP_MEMBERS).unwrap())
            .map(|i| {
                Member::new(
                    addr(i),
                    if i == 0 {
                        Role::Treasurer
                    } else {
                        Role::Member
                    },
                    0,
                )
            })
            .collect();
        let n = members.len();
        assert_eq!(
            GroupAccount::new(
                "crowd",
                members,
                contribution(),
                PayoutPolicy::Accumulate(ShareRules {
                    required_guarantors: 1,
                    ..ShareRules::vicoba(Amount::ZERO)
                }),
                Quorum::TWO_THIRDS,
                Height(0)
            ),
            Err(GroupError::TooManyMembers(n))
        );
    }

    #[test]
    fn a_member_with_no_history_is_unrated_not_perfect() {
        // Reporting 100% for someone who has never been due would let a fresh
        // account masquerade as a proven borrower.
        let group = chama(3);
        assert_eq!(
            group.member(&addr(2)).expect("exists").reliability_bps(),
            None
        );
    }

    #[test]
    fn non_members_cannot_have_contributions_recorded() {
        let mut group = chama(3);
        assert_eq!(
            group.record_contribution(&addr(200)),
            Err(GroupError::NotAMember)
        );
    }

    #[test]
    fn accumulating_groups_have_no_rotation_recipient() {
        let members = vec![
            Member::new(addr(1), Role::Treasurer, 0),
            Member::new(addr(2), Role::Member, 0),
        ];
        let vsla = GroupAccount::new(
            "VSLA",
            members,
            contribution(),
            PayoutPolicy::Accumulate(ShareRules {
                required_guarantors: 1,
                ..ShareRules::vicoba(Amount::ZERO)
            }),
            Quorum::TWO_THIRDS,
            Height(0),
        )
        .expect("valid VSLA");
        assert_eq!(vsla.next_recipient(), None);
    }

    #[test]
    fn group_round_trips_through_the_canonical_codec() {
        let group = chama(4);
        assert_eq!(decode_exact::<GroupAccount>(&group.to_bytes()), Ok(group));
    }

    #[test]
    fn treasurer_is_identifiable() {
        assert_eq!(chama(4).treasurer(), Some(addr(1)));
    }

    // -----------------------------------------------------------------------
    // Vikoba: shares, loans, the social fund (ADR-0019)
    // -----------------------------------------------------------------------

    fn rules() -> ShareRules {
        ShareRules {
            required_guarantors: 1,
            cycles_per_round: 4,
            ..ShareRules::vicoba(Amount::from_afri(50))
        }
    }

    /// A four-member vikoba: 500 KES a share, 1–5 shares a cycle.
    fn vikoba(n: u8) -> GroupAccount {
        let members: Vec<Member> = (0..n)
            .map(|i| {
                let role = if i == 0 {
                    Role::Treasurer
                } else {
                    Role::Member
                };
                Member::new(addr(i + 1), role, 0)
            })
            .collect();
        GroupAccount::new(
            "Vikoba",
            members,
            contribution(),
            PayoutPolicy::Accumulate(rules()),
            Quorum::TWO_THIRDS,
            Height(0),
        )
        .expect("valid vikoba")
    }

    #[test]
    fn share_rules_that_could_not_be_honoured_are_refused() {
        // Each of these describes a group that would work until the day it did
        // not, and the day it did not would be the share-out.
        let cases: [(&str, ShareRules); 4] = [
            (
                "a loan term outlasting the round would make every borrower a \
                 defaulter at the share-out, for a term the group itself agreed",
                ShareRules {
                    cycles_per_round: 2,
                    loan_term_cycles: 3,
                    ..rules()
                },
            ),
            (
                "a ceiling below the floor means no legal purchase exists",
                ShareRules {
                    min_shares: 4,
                    max_shares: 2,
                    ..rules()
                },
            ),
            (
                "zero cover would let a member borrow the whole fund against nothing",
                ShareRules {
                    cover_bps: 0,
                    ..rules()
                },
            ),
            (
                "a round of no cycles could never complete",
                ShareRules {
                    cycles_per_round: 0,
                    ..rules()
                },
            ),
        ];
        for (why, broken) in cases {
            assert!(broken.validate().is_err(), "{why}");
        }
        assert!(rules().validate().is_ok());
    }

    #[test]
    fn a_group_that_could_never_lend_is_refused_at_creation() {
        // Two members, both of whom must guarantee any loan — but a borrower
        // may not guarantee their own. The group could take savings forever and
        // never do the one thing it exists for.
        let members = vec![
            Member::new(addr(1), Role::Treasurer, 0),
            Member::new(addr(2), Role::Member, 0),
        ];
        assert!(matches!(
            GroupAccount::new(
                "impossible",
                members,
                contribution(),
                PayoutPolicy::Accumulate(ShareRules {
                    required_guarantors: 2,
                    ..rules()
                }),
                Quorum::TWO_THIRDS,
                Height(0),
            ),
            Err(GroupError::InvalidShareRules(_))
        ));
    }

    #[test]
    fn buying_the_floor_marks_the_cycle_paid_exactly_once() {
        // Buying more shares later in the same cycle is a purchase, not a
        // second entry in the record a lender reads.
        let mut group = vikoba(4);
        assert_eq!(
            group.buy_shares(&addr(2), 1).expect("legal"),
            Amount::from_afri(500)
        );
        group
            .buy_shares(&addr(2), 2)
            .expect("still under the ceiling");
        let member = group.member(&addr(2)).expect("exists");
        assert_eq!(member.shares, 3);
        assert_eq!(
            member.contributions_made, 1,
            "three shares in one cycle is one cycle honoured, not three"
        );
    }

    #[test]
    fn the_share_out_pays_earnings_in_proportion_and_settles_debts_against_savings() {
        let mut group = vikoba(4);
        // Two members buy 4 shares, two buy 2: twelve shares, 6,000 paid in.
        for (who, shares) in [(1u8, 4u32), (2, 4), (3, 2), (4, 2)] {
            group.buy_shares(&addr(who), shares).expect("legal");
        }
        assert_eq!(group.total_shares(), 12);

        for cycle in 0..4 {
            group.advance_cycle(Height(cycle + 1));
        }
        assert!(group.round_complete());

        // The fund came back 600 richer than it went out — service charges.
        let payments = group.share_out(Amount::from_afri(6_600)).expect("due");
        let paid = |who: u8| {
            payments
                .iter()
                .find(|(a, _)| a == &addr(who))
                .map(|(_, amount)| *amount)
                .unwrap_or(Amount::ZERO)
        };
        assert_eq!(paid(1), Amount::from_afri(2_200));
        assert_eq!(paid(3), Amount::from_afri(1_100));
        assert_eq!(
            paid(1).units(),
            paid(3).units() * 2,
            "twice the shares, twice the payout"
        );
        assert!(
            paid(3) > Amount::from_afri(1_000),
            "and everybody leaves with more than they paid in"
        );
        assert_eq!(group.round, 1);
        assert_eq!(
            group.total_shares(),
            0,
            "everyone starts the next round level"
        );
    }

    #[test]
    fn a_share_out_never_pays_out_more_than_the_fund_holds() {
        // Truncated division on somebody's savings, over every share split a
        // group can reach. If this ever fails the group is paying out money it
        // does not have, and the shortfall lands on whoever is paid last.
        for members in 2u8..=8 {
            for spread in 0..12u64 {
                let mut group = vikoba(members);
                for i in 0..members {
                    let shares = u32::try_from((u64::from(i) + spread) % 5 + 1).expect("small");
                    group.buy_shares(&addr(i + 1), shares).expect("legal");
                }
                for cycle in 0..4 {
                    group.advance_cycle(Height(cycle + 1));
                }
                let fund = Amount::from_units(1_000_000_007 + u128::from(spread) * 37);
                let payments = group.share_out(fund).expect("due");
                let total: u128 = payments.iter().map(|(_, a)| a.units()).sum();
                assert!(
                    total <= fund.units(),
                    "{members} members, spread {spread}: paid out {total} of {}",
                    fund.units()
                );
            }
        }
    }

    #[test]
    fn a_lapsed_proposal_does_not_block_the_group_forever() {
        // Otherwise one member holding an open question freezes every later one,
        // and a group is stuck for the price of a single fee.
        let mut group = vikoba(4);
        group
            .open_proposal(
                addr(2),
                ProposalKind::SocialGrant {
                    amount: Amount::from_afri(10),
                },
                Amount::from_afri(1_000),
            )
            .expect_err("nothing in the social fund yet");

        group.social_fund = Amount::from_afri(100);
        group
            .open_proposal(
                addr(2),
                ProposalKind::SocialGrant {
                    amount: Amount::from_afri(10),
                },
                Amount::from_afri(1_000),
            )
            .expect("now it is affordable");
        assert_eq!(
            group.open_proposal(
                addr(3),
                ProposalKind::SocialGrant {
                    amount: Amount::from_afri(10),
                },
                Amount::from_afri(1_000),
            ),
            Err(GroupError::ProposalPending)
        );

        group.advance_cycle(Height(1));
        assert!(group.pending.is_none(), "an undecided question lapses");
        group
            .open_proposal(
                addr(3),
                ProposalKind::SocialGrant {
                    amount: Amount::from_afri(10),
                },
                Amount::from_afri(1_000),
            )
            .expect("and the next member may ask");
    }

    #[test]
    fn a_repeated_approval_is_refused_rather_than_counted() {
        let mut group = vikoba(4);
        group.social_fund = Amount::from_afri(100);
        group
            .open_proposal(
                addr(2),
                ProposalKind::SocialGrant {
                    amount: Amount::from_afri(10),
                },
                Amount::from_afri(1_000),
            )
            .expect("affordable");
        assert_eq!(group.approve(addr(3)), Ok(false));
        assert_eq!(group.approve(addr(3)), Err(GroupError::AlreadyApproved));
        assert_eq!(group.approve(addr(4)), Ok(false));
        assert_eq!(
            group.approve(addr(1)),
            Ok(true),
            "three of four reaches a two-thirds quorum"
        );
    }

    #[test]
    fn a_record_with_unsorted_approvals_is_refused_rather_than_sorted() {
        // The approvals decide whether money leaves the fund, and the record is
        // hashed into the state root. Repairing it here would give one state two
        // spellings — and would quietly turn a repeated approval into a valid
        // one.
        let mut group = vikoba(4);
        group.social_fund = Amount::from_afri(100);
        group
            .open_proposal(
                addr(2),
                ProposalKind::SocialGrant {
                    amount: Amount::from_afri(10),
                },
                Amount::from_afri(1_000),
            )
            .expect("affordable");
        group.approve(addr(3)).expect("member");
        group.approve(addr(4)).expect("member");

        let mut broken = group.clone();
        let pending = broken.pending.as_mut().expect("open");
        pending.approvals.reverse();
        assert!(decode_exact::<GroupAccount>(&broken.to_bytes()).is_err());

        let mut doubled = group.clone();
        let pending = doubled.pending.as_mut().expect("open");
        let first = pending.approvals[0];
        pending.approvals.insert(0, first);
        assert!(decode_exact::<GroupAccount>(&doubled.to_bytes()).is_err());

        assert_eq!(decode_exact::<GroupAccount>(&group.to_bytes()), Ok(group));
    }

    #[test]
    fn an_overdue_debt_is_fined_once_however_long_it_stays_late() {
        let mut group = vikoba(4);
        group.buy_shares(&addr(2), 5).expect("legal");
        let member = group
            .members
            .iter_mut()
            .find(|m| m.address == addr(2))
            .expect("exists");
        member.loan = Some(Loan {
            principal: Amount::from_afri(1_000),
            service_charge: Amount::from_afri(100),
            repaid: Amount::ZERO,
            due_cycle: 1,
            guarantors: vec![addr(3)],
            fined: false,
        });

        for cycle in 0..4 {
            group.advance_cycle(Height(cycle + 1));
        }
        assert_eq!(
            group.member(&addr(2)).expect("exists").fines_owed,
            Amount::from_afri(110),
            "10% of the 1,100 outstanding, once — not once per late cycle"
        );
    }

    #[test]
    fn a_settled_loan_counts_and_an_unsettled_one_does_not() {
        let mut group = vikoba(4);
        group.buy_shares(&addr(2), 5).expect("legal");
        let member = group
            .members
            .iter_mut()
            .find(|m| m.address == addr(2))
            .expect("exists");
        member.loan = Some(Loan {
            principal: Amount::from_afri(1_000),
            service_charge: Amount::from_afri(100),
            repaid: Amount::ZERO,
            due_cycle: 2,
            guarantors: vec![addr(3)],
            fined: false,
        });

        assert_eq!(
            group.repay(&addr(2), Amount::from_afri(2_000)),
            Err(GroupError::Overpayment {
                owed: Amount::from_afri(1_100).units().to_string()
            })
        );
        group
            .repay(&addr(2), Amount::from_afri(600))
            .expect("partial");
        assert!(
            group.member(&addr(2)).expect("exists").loan.is_some(),
            "half a repayment is not a repayment"
        );
        group
            .repay(&addr(2), Amount::from_afri(500))
            .expect("the rest");

        let member = group.member(&addr(2)).expect("exists");
        assert!(member.loan.is_none());
        assert_eq!(member.loans_repaid, 1);
        assert_eq!(member.repayment_bps(), Some(10_000));
    }

    #[test]
    fn a_member_who_has_never_borrowed_is_unrated_not_flawless() {
        // The same trap as `reliability_bps`: reporting a perfect repayment
        // record for someone who has never repaid anything would let a fresh
        // account present itself as a proven borrower.
        assert_eq!(
            vikoba(4).member(&addr(2)).expect("exists").repayment_bps(),
            None
        );
    }

    #[test]
    fn a_vikoba_round_trips_through_the_canonical_codec() {
        let mut group = vikoba(4);
        group.buy_shares(&addr(2), 3).expect("legal");
        group.social_fund = Amount::from_afri(200);
        group
            .open_proposal(
                addr(2),
                ProposalKind::Loan {
                    principal: Amount::from_afri(1_000),
                    guarantors: vec![addr(3)],
                },
                Amount::from_afri(10_000),
            )
            .expect("affordable and covered");
        group.approve(addr(4)).expect("member");
        assert_eq!(decode_exact::<GroupAccount>(&group.to_bytes()), Ok(group));
    }

    #[test]
    fn a_round_that_started_after_the_current_cycle_is_refused_on_decode() {
        // It would make `cycles_this_round` saturate to zero and the round never
        // complete — savings a group could pay into and never share out.
        let mut group = vikoba(4);
        group.round_start_cycle = 7;
        assert!(decode_exact::<GroupAccount>(&group.to_bytes()).is_err());
    }
}
