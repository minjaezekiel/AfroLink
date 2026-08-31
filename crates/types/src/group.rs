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
        }
    }

    /// Whether this member has already paid into `cycle`.
    #[must_use]
    pub fn has_paid(&self, cycle: u64) -> bool {
        self.last_paid_cycle == Some(cycle)
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
    /// ASCA/VSLA: the pot accumulates and is lent out, rather than rotating.
    Accumulate,
}

/// The recurring obligation each member takes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    /// Amount due each cycle.
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
    /// Cycles completed since formation.
    pub cycle: u64,
    /// Height at which the cycle now open began.
    ///
    /// Without it `Contribution::period_blocks` is a number nobody reads, and
    /// "the cycle is over" has no definition the chain can check — which is what
    /// let any member advance the rotation at will.
    pub cycle_started: Height,
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

        if let PayoutPolicy::Rotation { order, next } = &policy {
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

        Ok(Self {
            name,
            members,
            contribution,
            policy,
            quorum,
            cycle: 0,
            cycle_started: opened_at,
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
            PayoutPolicy::Accumulate => None,
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
        for member in &mut self.members {
            if !member.has_paid(closing) {
                member.contributions_missed = member.contributions_missed.saturating_add(1);
            }
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

impl Encode for Member {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.role.encode(out);
        self.joined_cycle.encode(out);
        self.contributions_made.encode(out);
        self.contributions_missed.encode(out);
        self.last_paid_cycle.encode(out);
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
            Self::Accumulate => out.push(1),
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
            1 => Ok(Self::Accumulate),
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
                PayoutPolicy::Accumulate,
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
                PayoutPolicy::Accumulate,
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
                PayoutPolicy::Accumulate,
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
                PayoutPolicy::Accumulate,
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
            PayoutPolicy::Accumulate,
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
}
