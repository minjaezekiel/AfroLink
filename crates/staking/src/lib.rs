//! Staking: making the economic half of the security argument real.
//!
//! [ADR-0010](../../../docs/adr/0010-long-range-attacks.md) closed the
//! long-range attack in the light client and was explicit about what it had not
//! done:
//!
//! > **Deliberately not done.** Validator set *changes* are committed to in
//! > headers but there is no mechanism to actually change the set yet — that is
//! > staking, and it is Phase 2. Slashing is likewise Phase 2, and until it
//! > exists the unbonding period is a documented parameter rather than an
//! > enforced one.
//!
//! This is that. `UNBONDING_MS` now locks real money, and equivocation now costs
//! its author something.
//!
//! # The two things that are easy to get wrong
//!
//! **Slashing must reach stake that has already begun unbonding.** Otherwise a
//! validator equivocates, unbonds in the same block, and by the time anyone
//! submits the evidence the money is sitting in a queue nobody thinks to touch.
//! The whole 21-day window buys exactly nothing. Every [`Unbonding`] entry
//! therefore records the height at which it left, and an infraction at height
//! `h` reaches every entry that was still bonded then. See
//! [`Unbonding::covers`].
//!
//! **Concentration limits must not be able to halt the chain.** The obvious
//! reading of [ADR-0007](../../../docs/adr/0007-distribution-and-sybil-resistance.md)'s
//! ceiling is "refuse to build a set that breaches it" — and then validators
//! leave, the remaining set breaches it, and no set can be built at all. Excess
//! power is discarded instead, so the ceiling shapes incentives without ever
//! being able to stop block production. See [`set::active_set`].
//!
//! # Jailing and slashing are different things
//!
//! Slashing takes money, once. Jailing stops the operator signing until
//! governance releases them. Only the second protects the chain from a validator
//! that is misbehaving *right now* — a slashed validator with stake remaining is
//! still in the set unless jailing removes them.
//!
//! # What is deliberately not here
//!
//! **Delegation.** A holder cannot yet stake through someone else's validator.
//! It is the single largest addition to this module's surface — reward
//! accounting, partial slashing across delegators, withdrawal of rewards — and
//! folding it in alongside the slashing rules above would make both harder to
//! review. The state namespace is reserved.
//!
//! **Downtime slashing.** Signing-liveness tracking needs the block-level vote
//! history a networked node has and this one does not. Equivocation is the
//! infraction that breaks *safety*, and it is provable from two signatures
//! alone; downtime only costs liveness and needs a window of observations.
//!
//! **Rewards.** Emission schedule is [02](../../../docs/02-tokenomics.md) and
//! belongs with the fee market, not here.

#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
    )
)]

pub mod bond;
pub mod set;

pub use bond::{Bond, Unbonding};
pub use set::{active_set, power_of};

use afrolink_bank::Bank;
use afrolink_consensus::{CountryCode, Equivocation, ValidatorSet};
use afrolink_crypto::{Address, PublicKey};
use afrolink_primitives::codec::{Encode, decode_exact};
use afrolink_primitives::{Amount, Denom, Height, Timestamp};
use afrolink_state::{KeyValueStore, StateError, StoreKey};
use thiserror::Error;

/// How long stake stays slashable after unbonding begins.
///
/// Taken from `afrolink_primitives` rather than redefined, because the light
/// client derives its trusting period from the same constant and the two must
/// never drift. See [ADR-0010](../../../docs/adr/0010-long-range-attacks.md).
pub use afrolink_primitives::UNBONDING_MS;

/// Fraction of stake destroyed for equivocation, in basis points.
///
/// 5%. High enough that a validator running two machines by accident feels it
/// and fixes the setup; low enough that a single operational mistake is not
/// fatal to a small operator, which matters when the target validator set spans
/// countries where the capital involved is significant.
pub const SLASH_EQUIVOCATION_BPS: u32 = 500;

/// The module account holding every bond.
///
/// Bonded stake leaves the operator's balance entirely. It is not "locked in
/// place" with a flag, because a flag is one forgotten check away from being
/// spendable, and the balance is the thing every other module reads.
#[must_use]
pub fn staking_account() -> Address {
    Address::derived(afrolink_crypto::hash::Domain::ModuleAddress, b"staking")
}

/// Tunable limits.
///
/// Defined in `crates/gov` and re-exported here. It moved when governance
/// arrived: a number the network votes on is a value shared between modules,
/// not a private detail of the one module that reads it — the same move
/// [`CountryCode`](afrolink_primitives::CountryCode) made when a second user
/// appeared. Every existing import keeps working.
pub use afrolink_gov::StakingParams;

/// Why a staking operation failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StakingError {
    /// The bond would be below [`StakingParams::min_bond`].
    #[error("bond of {got} is below the minimum of {min}")]
    BelowMinimumBond {
        /// Offered.
        got: String,
        /// Required.
        min: String,
    },
    /// No bond exists for that operator.
    #[error("no bond for this operator")]
    NoSuchBond,
    /// The operator already has a bond.
    #[error("this operator already has a bond")]
    AlreadyBonded,
    /// Unbonding more than is bonded.
    #[error("cannot unbond {requested}; only {bonded} is bonded")]
    InsufficientBond {
        /// Requested.
        requested: String,
        /// Available.
        bonded: String,
    },
    /// The unbonding queue for this operator is full.
    #[error("too many queued unbonding entries; wait for one to mature")]
    TooManyUnbondingEntries,
    /// No more operators may bond.
    #[error("the candidate set is full")]
    CandidateSetFull,
    /// Nothing has matured yet.
    #[error("no unbonding entry has matured yet")]
    NothingMatured,
    /// The active set would be empty.
    #[error("no validator qualifies for the active set")]
    NoEligibleValidators,
    /// The evidence does not show equivocation.
    #[error("evidence does not prove equivocation")]
    NotEquivocation,
    /// The offender has already been punished for this.
    #[error("this operator is already jailed")]
    AlreadyJailed,
    /// A zero-valued operation.
    #[error("amount must be greater than zero")]
    ZeroAmount,
    /// The bank refused.
    #[error(transparent)]
    Bank(#[from] afrolink_bank::BankError),
    /// Corrupt state.
    #[error(transparent)]
    State(#[from] StateError),
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, StakingError>;

/// Staking operations over a borrowed store.
pub struct Staking<'a, S: KeyValueStore> {
    store: &'a mut S,
    params: StakingParams,
}

impl<'a, S: KeyValueStore> Staking<'a, S> {
    /// Open the module with default parameters.
    pub fn new(store: &'a mut S) -> Self {
        Self {
            store,
            params: StakingParams::default(),
        }
    }

    /// Open the module with explicit parameters.
    pub fn with_params(store: &'a mut S, params: StakingParams) -> Self {
        Self { store, params }
    }

    /// The parameters in force.
    #[must_use]
    pub fn params(&self) -> &StakingParams {
        &self.params
    }

    /// Read one operator's bond.
    ///
    /// # Errors
    /// [`StakingError::State`] if the record is corrupt.
    pub fn bond_of(&self, operator: &Address) -> Result<Option<Bond>> {
        let Some(bytes) = self.store.get(&StoreKey::bond(operator)) else {
            return Ok(None);
        };
        decode_exact::<Bond>(&bytes)
            .map(Some)
            .map_err(|e| corrupt("bond", &e))
    }

    /// Read one operator's unbonding queue.
    ///
    /// # Errors
    /// [`StakingError::State`] if the record is corrupt.
    pub fn unbonding_of(&self, operator: &Address) -> Result<Vec<Unbonding>> {
        let Some(bytes) = self.store.get(&StoreKey::unbonding(operator)) else {
            return Ok(Vec::new());
        };
        decode_exact::<Vec<Unbonding>>(&bytes).map_err(|e| corrupt("bond", &e))
    }

    /// Every operator holding a bond.
    ///
    /// # Errors
    /// [`StakingError::State`] if the index is corrupt.
    pub fn candidates(&self) -> Result<Vec<Address>> {
        let Some(bytes) = self.store.get(&StoreKey::bond_index()) else {
            return Ok(Vec::new());
        };
        decode_exact::<Vec<Address>>(&bytes).map_err(|e| corrupt("bond", &e))
    }

    /// Every bond, in candidate-index order.
    ///
    /// # Errors
    /// [`StakingError::State`] if any record is corrupt.
    pub fn bonds(&self) -> Result<Vec<Bond>> {
        let mut out = Vec::new();
        for operator in self.candidates()? {
            if let Some(bond) = self.bond_of(&operator)? {
                out.push(bond);
            }
        }
        Ok(out)
    }

    /// Derive the active validator set.
    ///
    /// # Errors
    /// [`StakingError::NoEligibleValidators`] if nothing qualifies.
    pub fn active_set(&self) -> Result<ValidatorSet> {
        set::active_set(&self.bonds()?, &self.params)
    }

    /// Lock stake and register as a validator candidate.
    ///
    /// The stake moves out of the operator's balance into the module account. A
    /// balance flag would be one forgotten check away from being spendable.
    ///
    /// # Errors
    /// [`StakingError::BelowMinimumBond`], [`StakingError::AlreadyBonded`],
    /// [`StakingError::CandidateSetFull`], or a bank error if the operator
    /// cannot cover it.
    pub fn bond(
        &mut self,
        operator: &Address,
        public_key: PublicKey,
        country: CountryCode,
        amount: Amount,
    ) -> Result<()> {
        if amount.is_zero() {
            return Err(StakingError::ZeroAmount);
        }
        if amount.units() < self.params.min_bond.units() {
            return Err(StakingError::BelowMinimumBond {
                got: amount.to_string(),
                min: self.params.min_bond.to_string(),
            });
        }
        if self.bond_of(operator)?.is_some() {
            return Err(StakingError::AlreadyBonded);
        }
        let mut index = self.candidates()?;
        if index.len() >= self.params.max_candidates {
            return Err(StakingError::CandidateSetFull);
        }

        Bank::new(self.store).transfer(operator, &staking_account(), &Denom::native(), amount)?;

        let bond = Bond::new(*operator, public_key, country, amount);
        self.write_bond(&bond);
        index.push(*operator);
        // Sorted so the candidate list — and therefore every derived set — is
        // identical on every node regardless of the order bonds arrived in.
        index.sort_unstable();
        self.write_index(&index);
        Ok(())
    }

    /// Add to an existing bond.
    ///
    /// # Errors
    /// [`StakingError::NoSuchBond`], or a bank error.
    pub fn add_stake(&mut self, operator: &Address, amount: Amount) -> Result<()> {
        if amount.is_zero() {
            return Err(StakingError::ZeroAmount);
        }
        let mut bond = self.bond_of(operator)?.ok_or(StakingError::NoSuchBond)?;
        Bank::new(self.store).transfer(operator, &staking_account(), &Denom::native(), amount)?;
        bond.bonded = bond
            .bonded
            .checked_add(amount)
            .map_err(|_| StakingError::ZeroAmount)?;
        self.write_bond(&bond);
        Ok(())
    }

    /// Begin withdrawing stake.
    ///
    /// The stake leaves the active set immediately and the funds stay in the
    /// module account, still slashable, until `unbonding_ms` has elapsed.
    ///
    /// # Errors
    /// [`StakingError::NoSuchBond`], [`StakingError::InsufficientBond`], or
    /// [`StakingError::TooManyUnbondingEntries`].
    pub fn unbond(
        &mut self,
        operator: &Address,
        amount: Amount,
        height: Height,
        now: Timestamp,
    ) -> Result<()> {
        if amount.is_zero() {
            return Err(StakingError::ZeroAmount);
        }
        let mut bond = self.bond_of(operator)?.ok_or(StakingError::NoSuchBond)?;
        if amount.units() > bond.bonded.units() {
            return Err(StakingError::InsufficientBond {
                requested: amount.to_string(),
                bonded: bond.bonded.to_string(),
            });
        }
        let mut queue = self.unbonding_of(operator)?;
        if queue.len() >= self.params.max_unbonding_entries {
            return Err(StakingError::TooManyUnbondingEntries);
        }

        bond.bonded = bond
            .bonded
            .checked_sub(amount)
            .map_err(|_| StakingError::ZeroAmount)?;
        queue.push(Unbonding {
            amount,
            // The field the whole unbonding period rests on: an infraction at
            // any height below this one still reaches this stake.
            started_at: height,
            completes_at: Timestamp::from_millis(now.0.saturating_add(self.params.unbonding_ms)),
        });
        self.write_bond(&bond);
        self.write_queue(operator, &queue);
        Ok(())
    }

    /// Withdraw every matured unbonding entry.
    ///
    /// Returns the amount released.
    ///
    /// # Errors
    /// [`StakingError::NothingMatured`] if no entry has completed its period.
    pub fn withdraw(&mut self, operator: &Address, now: Timestamp) -> Result<Amount> {
        let queue = self.unbonding_of(operator)?;
        let (matured, pending): (Vec<Unbonding>, Vec<Unbonding>) =
            queue.into_iter().partition(|e| e.matured(now));

        if matured.is_empty() {
            return Err(StakingError::NothingMatured);
        }
        let mut total = Amount::ZERO;
        for entry in &matured {
            total = total
                .checked_add(entry.amount)
                .map_err(|_| StakingError::ZeroAmount)?;
        }

        self.write_queue(operator, &pending);
        if !total.is_zero() {
            Bank::new(self.store).transfer(
                &staking_account(),
                operator,
                &Denom::native(),
                total,
            )?;
        }
        Ok(total)
    }

    /// Punish an operator for signing two conflicting votes.
    ///
    /// Destroys [`SLASH_EQUIVOCATION_BPS`] of the operator's bonded stake **and
    /// of every unbonding entry that was still bonded at the infraction
    /// height**, then jails them.
    ///
    /// The second half is the point. Without it, unbonding in the same block as
    /// the infraction makes the stake untouchable, and the unbonding period
    /// protects nothing.
    ///
    /// # Errors
    /// [`StakingError::NotEquivocation`] if the evidence does not prove it,
    /// [`StakingError::NoSuchBond`] if the offender never bonded, or
    /// [`StakingError::AlreadyJailed`].
    pub fn slash_equivocation(
        &mut self,
        evidence: &Equivocation,
        set: &ValidatorSet,
        height: Height,
    ) -> Result<Amount> {
        // The evidence has to prove itself. A caller handing over two unrelated
        // votes must not be able to destroy somebody's stake.
        if !proves_equivocation(evidence, set) {
            return Err(StakingError::NotEquivocation);
        }
        self.slash(&evidence.validator, evidence.first.vote.height, height)
    }

    /// Slash and jail an operator for an infraction committed at
    /// `infraction_height`.
    ///
    /// # Errors
    /// [`StakingError::NoSuchBond`] or [`StakingError::AlreadyJailed`].
    pub fn slash(
        &mut self,
        operator: &Address,
        infraction_height: Height,
        now_height: Height,
    ) -> Result<Amount> {
        let mut bond = self.bond_of(operator)?.ok_or(StakingError::NoSuchBond)?;
        if bond.jailed {
            return Err(StakingError::AlreadyJailed);
        }

        let bps = u128::from(SLASH_EQUIVOCATION_BPS);
        let from_bond = fraction(bond.bonded, bps);

        // Every entry that was still bonded when the infraction happened.
        let mut queue = self.unbonding_of(operator)?;
        let mut from_queue = Amount::ZERO;
        for entry in &mut queue {
            if !entry.covers(infraction_height) {
                continue;
            }
            let take = fraction(entry.amount, bps);
            entry.amount = entry
                .amount
                .checked_sub(take)
                .map_err(|_| StakingError::ZeroAmount)?;
            from_queue = from_queue
                .checked_add(take)
                .map_err(|_| StakingError::ZeroAmount)?;
        }

        let total = from_bond
            .checked_add(from_queue)
            .map_err(|_| StakingError::ZeroAmount)?;

        bond.bonded = bond
            .bonded
            .checked_sub(from_bond)
            .map_err(|_| StakingError::ZeroAmount)?;
        // Jailing is what stops the ongoing misbehaviour; slashing only prices
        // what already happened.
        bond.jailed = true;
        bond.jailed_at = Some(now_height);

        self.write_bond(&bond);
        self.write_queue(operator, &queue);
        if !total.is_zero() {
            Bank::new(self.store).slash_native(&staking_account(), total)?;
        }
        Ok(total)
    }

    /// Release a jailed operator back into the candidate set.
    ///
    /// Governance-only. Not exposed as a transaction message: an operator who
    /// could unjail themselves is not jailed.
    ///
    /// # Errors
    /// [`StakingError::NoSuchBond`].
    pub fn unjail(&mut self, operator: &Address) -> Result<()> {
        let mut bond = self.bond_of(operator)?.ok_or(StakingError::NoSuchBond)?;
        bond.jailed = false;
        bond.jailed_at = None;
        self.write_bond(&bond);
        Ok(())
    }

    fn write_bond(&mut self, bond: &Bond) {
        self.store
            .set(&StoreKey::bond(&bond.operator), bond.to_bytes());
    }

    fn write_queue(&mut self, operator: &Address, queue: &[Unbonding]) {
        let key = StoreKey::unbonding(operator);
        if queue.is_empty() {
            self.store.delete(&key);
        } else {
            self.store.set(&key, queue.to_vec().to_bytes());
        }
    }

    fn write_index(&mut self, index: &[Address]) {
        self.store
            .set(&StoreKey::bond_index(), index.to_vec().to_bytes());
    }
}

fn corrupt(what: &str, e: &afrolink_primitives::codec::CodecError) -> StakingError {
    StakingError::State(StateError::Corrupt {
        key: what.to_owned(),
        reason: e.to_string(),
    })
}

/// `amount * bps / 10_000`, rounded down.
fn fraction(amount: Amount, bps: u128) -> Amount {
    Amount::from_units(amount.units().saturating_mul(bps).saturating_div(10_000))
}

/// Whether this evidence really shows one validator signing two conflicting
/// votes.
///
/// Checked rather than trusted: `Equivocation` is a plain struct that anyone can
/// build, and accepting it on faith would let a caller destroy any validator's
/// stake by asserting misbehaviour.
#[must_use]
pub fn proves_equivocation(evidence: &Equivocation, set: &ValidatorSet) -> bool {
    let (a, b) = (&evidence.first, &evidence.second);

    // Same signer, and one the chain actually recognises.
    if a.vote.validator != evidence.validator || b.vote.validator != evidence.validator {
        return false;
    }
    let Some(validator) = set.get(&evidence.validator) else {
        return false;
    };

    // Same slot, different content. Voting twice at different heights or rounds
    // is ordinary behaviour, not an infraction.
    if a.vote.height != b.vote.height
        || a.vote.round != b.vote.round
        || a.vote.vote_type != b.vote.vote_type
    {
        return false;
    }
    if a.vote.block_id == b.vote.block_id {
        return false;
    }

    // And both must genuinely be signed by that validator, or this is an
    // accusation rather than evidence.
    let domain = afrolink_crypto::hash::Domain::VoteSignDoc;
    validator
        .public_key
        .verify(domain, &a.vote.sign_doc(), &a.signature)
        .is_ok()
        && validator
            .public_key
            .verify(domain, &b.vote.sign_doc(), &b.signature)
            .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_consensus::{Validator, Vote, VoteType};
    use afrolink_crypto::SecretKey;
    use afrolink_crypto::hash::Hash32;
    use afrolink_primitives::Round;
    use afrolink_state::MemoryStore;

    const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    fn ke() -> CountryCode {
        CountryCode::new("ke").expect("valid")
    }

    fn params() -> StakingParams {
        StakingParams {
            min_bond: Amount::from_afri(1_000),
            max_single_share_bps: 10_000,
            ..StakingParams::default()
        }
    }

    fn at(day: u64) -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000 + day * DAY_MS)
    }

    /// A store where operators 1..=n each hold `funded` AFRI.
    fn funded_store(n: u8, funded: u64) -> MemoryStore {
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        for seed in 1..=n {
            bank.genesis_allocate(&addr(seed), &Denom::native(), Amount::from_afri(funded))
                .expect("allocates");
        }
        store
    }

    fn staking(store: &mut MemoryStore) -> Staking<'_, MemoryStore> {
        Staking::with_params(store, params())
    }

    fn bond_one(store: &mut MemoryStore, seed: u8, afri: u64) {
        staking(store)
            .bond(
                &addr(seed),
                key(seed).public_key(),
                ke(),
                Amount::from_afri(afri),
            )
            .expect("bonds");
    }

    #[test]
    fn bonding_moves_the_stake_out_of_the_operators_balance() {
        // Not a flag on the balance: bonded stake must be unspendable by every
        // path, including ones written later that forget to check a flag.
        let mut store = funded_store(1, 10_000);
        bond_one(&mut store, 1, 4_000);

        let bank = Bank::new(&mut store);
        assert_eq!(
            bank.balance(&addr(1), &Denom::native()).expect("reads"),
            Amount::from_afri(6_000)
        );
        assert_eq!(
            bank.balance(&staking_account(), &Denom::native())
                .expect("reads"),
            Amount::from_afri(4_000)
        );
    }

    #[test]
    fn stake_cannot_be_spent_while_bonded() {
        let mut store = funded_store(1, 10_000);
        bond_one(&mut store, 1, 9_000);

        let moved = Bank::new(&mut store).transfer(
            &addr(1),
            &addr(2),
            &Denom::native(),
            Amount::from_afri(2_000),
        );
        assert!(moved.is_err(), "only 1 000 AFRI is left unbonded");
    }

    #[test]
    fn unbonded_stake_is_not_released_before_the_period_elapses() {
        // The 21 days is the whole basis of the light client's trusting period.
        // If it can be skipped, ADR-0010's argument collapses.
        let mut store = funded_store(1, 10_000);
        bond_one(&mut store, 1, 8_000);
        staking(&mut store)
            .unbond(&addr(1), Amount::from_afri(8_000), Height(10), at(0))
            .expect("unbonds");

        for day in [0u64, 1, 20] {
            assert_eq!(
                staking(&mut store).withdraw(&addr(1), at(day)),
                Err(StakingError::NothingMatured),
                "released on day {day}"
            );
        }
        assert_eq!(
            staking(&mut store)
                .withdraw(&addr(1), at(21))
                .expect("matured"),
            Amount::from_afri(8_000)
        );
    }

    #[test]
    fn slashing_reaches_stake_that_has_already_begun_unbonding() {
        // **The property the unbonding period exists for.** A validator
        // equivocates at height 10 and unbonds everything at height 11, long
        // before anyone submits evidence. If the queued stake were exempt, the
        // 21-day window would buy nothing at all.
        let mut store = funded_store(1, 100_000);
        bond_one(&mut store, 1, 50_000);
        staking(&mut store)
            .unbond(&addr(1), Amount::from_afri(50_000), Height(11), at(0))
            .expect("unbonds everything");

        assert_eq!(
            staking(&mut store)
                .bond_of(&addr(1))
                .expect("reads")
                .expect("exists")
                .bonded,
            Amount::ZERO,
            "nothing is bonded any more, so only the queue can be slashed"
        );

        let burned = staking(&mut store)
            .slash(&addr(1), Height(10), Height(30))
            .expect("slashes");
        assert_eq!(
            burned,
            Amount::from_afri(2_500),
            "5% of the queued 50 000 must still be reachable"
        );

        // And what is eventually withdrawn is the reduced amount.
        let released = staking(&mut store)
            .withdraw(&addr(1), at(21))
            .expect("matured");
        assert_eq!(released, Amount::from_afri(47_500));
    }

    #[test]
    fn slashing_does_not_reach_stake_that_left_before_the_infraction() {
        // The other half of the same rule. Stake that had already stopped
        // securing the chain must not answer for what happened afterwards —
        // taking it would be confiscation, not slashing.
        let mut store = funded_store(1, 100_000);
        bond_one(&mut store, 1, 50_000);
        staking(&mut store)
            .unbond(&addr(1), Amount::from_afri(20_000), Height(5), at(0))
            .expect("unbonds early");

        let burned = staking(&mut store)
            .slash(&addr(1), Height(50), Height(60))
            .expect("slashes");

        // 5% of the 30 000 still bonded, and nothing from the entry that left
        // at height 5.
        assert_eq!(burned, Amount::from_afri(1_500));
        let queue = staking(&mut store).unbonding_of(&addr(1)).expect("reads");
        assert_eq!(queue[0].amount, Amount::from_afri(20_000), "untouched");
    }

    #[test]
    fn slashed_stake_is_destroyed_rather_than_paid_to_anyone() {
        // Paying it to a treasury or a reporter creates a party that profits
        // from slashing, and therefore one with a reason to manufacture it.
        let mut store = funded_store(1, 100_000);
        bond_one(&mut store, 1, 50_000);
        let before = Bank::new(&mut store)
            .total_supply(&Denom::native())
            .expect("reads");

        let burned = staking(&mut store)
            .slash(&addr(1), Height(1), Height(2))
            .expect("slashes");

        let after = Bank::new(&mut store)
            .total_supply(&Denom::native())
            .expect("reads");
        assert_eq!(
            after.units(),
            before.units() - burned.units(),
            "supply must fall by exactly the slashed amount"
        );
    }

    #[test]
    fn a_slashed_validator_is_jailed_and_leaves_the_active_set() {
        // Slashing prices what already happened; only jailing stops what is
        // happening now.
        let mut store = funded_store(3, 100_000);
        for seed in 1..=3u8 {
            bond_one(&mut store, seed, 10_000);
        }
        assert_eq!(
            staking(&mut store)
                .active_set()
                .expect("set forms")
                .validators()
                .len(),
            3
        );

        staking(&mut store)
            .slash(&addr(2), Height(1), Height(2))
            .expect("slashes");

        let set = staking(&mut store).active_set().expect("set forms");
        assert_eq!(set.validators().len(), 2);
        assert!(
            set.get(&addr(2)).is_none(),
            "a jailed validator must not be able to sign"
        );
    }

    #[test]
    fn an_operator_cannot_be_slashed_twice_for_the_same_infraction() {
        let mut store = funded_store(1, 100_000);
        bond_one(&mut store, 1, 50_000);
        staking(&mut store)
            .slash(&addr(1), Height(1), Height(2))
            .expect("slashes");
        assert_eq!(
            staking(&mut store).slash(&addr(1), Height(1), Height(2)),
            Err(StakingError::AlreadyJailed)
        );
    }

    /// Two conflicting precommits by `seed` at the same height and round.
    fn equivocation(seed: u8, height: u64) -> Equivocation {
        let make = |block: [u8; 32]| {
            Vote {
                chain_id: afrolink_primitives::ChainId::new("afrolink-1").expect("valid"),
                height: Height(height),
                round: Round::ZERO,
                vote_type: VoteType::Precommit,
                block_id: Some(Hash32::from_bytes(block)),
                validator: addr(seed),
            }
            .sign(&key(seed))
        };
        Equivocation {
            validator: addr(seed),
            first: make([0xAA; 32]),
            second: make([0xBB; 32]),
        }
    }

    fn set_of(seeds: &[u8]) -> ValidatorSet {
        ValidatorSet::new(
            seeds
                .iter()
                .map(|s| Validator::new(key(*s).public_key(), 10, ke()))
                .collect(),
        )
        .expect("valid set")
    }

    #[test]
    fn genuine_equivocation_evidence_is_punished() {
        let mut store = funded_store(2, 100_000);
        bond_one(&mut store, 1, 50_000);
        let evidence = equivocation(1, 7);

        let burned = staking(&mut store)
            .slash_equivocation(&evidence, &set_of(&[1, 2]), Height(9))
            .expect("evidence is genuine");
        assert_eq!(burned, Amount::from_afri(2_500));
    }

    #[test]
    fn an_accusation_without_two_real_signatures_destroys_nothing() {
        // `Equivocation` is a plain struct anyone can build. Accepting it on
        // faith would let a caller destroy any validator's stake by asserting
        // misbehaviour.
        let mut store = funded_store(2, 100_000);
        bond_one(&mut store, 1, 50_000);

        // Signed by validator 2, but blamed on validator 1.
        let mut framed = equivocation(2, 7);
        framed.validator = addr(1);

        assert_eq!(
            staking(&mut store).slash_equivocation(&framed, &set_of(&[1, 2]), Height(9)),
            Err(StakingError::NotEquivocation)
        );
        assert_eq!(
            staking(&mut store)
                .bond_of(&addr(1))
                .expect("reads")
                .expect("exists")
                .bonded,
            Amount::from_afri(50_000),
            "an accusation must not move money"
        );
    }

    #[test]
    fn voting_twice_at_different_heights_is_not_equivocation() {
        // Ordinary behaviour: a validator votes at every height. Only two
        // conflicting votes in the *same* slot are an infraction.
        let a = equivocation(1, 7);
        let b = equivocation(1, 8);
        let not_evidence = Equivocation {
            validator: addr(1),
            first: a.first,
            second: b.second,
        };
        assert!(!proves_equivocation(&not_evidence, &set_of(&[1])));
    }

    #[test]
    fn the_same_vote_twice_is_not_equivocation() {
        let e = equivocation(1, 7);
        let duplicate = Equivocation {
            validator: addr(1),
            first: e.first.clone(),
            second: e.first,
        };
        assert!(!proves_equivocation(&duplicate, &set_of(&[1])));
    }

    #[test]
    fn evidence_against_a_non_validator_is_ignored() {
        let evidence = equivocation(9, 7);
        assert!(!proves_equivocation(&evidence, &set_of(&[1, 2])));
    }

    #[test]
    fn an_operator_cannot_bond_twice() {
        let mut store = funded_store(1, 100_000);
        bond_one(&mut store, 1, 10_000);
        assert_eq!(
            staking(&mut store).bond(
                &addr(1),
                key(1).public_key(),
                ke(),
                Amount::from_afri(10_000)
            ),
            Err(StakingError::AlreadyBonded)
        );
    }

    #[test]
    fn a_bond_below_the_minimum_is_refused() {
        let mut store = funded_store(1, 100_000);
        assert!(matches!(
            staking(&mut store).bond(&addr(1), key(1).public_key(), ke(), Amount::from_afri(10)),
            Err(StakingError::BelowMinimumBond { .. })
        ));
    }

    #[test]
    fn an_operator_cannot_unbond_more_than_they_staked() {
        let mut store = funded_store(1, 100_000);
        bond_one(&mut store, 1, 10_000);
        assert!(matches!(
            staking(&mut store).unbond(&addr(1), Amount::from_afri(10_001), Height(1), at(0)),
            Err(StakingError::InsufficientBond { .. })
        ));
    }

    #[test]
    fn the_unbonding_queue_is_bounded() {
        // Otherwise an operator makes their own queue too expensive to slash.
        let mut store = funded_store(1, 1_000_000);
        bond_one(&mut store, 1, 100_000);
        let max = params().max_unbonding_entries;
        for i in 0..max {
            staking(&mut store)
                .unbond(
                    &addr(1),
                    Amount::from_afri(100),
                    Height(i as u64 + 1),
                    at(0),
                )
                .expect("queues");
        }
        assert_eq!(
            staking(&mut store).unbond(&addr(1), Amount::from_afri(100), Height(99), at(0)),
            Err(StakingError::TooManyUnbondingEntries)
        );
    }

    #[test]
    fn only_matured_entries_are_released() {
        let mut store = funded_store(1, 1_000_000);
        bond_one(&mut store, 1, 100_000);
        staking(&mut store)
            .unbond(&addr(1), Amount::from_afri(1_000), Height(1), at(0))
            .expect("queues");
        staking(&mut store)
            .unbond(&addr(1), Amount::from_afri(2_000), Height(2), at(10))
            .expect("queues");

        // Day 21 matures the first only; the second completes on day 31.
        let released = staking(&mut store)
            .withdraw(&addr(1), at(21))
            .expect("one matured");
        assert_eq!(released, Amount::from_afri(1_000));
        assert_eq!(
            staking(&mut store)
                .unbonding_of(&addr(1))
                .expect("reads")
                .len(),
            1
        );
    }

    #[test]
    fn the_validator_set_tracks_stake_changes() {
        // The point of the whole module: the set is derived from stake, so
        // bonding and unbonding change who signs.
        let mut store = funded_store(4, 100_000);
        for seed in 1..=3u8 {
            bond_one(&mut store, seed, 10_000);
        }
        let before = staking(&mut store).active_set().expect("set forms");

        bond_one(&mut store, 4, 10_000);
        let after = staking(&mut store).active_set().expect("set forms");

        assert_eq!(before.validators().len(), 3);
        assert_eq!(after.validators().len(), 4);
        assert_ne!(
            before.hash(),
            after.hash(),
            "a set change must be visible in the hash a header commits to"
        );
    }

    #[test]
    fn unbonding_below_the_minimum_removes_a_validator_from_the_set() {
        let mut store = funded_store(3, 100_000);
        for seed in 1..=3u8 {
            bond_one(&mut store, seed, 10_000);
        }
        staking(&mut store)
            .unbond(&addr(3), Amount::from_afri(9_500), Height(1), at(0))
            .expect("unbonds most of it");

        let set = staking(&mut store).active_set().expect("set forms");
        assert_eq!(set.validators().len(), 2, "500 AFRI is below the minimum");
    }

    #[test]
    fn an_unjailed_operator_can_return() {
        let mut store = funded_store(2, 100_000);
        bond_one(&mut store, 1, 50_000);
        bond_one(&mut store, 2, 50_000);
        staking(&mut store)
            .slash(&addr(1), Height(1), Height(2))
            .expect("slashes");
        assert_eq!(
            staking(&mut store)
                .active_set()
                .expect("set forms")
                .validators()
                .len(),
            1
        );

        staking(&mut store).unjail(&addr(1)).expect("released");
        assert_eq!(
            staking(&mut store)
                .active_set()
                .expect("set forms")
                .validators()
                .len(),
            2
        );
    }

    #[test]
    fn the_candidate_index_is_ordered_identically_on_every_node() {
        // Two nodes that bond the same operators in different orders must
        // derive the same set, or they disagree about who proposes.
        let mut a = funded_store(4, 100_000);
        let mut b = funded_store(4, 100_000);
        for seed in [1u8, 2, 3, 4] {
            bond_one(&mut a, seed, 10_000);
        }
        for seed in [4u8, 3, 2, 1] {
            bond_one(&mut b, seed, 10_000);
        }
        assert_eq!(
            staking(&mut a).candidates().expect("reads"),
            staking(&mut b).candidates().expect("reads")
        );
        assert_eq!(
            staking(&mut a).active_set().expect("forms").hash(),
            staking(&mut b).active_set().expect("forms").hash()
        );
    }
}
