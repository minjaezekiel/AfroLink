//! Validator sets, voting power and proposer selection.
//!
//! # The quorum rule
//!
//! Byzantine agreement tolerates `f` faulty validators out of `3f + 1`. A
//! decision therefore needs **strictly more than two thirds** of voting power.
//! The classic implementation bug is writing `>=` where `>` belongs, or using
//! `2 * total / 3` and losing the remainder to integer division. Either lets two
//! disjoint quorums exist at once, which means two different blocks can be
//! committed at the same height — the exact failure BFT is supposed to prevent.
//!
//! [`ValidatorSet::quorum_threshold`] is therefore `floor(2 * total / 3) + 1`,
//! and it is tested against every total from 1 to 1000.

use afrolink_crypto::hash::{Domain, Hash32, hash, hash_parts};
use afrolink_crypto::{Address, PublicKey};
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Height, Round};
use thiserror::Error;

/// Errors from validator set construction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidatorError {
    /// A set with no validators cannot make progress.
    #[error("validator set must not be empty")]
    Empty,
    /// The same validator appears twice.
    #[error("duplicate validator in set")]
    Duplicate,
    /// A validator with no stake cannot vote.
    #[error("validator has zero voting power")]
    ZeroPower,
    /// Total voting power exceeded what can be counted.
    #[error("total voting power overflows")]
    PowerOverflow,
    /// A country code was not two lowercase ASCII letters.
    #[error("country code must be two lowercase ASCII letters")]
    InvalidCountry,
}

// `CountryCode` now lives in `crates/primitives`: the attestor registry needs
// one too, and a jurisdiction is not a consensus concept. Re-exported here so
// every existing import keeps working.
pub use afrolink_primitives::CountryCode;

/// One validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    /// The validator's account address.
    pub address: Address,
    /// Key used to sign consensus votes.
    pub public_key: PublicKey,
    /// Voting power, proportional to stake.
    pub voting_power: u64,
    /// Where the validator operates.
    pub country: CountryCode,
}

impl Validator {
    /// Build a validator record.
    #[must_use]
    pub fn new(public_key: PublicKey, voting_power: u64, country: CountryCode) -> Self {
        Self {
            address: Address::from_public_key(&public_key),
            public_key,
            voting_power,
            country,
        }
    }
}

/// An ordered set of validators with their voting power.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    total_power: u64,
}

impl ValidatorSet {
    /// Build a validator set, sorting it canonically.
    ///
    /// Validators are ordered by address so that every node derives the same
    /// set — and therefore the same proposer — from the same membership,
    /// regardless of the order they were supplied in.
    ///
    /// # Errors
    /// Returns the first [`ValidatorError`] encountered.
    pub fn new(mut validators: Vec<Validator>) -> Result<Self, ValidatorError> {
        if validators.is_empty() {
            return Err(ValidatorError::Empty);
        }
        if validators.iter().any(|v| v.voting_power == 0) {
            return Err(ValidatorError::ZeroPower);
        }

        validators.sort_by_key(|v| v.address);
        if validators
            .windows(2)
            .any(|w| w.first().map(|v| v.address) == w.get(1).map(|v| v.address))
        {
            return Err(ValidatorError::Duplicate);
        }

        let mut total_power: u64 = 0;
        for v in &validators {
            total_power = total_power
                .checked_add(v.voting_power)
                .ok_or(ValidatorError::PowerOverflow)?;
        }

        Ok(Self {
            validators,
            total_power,
        })
    }

    /// The validators, in canonical order.
    #[must_use]
    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    /// Number of validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Whether the set is empty. Never true for a constructed set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Total voting power across the set.
    #[must_use]
    pub fn total_power(&self) -> u64 {
        self.total_power
    }

    /// The power required for a decision: `floor(2 * total / 3) + 1`.
    ///
    /// Strictly more than two thirds. See the module note on why this exact
    /// expression matters.
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "widened to u128 first, so doubling cannot overflow and division is by a \
                  non-zero constant"
    )]
    pub fn quorum_threshold(&self) -> u64 {
        // Widen to u128 so the doubling cannot overflow near u64::MAX.
        let total = u128::from(self.total_power);
        let threshold = total.saturating_mul(2) / 3 + 1;
        u64::try_from(threshold).unwrap_or(u64::MAX)
    }

    /// Whether `power` constitutes a quorum.
    #[must_use]
    pub fn has_quorum(&self, power: u64) -> bool {
        power >= self.quorum_threshold()
    }

    /// The maximum power a Byzantine coalition may hold without breaking safety:
    /// `ceil(total / 3) - 1`.
    #[must_use]
    pub fn max_byzantine_power(&self) -> u64 {
        // `f` is the largest value satisfying `3f < total`.
        let total = u128::from(self.total_power);
        let f = total.saturating_sub(1) / 3;
        u64::try_from(f).unwrap_or(u64::MAX)
    }

    /// A commitment to this exact set: members, powers and order.
    ///
    /// A block header carries this rather than the set itself, so a light client
    /// can check that a validator set someone hands it is the one the chain
    /// actually committed to. Without it, a client updating across a validator
    /// set change has to *trust* the new set — which is precisely the hole a
    /// long-range attack walks through
    /// ([ADR-0010](../../../docs/adr/0010-long-range-attacks.md)).
    ///
    /// Covers voting power, so an attacker cannot present the same members with
    /// their own weights.
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        let mut bytes = Vec::new();
        // The set is canonically ordered by address at construction, so this is
        // deterministic across nodes.
        for v in &self.validators {
            bytes.extend_from_slice(v.address.as_bytes());
            bytes.extend_from_slice(&v.public_key.to_bytes());
            bytes.extend_from_slice(&v.voting_power.to_le_bytes());
            bytes.extend_from_slice(v.country.as_str().as_bytes());
        }
        hash(Domain::ValidatorSetHash, &bytes)
    }

    /// Look up a validator by address.
    #[must_use]
    pub fn get(&self, address: &Address) -> Option<&Validator> {
        self.validators
            .binary_search_by(|v| v.address.cmp(address))
            .ok()
            .and_then(|i| self.validators.get(i))
    }

    /// The voting power of one validator, or zero if not a member.
    #[must_use]
    pub fn power_of(&self, address: &Address) -> u64 {
        self.get(address).map_or(0, |v| v.voting_power)
    }

    /// How many distinct countries the set spans.
    #[must_use]
    pub fn countries_represented(&self) -> usize {
        let mut seen: Vec<CountryCode> = self.validators.iter().map(|v| v.country).collect();
        seen.sort_unstable();
        seen.dedup();
        seen.len()
    }

    /// Whether the set meets the geographic distribution requirement.
    #[must_use]
    pub fn meets_distribution_requirement(&self, min_countries: usize) -> bool {
        self.countries_represented() >= min_countries
    }

    /// The largest share any single validator holds, in basis points.
    ///
    /// Governance caps this to keep one operator from dominating the set.
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "total_power is checked non-zero above, and the product is widened to u128"
    )]
    pub fn max_single_share_bps(&self) -> u32 {
        if self.total_power == 0 {
            return 0;
        }
        let max = self
            .validators
            .iter()
            .map(|v| v.voting_power)
            .max()
            .unwrap_or(0);
        let bps = u128::from(max).saturating_mul(10_000) / u128::from(self.total_power);
        u32::try_from(bps).unwrap_or(u32::MAX)
    }

    /// Select the proposer for a given height and round.
    ///
    /// Deterministic and stake-weighted: every node computes the same proposer
    /// from `(height, round)` alone, and a validator's chance of proposing is
    /// proportional to its power. Rotating on `round` is what gives liveness
    /// when a proposer is offline — the next round picks someone else.
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "total_power is checked non-zero above, so the modulo is well defined"
    )]
    pub fn proposer(&self, height: Height, round: Round) -> Option<&Validator> {
        if self.validators.is_empty() || self.total_power == 0 {
            return None;
        }
        let seed = hash_parts(
            Domain::ValidatorId,
            &[&height.0.to_le_bytes(), &round.0.to_le_bytes()],
        );
        // Take 8 bytes of the digest as a big-endian integer, then map it into
        // the cumulative power range.
        let mut buf = [0u8; 8];
        buf.copy_from_slice(seed.as_bytes().get(..8).unwrap_or(&[0; 8]));
        let draw = u128::from(u64::from_be_bytes(buf)) % u128::from(self.total_power);

        let mut cumulative: u128 = 0;
        for v in &self.validators {
            cumulative = cumulative.saturating_add(u128::from(v.voting_power));
            if draw < cumulative {
                return Some(v);
            }
        }
        self.validators.last()
    }
}

impl Encode for Validator {
    fn encode(&self, out: &mut Vec<u8>) {
        self.public_key.encode(out);
        self.voting_power.encode(out);
        self.country.encode(out);
    }
}

impl Decode for Validator {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let public_key = PublicKey::decode(r)?;
        Ok(Self {
            address: Address::from_public_key(&public_key),
            public_key,
            voting_power: u64::decode(r)?,
            country: CountryCode::decode(r)?,
        })
    }
}

impl Encode for ValidatorSet {
    fn encode(&self, out: &mut Vec<u8>) {
        self.validators.encode(out);
    }
}

impl Decode for ValidatorSet {
    /// Refuses a set that is not already in canonical order.
    ///
    /// [`ValidatorSet::new`] sorts by address, which is right for a caller
    /// assembling a set and wrong for bytes off the wire: it would make every
    /// permutation of the same membership a valid encoding of one value, and
    /// the codec's rule is that there is exactly one.
    ///
    /// It matters most for genesis. A genesis file is the one input a node
    /// ingests before it can check anything against a chain, and operators
    /// publish its hash before launch. If the same set has `n!` encodings, that
    /// published hash does not identify a unique file.
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let validators = Vec::<Validator>::decode(r)?;
        let offered: Vec<Address> = validators.iter().map(|v| v.address).collect();
        let set = Self::new(validators).map_err(|e| CodecError::Invalid(e.to_string()))?;
        if set.validators.iter().map(|v| v.address).ne(offered) {
            return Err(CodecError::Invalid(
                "validator set is not in canonical order".to_owned(),
            ));
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;

    fn validator(seed: u8, power: u64, country: &str) -> Validator {
        Validator::new(
            SecretKey::from_bytes(&[seed; 32]).public_key(),
            power,
            CountryCode::new(country).expect("valid country"),
        )
    }

    fn set_of(n: u8, power: u64) -> ValidatorSet {
        ValidatorSet::new((1..=n).map(|i| validator(i, power, "ke")).collect()).expect("valid set")
    }

    #[test]
    fn a_permuted_validator_set_on_the_wire_is_refused_rather_than_sorted() {
        // Found by the adversarial harness. `ValidatorSet::new` sorts by
        // address — right for a caller assembling a set, wrong at the decode
        // boundary, because it made every permutation of one membership a
        // valid encoding of the same value.
        //
        // It matters most for genesis: operators publish the genesis file's
        // hash before launch, and `n!` encodings means that hash identifies no
        // unique file.
        use afrolink_primitives::codec::decode_exact;

        let canonical = set_of(4, 10);
        let bytes = canonical.to_bytes();
        assert_eq!(decode_exact::<ValidatorSet>(&bytes), Ok(canonical.clone()));

        // Same membership, offered in a different order.
        let mut shuffled: Vec<Validator> = canonical.validators().to_vec();
        shuffled.reverse();
        assert_ne!(
            shuffled.first().map(|v| v.address),
            canonical.validators().first().map(|v| v.address),
            "the fixture must actually be reordered, or this proves nothing"
        );
        let mut permuted = Vec::new();
        shuffled.encode(&mut permuted);

        assert!(
            decode_exact::<ValidatorSet>(&permuted).is_err(),
            "a permuted validator set must not decode"
        );
    }

    #[test]
    fn quorum_is_strictly_more_than_two_thirds() {
        // The bug this guards: `>=2/3` lets two disjoint quorums exist, so two
        // different blocks can commit at the same height.
        for total in 1..=1_000u64 {
            let vs = ValidatorSet::new(vec![validator(1, total, "ke")]).expect("valid");
            let q = vs.quorum_threshold();
            assert!(
                u128::from(q) * 3 > u128::from(total) * 2,
                "threshold {q} is not strictly more than 2/3 of {total}"
            );
            assert!(
                u128::from(q - 1) * 3 <= u128::from(total) * 2,
                "threshold {q} is not minimal for {total}"
            );
        }
    }

    #[test]
    fn two_quorums_cannot_be_disjoint() {
        // Directly assert the safety property: any two quorums must overlap, so
        // one validator would have to vote for both values.
        for total in 1..=300u64 {
            let vs = ValidatorSet::new(vec![validator(1, total, "ke")]).expect("valid");
            let q = u128::from(vs.quorum_threshold());
            assert!(
                q * 2 > u128::from(total),
                "two quorums of {q} would fit in {total}"
            );
        }
    }

    #[test]
    fn classic_three_f_plus_one_sizes_behave() {
        // 4 validators of power 1: quorum 3, tolerates 1 Byzantine.
        let vs = set_of(4, 1);
        assert_eq!(vs.total_power(), 4);
        assert_eq!(vs.quorum_threshold(), 3);
        assert_eq!(vs.max_byzantine_power(), 1);
        assert!(vs.has_quorum(3));
        assert!(!vs.has_quorum(2));

        // 100 validators of power 1: quorum 67.
        let vs = set_of(100, 1);
        assert_eq!(vs.quorum_threshold(), 67);
        assert_eq!(vs.max_byzantine_power(), 33);
    }

    #[test]
    fn quorum_does_not_overflow_at_extreme_power() {
        let vs = ValidatorSet::new(vec![validator(1, u64::MAX, "ke")]).expect("valid");
        let q = vs.quorum_threshold();
        assert!(q > u64::MAX / 2, "must not wrap to a tiny threshold");
    }

    #[test]
    fn total_power_overflow_is_refused() {
        let vs = ValidatorSet::new(vec![validator(1, u64::MAX, "ke"), validator(2, 2, "ng")]);
        assert_eq!(vs, Err(ValidatorError::PowerOverflow));
    }

    #[test]
    fn malformed_sets_are_rejected() {
        assert_eq!(ValidatorSet::new(vec![]), Err(ValidatorError::Empty));
        assert_eq!(
            ValidatorSet::new(vec![validator(1, 0, "ke")]),
            Err(ValidatorError::ZeroPower)
        );
        assert_eq!(
            ValidatorSet::new(vec![validator(1, 5, "ke"), validator(1, 5, "ng")]),
            Err(ValidatorError::Duplicate)
        );
    }

    #[test]
    fn ordering_is_canonical_regardless_of_input_order() {
        // Two nodes given the same members in different orders must derive the
        // same set, or they will disagree about the proposer.
        let forward =
            ValidatorSet::new((1..=5).map(|i| validator(i, 10, "ke")).collect()).expect("valid");
        let backward = ValidatorSet::new((1..=5).rev().map(|i| validator(i, 10, "ke")).collect())
            .expect("valid");
        assert_eq!(forward, backward);
        assert_eq!(forward.to_bytes(), backward.to_bytes());
    }

    #[test]
    fn proposer_selection_is_deterministic() {
        let vs = set_of(10, 1);
        for round in 0..5u32 {
            let a = vs.proposer(Height(7), Round(round)).map(|v| v.address);
            let b = vs.proposer(Height(7), Round(round)).map(|v| v.address);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn proposer_rotates_across_rounds_so_a_dead_proposer_does_not_stall_the_chain() {
        let vs = set_of(10, 1);
        let proposers: Vec<Address> = (0..20)
            .filter_map(|r| vs.proposer(Height(1), Round(r)).map(|v| v.address))
            .collect();
        let mut distinct = proposers.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert!(
            distinct.len() > 1,
            "rounds must not always pick the same proposer"
        );
    }

    #[test]
    fn proposer_selection_is_weighted_by_stake() {
        // One validator with 90% of the power should propose most of the time.
        let heavy = validator(1, 900, "ke");
        let heavy_addr = heavy.address;
        let mut members = vec![heavy];
        members.extend((2..=11u8).map(|i| validator(i, 10, "ng")));
        let vs = ValidatorSet::new(members).expect("valid");

        let wins = (0..1_000u64)
            .filter(|h| vs.proposer(Height(*h), Round::ZERO).map(|v| v.address) == Some(heavy_addr))
            .count();
        assert!(
            (700..=990).contains(&wins),
            "a 90% stakeholder proposed {wins}/1000 times, expected roughly 900"
        );
    }

    #[test]
    fn geographic_distribution_is_measurable() {
        let members = vec![
            validator(1, 10, "ke"),
            validator(2, 10, "ng"),
            validator(3, 10, "za"),
            validator(4, 10, "ke"),
        ];
        let vs = ValidatorSet::new(members).expect("valid");
        assert_eq!(vs.countries_represented(), 3);
        assert!(vs.meets_distribution_requirement(3));
        assert!(
            !vs.meets_distribution_requirement(15),
            "the mainnet rule is 15 countries"
        );
    }

    #[test]
    fn concentration_is_measurable_in_basis_points() {
        let vs = ValidatorSet::new(vec![validator(1, 750, "ke"), validator(2, 250, "ng")])
            .expect("valid");
        assert_eq!(vs.max_single_share_bps(), 7_500);
    }

    #[test]
    fn lookup_finds_members_and_rejects_strangers() {
        let vs = set_of(5, 3);
        let member = validator(3, 3, "ke").address;
        assert_eq!(vs.power_of(&member), 3);
        let stranger = validator(99, 1, "ke").address;
        assert_eq!(vs.power_of(&stranger), 0);
        assert!(vs.get(&stranger).is_none());
    }

    #[test]
    fn validator_sets_round_trip_and_revalidate() {
        let vs = set_of(4, 7);
        let bytes = vs.to_bytes();
        assert_eq!(
            afrolink_primitives::codec::decode_exact::<ValidatorSet>(&bytes),
            Ok(vs)
        );
    }

    #[test]
    fn country_codes_are_validated() {
        assert!(CountryCode::new("ke").is_ok());
        assert!(CountryCode::new("KE").is_err());
        assert!(CountryCode::new("ken").is_err());
        assert!(CountryCode::new("k").is_err());
    }
}
