//! Decentralisation, measured rather than claimed.
//!
//! [ADR-0007](../../../docs/adr/0007-distribution-and-sybil-resistance.md) binds
//! us to publish this as a metric. The reason is drawn from three networks we
//! studied, all of which failed the same way in public:
//!
//! * **Pi Network** described itself as decentralised while running a federated
//!   consensus whose quorum slices were held by one organisation — reportedly
//!   ~43 nodes and 3 validators.
//! * **TRON**'s node population is heavily concentrated in a single country,
//!   which no validator-count figure reveals.
//! * **XRPL**'s unique node list makes validator diversity a recurring question
//!   precisely because it is a policy choice rather than an observable.
//!
//! In each case the claim was qualitative and the reality was not measured. A
//! chain that reports "3 validators, 1 country" honestly is in better shape than
//! one that says "decentralised" and means the same thing.
//!
//! # What is measured
//!
//! [`GenesisLimits`](../../../executor/genesis/struct.GenesisLimits.html) already
//! constrains the set at genesis. This module answers the different question of
//! what the set looks like *now*, at any height, and it measures two axes that a
//! validator count cannot express:
//!
//! * **Concentration of power** — how few validators are needed to stall or to
//!   control the chain ([`Decentralization::nakamoto_halt`],
//!   [`Decentralization::nakamoto_control`]).
//! * **Concentration of geography** — the same two numbers over *countries*, plus
//!   the largest share any one country holds. A set of 100 validators in one
//!   jurisdiction is one subpoena away from being a set of zero.
//!
//! The second axis is the one this project cannot afford to leave unmeasured.
//! Validators spread across fifteen countries and validators spread across
//! fifteen racks produce identical counts and entirely different failure modes.

use crate::validator::{CountryCode, ValidatorSet};

/// Basis points in a whole: 100% = 10 000 bps.
const BPS: u128 = 10_000;

/// A point-in-time measurement of how concentrated a validator set is.
///
/// Every field is derived from the set alone, so any node computes the same
/// report from the same membership and two nodes disagreeing is itself a bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decentralization {
    /// Number of validators in the set.
    pub validators: usize,
    /// Total voting power across the set.
    pub total_power: u64,
    /// Fewest validators whose combined power can **stall** the chain by
    /// withholding votes — the smallest coalition holding more than `1/3`.
    ///
    /// This is the number usually quoted as "the Nakamoto coefficient". It is a
    /// liveness bound: at this size, a coalition cannot forge a block but can
    /// stop anyone else from producing one.
    pub nakamoto_halt: usize,
    /// Fewest validators whose combined power can **control** the chain — the
    /// smallest coalition reaching quorum, which can commit whatever it agrees
    /// on.
    ///
    /// This is the safety bound, and it is the more alarming of the two when it
    /// is small.
    pub nakamoto_control: usize,
    /// The largest share held by a single validator, in basis points.
    pub max_validator_share_bps: u32,
    /// Herfindahl–Hirschman index over validator power shares, scaled to
    /// `0..=10_000`.
    ///
    /// `10_000` means one validator holds everything; `10_000 / n` means `n`
    /// validators hold equal shares. It captures the whole distribution's shape,
    /// where the Nakamoto coefficients capture only its head.
    pub stake_hhi: u32,
    /// Number of distinct countries represented.
    pub countries: usize,
    /// The largest share of voting power in any single country, in basis points.
    ///
    /// **The figure a validator count hides.** This is what would have exposed
    /// TRON's geographic concentration at a glance.
    pub max_country_share_bps: u32,
    /// Fewest *countries* that together can stall the chain.
    ///
    /// A value of 1 means a single jurisdiction can halt the network by
    /// regulation, power cut, or cable fault — regardless of validator count.
    pub country_nakamoto_halt: usize,
    /// Fewest *countries* that together can control the chain.
    pub country_nakamoto_control: usize,
}

impl Decentralization {
    /// Measure a validator set.
    #[must_use]
    pub fn measure(set: &ValidatorSet) -> Self {
        let total = set.total_power();
        let byzantine_ceiling = set.max_byzantine_power();
        let quorum = set.quorum_threshold();

        let validator_powers: Vec<u64> = set.validators().iter().map(|v| v.voting_power).collect();
        let country_powers = power_by_country(set);

        Self {
            validators: set.len(),
            total_power: total,
            nakamoto_halt: min_coalition_above(&validator_powers, byzantine_ceiling),
            nakamoto_control: min_coalition_at_least(&validator_powers, quorum),
            max_validator_share_bps: set.max_single_share_bps(),
            stake_hhi: hhi(&validator_powers, total),
            countries: country_powers.len(),
            max_country_share_bps: max_share_bps(&country_powers, total),
            country_nakamoto_halt: min_coalition_above(&country_powers, byzantine_ceiling),
            country_nakamoto_control: min_coalition_at_least(&country_powers, quorum),
        }
    }

    /// Whether a single validator can stall the chain on its own.
    #[must_use]
    pub fn single_validator_can_halt(&self) -> bool {
        self.nakamoto_halt <= 1
    }

    /// Whether a single country can stall the chain on its own.
    ///
    /// True for any set inside one jurisdiction, however many validators it has.
    #[must_use]
    pub fn single_country_can_halt(&self) -> bool {
        self.country_nakamoto_halt <= 1
    }
}

impl core::fmt::Display for Decentralization {
    /// One line per axis, in the form a node logs at startup and an RPC serves.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "validators={} power={} nakamoto(halt/control)={}/{} \
             max_validator={}bps hhi={} countries={} max_country={}bps \
             country_nakamoto(halt/control)={}/{}",
            self.validators,
            self.total_power,
            self.nakamoto_halt,
            self.nakamoto_control,
            self.max_validator_share_bps,
            self.stake_hhi,
            self.countries,
            self.max_country_share_bps,
            self.country_nakamoto_halt,
            self.country_nakamoto_control,
        )
    }
}

/// Aggregate voting power by country.
fn power_by_country(set: &ValidatorSet) -> Vec<u64> {
    let mut pairs: Vec<(CountryCode, u64)> = Vec::new();
    for v in set.validators() {
        match pairs.iter_mut().find(|(c, _)| *c == v.country) {
            Some((_, power)) => *power = power.saturating_add(v.voting_power),
            None => pairs.push((v.country, v.voting_power)),
        }
    }
    pairs.into_iter().map(|(_, power)| power).collect()
}

/// Fewest entries, taken largest-first, whose sum strictly exceeds `ceiling`.
///
/// Returns `0` when no coalition can reach it, which happens only for an empty
/// set — a constructed [`ValidatorSet`] is never empty.
fn min_coalition_above(powers: &[u64], ceiling: u64) -> usize {
    min_coalition(powers, |sum| sum > u128::from(ceiling))
}

/// Fewest entries, taken largest-first, whose sum reaches `target`.
fn min_coalition_at_least(powers: &[u64], target: u64) -> usize {
    min_coalition(powers, |sum| sum >= u128::from(target))
}

/// Shared greedy walk: the smallest coalition is always the largest holders,
/// so sorting descending and accumulating is exact rather than an approximation.
fn min_coalition<F: Fn(u128) -> bool>(powers: &[u64], reached: F) -> usize {
    let mut sorted: Vec<u64> = powers.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));

    let mut sum: u128 = 0;
    for (index, power) in sorted.iter().enumerate() {
        sum = sum.saturating_add(u128::from(*power));
        if reached(sum) {
            return index.saturating_add(1);
        }
    }
    0
}

/// The largest single share, in basis points.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "total is checked non-zero above, and the product is widened to u128"
)]
fn max_share_bps(powers: &[u64], total: u64) -> u32 {
    if total == 0 {
        return 0;
    }
    let max = powers.iter().copied().max().unwrap_or(0);
    let bps = u128::from(max).saturating_mul(BPS) / u128::from(total);
    u32::try_from(bps).unwrap_or(u32::MAX)
}

/// Herfindahl–Hirschman index over shares, scaled to `0..=10_000`.
///
/// Computed as `sum(share_bps^2) / 10_000` so the whole calculation stays in
/// integers — a float here would make the metric non-deterministic across
/// platforms, and a metric two nodes can disagree about is not a metric.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "total is checked non-zero above, BPS is a non-zero constant, and every \
              intermediate is widened to u128"
)]
fn hhi(powers: &[u64], total: u64) -> u32 {
    if total == 0 {
        return 0;
    }
    let mut acc: u128 = 0;
    for power in powers {
        let share = u128::from(*power).saturating_mul(BPS) / u128::from(total);
        acc = acc.saturating_add(share.saturating_mul(share));
    }
    u32::try_from(acc / BPS).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::Validator;
    use afrolink_crypto::SecretKey;

    fn validator(seed: u8, power: u64, country: &str) -> Validator {
        let secret = SecretKey::from_bytes(&[seed; 32]);
        let country = CountryCode::new(country).unwrap();
        Validator::new(secret.public_key(), power, country)
    }

    fn set(specs: &[(u8, u64, &str)]) -> ValidatorSet {
        let validators = specs
            .iter()
            .map(|(seed, power, country)| validator(*seed, *power, country))
            .collect();
        ValidatorSet::new(validators).unwrap()
    }

    #[test]
    fn equal_validators_give_the_expected_coalition_sizes() {
        // Four equal validators: 25% each. Halting needs >1/3, so two.
        // Control needs >=2/3, so three.
        let report = Decentralization::measure(&set(&[
            (1, 25, "ke"),
            (2, 25, "ng"),
            (3, 25, "za"),
            (4, 25, "gh"),
        ]));

        assert_eq!(report.validators, 4);
        assert_eq!(report.nakamoto_halt, 2);
        assert_eq!(report.nakamoto_control, 3);
        assert_eq!(report.max_validator_share_bps, 2_500);
    }

    #[test]
    fn one_dominant_validator_can_halt_alone() {
        // 40% is above the one-third ceiling, so this validator alone can
        // withhold votes and stop the chain.
        let report = Decentralization::measure(&set(&[
            (1, 40, "ke"),
            (2, 20, "ng"),
            (3, 20, "za"),
            (4, 20, "gh"),
        ]));

        assert_eq!(report.nakamoto_halt, 1);
        assert!(report.single_validator_can_halt());
        // But not control it: 40% is far short of quorum.
        assert_eq!(report.nakamoto_control, 3);
    }

    #[test]
    fn a_validator_count_hides_geographic_concentration() {
        // This is the whole reason the module exists. Twelve validators, none
        // above 10% of power, every per-validator check passing — and one
        // country holding enough to halt the chain by itself.
        let mut specs: Vec<(u8, u64, &str)> = (1..=9).map(|i| (i, 10u64, "vn")).collect();
        specs.push((10, 10, "ke"));
        specs.push((11, 10, "ng"));
        specs.push((12, 10, "za"));
        let report = Decentralization::measure(&set(&specs));

        // Every conventional signal looks healthy.
        assert_eq!(report.validators, 12);
        assert_eq!(report.max_validator_share_bps, 833);
        // Total power 120, Byzantine ceiling 39, so four validators reach 40.
        assert_eq!(report.nakamoto_halt, 4);

        // The geographic axis says otherwise.
        assert_eq!(report.countries, 4);
        assert_eq!(report.max_country_share_bps, 7_500);
        assert_eq!(report.country_nakamoto_halt, 1);
        assert_eq!(report.country_nakamoto_control, 1);
        assert!(report.single_country_can_halt());
        assert!(!report.single_validator_can_halt());
    }

    #[test]
    fn spreading_the_same_validators_across_countries_fixes_only_the_geographic_axis() {
        let concentrated = Decentralization::measure(&set(&[
            (1, 10, "vn"),
            (2, 10, "vn"),
            (3, 10, "vn"),
            (4, 10, "vn"),
        ]));
        let spread = Decentralization::measure(&set(&[
            (1, 10, "ke"),
            (2, 10, "ng"),
            (3, 10, "za"),
            (4, 10, "gh"),
        ]));

        // Identical stake distribution, so the stake axis is unchanged.
        assert_eq!(concentrated.nakamoto_halt, spread.nakamoto_halt);
        assert_eq!(concentrated.stake_hhi, spread.stake_hhi);

        // Entirely different jurisdictional exposure.
        assert_eq!(concentrated.country_nakamoto_halt, 1);
        assert_eq!(spread.country_nakamoto_halt, 2);
        assert_eq!(concentrated.max_country_share_bps, 10_000);
        assert_eq!(spread.max_country_share_bps, 2_500);
    }

    #[test]
    fn a_single_validator_set_is_reported_as_fully_concentrated() {
        // A devnet. The report should say so plainly rather than flatter it.
        let report = Decentralization::measure(&set(&[(1, 100, "ke")]));

        assert_eq!(report.validators, 1);
        assert_eq!(report.nakamoto_halt, 1);
        assert_eq!(report.nakamoto_control, 1);
        assert_eq!(report.stake_hhi, 10_000);
        assert_eq!(report.max_country_share_bps, 10_000);
        assert!(report.single_validator_can_halt());
        assert!(report.single_country_can_halt());
    }

    #[test]
    fn hhi_falls_as_power_spreads() {
        let two = Decentralization::measure(&set(&[(1, 50, "ke"), (2, 50, "ng")]));
        let four = Decentralization::measure(&set(&[
            (1, 25, "ke"),
            (2, 25, "ng"),
            (3, 25, "za"),
            (4, 25, "gh"),
        ]));

        // n equal holders give 10_000 / n.
        assert_eq!(two.stake_hhi, 5_000);
        assert_eq!(four.stake_hhi, 2_500);
    }

    #[test]
    fn hhi_distinguishes_sets_the_nakamoto_coefficient_cannot() {
        // Both need two validators to halt, but the tails differ sharply.
        let flat = Decentralization::measure(&set(&[
            (1, 30, "ke"),
            (2, 30, "ng"),
            (3, 20, "za"),
            (4, 20, "gh"),
        ]));
        let skewed = Decentralization::measure(&set(&[
            (1, 32, "ke"),
            (2, 32, "ng"),
            (3, 32, "za"),
            (4, 4, "gh"),
        ]));

        assert_eq!(flat.nakamoto_halt, skewed.nakamoto_halt);
        assert!(skewed.stake_hhi > flat.stake_hhi);
    }

    #[test]
    fn the_report_renders_every_axis() {
        let report = Decentralization::measure(&set(&[(1, 50, "ke"), (2, 50, "ng")]));
        let rendered = report.to_string();

        assert!(rendered.contains("validators=2"));
        assert!(rendered.contains("nakamoto(halt/control)=1/2"));
        assert!(rendered.contains("countries=2"));
        assert!(rendered.contains("max_country=5000bps"));
    }
}
