//! Turning bonds into the active validator set.

use afrolink_consensus::{Validator, ValidatorSet};
use afrolink_primitives::Amount;
use afrolink_primitives::amount::SENTE_PER_AFRI;

use crate::bond::Bond;
use crate::{StakingError, StakingParams};

/// Voting power for a bond: one unit per whole AFRI.
///
/// `Amount` is a `u128` of sente and voting power is a `u64`, so this both
/// converts and bounds. Sub-AFRI dust cannot buy power, which is the point:
/// power should be legible, and a set whose weights are enormous numbers is a
/// set nobody can eyeball for concentration.
#[must_use]
pub fn power_of(bonded: Amount) -> u64 {
    let whole = bonded.units() / SENTE_PER_AFRI;
    u64::try_from(whole).unwrap_or(u64::MAX)
}

/// Derive the active validator set from every bond.
///
/// Selection is: drop jailed operators and anything below the minimum bond,
/// sort by power (descending, address ascending to break ties deterministically),
/// take the top `max_validators`, then cap concentration.
///
/// # Why concentration is capped rather than rejected
///
/// [ADR-0007](../../../docs/adr/0007-distribution-and-sybil-resistance.md) sets
/// a ceiling on any one validator's share. The obvious implementation — refuse
/// to build a set that breaches it — **halts the chain**: validators leave, the
/// remaining set breaches the limit, and now no set can be formed at all. A
/// safety rule that stops block production is a liveness bug wearing a safety
/// rule's clothes.
///
/// So excess power is *discarded* instead. Stake above the ceiling earns its
/// operator nothing, which pushes large holders to split or delegate — the
/// behaviour the limit exists to produce — while the chain keeps running.
///
/// Capping lowers the total, which can push another validator over the ceiling,
/// so this iterates to a fixed point. It terminates because total power is
/// non-increasing and strictly decreases whenever anything is capped.
///
/// # Errors
/// [`StakingError::NoEligibleValidators`] if nothing qualifies. That is a real
/// halt, but an unavoidable one: a chain with no validators cannot produce
/// blocks, and pretending otherwise would mean inventing power nobody staked.
pub fn active_set(bonds: &[Bond], params: &StakingParams) -> Result<ValidatorSet, StakingError> {
    let mut eligible: Vec<&Bond> = bonds
        .iter()
        .filter(|b| !b.jailed && b.bonded.units() >= params.min_bond.units())
        .collect();

    // Deterministic on every node: power first, then address. Without the
    // address tiebreak two nodes could order equal stakes differently and
    // disagree about who proposes.
    eligible.sort_by(|a, b| {
        power_of(b.bonded)
            .cmp(&power_of(a.bonded))
            .then_with(|| a.operator.cmp(&b.operator))
    });
    eligible.truncate(params.max_validators);

    let mut powers: Vec<u64> = eligible.iter().map(|b| power_of(b.bonded)).collect();
    // A bond at or above the minimum always has at least one unit of power, but
    // guard anyway: `ValidatorSet::new` rejects zero and a halt here would be
    // hard to trace back.
    for p in &mut powers {
        *p = (*p).max(1);
    }
    if powers.is_empty() {
        return Err(StakingError::NoEligibleValidators);
    }

    cap_concentration(&mut powers, params.max_single_share_bps);

    let validators = eligible
        .iter()
        .zip(powers)
        .map(|(b, power)| Validator::new(b.public_key, power, b.country))
        .collect();

    ValidatorSet::new(validators).map_err(|_| StakingError::NoEligibleValidators)
}

/// Reduce any share above `max_bps` of the total, repeatedly, until none is.
fn cap_concentration(powers: &mut [u64], max_bps: u32) {
    if max_bps == 0 || max_bps >= 10_000 {
        return;
    }
    // At most one validator can be newly capped per pass, so `len` passes is a
    // sufficient bound as well as a guarantee of termination.
    for _ in 0..powers.len() {
        let total: u128 = powers.iter().map(|p| u128::from(*p)).sum();
        if total == 0 {
            return;
        }
        let ceiling = total
            .saturating_mul(u128::from(max_bps))
            .saturating_div(10_000);
        let ceiling = u64::try_from(ceiling).unwrap_or(u64::MAX).max(1);

        let mut changed = false;
        for p in powers.iter_mut() {
            if *p > ceiling {
                *p = ceiling;
                changed = true;
            }
        }
        if !changed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_consensus::CountryCode;
    use afrolink_crypto::{Address, SecretKey};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn bond(seed: u8, afri: u64, country: &str) -> Bond {
        Bond::new(
            Address::from_public_key(&key(seed).public_key()),
            key(seed).public_key(),
            CountryCode::new(country).expect("valid"),
            Amount::from_afri(afri),
        )
    }

    fn params() -> StakingParams {
        StakingParams {
            min_bond: Amount::from_afri(1_000),
            max_validators: 100,
            max_single_share_bps: 1_000,
            ..StakingParams::default()
        }
    }

    #[test]
    fn power_is_one_unit_per_whole_afri() {
        assert_eq!(power_of(Amount::from_afri(5_000)), 5_000);
        // Dust buys nothing.
        assert_eq!(power_of(Amount::from_units(SENTE_PER_AFRI - 1)), 0);
    }

    #[test]
    fn bonds_below_the_minimum_do_not_join_the_set() {
        let bonds = vec![
            bond(1, 5_000, "ke"),
            bond(2, 999, "ng"),
            bond(3, 5_000, "za"),
        ];
        let set = active_set(&bonds, &params()).expect("two qualify");
        assert_eq!(set.validators().len(), 2);
    }

    #[test]
    fn a_jailed_operator_is_not_in_the_set() {
        let mut jailed = bond(2, 50_000, "ng");
        jailed.jailed = true;
        let bonds = vec![bond(1, 5_000, "ke"), jailed, bond(3, 5_000, "za")];
        let set = active_set(&bonds, &params()).expect("two qualify");
        assert_eq!(
            set.validators().len(),
            2,
            "the largest bond is jailed and must not sign"
        );
    }

    #[test]
    fn concentration_is_capped_rather_than_the_set_refused() {
        // One whale at 90%. Refusing would halt the chain; capping keeps it
        // running and makes the excess stake earn nothing.
        let mut bonds = vec![bond(1, 900_000, "ke")];
        for seed in 2..=10u8 {
            bonds.push(bond(seed, 11_000, "ng"));
        }
        let set = active_set(&bonds, &params()).expect("set forms");

        let total = set.total_power();
        let largest = set
            .validators()
            .iter()
            .map(|v| v.voting_power)
            .max()
            .expect("non-empty");
        let share_bps =
            u32::try_from(u128::from(largest) * 10_000 / u128::from(total)).expect("share fits");
        assert!(
            share_bps <= 1_000,
            "capped share is {share_bps}bps, limit is 1000"
        );
    }

    #[test]
    fn capping_converges_when_several_would_breach_the_limit() {
        // Capping lowers the total, which can push the next validator over the
        // line. A single pass is not enough; this must reach a fixed point.
        let bonds: Vec<Bond> = (1..=12u8).map(|s| bond(s, 100_000, "ke")).collect();
        let set = active_set(&bonds, &params()).expect("set forms");

        let total = set.total_power();
        for v in set.validators() {
            let share = u128::from(v.voting_power) * 10_000 / u128::from(total);
            assert!(share <= 1_000, "share {share}bps exceeds the cap");
        }
    }

    #[test]
    fn an_empty_candidate_list_is_an_honest_halt() {
        // A chain with no validators cannot produce blocks. Inventing power
        // nobody staked would be worse than saying so.
        assert_eq!(
            active_set(&[], &params()),
            Err(StakingError::NoEligibleValidators)
        );
    }

    #[test]
    fn the_set_is_identical_on_every_node() {
        // Two nodes handed the same bonds in different orders must derive the
        // same set, or they disagree about who proposes.
        let mut a = vec![
            bond(1, 5_000, "ke"),
            bond(2, 5_000, "ng"),
            bond(3, 5_000, "za"),
        ];
        let b: Vec<Bond> = a.iter().rev().cloned().collect();
        a.rotate_left(1);

        let from_a = active_set(&a, &params()).expect("set forms");
        let from_b = active_set(&b, &params()).expect("set forms");
        assert_eq!(from_a.hash(), from_b.hash(), "equal stakes, one ordering");
    }

    #[test]
    fn the_set_is_bounded_by_max_validators() {
        let bonds: Vec<Bond> = (1..=60u8).map(|s| bond(s, 5_000, "ke")).collect();
        let p = StakingParams {
            max_validators: 10,
            ..params()
        };
        let set = active_set(&bonds, &p).expect("set forms");
        assert_eq!(set.validators().len(), 10);
    }

    #[test]
    fn the_largest_bonds_are_the_ones_selected() {
        let mut bonds: Vec<Bond> = (1..=20u8)
            .map(|s| bond(s, 1_000 + u64::from(s) * 1_000, "ke"))
            .collect();
        bonds.reverse();
        let p = StakingParams {
            max_validators: 3,
            max_single_share_bps: 10_000,
            ..params()
        };
        let set = active_set(&bonds, &p).expect("set forms");

        let mut powers: Vec<u64> = set.validators().iter().map(|v| v.voting_power).collect();
        powers.sort_unstable();
        assert_eq!(powers, vec![19_000, 20_000, 21_000]);
    }
}
