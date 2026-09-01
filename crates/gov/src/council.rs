//! The body that decides network-wide questions, and the rules it cannot vote
//! itself out of.
//!
//! # Why a council, and why it says so
//!
//! The obvious answer is stake-weighted voting, and it is the wrong one *here*
//! and *now*, for two separate reasons.
//!
//! The first is timing. A token vote at launch, when the founders hold almost
//! everything, is a vote whose result is known in advance. Polkadot ran a
//! Council and a Technical Committee for years and moved to fully open,
//! stake-weighted OpenGov only once there was a distribution to vote with;
//! pretending to skip that stage does not skip it, it only hides it.
//!
//! The second is subject matter. This chain's governable questions include which
//! institution may attest a national identity and which currency joins the
//! network. Those are licensing questions, decided in the world by regulators,
//! and settling them by "whoever bought the most AFRI" would be a worse answer
//! than the one every jurisdiction already has. Cosmos governance shows the
//! failure mode plainly enough: low turnout makes a coordinated minority
//! decisive, and apathy concentrates power rather than distributing it.
//!
//! So: a seated council now, its composition itself governed, and an explicit
//! path to open it later — recorded in
//! [ADR-0022](../../../docs/adr/0022-governance.md) rather than left implied.
//!
//! # The two numbers
//!
//! A proposal passes at [`MIN_COUNCIL_THRESHOLD_BPS`] — two thirds, the same bar
//! consensus uses — and no jurisdiction may hold more than
//! [`MAX_COUNCIL_COUNTRY_SHARE_BPS`](crate::params::MAX_COUNCIL_COUNTRY_SHARE_BPS)
//! of the weight. Those two numbers together give the property worth having:
//!
//! * **No single country can block.** Blocking a two-thirds threshold takes
//!   strictly more than a third, and a third is the most any country may hold.
//! * **No two countries can decide.** Two caps sum to at most two thirds minus
//!   the rounding, which does not reach the threshold.
//!
//! It is the geographic rule [ADR-0002](../../../docs/adr/0002-consensus.md)
//! already applies to validators, applied to the body that governs them. A
//! network whose consensus cannot be captured by one jurisdiction, but whose
//! governance can, is capturable by one jurisdiction.

use afrolink_crypto::Address;
use afrolink_primitives::CountryCode;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

/// Most seats a council may hold.
///
/// The record is read on every vote and rewritten whenever the council changes,
/// so it is bounded like every other list in this codebase. Far above the size
/// of any deliberative body that actually decides things.
pub const MAX_SEATS: usize = 32;

/// The lowest threshold a council may adopt, in basis points.
///
/// Two thirds, matching the consensus quorum. A simple majority would let half
/// the weight plus one seat change the parameters the other half is relying on,
/// and this body can license attestors and admit currencies.
pub const MIN_COUNCIL_THRESHOLD_BPS: u32 = 6_667;

/// One seat on the council.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seat {
    /// The account that votes.
    pub holder: Address,
    /// How much this seat's vote counts for.
    ///
    /// Weighted rather than one-seat-one-vote so a founding set can reflect real
    /// asymmetries — a central bank and a two-person wallet startup are both
    /// legitimately at the table and are not the same size — without having to
    /// hand one of them several seats and pretend they are separate parties.
    pub weight: u32,
    /// The jurisdiction this seat is counted under, for the concentration cap.
    pub country: CountryCode,
}

impl Seat {
    /// A seat of `weight` held by `holder`, counted under `country`.
    #[must_use]
    pub const fn new(holder: Address, weight: u32, country: CountryCode) -> Self {
        Self {
            holder,
            weight,
            country,
        }
    }
}

/// Why a council was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CouncilError {
    /// A council with no seats, which is a chain with no governance.
    #[error("a council must have at least one seat")]
    Empty,
    /// More than [`MAX_SEATS`].
    #[error("a council may have at most {MAX_SEATS} seats, got {0}")]
    TooManySeats(usize),
    /// Seats out of order, or one account seated twice.
    #[error("seats must be sorted by holder and unique")]
    UnsortedSeats,
    /// A seat that counts for nothing.
    #[error("a seat must carry weight greater than zero")]
    ZeroWeight,
    /// A threshold below [`MIN_COUNCIL_THRESHOLD_BPS`] or above 100%.
    #[error("a threshold must be {MIN_COUNCIL_THRESHOLD_BPS}..=10000 bps, got {0}")]
    Threshold(u32),
    /// One jurisdiction holds more weight than the cap allows.
    #[error("{country} holds {found} bps of council weight, cap is {cap}")]
    CountryConcentration {
        /// The jurisdiction over the cap.
        country: CountryCode,
        /// Its share, in basis points.
        found: u32,
        /// The cap in force.
        cap: u32,
    },
}

/// The seated body that decides network-wide questions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Council {
    /// Seats, sorted by holder and free of repeats.
    ///
    /// Checked on decode and **not repaired**, for the reason every other
    /// canonical list in this codebase is not repaired: the record is hashed into
    /// the state root, so a second ordering would be a second root for one
    /// council. Sorting a repeat away would also silently merge two seats and
    /// let the surviving one decide how much weight an account votes with.
    seats: Vec<Seat>,
    /// Weight required to pass, in basis points of the total.
    threshold_bps: u32,
}

impl Council {
    /// Build and validate a council.
    ///
    /// Structural rules only: composition rules that depend on chain state — the
    /// jurisdiction cap — are [`Self::check_concentration`], because the cap is a
    /// governed parameter and this type does not read state.
    ///
    /// # Errors
    /// Returns the first [`CouncilError`] found.
    pub fn new(seats: Vec<Seat>, threshold_bps: u32) -> Result<Self, CouncilError> {
        if seats.is_empty() {
            return Err(CouncilError::Empty);
        }
        if seats.len() > MAX_SEATS {
            return Err(CouncilError::TooManySeats(seats.len()));
        }
        if !seats.is_sorted_by(|a, b| a.holder < b.holder) {
            return Err(CouncilError::UnsortedSeats);
        }
        if seats.iter().any(|s| s.weight == 0) {
            return Err(CouncilError::ZeroWeight);
        }
        if !(MIN_COUNCIL_THRESHOLD_BPS..=10_000).contains(&threshold_bps) {
            return Err(CouncilError::Threshold(threshold_bps));
        }
        Ok(Self {
            seats,
            threshold_bps,
        })
    }

    /// A one-seat council for a local devnet, where one operator runs
    /// everything.
    ///
    /// Seated under [`CountryCode::UNSPECIFIED`], because the operator is not
    /// standing in for a jurisdiction. A mainnet `GenesisLimits` refuses it —
    /// one seat is one jurisdiction holding every basis point — which is the
    /// intended behaviour: this exists so a devnet is *governable*, not so a
    /// real network can launch ungoverned.
    #[must_use]
    pub fn devnet(holder: Address) -> Self {
        Self {
            seats: vec![Seat::new(holder, 1, CountryCode::UNSPECIFIED)],
            threshold_bps: 10_000,
        }
    }

    /// The seats, in canonical order.
    #[must_use]
    pub fn seats(&self) -> &[Seat] {
        &self.seats
    }

    /// The weight a proposal must reach, in basis points.
    #[must_use]
    pub const fn threshold_bps(&self) -> u32 {
        self.threshold_bps
    }

    /// Total weight of every seat.
    ///
    /// A `u64` because [`MAX_SEATS`] seats of `u32::MAX` overflow a `u32` and a
    /// governance total that wraps is a threshold that can be met with nothing.
    #[must_use]
    pub fn total_weight(&self) -> u64 {
        self.seats.iter().map(|s| u64::from(s.weight)).sum()
    }

    /// What `account` votes with. Zero for someone with no seat.
    #[must_use]
    pub fn weight_of(&self, account: &Address) -> u32 {
        self.seats
            .binary_search_by(|s| s.holder.cmp(account))
            .ok()
            .and_then(|at| self.seats.get(at))
            .map_or(0, |s| s.weight)
    }

    /// Whether `account` holds a seat.
    #[must_use]
    pub fn is_seated(&self, account: &Address) -> bool {
        self.weight_of(account) > 0
    }

    /// Whether `weight` reaches the threshold.
    ///
    /// Compared by cross-multiplication rather than by computing a percentage, so
    /// no division rounds a vote that fell short up to one that passed.
    #[must_use]
    pub fn reached(&self, weight: u64) -> bool {
        u128::from(weight).saturating_mul(10_000)
            >= u128::from(self.total_weight()).saturating_mul(u128::from(self.threshold_bps))
    }

    /// The largest share any one jurisdiction holds, in basis points.
    ///
    /// **Rounded up.** A concentration measure rounded down flatters the thing it
    /// measures: a country holding exactly a third would report 3333 and pass a
    /// cap of 3333, while in fact holding enough to block a two-thirds
    /// threshold. Rounding up reports 3334 and refuses it, which is the answer
    /// the cap was written to give.
    #[must_use]
    pub fn max_country_share_bps(&self) -> u32 {
        self.heaviest_country().map_or(0, |(_, bps)| bps)
    }

    /// Check the council against a jurisdiction cap.
    ///
    /// # Errors
    /// Returns [`CouncilError::CountryConcentration`] if any jurisdiction is over.
    pub fn check_concentration(&self, cap_bps: u32) -> Result<(), CouncilError> {
        match self.heaviest_country() {
            Some((country, found)) if found > cap_bps => Err(CouncilError::CountryConcentration {
                country,
                found,
                cap: cap_bps,
            }),
            _ => Ok(()),
        }
    }

    /// The jurisdiction holding the most weight, and its share in basis points.
    fn heaviest_country(&self) -> Option<(CountryCode, u32)> {
        let total = self.total_weight();
        if total == 0 {
            return None;
        }
        let mut countries: Vec<CountryCode> = self.seats.iter().map(|s| s.country).collect();
        countries.sort_unstable();
        countries.dedup();

        let mut worst: Option<(CountryCode, u32)> = None;
        for country in countries {
            let held: u64 = self
                .seats
                .iter()
                .filter(|s| s.country == country)
                .map(|s| u64::from(s.weight))
                .sum();
            // Ceiling division, deliberately: see the doc on
            // `max_country_share_bps`.
            let numerator = u128::from(held).saturating_mul(10_000);
            let total = u128::from(total);
            let bps = numerator.div_ceil(total);
            let bps = u32::try_from(bps).unwrap_or(u32::MAX);
            if worst.is_none_or(|(_, w)| bps > w) {
                worst = Some((country, bps));
            }
        }
        worst
    }
}

impl Encode for Seat {
    fn encode(&self, out: &mut Vec<u8>) {
        self.holder.encode(out);
        self.weight.encode(out);
        self.country.encode(out);
    }
}

impl Decode for Seat {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            holder: Address::decode(r)?,
            weight: u32::decode(r)?,
            country: CountryCode::decode(r)?,
        })
    }
}

impl Encode for Council {
    fn encode(&self, out: &mut Vec<u8>) {
        self.seats.encode(out);
        self.threshold_bps.encode(out);
    }
}

impl Decode for Council {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let seats = Vec::<Seat>::decode(r)?;
        let threshold_bps = u32::decode(r)?;
        Self::new(seats, threshold_bps).map_err(|e| CodecError::Invalid(e.to_string()))
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

    fn cc(s: &str) -> CountryCode {
        CountryCode::new(s).expect("valid country")
    }

    /// Seats given as `(seed, weight, country)`, sorted into canonical order.
    fn council(seats: &[(u8, u32, &str)], threshold: u32) -> Result<Council, CouncilError> {
        let mut seats: Vec<Seat> = seats
            .iter()
            .map(|(seed, weight, country)| Seat::new(addr(*seed), *weight, cc(country)))
            .collect();
        seats.sort_by_key(|seat| seat.holder);
        Council::new(seats, threshold)
    }

    #[test]
    fn no_single_jurisdiction_can_block_a_vote() {
        // Three countries at exactly a third each: every one of them is over the
        // cap, because a third is exactly enough to block a two-thirds
        // threshold. This is the case a rounded-down measure would wave through.
        let c = council(&[(1, 100, "ke"), (2, 100, "ng"), (3, 100, "za")], 6_667)
            .expect("structurally valid");
        assert_eq!(c.max_country_share_bps(), 3_334, "a third, rounded up");
        assert!(matches!(
            c.check_concentration(3_333),
            Err(CouncilError::CountryConcentration { found: 3_334, .. })
        ));

        // And the property it protects: the other two thirds must be able to
        // pass something without the third country.
        let ke = c.weight_of(&addr(1));
        assert!(
            !c.reached(u64::from(ke)),
            "one country alone must not pass a proposal"
        );
        assert!(
            !c.reached(c.total_weight() - u64::from(ke)),
            "and with an exact third held out, nothing passes — which is why the \
             cap has to be strictly under a third"
        );
    }

    #[test]
    fn no_two_jurisdictions_can_decide_alone() {
        // Six seats, three countries, each country under the cap. Any two
        // countries together fall short of two thirds; any three reach it.
        let c = council(
            &[
                (1, 33, "ke"),
                (2, 33, "ng"),
                (3, 33, "za"),
                (4, 1, "gh"),
                (5, 1, "tz"),
                (6, 1, "ug"),
            ],
            6_667,
        )
        .expect("valid");
        assert!(c.check_concentration(3_333).is_ok());

        let two_countries = u64::from(c.weight_of(&addr(1))) + u64::from(c.weight_of(&addr(2)));
        assert!(
            !c.reached(two_countries),
            "two jurisdictions must not be able to decide for the network"
        );
        let three = two_countries + u64::from(c.weight_of(&addr(3)));
        assert!(c.reached(three), "three reach the threshold");
    }

    #[test]
    fn a_council_that_could_be_written_two_ways_is_refused() {
        // The record is hashed into the state root, so a second ordering would
        // be a second root for one council.
        let seats = vec![
            Seat::new(addr(2), 1, cc("ke")),
            Seat::new(addr(1), 1, cc("ng")),
        ];
        let mut sorted = seats.clone();
        sorted.sort_by_key(|seat| seat.holder);
        assert_ne!(seats, sorted, "the fixture is genuinely out of order");
        assert_eq!(
            Council::new(seats, 10_000),
            Err(CouncilError::UnsortedSeats)
        );

        // And one account cannot hold two seats: sorting a repeat away would
        // silently pick which weight survives.
        let twice = vec![
            Seat::new(addr(1), 1, cc("ke")),
            Seat::new(addr(1), 9, cc("ng")),
        ];
        assert_eq!(
            Council::new(twice, 10_000),
            Err(CouncilError::UnsortedSeats)
        );
    }

    #[test]
    fn a_simple_majority_is_not_enough_to_govern() {
        assert_eq!(
            council(&[(1, 1, "ke"), (2, 1, "ng")], 5_001),
            Err(CouncilError::Threshold(5_001))
        );
        assert!(council(&[(1, 1, "ke"), (2, 1, "ng")], MIN_COUNCIL_THRESHOLD_BPS).is_ok());
    }

    #[test]
    fn an_empty_or_weightless_council_is_refused() {
        assert_eq!(Council::new(Vec::new(), 10_000), Err(CouncilError::Empty));
        assert_eq!(
            council(&[(1, 0, "ke")], 10_000),
            Err(CouncilError::ZeroWeight)
        );
    }

    #[test]
    fn a_threshold_is_never_reached_by_rounding() {
        // Three seats of one, threshold two thirds: two votes is 6666.67 bps,
        // which must not round up into a pass.
        let c = council(&[(1, 1, "ke"), (2, 1, "ng"), (3, 1, "za")], 6_667).expect("valid");
        assert!(!c.reached(2));
        assert!(c.reached(3));
    }

    #[test]
    fn a_stranger_holds_no_weight() {
        let c = council(&[(1, 5, "ke"), (2, 5, "ng")], 10_000).expect("valid");
        assert_eq!(c.weight_of(&addr(1)), 5);
        assert_eq!(c.weight_of(&addr(99)), 0);
        assert!(!c.is_seated(&addr(99)));
    }

    #[test]
    fn councils_round_trip_and_revalidate_on_decode() {
        let c = council(&[(1, 3, "ke"), (2, 4, "ng"), (3, 3, "za")], 7_500).expect("valid");
        assert_eq!(decode_exact::<Council>(&c.to_bytes()), Ok(c));

        // A hand-built encoding with the seats swapped must not decode.
        let mut bad = Vec::new();
        2u32.encode(&mut bad);
        Seat::new(addr(2), 1, cc("ke")).encode(&mut bad);
        Seat::new(addr(1), 1, cc("ng")).encode(&mut bad);
        10_000u32.encode(&mut bad);
        assert!(decode_exact::<Council>(&bad).is_err());
    }
}
