//! Corroboration: turning several witnesses' observations into a checkpoint,
//! or refusing to.
//!
//! # The rule, and why it is this way round
//!
//! A stale wallet is in more danger, not less. So as its trusted header ages,
//! this module asks for **more** independent agreement — never less, and never
//! a "probably fine" shortcut. Degrading a single anchor because time has passed
//! is the exact failure
//! [ADR-0010](../../../docs/adr/0010-long-range-attacks.md) exists to prevent.
//! Requiring more independent anchors is its opposite.

use afrolink_crypto::hash::Hash32;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{ChainId, Height};

use crate::WitnessError;
use crate::audit::Observation;
use crate::head::LogId;

/// The trusted root a wallet starts from: a chain, a height, and a block.
///
/// Small on purpose. Everything else a light client needs — the header, both
/// validator sets — can be fetched from anyone at all and checked against this,
/// because the header's identifier commits to its own contents. So this is the
/// entire trusted surface, and it fits in a QR code an agent can print or
/// another phone can display offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Which network.
    pub chain_id: ChainId,
    /// Height of the checkpointed block.
    pub height: Height,
    /// Its block identifier.
    pub block_id: Hash32,
}

/// How much agreement a wallet demands before it will adopt a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Distinct witnesses that must agree.
    pub min_witnesses: usize,
    /// Distinct jurisdictions those witnesses must span.
    pub min_countries: usize,
}

/// The most independent agreement [`Policy::for_age`] will ever demand.
///
/// The cap exists because an unsatisfiable policy is a refusal dressed up as a
/// rule: past a handful of jurisdictions a wallet is asking for more independent
/// legal authorities than its witness set contains, and would strand the user
/// permanently while looking principled. Depth beyond this point is the job of
/// an external anchor, not of more signatures.
pub const MAX_CORROBORATION: usize = 4;

impl Policy {
    /// The baseline: two witnesses in two jurisdictions.
    ///
    /// Two, not one, because a single source is indistinguishable from no
    /// source. Two jurisdictions, not two witnesses, because collusion is
    /// cheapest under one legal authority.
    pub const BASELINE: Self = Self {
        min_witnesses: 2,
        min_countries: 2,
    };

    /// The policy for a wallet whose trusted header is `age_ms` old.
    ///
    /// One further independent witness, in one further jurisdiction, per
    /// trusting period of staleness — up to [`MAX_CORROBORATION`].
    #[must_use]
    pub fn for_age(age_ms: u64, trusting_period_ms: u64) -> Self {
        let periods = age_ms.checked_div(trusting_period_ms).unwrap_or(0);
        let extra = usize::try_from(periods)
            .unwrap_or(MAX_CORROBORATION)
            .min(MAX_CORROBORATION.saturating_sub(Self::BASELINE.min_witnesses));
        Self {
            min_witnesses: Self::BASELINE.min_witnesses.saturating_add(extra),
            min_countries: Self::BASELINE.min_countries.saturating_add(extra),
        }
    }

    /// Whether a set of witnesses could ever satisfy this policy.
    ///
    /// Worth checking before a user needs it: a wallet that discovers its
    /// witness set is too narrow only when the user is stranded has discovered
    /// it too late.
    #[must_use]
    pub fn satisfiable_by(&self, witnesses: usize, countries: usize) -> bool {
        witnesses >= self.min_witnesses && countries >= self.min_countries
    }
}

/// Combine verified observations into a checkpoint, or refuse.
///
/// Returns the **highest** height that meets `policy`.
///
/// # Errors
///
/// [`WitnessError::SplitView`] if any two witnesses reported different blocks at
/// the same height. This refuses *everything*, not merely the disputed height:
/// witnesses that disagree anywhere have already told the wallet it cannot rely
/// on them, and picking a winner among them is exactly the judgement a light
/// client is not equipped to make.
///
/// [`WitnessError::NotCorroborated`] if no height gathered enough independent
/// agreement, carrying the best it managed so a caller can report something
/// useful rather than a bare failure.
pub fn corroborate(
    chain_id: &ChainId,
    observations: &[Observation],
    policy: Policy,
) -> Result<Checkpoint, WitnessError> {
    // A disagreement anywhere disqualifies the whole set.
    for (i, a) in observations.iter().enumerate() {
        for b in observations.iter().skip(i.saturating_add(1)) {
            if a.height() == b.height() && a.block_id() != b.block_id() {
                return Err(WitnessError::SplitView {
                    height: a.height().0,
                });
            }
        }
    }

    let mut best = Checkpoint {
        chain_id: chain_id.clone(),
        height: Height::GENESIS,
        block_id: Hash32::ZERO,
    };
    let mut found = false;
    let (mut best_witnesses, mut best_countries) = (0usize, 0usize);

    for candidate in observations {
        let mut logs: Vec<LogId> = Vec::new();
        let mut countries: Vec<[u8; 2]> = Vec::new();
        for o in observations
            .iter()
            .filter(|o| o.height() == candidate.height())
        {
            // Each operator counts once however many times it answered.
            if !logs.contains(&o.log()) {
                logs.push(o.log());
            }
            if !countries.contains(&o.country()) {
                countries.push(o.country());
            }
        }
        best_witnesses = best_witnesses.max(logs.len());
        best_countries = best_countries.max(countries.len());

        if policy.satisfiable_by(logs.len(), countries.len())
            && (!found || candidate.height() > best.height)
        {
            best = Checkpoint {
                chain_id: chain_id.clone(),
                height: candidate.height(),
                block_id: candidate.block_id(),
            };
            found = true;
        }
    }

    if found {
        Ok(best)
    } else {
        Err(WitnessError::NotCorroborated {
            witnesses: best_witnesses,
            countries: best_countries,
            need_witnesses: policy.min_witnesses,
            need_countries: policy.min_countries,
        })
    }
}

impl Encode for Checkpoint {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.height.encode(out);
        self.block_id.encode(out);
    }
}

impl Decode for Checkpoint {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: ChainId::decode(r)?,
            height: Height::decode(r)?,
            block_id: Hash32::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Witness, WitnessSet};
    use crate::log::{LogEntry, WitnessLog};
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::Timestamp;
    use afrolink_primitives::codec::decode_exact;

    const TRUSTING: u64 = 14 * 24 * 60 * 60 * 1_000;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn block(h: u64) -> Hash32 {
        Hash32::from_bytes([u8::try_from(h % 251).unwrap_or(0); 32])
    }

    /// One witness observing heights 1..=n, honestly unless `lie_at` says
    /// otherwise.
    fn observation(
        set: &WitnessSet,
        seed: u8,
        heights: &[u64],
        want: u64,
        lie: Option<Hash32>,
    ) -> Observation {
        let mut log = WitnessLog::new(chain(), LogId::from_public_key(&key(seed).public_key()));
        let mut index = 0u64;
        for (i, h) in heights.iter().enumerate() {
            let block_id = if *h == want {
                lie.unwrap_or(block(*h))
            } else {
                block(*h)
            };
            log.append(LogEntry {
                height: Height(*h),
                block_id,
                observed_at: Timestamp::from_millis(1_700_000_000_000 + h * 1_000),
            })
            .expect("monotonic");
            if *h == want {
                index = u64::try_from(i).unwrap_or(0);
            }
        }
        let sth = log
            .sign_head(&key(seed), Timestamp::from_millis(1_700_001_000_000))
            .expect("own key");
        let proof = log.prove_inclusion(index).expect("in range");
        set.observe(
            &chain(),
            &sth,
            index,
            log.entry(index).expect("in range"),
            &proof,
        )
        .expect("proved")
    }

    fn witnesses() -> WitnessSet {
        WitnessSet::new(vec![
            Witness::new(key(1).public_key(), *b"ke", "one"),
            Witness::new(key(2).public_key(), *b"ng", "two"),
            Witness::new(key(3).public_key(), *b"za", "three"),
            Witness::new(key(4).public_key(), *b"gh", "four"),
        ])
        .expect("valid")
    }

    #[test]
    fn two_independent_witnesses_produce_a_checkpoint() {
        let set = witnesses();
        let obs = vec![
            observation(&set, 1, &[10, 20, 30], 30, None),
            observation(&set, 2, &[10, 20, 30], 30, None),
        ];
        let cp = corroborate(&chain(), &obs, Policy::BASELINE).expect("corroborated");
        assert_eq!(cp.height, Height(30));
        assert_eq!(cp.block_id, block(30));
    }

    #[test]
    fn one_witness_alone_is_never_enough() {
        // A single source is indistinguishable from no source.
        let set = witnesses();
        let obs = vec![observation(&set, 1, &[10, 20], 20, None)];
        assert!(matches!(
            corroborate(&chain(), &obs, Policy::BASELINE),
            Err(WitnessError::NotCorroborated { .. })
        ));
    }

    #[test]
    fn agreement_inside_one_jurisdiction_does_not_count_as_independence() {
        // Collusion is cheapest under a single legal authority, so two witnesses
        // in one country are treated as closer to one than to two.
        let set = WitnessSet::new(vec![
            Witness::new(key(1).public_key(), *b"ke", "one"),
            Witness::new(key(2).public_key(), *b"ke", "two"),
        ])
        .expect("valid");
        let obs = vec![
            observation(&set, 1, &[10], 10, None),
            observation(&set, 2, &[10], 10, None),
        ];
        assert!(matches!(
            corroborate(&chain(), &obs, Policy::BASELINE),
            Err(WitnessError::NotCorroborated { countries: 1, .. })
        ));
    }

    #[test]
    fn a_single_disagreement_disqualifies_the_whole_set() {
        // Three witnesses agree at height 30 and would satisfy the policy on
        // their own. One dissents. The wallet must refuse rather than outvote
        // it: choosing between conflicting histories is the judgement a light
        // client cannot make.
        let set = witnesses();
        let obs = vec![
            observation(&set, 1, &[30], 30, None),
            observation(&set, 2, &[30], 30, None),
            observation(&set, 3, &[30], 30, None),
            observation(&set, 4, &[30], 30, Some(Hash32::from_bytes([0xEE; 32]))),
        ];
        assert_eq!(
            corroborate(&chain(), &obs, Policy::BASELINE),
            Err(WitnessError::SplitView { height: 30 })
        );
    }

    #[test]
    fn the_highest_corroborated_height_wins() {
        // Witnesses poll at different times, so they agree deeply and diverge
        // at the tip. The wallet should take the deepest point that still meets
        // the policy, not the newest thing anyone claims.
        let set = witnesses();
        let obs = vec![
            observation(&set, 1, &[10, 20, 30], 20, None),
            observation(&set, 2, &[10, 20, 30], 20, None),
            observation(&set, 3, &[10, 20, 30], 30, None),
        ];
        let cp = corroborate(&chain(), &obs, Policy::BASELINE).expect("corroborated");
        assert_eq!(
            cp.height,
            Height(20),
            "height 30 has only one witness behind it"
        );
    }

    #[test]
    fn staleness_raises_the_bar_and_never_lowers_it() {
        let fresh = Policy::for_age(0, TRUSTING);
        assert_eq!(fresh, Policy::BASELINE);

        let one_period = Policy::for_age(TRUSTING, TRUSTING);
        assert_eq!(one_period.min_witnesses, 3);
        assert_eq!(one_period.min_countries, 3);

        let very_stale = Policy::for_age(TRUSTING * 400, TRUSTING);
        assert_eq!(
            very_stale.min_witnesses, MAX_CORROBORATION,
            "the demand is capped, because an unsatisfiable policy strands users"
        );

        // Monotonic in age: no amount of waiting ever makes the bar easier.
        let mut previous = 0;
        for periods in 0..10u64 {
            let p = Policy::for_age(TRUSTING * periods, TRUSTING);
            assert!(p.min_witnesses >= previous);
            previous = p.min_witnesses;
        }
    }

    #[test]
    fn a_stale_wallet_needs_more_agreement_than_a_fresh_one() {
        let set = witnesses();
        let obs = vec![
            observation(&set, 1, &[30], 30, None),
            observation(&set, 2, &[30], 30, None),
        ];
        assert!(corroborate(&chain(), &obs, Policy::BASELINE).is_ok());

        let stale = Policy::for_age(TRUSTING * 2, TRUSTING);
        assert!(matches!(
            corroborate(&chain(), &obs, stale),
            Err(WitnessError::NotCorroborated { .. })
        ));
    }

    #[test]
    fn a_wallet_can_tell_in_advance_that_its_witness_set_is_too_narrow() {
        let set = WitnessSet::new(vec![
            Witness::new(key(1).public_key(), *b"ke", "one"),
            Witness::new(key(2).public_key(), *b"ke", "two"),
        ])
        .expect("valid");
        assert!(!Policy::BASELINE.satisfiable_by(set.len(), set.countries()));
    }

    #[test]
    fn a_checkpoint_round_trips_for_a_qr_code() {
        let cp = Checkpoint {
            chain_id: chain(),
            height: Height(1_234_567),
            block_id: block(7),
        };
        let bytes = cp.to_bytes();
        assert!(
            bytes.len() < 128,
            "must stay small enough to scan: {} bytes",
            bytes.len()
        );
        assert_eq!(decode_exact::<Checkpoint>(&bytes), Ok(cp));
    }
}
