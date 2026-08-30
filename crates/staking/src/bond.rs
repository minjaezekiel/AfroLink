//! Bonds, and stake on its way out.

use afrolink_consensus::CountryCode;
use afrolink_crypto::{Address, PublicKey};
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Amount, Height, Timestamp};

/// An operator's stake and the identity it secures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bond {
    /// The account that controls this bond and receives its stake back.
    pub operator: Address,
    /// The consensus key this operator signs blocks with.
    ///
    /// Distinct from the operator address on purpose: the consensus key lives on
    /// a machine that is online continuously, and the account that owns the
    /// money should not have to.
    pub public_key: PublicKey,
    /// Where the operator is, for the concentration limits in
    /// [ADR-0007](../../../docs/adr/0007-distribution-and-sybil-resistance.md).
    pub country: CountryCode,
    /// Stake currently at risk.
    pub bonded: Amount,
    /// Whether an infraction has removed this operator from the active set.
    ///
    /// Jailing is separate from slashing. Slashing takes money once; jailing
    /// stops the operator signing until governance releases them, which is what
    /// actually protects the chain from a validator that is misbehaving *now*.
    pub jailed: bool,
    /// Height at which the operator was jailed, if they are.
    pub jailed_at: Option<Height>,
}

impl Bond {
    /// A new, unjailed bond.
    #[must_use]
    pub fn new(
        operator: Address,
        public_key: PublicKey,
        country: CountryCode,
        bonded: Amount,
    ) -> Self {
        Self {
            operator,
            public_key,
            country,
            bonded,
            jailed: false,
            jailed_at: None,
        }
    }
}

/// Stake that has been withdrawn from the active set but is still slashable.
///
/// # The field that makes the unbonding period mean anything
///
/// `started_at`. Without it, a validator equivocates and immediately unbonds,
/// and by the time anyone submits the evidence the stake is in a queue that
/// nobody thinks to touch. The whole 21 days buys nothing.
///
/// So an infraction at height `h` reaches **every entry that was still bonded at
/// `h`** — that is, every entry with `started_at > h`. The stake left the active
/// set, but it had not left the period during which it answers for what it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unbonding {
    /// How much is queued.
    pub amount: Amount,
    /// The height at which unbonding began.
    pub started_at: Height,
    /// The wall-clock time at which the funds may be withdrawn.
    pub completes_at: Timestamp,
}

impl Unbonding {
    /// Whether this entry was still bonded at `height`, and so answers for an
    /// infraction committed then.
    #[must_use]
    pub fn covers(&self, height: Height) -> bool {
        self.started_at > height
    }

    /// Whether the funds may be withdrawn at `now`.
    #[must_use]
    pub fn matured(&self, now: Timestamp) -> bool {
        now.0 >= self.completes_at.0
    }
}

impl Encode for Bond {
    fn encode(&self, out: &mut Vec<u8>) {
        self.operator.encode(out);
        self.public_key.encode(out);
        self.country.encode(out);
        self.bonded.encode(out);
        self.jailed.encode(out);
        self.jailed_at.encode(out);
    }
}

impl Decode for Bond {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            operator: Address::decode(r)?,
            public_key: PublicKey::decode(r)?,
            country: CountryCode::decode(r)?,
            bonded: Amount::decode(r)?,
            jailed: bool::decode(r)?,
            jailed_at: Option::<Height>::decode(r)?,
        })
    }
}

impl Encode for Unbonding {
    fn encode(&self, out: &mut Vec<u8>) {
        self.amount.encode(out);
        self.started_at.encode(out);
        self.completes_at.encode(out);
    }
}

impl Decode for Unbonding {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            amount: Amount::decode(r)?,
            started_at: Height::decode(r)?,
            completes_at: Timestamp::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_primitives::codec::decode_exact;

    fn entry(started: u64) -> Unbonding {
        Unbonding {
            amount: Amount::from_afri(1_000),
            started_at: Height(started),
            completes_at: Timestamp::from_millis(2_000),
        }
    }

    #[test]
    fn an_entry_answers_for_infractions_committed_before_it_left() {
        // Unbonding started at height 100, so this stake was bonded for every
        // height below that and answers for all of them.
        let e = entry(100);
        assert!(e.covers(Height(99)), "bonded at 99, so still liable");
        assert!(e.covers(Height(0)));
    }

    #[test]
    fn an_entry_does_not_answer_for_infractions_after_it_left() {
        // At height 100 onwards this stake was no longer securing anything, so
        // slashing it would be taking money for something it did not back.
        let e = entry(100);
        assert!(!e.covers(Height(100)));
        assert!(!e.covers(Height(500)));
    }

    #[test]
    fn maturity_is_inclusive_of_the_completion_instant() {
        let e = entry(1);
        assert!(!e.matured(Timestamp::from_millis(1_999)));
        assert!(e.matured(Timestamp::from_millis(2_000)));
        assert!(e.matured(Timestamp::from_millis(2_001)));
    }

    #[test]
    fn records_round_trip() {
        let e = entry(7);
        assert_eq!(decode_exact::<Unbonding>(&e.to_bytes()), Ok(e));

        let bond = Bond::new(
            Address::from_public_key(
                &afrolink_crypto::SecretKey::from_bytes(&[1; 32]).public_key(),
            ),
            afrolink_crypto::SecretKey::from_bytes(&[1; 32]).public_key(),
            CountryCode::new("ke").expect("valid"),
            Amount::from_afri(5_000),
        );
        assert_eq!(decode_exact::<Bond>(&bond.to_bytes()), Ok(bond));
    }
}
