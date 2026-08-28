//! Fixed-point token amounts.
//!
//! An [`Amount`] is an unsigned integer count of the *smallest indivisible unit*
//! of a token. There are no fractions and no floats anywhere in AfroLink: money
//! bugs on a payments chain are unrecoverable, and IEEE-754 cannot represent
//! `0.1` exactly.
//!
//! For AFRI the smallest unit is the **sente**, with 10^9 sente = 1 AFRI.

use crate::codec::{CodecError, Decode, Encode, Reader};
use crate::error::{Error, Result};

/// Decimal places between one AFRI and one sente.
pub const AFRI_DECIMALS: u32 = 9;

/// Number of sente in one whole AFRI.
pub const SENTE_PER_AFRI: u128 = 1_000_000_000;

/// An unsigned amount of the smallest unit of some denomination.
///
/// `u128` is chosen deliberately: at 9 decimals, `u64` would cap total supply at
/// ~18 billion AFRI, which is too tight a ceiling for a currency intended to
/// carry national stablecoins with their own decimal conventions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u128);

impl Amount {
    /// The zero amount.
    pub const ZERO: Self = Self(0);

    /// The largest representable amount.
    pub const MAX: Self = Self(u128::MAX);

    /// Construct from a raw count of smallest units.
    #[must_use]
    pub const fn from_units(units: u128) -> Self {
        Self(units)
    }

    /// Construct from a whole number of AFRI, saturating at [`Self::MAX`].
    #[must_use]
    pub const fn from_afri(whole: u64) -> Self {
        Self((whole as u128).saturating_mul(SENTE_PER_AFRI))
    }

    /// The raw count of smallest units.
    #[must_use]
    pub const fn units(self) -> u128 {
        self.0
    }

    /// Whether this is exactly zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Checked addition.
    ///
    /// # Errors
    /// Returns [`Error::Overflow`] if the sum exceeds [`Self::MAX`].
    pub fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(Error::Overflow { op: "Amount::add" })
    }

    /// Checked subtraction.
    ///
    /// # Errors
    /// Returns [`Error::Overflow`] if `other > self`. Balances are unsigned, so
    /// an underflow here is exactly the "spent more than you have" case and
    /// must never wrap.
    pub fn checked_sub(self, other: Self) -> Result<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(Error::Overflow { op: "Amount::sub" })
    }

    /// Checked multiplication by a scalar.
    ///
    /// # Errors
    /// Returns [`Error::Overflow`] on wrap.
    pub fn checked_mul(self, scalar: u128) -> Result<Self> {
        self.0
            .checked_mul(scalar)
            .map(Self)
            .ok_or(Error::Overflow { op: "Amount::mul" })
    }

    /// Multiply by `numer / denom` with truncation, without intermediate overflow
    /// for the common case. Used for fee splits and staking reward shares.
    ///
    /// # Errors
    /// Returns [`Error::Overflow`] if `denom` is zero or the product wraps.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "the only unchecked operations are `/` and `%` by `denom`, which is \
                  guarded against zero on the first line; u128 division cannot overflow"
    )]
    pub fn mul_ratio(self, numer: u128, denom: u128) -> Result<Self> {
        if denom == 0 {
            return Err(Error::Overflow {
                op: "Amount::mul_ratio/zero-denominator",
            });
        }
        // Split to keep `self * numer` from overflowing when both are large:
        //   (q*denom + r) * numer / denom  ==  q*numer + (r*numer)/denom
        let q = self.0 / denom;
        let r = self.0 % denom;
        let lhs = q.checked_mul(numer).ok_or(Error::Overflow {
            op: "Amount::mul_ratio",
        })?;
        let rhs = r.checked_mul(numer).ok_or(Error::Overflow {
            op: "Amount::mul_ratio",
        })? / denom;
        lhs.checked_add(rhs).map(Self).ok_or(Error::Overflow {
            op: "Amount::mul_ratio",
        })
    }
}

impl core::fmt::Display for Amount {
    /// Render as a decimal string with [`AFRI_DECIMALS`] places, trimming trailing
    /// zeros but always keeping at least one digit after the point.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let whole = self.0 / SENTE_PER_AFRI;
        let frac = self.0 % SENTE_PER_AFRI;
        let frac_str = format!("{frac:0>width$}", width = AFRI_DECIMALS as usize);
        let trimmed = frac_str.trim_end_matches('0');
        if trimmed.is_empty() {
            write!(f, "{whole}.0")
        } else {
            write!(f, "{whole}.{trimmed}")
        }
    }
}

impl Encode for Amount {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for Amount {
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        Ok(Self(u128::decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::decode_exact;

    #[test]
    fn overspending_errors_instead_of_wrapping() {
        let balance = Amount::from_units(5);
        assert!(balance.checked_sub(Amount::from_units(6)).is_err());
    }

    #[test]
    fn addition_at_the_ceiling_errors() {
        assert!(Amount::MAX.checked_add(Amount::from_units(1)).is_err());
    }

    #[test]
    fn display_renders_nine_decimals() {
        assert_eq!(Amount::from_afri(2).to_string(), "2.0");
        assert_eq!(Amount::from_units(2_500_000_000).to_string(), "2.5");
        assert_eq!(Amount::from_units(1).to_string(), "0.000000001");
    }

    #[test]
    fn mul_ratio_avoids_intermediate_overflow() {
        // Naive `self * numer` would wrap here; the split must not.
        let huge = Amount::from_units(u128::MAX / 2);
        let half = huge.mul_ratio(1, 2).expect("ratio must not overflow");
        assert_eq!(half.units(), (u128::MAX / 2) / 2);
    }

    #[test]
    fn mul_ratio_rejects_zero_denominator() {
        assert!(Amount::from_afri(1).mul_ratio(1, 0).is_err());
    }

    #[test]
    fn amount_round_trips_through_codec() {
        let a = Amount::from_afri(1_234);
        assert_eq!(decode_exact::<Amount>(&a.to_bytes()), Ok(a));
    }
}
