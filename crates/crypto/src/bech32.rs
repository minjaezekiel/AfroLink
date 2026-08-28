//! A minimal Bech32m encoder/decoder (BIP-173 / BIP-350).
//!
//! Implemented in-tree rather than pulled from a dependency because the address
//! format is consensus-critical and permanent: a checksum change would orphan
//! every wallet ever printed. It is ~120 lines of well-specified arithmetic and
//! is tested against the published BIP-350 vectors below.
//!
//! Bech32m is the right format for this chain specifically because its checksum
//! catches every error of up to 4 characters — which matters when an address is
//! read over a phone line or typed on a feature-phone keypad.

// The BCH checksum arithmetic is a fixed sequence of shifts, masks and XORs over
// values the algorithm itself bounds: `to`/`from` are the constants 5 and 8,
// charset indices are < 32, and every slice access goes through `get`. Spelling
// out a checked variant of each step would obscure a well-specified algorithm
// without making it safer, so the lint is disabled for this module only.
#![allow(
    clippy::arithmetic_side_effects,
    reason = "bit-twiddling over algorithm-bounded constants; see module note above"
)]

use crate::{CryptoError, Result};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// Maximum total length of a bech32 string, per BIP-173.
pub const MAX_LEN: usize = 90;

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GENERATOR.iter().enumerate() {
            #[expect(clippy::cast_possible_truncation, reason = "i < 5")]
            if (top >> i as u32) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    out.extend(bytes.iter().map(|b| b >> 5));
    out.push(0);
    out.extend(bytes.iter().map(|b| b & 31));
    out
}

/// Regroup bits from `from` bits per input element to `to` bits per output element.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << to) - 1;
    for &value in data {
        let v = u32::from(value);
        if (v >> from) != 0 {
            return Err(CryptoError::Bech32("input value out of range".to_owned()));
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "masked to `to` bits, to <= 8"
            )]
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "masked to `to` bits, to <= 8"
            )]
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        // Reject non-zero padding: it would let two strings decode to the same
        // payload, giving an address more than one valid spelling.
        return Err(CryptoError::Bech32("invalid padding".to_owned()));
    }
    Ok(out)
}

/// Encode `data` (arbitrary bytes) under human-readable prefix `hrp`.
///
/// # Errors
/// Returns [`CryptoError::Bech32`] if the hrp is empty, out of range, or the
/// result would exceed [`MAX_LEN`].
pub fn encode(hrp: &str, data: &[u8]) -> Result<String> {
    if hrp.is_empty() {
        return Err(CryptoError::Bech32("empty hrp".to_owned()));
    }
    if !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(CryptoError::Bech32("hrp character out of range".to_owned()));
    }
    if hrp.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(CryptoError::Bech32("hrp must be lowercase".to_owned()));
    }

    let payload = convert_bits(data, 8, 5, true)?;
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&payload);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let checksum = polymod(&values) ^ BECH32M_CONST;

    let mut out = String::with_capacity(hrp.len() + 1 + payload.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for v in payload {
        out.push(char::from(*CHARSET.get(v as usize).unwrap_or(&b'q')));
    }
    for i in 0..6 {
        let idx = ((checksum >> (5 * (5 - i))) & 31) as usize;
        out.push(char::from(*CHARSET.get(idx).unwrap_or(&b'q')));
    }
    if out.len() > MAX_LEN {
        return Err(CryptoError::Bech32(
            "encoded string exceeds 90 characters".to_owned(),
        ));
    }
    Ok(out)
}

/// Decode a bech32m string, returning `(hrp, data)`.
///
/// # Errors
/// Returns [`CryptoError::Bech32`] on any malformed input, including a bad
/// checksum, mixed case, or non-zero padding bits.
pub fn decode(s: &str) -> Result<(String, Vec<u8>)> {
    if s.len() > MAX_LEN {
        return Err(CryptoError::Bech32(
            "string exceeds 90 characters".to_owned(),
        ));
    }
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        // Mixed case would give one address two spellings with the same checksum.
        return Err(CryptoError::Bech32("mixed case".to_owned()));
    }
    let lowered = s.to_ascii_lowercase();

    let sep = lowered
        .rfind('1')
        .ok_or_else(|| CryptoError::Bech32("missing separator".to_owned()))?;
    let hrp = lowered.get(..sep).unwrap_or_default();
    let data_part = lowered.get(sep + 1..).unwrap_or_default();
    if hrp.is_empty() {
        return Err(CryptoError::Bech32("empty hrp".to_owned()));
    }
    if data_part.len() < 6 {
        return Err(CryptoError::Bech32(
            "data part shorter than checksum".to_owned(),
        ));
    }

    let mut values = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        let idx = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| CryptoError::Bech32(format!("invalid character {:?}", char::from(c))))?;
        #[expect(clippy::cast_possible_truncation, reason = "position < 32")]
        values.push(idx as u8);
    }

    let mut checked = hrp_expand(hrp);
    checked.extend_from_slice(&values);
    if polymod(&checked) != BECH32M_CONST {
        return Err(CryptoError::Bech32("checksum mismatch".to_owned()));
    }

    let payload = values
        .get(..values.len().saturating_sub(6))
        .unwrap_or_default();
    let data = convert_bits(payload, 5, 8, false)?;
    Ok((hrp.to_owned(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_payloads() {
        let data = [0xABu8; 20];
        let s = encode("afri", &data).expect("encodes");
        let (hrp, back) = decode(&s).expect("decodes");
        assert_eq!(hrp, "afri");
        assert_eq!(back, data);
    }

    #[test]
    fn matches_bip350_valid_vectors() {
        // From BIP-350's list of valid bech32m strings.
        for v in [
            "A1LQFN3A",
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "?1v759aa",
        ] {
            assert!(decode(v).is_ok(), "{v} should be a valid bech32m string");
        }
    }

    #[test]
    fn rejects_bip350_invalid_vectors() {
        for v in [
            "a1lqfn3a1",                                      // trailing junk breaks the checksum
            "qyrz8wqd2c9m",                                   // no separator-delimited hrp
            "1qyrz8wqd2c9m",                                  // empty hrp
            "A1G7SGD8", // bech32 (not bech32m) checksum constant
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryxx", // corrupted checksum
        ] {
            assert!(decode(v).is_err(), "{v} should be rejected");
        }
    }

    #[test]
    fn mixed_case_is_rejected() {
        let s = encode("afri", &[1u8; 20]).expect("encodes");
        let mut mixed = s.clone();
        mixed.replace_range(0..1, "A");
        assert!(decode(&mixed).is_err());
    }

    #[test]
    fn single_character_corruption_is_caught() {
        let s = encode("afri", &[7u8; 20]).expect("encodes");
        let bytes = s.as_bytes();
        let last = bytes.len() - 1;
        let orig = char::from(bytes[last]);
        let swap = if orig == 'q' { 'p' } else { 'q' };
        let mut corrupted = s.clone();
        corrupted.replace_range(last..=last, &swap.to_string());
        assert!(
            decode(&corrupted).is_err(),
            "checksum must catch a 1-char typo"
        );
    }

    #[test]
    fn uppercase_round_trips_to_the_same_payload() {
        let data = [0x11u8; 20];
        let s = encode("afri", &data).expect("encodes");
        let (_, from_upper) = decode(&s.to_ascii_uppercase()).expect("uppercase decodes");
        assert_eq!(
            from_upper, data,
            "case-insensitive by design, for USSD entry"
        );
    }
}
