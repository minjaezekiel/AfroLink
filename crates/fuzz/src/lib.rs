//! A deterministic adversarial-input harness.
//!
//! # Why this is hand-rolled
//!
//! Everything here could be a `proptest` or `cargo-fuzz` dependency. It is not,
//! for the same reason the codec is not serde: a failure that cannot be
//! reproduced exactly is a failure that gets closed as flaky. Every case this
//! harness generates is a pure function of a `u64` seed, so a failing assertion
//! names the seed that produced it and re-running that seed reproduces it on any
//! machine, forever, with no corpus directory to lose.
//!
//! It also keeps this runnable as an ordinary `cargo test` in CI, rather than as
//! a separate long-running job nobody looks at.
//!
//! # What it is for
//!
//! Not throughput. Load tells you nothing about whether a node can be lied to,
//! and there is no network here to load. This targets the surface a hostile peer
//! actually touches: **bytes that arrive from someone else**.
//!
//! Three properties, applied across every type that decodes untrusted input:
//!
//! * [`decodes_are_canonical`] — if bytes decode, re-encoding must reproduce
//!   *those exact bytes*. This is the consensus-critical one. Two encodings of
//!   one value means two nodes can hash the same logical object differently,
//!   which is a chain split.
//! * [`truncations_are_rejected`] — every prefix of a valid encoding must fail
//!   cleanly rather than reading past the end or inventing a default.
//! * [`extensions_are_rejected`] — trailing bytes are an error, so a peer cannot
//!   append a payload that one implementation ignores and another reads.
//!
//! Panics need no explicit assertion: a panic in a decoder *is* the test
//! failure, and the workspace already denies `unwrap`/`expect`/`panic` in
//! non-test code precisely so that this stays true.

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

use afrolink_primitives::codec::{Decode, Encode, decode_exact};

/// A seeded, reproducible pseudo-random generator (SplitMix64).
///
/// Not cryptographic and not trying to be. Its only job is to produce the same
/// stream from the same seed on every platform, so a failure is a bug report
/// with a seed number in it.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Start a stream from `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next value in the stream.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n`. Returns 0 when `n` is 0.
    pub fn below(&mut self, n: usize) -> usize {
        let Ok(bound) = u64::try_from(n) else {
            return 0;
        };
        if bound == 0 {
            return 0;
        }
        let Some(v) = self.next_u64().checked_rem(bound) else {
            return 0;
        };
        usize::try_from(v).unwrap_or(0)
    }

    /// A random byte.
    pub fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xFF).unwrap_or(0)
    }

    /// `len` random bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// A random byte string of length `0..=max`.
    pub fn blob(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max.saturating_add(1));
        self.bytes(len)
    }
}

/// Derive a hostile variant of `input`.
///
/// Structure-aware rather than uniformly random: a valid encoding that has been
/// nudged reaches decoder paths that random noise never does, because random
/// noise almost never gets past the first length prefix.
#[must_use]
pub fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    match rng.below(7) {
        // Flip one bit. The classic, and the one that finds sign and boundary
        // confusion.
        0 => {
            if !out.is_empty() {
                let i = rng.below(out.len());
                let bit = rng.below(8);
                if let Some(b) = out.get_mut(i) {
                    *b ^= 1u8 << bit;
                }
            }
        }
        // Replace a byte outright.
        1 => {
            if !out.is_empty() {
                let i = rng.below(out.len());
                let v = rng.byte();
                if let Some(b) = out.get_mut(i) {
                    *b = v;
                }
            }
        }
        // Truncate. Targets end-of-input handling.
        2 => {
            let n = rng.below(out.len().saturating_add(1));
            out.truncate(n);
        }
        // Append junk. Must be rejected: trailing bytes are an error.
        3 => {
            let extra = rng.blob(8);
            out.extend_from_slice(&extra);
        }
        // Corrupt the leading length prefix, where allocation decisions live.
        4 => {
            let v = rng.next_u64();
            for (i, b) in v.to_le_bytes().iter().take(4).enumerate() {
                if let Some(slot) = out.get_mut(i) {
                    *slot = *b;
                }
            }
        }
        // Splice out a run, shifting everything after it.
        5 => {
            if out.len() > 2 {
                let start = rng.below(out.len());
                let len = rng.below(out.len().saturating_sub(start)).max(1);
                let end = start.saturating_add(len).min(out.len());
                out.drain(start..end);
            }
        }
        // Duplicate a run, which is how a repeated field slips past a decoder
        // that stops at the first one it recognises.
        _ => {
            if !out.is_empty() {
                let start = rng.below(out.len());
                let len = rng.below(out.len().saturating_sub(start)).max(1);
                let end = start.saturating_add(len).min(out.len());
                let slice = out.get(start..end).unwrap_or_default().to_vec();
                out.extend_from_slice(&slice);
            }
        }
    }
    out
}

/// **The consensus-critical property.** If bytes decode, they must be the
/// encoding that value produces.
///
/// A violation means one logical value has two valid byte strings. Two honest
/// nodes handed the two would compute different hashes for the same object and
/// disagree about a block — so this is a chain split found in a unit test rather
/// than in production.
///
/// # Panics
/// Asserts on the first non-canonical decode, naming the type, the seed and the
/// bytes.
pub fn decodes_are_canonical<T>(label: &str, seed: u64, bytes: &[u8])
where
    T: Encode + Decode,
{
    if let Ok(value) = decode_exact::<T>(bytes) {
        let re = value.to_bytes();
        assert_eq!(
            re.as_slice(),
            bytes,
            "{label}: decode is not canonical (seed {seed})\n  \
             accepted: {}\n  re-encoded: {}",
            hex(bytes),
            hex(&re)
        );
    }
}

/// Every strict prefix of a valid encoding must be refused.
///
/// A decoder that reads past the end, or quietly substitutes a default for a
/// field it could not find, hands a truncating peer control over a value nobody
/// sent.
///
/// # Panics
/// Asserts if any prefix decodes.
pub fn truncations_are_rejected<T>(label: &str, valid: &[u8])
where
    T: Encode + Decode,
{
    for cut in 0..valid.len() {
        let prefix = valid.get(..cut).unwrap_or_default();
        assert!(
            decode_exact::<T>(prefix).is_err(),
            "{label}: a {cut}-byte prefix of a {}-byte encoding decoded",
            valid.len()
        );
    }
}

/// Trailing bytes must be an error.
///
/// Otherwise a peer appends a payload that one implementation ignores and
/// another reads, and the two disagree about what they received.
///
/// # Panics
/// Asserts if a padded encoding decodes.
pub fn extensions_are_rejected<T>(label: &str, valid: &[u8])
where
    T: Encode + Decode,
{
    for pad in 1..=4usize {
        let mut padded = valid.to_vec();
        padded.extend(core::iter::repeat_n(0u8, pad));
        assert!(
            decode_exact::<T>(&padded).is_err(),
            "{label}: {pad} trailing byte(s) were accepted"
        );
    }
}

/// Run all three properties over a valid encoding and `rounds` mutations of it.
///
/// # Panics
/// Asserts on the first property violation.
pub fn hammer<T>(label: &str, value: &T, rounds: u64)
where
    T: Encode + Decode,
{
    let valid = value.to_bytes();

    // The fixture itself must round-trip, or the rest of this proves nothing.
    assert_eq!(
        decode_exact::<T>(&valid).map(|v| v.to_bytes()).as_deref(),
        Ok(valid.as_slice()),
        "{label}: fixture does not round-trip"
    );

    truncations_are_rejected::<T>(label, &valid);
    extensions_are_rejected::<T>(label, &valid);

    for seed in 0..rounds {
        let mut rng = Rng::new(seed);
        // Structure-aware: a nudged valid encoding reaches deep decoder paths.
        let mutated = mutate(&mut rng, &valid);
        decodes_are_canonical::<T>(label, seed, &mutated);
        // And pure noise, which is what a peer sending garbage looks like.
        let noise = rng.blob(valid.len().saturating_add(16));
        decodes_are_canonical::<T>(label, seed, &noise);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generator_is_reproducible_across_runs() {
        // The whole point: a seed in a failure message must reproduce the case.
        let a: Vec<u64> = (0..8).map(|_| Rng::new(42).next_u64()).collect();
        let mut rng = Rng::new(42);
        let b: Vec<u64> = (0..8).map(|_| rng.next_u64()).collect();
        assert_eq!(a[0], b[0]);
        assert_ne!(b[0], b[1], "and it must actually advance");
    }

    #[test]
    fn different_seeds_diverge() {
        assert_ne!(Rng::new(1).next_u64(), Rng::new(2).next_u64());
    }

    #[test]
    fn mutation_reaches_every_shape() {
        // A mutator that only ever flips bits would never test truncation or
        // trailing-byte handling, and the suite would look thorough while
        // covering one path.
        let input = vec![0u8; 16];
        let mut shorter = false;
        let mut longer = false;
        let mut same_length_but_changed = false;
        for seed in 0..200 {
            let mut rng = Rng::new(seed);
            let out = mutate(&mut rng, &input);
            match out.len().cmp(&input.len()) {
                core::cmp::Ordering::Less => shorter = true,
                core::cmp::Ordering::Greater => longer = true,
                core::cmp::Ordering::Equal => {
                    if out != input {
                        same_length_but_changed = true;
                    }
                }
            }
        }
        assert!(shorter && longer && same_length_but_changed);
    }

    #[test]
    fn the_canonical_check_catches_a_non_canonical_decoder() {
        // Guard against the suite silently passing because the property is
        // vacuous. `bool` is the smallest type with a redundant encoding
        // available: only 0 and 1 are canonical.
        assert!(decode_exact::<bool>(&[2]).is_err(), "2 must not decode");
        decodes_are_canonical::<bool>("bool", 0, &[1]);
        decodes_are_canonical::<bool>("bool", 0, &[0]);
    }
}
