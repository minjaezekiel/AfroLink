//! The canonical consensus codec.
//!
//! Blockchains hash their own data structures, so the encoding *is* part of the
//! protocol. We do not use serde here on purpose: serde's derive is tuned for
//! flexible interchange (skipped fields, defaults, backwards-compatible enums),
//! and every one of those conveniences is a way for two implementations to
//! produce different bytes for the same logical value — which is a chain split.
//!
//! Rules:
//! * fixed-width little-endian integers
//! * `u32` length prefix on all variable-length data
//! * enum variants prefixed with a `u8` discriminant
//! * decoding is strict: trailing bytes are an error ([`decode_exact`])

use thiserror::Error;

/// Maximum length accepted for any single length-prefixed field (16 MiB).
///
/// This bounds the allocation a malicious peer can induce with a forged length
/// prefix. Anything legitimately larger must be chunked by the caller.
pub const MAX_FIELD_LEN: u32 = 16 * 1024 * 1024;

/// Errors produced while decoding untrusted bytes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The buffer ended before the value did.
    #[error("unexpected end of input: wanted {wanted} more byte(s), {left} left")]
    UnexpectedEof {
        /// Bytes the decoder asked for.
        wanted: usize,
        /// Bytes actually remaining.
        left: usize,
    },
    /// A length prefix exceeded [`MAX_FIELD_LEN`].
    #[error("length prefix {len} exceeds maximum {MAX_FIELD_LEN}")]
    LengthTooLarge {
        /// The offending declared length.
        len: u32,
    },
    /// An enum discriminant did not correspond to a known variant.
    #[error("unknown discriminant {tag} for {type_name}")]
    UnknownDiscriminant {
        /// The unrecognised tag byte.
        tag: u8,
        /// Name of the type being decoded, for diagnostics.
        type_name: &'static str,
    },
    /// Bytes remained after a complete value was decoded.
    #[error("{left} trailing byte(s) after value")]
    TrailingBytes {
        /// Number of unconsumed bytes.
        left: usize,
    },
    /// A field held bytes that are structurally valid but semantically illegal.
    #[error("invalid value: {0}")]
    Invalid(String),
}

/// A value with a canonical byte encoding.
pub trait Encode {
    /// Append the canonical encoding of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>);

    /// Convenience wrapper returning a fresh `Vec`.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// A value that can be reconstructed from its canonical encoding.
pub trait Decode: Sized {
    /// Consume exactly one value from `r`.
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError>;
}

/// Decode a value and require that the whole input was consumed.
///
/// Use this at trust boundaries (network, RPC, database). Accepting trailing
/// bytes would let an attacker produce two distinct byte strings that decode to
/// the same transaction, which breaks hash-based deduplication.
pub fn decode_exact<T: Decode>(bytes: &[u8]) -> Result<T, CodecError> {
    let mut r = Reader::new(bytes);
    let value = T::decode(&mut r)?;
    if !r.is_empty() {
        return Err(CodecError::TrailingBytes {
            left: r.remaining(),
        });
    }
    Ok(value)
}

/// A cursor over a byte slice with bounds-checked reads.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether the input is fully consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Take exactly `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(CodecError::LengthTooLarge { len: u32::MAX })?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(CodecError::UnexpectedEof {
                wanted: n,
                left: self.remaining(),
            })?;
        self.pos = end;
        Ok(slice)
    }

    /// Take exactly `N` bytes as a fixed-size array.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Read a length prefix, rejecting absurd values before allocating.
    pub fn take_len(&mut self) -> Result<usize, CodecError> {
        let len = u32::decode(self)?;
        if len > MAX_FIELD_LEN {
            return Err(CodecError::LengthTooLarge { len });
        }
        Ok(len as usize)
    }
}

macro_rules! impl_int_codec {
    ($($t:ty),* $(,)?) => {$(
        impl Encode for $t {
            fn encode(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_le_bytes());
            }
        }
        impl Decode for $t {
            fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
                Ok(<$t>::from_le_bytes(r.take_array::<{ size_of::<$t>() }>()?))
            }
        }
    )*};
}

impl_int_codec!(u8, u16, u32, u64, u128, i32, i64);

impl Encode for bool {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
}

impl Decode for bool {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(false),
            1 => Ok(true),
            // Rejecting 2..=255 keeps the encoding injective.
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "bool",
            }),
        }
    }
}

/// Encode a raw byte slice as a length-prefixed field.
///
/// This is the fast path for blobs. It is byte-for-byte identical to what the
/// generic `Vec<T>` impl produces for `Vec<u8>`, since a `u8` encodes as itself.
pub fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    debug_assert!(
        bytes.len() <= MAX_FIELD_LEN as usize,
        "field exceeds MAX_FIELD_LEN"
    );
    #[expect(
        clippy::cast_possible_truncation,
        reason = "callers stay under MAX_FIELD_LEN"
    )]
    let len = bytes.len() as u32;
    len.encode(out);
    out.extend_from_slice(bytes);
}

/// Decode a length-prefixed byte blob, bounds-checked against [`MAX_FIELD_LEN`].
pub fn decode_bytes(r: &mut Reader<'_>) -> Result<Vec<u8>, CodecError> {
    let len = r.take_len()?;
    Ok(r.take(len)?.to_vec())
}

impl Encode for str {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_bytes(self.as_bytes(), out);
    }
}

impl Encode for String {
    fn encode(&self, out: &mut Vec<u8>) {
        self.as_str().encode(out);
    }
}

impl Decode for String {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let bytes = decode_bytes(r)?;
        Self::from_utf8(bytes).map_err(|e| CodecError::Invalid(format!("non-utf8 string: {e}")))
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.encode(out);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(r)?)),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "Option",
            }),
        }
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        debug_assert!(
            self.len() <= MAX_FIELD_LEN as usize,
            "field exceeds MAX_FIELD_LEN"
        );
        #[expect(
            clippy::cast_possible_truncation,
            reason = "callers stay under MAX_FIELD_LEN"
        )]
        let len = self.len() as u32;
        len.encode(out);
        for item in self {
            item.encode(out);
        }
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let len = r.take_len()?;
        // Do not pre-allocate `len` elements: a peer can declare a large count
        // cheaply, and each element still has to be present in the buffer.
        let mut out = Self::new();
        for _ in 0..len {
            out.push(T::decode(r)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_little_endian() {
        let mut out = Vec::new();
        1u32.encode(&mut out);
        assert_eq!(out, vec![1, 0, 0, 0], "must be little-endian");
        assert_eq!(decode_exact::<u32>(&out), Ok(1));
    }

    #[test]
    fn strings_and_bytes_round_trip() {
        let s = "kesi".to_owned();
        assert_eq!(decode_exact::<String>(&s.to_bytes()), Ok(s));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = 7u64.to_bytes();
        bytes.push(0xFF);
        assert_eq!(
            decode_exact::<u64>(&bytes),
            Err(CodecError::TrailingBytes { left: 1 })
        );
    }

    #[test]
    fn bool_encoding_is_injective() {
        // 0x02 must not silently decode as `true`, or two byte strings would
        // hash differently while representing the same transaction.
        assert!(decode_exact::<bool>(&[2]).is_err());
    }

    #[test]
    fn forged_length_prefix_does_not_allocate() {
        // u32::MAX length prefix with no payload: must error, not try to allocate 4 GiB.
        let bytes = u32::MAX.to_le_bytes();
        assert_eq!(
            decode_exact::<Vec<u8>>(&bytes),
            Err(CodecError::LengthTooLarge { len: u32::MAX })
        );
    }

    #[test]
    fn truncated_input_errors_cleanly() {
        assert!(matches!(
            decode_exact::<u64>(&[1, 2, 3]),
            Err(CodecError::UnexpectedEof { .. })
        ));
    }
}
