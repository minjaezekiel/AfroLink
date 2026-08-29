//! Usernames, and the confusable folding that keeps two of them from looking
//! alike.
//!
//! # Why this is strict
//!
//! A username is a payment destination. If two names can be rendered so that a
//! human cannot tell them apart, someone loses money — and unlike a mistyped
//! bech32 address, a lookalike name *resolves successfully* and the transfer
//! goes through to the wrong person.
//!
//! ENS demonstrates the failure at scale. Its normalisation is complex enough
//! that different clients have resolved the same displayed name to different
//! addresses, which is the subject of published research (ACM Web Conference
//! 2025). The complexity comes from admitting the whole of Unicode.
//!
//! So this module does not attempt to *detect* confusable names. It refuses the
//! conditions that make them possible:
//!
//! 1. **ASCII only.** Cyrillic `а`, Greek `ο` and the several hundred other
//!    Latin lookalikes cannot be typed into a name at all.
//! 2. **A skeleton index.** Within ASCII, `0`/`o` and `rn`/`m` are still
//!    confusable in most fonts. Each name folds to a skeleton, and a
//!    registration is refused when its skeleton is already taken.
//!
//! # The cost, stated plainly
//!
//! No Swahili, Amharic, Arabic or Tifinagh script in a username. For a project
//! whose [ADR-0005](../../../docs/adr/0005-african-first-design.md) rejects
//! ported Western assumptions, that deserves discomfort rather than a shrug.
//!
//! The line ADR-0005 draws is that a market assumption is a design choice about
//! a context, while a mathematical primitive is not. Homoglyph confusability is
//! a property of Unicode's code-point space, not an assumption about who is
//! using it — and the people who would be harmed by a lookalike payment name are
//! exactly the users this chain exists for. Local scripts belong in a wallet's
//! address book, where the user has already confirmed who they are paying, not
//! in the globally-resolvable identifier.

use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use thiserror::Error;

/// Shortest permitted username.
pub const MIN_NAME_LEN: usize = 3;
/// Longest permitted username.
pub const MAX_NAME_LEN: usize = 32;

/// Why a username was rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NameError {
    /// Outside [`MIN_NAME_LEN`]..=[`MAX_NAME_LEN`].
    #[error("username must be {MIN_NAME_LEN}..={MAX_NAME_LEN} characters, got {0}")]
    Length(usize),
    /// Contained a byte outside `[a-z0-9_-]`.
    #[error("username may only contain a-z, 0-9, '-' and '_'; found {0:?}")]
    Charset(char),
    /// Contained a non-ASCII character.
    ///
    /// Separate from [`Self::Charset`] because it is the security-relevant case
    /// and deserves its own message in a wallet.
    #[error(
        "username must be ASCII; {0:?} is not, and lookalike scripts are how people get robbed"
    )]
    NotAscii(char),
    /// Began or ended with a separator.
    #[error("username must start and end with a letter or digit")]
    EdgeSeparator,
    /// Two separators in a row.
    #[error("username must not contain consecutive separators")]
    DoubleSeparator,
    /// Reserved by the protocol or by governance.
    #[error("username {0:?} is reserved")]
    Reserved(String),
}

/// Names nobody may register.
///
/// The point is impersonation, not tidiness: `@sov` or `@ke` next to a sovereign
/// stablecoin denomination would be read as official by exactly the users least
/// equipped to check. Governance can extend this list; it cannot shrink it
/// below these entries.
const RESERVED: &[&str] = &[
    "afri",
    "afrolink",
    "sov",
    "admin",
    "root",
    "support",
    "official",
    "treasury",
    "validator",
    "genesis",
];

/// Multi-character confusable pairs, applied before single characters.
///
/// Order matters: `rn` must fold to `m` before `r` and `n` are considered
/// individually, or the pair is never seen.
const DIGRAPHS: &[(&str, &str)] = &[("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")];

/// A validated, canonical username.
///
/// Construction is the only way to obtain one, so a `Username` in hand has
/// already passed every rule in this module.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Username(String);

impl Username {
    /// Validate and canonicalise a username.
    ///
    /// Input is lowercased first, so `Amina` and `amina` are the same name
    /// rather than two names that look identical when a wallet renders them.
    ///
    /// # Errors
    /// Returns the first [`NameError`] found.
    pub fn new(input: &str) -> Result<Self, NameError> {
        let lowered = input.to_lowercase();

        // Length is checked in characters, not bytes. They are equal for valid
        // input, but a rejected non-ASCII name should report a sensible number.
        let char_count = lowered.chars().count();
        if !(MIN_NAME_LEN..=MAX_NAME_LEN).contains(&char_count) {
            return Err(NameError::Length(char_count));
        }

        for c in lowered.chars() {
            if !c.is_ascii() {
                return Err(NameError::NotAscii(c));
            }
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
                return Err(NameError::Charset(c));
            }
        }

        let is_separator = |c: char| c == '-' || c == '_';
        let first = lowered.chars().next().ok_or(NameError::Length(0))?;
        let last = lowered.chars().next_back().ok_or(NameError::Length(0))?;
        if is_separator(first) || is_separator(last) {
            return Err(NameError::EdgeSeparator);
        }

        let mut previous_was_separator = false;
        for c in lowered.chars() {
            let separator = is_separator(c);
            if separator && previous_was_separator {
                return Err(NameError::DoubleSeparator);
            }
            previous_was_separator = separator;
        }

        if RESERVED.contains(&lowered.as_str()) || is_country_code(&lowered) {
            return Err(NameError::Reserved(lowered));
        }

        Ok(Self(lowered))
    }

    /// The canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The confusable-folded form used to detect lookalikes.
    ///
    /// Two names with the same skeleton may be indistinguishable on a small
    /// screen, so at most one of them may exist.
    #[must_use]
    pub fn skeleton(&self) -> Skeleton {
        let mut s = self.0.clone();

        for (from, to) in DIGRAPHS {
            s = s.replace(from, to);
        }

        let folded: String = s
            .chars()
            .filter(|c| *c != '-' && *c != '_')
            .map(|c| match c {
                '0' => 'o',
                '1' | 'i' | '!' | '|' => 'l',
                '5' => 's',
                '2' => 'z',
                '8' => 'b',
                other => other,
            })
            .collect();

        Skeleton(folded)
    }
}

impl core::fmt::Display for Username {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "@{}", self.0)
    }
}

/// The confusable-folded form of a username.
///
/// Only ever used as an index key. It is not a name and cannot be registered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Skeleton(String);

impl Skeleton {
    /// The folded string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether a name is a two-letter code that could be read as a country.
///
/// Rejecting all two-letter names is simpler and safer than maintaining the ISO
/// 3166 list, and [`MIN_NAME_LEN`] already excludes them — this is the belt to
/// that braces, so a future relaxation of the length rule cannot quietly open
/// `@ke` for registration.
fn is_country_code(name: &str) -> bool {
    name.len() == 2 && name.chars().all(|c| c.is_ascii_lowercase())
}

impl Encode for Username {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for Username {
    /// Re-validates on the way in.
    ///
    /// A username arrives inside a transaction from an untrusted peer, so the
    /// rules are enforced at the decode boundary rather than trusted to have
    /// been applied by whoever built the message. Without this, a hand-rolled
    /// transaction could carry a Cyrillic name straight past every check in
    /// this module.
    fn decode(r: &mut Reader<'_>) -> core::result::Result<Self, CodecError> {
        Self::new(&String::decode(r)?).map_err(|e| CodecError::Invalid(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_primitives::codec::decode_exact;

    #[test]
    fn ordinary_names_are_accepted() {
        for name in ["amina", "kwame_ke", "chama-ya-soweto", "shop254", "abc"] {
            assert!(Username::new(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn a_name_is_canonicalised_to_lowercase() {
        // Otherwise @Amina and @amina are different destinations that render
        // identically in a wallet that title-cases its display.
        let upper = Username::new("AMINA").expect("valid");
        let lower = Username::new("amina").expect("valid");
        assert_eq!(upper, lower);
        assert_eq!(upper.as_str(), "amina");
    }

    #[test]
    fn a_non_ascii_name_is_rejected() {
        // Cyrillic 'а' (U+0430) is visually identical to Latin 'a' in nearly
        // every font. This is the attack the ASCII rule exists for.
        let cyrillic = "\u{430}mina";
        assert!(matches!(
            Username::new(cyrillic),
            Err(NameError::NotAscii(_))
        ));

        for name in ["amïna", "аmina", "阿米娜", "أمينة"] {
            assert!(
                matches!(Username::new(name), Err(NameError::NotAscii(_))),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn confusable_names_share_a_skeleton() {
        // The whole point of the index: each of these renders close enough to
        // "amina" to fool someone, so at most one may be registered.
        let target = Username::new("amina").expect("valid").skeleton();

        for lookalike in ["arnina", "am1na", "am-ina", "am_ina", "amlna"] {
            assert_eq!(
                Username::new(lookalike).expect("valid").skeleton(),
                target,
                "{lookalike} must fold to the same skeleton as amina"
            );
        }
    }

    #[test]
    fn genuinely_different_names_do_not_collide() {
        // A skeleton that folds too aggressively would lock legitimate users
        // out of the namespace, which is its own kind of failure.
        let names = ["amina", "kwame", "thabo", "chidi", "fatou", "shop254"];
        for (i, a) in names.iter().enumerate() {
            for b in names.iter().skip(i.saturating_add(1)) {
                assert_ne!(
                    Username::new(a).expect("valid").skeleton(),
                    Username::new(b).expect("valid").skeleton(),
                    "{a} and {b} must not collide"
                );
            }
        }
    }

    #[test]
    fn digraphs_fold_before_single_characters() {
        // If 'rn' were not handled first, "arnina" would keep both letters and
        // never match "amina". The trailing 'i' then folds to 'l' like every
        // other i/1/l, which is why the skeleton is "amlna" rather than "amina"
        // — a skeleton is an index key, not a readable name.
        assert_eq!(
            Username::new("arnina").expect("valid").skeleton().as_str(),
            "amlna"
        );
        assert_eq!(
            Username::new("amina").expect("valid").skeleton().as_str(),
            "amlna",
            "and it must agree with the name it protects"
        );
        assert_eq!(
            Username::new("vvater").expect("valid").skeleton().as_str(),
            "water"
        );
    }

    #[test]
    fn reserved_names_cannot_be_registered() {
        for name in ["afri", "afrolink", "sov", "treasury", "official", "AFRI"] {
            assert!(
                matches!(Username::new(name), Err(NameError::Reserved(_))),
                "{name} must be reserved"
            );
        }
    }

    #[test]
    fn separator_placement_is_constrained() {
        assert_eq!(Username::new("-amina"), Err(NameError::EdgeSeparator));
        assert_eq!(Username::new("amina_"), Err(NameError::EdgeSeparator));
        assert_eq!(Username::new("am--ina"), Err(NameError::DoubleSeparator));
        assert_eq!(Username::new("am-_ina"), Err(NameError::DoubleSeparator));
    }

    #[test]
    fn length_bounds_are_enforced() {
        assert_eq!(Username::new("ab"), Err(NameError::Length(2)));
        assert!(Username::new(&"a".repeat(MAX_NAME_LEN)).is_ok());
        assert_eq!(
            Username::new(&"a".repeat(MAX_NAME_LEN + 1)),
            Err(NameError::Length(MAX_NAME_LEN + 1))
        );
    }

    #[test]
    fn punctuation_and_spaces_are_rejected() {
        for name in ["am ina", "am.ina", "am/ina", "am@ina", "am+ina"] {
            assert!(
                matches!(Username::new(name), Err(NameError::Charset(_))),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn a_two_letter_name_can_never_impersonate_a_country() {
        // Length already excludes these; this asserts the second guard, so
        // relaxing MIN_NAME_LEN later cannot silently open @ke or @ng.
        assert!(is_country_code("ke"));
        assert!(is_country_code("ng"));
        assert!(!is_country_code("ken"));
    }

    #[test]
    fn a_name_displays_with_its_sigil() {
        assert_eq!(Username::new("amina").expect("valid").to_string(), "@amina");
    }

    #[test]
    fn names_round_trip_through_the_wire_format() {
        let name = Username::new("amina").expect("valid");
        assert_eq!(decode_exact::<Username>(&name.to_bytes()), Ok(name));
    }

    #[test]
    fn a_hand_rolled_transaction_cannot_smuggle_an_invalid_name() {
        // Validation must live at the decode boundary, not only in the
        // constructor a well-behaved wallet happens to call.
        for smuggled in ["\u{430}mina", "am ina", "afri", "ab", "-amina"] {
            let mut bytes = Vec::new();
            smuggled.to_owned().encode(&mut bytes);
            assert!(
                decode_exact::<Username>(&bytes).is_err(),
                "{smuggled:?} must be rejected on decode"
            );
        }
    }
}
