use super::{Anchor, ByteSet, Finder, RunClass, RunRule};
use std::ops::Range;

#[derive(Default)]
pub struct Uuid {}

impl Uuid {
    fn is_hex(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }

    /// Whether the 36 bytes at `start` are `8-4-4-4-12` hex groups.
    fn check_pattern(input: &[u8], start: usize) -> bool {
        let Some(bytes) = input.get(start..start + 36) else {
            return false;
        };
        let bytes: &[u8; 36] = bytes.try_into().expect("36 bytes");
        #[cfg(target_arch = "aarch64")]
        {
            Self::check_pattern_neon(bytes)
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            Self::check_pattern_scalar(bytes)
        }
    }

    #[cfg(any(test, not(target_arch = "aarch64")))]
    fn check_pattern_scalar(bytes: &[u8; 36]) -> bool {
        bytes.iter().enumerate().all(|(i, &b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => Self::is_hex(b),
        })
    }

    /// The same test on two 16-byte vectors and a 4-byte tail: every byte
    /// is a hex digit except the dashes at 8, 13, 18 and 23.
    #[cfg(target_arch = "aarch64")]
    fn check_pattern_neon(bytes: &[u8; 36]) -> bool {
        use core::arch::aarch64::*;
        // Dash positions within each 16-byte block: 8, 13 | 18, 23.
        const DASHES_LO: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0, 0xFF, 0, 0];
        const DASHES_HI: [u8; 16] = [0, 0, 0xFF, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0];
        // SAFETY: NEON is part of the aarch64 baseline; the loads read 16
        // bytes at offsets 0 and 16 of a 36-byte array.
        unsafe {
            let hex_ok = |v: uint8x16_t| -> uint8x16_t {
                let digit = vcltq_u8(vsubq_u8(v, vdupq_n_u8(b'0')), vdupq_n_u8(10));
                let lower = vorrq_u8(v, vdupq_n_u8(0x20));
                let alpha = vcltq_u8(vsubq_u8(lower, vdupq_n_u8(b'a')), vdupq_n_u8(6));
                vorrq_u8(digit, alpha)
            };
            let check = |v: uint8x16_t, dashes: uint8x16_t| -> bool {
                let is_dash = vceqq_u8(v, vdupq_n_u8(b'-'));
                // Dash lanes must be dashes, the others hex digits.
                let ok = vbslq_u8(dashes, is_dash, hex_ok(v));
                vminvq_u8(ok) == 0xFF
            };
            let lo = vld1q_u8(bytes.as_ptr());
            let hi = vld1q_u8(bytes.as_ptr().add(16));
            check(lo, vld1q_u8(DASHES_LO.as_ptr()))
                && check(hi, vld1q_u8(DASHES_HI.as_ptr()))
                && bytes[32..36].iter().all(|&b| Self::is_hex(b))
        }
    }
}

impl Finder for Uuid {
    fn line_agnostic(&self) -> bool {
        // Matches never contain a line terminator and `\n`/`\r` end every
        // walk exactly like the end of the input does.
        true
    }

    fn id(&self) -> &'static str {
        "uuid"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        byte.is_ascii_hexdigit()
    }

    fn could_start_after(&self, prev: u8, _cur: u8) -> bool {
        !(Self::is_hex(prev) || prev == b'-')
    }

    fn could_continue_with(&self, _cur: u8, next: u8) -> bool {
        Self::is_hex(next)
    }

    fn anchor(&self) -> Option<Anchor> {
        // The first dash sits at offset 8, the second at 13.
        Some(
            Anchor::new(
                ByteSet::from_bytes(b"-"),
                ByteSet::from_fn(|b| b.is_ascii_hexdigit()),
            )
            .confirm(b"-", &[5], b"-")
            .back(8),
        )
    }

    fn run_rules(&self) -> Vec<RunRule> {
        // `xxxxxxxx-xxxx-xxxx-`.
        vec![
            RunRule::new(RunClass::Hex, 8, 8)
                .followed_by(b"-")
                .then(RunClass::Hex, 4, 4)
                .followed_by(b"-")
                .then(RunClass::Hex, 4, 4)
                .followed_by(b"-"),
        ]
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        if !Self::is_hex(input[pos]) {
            return None;
        }
        if pos > 0 && (Self::is_hex(input[pos - 1]) || input[pos - 1] == b'-') {
            return None;
        }
        if !Self::check_pattern(input, pos) {
            return None;
        }
        let end = pos + 36;
        if end < input.len() && (Self::is_hex(input[end]) || input[end] == b'-') {
            return None;
        }
        Some(pos..end)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx + 36 <= input.len() {
            if Self::is_hex(input[idx]) {
                if idx > 0 && (Self::is_hex(input[idx - 1]) || input[idx - 1] == b'-') {
                    idx += 1;
                    continue;
                }

                if Self::check_pattern(input, idx) {
                    let end = idx + 36;
                    if end < input.len() && (Self::is_hex(input[end]) || input[end] == b'-') {
                        idx += 1;
                        continue;
                    }
                    return Some(idx..end);
                }
            }
            idx += 1;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_uuid() {
        let finder = Uuid::default();
        assert_eq!("uuid", finder.id());
    }

    #[test]
    fn find_should_extract_uuid() {
        let finder = Uuid::default();
        let input = "id: 550e8400-e29b-41d4-a716-446655440000";
        let range = finder.find(input).unwrap();
        assert_eq!("550e8400-e29b-41d4-a716-446655440000", &input[range]);
    }

    #[test]
    fn find_should_extract_uuid_at_start() {
        let finder = Uuid::default();
        let input = "550e8400-e29b-41d4-a716-446655440000 is the id";
        let range = finder.find(input).unwrap();
        assert_eq!("550e8400-e29b-41d4-a716-446655440000", &input[range]);
    }

    #[test]
    fn find_should_extract_uppercase_uuid() {
        let finder = Uuid::default();
        let input = "550E8400-E29B-41D4-A716-446655440000";
        let range = finder.find(input).unwrap();
        assert_eq!("550E8400-E29B-41D4-A716-446655440000", &input[range]);
    }

    #[test]
    fn find_should_extract_mixed_case_uuid() {
        let finder = Uuid::default();
        let input = "550e8400-E29B-41d4-A716-446655440000";
        let range = finder.find(input).unwrap();
        assert_eq!("550e8400-E29B-41d4-A716-446655440000", &input[range]);
    }

    #[test]
    fn find_should_reject_no_dashes() {
        let finder = Uuid::default();
        assert!(finder.find("550e8400e29b41d4a716446655440000").is_none());
    }

    #[test]
    fn find_should_reject_wrong_dash_positions() {
        let finder = Uuid::default();
        assert!(
            finder
                .find("550e840-0e29b-41d4-a716-446655440000")
                .is_none()
        );
    }

    #[test]
    fn find_should_reject_too_short() {
        let finder = Uuid::default();
        assert!(finder.find("550e8400-e29b-41d4-a716").is_none());
    }

    #[test]
    fn find_should_reject_non_hex() {
        let finder = Uuid::default();
        assert!(
            finder
                .find("550e8400-e29b-41d4-a716-44665544000g")
                .is_none()
        );
    }

    #[test]
    fn find_should_not_match_within_longer_hex() {
        let finder = Uuid::default();
        assert!(
            finder
                .find("ff550e8400-e29b-41d4-a716-446655440000")
                .is_none()
        );
    }

    #[test]
    fn find_should_not_match_with_trailing_hex() {
        let finder = Uuid::default();
        assert!(
            finder
                .find("550e8400-e29b-41d4-a716-446655440000ff")
                .is_none()
        );
    }

    #[test]
    fn find_should_extract_uuid_in_brackets() {
        let finder = Uuid::default();
        let input = "[550e8400-e29b-41d4-a716-446655440000]";
        let range = finder.find(input).unwrap();
        assert_eq!("550e8400-e29b-41d4-a716-446655440000", &input[range]);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Uuid::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_multiple_uuids_iteratively() {
        let finder = Uuid::default();
        let input = "550e8400-e29b-41d4-a716-446655440000 and 6ba7b810-9dad-11d1-80b4-00c04fd430c8";

        let mut results = Vec::new();
        let mut idx = 0;
        while idx < input.len() {
            if let Some(range) = finder.find(&input[idx..]) {
                results.push(&input[idx + range.start..idx + range.end]);
                idx += range.end;
            } else {
                break;
            }
        }

        assert_eq!(
            vec![
                "550e8400-e29b-41d4-a716-446655440000",
                "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
            ],
            results
        );
    }

    #[test]
    fn find_should_extract_nil_uuid() {
        let finder = Uuid::default();
        let input = "00000000-0000-0000-0000-000000000000";
        let range = finder.find(input).unwrap();
        assert_eq!("00000000-0000-0000-0000-000000000000", &input[range]);
    }

    #[test]
    fn try_at_at_start() {
        let finder = Uuid::default();
        let input = b"550e8400-e29b-41d4-a716-446655440000 end";
        assert_eq!(finder.try_at(input, 0), Some(0..36));
    }

    #[test]
    fn try_at_preceded_by_hex() {
        let finder = Uuid::default();
        let input = b"ff550e8400-e29b-41d4-a716-446655440000";
        assert!(finder.try_at(input, 2).is_none());
    }

    #[test]
    fn try_at_preceded_by_dash() {
        let finder = Uuid::default();
        let input = b"-550e8400-e29b-41d4-a716-446655440000";
        assert!(finder.try_at(input, 1).is_none());
    }

    #[test]
    fn try_at_too_short_input() {
        let finder = Uuid::default();
        let input = b"550e8400";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn find_should_reject_extra_dash_at_end() {
        let finder = Uuid::default();
        assert!(
            finder
                .find("550e8400-e29b-41d4-a716-446655440000-")
                .is_none()
        );
    }

    #[test]
    fn find_should_handle_uuid_at_exact_end() {
        let finder = Uuid::default();
        let input = "x 550e8400-e29b-41d4-a716-446655440000";
        let range = finder.find(input).unwrap();
        assert_eq!("550e8400-e29b-41d4-a716-446655440000", &input[range]);
    }

    #[test]
    fn find_should_handle_input_shorter_than_uuid() {
        let finder = Uuid::default();
        assert!(finder.find("abc").is_none());
        assert!(finder.find("a").is_none());
    }
}

#[cfg(test)]
mod pattern_tests {
    use super::Uuid;

    #[test]
    fn vector_pattern_check_agrees_with_the_scalar_one() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet = b"0123456789abcdefABCDEF-gG/ :";
        for round in 0..20_000 {
            let mut bytes = *b"550e8400-e29b-41d4-a716-446655440000";
            // Mostly valid UUIDs with a few bytes disturbed.
            let flips = round % 4;
            for _ in 0..flips {
                let at = (next() % 36) as usize;
                bytes[at] = alphabet[(next() % alphabet.len() as u64) as usize];
            }
            let input = bytes.to_vec();
            assert_eq!(
                Uuid::check_pattern(&input, 0),
                Uuid::check_pattern_scalar(&bytes),
                "{}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }
}
