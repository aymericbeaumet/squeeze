use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Uuid {}

impl Uuid {
    fn is_hex(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }

    fn check_pattern(input: &[u8], start: usize) -> bool {
        if start + 36 > input.len() {
            return false;
        }
        let groups = [8, 4, 4, 4, 12];
        let mut pos = start;
        for (i, &len) in groups.iter().enumerate() {
            if i > 0 {
                if input[pos] != b'-' {
                    return false;
                }
                pos += 1;
            }
            for _ in 0..len {
                if !Self::is_hex(input[pos]) {
                    return false;
                }
                pos += 1;
            }
        }
        true
    }
}

impl Finder for Uuid {
    fn id(&self) -> &'static str {
        "uuid"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        byte.is_ascii_hexdigit()
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
        assert!(finder
            .find("550e840-0e29b-41d4-a716-446655440000")
            .is_none());
    }

    #[test]
    fn find_should_reject_too_short() {
        let finder = Uuid::default();
        assert!(finder.find("550e8400-e29b-41d4-a716").is_none());
    }

    #[test]
    fn find_should_reject_non_hex() {
        let finder = Uuid::default();
        assert!(finder
            .find("550e8400-e29b-41d4-a716-44665544000g")
            .is_none());
    }

    #[test]
    fn find_should_not_match_within_longer_hex() {
        let finder = Uuid::default();
        assert!(finder
            .find("ff550e8400-e29b-41d4-a716-446655440000")
            .is_none());
    }

    #[test]
    fn find_should_not_match_with_trailing_hex() {
        let finder = Uuid::default();
        assert!(finder
            .find("550e8400-e29b-41d4-a716-446655440000ff")
            .is_none());
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
        assert!(finder
            .find("550e8400-e29b-41d4-a716-446655440000-")
            .is_none());
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
