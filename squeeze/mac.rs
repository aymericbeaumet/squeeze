use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Mac {}

impl Mac {
    fn is_hex(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }

    fn try_mac_colon(input: &[u8], idx: usize) -> Option<Range<usize>> {
        // AA:BB:CC:DD:EE:FF (17 chars)
        Self::try_mac_separated(input, idx, b':')
    }

    fn try_mac_dash(input: &[u8], idx: usize) -> Option<Range<usize>> {
        // AA-BB-CC-DD-EE-FF (17 chars)
        Self::try_mac_separated(input, idx, b'-')
    }

    fn try_mac_separated(input: &[u8], idx: usize, sep: u8) -> Option<Range<usize>> {
        if idx + 17 > input.len() {
            return None;
        }

        for group in 0..6 {
            let pos = idx + group * 3;
            if group > 0 && input[pos - 1] != sep {
                return None;
            }
            if !Self::is_hex(input[pos]) || !Self::is_hex(input[pos + 1]) {
                return None;
            }
        }

        let end = idx + 17;

        // Boundary after: not followed by hex digit or separator
        if end < input.len() && (Self::is_hex(input[end]) || input[end] == sep) {
            return None;
        }

        Some(idx..end)
    }

    fn try_mac_dot(input: &[u8], idx: usize) -> Option<Range<usize>> {
        // AABB.CCDD.EEFF (14 chars)
        if idx + 14 > input.len() {
            return None;
        }

        for group in 0..3 {
            let pos = idx + group * 5;
            if group > 0 && input[pos - 1] != b'.' {
                return None;
            }
            for i in 0..4 {
                if !Self::is_hex(input[pos + i]) {
                    return None;
                }
            }
        }

        let end = idx + 14;

        // Boundary after: not followed by hex digit or dot
        if end < input.len() && (Self::is_hex(input[end]) || input[end] == b'.') {
            return None;
        }

        Some(idx..end)
    }
}

impl Finder for Mac {
    fn id(&self) -> &'static str {
        "mac"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            if Self::is_hex(input[idx]) {
                // Boundary before: not preceded by hex digit, colon, dash, or dot
                if idx > 0
                    && (Self::is_hex(input[idx - 1])
                        || input[idx - 1] == b':'
                        || input[idx - 1] == b'-'
                        || input[idx - 1] == b'.')
                {
                    idx += 1;
                    continue;
                }

                if let Some(range) = Self::try_mac_colon(input, idx) {
                    return Some(range);
                }
                if let Some(range) = Self::try_mac_dash(input, idx) {
                    return Some(range);
                }
                if let Some(range) = Self::try_mac_dot(input, idx) {
                    return Some(range);
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
    fn id_should_return_mac() {
        let finder = Mac::default();
        assert_eq!("mac", finder.id());
    }

    #[test]
    fn find_should_extract_colon_separated() {
        let finder = Mac::default();
        let input = "interface: 00:1A:2B:3C:4D:5E";
        let range = finder.find(input).unwrap();
        assert_eq!("00:1A:2B:3C:4D:5E", &input[range]);
    }

    #[test]
    fn find_should_extract_dash_separated() {
        let finder = Mac::default();
        let input = "interface: 00-1A-2B-3C-4D-5E";
        let range = finder.find(input).unwrap();
        assert_eq!("00-1A-2B-3C-4D-5E", &input[range]);
    }

    #[test]
    fn find_should_extract_dot_separated() {
        let finder = Mac::default();
        let input = "interface: 001A.2B3C.4D5E";
        let range = finder.find(input).unwrap();
        assert_eq!("001A.2B3C.4D5E", &input[range]);
    }

    #[test]
    fn find_should_extract_lowercase() {
        let finder = Mac::default();
        let input = "aa:bb:cc:dd:ee:ff";
        let range = finder.find(input).unwrap();
        assert_eq!("aa:bb:cc:dd:ee:ff", &input[range]);
    }

    #[test]
    fn find_should_extract_uppercase() {
        let finder = Mac::default();
        let input = "AA:BB:CC:DD:EE:FF";
        let range = finder.find(input).unwrap();
        assert_eq!("AA:BB:CC:DD:EE:FF", &input[range]);
    }

    #[test]
    fn find_should_extract_mac_in_text() {
        let finder = Mac::default();
        let input = "device 00:1A:2B:3C:4D:5E connected";
        let range = finder.find(input).unwrap();
        assert_eq!("00:1A:2B:3C:4D:5E", &input[range]);
    }

    #[test]
    fn find_should_extract_mac_at_start() {
        let finder = Mac::default();
        let input = "00:1A:2B:3C:4D:5E is the address";
        let range = finder.find(input).unwrap();
        assert_eq!("00:1A:2B:3C:4D:5E", &input[range]);
    }

    #[test]
    fn find_should_reject_too_short() {
        let finder = Mac::default();
        assert!(finder.find("00:1A:2B:3C:4D").is_none());
    }

    #[test]
    fn find_should_reject_non_hex() {
        let finder = Mac::default();
        assert!(finder.find("00:1A:2B:3C:4D:5G").is_none());
    }

    #[test]
    fn find_should_reject_mixed_separators() {
        let finder = Mac::default();
        assert!(finder.find("00:1A-2B:3C-4D:5E").is_none());
    }

    #[test]
    fn find_should_not_match_within_longer_hex() {
        let finder = Mac::default();
        assert!(finder.find("ff00:1A:2B:3C:4D:5E").is_none());
    }

    #[test]
    fn find_should_not_match_with_trailing_hex() {
        let finder = Mac::default();
        assert!(finder.find("00:1A:2B:3C:4D:5Eff").is_none());
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Mac::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_multiple_macs_iteratively() {
        let finder = Mac::default();
        let input = "00:1A:2B:3C:4D:5E and AA:BB:CC:DD:EE:FF";

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

        assert_eq!(vec!["00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF"], results);
    }

    #[test]
    fn find_should_extract_broadcast_mac() {
        let finder = Mac::default();
        let input = "FF:FF:FF:FF:FF:FF";
        let range = finder.find(input).unwrap();
        assert_eq!("FF:FF:FF:FF:FF:FF", &input[range]);
    }

    #[test]
    fn find_should_extract_zero_mac() {
        let finder = Mac::default();
        let input = "00:00:00:00:00:00";
        let range = finder.find(input).unwrap();
        assert_eq!("00:00:00:00:00:00", &input[range]);
    }
}
