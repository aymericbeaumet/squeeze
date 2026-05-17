use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Semver {}

impl Semver {
    fn is_boundary_before(input: &[u8], pos: usize) -> bool {
        if pos == 0 {
            return true;
        }
        let b = input[pos - 1];
        !b.is_ascii_alphanumeric() && b != b'.'
    }

    fn is_boundary_after(input: &[u8], pos: usize) -> bool {
        if pos >= input.len() {
            return true;
        }
        let b = input[pos];
        !b.is_ascii_alphanumeric() && b != b'.' && b != b'-' && b != b'+'
    }

    fn parse_digits(input: &[u8], pos: usize) -> Option<usize> {
        if pos >= input.len() || !input[pos].is_ascii_digit() {
            return None;
        }
        let mut end = pos + 1;
        while end < input.len() && input[end].is_ascii_digit() {
            end += 1;
        }
        Some(end)
    }

    fn parse_prerelease_or_build(input: &[u8], pos: usize) -> usize {
        let mut end = pos;
        while end < input.len()
            && (input[end].is_ascii_alphanumeric() || input[end] == b'-' || input[end] == b'.')
        {
            end += 1;
        }
        // Don't end on a dot
        while end > pos && input[end - 1] == b'.' {
            end -= 1;
        }
        end
    }
}

impl Finder for Semver {
    fn id(&self) -> &'static str {
        "semver"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            let start = idx;
            let mut pos = idx;

            // Optional v/V prefix
            if pos < input.len() && (input[pos] == b'v' || input[pos] == b'V') {
                if pos + 1 < input.len() && input[pos + 1].is_ascii_digit() {
                    pos += 1;
                } else {
                    idx += 1;
                    continue;
                }
            } else if pos < input.len() && input[pos].is_ascii_digit() {
                // ok
            } else {
                idx += 1;
                continue;
            }

            if !Self::is_boundary_before(input, start) {
                idx += 1;
                continue;
            }

            // MAJOR
            let major_end = match Self::parse_digits(input, pos) {
                Some(e) => e,
                None => {
                    idx += 1;
                    continue;
                }
            };

            // .MINOR
            if major_end >= input.len() || input[major_end] != b'.' {
                idx += 1;
                continue;
            }
            let minor_end = match Self::parse_digits(input, major_end + 1) {
                Some(e) => e,
                None => {
                    idx += 1;
                    continue;
                }
            };

            // .PATCH
            if minor_end >= input.len() || input[minor_end] != b'.' {
                idx += 1;
                continue;
            }
            let patch_end = match Self::parse_digits(input, minor_end + 1) {
                Some(e) => e,
                None => {
                    idx += 1;
                    continue;
                }
            };

            let mut end = patch_end;

            // Optional -prerelease
            if end < input.len() && input[end] == b'-' {
                let pre_end = Self::parse_prerelease_or_build(input, end + 1);
                if pre_end > end + 1 {
                    end = pre_end;
                }
            }

            // Optional +buildmeta
            if end < input.len() && input[end] == b'+' {
                let build_end = Self::parse_prerelease_or_build(input, end + 1);
                if build_end > end + 1 {
                    end = build_end;
                }
            }

            if Self::is_boundary_after(input, end) {
                return Some(start..end);
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
    fn id_should_return_semver() {
        let finder = Semver::default();
        assert_eq!("semver", finder.id());
    }

    #[test]
    fn find_should_extract_simple_version() {
        let finder = Semver::default();
        let input = "version 1.0.0 released";
        let range = finder.find(input).unwrap();
        assert_eq!("1.0.0", &input[range]);
    }

    #[test]
    fn find_should_extract_version_with_v_prefix() {
        let finder = Semver::default();
        let input = "tag v2.3.1 created";
        let range = finder.find(input).unwrap();
        assert_eq!("v2.3.1", &input[range]);
    }

    #[test]
    fn find_should_extract_version_with_uppercase_v() {
        let finder = Semver::default();
        let input = "V1.0.0";
        let range = finder.find(input).unwrap();
        assert_eq!("V1.0.0", &input[range]);
    }

    #[test]
    fn find_should_extract_version_with_prerelease() {
        let finder = Semver::default();
        let input = "v1.0.0-rc.1 is out";
        let range = finder.find(input).unwrap();
        assert_eq!("v1.0.0-rc.1", &input[range]);
    }

    #[test]
    fn find_should_extract_version_with_build_meta() {
        let finder = Semver::default();
        let input = "1.0.0+build.42";
        let range = finder.find(input).unwrap();
        assert_eq!("1.0.0+build.42", &input[range]);
    }

    #[test]
    fn find_should_extract_version_with_prerelease_and_build() {
        let finder = Semver::default();
        let input = "v2.0.0-alpha.1+build.123";
        let range = finder.find(input).unwrap();
        assert_eq!("v2.0.0-alpha.1+build.123", &input[range]);
    }

    #[test]
    fn find_should_extract_version_with_large_numbers() {
        let finder = Semver::default();
        let input = "100.200.300";
        let range = finder.find(input).unwrap();
        assert_eq!("100.200.300", &input[range]);
    }

    #[test]
    fn find_should_extract_version_with_zeros() {
        let finder = Semver::default();
        let input = "0.0.0";
        let range = finder.find(input).unwrap();
        assert_eq!("0.0.0", &input[range]);
    }

    #[test]
    fn find_should_reject_two_components() {
        let finder = Semver::default();
        assert!(finder.find("1.0 only").is_none());
    }

    #[test]
    fn find_should_reject_four_components() {
        let finder = Semver::default();
        assert!(finder.find("1.0.0.0 too many").is_none());
    }

    #[test]
    fn find_should_reject_preceded_by_alphanumeric() {
        let finder = Semver::default();
        assert!(finder.find("a1.0.0").is_none());
    }

    #[test]
    fn find_should_reject_preceded_by_dot() {
        let finder = Semver::default();
        assert!(finder.find(".1.0.0").is_none());
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Semver::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_version_at_start() {
        let finder = Semver::default();
        let input = "1.2.3 is the version";
        let range = finder.find(input).unwrap();
        assert_eq!("1.2.3", &input[range]);
    }

    #[test]
    fn find_should_extract_version_at_end() {
        let finder = Semver::default();
        let input = "version is 1.2.3";
        let range = finder.find(input).unwrap();
        assert_eq!("1.2.3", &input[range]);
    }

    #[test]
    fn find_should_extract_multiple_versions_iteratively() {
        let finder = Semver::default();
        let input = "from 1.0.0 to 2.0.0";

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

        assert_eq!(vec!["1.0.0", "2.0.0"], results);
    }

    #[test]
    fn find_should_extract_version_with_hyphen_prerelease() {
        let finder = Semver::default();
        let input = "1.0.0-beta-2";
        let range = finder.find(input).unwrap();
        assert_eq!("1.0.0-beta-2", &input[range]);
    }

    #[test]
    fn find_should_extract_version_in_parentheses() {
        let finder = Semver::default();
        let input = "(v1.2.3)";
        let range = finder.find(input).unwrap();
        assert_eq!("v1.2.3", &input[range]);
    }

    #[test]
    fn find_should_not_match_ip_address() {
        let finder = Semver::default();
        assert!(finder.find("192.168.1.1").is_none());
    }
}
