use super::Finder;
use std::ops::Range;

pub struct Ip {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Default for Ip {
    fn default() -> Self {
        Ip {
            ipv4: true,
            ipv6: true,
        }
    }
}

impl Ip {
    fn try_ipv4(input: &[u8], idx: usize) -> Option<Range<usize>> {
        if !input[idx].is_ascii_digit() {
            return None;
        }
        // Boundary before: not preceded by digit or dot
        if idx > 0 && (input[idx - 1].is_ascii_digit() || input[idx - 1] == b'.') {
            return None;
        }

        let start = idx;
        let mut pos = idx;

        for octet_idx in 0..4 {
            if octet_idx > 0 {
                if pos >= input.len() || input[pos] != b'.' {
                    return None;
                }
                pos += 1;
            }

            let octet_start = pos;
            while pos < input.len() && input[pos].is_ascii_digit() {
                pos += 1;
            }
            let octet_len = pos - octet_start;
            if octet_len == 0 || octet_len > 3 {
                return None;
            }

            // No leading zeros (except "0" itself)
            if octet_len > 1 && input[octet_start] == b'0' {
                return None;
            }

            let octet_str = std::str::from_utf8(&input[octet_start..pos]).ok()?;
            let value: u16 = octet_str.parse().ok()?;
            if value > 255 {
                return None;
            }
        }

        // Boundary after: not followed by digit or dot
        if pos < input.len() && (input[pos].is_ascii_digit() || input[pos] == b'.') {
            return None;
        }

        Some(start..pos)
    }

    fn try_bracketed_ipv6(input: &[u8], idx: usize) -> Option<Range<usize>> {
        if input[idx] != b'[' {
            return None;
        }

        let close = input[idx..].iter().position(|&b| b == b']')?;
        let close_pos = idx + close;
        let inner = &input[idx + 1..close_pos];

        if Self::is_valid_ipv6(inner) {
            Some(idx..close_pos + 1)
        } else {
            None
        }
    }

    fn try_bare_ipv6(input: &[u8], idx: usize) -> Option<Range<usize>> {
        // Must start with hex digit or ':'
        if !input[idx].is_ascii_hexdigit() && input[idx] != b':' {
            return None;
        }

        // Boundary before: not preceded by hex digit, colon, or alphanumeric
        if idx > 0 && (input[idx - 1].is_ascii_alphanumeric() || input[idx - 1] == b':') {
            return None;
        }

        let start = idx;
        let mut end = idx;

        while end < input.len()
            && (input[end].is_ascii_hexdigit() || input[end] == b':' || input[end] == b'.')
        {
            end += 1;
        }

        // Strip trailing colons
        while end > start && input[end - 1] == b':' && !(end >= 2 && input[end - 2] == b':') {
            end -= 1;
        }

        let candidate = &input[start..end];

        // Must contain at least one colon
        if !candidate.contains(&b':') {
            return None;
        }

        // Boundary after
        if end < input.len() && (input[end].is_ascii_alphanumeric() || input[end] == b':') {
            return None;
        }

        if Self::is_valid_ipv6(candidate) {
            Some(start..end)
        } else {
            None
        }
    }

    fn is_valid_ipv6(bytes: &[u8]) -> bool {
        let s = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Handle IPv4-mapped IPv6 (e.g., ::ffff:192.168.1.1)
        if let Some(last_colon) = s.rfind(':') {
            let suffix = &s[last_colon + 1..];
            if suffix.contains('.') {
                let prefix = &s[..last_colon + 1];
                let prefix_bytes = prefix.as_bytes();
                // Validate the IPv4 part
                let parts: Vec<&str> = suffix.split('.').collect();
                if parts.len() == 4 {
                    let ipv4_valid = parts.iter().all(|p| {
                        if p.is_empty() || p.len() > 3 {
                            return false;
                        }
                        if p.len() > 1 && p.starts_with('0') {
                            return false;
                        }
                        p.parse::<u16>().is_ok_and(|v| v <= 255)
                    });
                    if ipv4_valid {
                        // Validate the prefix as IPv6 groups (should end with :)
                        // Count the groups in prefix
                        let trimmed = prefix.trim_end_matches(':');
                        if trimmed.is_empty() {
                            // Just "::" prefix — valid
                            return prefix_bytes.windows(2).any(|w| w == b"::");
                        }
                        // Validate prefix groups
                        return Self::validate_ipv6_groups(trimmed, true);
                    }
                }
            }
        }

        Self::validate_ipv6_groups(s, false)
    }

    fn validate_ipv6_groups(s: &str, has_ipv4_suffix: bool) -> bool {
        let max_groups = if has_ipv4_suffix { 6 } else { 8 };

        if s == "::" {
            return true;
        }

        let has_double_colon = s.contains("::");

        // Split on :: first
        if has_double_colon {
            let parts: Vec<&str> = s.splitn(2, "::").collect();
            if parts.len() != 2 {
                return false;
            }

            let left_groups: Vec<&str> = if parts[0].is_empty() {
                vec![]
            } else {
                parts[0].split(':').collect()
            };

            let right_groups: Vec<&str> = if parts[1].is_empty() {
                vec![]
            } else {
                parts[1].split(':').collect()
            };

            let total = left_groups.len() + right_groups.len();
            if total >= max_groups {
                return false;
            }

            left_groups
                .iter()
                .chain(right_groups.iter())
                .all(|g| Self::is_valid_hex_group(g))
        } else {
            let groups: Vec<&str> = s.split(':').collect();
            groups.len() == max_groups && groups.iter().all(|g| Self::is_valid_hex_group(g))
        }
    }

    fn is_valid_hex_group(g: &str) -> bool {
        !g.is_empty() && g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

impl Finder for Ip {
    fn id(&self) -> &'static str {
        "ip"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            if self.ipv6 {
                if input[idx] == b'[' {
                    if let Some(range) = Self::try_bracketed_ipv6(input, idx) {
                        return Some(range);
                    }
                }

                if input[idx].is_ascii_hexdigit() || input[idx] == b':' {
                    if let Some(range) = Self::try_bare_ipv6(input, idx) {
                        return Some(range);
                    }
                }
            }

            if self.ipv4 && input[idx].is_ascii_digit() {
                if let Some(range) = Self::try_ipv4(input, idx) {
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
    fn id_should_return_ip() {
        let finder = Ip::default();
        assert_eq!("ip", finder.id());
    }

    // IPv4 tests
    #[test]
    fn find_should_extract_ipv4() {
        let finder = Ip::default();
        let input = "server at 192.168.1.1 running";
        let range = finder.find(input).unwrap();
        assert_eq!("192.168.1.1", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv4_at_start() {
        let finder = Ip::default();
        let input = "10.0.0.1 is gateway";
        let range = finder.find(input).unwrap();
        assert_eq!("10.0.0.1", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv4_at_end() {
        let finder = Ip::default();
        let input = "connect to 172.16.0.1";
        let range = finder.find(input).unwrap();
        assert_eq!("172.16.0.1", &input[range]);
    }

    #[test]
    fn find_should_extract_localhost() {
        let finder = Ip::default();
        let input = "127.0.0.1";
        let range = finder.find(input).unwrap();
        assert_eq!("127.0.0.1", &input[range]);
    }

    #[test]
    fn find_should_extract_all_zeros() {
        let finder = Ip::default();
        let input = "0.0.0.0";
        let range = finder.find(input).unwrap();
        assert_eq!("0.0.0.0", &input[range]);
    }

    #[test]
    fn find_should_extract_max_values() {
        let finder = Ip::default();
        let input = "255.255.255.255";
        let range = finder.find(input).unwrap();
        assert_eq!("255.255.255.255", &input[range]);
    }

    #[test]
    fn find_should_reject_octet_over_255() {
        let finder = Ip::default();
        assert!(finder.find("256.1.1.1").is_none());
    }

    #[test]
    fn find_should_reject_three_octets() {
        let finder = Ip::default();
        assert!(finder.find("192.168.1 only").is_none());
    }

    #[test]
    fn find_should_reject_five_octets() {
        let finder = Ip::default();
        assert!(finder.find("192.168.1.1.1").is_none());
    }

    #[test]
    fn find_should_reject_leading_zeros() {
        let finder = Ip::default();
        assert!(finder.find("192.168.01.1").is_none());
    }

    #[test]
    fn find_should_reject_preceded_by_digit() {
        let finder = Ip::default();
        assert!(finder.find("9192.168.1.1").is_none());
    }

    // IPv6 tests
    #[test]
    fn find_should_extract_bracketed_ipv6() {
        let finder = Ip::default();
        let input = "connect to [::1] now";
        let range = finder.find(input).unwrap();
        assert_eq!("[::1]", &input[range]);
    }

    #[test]
    fn find_should_extract_full_ipv6() {
        let finder = Ip::default();
        let input = "addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 here";
        let range = finder.find(input).unwrap();
        assert_eq!("2001:0db8:85a3:0000:0000:8a2e:0370:7334", &input[range]);
    }

    #[test]
    fn find_should_extract_compressed_ipv6() {
        let finder = Ip::default();
        let input = "addr 2001:db8::1 here";
        let range = finder.find(input).unwrap();
        assert_eq!("2001:db8::1", &input[range]);
    }

    #[test]
    fn find_should_extract_loopback_ipv6() {
        let finder = Ip::default();
        let input = "[::1]";
        let range = finder.find(input).unwrap();
        assert_eq!("[::1]", &input[range]);
    }

    #[test]
    fn find_should_extract_bare_double_colon() {
        let finder = Ip::default();
        let input = "addr :: here";
        let range = finder.find(input).unwrap();
        assert_eq!("::", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv6_with_prefix_groups() {
        let finder = Ip::default();
        let input = "fe80::1";
        let range = finder.find(input).unwrap();
        assert_eq!("fe80::1", &input[range]);
    }

    // Filter tests
    #[test]
    fn find_should_only_match_ipv4_when_configured() {
        let finder = Ip {
            ipv4: true,
            ipv6: false,
        };
        let input = "192.168.1.1 and [::1]";
        let range = finder.find(input).unwrap();
        assert_eq!("192.168.1.1", &input[range]);
    }

    #[test]
    fn find_should_only_match_ipv6_when_configured() {
        let finder = Ip {
            ipv4: false,
            ipv6: true,
        };
        let input = "192.168.1.1 and [::1]";
        let range = finder.find(input).unwrap();
        assert_eq!("[::1]", &input[range]);
    }

    // Multiple
    #[test]
    fn find_should_extract_multiple_ips_iteratively() {
        let finder = Ip::default();
        let input = "10.0.0.1 and 10.0.0.2";

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

        assert_eq!(vec!["10.0.0.1", "10.0.0.2"], results);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Ip::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_handle_no_ip() {
        let finder = Ip::default();
        assert!(finder.find("just some text").is_none());
    }
}
