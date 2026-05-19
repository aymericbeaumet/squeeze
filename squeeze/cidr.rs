use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Cidr {}

impl Cidr {
    fn try_ipv4_cidr(input: &[u8], idx: usize) -> Option<Range<usize>> {
        if !input[idx].is_ascii_digit() {
            return None;
        }

        // Boundary before: not preceded by digit or dot
        if idx > 0 && (input[idx - 1].is_ascii_digit() || input[idx - 1] == b'.') {
            return None;
        }

        let start = idx;
        let mut pos = idx;

        // Parse 4 octets
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

            if octet_len > 1 && input[octet_start] == b'0' {
                return None;
            }

            let mut value: u16 = 0;
            for &b in &input[octet_start..pos] {
                value = value * 10 + (b - b'0') as u16;
            }
            if value > 255 {
                return None;
            }
        }

        // Must have /prefix
        if pos >= input.len() || input[pos] != b'/' {
            return None;
        }
        pos += 1;

        let prefix_start = pos;
        while pos < input.len() && input[pos].is_ascii_digit() {
            pos += 1;
        }
        let prefix_len = pos - prefix_start;
        if prefix_len == 0 || prefix_len > 2 {
            return None;
        }

        // No leading zeros in prefix
        if prefix_len > 1 && input[prefix_start] == b'0' {
            return None;
        }

        let mut prefix: u8 = 0;
        for &b in &input[prefix_start..pos] {
            prefix = prefix * 10 + (b - b'0');
        }
        if prefix > 32 {
            return None;
        }

        // Boundary after: not followed by digit or dot
        if pos < input.len() && (input[pos].is_ascii_digit() || input[pos] == b'.') {
            return None;
        }

        Some(start..pos)
    }

    fn try_ipv6_cidr(input: &[u8], idx: usize) -> Option<Range<usize>> {
        // Look for IPv6 addresses followed by /prefix
        // Handle both bare and bracketed forms
        let (ip_start, ip_end) = if input[idx] == b'[' {
            let close = input[idx..].iter().position(|&b| b == b']')?;
            let close_pos = idx + close;
            let inner = &input[idx + 1..close_pos];
            if !crate::ipv6::is_valid_ipv6(inner) {
                return None;
            }
            (idx, close_pos + 1)
        } else {
            if !input[idx].is_ascii_hexdigit() && input[idx] != b':' {
                return None;
            }
            // Boundary before
            if idx > 0 && (input[idx - 1].is_ascii_alphanumeric() || input[idx - 1] == b':') {
                return None;
            }

            let start = idx;
            let mut end = idx;
            while end < input.len() && (input[end].is_ascii_hexdigit() || input[end] == b':') {
                end += 1;
            }

            // Strip trailing colons (except ::)
            while end > start && input[end - 1] == b':' && !(end >= 2 && input[end - 2] == b':') {
                end -= 1;
            }

            let candidate = &input[start..end];
            if !candidate.contains(&b':') {
                return None;
            }
            if !crate::ipv6::is_valid_ipv6(candidate) {
                return None;
            }
            (start, end)
        };

        // Must have /prefix
        if ip_end >= input.len() || input[ip_end] != b'/' {
            return None;
        }
        let mut pos = ip_end + 1;

        let prefix_start = pos;
        while pos < input.len() && input[pos].is_ascii_digit() {
            pos += 1;
        }
        let prefix_len = pos - prefix_start;
        if prefix_len == 0 || prefix_len > 3 {
            return None;
        }

        if prefix_len > 1 && input[prefix_start] == b'0' {
            return None;
        }

        let mut prefix: u16 = 0;
        for &b in &input[prefix_start..pos] {
            prefix = prefix * 10 + (b - b'0') as u16;
        }
        if prefix > 128 {
            return None;
        }

        // Boundary after
        if pos < input.len() && (input[pos].is_ascii_digit() || input[pos] == b'.') {
            return None;
        }

        Some(ip_start..pos)
    }
}

impl Finder for Cidr {
    fn id(&self) -> &'static str {
        "cidr"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        byte.is_ascii_hexdigit() || byte == b':' || byte == b'['
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        if input[pos].is_ascii_digit()
            && let Some(range) = Self::try_ipv4_cidr(input, pos)
        {
            return Some(range);
        }
        if (input[pos] == b'[' || input[pos].is_ascii_hexdigit() || input[pos] == b':')
            && let Some(range) = Self::try_ipv6_cidr(input, pos)
        {
            return Some(range);
        }
        None
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            if input[idx].is_ascii_digit()
                && let Some(range) = Self::try_ipv4_cidr(input, idx)
            {
                return Some(range);
            }

            if (input[idx] == b'[' || input[idx].is_ascii_hexdigit() || input[idx] == b':')
                && let Some(range) = Self::try_ipv6_cidr(input, idx)
            {
                return Some(range);
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
    fn id_should_return_cidr() {
        let finder = Cidr::default();
        assert_eq!("cidr", finder.id());
    }

    // IPv4 CIDR
    #[test]
    fn find_should_extract_ipv4_cidr() {
        let finder = Cidr::default();
        let input = "network 192.168.1.0/24 is local";
        let range = finder.find(input).unwrap();
        assert_eq!("192.168.1.0/24", &input[range]);
    }

    #[test]
    fn find_should_extract_class_a() {
        let finder = Cidr::default();
        let input = "10.0.0.0/8";
        let range = finder.find(input).unwrap();
        assert_eq!("10.0.0.0/8", &input[range]);
    }

    #[test]
    fn find_should_extract_host_route() {
        let finder = Cidr::default();
        let input = "host 10.0.0.1/32 route";
        let range = finder.find(input).unwrap();
        assert_eq!("10.0.0.1/32", &input[range]);
    }

    #[test]
    fn find_should_extract_default_route() {
        let finder = Cidr::default();
        let input = "0.0.0.0/0";
        let range = finder.find(input).unwrap();
        assert_eq!("0.0.0.0/0", &input[range]);
    }

    #[test]
    fn find_should_reject_prefix_over_32() {
        let finder = Cidr::default();
        assert!(finder.find("192.168.1.0/33").is_none());
    }

    #[test]
    fn find_should_reject_no_prefix() {
        let finder = Cidr::default();
        assert!(finder.find("only 192.168.1.0 here").is_none());
    }

    #[test]
    fn find_should_reject_invalid_octet() {
        let finder = Cidr::default();
        assert!(finder.find("256.168.1.0/24").is_none());
    }

    #[test]
    fn find_should_reject_leading_zero_octet() {
        let finder = Cidr::default();
        assert!(finder.find("192.168.01.0/24").is_none());
    }

    #[test]
    fn find_should_reject_leading_zero_prefix() {
        let finder = Cidr::default();
        assert!(finder.find("192.168.1.0/08").is_none());
    }

    #[test]
    fn find_should_reject_preceded_by_digit() {
        let finder = Cidr::default();
        assert!(finder.find("x1192.168.1.0/24").is_none());
    }

    #[test]
    fn find_should_reject_followed_by_digit() {
        let finder = Cidr::default();
        assert!(finder.find("192.168.1.0/245").is_none());
    }

    // IPv6 CIDR
    #[test]
    fn find_should_extract_ipv6_cidr() {
        let finder = Cidr::default();
        let input = "network 2001:db8::/32 configured";
        let range = finder.find(input).unwrap();
        assert_eq!("2001:db8::/32", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv6_full_cidr() {
        let finder = Cidr::default();
        let input = "2001:0db8:85a3:0000:0000:8a2e:0370:7334/64";
        let range = finder.find(input).unwrap();
        assert_eq!("2001:0db8:85a3:0000:0000:8a2e:0370:7334/64", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv6_loopback_cidr() {
        let finder = Cidr::default();
        let input = "::1/128";
        let range = finder.find(input).unwrap();
        assert_eq!("::1/128", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv6_default_cidr() {
        let finder = Cidr::default();
        let input = "::/0";
        let range = finder.find(input).unwrap();
        assert_eq!("::/0", &input[range]);
    }

    #[test]
    fn find_should_reject_ipv6_prefix_over_128() {
        let finder = Cidr::default();
        assert!(finder.find("2001:db8::/129").is_none());
    }

    // Multiple
    #[test]
    fn find_should_extract_multiple_cidrs_iteratively() {
        let finder = Cidr::default();
        let input = "10.0.0.0/8 and 192.168.1.0/24";

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

        assert_eq!(vec!["10.0.0.0/8", "192.168.1.0/24"], results);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Cidr::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_cidr_at_start() {
        let finder = Cidr::default();
        let input = "10.0.0.0/8 is class A";
        let range = finder.find(input).unwrap();
        assert_eq!("10.0.0.0/8", &input[range]);
    }

    #[test]
    fn find_should_extract_cidr_at_end() {
        let finder = Cidr::default();
        let input = "subnet is 172.16.0.0/12";
        let range = finder.find(input).unwrap();
        assert_eq!("172.16.0.0/12", &input[range]);
    }

    #[test]
    fn try_at_ipv4_cidr() {
        let finder = Cidr::default();
        let input = b"192.168.1.0/24 rest";
        assert_eq!(finder.try_at(input, 0), Some(0..14));
    }

    #[test]
    fn try_at_ipv6_cidr() {
        let finder = Cidr::default();
        let input = b"2001:db8::/32 rest";
        assert_eq!(finder.try_at(input, 0), Some(0..13));
    }

    #[test]
    fn try_at_no_prefix() {
        let finder = Cidr::default();
        let input = b"192.168.1.0 no prefix";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn try_at_non_digit() {
        let finder = Cidr::default();
        assert!(finder.try_at(b"abc", 0).is_none());
    }

    #[test]
    fn try_at_single_digit() {
        let finder = Cidr::default();
        assert!(finder.try_at(b"1", 0).is_none());
    }

    #[test]
    fn find_prefix_zero() {
        let finder = Cidr::default();
        let input = "0.0.0.0/0";
        let range = finder.find(input).unwrap();
        assert_eq!("0.0.0.0/0", &input[range]);
    }

    #[test]
    fn find_prefix_32() {
        let finder = Cidr::default();
        let input = "10.0.0.1/32";
        let range = finder.find(input).unwrap();
        assert_eq!("10.0.0.1/32", &input[range]);
    }

    #[test]
    fn find_rejects_prefix_with_leading_zero() {
        let finder = Cidr::default();
        assert!(finder.find("10.0.0.0/08").is_none());
    }

    #[test]
    fn find_ipv6_prefix_128() {
        let finder = Cidr::default();
        let input = "::1/128";
        let range = finder.find(input).unwrap();
        assert_eq!("::1/128", &input[range]);
    }

    #[test]
    fn find_ipv6_prefix_zero() {
        let finder = Cidr::default();
        let input = "::/0";
        let range = finder.find(input).unwrap();
        assert_eq!("::/0", &input[range]);
    }

    // --- Regression: could_start_at without redundant digit check ---

    #[test]
    fn could_start_at_digit() {
        let finder = Cidr::default();
        for b in b'0'..=b'9' {
            assert!(
                finder.could_start_at(b),
                "should start at digit {}",
                b as char
            );
        }
    }

    #[test]
    fn could_start_at_hex_alpha() {
        let finder = Cidr::default();
        for b in b'a'..=b'f' {
            assert!(finder.could_start_at(b), "should start at {}", b as char);
        }
        for b in b'A'..=b'F' {
            assert!(finder.could_start_at(b), "should start at {}", b as char);
        }
    }

    #[test]
    fn could_start_at_colon_bracket() {
        let finder = Cidr::default();
        assert!(finder.could_start_at(b':'));
        assert!(finder.could_start_at(b'['));
    }

    #[test]
    fn could_not_start_at_non_hex() {
        let finder = Cidr::default();
        assert!(!finder.could_start_at(b'g'));
        assert!(!finder.could_start_at(b' '));
        assert!(!finder.could_start_at(b'/'));
    }
}
