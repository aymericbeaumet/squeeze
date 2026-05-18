pub(crate) fn is_valid_ipv6(bytes: &[u8]) -> bool {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if let Some(last_colon) = s.rfind(':') {
        let suffix = &s[last_colon + 1..];
        if suffix.contains('.') {
            let prefix = &s[..last_colon + 1];
            let prefix_bytes = prefix.as_bytes();
            if is_valid_ipv4_suffix(suffix) {
                let trimmed = prefix.trim_end_matches(':');
                if trimmed.is_empty() {
                    return prefix_bytes.windows(2).any(|w| w == b"::");
                }
                return validate_groups(trimmed, true);
            }
        }
    }

    validate_groups(s, false)
}

fn is_valid_ipv4_suffix(s: &str) -> bool {
    let mut octet_count = 0u8;
    let mut octet_start = 0;
    let bytes = s.as_bytes();
    let mut i = 0;

    while i <= bytes.len() {
        if i == bytes.len() || bytes[i] == b'.' {
            let octet = &s[octet_start..i];
            if octet.is_empty() || octet.len() > 3 {
                return false;
            }
            if octet.len() > 1 && octet.as_bytes()[0] == b'0' {
                return false;
            }
            let mut val = 0u16;
            for &b in octet.as_bytes() {
                if !b.is_ascii_digit() {
                    return false;
                }
                val = val * 10 + (b - b'0') as u16;
            }
            if val > 255 {
                return false;
            }
            octet_count += 1;
            octet_start = i + 1;
        }
        i += 1;
    }

    octet_count == 4
}

pub(crate) fn validate_groups(s: &str, has_ipv4_suffix: bool) -> bool {
    let max_groups: usize = if has_ipv4_suffix { 6 } else { 8 };

    if s == "::" {
        return true;
    }

    let has_double_colon = s.contains("::");

    if has_double_colon {
        let Some(dc_pos) = s.find("::") else {
            return false;
        };
        let left_str = &s[..dc_pos];
        let right_str = &s[dc_pos + 2..];

        let left_count = if left_str.is_empty() {
            0
        } else {
            count_and_validate_groups(left_str)
        };
        let right_count = if right_str.is_empty() {
            0
        } else {
            count_and_validate_groups(right_str)
        };

        if left_count == usize::MAX || right_count == usize::MAX {
            return false;
        }

        let total = left_count + right_count;
        total < max_groups
    } else {
        let count = count_and_validate_groups(s);
        count == max_groups
    }
}

fn count_and_validate_groups(s: &str) -> usize {
    let mut count = 0usize;
    for g in s.split(':') {
        if !is_valid_hex_group(g) {
            return usize::MAX;
        }
        count += 1;
    }
    count
}

pub(crate) fn is_valid_hex_group(g: &str) -> bool {
    !g.is_empty() && g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_full_ipv6() {
        assert!(is_valid_ipv6(b"2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    #[test]
    fn valid_loopback() {
        assert!(is_valid_ipv6(b"::1"));
    }

    #[test]
    fn valid_all_zeros() {
        assert!(is_valid_ipv6(b"::"));
    }

    #[test]
    fn valid_compressed() {
        assert!(is_valid_ipv6(b"2001:db8::1"));
    }

    #[test]
    fn valid_leading_compressed() {
        assert!(is_valid_ipv6(b"::ffff:192.168.1.1"));
    }

    #[test]
    fn valid_ipv4_mapped() {
        assert!(is_valid_ipv6(b"::ffff:127.0.0.1"));
    }

    #[test]
    fn valid_full_eight_groups() {
        assert!(is_valid_ipv6(b"1:2:3:4:5:6:7:8"));
    }

    #[test]
    fn valid_with_ipv4_suffix() {
        assert!(is_valid_ipv6(b"1:2:3:4:5:6:127.0.0.1"));
    }

    #[test]
    fn invalid_too_many_groups() {
        assert!(!is_valid_ipv6(b"1:2:3:4:5:6:7:8:9"));
    }

    #[test]
    fn invalid_double_colon_twice() {
        assert!(!is_valid_ipv6(b"1::2::3"));
    }

    #[test]
    fn invalid_triple_colon() {
        assert!(!is_valid_ipv6(b":::"));
    }

    #[test]
    fn invalid_empty() {
        assert!(!is_valid_ipv6(b""));
    }

    #[test]
    fn invalid_group_too_long() {
        assert!(!is_valid_ipv6(b"12345::1"));
    }

    #[test]
    fn invalid_non_hex() {
        assert!(!is_valid_ipv6(b"gggg::1"));
    }

    #[test]
    fn valid_ipv4_suffix_with_compressed() {
        assert!(is_valid_ipv6(b"::127.0.0.1"));
    }

    #[test]
    fn invalid_ipv4_suffix_octet_over_255() {
        assert!(!is_valid_ipv6(b"::256.0.0.1"));
    }

    #[test]
    fn invalid_ipv4_suffix_leading_zero() {
        assert!(!is_valid_ipv6(b"::01.0.0.1"));
    }

    #[test]
    fn valid_fe80_link_local() {
        assert!(is_valid_ipv6(b"fe80::1"));
    }

    #[test]
    fn valid_only_double_colon() {
        assert!(is_valid_ipv6(b"1::"));
    }

    #[test]
    fn invalid_not_utf8() {
        assert!(!is_valid_ipv6(&[0xFF, 0xFE]));
    }
}
