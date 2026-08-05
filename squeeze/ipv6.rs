/// Validates an IPv6 address per RFC 4291 §2.2, matching the acceptance of
/// `std::net::Ipv6Addr::from_str` (minus zone IDs, which callers strip):
/// - at most one `::` compression marker, which must stand for at least one
///   zero group
/// - 1-4 hex digit groups, exactly 8 groups total when uncompressed
/// - an optional embedded IPv4 dotted quad as the last two groups (e.g.
///   `::ffff:192.168.1.1`, `64:ff9b::192.0.2.33`)
pub(crate) fn is_valid_ipv6(bytes: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return false;
    };
    if s.is_empty() {
        return false;
    }

    match s.find("::") {
        Some(pos) => {
            let left = &s[..pos];
            let right = &s[pos + 2..];
            // A second `::` (including overlapping runs like `:::`) is invalid.
            if right.contains("::") || right.starts_with(':') || left.ends_with(':') {
                return false;
            }
            let Some(left_groups) = count_groups(left, false) else {
                return false;
            };
            let Some(right_groups) = count_groups(right, true) else {
                return false;
            };
            // `::` must expand to at least one zero group.
            left_groups + right_groups < 8
        }
        None => count_groups(s, true) == Some(8),
    }
}

/// Counts the 16-bit groups in a colon-separated list, where the last element
/// may be an IPv4 dotted quad (counting as two groups) when `allow_v4_tail`.
/// Returns `None` if any element is invalid.
fn count_groups(part: &str, allow_v4_tail: bool) -> Option<usize> {
    if part.is_empty() {
        return Some(0);
    }
    let mut count = 0usize;
    let mut iter = part.split(':').peekable();
    while let Some(group) = iter.next() {
        let is_last = iter.peek().is_none();
        if is_last && allow_v4_tail && group.contains('.') {
            if !is_valid_ipv4_quad(group) {
                return None;
            }
            count += 2;
        } else {
            if !is_valid_hex_group(group) {
                return None;
            }
            count += 1;
        }
    }
    Some(count)
}

fn is_valid_ipv4_quad(s: &str) -> bool {
    let mut octet_count = 0u8;
    for octet in s.split('.') {
        let bytes = octet.as_bytes();
        if bytes.is_empty() || bytes.len() > 3 {
            return false;
        }
        // Leading zeros are rejected, matching `std::net`.
        if bytes.len() > 1 && bytes[0] == b'0' {
            return false;
        }
        let mut val = 0u16;
        for &b in bytes {
            if !b.is_ascii_digit() {
                return false;
            }
            val = val * 10 + u16::from(b - b'0');
        }
        if val > 255 {
            return false;
        }
        octet_count += 1;
        if octet_count > 4 {
            return false;
        }
    }
    octet_count == 4
}

fn is_valid_hex_group(g: &str) -> bool {
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

    // --- Regressions: `::` directly before an IPv4 tail (NAT64 family) ---

    #[test]
    fn valid_nat64_prefix_with_v4_tail() {
        assert!(is_valid_ipv6(b"64:ff9b::192.0.2.33"));
    }

    #[test]
    fn valid_compressed_one_group_with_v4_tail() {
        assert!(is_valid_ipv6(b"1::1.2.3.4"));
    }

    #[test]
    fn valid_compressed_five_groups_with_v4_tail() {
        assert!(is_valid_ipv6(b"1:2:3:4:5::1.2.3.4"));
    }

    #[test]
    fn valid_db8_with_v4_tail() {
        assert!(is_valid_ipv6(b"2001:db8::1.2.3.4"));
    }

    // --- Regressions: invalid v4-tail forms previously accepted ---

    #[test]
    fn invalid_six_groups_compressed_with_v4_tail() {
        // `::` would expand to zero groups: 6 + 2 = 8 already.
        assert!(!is_valid_ipv6(b"1:2:3:4:5:6::1.2.3.4"));
    }

    #[test]
    fn invalid_double_compression_with_v4_tail() {
        assert!(!is_valid_ipv6(b"1::2::1.2.3.4"));
    }

    #[test]
    fn invalid_triple_colon_with_v4_tail() {
        assert!(!is_valid_ipv6(b":::1.2.3.4"));
    }

    #[test]
    fn invalid_quad_colon_with_v4_tail() {
        assert!(!is_valid_ipv6(b"::::1.2.3.4"));
    }

    #[test]
    fn invalid_lone_leading_colon() {
        assert!(!is_valid_ipv6(b":1:2:3:4:5:6:7:8"));
    }

    #[test]
    fn invalid_lone_trailing_colon() {
        assert!(!is_valid_ipv6(b"1:2:3:4:5:6:7:8:"));
    }

    #[test]
    fn invalid_bare_ipv4() {
        assert!(!is_valid_ipv6(b"1.2.3.4"));
    }

    #[test]
    fn invalid_v4_tail_on_left_of_compression() {
        assert!(!is_valid_ipv6(b"1.2.3.4::1"));
    }

    #[test]
    fn invalid_eight_groups_plus_compression() {
        assert!(!is_valid_ipv6(b"1:2:3:4:5:6:7:8::"));
    }

    #[test]
    fn valid_seven_groups_trailing_compression() {
        assert!(is_valid_ipv6(b"1:2:3:4:5:6:7::"));
    }

    #[test]
    fn invalid_v4_tail_too_many_octets() {
        assert!(!is_valid_ipv6(b"::1.2.3.4.5"));
    }

    #[test]
    fn invalid_v4_tail_in_middle() {
        assert!(!is_valid_ipv6(b"::1.2.3.4:5"));
    }

    // --- Differential sanity vs std ---

    #[test]
    fn differential_against_std() {
        let candidates: &[&str] = &[
            "::",
            "::1",
            "1::",
            "1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6:7:8:9",
            "64:ff9b::192.0.2.33",
            "2001:db8::1.2.3.4",
            "1:2:3:4:5:6::1.2.3.4",
            "1:2:3:4:5::1.2.3.4",
            "::ffff:0.0.0.0",
            ":::1.2.3.4",
            "::::1.2.3.4",
            "1::2::3",
            ":::",
            "::1:",
            ":1::2",
            "12345::",
            "1:2:3:4:5:6:1.2.3.4",
            "1:2:3:4:5:6:7:1.2.3.4",
            "fe80::1",
            "::256.1.1.1",
            "::01.1.1.1",
            "a:b:c:d:e:f:1.2.3.4",
            "A:B:C:D:E:F:a:b",
        ];
        for c in candidates {
            let std_ok = c.parse::<std::net::Ipv6Addr>().is_ok();
            assert_eq!(
                is_valid_ipv6(c.as_bytes()),
                std_ok,
                "disagrees with std on {c:?}"
            );
        }
    }
}
