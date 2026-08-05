//! Hardening regression suite for the network finders (ip, cidr, mac).
//!
//! Covers the finder-level scan bugs fixed on top of the corrected
//! `ipv6::is_valid_ipv6` validator:
//! 1. v4-in-v6 extraction and the no-interior-mining policy for failed
//!    IPv6 candidates,
//! 2. bare IPv6 followed by a sentence dot,
//! 3. bare IPv6 followed by a trailing colon,
//! 4. IPv6 CIDR charset missing '.' and v4-CIDR mining of v6 leftovers,
//! 5. CIDR prefix followed by a sentence dot,
//! 6. dotted (Cisco) MAC followed by a sentence dot.
//!
//! Every deliberate non-bug stays pinned, a differential test checks the
//! ip finder against `std::net::Ipv6Addr`, and a scanner-parity test checks
//! dispatch mode against the documented `find()` loop on the whole corpus.

use squeeze::Finder;
use squeeze::cidr::Cidr;
use squeeze::ip::Ip;
use squeeze::mac::Mac;
use squeeze::scanner::Scanner;
use std::ops::Range;

fn find_str<'a>(finder: &dyn Finder, input: &'a str) -> Option<&'a str> {
    finder.find(input).map(|r| &input[r])
}

/// The documented multi-match loop: repeatedly `find()` on the remaining
/// slice, advancing past each match.
fn find_all<'a>(finder: &dyn Finder, input: &'a str) -> Vec<&'a str> {
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
    results
}

fn ipv6_only() -> Ip {
    Ip {
        ipv4: false,
        ipv6: true,
    }
}

fn ipv4_only() -> Ip {
    Ip {
        ipv4: true,
        ipv6: false,
    }
}

// ============================================================================
// Bug 1: v4-in-v6 at the ip.rs level (validator now accepts, scan must too)
// ============================================================================

#[test]
fn ip_finds_nat64_v4_in_v6_in_text() {
    let f = Ip::default();
    assert_eq!(
        find_str(&f, "prefix 64:ff9b::192.0.2.33 used"),
        Some("64:ff9b::192.0.2.33")
    );
}

#[test]
fn ip_finds_compressed_one_group_v4_tail_whole() {
    // The whole address must match, not a standalone `1.2.3.4`.
    let f = Ip::default();
    let input = "x 1::1.2.3.4 y";
    assert_eq!(find_str(&f, input), Some("1::1.2.3.4"));
    assert_eq!(find_all(&f, input), vec!["1::1.2.3.4"]);
}

#[test]
fn ip_v4_in_v6_via_try_at() {
    let f = Ip::default();
    let input = b"x 64:ff9b::192.0.2.33 y";
    assert_eq!(f.try_at(input, 2), Some(2..21));
}

#[test]
fn ip_v4_in_v6_bracketed() {
    let f = Ip::default();
    assert_eq!(
        find_str(&f, "conn [64:ff9b::192.0.2.33] ok"),
        Some("[64:ff9b::192.0.2.33]")
    );
}

#[test]
fn ip_v4_in_v6_in_ipv6_only_mode() {
    let f = ipv6_only();
    assert_eq!(
        find_str(&f, "prefix 64:ff9b::192.0.2.33 used"),
        Some("64:ff9b::192.0.2.33")
    );
}

#[test]
fn ip_rejects_six_groups_compressed_v4_tail_entirely() {
    // `::` would expand to zero groups; invalid, and the dotted tail must not
    // be re-extracted as bare IPv4 either.
    let f = Ip::default();
    assert_eq!(find_all(&f, "x 1:2:3:4:5:6::1.2.3.4 y"), Vec::<&str>::new());
}

#[test]
fn ip_rejects_triple_colon_v4_tail_entirely() {
    let f = Ip::default();
    assert_eq!(find_all(&f, "x :::1.2.3.4 y"), Vec::<&str>::new());
}

#[test]
fn ip_rejects_quad_colon_v4_tail_entirely() {
    let f = Ip::default();
    assert_eq!(find_all(&f, "x ::::1.2.3.4 y"), Vec::<&str>::new());
}

#[test]
fn ip_does_not_mine_v4_from_failed_v6_double_compression() {
    // Was the live FP: `--ip` printed `1.2.3.4` out of `1::2::1.2.3.4`.
    let f = Ip::default();
    assert_eq!(find_all(&f, "x 1::2::1.2.3.4 y"), Vec::<&str>::new());
}

#[test]
fn ip_does_not_mine_v4_in_ipv4_only_mode() {
    // The token is IPv6-shaped; --ipv4-only must not extract its tail.
    let f = ipv4_only();
    assert_eq!(find_all(&f, "x 1::2::1.2.3.4 y"), Vec::<&str>::new());
    assert_eq!(find_all(&f, "x :::1.2.3.4 y"), Vec::<&str>::new());
}

#[test]
fn ip_does_not_mine_v4_after_lone_leading_colon() {
    // `:1.2.3.4` at a token boundary is a failed IPv6 candidate too.
    let f = Ip::default();
    assert_eq!(find_all(&f, "x :1.2.3.4 y"), Vec::<&str>::new());
    assert_eq!(find_all(&f, ":1.2.3.4"), Vec::<&str>::new());
}

#[test]
fn ip_does_not_mine_v4_from_failed_hex_label_candidate() {
    // `beef:` is a viable IPv6 group, so `beef:10.0.0.1` was an IPv6
    // candidate that failed validation: its interior stays unmined.
    let f = Ip::default();
    assert_eq!(find_all(&f, "x beef:10.0.0.1 y"), Vec::<&str>::new());
}

#[test]
fn ip_word_colon_quad_still_matches() {
    // Documented leniency: `port:` cannot start an IPv6 address ('t' is not a
    // hex digit), so the quad after the colon is a genuine bare IPv4.
    let f = Ip::default();
    assert_eq!(find_str(&f, "port:10.0.0.1 dropped"), Some("10.0.0.1"));
}

#[test]
fn ip_head_quad_before_port_colon_still_matches() {
    // Pinned: the head of `addr:port` is a real IPv4 (only interiors *after*
    // a ':' are off limits).
    let f = Ip::default();
    assert_eq!(
        find_str(&f, "connect to 192.168.1.1:8080 ok"),
        Some("192.168.1.1")
    );
}

#[test]
fn ip_bracketed_failed_v6_not_mined() {
    let f = Ip::default();
    assert_eq!(find_all(&f, "[1:2:3:4:5:6::1.2.3.4]"), Vec::<&str>::new());
}

// ============================================================================
// Bug 2: bare IPv6 + sentence dot
// ============================================================================

#[test]
fn ip_bare_v6_followed_by_sentence_dot() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "see 2001:db8::1. next"), Some("2001:db8::1"));
}

#[test]
fn ip_eight_groups_followed_by_sentence_dot() {
    let f = Ip::default();
    assert_eq!(
        find_str(&f, "a 1:2:3:4:5:6:7:8. b"),
        Some("1:2:3:4:5:6:7:8")
    );
}

#[test]
fn ip_v4_tail_followed_by_sentence_dot() {
    let f = Ip::default();
    assert_eq!(
        find_str(&f, "addr ::ffff:192.168.1.1. ok"),
        Some("::ffff:192.168.1.1")
    );
}

#[test]
fn ip_v6_sentence_dot_at_end_of_line() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "ping 2001:db8::1."), Some("2001:db8::1"));
}

#[test]
fn ip_v6_followed_by_ellipsis() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "wat 2001:db8::1... hm"), Some("2001:db8::1"));
}

#[test]
fn ip_v6_dot_glued_to_letter_still_dead() {
    // A letter glued after the run means it is part of a larger token.
    let f = Ip::default();
    assert_eq!(find_all(&f, "see 2001:db8::1.next"), Vec::<&str>::new());
}

#[test]
fn ip_v4_sentence_dot_still_dead() {
    // Pinned non-bug: bare IPv4 + '.' stays ambiguous with a longer dotted
    // run and is deliberately not matched.
    let f = Ip::default();
    assert_eq!(find_all(&f, "ping 192.168.1.1. now"), Vec::<&str>::new());
}

// ============================================================================
// Bug 3: trailing-colon strip must actually produce a match
// ============================================================================

#[test]
fn ip_v6_followed_by_trailing_colon() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "host fe80::1: up"), Some("fe80::1"));
}

#[test]
fn ip_eight_groups_followed_by_trailing_colon() {
    // Pinned as acceptable: stripping the lone trailing colon of a valid
    // 8-group address yields the address.
    let f = Ip::default();
    assert_eq!(
        find_str(&f, "ports 1:2:3:4:5:6:7:8: x"),
        Some("1:2:3:4:5:6:7:8")
    );
}

#[test]
fn ip_nine_groups_still_dead() {
    // No-subset-of-longer-run policy: 9 groups never yields an 8-group match.
    let f = Ip::default();
    assert_eq!(find_all(&f, "1:2:3:4:5:6:7:8:9"), Vec::<&str>::new());
    assert_eq!(find_all(&f, "x 1:2:3:4:5:6:7:8:9 y"), Vec::<&str>::new());
}

#[test]
fn ip_trailing_double_colon_not_stripped() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "addr 2001:db8:: here"), Some("2001:db8::"));
}

#[test]
fn ip_bare_double_colon_still_matches() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "addr :: here"), Some("::"));
}

#[test]
fn ip_trailing_colon_glued_to_letter_still_dead() {
    // `fe80::1:x9` continues with a non-hex letter: part of a larger token.
    let f = Ip::default();
    assert_eq!(find_all(&f, "addr fe80::1:x9 end"), Vec::<&str>::new());
}

#[test]
fn ip_trailing_colon_via_try_at() {
    let f = Ip::default();
    let input = b"host fe80::1: up";
    assert_eq!(f.try_at(input, 5), Some(5..12));
}

// ============================================================================
// ip: other pinned non-bugs
// ============================================================================

#[test]
fn ip_zone_id_dropped_by_design() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "addr fe80::1%eth0 end"), Some("fe80::1"));
}

#[test]
fn ip_bracketed_with_port() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "[::1]:8080"), Some("[::1]"));
}

#[test]
fn ip_mac_shape_is_not_ip() {
    let f = Ip::default();
    assert_eq!(find_all(&f, "mac 11:22:33:44:55:66 x"), Vec::<&str>::new());
}

#[test]
fn ip_eui64_eight_groups_is_ip_not_mac() {
    let ip = Ip::default();
    let mac = Mac::default();
    let input = "x 11:22:33:44:55:66:77:88 y";
    assert_eq!(find_str(&ip, input), Some("11:22:33:44:55:66:77:88"));
    assert_eq!(find_all(&mac, input), Vec::<&str>::new());
}

#[test]
fn ip_time_of_day_not_matched() {
    let f = Ip::default();
    assert_eq!(find_all(&f, "meet at 12:30:45 ok"), Vec::<&str>::new());
}

#[test]
fn ip_ratio_not_matched() {
    let f = Ip::default();
    assert_eq!(find_all(&f, "ratio 3:4 x"), Vec::<&str>::new());
}

#[test]
fn ip_rust_path_not_matched() {
    let f = Ip::default();
    assert_eq!(find_all(&f, "use std::vec here"), Vec::<&str>::new());
}

#[test]
fn ip_letter_prefix_v4_asymmetry_by_design() {
    let f = Ip::default();
    assert_eq!(find_str(&f, "v10.0.0.1"), Some("10.0.0.1"));
}

#[test]
fn ip_leading_zero_octets_rejected() {
    let f = Ip::default();
    assert_eq!(find_all(&f, "ip 192.168.01.1 x"), Vec::<&str>::new());
}

// ============================================================================
// Bug 4: CIDR IPv6 charset missing '.' / v4 CIDR mining v6 leftovers
// ============================================================================

#[test]
fn cidr_v6_with_v4_tail_matches() {
    let f = Cidr::default();
    assert_eq!(
        find_str(&f, "range ::ffff:0.0.0.0/96 x"),
        Some("::ffff:0.0.0.0/96")
    );
}

#[test]
fn cidr_nat64_matches_whole_not_bogus_tail() {
    // Was the live FP: the v6 candidate stopped at the first '.', leaving
    // `192.0.2.33/24` for the v4 path.
    let f = Cidr::default();
    let input = "range 64:ff9b::192.0.2.33/24 x";
    assert_eq!(find_str(&f, input), Some("64:ff9b::192.0.2.33/24"));
    assert_eq!(find_all(&f, input), vec!["64:ff9b::192.0.2.33/24"]);
}

#[test]
fn cidr_failed_v6_leftover_not_mined() {
    let f = Cidr::default();
    assert_eq!(find_all(&f, "range 1::2::1.2.3.4/24 x"), Vec::<&str>::new());
    assert_eq!(find_all(&f, "range :::1.2.3.4/24 x"), Vec::<&str>::new());
}

#[test]
fn cidr_colon_prefixed_v4_not_mined() {
    let f = Cidr::default();
    assert_eq!(find_all(&f, "x :10.0.0.0/8 y"), Vec::<&str>::new());
}

#[test]
fn cidr_v4_in_v6_via_try_at() {
    let f = Cidr::default();
    let input = b"64:ff9b::192.0.2.33/24 x";
    assert_eq!(f.try_at(input, 0), Some(0..22));
}

#[test]
fn cidr_bracketed_v6_with_v4_tail() {
    let f = Cidr::default();
    assert_eq!(
        find_str(&f, "net [::ffff:1.2.3.4]/96 ok"),
        Some("[::ffff:1.2.3.4]/96")
    );
}

#[test]
fn cidr_plain_v6_still_matches() {
    let f = Cidr::default();
    assert_eq!(
        find_str(&f, "network 2001:db8::/32 up"),
        Some("2001:db8::/32")
    );
}

// ============================================================================
// Bug 5: CIDR + sentence dot after the prefix number
// ============================================================================

#[test]
fn cidr_v4_followed_by_sentence_dot() {
    let f = Cidr::default();
    assert_eq!(find_str(&f, "subnet 10.0.0.0/8. done"), Some("10.0.0.0/8"));
}

#[test]
fn cidr_v6_followed_by_sentence_dot() {
    let f = Cidr::default();
    assert_eq!(
        find_str(&f, "net 2001:db8::/32. done"),
        Some("2001:db8::/32")
    );
}

#[test]
fn cidr_v4_sentence_dot_at_end_of_line() {
    let f = Cidr::default();
    assert_eq!(find_str(&f, "scan 192.168.1.0/24."), Some("192.168.1.0/24"));
}

#[test]
fn cidr_prefix_dot_digit_still_dead() {
    // `/8.5` is a digit continuation, not a sentence dot.
    let f = Cidr::default();
    assert_eq!(find_all(&f, "x 10.0.0.0/8.5 y"), Vec::<&str>::new());
    assert_eq!(find_all(&f, "x 2001:db8::/32.5 y"), Vec::<&str>::new());
}

#[test]
fn cidr_prefix_glued_letters_leniency_kept() {
    // Pinned leniency: letters straight after the prefix do not veto it.
    let f = Cidr::default();
    assert_eq!(find_str(&f, "1.2.3.4/24extra"), Some("1.2.3.4/24"));
}

#[test]
fn cidr_host_bits_set_still_accepted() {
    let f = Cidr::default();
    assert_eq!(
        find_str(&f, "ip 192.168.1.77/24 x"),
        Some("192.168.1.77/24")
    );
}

#[test]
fn cidr_leading_zero_prefix_still_rejected() {
    let f = Cidr::default();
    assert_eq!(find_all(&f, "10.0.0.0/08"), Vec::<&str>::new());
}

#[test]
fn cidr_prefix_over_limit_still_rejected() {
    let f = Cidr::default();
    assert_eq!(find_all(&f, "192.168.1.0/33"), Vec::<&str>::new());
    assert_eq!(find_all(&f, "2001:db8::/129"), Vec::<&str>::new());
}

// ============================================================================
// Bug 6: dotted (Cisco) MAC + sentence dot
// ============================================================================

#[test]
fn mac_dotted_followed_by_sentence_dot() {
    let f = Mac::default();
    assert_eq!(
        find_str(&f, "port 001A.2B3C.4D5E. up"),
        Some("001A.2B3C.4D5E")
    );
}

#[test]
fn mac_dotted_sentence_dot_at_end_of_line() {
    let f = Mac::default();
    assert_eq!(find_str(&f, "addr 001A.2B3C.4D5E."), Some("001A.2B3C.4D5E"));
}

#[test]
fn mac_dotted_dot_then_hex_still_dead() {
    // A fourth dotted hex group means this is not a 3-group Cisco MAC.
    let f = Mac::default();
    assert_eq!(find_all(&f, "001A.2B3C.4D5E.7788"), Vec::<&str>::new());
    assert_eq!(find_all(&f, "x 001A.2B3C.4D5E.7 y"), Vec::<&str>::new());
}

#[test]
fn mac_dotted_sentence_dot_via_try_at() {
    let f = Mac::default();
    let input = b"port 001A.2B3C.4D5E. up";
    assert_eq!(f.try_at(input, 5), Some(5..19));
}

#[test]
fn mac_colon_followed_by_sentence_dot() {
    // Already worked (boundary only rejects hex or ':'): pin it.
    let f = Mac::default();
    assert_eq!(
        find_str(&f, "dev 00:1A:2B:3C:4D:5E. x"),
        Some("00:1A:2B:3C:4D:5E")
    );
}

#[test]
fn mac_dash_followed_by_sentence_dot() {
    let f = Mac::default();
    assert_eq!(
        find_str(&f, "dev 00-1A-2B-3C-4D-5E. x"),
        Some("00-1A-2B-3C-4D-5E")
    );
}

#[test]
fn mac_colon_form_is_mac_not_ip() {
    let mac = Mac::default();
    let ip = Ip::default();
    let input = "if 11:22:33:44:55:66 up";
    assert_eq!(find_str(&mac, input), Some("11:22:33:44:55:66"));
    assert_eq!(find_all(&ip, input), Vec::<&str>::new());
}

#[test]
fn mac_trailing_hex_still_dead() {
    let f = Mac::default();
    assert_eq!(find_all(&f, "00:1A:2B:3C:4D:5Eff"), Vec::<&str>::new());
    assert_eq!(find_all(&f, "001A.2B3C.4D5Eff"), Vec::<&str>::new());
}

// ============================================================================
// Differential: ip finder acceptance vs std::net::Ipv6Addr
// ============================================================================

#[test]
fn differential_ipv6_acceptance_matches_std() {
    // For unadorned candidates (no zone, no brackets) the ipv6-only finder
    // accepts the exact token if and only if std parses it. Partial matches
    // (trailing ':'/'.' strips) are allowed only when std rejects.
    let finder = ipv6_only();
    let candidates: &[&str] = &[
        // valid
        "::",
        "::1",
        "1::",
        "fe80::1",
        "2001:db8::1",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7::",
        "a:b:c:d:e:f:a:b",
        "64:ff9b::192.0.2.33",
        "1::1.2.3.4",
        "2001:db8::1.2.3.4",
        "1:2:3:4:5::1.2.3.4",
        "1:2:3:4:5:6:1.2.3.4",
        "::ffff:0.0.0.0",
        "::ffff:255.255.255.255",
        "::127.0.0.1",
        "a:b:c:d:e:f:1.2.3.4",
        // invalid
        "1:2:3:4:5:6::1.2.3.4",
        "1:2:3:4:5:6:7:1.2.3.4",
        ":::1.2.3.4",
        "::::1.2.3.4",
        "1::2::1.2.3.4",
        "1::2::3",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7:8:",
        ":1:2:3:4:5:6:7:8",
        ":::",
        "12345::",
        "gggg::1",
        "::1.2.3.4.5",
        "::256.1.1.1",
        "::01.2.3.4",
        "::ffff:1.2.3",
        "1.2.3.4",
        "fe80:",
        "1:2:3:4:5:6:7:8.",
        "fe80::1:",
    ];
    for c in candidates {
        let std_ok = c.parse::<std::net::Ipv6Addr>().is_ok();
        let finder_full = finder.find(c) == Some(0..c.len());
        assert_eq!(
            finder_full, std_ok,
            "finder full-token acceptance disagrees with std on {c:?}"
        );
    }
}

#[test]
fn differential_zone_and_bracket_leniencies() {
    // Documented leniencies on top of std acceptance.
    let f = Ip::default();
    assert_eq!(find_str(&f, "fe80::1%eth0"), Some("fe80::1"));
    assert_eq!(find_str(&f, "[::1]"), Some("[::1]"));
    assert_eq!(
        find_str(&f, "[64:ff9b::192.0.2.33]"),
        Some("[64:ff9b::192.0.2.33]")
    );
    assert!(f.find("[1::2::3]").is_none());
}

// ============================================================================
// Scanner parity: dispatch mode vs the documented find() loop
// ============================================================================

const PARITY_CORPUS: &[&str] = &[
    "prefix 64:ff9b::192.0.2.33 used",
    "x 1::1.2.3.4 y",
    "x 1:2:3:4:5:6::1.2.3.4 y",
    "x :::1.2.3.4 y",
    "x ::::1.2.3.4 y",
    "x 1::2::1.2.3.4 y",
    "x :1.2.3.4 y",
    "x beef:10.0.0.1 y",
    "port:10.0.0.1 dropped",
    "connect to 192.168.1.1:8080 ok",
    "see 2001:db8::1. next",
    "a 1:2:3:4:5:6:7:8. b",
    "addr ::ffff:192.168.1.1. ok",
    "ping 2001:db8::1.",
    "wat 2001:db8::1... hm",
    "see 2001:db8::1.next",
    "ping 192.168.1.1. now",
    "host fe80::1: up",
    "ports 1:2:3:4:5:6:7:8: x",
    "1:2:3:4:5:6:7:8:9",
    "addr 2001:db8:: here",
    "addr fe80::1:x9 end",
    "addr fe80::1%eth0 end",
    "[::1]:8080",
    "conn [64:ff9b::192.0.2.33] ok",
    "mac 11:22:33:44:55:66 x",
    "x 11:22:33:44:55:66:77:88 y",
    "range ::ffff:0.0.0.0/96 x",
    "range 64:ff9b::192.0.2.33/24 x",
    "range 1::2::1.2.3.4/24 x",
    "x :10.0.0.0/8 y",
    "subnet 10.0.0.0/8. done",
    "net 2001:db8::/32. done",
    "scan 192.168.1.0/24.",
    "x 10.0.0.0/8.5 y",
    "1.2.3.4/24extra",
    "net [::ffff:1.2.3.4]/96 ok",
    "port 001A.2B3C.4D5E. up",
    "addr 001A.2B3C.4D5E.",
    "001A.2B3C.4D5E.7788",
    "dev 00:1A:2B:3C:4D:5E. x",
    "dev 00-1A-2B-3C-4D-5E. x",
    "10.0.0.1 and 10.0.0.2",
    "fe80::1: fe80::2: x",
    "サーバ 2001:db8::1。次",
    "🌐fe80::1🌐",
    "网段 10.0.0.0/8。完",
    "ポート 001A.2B3C.4D5E。上",
    "🔌001A.2B3C.4D5E. ok",
];

fn assert_scanner_parity(make: fn() -> Box<dyn Finder>) {
    for input in PARITY_CORPUS {
        let finder = make();
        let mut find_spans: Vec<Range<usize>> = Vec::new();
        let mut idx = 0;
        while idx < input.len() {
            if let Some(range) = finder.find(&input[idx..]) {
                find_spans.push((idx + range.start)..(idx + range.end));
                idx += range.end;
            } else {
                break;
            }
        }
        let scanner = Scanner::new(vec![make()]);
        let scan_spans: Vec<Range<usize>> = scanner
            .scan_line(input)
            .into_iter()
            .map(|m| m.range)
            .collect();
        assert_eq!(find_spans, scan_spans, "parity mismatch on {input:?}");
    }
}

#[test]
fn scanner_parity_ip() {
    assert_scanner_parity(|| Box::new(Ip::default()));
}

#[test]
fn scanner_parity_cidr() {
    assert_scanner_parity(|| Box::new(Cidr::default()));
}

#[test]
fn scanner_parity_mac() {
    assert_scanner_parity(|| Box::new(Mac::default()));
}

#[test]
fn could_start_at_covers_every_match_start() {
    let finders: [fn() -> Box<dyn Finder>; 3] = [
        || Box::new(Ip::default()),
        || Box::new(Cidr::default()),
        || Box::new(Mac::default()),
    ];
    for make in finders {
        for input in PARITY_CORPUS {
            let finder = make();
            let mut idx = 0;
            while idx < input.len() {
                if let Some(range) = finder.find(&input[idx..]) {
                    let start_byte = input.as_bytes()[idx + range.start];
                    assert!(
                        finder.could_start_at(start_byte),
                        "{} match at {:?} starts with uncovered byte {:?} in {input:?}",
                        finder.id(),
                        (idx + range.start)..(idx + range.end),
                        start_byte as char
                    );
                    idx += range.end;
                } else {
                    break;
                }
            }
        }
    }
}

// ============================================================================
// Multibyte boundaries
// ============================================================================

#[test]
fn ip_v6_sentence_dot_next_to_cjk() {
    let f = Ip::default();
    // U+3002 ideographic full stop after the ASCII sentence dot's position.
    assert_eq!(find_str(&f, "サーバ 2001:db8::1。次"), Some("2001:db8::1"));
    assert_eq!(find_str(&f, "サーバ 2001:db8::1. 次"), Some("2001:db8::1"));
}

#[test]
fn ip_v6_between_emoji() {
    let f = Ip::default();
    let input = "🌐fe80::1🌐";
    let range = f.find(input).unwrap();
    assert!(input.is_char_boundary(range.start));
    assert!(input.is_char_boundary(range.end));
    assert_eq!("fe80::1", &input[range]);
}

#[test]
fn cidr_sentence_dot_next_to_cjk() {
    let f = Cidr::default();
    assert_eq!(find_str(&f, "网段 10.0.0.0/8。完"), Some("10.0.0.0/8"));
}

#[test]
fn mac_dotted_next_to_cjk_and_emoji() {
    let f = Mac::default();
    assert_eq!(
        find_str(&f, "ポート 001A.2B3C.4D5E。上"),
        Some("001A.2B3C.4D5E")
    );
    let input = "🔌001A.2B3C.4D5E. ok";
    let range = f.find(input).unwrap();
    assert!(input.is_char_boundary(range.start));
    assert!(input.is_char_boundary(range.end));
    assert_eq!("001A.2B3C.4D5E", &input[range]);
}

#[test]
fn ranges_are_char_boundaries_across_corpus() {
    let finders: [fn() -> Box<dyn Finder>; 3] = [
        || Box::new(Ip::default()),
        || Box::new(Cidr::default()),
        || Box::new(Mac::default()),
    ];
    for make in finders {
        for input in PARITY_CORPUS {
            let scanner = Scanner::new(vec![make()]);
            for m in scanner.scan_line(input) {
                assert!(m.range.start < m.range.end, "empty range in {input:?}");
                assert!(input.is_char_boundary(m.range.start), "{input:?}");
                assert!(input.is_char_boundary(m.range.end), "{input:?}");
            }
        }
    }
}
