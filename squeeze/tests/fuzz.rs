use proptest::prelude::*;
use squeeze::Finder;
use squeeze::scanner::Scanner;
use std::ops::Range;

fn all_finders() -> Vec<Box<dyn Finder>> {
    let mut codetag = squeeze::codetag::Codetag::default();
    codetag.build_mnemonics_regex().unwrap();

    vec![
        Box::new(squeeze::cidr::Cidr::default()),
        Box::new(codetag),
        Box::new(squeeze::color::Color::default()),
        Box::new(squeeze::datetime::Datetime::default()),
        Box::new(squeeze::email::Email::default()),
        Box::new(squeeze::env::Env::default()),
        Box::new(squeeze::hash::Hash::default()),
        Box::new(squeeze::ip::Ip::default()),
        Box::new(squeeze::json::Json::default()),
        Box::new(squeeze::jwt::Jwt::default()),
        Box::new(squeeze::mac::Mac::default()),
        Box::new(squeeze::path::Path::default()),
        Box::new(squeeze::phone::Phone::default()),
        Box::new(squeeze::semver::Semver::default()),
        Box::new(squeeze::uri::URI::default()),
        Box::new(squeeze::uuid::Uuid::default()),
    ]
}

fn old_style_find_all(finder: &dyn Finder, line: &str) -> Vec<Range<usize>> {
    let mut results = Vec::new();
    let mut idx = 0;
    while idx < line.len() {
        if let Some(range) = finder.find(&line[idx..]) {
            results.push((idx + range.start)..(idx + range.end));
            idx += range.end;
        } else {
            break;
        }
    }
    results
}

fn collect_texts(line: &str, ranges: &[Range<usize>]) -> Vec<String> {
    let mut texts: Vec<String> = ranges.iter().map(|r| line[r.clone()].to_string()).collect();
    texts.sort();
    texts
}

// --- Property-based tests ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn no_panic_on_arbitrary_utf8(s in "\\PC{0,200}") {
        let finders = all_finders();
        let scanner = Scanner::new(finders);
        let _ = scanner.scan_line(&s);
    }

    #[test]
    fn no_panic_on_arbitrary_ascii(s in "[\\x00-\\x7f]{0,300}") {
        let finders = all_finders();
        let scanner = Scanner::new(finders);
        let _ = scanner.scan_line(&s);
    }

    #[test]
    fn match_ranges_are_valid(s in "\\PC{0,200}") {
        let finders = all_finders();
        let scanner = Scanner::new(finders);
        for m in scanner.scan_line(&s) {
            prop_assert!(m.range.start <= m.range.end);
            prop_assert!(m.range.end <= s.len());
            prop_assert!(m.finder_index < scanner.finders().len());
            // The range must be valid UTF-8 boundaries
            prop_assert!(s.is_char_boundary(m.range.start));
            prop_assert!(s.is_char_boundary(m.range.end));
        }
    }

    #[test]
    fn matches_are_position_sorted(s in "\\PC{0,200}") {
        let finders = all_finders();
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line(&s);
        for w in matches.windows(2) {
            prop_assert!(w[0].range.start <= w[1].range.start);
        }
    }

    #[test]
    fn scan_line_first_returns_earliest(s in "\\PC{0,200}") {
        let finders = all_finders();
        let scanner = Scanner::new(finders);
        let all = scanner.scan_line(&s);
        let first = scanner.scan_line_first(&s);
        match (all.first(), first) {
            (None, None) => {} // OK
            (Some(a), Some(f)) => {
                prop_assert!(f.range.start <= a.range.start);
            }
            (Some(_), None) => {
                prop_assert!(false, "scan_line found matches but scan_line_first didn't");
            }
            (None, Some(_)) => {
                prop_assert!(false, "scan_line_first found match but scan_line didn't");
            }
        }
    }
}

// --- Scanner consistency: dispatch finders ---
// For each dispatchable finder, verify try_at-based scanning
// produces the same matches as find()-based scanning.

fn check_dispatch_consistency(finder: Box<dyn Finder>, input: &str) {
    let old = old_style_find_all(finder.as_ref(), input);
    let scanner = Scanner::new(vec![finder]);
    let new: Vec<Range<usize>> = scanner
        .scan_line(input)
        .into_iter()
        .map(|m| m.range)
        .collect();
    let old_texts = collect_texts(input, &old);
    let new_texts = collect_texts(input, &new);
    assert_eq!(old_texts, new_texts, "Mismatch on input: {:?}", input);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn hash_dispatch_consistent(s in "[a-f0-9 A-F]{0,200}") {
        check_dispatch_consistency(Box::new(squeeze::hash::Hash::default()), &s);
    }

    #[test]
    fn env_dispatch_consistent(s in "[a-zA-Z0-9_$ {}]{0,100}") {
        check_dispatch_consistency(Box::new(squeeze::env::Env::default()), &s);
    }

    #[test]
    fn color_dispatch_consistent(s in "[#a-fA-F0-9rgbhslRGBHSL() ,%.]{0,100}") {
        check_dispatch_consistency(Box::new(squeeze::color::Color::default()), &s);
    }

    #[test]
    fn json_dispatch_consistent(s in r#"[{}\[\]"a-z:, 0-9\\]{0,100}"#) {
        check_dispatch_consistency(Box::new(squeeze::json::Json::default()), &s);
    }

    #[test]
    fn uuid_dispatch_consistent(s in "[a-f0-9\\- ]{0,100}") {
        check_dispatch_consistency(Box::new(squeeze::uuid::Uuid::default()), &s);
    }

    #[test]
    fn mac_dispatch_consistent(s in "[a-fA-F0-9:.\\- ]{0,60}") {
        check_dispatch_consistency(Box::new(squeeze::mac::Mac::default()), &s);
    }

    #[test]
    fn ip_dispatch_consistent(s in "[0-9.:a-f\\[\\] ]{0,80}") {
        check_dispatch_consistency(Box::new(squeeze::ip::Ip::default()), &s);
    }

    #[test]
    fn datetime_dispatch_consistent(s in "[0-9\\-T:Z+. ]{0,60}") {
        check_dispatch_consistency(Box::new(squeeze::datetime::Datetime::default()), &s);
    }

    #[test]
    fn semver_dispatch_consistent(s in "[0-9.vV\\-+a-z ]{0,60}") {
        check_dispatch_consistency(Box::new(squeeze::semver::Semver::default()), &s);
    }

    #[test]
    fn jwt_dispatch_consistent(s in "[a-zA-Z0-9+/=._\\- ]{0,200}") {
        check_dispatch_consistency(Box::new(squeeze::jwt::Jwt::default()), &s);
    }

    #[test]
    fn cidr_dispatch_consistent(s in "[0-9.:/a-f ]{0,60}") {
        check_dispatch_consistency(Box::new(squeeze::cidr::Cidr::default()), &s);
    }

    #[test]
    fn path_dispatch_consistent(s in "[a-z/.~\\- :0-9 ]{0,60}") {
        check_dispatch_consistency(Box::new(squeeze::path::Path::default()), &s);
    }
}

// --- Fuzz: no panics with individual finders on arbitrary input ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn hash_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::hash::Hash::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn ip_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::ip::Ip::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn email_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::email::Email::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn json_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::json::Json::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn uri_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::uri::URI::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn datetime_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::datetime::Datetime::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn env_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::env::Env::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn uuid_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::uuid::Uuid::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn mac_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::mac::Mac::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn semver_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::semver::Semver::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn color_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::color::Color::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn cidr_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::cidr::Cidr::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn path_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::path::Path::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn phone_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::phone::Phone::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn jwt_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::jwt::Jwt::default();
        let _ = finder.find(&s);
    }

    #[test]
    fn mirror_no_panic(s in "\\PC{0,200}") {
        let finder = squeeze::mirror::Mirror::default();
        let _ = finder.find(&s);
    }
}

// --- Fuzz: try_at no panics on arbitrary positions ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn hash_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::hash::Hash::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn ip_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::ip::Ip::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn env_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::env::Env::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn uuid_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::uuid::Uuid::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn color_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::color::Color::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn mac_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::mac::Mac::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn datetime_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::datetime::Datetime::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn semver_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::semver::Semver::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn jwt_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::jwt::Jwt::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn path_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::path::Path::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn cidr_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::cidr::Cidr::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }
}

// --- Fuzz: mixed patterns with embedded valid tokens ---

fn hash_md5() -> &'static str {
    "5d41402abc4b2a76b9719d911017c592"
}

fn sample_email() -> &'static str {
    "user@example.com"
}

fn sample_ip() -> &'static str {
    "192.168.1.1"
}

fn sample_uuid() -> &'static str {
    "550e8400-e29b-41d4-a716-446655440000"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn scanner_with_embedded_hash(
        prefix in "[^a-fA-F0-9]{0,20}",
        suffix in "[^a-fA-F0-9]{0,20}"
    ) {
        let input = format!("{}{}{}", prefix, hash_md5(), suffix);
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(squeeze::hash::Hash::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line(&input);
        prop_assert_eq!(matches.len(), 1);
        prop_assert_eq!(&input[matches[0].range.clone()], hash_md5());
    }

    #[test]
    fn scanner_with_embedded_email(
        prefix in "[^a-zA-Z0-9.!#$%&'*+/=?^_`{|}~\\-]{0,20}",
        suffix in "[ \\t\\n]{0,5}"
    ) {
        let input = format!("{}{}{}", prefix, sample_email(), suffix);
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(squeeze::email::Email::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line(&input);
        prop_assert_eq!(matches.len(), 1);
        prop_assert_eq!(&input[matches[0].range.clone()], sample_email());
    }

    #[test]
    fn scanner_with_embedded_ip(
        prefix in "[^0-9.:a-fA-F\\[\\]]{0,20}",
        suffix in "[^0-9.:a-fA-F\\[\\]]{0,20}"
    ) {
        let input = format!("{}{}{}", prefix, sample_ip(), suffix);
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(squeeze::ip::Ip::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line(&input);
        prop_assert_eq!(matches.len(), 1);
        prop_assert_eq!(&input[matches[0].range.clone()], sample_ip());
    }

    #[test]
    fn scanner_with_embedded_uuid(
        prefix in "[^a-fA-F0-9\\-]{0,20}",
        suffix in "[^a-fA-F0-9\\-]{0,20}"
    ) {
        let input = format!("{}{}{}", prefix, sample_uuid(), suffix);
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(squeeze::uuid::Uuid::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line(&input);
        prop_assert_eq!(matches.len(), 1);
        prop_assert_eq!(&input[matches[0].range.clone()], sample_uuid());
    }
}

// --- Targeted consistency on known-good inputs ---

#[test]
fn dispatch_consistent_hash_known() {
    let cases = [
        "5d41402abc4b2a76b9719d911017c592",
        "md5: 5d41402abc4b2a76b9719d911017c592 end",
        "5d41402abc4b2a76b9719d911017c592 and 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
        "a5d41402abc4b2a76b9719d911017c592",
        "",
        "no hex here",
        "abcdef",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::hash::Hash::default()), input);
    }
}

#[test]
fn dispatch_consistent_env_known() {
    let cases = [
        "$HOME",
        "${PATH}",
        "$HOME and ${PATH}",
        "$",
        "$$",
        "$123",
        "${} foo",
        "${HOME",
        "",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::env::Env::default()), input);
    }
}

#[test]
fn dispatch_consistent_json_known() {
    let cases = [
        r#"{"key": "value"}"#,
        r#"{unclosed {"valid": true}"#,
        r#"[1, [2, 3]]"#,
        "{}",
        "[]",
        "{",
        "",
        r#"{"a": "}"}"#,
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::json::Json::default()), input);
    }
}

#[test]
fn dispatch_consistent_ip_known() {
    let cases = [
        "192.168.1.1",
        "10.0.0.1 and 10.0.0.2",
        "256.1.1.1",
        "[::1]",
        "2001:db8::1",
        "",
        "999.999.999.999",
        "1.2.3.4.5",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::ip::Ip::default()), input);
    }
}

#[test]
fn dispatch_consistent_datetime_known() {
    let cases = [
        "2024-01-15",
        "2024-01-15T10:30:00Z",
        "2024-01-15T10:30:00+05:30",
        "2024-13-01",
        "12024-01-15",
        "",
        "2024-01-155",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::datetime::Datetime::default()), input);
    }
}

#[test]
fn dispatch_consistent_uuid_known() {
    let cases = [
        "550e8400-e29b-41d4-a716-446655440000",
        "id: 550e8400-e29b-41d4-a716-446655440000 end",
        "ff550e8400-e29b-41d4-a716-446655440000",
        "550e8400-e29b-41d4-a716-446655440000ff",
        "",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::uuid::Uuid::default()), input);
    }
}

#[test]
fn dispatch_consistent_path_known() {
    let cases = [
        "/etc/hosts",
        "see /etc/hosts for details",
        "./src/main.rs",
        "../README.md",
        "~/.bashrc",
        "a / b",
        "",
        "https://example.com/path",
        "/var/log/syslog, /tmp/out",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::path::Path::default()), input);
    }
}

#[test]
fn dispatch_consistent_semver_known() {
    let cases = [
        "1.0.0",
        "v2.3.1",
        "v1.0.0-rc.1",
        "1.0.0+build.42",
        "1.0",
        "192.168.1.1",
        "",
        "a1.0.0",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::semver::Semver::default()), input);
    }
}

#[test]
fn dispatch_consistent_color_known() {
    let cases = [
        "#ff00aa",
        "#f0a",
        "rgb(255, 0, 170)",
        "hsla(120, 100%, 50%, 0.8)",
        "color: #333;",
        "#ff0000 and rgb(0, 255, 0)",
        "",
        "#gg",
        "srgb(1, 2, 3)",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::color::Color::default()), input);
    }
}

#[test]
fn dispatch_consistent_mac_known() {
    let cases = [
        "00:1A:2B:3C:4D:5E",
        "00-1A-2B-3C-4D-5E",
        "001A.2B3C.4D5E",
        "ff00:1A:2B:3C:4D:5E",
        "",
        "00:1A:2B:3C:4D",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::mac::Mac::default()), input);
    }
}

#[test]
fn dispatch_consistent_jwt_known() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let cases = [
        jwt,
        &format!("token: {} end", jwt),
        &format!("x{}", jwt),
        "abc.def.ghi",
        "",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::jwt::Jwt::default()), input);
    }
}

#[test]
fn dispatch_consistent_cidr_known() {
    let cases = [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "2001:db8::/32",
        "::1/128",
        "192.168.1.0/33",
        "192.168.1.1",
        "",
    ];
    for input in &cases {
        check_dispatch_consistency(Box::new(squeeze::cidr::Cidr::default()), input);
    }
}
