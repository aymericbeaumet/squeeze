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

#[test]
fn scan_line_first_considers_trigger_matches_starting_before_trigger() {
    let finders = all_finders();
    let scanner = Scanner::new(finders);

    for s in ["a+::\u{2000}", "𝒥A+::"] {
        let all = scanner.scan_line(s);
        let first = scanner.scan_line_first(s);
        let earliest = all.iter().map(|m| m.range.start).min();

        assert_eq!(first.as_ref().map(|m| m.range.start), earliest, "{s:?}");
    }
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
                // scan_line_first must return exactly scan_line()[0]:
                // same start, same finder (ties broken by index), same end.
                prop_assert_eq!(f.range.start, a.range.start);
                prop_assert_eq!(f.finder_index, a.finder_index);
                prop_assert_eq!(f.range.end, a.range.end);
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
    fn domain_trigger_consistent(
        s in "( |\\.|\\.\\.|@|/|:|-|_|\\(|\\)|,|[a-z]{1,4}|[0-9]{1,3}|com|org|uk|co\\.uk|museum|x|example\\.com|user@|https?://|bücher|ü|ß|日本|😀|\\+tag|first\\.last|192\\.168\\.1\\.1|v2){0,14}"
    ) {
        check_dispatch_consistency(Box::new(squeeze::domain::Domain::default()), &s);
    }

    #[test]
    fn domain_trigger_consistent_on_arbitrary_input(s in "\\PC{0,80}") {
        check_dispatch_consistency(Box::new(squeeze::domain::Domain::default()), &s);
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

    #[test]
    fn uri_trigger_consistent(s in "[a-zA-Z0-9:/?#.\\-_&=%+ ]{0,160}") {
        check_dispatch_consistency(Box::new(squeeze::uri::URI::default()), &s);
    }

    #[test]
    fn email_trigger_consistent(s in "[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~@\\-. ]{0,120}") {
        check_dispatch_consistency(Box::new(squeeze::email::Email::default()), &s);
    }

    #[test]
    fn phone_dispatch_consistent(s in "[0-9+().\\- a-zA-Z]{0,100}") {
        check_dispatch_consistency(Box::new(squeeze::phone::Phone::default()), &s);
    }

    #[test]
    fn modeline_dispatch_consistent(s in "[a-zA-Z0-9_=:.,\\-/ ]{0,100}") {
        check_dispatch_consistency(Box::new(squeeze::modeline::Modeline::default()), &s);
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

    #[test]
    fn json_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::json::Json::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn phone_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::phone::Phone::default();
        let input = s.as_bytes();
        for pos in 0..input.len() {
            let _ = finder.try_at(input, pos);
        }
    }

    #[test]
    fn modeline_try_at_no_panic(s in "[\\x00-\\x7f]{1,100}") {
        let finder = squeeze::modeline::Modeline::default();
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

    // The prefix is safe junk that cannot change the email's meaning: no
    // local-part chars (would extend the local part), no '@' (would turn it
    // into a fediverse handle, which email rejects by design), and no 2-byte
    // UTF-8 chars (glued-word truncation is rejected by design). The CJK char
    // pins the 3-byte-glue acceptance policy.
    #[test]
    fn scanner_with_embedded_email(
        prefix in "[ \\t(),;:<>\\[\\]\"火]{0,20}",
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

/// Every dispatch finder, including the ones the scanner-level suites leave
/// out, so the gate contract is checked for the complete set.
fn dispatch_finders() -> Vec<Box<dyn Finder>> {
    let mut hash = squeeze::hash::Hash::default();
    for algorithm in ["md5", "sha1", "sha256", "sha512"] {
        assert!(hash.add_algorithm(algorithm));
    }
    vec![
        Box::new(squeeze::cidr::Cidr::default()),
        Box::new(squeeze::color::Color::default()),
        Box::new(squeeze::datetime::Datetime::default()),
        Box::new(squeeze::emoji::Emoji::default()),
        Box::new(squeeze::env::Env::default()),
        Box::new(squeeze::handle::Handle::default()),
        Box::new(hash),
        Box::new(squeeze::ip::Ip::default()),
        Box::new(squeeze::ip::Ip {
            ipv4: true,
            ipv6: false,
        }),
        Box::new(squeeze::ip::Ip {
            ipv4: false,
            ipv6: true,
        }),
        Box::new(squeeze::json::Json::default()),
        Box::new(squeeze::jwt::Jwt::default()),
        Box::new(squeeze::mac::Mac::default()),
        Box::new(squeeze::path::Path::default()),
        Box::new(squeeze::semver::Semver::default()),
        Box::new(squeeze::uuid::Uuid::default()),
        Box::new(squeeze::email::Email::default()),
        Box::new(squeeze::uri::URI::default()),
        Box::new({
            let mut strict = squeeze::uri::URI::default();
            strict.strict = true;
            strict
        }),
    ]
}

/// The scanner skips `try_at` wherever a gate says no, so a gate that is
/// stricter than its finder would silently lose matches. Check the contract
/// at every position of the input, whatever the scanner would have done.
fn assert_gates_agree(finders: &[Box<dyn Finder>], line: &str) {
    let input = line.as_bytes();
    for finder in finders {
        let trigger = finder.triggerable();
        assert!(finder.dispatchable() || trigger);
        for pos in 0..input.len() {
            let cur = input[pos];
            if trigger {
                if !finder.could_trigger_at(cur) {
                    continue;
                }
                let gated = (pos > 0 && !finder.could_start_after(input[pos - 1], cur))
                    || (pos + 1 < input.len() && !finder.could_continue_with(cur, input[pos + 1]));
                if gated {
                    assert_eq!(
                        finder.try_trigger_at(input, pos),
                        None,
                        "{} trigger gate rejected {line:?} at {pos} but try_trigger_at matched",
                        finder.id()
                    );
                }
                continue;
            }
            if !finder.could_start_at(cur) {
                continue;
            }
            let gated_prev = pos > 0 && !finder.could_start_after(input[pos - 1], cur);
            let gated_next =
                pos + 1 < input.len() && !finder.could_continue_with(cur, input[pos + 1]);
            let rules = finder.run_rules();
            let gated_run =
                !squeeze::RunRule::allow(&rules, cur, &squeeze::Runs::at(input, pos), input, pos);
            if gated_prev || gated_next || gated_run {
                assert_eq!(
                    finder.try_at(input, pos),
                    None,
                    "{} gate rejected {line:?} at {pos} (prev gate: {gated_prev}, next gate: {gated_next}, run gate: {gated_run}) but try_at matched",
                    finder.id()
                );
            }
        }
    }
}

#[test]
fn dispatch_gates_hold_on_shaped_tokens() {
    for line in [
        "fe80::1%eth0",
        "a::b ",
        "a::b)",
        "a:b:: x",
        "a:b::c/64",
        "1:2:3:4:5:6:7:8",
        "1::",
        "12:34:56 ",
        "12:34",
        "3.14 ",
        "1.2.3.4",
        "10.0.0.0/8",
        "2001:db8::/32",
        "2024-01-15T10:00:00Z",
        "1.2.3-rc.1",
        "aa:bb:cc:dd:ee:ff",
        "aaaa.bbbb.cccc",
        "123-456-7890",
        "123.456.7890",
        "١٢٣-456-7890",
        "12٣-456-7890",
        "123-٤٥٦-7890",
        "123-45٦-7890",
        "123-456-٧٨٩٠",
        "123-456-78٩0",
        "550e8400-e29b-41d4-a716-446655440000",
    ] {
        assert_gates_agree(&dispatch_finders(), line);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn dispatch_gates_never_reject_a_match_on_dense_input(
        s in "[0-9a-fA-FgGsSyYxzRHrhe.:/@$#{}\\[\\]()<>\"'`=+~_ %?!,;*&-]{0,48}"
    ) {
        assert_gates_agree(&dispatch_finders(), &s);
    }

    #[test]
    fn dispatch_gates_never_reject_a_match_on_shaped_tokens(
        s in "( |-|\\.|:|/|x|[0-9]{1,4}|[0-9]{3}-[0-9]{3}-[0-9]{4}|[0-9]{3}\\.[0-9]{3}\\.[0-9]{4}|[0-9]{3}-[0-9]{3}-[٠-٩]{4}|[0-9]{3}-[٠-٩][0-9]{2}-[0-9]{4}|١٢٣-456-7890|12٣-456-7890|123-٤٥٦-7890|123-45٦-7890|123-456-٧٨٩٠|123-456-78٩0|\\+1 415 555 1234|\\(415\\) 555-1234|[0-9]{1,3}(\\.[0-9]{1,3}){3}|[0-9a-f]{1,4}(:[0-9a-f]{0,4}){1,7}|a::b|a:b::|::1|1::|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9A-F]{2}([:-][0-9A-F]{2}){5}|[0-9A-F]{4}(\\.[0-9A-F]{4}){2}|20[0-9]{2}-[01][0-9]-[0-3][0-9]|v?[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}|3\\.14|12:34:56|12:34|10\\.0\\.0\\.0/8|2001:db8::/32){0,10}"
    ) {
        assert_gates_agree(&dispatch_finders(), &s);
    }

    #[test]
    fn dispatch_gates_never_reject_a_match_on_long_runs(
        s in "( |-|:|\\.|/|x|[0-9a-f]{28,45}|[0-9a-f]{60,70}|[0-9a-f]{125,135}|[0-9]{1,5}|[0-9]{126,132}){1,6}"
    ) {
        assert_gates_agree(&dispatch_finders(), &s);
    }

    #[test]
    fn dispatch_gates_never_reject_a_match_on_structured_input(
        s in "( |\\.|:|/|@|-|_|[a-z]{1,4}|v?[0-9]{1,4}|0x[0-9a-f]{2,8}|#[0-9a-fA-F]{3,8}|rgb\\([0-9, ]{5,11}\\)|\\$\\{?[A-Z_]{1,6}\\}?|eyJ[a-zA-Z0-9_-]{2,10}|[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,2})?|[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9A-F]{2}(:[0-9A-F]{2}){5}|20[0-9]{2}-[01][0-9]-[0-3][0-9](T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z?)?|[0-9a-f]{32}|[0-9a-f]{40}|[0-9]️⃣|#️⃣|😀|🎉|©|~/[a-z]{1,4}|\\./[a-z]{1,4}|/[a-z]{1,4}(/[a-z]{1,4})*|\\{\"[a-z]{1,3}\": [0-9]{1,3}\\}|\\[[0-9, ]{0,6}\\]){0,12}"
    ) {
        assert_gates_agree(&dispatch_finders(), &s);
    }

    #[test]
    fn dispatch_gates_never_reject_a_match_on_arbitrary_input(s in "\\PC{0,40}") {
        assert_gates_agree(&dispatch_finders(), &s);
    }
}

/// One scanner per strategy and backend, built once: constructing the gate
/// tables is far more expensive than a scan, especially in debug builds.
fn strategy_scanners() -> &'static [Scanner] {
    static SCANNERS: std::sync::OnceLock<Vec<Scanner>> = std::sync::OnceLock::new();
    SCANNERS.get_or_init(|| {
        let mut scanners = Vec::new();
        for &strategy in squeeze::scanner::Strategy::ALL {
            for scalar in [false, true] {
                let mut scanner = Scanner::new(all_finders());
                scanner.set_strategy(strategy);
                if scalar {
                    scanner.use_scalar_backend();
                }
                scanners.push(scanner);
            }
        }
        scanners
    })
}

/// Strategies and backends must agree byte for byte: the vector stage may
/// only ever add candidates that the exact gates then reject.
fn assert_strategies_agree(line: &str) {
    let scanners = strategy_scanners();
    let reference = scanners[0].scan_line(line);
    assert_eq!(scanners[0].strategy(), squeeze::scanner::Strategy::Legacy);
    for scanner in scanners {
        let got = scanner.scan_line(line);
        assert_eq!(
            got,
            reference,
            "{} ({}) disagrees with legacy on {line:?}",
            scanner.strategy().name(),
            scanner.backend()
        );
        let first = scanner.scan_line_first(line);
        assert_eq!(first, reference.first().cloned(), "first match on {line:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn strategies_agree_on_dense_input(
        s in "[0-9a-fA-FgGsSyYxzRHrhe.:/@$#{}\\[\\]()<>\"'`=+~_ -]{0,70}"
    ) {
        assert_strategies_agree(&s);
    }

    #[test]
    fn strategies_agree_on_structured_input(
        s in "( |\\.|:|/|@|-|_|[a-z]{1,4}|v?[0-9]{1,4}|0x[0-9a-f]{2,8}|#[0-9a-fA-F]{3,8}|rgb\\([0-9, ]{5,11}\\)|\\$\\{?[A-Z_]{1,6}\\}?|eyJ[a-zA-Z0-9_-]{2,10}|[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,2})?|[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9A-F]{2}(:[0-9A-F]{2}){5}|20[0-9]{2}-[01][0-9]-[0-3][0-9](T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z?)?|[0-9a-f]{32}|[0-9a-f]{40}|[0-9]️⃣|#️⃣|😀|🎉|©|~/[a-z]{1,4}|\\./[a-z]{1,4}|/[a-z]{1,4}(/[a-z]{1,4})*|\\{\"[a-z]{1,3}\": [0-9]{1,3}\\}|\\[[0-9, ]{0,6}\\]|https?://[a-z]{2,6}\\.[a-z]{2,3}(/[a-z0-9]{1,5})*|[a-z]{2,5}@[a-z]{2,5}\\.(com|org)|TODO: |vim: set ts=4:|\\+1-415-555-[0-9]{4}){0,14}"
    ) {
        assert_strategies_agree(&s);
    }

    #[test]
    fn strategies_agree_on_arbitrary_input(s in "\\PC{0,50}") {
        assert_strategies_agree(&s);
    }
}

#[test]
fn strategies_agree_around_block_boundaries() {
    // Matches straddling or touching 16-byte block edges, at every offset.
    let items = [
        "5d41402abc4b2a76b9719d911017c592",
        "550e8400-e29b-41d4-a716-446655440000",
        "https://example.com/a",
        "user@example.com",
        "192.168.1.1",
        "2024-01-15T10:30:00Z",
        "$HOME",
        "#ff00aa",
        "./src/main.rs",
        "1️⃣",
        "😀",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
        "00:1A:2B:3C:4D:5E",
        "v1.2.3",
        "{\"a\": 1}",
    ];
    for item in items {
        for pad in 0..40 {
            let line = format!("{}{item}{}", "x".repeat(pad), " tail".repeat(pad % 3));
            assert_strategies_agree(&line);
            let line = format!("{}{item}", " ".repeat(pad));
            assert_strategies_agree(&line);
        }
    }
}

/// `scan_buffer` must report exactly what `scan_line` reports for every
/// line of the buffer, with line offsets, terminators and `\r`s handled
/// as the CLI's per-line path does.
fn assert_buffer_agrees(text: &str) {
    let scanners = strategy_scanners();
    let reference = &scanners[0]; // legacy, per line
    let mut expected = Vec::new();
    let mut pos = 0;
    let bytes = text.as_bytes();
    while pos < bytes.len() {
        let nl = bytes[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |i| pos + i);
        let mut end = nl;
        while end > pos && bytes[end - 1] == b'\r' {
            end -= 1;
        }
        let matches = reference.scan_line(&text[pos..end]);
        if !matches.is_empty() {
            expected.push((pos, end, matches));
        }
        pos = nl + 1;
    }
    for scanner in scanners {
        let mut got = Vec::new();
        let stopped = scanner.scan_buffer(text, |start, end, matches| {
            got.push((start, end, matches.to_vec()));
            false
        });
        assert!(!stopped);
        assert_eq!(
            got,
            expected,
            "{} ({}) scan_buffer disagrees with per-line scanning on {text:?}",
            scanner.strategy().name(),
            scanner.backend()
        );
        // Stopping after the first emitted line.
        if let Some(first) = expected.first() {
            let mut seen = Vec::new();
            let stopped = scanner.scan_buffer(text, |start, end, matches| {
                seen.push((start, end, matches.to_vec()));
                true
            });
            assert!(stopped);
            assert_eq!(seen, vec![first.clone()]);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn scan_buffer_agrees_with_per_line_scanning(
        lines in proptest::collection::vec(
            "( |\\.|:|/|@|-|_|\r|[a-z]{1,4}|v?[0-9]{1,4}|0x[0-9a-f]{2,8}|#[0-9a-fA-F]{3,8}|\\$\\{?[A-Z_]{1,6}\\}?|eyJ[a-zA-Z0-9_-]{2,10}|[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,2})?|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9A-F]{2}(:[0-9A-F]{2}){5}|20[0-9]{2}-[01][0-9]-[0-3][0-9](T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z?)?|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|😀|©|~/[a-z]{1,4}|/[a-z]{1,4}(/[a-z]{1,4})*|\\{\"[a-z]{1,3}\": [0-9]{1,3}\\}|https?://[a-z]{2,6}\\.[a-z]{2,3}(/[a-z0-9]{1,5})*|[a-z]{2,5}@[a-z]{2,5}\\.(com|org)|TODO: |vim: set ts=4:|\\+1-415-555-[0-9]{4}){0,10}",
            0..8
        ),
        crlf in proptest::bool::ANY,
        trailing_newline in proptest::bool::ANY,
    ) {
        let sep = if crlf { "\r\n" } else { "\n" };
        let mut text = lines.join(sep);
        if trailing_newline {
            text.push_str(sep);
        }
        assert_buffer_agrees(&text);
    }

    #[test]
    fn scan_buffer_agrees_on_arbitrary_input(s in "(\\PC|\n|\r){0,120}") {
        assert_buffer_agrees(&s);
        assert_sparse_buffers_agree(&s);
    }

    #[test]
    fn sparse_scan_buffer_agrees_on_structured_lines(
        lines in proptest::collection::vec(
            "( |:|/|@|\\.|-|\r|[a-z]{1,4}|[0-9]{1,4}|https?://[a-z]{2,6}\\.[a-z]{2,3}(/[a-z0-9]{1,5})*|mailto:[a-z]{2,5}@[a-z]{2,5}\\.com|[a-z]{2,5}@[a-z]{2,5}\\.(com|org)|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\\$\\{?[A-Z_]{1,6}\\}?|~/[a-z]{1,4}|/[a-z]{1,4}(/[a-z]{1,4})*|[0-9]{1,3}(\\.[0-9]{1,3}){3}|[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}){0,10}",
            0..8
        ),
        crlf in proptest::bool::ANY,
    ) {
        let sep = if crlf { "\r\n" } else { "\n" };
        let text = lines.join(sep);
        assert_sparse_buffers_agree(&text);
    }
}

#[test]
fn scan_buffer_handles_edges() {
    for text in [
        "",
        "\n",
        "\r\n\r\n",
        "a@b.co",
        "a@b.co\n",
        "\na@b.co",
        "x\n\n5d41402abc4b2a76b9719d911017c592\r\n\nhttps://e.com\n",
        "550e8400-e29b-41d4-a716-446655440000\n192.168.1.1\n$HOME\n",
        &format!("{}\n{}", "1".repeat(200), "a@b.co ".repeat(40)),
        &format!("{}\r\nend@x.io", "deadbeef".repeat(20)),
    ] {
        assert_buffer_agrees(text);
    }
}

/// Anchor contract: every dispatch match contains an anchor byte, reached
/// from the match start over `walk` bytes only.
fn assert_anchors_hold(finders: &[Box<dyn Finder>], line: &str) {
    let input = line.as_bytes();
    for finder in finders {
        let Some(anchor) = finder.anchor() else {
            continue;
        };
        for pos in 0..input.len() {
            if !finder.could_start_at(input[pos]) {
                continue;
            }
            if let Some(range) = finder.try_at(input, pos) {
                let first = range
                    .clone()
                    .find(|&i| anchor.bytes.contains(input[i]))
                    .unwrap_or_else(|| {
                        panic!(
                            "{} match {:?} in {line:?} has no anchor byte",
                            finder.id(),
                            range
                        )
                    });
                for (i, &b) in input.iter().enumerate().take(first).skip(range.start) {
                    assert!(
                        anchor.walk.contains(b),
                        "{} match {:?} in {line:?}: byte {i} before the anchor is not a walk byte",
                        finder.id(),
                        range
                    );
                }
            }
        }
    }
}

/// Every anchored finder scanned alone uses the anchor plan; it must agree
/// with the plain dispatch walk of the legacy strategy.
fn anchored_pairs() -> &'static [(Scanner, Scanner)] {
    static PAIRS: std::sync::OnceLock<Vec<(Scanner, Scanner)>> = std::sync::OnceLock::new();
    PAIRS.get_or_init(|| {
        let singles: Vec<Box<dyn Fn() -> Box<dyn Finder>>> = vec![
            Box::new(|| Box::new(squeeze::uuid::Uuid::default())),
            Box::new(|| Box::new(squeeze::ip::Ip::default())),
            Box::new(|| {
                Box::new(squeeze::ip::Ip {
                    ipv4: true,
                    ipv6: false,
                })
            }),
            Box::new(|| {
                Box::new(squeeze::ip::Ip {
                    ipv4: false,
                    ipv6: true,
                })
            }),
            Box::new(|| Box::new(squeeze::cidr::Cidr::default())),
            Box::new(|| Box::new(squeeze::datetime::Datetime::default())),
            Box::new(|| Box::new(squeeze::semver::Semver::default())),
            Box::new(|| Box::new(squeeze::mac::Mac::default())),
            Box::new(|| Box::new(squeeze::color::Color::default())),
        ];
        let mut pairs = Vec::new();
        for make in &singles {
            let anchored = Scanner::new(vec![make()]);
            assert!(
                anchored.plan().starts_with("anchors("),
                "{}: {}",
                anchored.finders()[0].id(),
                anchored.plan()
            );
            let _ = &anchored;
            let mut legacy = Scanner::new(vec![make()]);
            legacy.set_strategy(squeeze::scanner::Strategy::Legacy);
            pairs.push((anchored, legacy));
        }
        // Block-plan scanners with a minimum hex run: hash alone, and a
        // single algorithm.
        for make in [
            (|| Box::new(squeeze::hash::Hash::default()) as Box<dyn Finder>)
                as fn() -> Box<dyn Finder>,
            || {
                let mut hash = squeeze::hash::Hash::default();
                assert!(hash.add_algorithm("sha256"));
                Box::new(hash)
            },
            || {
                let mut hash = squeeze::hash::Hash::default();
                assert!(hash.add_algorithm("md5"));
                Box::new(hash)
            },
        ] {
            let fast = Scanner::new(vec![make()]);
            assert_eq!(fast.plan(), "blocks");
            let mut legacy = Scanner::new(vec![make()]);
            legacy.set_strategy(squeeze::scanner::Strategy::Legacy);
            pairs.push((fast, legacy));
        }
        // Two anchored finders together, and an anchored finder with a trigger one.
        let mut legacy = Scanner::new(vec![
            Box::new(squeeze::datetime::Datetime::default()),
            Box::new(squeeze::ip::Ip::default()),
        ]);
        legacy.set_strategy(squeeze::scanner::Strategy::Legacy);
        pairs.push((
            Scanner::new(vec![
                Box::new(squeeze::datetime::Datetime::default()),
                Box::new(squeeze::ip::Ip::default()),
            ]),
            legacy,
        ));
        let mut legacy = Scanner::new(vec![
            Box::new(squeeze::uuid::Uuid::default()),
            Box::new(squeeze::email::Email::default()),
        ]);
        legacy.set_strategy(squeeze::scanner::Strategy::Legacy);
        pairs.push((
            Scanner::new(vec![
                Box::new(squeeze::uuid::Uuid::default()),
                Box::new(squeeze::email::Email::default()),
            ]),
            legacy,
        ));
        pairs
    })
}

/// Scanners that walk whole buffers (memchr passes, line-agnostic finders
/// probed with absolute positions, block passes resolving lines lazily)
/// must agree with per-line scanning.
fn assert_sparse_buffers_agree(text: &str) {
    let scanners = buffer_scanners();
    for (fast, legacy) in scanners {
        let mut expected = Vec::new();
        let bytes = text.as_bytes();
        let mut pos = 0;
        while pos < bytes.len() {
            let nl = bytes[pos..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(bytes.len(), |i| pos + i);
            let mut end = nl;
            while end > pos && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            let matches = legacy.scan_line(&text[pos..end]);
            if !matches.is_empty() {
                expected.push((pos, end, matches));
            }
            pos = nl + 1;
        }
        let mut got = Vec::new();
        fast.scan_buffer(text, |s, e, m| {
            got.push((s, e, m.to_vec()));
            false
        });
        assert_eq!(
            got,
            expected,
            "{} plan for {:?} disagrees with per-line scanning on {text:?}",
            fast.plan(),
            fast.finders().iter().map(|f| f.id()).collect::<Vec<_>>()
        );
    }
}

fn buffer_scanners() -> &'static [(Scanner, Scanner)] {
    static PAIRS: std::sync::OnceLock<Vec<(Scanner, Scanner)>> = std::sync::OnceLock::new();
    PAIRS.get_or_init(|| {
        type Make = Box<dyn Fn() -> Vec<Box<dyn Finder>>>;
        let mut sets: Vec<Make> = vec![
            Box::new(|| vec![Box::new(squeeze::ip::Ip::default())]),
            Box::new(|| vec![Box::new(squeeze::cidr::Cidr::default())]),
            Box::new(|| vec![Box::new(squeeze::datetime::Datetime::default())]),
            Box::new(|| vec![Box::new(squeeze::semver::Semver::default())]),
            Box::new(|| vec![Box::new(squeeze::mac::Mac::default())]),
            Box::new(|| vec![Box::new(squeeze::color::Color::default())]),
            Box::new(|| vec![Box::new(squeeze::handle::Handle::default())]),
            Box::new(|| vec![Box::new(squeeze::jwt::Jwt::default())]),
            Box::new(|| vec![Box::new(squeeze::emoji::Emoji::default())]),
            Box::new(|| {
                let mut hash = squeeze::hash::Hash::default();
                for algorithm in ["md5", "sha1", "sha256", "sha512"] {
                    assert!(hash.add_algorithm(algorithm));
                }
                vec![Box::new(hash)]
            }),
            Box::new(|| {
                let mut hash = squeeze::hash::Hash::default();
                assert!(hash.add_algorithm("sha256"));
                vec![
                    Box::new(hash),
                    Box::new(squeeze::uuid::Uuid::default()),
                    Box::new(squeeze::uri::URI::default()),
                    Box::new(squeeze::email::Email::default()),
                    Box::new(squeeze::ip::Ip::default()),
                ]
            }),
            Box::new(|| {
                vec![
                    Box::new(squeeze::json::Json::default()),
                    Box::new(squeeze::uuid::Uuid::default()),
                    Box::new(squeeze::phone::Phone::default()),
                ]
            }),
            Box::new(|| {
                vec![
                    Box::new(squeeze::path::Path::default()),
                    Box::new(squeeze::env::Env::default()),
                    Box::new(squeeze::handle::Handle::default()),
                    Box::new(squeeze::mac::Mac::default()),
                ]
            }),
        ];
        sets.extend::<Vec<Make>>(vec![
            Box::new(|| vec![Box::new(squeeze::uri::URI::default())]),
            Box::new(|| vec![Box::new(squeeze::email::Email::default())]),
            Box::new(|| {
                vec![
                    Box::new(squeeze::uri::URI::default()),
                    Box::new(squeeze::email::Email::default()),
                ]
            }),
            Box::new(|| vec![Box::new(squeeze::uuid::Uuid::default())]),
            Box::new(|| vec![Box::new(squeeze::env::Env::default())]),
            Box::new(|| vec![Box::new(squeeze::path::Path::default())]),
            Box::new(|| {
                vec![
                    Box::new(squeeze::ip::Ip::default()),
                    Box::new(squeeze::email::Email::default()),
                ]
            }),
        ]);
        sets.iter()
            .map(|make| {
                let fast = Scanner::new(make());
                let mut legacy = Scanner::new(make());
                legacy.set_strategy(squeeze::scanner::Strategy::Legacy);
                (fast, legacy)
            })
            .collect()
    })
}

fn assert_anchored_agree(line: &str) {
    for (anchored, legacy) in anchored_pairs() {
        assert_eq!(
            anchored.scan_line(line),
            legacy.scan_line(line),
            "anchor plan for {} disagrees on {line:?}",
            anchored.finders()[0].id()
        );
        assert_eq!(anchored.scan_line_first(line), legacy.scan_line_first(line));
        let mut buffered = Vec::new();
        anchored.scan_buffer(line, |s, e, m| {
            buffered.push((s, e, m.to_vec()));
            false
        });
        let expected: Vec<_> = {
            let m = legacy.scan_line(line);
            if m.is_empty() {
                Vec::new()
            } else {
                vec![(0, line.len(), m)]
            }
        };
        assert_eq!(buffered, expected, "anchored scan_buffer on {line:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn anchors_hold_on_structured_input(
        s in "( |\\.|:|/|@|-|_|\\[|\\]|v|#|\\(|\\)|rgb|hsl|[a-z]{1,4}|[0-9]{1,4}|[0-9a-f]{1,8}|[0-9a-f]{30,34}|[0-9a-f]{38,42}|[0-9a-f]{62,66}|x[0-9a-f]{32}|[0-9a-f]{16}x[0-9a-f]{16}|[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,2})?|[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}(/[0-9]{1,3})?|::ffff:[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,3})?|\\[[0-9a-f:]{2,12}\\](/[0-9]{1,3})?|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9A-F]{2}([:-][0-9A-F]{2}){5}|[0-9A-F]{4}(\\.[0-9A-F]{4}){2}|20[0-9]{2}-[01][0-9]-[0-3][0-9](T[0-2][0-9]:[0-5][0-9]:[0-5][0-9](\\.[0-9]{1,3})?Z?)?|v?[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}(-[a-z0-9.]{1,6})?(\\+[a-z0-9.]{1,6})?|#[0-9a-fA-F]{3,8}|rgba?\\([0-9, .%]{5,14}\\)|hsla?\\([0-9, .%]{5,14}\\)|[a-z]{2,5}@[a-z]{2,5}\\.(com|org)){0,12}"
    ) {
        assert_anchors_hold(&dispatch_finders(), &s);
        assert_anchored_agree(&s);
    }

    #[test]
    fn anchors_hold_on_arbitrary_input(s in "\\PC{0,50}") {
        assert_anchors_hold(&dispatch_finders(), &s);
        assert_anchored_agree(&s);
    }
}
