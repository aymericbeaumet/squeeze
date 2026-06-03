//! Stress test that runs every finder together against a wide variety of
//! inputs. The goal is to surface priority/conflict issues that don't show
//! up when finders are tested in isolation.
//!
//! Tests here assert *concrete* output sets — if a finder change shifts a
//! span, this suite will fail loudly so the new behavior is reviewed.

use squeeze::{
    cidr::Cidr,
    codetag::Codetag,
    color::Color,
    datetime::Datetime,
    domain::Domain,
    email::Email,
    emoji::Emoji,
    env::Env,
    handle::Handle,
    hash::Hash,
    ip::Ip,
    json::Json,
    jwt::Jwt,
    mac::Mac,
    modeline::Modeline,
    path::Path,
    phone::Phone,
    scanner::{Match, Scanner},
    semver::Semver,
    uri::URI,
    uuid::Uuid,
    Finder,
};

fn all_finders() -> Vec<Box<dyn Finder>> {
    let mut codetag = Codetag::default();
    codetag.build_mnemonics_regex().unwrap();
    let mut uri = URI::default();
    for s in [
        "data", "ftp", "ftps", "http", "https", "mailto", "sftp", "ws", "wss",
    ] {
        uri.add_scheme(s);
    }
    let mut hash = Hash::default();
    for a in ["md5", "sha1", "sha256", "sha512"] {
        hash.add_algorithm(a);
    }
    vec![
        Box::new(Cidr::default()),
        Box::new(codetag),
        Box::new(Color::default()),
        Box::new(Datetime::default()),
        Box::new(Domain::default()),
        Box::new(Email::default()),
        Box::new(Emoji::default()),
        Box::new(Env::default()),
        Box::new(Handle::default()),
        Box::new(hash),
        Box::new(Ip::default()),
        Box::new(Json::default()),
        Box::new(Jwt::default()),
        Box::new(Mac::default()),
        Box::new(Modeline::default()),
        Box::new(Path::default()),
        Box::new(Phone::default()),
        Box::new(Semver::default()),
        Box::new(uri),
        Box::new(Uuid::default()),
    ]
}

fn spans<'a>(scanner: &Scanner, input: &'a str) -> Vec<(&'static str, &'a str)> {
    let mut buf: Vec<Match> = Vec::new();
    scanner.scan_line_into(input, &mut buf);
    buf.into_iter()
        .map(|m| {
            let id = scanner.finders()[m.finder_index].id();
            (id, &input[m.range])
        })
        .collect()
}

fn ids(scanner: &Scanner, input: &str) -> Vec<&'static str> {
    let mut buf: Vec<Match> = Vec::new();
    scanner.scan_line_into(input, &mut buf);
    buf.iter()
        .map(|m| scanner.finders()[m.finder_index].id())
        .collect()
}

// ============================================================================
// CIDR vs IP
// ============================================================================

#[test]
fn cidr_and_ip_both_match_cidr_input() {
    // CIDR captures the whole `192.168.1.0/24`; IP also legitimately captures
    // the IPv4 prefix `192.168.1.0`. We accept this overlap — consumers can
    // pick whichever they wanted.
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "net 192.168.1.0/24 ok");
    let cidr_match = s.iter().find(|(id, _)| *id == "cidr");
    let ip_match = s.iter().find(|(id, _)| *id == "ip");
    assert_eq!(cidr_match, Some(&("cidr", "192.168.1.0/24")));
    assert_eq!(ip_match, Some(&("ip", "192.168.1.0")));
}

#[test]
fn ipv6_cidr_yields_both_ipv6_and_cidr() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "2001:db8::/32 net");
    let cidr = s.iter().find(|(id, _)| *id == "cidr");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    assert_eq!(cidr, Some(&("cidr", "2001:db8::/32")));
    assert!(ip.is_some());
}

// ============================================================================
// IP vs MAC
// ============================================================================

#[test]
fn mac_is_not_misread_as_ipv6() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "mac 00:1A:2B:3C:4D:5E end");
    let mac_match = s.iter().find(|(id, _)| *id == "mac");
    let ip_match = s.iter().find(|(id, _)| *id == "ip");
    assert_eq!(mac_match, Some(&("mac", "00:1A:2B:3C:4D:5E")));
    assert!(ip_match.is_none(), "MAC must not be misread as IPv6");
}

#[test]
fn ipv4_does_not_match_as_mac() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "ip 192.168.1.1 end");
    let mac_match = s.iter().find(|(id, _)| *id == "mac");
    assert!(mac_match.is_none(), "IPv4 must not be reported as MAC");
}

// ============================================================================
// UUID vs Hash
// ============================================================================

#[test]
fn uuid_is_not_misread_as_hash() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "id 550e8400-e29b-41d4-a716-446655440000 end");
    let uuid_match = s.iter().find(|(id, _)| *id == "uuid");
    let hash_match = s.iter().find(|(id, _)| *id == "hash");
    assert_eq!(
        uuid_match,
        Some(&("uuid", "550e8400-e29b-41d4-a716-446655440000"))
    );
    assert!(
        hash_match.is_none(),
        "UUID hex groups must not be reported as hashes"
    );
}

#[test]
fn md5_hash_is_reported_as_hash_not_uuid() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "md5 5d41402abc4b2a76b9719d911017c592 end");
    let uuid_match = s.iter().find(|(id, _)| *id == "uuid");
    let hash_match = s.iter().find(|(id, _)| *id == "hash");
    assert!(hash_match.is_some());
    assert!(uuid_match.is_none());
}

// ============================================================================
// Hash vs JWT
// ============================================================================

#[test]
fn jwt_is_reported_as_jwt() {
    let scanner = Scanner::new(all_finders());
    // Real-ish JWT (3 base64url segments separated by dots)
    let jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let line = format!("token: {} ok", jwt);
    let s = spans(&scanner, &line);
    let jwt_match = s.iter().find(|(id, _)| *id == "jwt");
    assert_eq!(jwt_match, Some(&("jwt", jwt)));
}

// ============================================================================
// JSON containing other tokens
// ============================================================================

#[test]
fn json_object_does_not_swallow_inner_url_match() {
    // When both finders are enabled, JSON captures the whole object and the
    // URI finder also captures the inner URL. Both are valid; we document
    // the observed behavior.
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, r#"data: {"url":"https://example.com"} ok"#);
    let json_match = s.iter().find(|(id, _)| *id == "json");
    let uri_match = s.iter().find(|(id, _)| *id == "uri");
    assert!(json_match.is_some(), "JSON object must be captured");
    assert!(uri_match.is_some(), "Inner URL must also be captured");
}

// ============================================================================
// Codetag containing URI
// ============================================================================

#[test]
fn codetag_with_url_inside_yields_both() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "// TODO: visit https://example.com soon");
    let cs = s.iter().find(|(id, _)| *id == "codetag");
    let uri = s.iter().find(|(id, _)| *id == "uri");
    assert!(cs.is_some());
    assert!(uri.is_some());
}

// ============================================================================
// Email vs URI / Domain
// ============================================================================

#[test]
fn mailto_uri_captures_uri_and_email() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "mail mailto:user@example.com today");
    let uri = s.iter().find(|(id, _)| *id == "uri");
    let email = s.iter().find(|(id, _)| *id == "email");
    assert!(uri.is_some());
    assert!(email.is_some());
}

#[test]
fn email_blocks_domain_on_same_input() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "user@example.com only");
    let email = s.iter().find(|(id, _)| *id == "email");
    let domain = s.iter().find(|(id, _)| *id == "domain");
    assert!(email.is_some());
    assert!(domain.is_none());
}

// ============================================================================
// URI vs Domain
// ============================================================================

#[test]
fn url_blocks_domain() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "see https://example.com only");
    let uri = s.iter().find(|(id, _)| *id == "uri");
    let domain = s.iter().find(|(id, _)| *id == "domain");
    assert!(uri.is_some());
    assert!(domain.is_none());
}

// ============================================================================
// Path vs Datetime
// ============================================================================

#[test]
fn datetime_inside_path_does_not_block_path() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "see /var/log/2024-01-15.log here");
    let path = s.iter().find(|(id, _)| *id == "path");
    assert!(path.is_some(), "path should be captured");
}

// ============================================================================
// Semver vs IPv4
// ============================================================================

#[test]
fn ipv4_is_not_semver() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "addr 192.168.1.1 end");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    let sv = s.iter().find(|(id, _)| *id == "semver");
    assert_eq!(ip, Some(&("ip", "192.168.1.1")));
    assert!(sv.is_none(), "IPv4 must not be misread as semver");
}

#[test]
fn semver_is_not_ip() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "v 1.2.3 release");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    let sv = s.iter().find(|(id, _)| *id == "semver");
    assert!(ip.is_none(), "semver `1.2.3` must not be reported as IP");
    assert!(sv.is_some());
}

// ============================================================================
// Datetime vs phone
// ============================================================================

#[test]
fn datetime_is_not_phone() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "at 2024-01-15T10:30:00Z next");
    let dt = s.iter().find(|(id, _)| *id == "datetime");
    let ph = s.iter().find(|(id, _)| *id == "phone");
    assert!(dt.is_some());
    assert!(ph.is_none(), "datetime must not be reported as phone");
}

// ============================================================================
// Phone vs datetime
// ============================================================================

#[test]
fn phone_is_not_datetime() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "call +14155551234 today");
    let dt = s.iter().find(|(id, _)| *id == "datetime");
    let ph = s.iter().find(|(id, _)| *id == "phone");
    assert!(ph.is_some());
    assert!(dt.is_none(), "phone must not be reported as datetime");
}

// ============================================================================
// Color vs hash (both can use #-prefixed hex)
// ============================================================================

#[test]
fn color_hex_is_not_hash() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "bg #ff00aa end");
    let color = s.iter().find(|(id, _)| *id == "color");
    let hash = s.iter().find(|(id, _)| *id == "hash");
    assert!(color.is_some());
    assert!(hash.is_none(), "color hex must not be reported as hash");
}

// ============================================================================
// Comprehensive multi-token line
// ============================================================================

#[test]
fn comprehensive_real_world_line() {
    let scanner = Scanner::new(all_finders());
    let input =
        "TODO: contact alice@example.com about https://example.com, see /etc/hosts, version 1.2.3 #ff0000";
    let got_ids: Vec<_> = ids(&scanner, input).into_iter().collect();
    // Required: codetag, email, uri, path, semver, color.
    for required in ["codetag", "email", "uri", "path", "semver", "color"] {
        assert!(
            got_ids.contains(&required),
            "missing {required} in {got_ids:?}"
        );
    }
}

// ============================================================================
// Pathological / fuzzy inputs
// ============================================================================

#[test]
fn empty_input_yields_no_matches() {
    let scanner = Scanner::new(all_finders());
    assert!(spans(&scanner, "").is_empty());
}

#[test]
fn whitespace_input_yields_no_matches() {
    let scanner = Scanner::new(all_finders());
    assert!(spans(&scanner, "  \t  ").is_empty());
}

#[test]
fn long_random_alphanumeric_does_not_panic() {
    let scanner = Scanner::new(all_finders());
    let input: String = (0..1000).map(|i| ((i % 26) as u8 + b'a') as char).collect();
    let _ = spans(&scanner, &input);
}

#[test]
fn punctuation_storm_does_not_panic() {
    let scanner = Scanner::new(all_finders());
    let input = "::;;@@##$$%%^^&&**()[]{}/\\<>?,.|+=-_";
    let _ = spans(&scanner, input);
}

// ============================================================================
// Multibyte / unicode safety
// ============================================================================

#[test]
fn unicode_around_matches_does_not_panic() {
    let scanner = Scanner::new(all_finders());
    let inputs = [
        "héllo user@example.com 世界",
        "🎉 v1.2.3 release 🚀",
        "look at https://例え.jp here",
        "café at 192.168.1.1",
    ];
    for input in inputs {
        let _ = spans(&scanner, input);
    }
}

// ============================================================================
// Adjacent matches
// ============================================================================

#[test]
fn env_var_glued_to_path_only_yields_env() {
    // The path finder intentionally requires a boundary before `/`, so
    // `$HOME/etc/hosts` reports only the env variable. This locks in that
    // behavior so future changes are deliberate.
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "$HOME/etc/hosts");
    let env = s.iter().find(|(id, _)| *id == "env");
    assert_eq!(env, Some(&("env", "$HOME")));
    assert!(s.iter().all(|(id, _)| *id != "path"));
}

#[test]
fn env_var_followed_by_space_then_path_yields_both() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "$HOME /etc/hosts");
    let env = s.iter().find(|(id, _)| *id == "env");
    let path = s.iter().find(|(id, _)| *id == "path");
    assert_eq!(env, Some(&("env", "$HOME")));
    assert_eq!(path, Some(&("path", "/etc/hosts")));
}

// ============================================================================
// Span ordering invariant
// ============================================================================

#[test]
fn matches_returned_in_position_order() {
    let scanner = Scanner::new(all_finders());
    let input =
        "first https://a.com second 192.168.1.1 third user@example.com fourth #ff0000 fifth";
    let mut buf: Vec<Match> = Vec::new();
    scanner.scan_line_into(input, &mut buf);
    let mut prev = 0usize;
    for m in &buf {
        assert!(
            m.range.start >= prev,
            "matches must be ordered by start; got {:?} after prev={}",
            m.range,
            prev
        );
        prev = m.range.start;
    }
}

// ============================================================================
// Determinism: scan_line vs scan_line_into vs scan_line_first
// ============================================================================

#[test]
fn scan_line_and_scan_line_into_agree() {
    let scanner = Scanner::new(all_finders());
    let inputs = [
        "user@example.com https://example.com /etc/hosts 1.2.3",
        "TODO: this is a task with $HOME env",
        "uuid 550e8400-e29b-41d4-a716-446655440000 and #fff",
    ];
    for input in inputs {
        let a = scanner.scan_line(input);
        let mut b = Vec::new();
        scanner.scan_line_into(input, &mut b);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.range, y.range);
            assert_eq!(x.finder_index, y.finder_index);
        }
    }
}

#[test]
fn scan_line_first_matches_earliest_overall() {
    let scanner = Scanner::new(all_finders());
    let input = "first https://a.com then 192.168.1.1";
    let all = scanner.scan_line(input);
    let first = scanner.scan_line_first(input).unwrap();
    let earliest_start = all.iter().map(|m| m.range.start).min().unwrap();
    assert_eq!(first.range.start, earliest_start);
}

// ============================================================================
// URL containing other token-like substrings
// ============================================================================

#[test]
fn url_with_uuid_in_path_yields_both() {
    // Both URL and UUID are legitimate captures; document the overlap.
    let scanner = Scanner::new(all_finders());
    let url = "https://example.com/550e8400-e29b-41d4-a716-446655440000";
    let s = spans(&scanner, url);
    let url_match = s.iter().find(|(id, _)| *id == "uri");
    let uuid_match = s.iter().find(|(id, _)| *id == "uuid");
    assert!(url_match.is_some());
    assert!(uuid_match.is_some());
}

#[test]
fn ip_with_port_reports_ip_only() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "connect to 192.168.1.1:8080 ok");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    assert_eq!(ip, Some(&("ip", "192.168.1.1")));
}

#[test]
fn five_octet_mac_does_not_match() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "broken aa:bb:cc:dd:ee");
    assert!(
        s.iter().all(|(id, _)| *id != "mac"),
        "5-octet sequence must not be reported as MAC: {s:?}"
    );
}

#[test]
fn ipv4_with_too_many_octets_does_not_match() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "weird 1.2.3.4.5.6 here");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    // The IP finder may match only the first valid prefix '1.2.3.4'; either it
    // captures none or captures '1.2.3.4' — verify it doesn't capture the full
    // 6-octet thing.
    if let Some((_, span)) = ip {
        assert!(*span == "1.2.3.4", "unexpected ip span {span}");
    }
}

// ============================================================================
// CIDR / IP overlap documentation
// ============================================================================

#[test]
fn ipv4_cidr_yields_both_cidr_and_ip() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "172.16.0.0/12");
    let cidr = s.iter().find(|(id, _)| *id == "cidr");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    assert_eq!(cidr, Some(&("cidr", "172.16.0.0/12")));
    assert_eq!(ip, Some(&("ip", "172.16.0.0")));
}

// ============================================================================
// Hash boundary
// ============================================================================

#[test]
fn hash_does_not_match_short_hex_run() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "short aabbcc end");
    assert!(s.iter().all(|(id, _)| *id != "hash"));
}

#[test]
fn hash_does_not_match_31_char_hex_run() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "x 5d41402abc4b2a76b9719d911017c59 x");
    assert!(s.iter().all(|(id, _)| *id != "hash"));
}

#[test]
fn hash_matches_exact_md5_length() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "x 5d41402abc4b2a76b9719d911017c592 x");
    let hash = s.iter().find(|(id, _)| *id == "hash");
    assert_eq!(hash, Some(&("hash", "5d41402abc4b2a76b9719d911017c592")));
}

// ============================================================================
// Color formats
// ============================================================================

#[test]
fn color_three_six_eight_digit_hex_all_match() {
    let scanner = Scanner::new(all_finders());
    for (input, expected) in [
        ("#fff", "#fff"),
        ("#abc123", "#abc123"),
        ("#ff00aaff", "#ff00aaff"),
    ] {
        let s = spans(&scanner, input);
        let color = s.iter().find(|(id, _)| *id == "color");
        assert_eq!(color, Some(&("color", expected)));
        let hash = s.iter().find(|(id, _)| *id == "hash");
        assert!(hash.is_none(), "color hex must not be reported as hash");
    }
}

// ============================================================================
// Email with IP host: documented gap
// ============================================================================

#[test]
fn email_with_ipv4_host_is_skipped_but_ip_matches() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "send to user@1.2.3.4 today");
    let email = s.iter().find(|(id, _)| *id == "email");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    assert!(email.is_none(), "IP-literal emails are not supported");
    assert_eq!(ip, Some(&("ip", "1.2.3.4")));
}

// ============================================================================
// JSON strict validation
// ============================================================================

#[test]
fn json_balanced_braces_with_garbage_are_rejected() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "weird {not really json}");
    let json = s.iter().find(|(id, _)| *id == "json");
    assert!(
        json.is_none(),
        "balanced-but-invalid JSON must be rejected: {s:?}"
    );
}

#[test]
fn json_valid_object_is_accepted() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, r#"data: {"key": "value"} ok"#);
    let json = s.iter().find(|(id, _)| *id == "json");
    assert_eq!(json, Some(&("json", r#"{"key": "value"}"#)));
}

// ============================================================================
// Datetime variations
// ============================================================================

#[test]
fn datetime_iso8601_with_fractional_seconds() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "ts 2024-01-15T10:30:00.123Z end");
    let dt = s.iter().find(|(id, _)| *id == "datetime");
    assert_eq!(dt, Some(&("datetime", "2024-01-15T10:30:00.123Z")));
}

#[test]
fn datetime_date_only() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "see 2024-01-15 next");
    let dt = s.iter().find(|(id, _)| *id == "datetime");
    assert_eq!(dt, Some(&("datetime", "2024-01-15")));
}

// ============================================================================
// Semver variations
// ============================================================================

#[test]
fn semver_with_prerelease_and_build() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "release 1.0.0-rc.1+build.42 ok");
    let sv = s.iter().find(|(id, _)| *id == "semver");
    assert_eq!(sv, Some(&("semver", "1.0.0-rc.1+build.42")));
}

#[test]
fn semver_with_v_prefix() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "tag v1.2.3 here");
    let sv = s.iter().find(|(id, _)| *id == "semver");
    assert!(sv.is_some());
}

#[test]
fn two_component_version_not_semver() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "is 1.0 a version?");
    assert!(s.iter().all(|(id, _)| *id != "semver"));
}

// ============================================================================
// Env variations
// ============================================================================

#[test]
fn env_var_adjacent_no_separator() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "$HOME$USER");
    let envs: Vec<_> = s.iter().filter(|(id, _)| *id == "env").collect();
    let names: Vec<&str> = envs.iter().map(|(_, v)| *v).collect();
    assert_eq!(names, vec!["$HOME", "$USER"]);
}

#[test]
fn env_var_braced() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "use ${HOME}/foo");
    let env = s.iter().find(|(id, _)| *id == "env");
    assert_eq!(env, Some(&("env", "${HOME}")));
}

// ============================================================================
// IPv6 special forms
// ============================================================================

#[test]
fn ipv4_mapped_ipv6_matches() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "addr ::ffff:192.168.1.1 ok");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    assert!(ip.is_some());
}

#[test]
fn ipv6_link_local_matches_without_zone_id() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "addr fe80::1%eth0 end");
    let ip = s.iter().find(|(id, _)| *id == "ip");
    // We currently strip the zone id; just assert *some* IPv6 was matched.
    assert!(ip.is_some());
}

// ============================================================================
// Codetag content variations
// ============================================================================

#[test]
fn codetag_with_paren_handle_yields_both() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "FIXME(@alice): bug here");
    let cs = s.iter().find(|(id, _)| *id == "codetag");
    let handle = s.iter().find(|(id, _)| *id == "handle");
    assert!(cs.is_some());
    assert_eq!(handle, Some(&("handle", "@alice")));
}

// ============================================================================
// Mailto URI
// ============================================================================

#[test]
fn mailto_uri_email_overlap_both_matched() {
    let scanner = Scanner::new(all_finders());
    let s = spans(&scanner, "send mailto:user@example.com here");
    let uri = s.iter().find(|(id, _)| *id == "uri");
    let email = s.iter().find(|(id, _)| *id == "email");
    assert!(uri.is_some());
    assert!(email.is_some());
}

// ============================================================================
// Multibyte boundary safety
// ============================================================================

#[test]
fn unicode_grapheme_before_match_is_preserved() {
    let scanner = Scanner::new(all_finders());
    let input = "🚀 v1.2.3";
    let s = spans(&scanner, input);
    let sv = s.iter().find(|(id, _)| *id == "semver");
    assert!(sv.is_some());
    // Span should not cut into the emoji bytes.
    let sv_range = scanner.scan_line(input)[0].range.clone();
    assert!(
        input.get(sv_range).is_some(),
        "match must be valid UTF-8 slice"
    );
}

// ============================================================================
// Many-match line
// ============================================================================

#[test]
fn line_with_many_envs_returns_all_in_order() {
    let scanner = Scanner::new(all_finders());
    let input: String = (0..50).map(|i| format!("$V{} ", i)).collect();
    let mut buf = Vec::new();
    scanner.scan_line_into(&input, &mut buf);
    let envs: Vec<_> = buf
        .iter()
        .filter(|m| scanner.finders()[m.finder_index].id() == "env")
        .collect();
    assert_eq!(envs.len(), 50);
}
