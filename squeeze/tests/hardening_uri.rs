//! Hardening regression tests for the URI finder.
//!
//! Each section pins one of the audited bugs (or a confirmed-good behavior)
//! so future refactors cannot silently reintroduce them.

use squeeze::Finder;
use squeeze::scanner::Scanner;
use squeeze::uri::URI;

fn lax() -> URI {
    URI::default()
}

fn strict() -> URI {
    let mut f = URI::default();
    f.strict = true;
    f
}

/// First match of `finder` in `input`, as text.
fn first<'a>(finder: &URI, input: &'a str) -> Option<&'a str> {
    finder.find(input).map(|r| &input[r])
}

/// All matches produced by the documented find() loop (slice + advance).
fn find_all(finder: &URI, input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut idx = 0;
    while idx < input.len() {
        match finder.find(&input[idx..]) {
            Some(range) => {
                out.push(input[idx + range.start..idx + range.end].to_string());
                idx += range.end;
            }
            None => break,
        }
    }
    out
}

/// All matches produced by the trigger-dispatch Scanner, as text.
fn scan_all(input: &str) -> Vec<String> {
    let scanner = Scanner::new(vec![Box::new(URI::default()) as Box<dyn Finder>]);
    scanner
        .scan_line(input)
        .into_iter()
        .map(|m| input[m.range].to_string())
        .collect()
}

// ============================================================================
// Bug 1: IPv4-prefix hosts must not be truncated mid reg-name
// ============================================================================

#[test]
fn ipv4_prefix_hostname_is_not_truncated() {
    let f = lax();
    for input in [
        "http://10.0.0.1.nip.io/app",
        "https://192.168.0.1.evil.example.com/login",
        "http://1.2.3.4.5/",
        "http://127.0.0.1.example.com",
        "http://10.0.0.1-app.example.com/x",
    ] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

#[test]
fn plain_ipv4_hosts_still_match_exactly() {
    let f = lax();
    for input in [
        "http://10.0.0.1/app",
        "http://255.255.255.255",
        "http://192.0.2.235:8080/x?y=z",
    ] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

#[test]
fn ipv4_host_followed_by_prose_is_unaffected() {
    let f = lax();
    let input = "curl http://10.0.0.1 now";
    assert_eq!(Some("http://10.0.0.1"), first(&f, input));
}

// ============================================================================
// Bug 2: parenthesis balancing in lax mode
// ============================================================================

#[test]
fn balanced_parens_in_path_are_kept() {
    let f = lax();
    for input in [
        "https://en.wikipedia.org/wiki/Sport_(disambiguation)",
        "https://ex.com/a_(b)_(c)",
        "http://ex.com/nested_(a(b)c)_end",
        "http://ex.com/?q=(1+2)",
        "http://ex.com/frag#sec_(2)",
    ] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

#[test]
fn unmatched_close_paren_still_terminates() {
    let f = lax();
    let cases = [
        ("[docs](https://x.com/a)", "https://x.com/a"),
        ("(see http://x.com/path) ok", "http://x.com/path"),
        (
            "(https://en.wikipedia.org/wiki/Sport_(disambiguation))",
            "https://en.wikipedia.org/wiki/Sport_(disambiguation)",
        ),
        (
            "[link](http://ex.com/a_(b)_c) tail",
            "http://ex.com/a_(b)_c",
        ),
        ("[link](foobar:)", "foobar:"),
    ];
    for (input, expected) in cases {
        assert_eq!(Some(expected), first(&f, input), "{input}");
    }
}

#[test]
fn strict_mode_paren_handling_is_unchanged() {
    let f = strict();
    for input in ["http://localhost/)", "http://localhost/(a))"] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

// ============================================================================
// Bug 3: DNS label length — 63 chars allowed, 64+ rejects the candidate
// ============================================================================

#[test]
fn sixty_three_char_label_matches_fully() {
    let f = lax();
    let label = "a".repeat(63);
    for input in [
        format!("http://{label}.com/x"),
        format!("http://sub.{label}.com"),
    ] {
        assert_eq!(Some(input.as_str()), first(&f, &input), "{input}");
    }
}

#[test]
fn oversized_label_rejects_whole_candidate() {
    let f = lax();
    for host in [
        format!("{}.com", "a".repeat(64)),
        format!("sub.{}.com", "b".repeat(70)),
    ] {
        let input = format!("http://{host}/x");
        assert_eq!(None, f.find(&input), "{input}");
    }
}

#[test]
fn oversized_hostname_rejects_whole_candidate() {
    let f = lax();
    let host = ["ab"; 100].join("."); // 299 chars > 253
    let input = format!("http://{host}/x");
    assert_eq!(None, f.find(&input), "{input}");
}

#[test]
fn hostname_up_to_253_chars_matches() {
    let f = lax();
    let host = ["a"; 127].join("."); // 253 chars
    assert_eq!(host.len(), 253);
    let input = format!("http://{host}");
    assert_eq!(Some(input.as_str()), first(&f, &input));
}

// ============================================================================
// Bug 4: IPv6 zone-ID literals + std-exact bracket validation
// ============================================================================

#[test]
fn zone_id_literals_match() {
    let f = lax();
    for input in [
        "http://[fe80::1%25eth0]/",
        "http://[fe80::1%25eth0]:8080/x",
        "http://[fe80::a1b2:3c4d%25en0]/status",
        "http://[fe80::1%eth0]/", // lenient bare "%" separator
        "http://[fe80::1%25.zone-id_ok~]/",
    ] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

#[test]
fn zone_id_requires_valid_address_and_zone() {
    let f = lax();
    for input in [
        "http://[fe80::1%]/",      // empty zone
        "http://[:::1%25eth0]/",   // invalid address part
        "http://[fe80::1%25e/h]/", // '/' is not unreserved (no ']' in range)
    ] {
        let found = f.find(input).map(|r| &input[r]);
        assert!(
            found.is_none_or(|m| !m.contains('[')),
            "bracket literal must not match in {input}: {found:?}"
        );
    }
}

#[test]
fn invalid_ipv6_literals_die_entirely() {
    let f = lax();
    for input in [
        "http://[::1:]/",
        "http://[1:2:3:4:5:6:7:8:]/",
        "http://[:1:2:3:4:5:6:7:8]/",
        "http://[1:2:3:4:5:6::7:8]/",
        "http://[1::2::3]/",
    ] {
        assert_eq!(None, f.find(input), "{input}");
    }
}

#[test]
fn valid_ipv6_literals_still_match() {
    let f = lax();
    for input in [
        "http://[1:2:3:4:5:6:7::]/",
        "http://[::1]/",
        "http://[1::127.0.0.1]/",
        "http://[2001:db8::1]:443/path",
        "http://[::ffff:192.0.2.128]",
    ] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

#[test]
fn bracket_acceptance_matches_std_ipv6_parser() {
    let f = lax();
    for addr in [
        "::",
        "::1",
        "1::",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:127.0.0.1",
        "1:2:3:4:5:6::127.0.0.1",
        "1::127.0.0.1",
        "::ffff:255.255.255.255",
        "::1:",
        ":1:",
        "1:2:3:4:5:6:7::",
        "12345::1",
        "::01.2.3.4",
        "::256.0.0.1",
        "1:127.0.0.1::",
        "fe80::1",
    ] {
        let input = format!("x://[{addr}]/");
        let expects = addr.parse::<std::net::Ipv6Addr>().is_ok();
        let got = first(&f, &input) == Some(input.as_str());
        assert_eq!(expects, got, "std disagrees on [{addr}]");
    }
}

// ============================================================================
// Bug 5: digit-glued colons are not scheme positions
// ============================================================================

#[test]
fn timestamps_do_not_produce_uris() {
    let f = lax();
    for input in [
        "at 2024-01-15T10:30:00Z x",
        "2024-01-15T10:30:00Z",
        "log 2024-01-15T10:30:00.123Z end",
        "12:30:45",
        "1:2",
    ] {
        assert_eq!(None, f.find(input), "{input}");
    }
}

#[test]
fn runs_starting_with_punctuation_still_anchor_on_alpha() {
    let f = lax();
    for (input, expected) in [
        ("(http://x.com", "http://x.com"),
        ("-http://x.com", "http://x.com"),
        (".http://x.com", "http://x.com"),
        ("+http://x.com", "http://x.com"),
    ] {
        assert_eq!(Some(expected), first(&f, input), "{input}");
    }
}

#[test]
fn alpha_start_schemes_with_digits_still_match() {
    let f = lax();
    for input in ["h2c://example.com", "x2024://host/y", "v1.2://host"] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

// ============================================================================
// Bug 6: trailing punctuation is prose, not URI (lax mode only)
// ============================================================================

#[test]
fn trailing_punctuation_is_trimmed_in_lax_mode() {
    let f = lax();
    for (input, expected) in [
        ("See https://example.com. Next", "https://example.com"),
        ("See https://example.com.", "https://example.com"),
        ("go to http://x.com/a, then", "http://x.com/a"),
        ("http://x.com/a; done", "http://x.com/a"),
        ("really http://x.com/a!", "http://x.com/a"),
        ("is it http://x.com/a? maybe", "http://x.com/a"),
        ("http://x.com: yes", "http://x.com"),
        ("http://x.com:8080: yes", "http://x.com:8080"),
        ("wow http://x.com/a?!... next", "http://x.com/a"),
        ("host http://x.com. port", "http://x.com"),
    ] {
        assert_eq!(Some(expected), first(&f, input), "{input}");
    }
}

#[test]
fn interior_punctuation_is_untouched() {
    let f = lax();
    for input in [
        "http://x.com/a.b",
        "http://x.com/a/",
        "http://x.com/a,b;c!d",
        "http://x.com/?q=a.b",
        "mailto:user@example.com?subject=Hello&body=World",
    ] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

#[test]
fn scheme_colon_survives_trimming() {
    let f = lax();
    for input in ["foobar:", " foobar: ", "[link](foobar:)"] {
        assert_eq!(Some("foobar:"), first(&f, input), "{input}");
    }
}

#[test]
fn strict_mode_keeps_trailing_punctuation() {
    let f = strict();
    for input in [
        "http://x.com/a.",
        "http://x.com:",
        "http://x.com/a?",
        "http://bitromix.com/download.php?",
    ] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

#[test]
fn hostname_does_not_end_with_a_dot() {
    let f = lax();
    for (input, expected) in [
        ("http://example.com. and", "http://example.com"),
        ("http://a.b.c.. x", "http://a.b.c"),
        ("http://a.-b", "http://a"),
    ] {
        assert_eq!(Some(expected), first(&f, input), "{input}");
    }
}

// ============================================================================
// Bug 7: non-ASCII glued to the host rejects the candidate
// ============================================================================

#[test]
fn non_ascii_in_host_rejects_candidate() {
    let f = lax();
    for input in [
        "https://exämple.com/path",
        "foo://例え.jp/",
        "https://例え.jp",
        "http://ex\u{00e9}.com",
        "https://example.香港/",
    ] {
        assert_eq!(None, f.find(input), "{input}");
    }
}

#[test]
fn ascii_host_with_non_ascii_path_may_truncate() {
    let f = lax();
    let input = "https://example.com/caf\u{00e9}";
    assert_eq!(Some("https://example.com/caf"), first(&f, input));
}

#[test]
fn punycode_hosts_still_match() {
    let f = lax();
    for input in ["http://xn--n3h.com", "http://xn--80ak6aa92e.com/x"] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

// ============================================================================
// Bug 8: scheme allowlist applies (moved before the parse; behavior pinned)
// ============================================================================

#[test]
fn scheme_allowlist_still_filters() {
    let mut f = URI::default();
    f.add_scheme("https");
    assert_eq!(None, f.find("http://insecure.com"));
    let input = "http://first.com https://second.com";
    assert_eq!(Some("https://second.com"), first(&f, input));
    let upper = "HTTPS://UPPER.COM";
    assert_eq!(Some(upper), first(&f, upper));
}

// ============================================================================
// Confirmed-good behaviors (pins)
// ============================================================================

#[test]
fn double_at_userinfo_stops_at_second_at() {
    let f = lax();
    let input = "http://user@pass@example.com/";
    assert_eq!(Some("http://user@pass"), first(&f, input));
}

#[test]
fn inner_url_in_query_is_part_of_outer_match() {
    let f = lax();
    let input = "https://a.com/redirect?url=https://b.com";
    assert_eq!(Some(input), first(&f, input));
}

#[test]
fn scheme_matching_is_case_insensitive() {
    let f = lax();
    for input in ["HTTP://EXAMPLE.COM", "HtTpS://example.com/x"] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
    assert_eq!(None, f.find("HTTP:///missing-host"));
}

#[test]
fn bad_percent_escapes_stop_the_match() {
    let f = lax();
    for (input, expected) in [
        ("http://example.com/path%GG", "http://example.com/path"),
        ("http://example.com/path%2", "http://example.com/path"),
    ] {
        assert_eq!(Some(expected), first(&f, input), "{input}");
    }
}

#[test]
fn query_stops_at_open_bracket() {
    let f = lax();
    let input = "http://x.com/?a[]=1";
    assert_eq!(Some("http://x.com/?a"), first(&f, input));
}

#[test]
fn common_scheme_forms_still_match() {
    let f = lax();
    for input in [
        "mailto:fred@example.com",
        "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        "file:///etc/hosts",
        "data:text/plain;base64,SGVsbG8=",
        "tel:+1-816-555-1212",
    ] {
        assert_eq!(Some(input), first(&f, input), "{input}");
    }
}

// ============================================================================
// Scanner-vs-find() parity on the fixed grammars
// ============================================================================

#[test]
fn scanner_and_find_loop_agree_on_fixed_grammars() {
    let f = lax();
    for input in [
        "http://10.0.0.1.nip.io/app and http://1.2.3.4.5/",
        "wiki https://en.wikipedia.org/wiki/Sport_(disambiguation) end",
        "[docs](https://x.com/a) [more](http://y.org/b).",
        "at 2024-01-15T10:30:00Z x",
        "See https://example.com. Next http://x.com: done",
        "http://[fe80::1%25eth0]/ http://[::1:]/",
        "https://exämple.com/path foo://例え.jp/",
        "long http://sub.example.com. tail foobar: opaque",
        "See https://a.com/redirect?url=https://b.com!",
        "ports http://x.com:8080/a. http://y.com:. z",
        // Counterexamples found by proptest while hardening the lax trims:
        // trimmed trailing ":" leaves a live trigger colon behind.
        "a:=a:%",
        "a:#a:#",
        "A:#A:.#",
        "http://x.com:80foo: z",
        "http://[::1]x: z",
    ] {
        let mut expected = find_all(&f, input);
        let mut got = scan_all(input);
        expected.sort();
        got.sort();
        assert_eq!(expected, got, "parity diverged on {input:?}");
    }
}
