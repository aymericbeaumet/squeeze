//! Hardening regression tests for the contact finders (email, domain, handle).
//!
//! Each section covers one verified bug plus its variants, pins the
//! documented non-bugs, and checks Scanner parity against the documented
//! `find()` loop.

use squeeze::Finder;
use squeeze::domain::Domain;
use squeeze::email::Email;
use squeeze::handle::Handle;
use squeeze::scanner::Scanner;

fn find_one(finder: &dyn Finder, input: &str) -> Option<String> {
    finder.find(input).map(|r| input[r].to_string())
}

/// The documented `find()` loop from the `Finder` trait docs.
fn find_all(finder: &dyn Finder, input: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut idx = 0;
    while idx < input.len() {
        if let Some(range) = finder.find(&input[idx..]) {
            results.push(input[idx + range.start..idx + range.end].to_string());
            idx += range.end;
        } else {
            break;
        }
    }
    results
}

fn scan_texts(finders: Vec<Box<dyn Finder>>, input: &str) -> Vec<String> {
    Scanner::new(finders)
        .scan_line(input)
        .into_iter()
        .map(|m| input[m.range].to_string())
        .collect()
}

fn scan_ids_texts(finders: Vec<Box<dyn Finder>>, input: &str) -> Vec<(String, String)> {
    let scanner = Scanner::new(finders);
    scanner
        .scan_line(input)
        .into_iter()
        .map(|m| {
            (
                scanner.finders()[m.finder_index].id().to_string(),
                input[m.range].to_string(),
            )
        })
        .collect()
}

// ============================================================================
// Fix 1: ellipsis after a domain must not kill the match
// ============================================================================

#[test]
fn email_ellipsis_two_dots() {
    let input = "go to user@foo.com.. now";
    assert_eq!(
        Some("user@foo.com".to_string()),
        find_one(&Email::default(), input)
    );
}

#[test]
fn email_ellipsis_three_dots() {
    let input = "contact user@foo.com... thanks";
    assert_eq!(
        Some("user@foo.com".to_string()),
        find_one(&Email::default(), input)
    );
}

#[test]
fn email_ellipsis_four_dots() {
    let input = "user@foo.com.... end";
    assert_eq!(
        Some("user@foo.com".to_string()),
        find_one(&Email::default(), input)
    );
}

#[test]
fn email_ellipsis_at_end_of_input() {
    let input = "user@foo.com...";
    assert_eq!(
        Some("user@foo.com".to_string()),
        find_one(&Email::default(), input)
    );
}

#[test]
fn email_single_trailing_dot_unchanged() {
    let input = "user@example.com. next";
    assert_eq!(
        Some("user@example.com".to_string()),
        find_one(&Email::default(), input)
    );
}

#[test]
fn email_interior_double_dot_domain_still_rejected() {
    assert_eq!(None, find_one(&Email::default(), "user@example..com"));
}

#[test]
fn domain_ellipsis_two_dots() {
    let input = "go to example.com.. now";
    assert_eq!(
        Some("example.com".to_string()),
        find_one(&Domain::default(), input)
    );
}

#[test]
fn domain_ellipsis_three_dots() {
    let input = "go to example.com... now";
    assert_eq!(
        Some("example.com".to_string()),
        find_one(&Domain::default(), input)
    );
}

#[test]
fn domain_ellipsis_four_dots() {
    let input = "example.com....";
    assert_eq!(
        Some("example.com".to_string()),
        find_one(&Domain::default(), input)
    );
}

#[test]
fn domain_single_trailing_dot_unchanged() {
    let input = "go to example.com.";
    assert_eq!(
        Some("example.com".to_string()),
        find_one(&Domain::default(), input)
    );
}

#[test]
fn domain_interior_double_dot_still_rejected() {
    assert_eq!(None, find_one(&Domain::default(), "foo..bar.com"));
}

// ============================================================================
// Fix 2: multibyte glue must not produce truncated matches (domain side)
//
// Policy: reject only when the preceding char is a 2-byte UTF-8 sequence
// (Latin/Greek/Cyrillic scripts, where the ASCII tail is a truncation of a
// word, e.g. `bücher.de` -> `cher.de`). 3-and-4-byte scripts (CJK, emoji)
// remain accepted as delimiters, preserving the pins in tests/multibyte.rs
// (`email_with_emoji_around`, `scanner_multibyte_multi_finder`).
// ============================================================================

#[test]
fn domain_rejects_two_byte_latin_glue() {
    assert_eq!(None, find_one(&Domain::default(), "see bücher.de now"));
}

#[test]
fn domain_rejects_two_byte_cyrillic_glue() {
    assert_eq!(None, find_one(&Domain::default(), "дexample.com"));
}

#[test]
fn domain_rejects_two_byte_greek_glue() {
    assert_eq!(None, find_one(&Domain::default(), "αexample.com"));
}

#[test]
fn domain_cafe_fr_yields_nothing() {
    // The 2-byte é splits the token; no corrupted `.fr` match may surface.
    assert_eq!(None, find_one(&Domain::default(), "visit café.fr today"));
}

#[test]
fn domain_accepts_three_byte_cjk_glue() {
    // CJK adjacency stays accepted (policy pin).
    assert_eq!(
        Some("example.com".to_string()),
        find_one(&Domain::default(), "見example.com")
    );
}

#[test]
fn domain_accepts_four_byte_emoji_glue() {
    assert_eq!(
        Some("example.com".to_string()),
        find_one(&Domain::default(), "🌐example.com")
    );
}

// KNOWN LIMITATION (email side of fix 2 not applied): the frozen fuzz
// property `scanner_with_embedded_email` (tests/fuzz.rs) generates arbitrary
// non-local-part prefixes -- measured ~8.6% of them end with a 2-byte char --
// glued to `user@example.com` and requires the email to match. Rejecting
// 2-byte glue in the email finder would therefore fail the fuzz suite, which
// may not be modified. The truncated match below documents that accepted
// trade-off.
#[test]
fn email_two_byte_glue_known_limitation() {
    assert_eq!(
        Some("ller@example.com".to_string()),
        find_one(&Email::default(), "mail müller@example.com now")
    );
}

// ============================================================================
// Fix 3: no bogus domain inside plus-addressed emails
// ============================================================================

#[test]
fn domain_suppressed_inside_plus_addressed_email() {
    assert_eq!(
        None,
        find_one(&Domain::default(), "first.last+tag@company.co.uk")
    );
}

#[test]
fn domain_suppressed_with_multiple_dotted_runs() {
    assert_eq!(
        None,
        find_one(&Domain::default(), "a.dev+x.y@corp.example.org")
    );
}

#[test]
fn domain_suppressed_percent_local() {
    assert_eq!(
        None,
        find_one(&Domain::default(), "beta.builds%nightly@ci.example.com")
    );
}

#[test]
fn email_plus_addressed_matches_fully() {
    let input = "first.last+tag@company.co.uk";
    assert_eq!(Some(input.to_string()), find_one(&Email::default(), input));
}

#[test]
fn scanner_plus_addressed_yields_only_email() {
    let finders: Vec<Box<dyn Finder>> =
        vec![Box::new(Domain::default()), Box::new(Email::default())];
    assert_eq!(
        vec![(
            "email".to_string(),
            "first.last+tag@company.co.uk".to_string()
        )],
        scan_ids_texts(finders, "first.last+tag@company.co.uk")
    );
}

#[test]
fn domain_directly_followed_by_at_still_suppressed() {
    assert_eq!(None, find_one(&Domain::default(), "foo.com@bar"));
}

#[test]
fn domain_followed_by_space_then_local_chars_not_suppressed() {
    assert_eq!(
        Some("foo.com".to_string()),
        find_one(&Domain::default(), "foo.com +tag")
    );
}

// ============================================================================
// Fix 4 (documented conflict): email on fediverse handles
//
// KNOWN LIMITATION: rejecting an email whose local part is preceded by '@'
// would break the frozen fuzz property `scanner_with_embedded_email`
// (tests/fuzz.rs): its random prefix ends with '@' in ~7% of cases (measured)
// and the property requires `<prefix>user@example.com` to yield the email.
// `@user@example.com` (prefix "@") and `@alice@hachyderm.io` are byte-wise
// the same shape, so the finder cannot reject one and accept the other. The
// handle finder owns the full `@alice@hachyderm.io` span; the email overlap
// is the same accepted behavior pinned by
// `mastodon_handle_with_email_present` in tests/incompatibility.rs.
// ============================================================================

#[test]
fn email_fediverse_overlap_known_limitation() {
    assert_eq!(
        Some("alice@hachyderm.io".to_string()),
        find_one(&Email::default(), "@alice@hachyderm.io")
    );
}

#[test]
fn handle_matches_fediverse_fully() {
    assert_eq!(
        Some("@alice@hachyderm.io".to_string()),
        find_one(&Handle::default(), "@alice@hachyderm.io")
    );
}

#[test]
fn scanner_fediverse_handle_and_email_overlap() {
    let finders: Vec<Box<dyn Finder>> =
        vec![Box::new(Handle::default()), Box::new(Email::default())];
    assert_eq!(
        vec![
            ("handle".to_string(), "@alice@hachyderm.io".to_string()),
            ("email".to_string(), "alice@hachyderm.io".to_string()),
        ],
        scan_ids_texts(finders, "ping @alice@hachyderm.io ok")
    );
}

// ============================================================================
// Fix 5: no consecutive dots in the email local part (RFC 5322 dot-atom)
// ============================================================================

#[test]
fn email_rejects_double_dot_local() {
    assert_eq!(None, find_one(&Email::default(), "a..b@x.com"));
}

#[test]
fn email_rejects_double_dot_local_in_text() {
    assert_eq!(
        None,
        find_one(&Email::default(), "mail first..last@example.com now")
    );
}

#[test]
fn email_rejects_triple_dot_local() {
    assert_eq!(None, find_one(&Email::default(), "a...b@x.com"));
}

#[test]
fn email_accepts_single_dots_local() {
    let input = "first.last@example.com";
    assert_eq!(Some(input.to_string()), find_one(&Email::default(), input));
}

// ============================================================================
// Fix 6: email domain-part limits aligned with the domain finder
// ============================================================================

#[test]
fn email_accepts_63_char_label() {
    let input = format!("user@{}.com", "a".repeat(63));
    assert_eq!(Some(input.clone()), find_one(&Email::default(), &input));
}

#[test]
fn email_rejects_64_char_label() {
    let input = format!("user@{}.com", "a".repeat(64));
    assert_eq!(None, find_one(&Email::default(), &input));
}

#[test]
fn email_accepts_24_char_tld() {
    let input = format!("user@example.{}", "a".repeat(24));
    assert_eq!(Some(input.clone()), find_one(&Email::default(), &input));
}

#[test]
fn email_rejects_25_char_tld() {
    let input = format!("user@example.{}", "a".repeat(25));
    assert_eq!(None, find_one(&Email::default(), &input));
}

#[test]
fn domain_label_length_bounds_guard() {
    // Alignment guard: the domain finder already enforces these bounds.
    let ok = format!("{}.com", "a".repeat(63));
    assert_eq!(Some(ok.clone()), find_one(&Domain::default(), &ok));
    let too_long = format!("{}.com", "a".repeat(64));
    assert_eq!(None, find_one(&Domain::default(), &too_long));
}

#[test]
fn domain_tld_length_bounds_guard() {
    let ok = format!("example.{}", "a".repeat(24));
    assert_eq!(Some(ok.clone()), find_one(&Domain::default(), &ok));
    let too_long = format!("example.{}", "a".repeat(25));
    assert_eq!(None, find_one(&Domain::default(), &too_long));
}

#[test]
fn email_png_tld_still_matches() {
    // Known FP inherent to the no-TLD-allowlist design (pinned non-bug).
    let input = "foo@2x.png";
    assert_eq!(Some(input.to_string()), find_one(&Email::default(), input));
}

// ============================================================================
// Fix 7: sentence dot must not convert a dotless host into a valid one
// ============================================================================

#[test]
fn handle_dotless_host_sentence_dot() {
    assert_eq!(
        Some("@user".to_string()),
        find_one(&Handle::default(), "ping @user@localhost. thanks")
    );
}

#[test]
fn handle_dotless_host_plain_guard() {
    assert_eq!(
        Some("@user".to_string()),
        find_one(&Handle::default(), "ping @user@localhost thanks")
    );
}

#[test]
fn handle_valid_host_sentence_dot() {
    assert_eq!(
        Some("@user@example.social".to_string()),
        find_one(&Handle::default(), "see @user@example.social. bye")
    );
}

// ============================================================================
// Fix 8: handle host must validate like a domain, else bare-handle fallback
// ============================================================================

#[test]
fn handle_host_leading_dot_falls_back() {
    assert_eq!(
        Some("@u".to_string()),
        find_one(&Handle::default(), "@u@.com")
    );
}

#[test]
fn handle_host_consecutive_dots_falls_back() {
    assert_eq!(
        Some("@u".to_string()),
        find_one(&Handle::default(), "@u@a..b")
    );
}

#[test]
fn handle_host_numeric_tld_falls_back() {
    assert_eq!(
        Some("@u".to_string()),
        find_one(&Handle::default(), "@u@1.2")
    );
}

#[test]
fn handle_host_bare_trailing_dot_falls_back() {
    assert_eq!(
        Some("@u".to_string()),
        find_one(&Handle::default(), "@u@x. done")
    );
}

#[test]
fn handle_host_one_char_tld_falls_back() {
    assert_eq!(
        Some("@u".to_string()),
        find_one(&Handle::default(), "@u@x.c")
    );
}

#[test]
fn handle_host_subdomain_accepted() {
    let input = "@u@sub.domain.social";
    assert_eq!(Some(input.to_string()), find_one(&Handle::default(), input));
}

#[test]
fn handle_host_trailing_dots_stripped_then_valid() {
    assert_eq!(
        Some("@user@example.social".to_string()),
        find_one(&Handle::default(), "@user@example.social..")
    );
}

// ============================================================================
// Pinned non-bugs (intentional behavior, do not "fix")
// ============================================================================

#[test]
fn pin_domain_with_port_yields_nothing() {
    assert_eq!(None, find_one(&Domain::default(), "example.com:8080"));
}

#[test]
fn pin_domain_with_path_yields_nothing() {
    assert_eq!(None, find_one(&Domain::default(), "sub.example.com/path"));
}

#[test]
fn pin_email_ip_literal_unsupported() {
    assert_eq!(None, find_one(&Email::default(), "user@[192.168.1.1]"));
}

#[test]
fn pin_domain_matches_readme_md() {
    // TLD-shape heuristic, pinned.
    assert_eq!(
        Some("README.md".to_string()),
        find_one(&Domain::default(), "README.md")
    );
}

#[test]
fn pin_domain_matches_node_js() {
    assert_eq!(
        Some("node.js".to_string()),
        find_one(&Domain::default(), "node.js")
    );
}

#[test]
fn pin_email_in_scp_style_git_url() {
    assert_eq!(
        Some("git@github.com".to_string()),
        find_one(&Email::default(), "git@github.com:org/repo.git")
    );
}

#[test]
fn pin_dot_at_alice_matches_nothing() {
    assert_eq!(None, find_one(&Email::default(), ".@alice"));
    assert_eq!(None, find_one(&Handle::default(), ".@alice"));
}

#[test]
fn pin_babel_scope_yields_bare_handle() {
    assert_eq!(
        Some("@babel".to_string()),
        find_one(&Handle::default(), "@babel/core")
    );
}

// ============================================================================
// Scanner parity: scan_line vs the documented find() loop
// ============================================================================

#[test]
fn scanner_email_parity_on_corpus() {
    let corpus = [
        "go to user@foo.com... thanks",
        "user@example.com@evil.org",
        "a..b@x.com",
        "mail müller@example.com now",
        "cc: alice@one.com and bob@two.org",
        "first.last+tag@company.co.uk",
        "user@example.com.. next",
        "📧user@example.com📧",
        "ping @alice@hachyderm.io ok",
        "user@example..com",
        "git@github.com:org/repo.git",
    ];
    for input in corpus {
        let via_find = find_all(&Email::default(), input);
        let via_scanner = scan_texts(vec![Box::new(Email::default())], input);
        assert_eq!(via_find, via_scanner, "email parity on {input:?}");
    }
}

#[test]
fn scanner_email_overlapping_at_yields_single_match() {
    // The base-commit Scanner keeps per-finder matches disjoint.
    assert_eq!(
        vec!["user@example.com".to_string()],
        scan_texts(
            vec![Box::new(Email::default())],
            "user@example.com@evil.org"
        )
    );
}

#[test]
fn scanner_domain_parity_on_corpus() {
    let corpus = [
        "go to example.com.. now",
        "see bücher.de now",
        "first.last+tag@company.co.uk",
        "visit example.com today",
        "README.md and node.js",
        "example.com:8080 sub.example.com/path",
        "example.com and other.org",
        "дexample.com... ok",
    ];
    for input in corpus {
        let via_find = find_all(&Domain::default(), input);
        let via_scanner = scan_texts(vec![Box::new(Domain::default())], input);
        assert_eq!(via_find, via_scanner, "domain parity on {input:?}");
    }
}

#[test]
fn scanner_handle_parity_on_safe_corpus() {
    // Inputs whose matches are never immediately followed by another '@'
    // (the handle finder's known slice-boundary divergence, pinned below).
    let corpus = [
        "cc @alice@hachyderm.io and @bob",
        "@u@sub.domain.social ok",
        "say @bob- here",
        "ping @user@example.social. bye",
    ];
    for input in corpus {
        let via_find = find_all(&Handle::default(), input);
        let via_scanner = scan_texts(vec![Box::new(Handle::default())], input);
        assert_eq!(via_find, via_scanner, "handle parity on {input:?}");
    }
}

#[test]
fn scanner_handle_adjacent_divergence_pins() {
    // Pre-existing, accepted divergence: find() at slice position 0 cannot
    // see left context, so the find() loop re-matches `@b`, while the
    // Scanner (absolute positions) rejects it.
    assert_eq!(
        vec!["@a".to_string(), "@b".to_string()],
        find_all(&Handle::default(), "@a@b cool")
    );
    assert_eq!(
        vec!["@a".to_string()],
        scan_texts(vec![Box::new(Handle::default())], "@a@b cool")
    );
}

#[test]
fn scanner_handle_dotless_fallback_pins() {
    // Same accepted divergence class after a bare-handle fallback.
    assert_eq!(
        vec!["@user".to_string(), "@localhost".to_string()],
        find_all(&Handle::default(), "ping @user@localhost. thanks")
    );
    assert_eq!(
        vec!["@user".to_string()],
        scan_texts(
            vec![Box::new(Handle::default())],
            "ping @user@localhost. thanks"
        )
    );
}
