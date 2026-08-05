//! Hardening regression tests for the scalar finders: datetime, semver,
//! phone, and color.
//!
//! Each fixed bug gets a direct regression test plus variants, every
//! documented non-bug (accepted leniency / known false positive) is pinned,
//! and Scanner-vs-find parity is asserted over the whole corpus for all four
//! finders.

use squeeze::Finder;
use squeeze::color::Color;
use squeeze::datetime::Datetime;
use squeeze::phone::Phone;
use squeeze::scanner::Scanner;
use squeeze::semver::Semver;

// ============================================================================
// Helpers
// ============================================================================

fn find_all(finder: &dyn Finder, input: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut idx = 0;
    while idx < input.len() {
        if let Some(range) = finder.find(&input[idx..]) {
            assert!(range.start < range.end, "empty range on {input:?}");
            results.push(input[idx + range.start..idx + range.end].to_string());
            idx += range.end;
        } else {
            break;
        }
    }
    results
}

fn assert_finds(finder: &dyn Finder, input: &str, expected: &str) {
    let range = finder
        .find(input)
        .unwrap_or_else(|| panic!("expected {expected:?} in {input:?}, got no match"));
    assert_eq!(expected, &input[range], "wrong span in {input:?}");
}

fn assert_finds_none(finder: &dyn Finder, input: &str) {
    if let Some(range) = finder.find(input) {
        panic!("expected no match in {input:?}, got {:?}", &input[range]);
    }
}

/// Scanner-vs-find parity: the Scanner (whatever mode the finder uses) must
/// surface the same match texts as the plain find() loop.
fn assert_scanner_find_parity(make: fn() -> Box<dyn Finder>, corpus: &[&str]) {
    for input in corpus {
        let mut old = find_all(make().as_ref(), input);
        let scanner = Scanner::new(vec![make()]);
        let mut new: Vec<String> = scanner
            .scan_line(input)
            .into_iter()
            .map(|m| input[m.range].to_string())
            .collect();
        old.sort();
        new.sort();
        assert_eq!(old, new, "Scanner-vs-find mismatch on {input:?}");
    }
}

// ============================================================================
// Datetime: timezone offsets after a time component (bugs 1a + 3)
// ============================================================================

#[test]
fn datetime_negative_basic_offset() {
    let input = "2024-01-15T10:30:00-0800";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00-0800");
}

#[test]
fn datetime_positive_basic_offset_includes_offset() {
    let input = "2024-01-15T10:30:00+0800";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00+0800");
}

#[test]
fn datetime_negative_hh_only_offset() {
    let input = "2024-01-15T10:30:00-08";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00-08");
}

#[test]
fn datetime_positive_hh_only_offset() {
    let input = "2024-01-15T10:30:00+05";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00+05");
}

#[test]
fn datetime_positive_basic_offset_0530() {
    let input = "2024-01-15T10:30:00+0530";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00+0530");
}

#[test]
fn datetime_extended_offsets_still_work() {
    assert_finds(
        &Datetime::default(),
        "2024-01-15T10:30:00-08:00",
        "2024-01-15T10:30:00-08:00",
    );
    assert_finds(
        &Datetime::default(),
        "2024-01-15T10:30:00+05:30",
        "2024-01-15T10:30:00+05:30",
    );
}

#[test]
fn datetime_postgres_form_space_separator_hh_offset() {
    let input = "ts 2024-01-15 10:30:00-08 end";
    assert_finds(&Datetime::default(), input, "2024-01-15 10:30:00-08");
}

#[test]
fn datetime_offset_embedded_in_text() {
    let input = "deployed at 2024-01-15T10:30:00-0800 by ci";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00-0800");
}

#[test]
fn datetime_offset_after_fractional_seconds() {
    let input = "2024-01-15T10:30:00.123-0800";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00.123-0800");
}

#[test]
fn datetime_offset_without_seconds() {
    let input = "2024-01-15T10:30-0500";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30-0500");
}

#[test]
fn datetime_no_offset_on_bare_date() {
    // No time component means no timezone: `-0800` after a bare date keeps
    // the digit-after-dash ambiguity veto.
    assert_finds_none(&Datetime::default(), "2024-01-15-0800");
}

// ============================================================================
// Datetime: kebab-case boundaries (bug 1b)
// ============================================================================

#[test]
fn datetime_jekyll_post_name_at_start() {
    let input = "2024-01-15-my-blog-post.md";
    assert_finds(&Datetime::default(), input, "2024-01-15");
}

#[test]
fn datetime_kebab_date_mid_word() {
    let input = "backup-2024-01-15-full.tar.gz";
    assert_finds(&Datetime::default(), input, "2024-01-15");
}

#[test]
fn datetime_kebab_date_at_end() {
    let input = "notes-2024-01-15";
    assert_finds(&Datetime::default(), input, "2024-01-15");
}

#[test]
fn datetime_trailing_dash_at_eof() {
    let input = "2024-01-15-";
    assert_finds(&Datetime::default(), input, "2024-01-15");
}

#[test]
fn datetime_dash_digit_still_vetoed() {
    // `2024-01-15-01` is ambiguous (could be a longer serial); keep vetoing.
    assert_finds_none(&Datetime::default(), "2024-01-15-01");
}

#[test]
fn datetime_digit_dash_prefix_still_vetoed() {
    // A '-' glued to a preceding digit run is not a word boundary.
    assert_finds_none(&Datetime::default(), "01-2024-01-15");
}

#[test]
fn datetime_multiple_kebab_dates_iteratively() {
    let finder = Datetime::default();
    let input = "2024-01-15-post and draft-2024-02-20-v2.md";
    assert_eq!(find_all(&finder, input), vec!["2024-01-15", "2024-02-20"]);
}

// ============================================================================
// Datetime: lowercase t / z (bug 2)
// ============================================================================

#[test]
fn datetime_lowercase_t_and_z() {
    let input = "2024-01-15t10:30:00z";
    assert_finds(&Datetime::default(), input, "2024-01-15t10:30:00z");
}

#[test]
fn datetime_lowercase_z_only() {
    let input = "2024-01-15T10:30:00z";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00z");
}

#[test]
fn datetime_lowercase_t_only() {
    let input = "2024-01-15t10:30:00";
    assert_finds(&Datetime::default(), input, "2024-01-15t10:30:00");
}

#[test]
fn datetime_lowercase_t_with_offset() {
    let input = "2024-01-15t10:30:00-0800";
    assert_finds(&Datetime::default(), input, "2024-01-15t10:30:00-0800");
}

#[test]
fn datetime_t_followed_by_word_is_date_only() {
    let input = "2024-01-15this-is-fine";
    assert_finds(&Datetime::default(), input, "2024-01-15");
}

// ============================================================================
// Datetime: comma fractional seconds (bug 4)
// ============================================================================

#[test]
fn datetime_comma_fraction() {
    let input = "2024-01-15T10:30:00,5";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00,5");
}

#[test]
fn datetime_comma_fraction_with_zone() {
    let input = "2024-01-15T10:30:00,123Z";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00,123Z");
}

#[test]
fn datetime_comma_then_space_not_consumed() {
    let input = "at 2024-01-15 10:30:00, next item";
    assert_finds(&Datetime::default(), input, "2024-01-15 10:30:00");
}

#[test]
fn datetime_dot_fraction_still_works() {
    let input = "2024-01-15T10:30:00.123456+02:00";
    assert_finds(
        &Datetime::default(),
        input,
        "2024-01-15T10:30:00.123456+02:00",
    );
}

// ============================================================================
// Datetime: pinned non-bugs (documented leniency)
// ============================================================================

#[test]
fn datetime_pin_feb_30_lenient() {
    // Day is range-checked (1..=31) but not calendar-checked.
    assert_finds(&Datetime::default(), "2024-02-30", "2024-02-30");
}

#[test]
fn datetime_pin_hour_24_degrades_to_date_only() {
    assert_finds(&Datetime::default(), "2024-01-15T24:00:00Z", "2024-01-15");
}

#[test]
fn datetime_pin_leap_second_any_minute() {
    let input = "2024-06-30T12:15:60Z";
    assert_finds(&Datetime::default(), input, "2024-06-30T12:15:60Z");
}

#[test]
fn datetime_pin_out_of_range_offset_lenient() {
    let input = "2024-01-15T10:30:00+99:99";
    assert_finds(&Datetime::default(), input, "2024-01-15T10:30:00+99:99");
}

#[test]
fn datetime_pin_basic_format_unsupported() {
    assert_finds_none(&Datetime::default(), "20240115T103000Z");
}

#[test]
fn datetime_pin_week_date_unsupported() {
    assert_finds_none(&Datetime::default(), "2024-W03-1");
}

#[test]
fn datetime_pin_ordinal_date_unsupported() {
    assert_finds_none(&Datetime::default(), "2024-032");
}

#[test]
fn datetime_pin_followed_by_digit_rejected() {
    assert_finds_none(&Datetime::default(), "2024-01-155");
}

#[test]
fn datetime_pin_preceded_by_digit_rejected() {
    assert_finds_none(&Datetime::default(), "x12024-01-15");
}

// ============================================================================
// Semver: trailing dot as punctuation (bug 5)
// ============================================================================

#[test]
fn semver_trailing_dot_sentence() {
    let input = "Upgrade to 1.2.3.";
    assert_finds(&Semver::default(), input, "1.2.3");
}

#[test]
fn semver_trailing_dot_tarball() {
    let input = "pkg-1.2.3.tar.gz";
    assert_finds(&Semver::default(), input, "1.2.3");
}

#[test]
fn semver_prerelease_trailing_dot_in_text() {
    let input = "use 1.0.0-beta. done";
    assert_finds(&Semver::default(), input, "1.0.0-beta");
}

#[test]
fn semver_prerelease_trailing_dot_at_eof() {
    let input = "1.0.0-beta.";
    assert_finds(&Semver::default(), input, "1.0.0-beta");
}

#[test]
fn semver_dotted_prerelease_trailing_dot() {
    let input = "try 1.0.0-rc.1. thanks";
    assert_finds(&Semver::default(), input, "1.0.0-rc.1");
}

#[test]
fn semver_four_components_still_rejected() {
    assert_finds_none(&Semver::default(), "1.2.3.4");
    assert_finds_none(&Semver::default(), "1.0.0.0 too many");
}

// ============================================================================
// Semver: trailing '-' / '+' as boundaries (bug 6)
// ============================================================================

#[test]
fn semver_arrow_extracts_both_versions() {
    let finder = Semver::default();
    let input = "1.0.0->2.0.0";
    assert_eq!(find_all(&finder, input), vec!["1.0.0", "2.0.0"]);
}

#[test]
fn semver_trailing_dash_in_text() {
    let input = "use 1.2.3- now";
    assert_finds(&Semver::default(), input, "1.2.3");
}

#[test]
fn semver_trailing_plus_at_eof() {
    let input = "1.2.3+";
    assert_finds(&Semver::default(), input, "1.2.3");
}

#[test]
fn semver_trailing_plus_in_text() {
    let input = "bump 1.2.3+ done";
    assert_finds(&Semver::default(), input, "1.2.3");
}

#[test]
fn semver_prerelease_then_dangling_plus() {
    let input = "1.0.0-beta+";
    assert_finds(&Semver::default(), input, "1.0.0-beta");
}

// ============================================================================
// Semver: pinned non-bugs
// ============================================================================

#[test]
fn semver_pin_ip_not_semver() {
    assert_finds_none(&Semver::default(), "192.168.1.1");
}

#[test]
fn semver_pin_leading_zero_leniency() {
    assert_finds(&Semver::default(), "1.02.3", "1.02.3");
    assert_finds(&Semver::default(), "01.2.3", "01.2.3");
}

#[test]
fn semver_pin_full_prerelease_build_untouched() {
    let input = "release 1.0.0-rc.1+build.42 ok";
    assert_finds(&Semver::default(), input, "1.0.0-rc.1+build.42");
}

#[test]
fn semver_pin_two_components_rejected() {
    assert_finds_none(&Semver::default(), "1.0 only");
}

#[test]
fn semver_pin_preceded_by_dot_rejected() {
    assert_finds_none(&Semver::default(), ".1.0.0");
}

// ============================================================================
// Phone: scan-mode conversion + overlap resume (bug 7)
// ============================================================================

#[test]
fn phone_find_recovers_overlapping_number() {
    // The `+415...` candidate fails the boundary-before check ('x' is
    // alphanumeric); find() must resume inside it and surface `415.555.1234`.
    let input = "x+415.555.1234";
    assert_finds(&Phone::default(), input, "415.555.1234");
}

#[test]
fn phone_is_plain_scan_mode() {
    let finder = Phone::default();
    assert!(!finder.dispatchable(), "phone must be a scan-mode finder");
    assert!(!finder.triggerable());
    // Default trait impl: try_at is inert.
    assert!(finder.try_at(b"+14155551234", 0).is_none());
}

#[test]
fn phone_all_digit_100kb_line_scans() {
    // Correctness stand-in for the perf fix: a single 100KB digit line used
    // to take ~60s through the dispatch path. No timing assert; the test
    // simply has to complete (and find nothing).
    let input = "9".repeat(100_000);
    assert_finds_none(&Phone::default(), &input);

    let scanner = Scanner::new(vec![Box::new(Phone::default()) as Box<dyn Finder>]);
    assert!(scanner.scan_line(&input).is_empty());
}

#[test]
fn phone_plus_then_100kb_digits_scans() {
    // One oversized '+' candidate (>15 digits) then a clean resume.
    let mut input = String::from("+");
    input.push_str(&"9".repeat(100_000));
    assert_finds_none(&Phone::default(), &input);
}

#[test]
fn phone_scanner_still_finds_numbers_after_conversion() {
    let scanner = Scanner::new(vec![Box::new(Phone::default()) as Box<dyn Finder>]);
    let input = "call +1-800-555-0199 or (212) 555-6789 now";
    let texts: Vec<&str> = scanner
        .scan_line(input)
        .into_iter()
        .map(|m| &input[m.range])
        .collect();
    assert_eq!(texts, vec!["+1-800-555-0199", "(212) 555-6789"]);
}

// ============================================================================
// Phone: 5+ digit-group internationals (bug 8)
// ============================================================================

#[test]
fn phone_french_number() {
    let input = "appelez le +33 1 42 96 12 34 svp";
    assert_finds(&Phone::default(), input, "+33 1 42 96 12 34");
}

#[test]
fn phone_german_number() {
    let input = "+49 30 12 34 56 78";
    assert_finds(&Phone::default(), input, "+49 30 12 34 56 78");
}

#[test]
fn phone_uk_number() {
    let input = "+44 20 7946 0958";
    assert_finds(&Phone::default(), input, "+44 20 7946 0958");
}

#[test]
fn phone_french_number_with_dots() {
    let input = "+33.1.42.96.12.34";
    assert_finds(&Phone::default(), input, "+33.1.42.96.12.34");
}

// ============================================================================
// Phone: diff-line false positive (bug 9)
// ============================================================================

#[test]
fn phone_diff_line_date_rejected() {
    assert_finds_none(&Phone::default(), "+2024-01-15 fixed the bug");
}

#[test]
fn phone_plus_year_with_separators_rejected() {
    assert_finds_none(&Phone::default(), "+2024.01.15");
}

#[test]
fn phone_compact_e164_unaffected() {
    assert_finds(&Phone::default(), "call +14155551234", "+14155551234");
}

#[test]
fn phone_separated_short_country_codes_unaffected() {
    assert_finds(&Phone::default(), "+1 415 555 1234", "+1 415 555 1234");
    assert_finds(&Phone::default(), "+1-415-555-1234", "+1-415-555-1234");
    assert_finds(&Phone::default(), "+33 1 42 96 12 34", "+33 1 42 96 12 34");
}

// ============================================================================
// Phone: pinned non-bugs
// ============================================================================

#[test]
fn phone_pin_bare_10_digit_run_rejected() {
    assert_finds_none(&Phone::default(), "4155551234");
    assert_finds_none(&Phone::default(), "1234567890");
}

#[test]
fn phone_pin_year_rejected() {
    assert_finds_none(&Phone::default(), "in 2024 we shipped");
}

#[test]
fn phone_pin_ip_rejected() {
    assert_finds_none(&Phone::default(), "192.168.1.1");
}

#[test]
fn phone_pin_credit_card_rejected() {
    assert_finds_none(&Phone::default(), "4111-1111-1111-1111");
}

#[test]
fn phone_pin_more_than_15_digits_rejected() {
    assert_finds_none(&Phone::default(), "+1234567890123456");
}

#[test]
fn phone_pin_preceded_by_alpha_rejected() {
    assert_finds_none(&Phone::default(), "x+14155551234");
}

#[test]
fn phone_pin_na_formats_untouched() {
    assert_finds(&Phone::default(), "call (415) 555-1234", "(415) 555-1234");
    assert_finds(&Phone::default(), "call 415-555-1234", "415-555-1234");
    assert_finds(&Phone::default(), "call 415.555.1234", "415.555.1234");
}

#[test]
fn phone_pin_followed_by_digit_rejected() {
    assert_finds_none(&Phone::default(), "415.555.12345");
}

// ============================================================================
// Color: word-boundary after hex run (bug 11)
// ============================================================================

#[test]
fn color_deadline_is_not_a_color() {
    assert_finds_none(&Color::default(), "#deadline");
}

#[test]
fn color_fadeout_is_not_a_color() {
    assert_finds_none(&Color::default(), "#fadeout");
}

#[test]
fn color_deadline_family_words_rejected() {
    for input in ["#deadlines", "#fadeout2", "#beefy", "#cafeteria", "#facets"] {
        assert_finds_none(&Color::default(), input);
    }
}

#[test]
fn color_underscore_after_hex_rejected() {
    assert_finds_none(&Color::default(), "#dead_beef");
}

#[test]
fn color_hex_before_punctuation_still_matches() {
    assert_finds(&Color::default(), "#dead;", "#dead");
    assert_finds(&Color::default(), "bg: #ff00aa!", "#ff00aa");
    assert_finds(&Color::default(), "#abc123 next", "#abc123");
}

#[test]
fn color_hex_at_eof_still_matches() {
    assert_finds(&Color::default(), "#dead", "#dead");
}

#[test]
fn color_pin_decade_whole_word_hex_fp() {
    // `#decade` is entirely hex digits; accepted as a known false positive.
    assert_finds(&Color::default(), "#decade", "#decade");
}

#[test]
fn color_pin_facade_whole_word_hex_fp() {
    // Same class as `#decade`: `facade` minus the non-hex... `facade` is
    // f,a,c,a,d,e — all hex — 6 chars, accepted FP.
    assert_finds(&Color::default(), "#facade", "#facade");
}

#[test]
fn color_pin_issue_number_fp() {
    // `fixes #1234` — 4 hex digits — inherent false positive, pinned.
    assert_finds(&Color::default(), "fixes #1234", "#1234");
}

// ============================================================================
// Color: capped closing-paren search (bug 12)
// ============================================================================

#[test]
fn color_spaced_rgb_still_matches() {
    let input = "rgb( 255 , 0 , 0 )";
    assert_finds(&Color::default(), input, "rgb( 255 , 0 , 0 )");
}

#[test]
fn color_longish_function_under_cap_matches() {
    // ~100 bytes of arguments: still well under the 256-byte cap.
    let args = format!("{}255, 0, 0{}", " ".repeat(50), " ".repeat(50));
    let input = format!("rgb({args})");
    assert_finds(&Color::default(), &input, &input);
}

#[test]
fn color_function_body_over_cap_rejected() {
    // The closing paren sits past the 256-byte cap: treated as unclosed.
    let input = format!("rgb({})", " ".repeat(300));
    assert_finds_none(&Color::default(), &input);
}

#[test]
fn color_many_unclosed_rgb_completes() {
    // 100KB of `rgb(`: each candidate's paren search is capped, so this
    // completes quickly instead of scanning to end-of-line per candidate.
    let input = "rgb(".repeat(25_000);
    assert_finds_none(&Color::default(), &input);

    let scanner = Scanner::new(vec![Box::new(Color::default()) as Box<dyn Finder>]);
    assert!(scanner.scan_line(&input).is_empty());
}

#[test]
fn color_unclosed_rgb_rejected() {
    assert_finds_none(&Color::default(), "rgb(255, 0, 170");
}

#[test]
fn color_nested_parens_still_supported() {
    let input = "rgba(calc(1), 0, 0, 1)";
    assert_finds(&Color::default(), input, "rgba(calc(1), 0, 0, 1)");
}

// ============================================================================
// Color: pinned non-bugs
// ============================================================================

#[test]
fn color_pin_modern_functions_unsupported() {
    for input in ["hwb(120 100% 50%)", "lab(50% 40 59)", "oklch(0.7 0.1 200)"] {
        assert_finds_none(&Color::default(), input);
    }
}

#[test]
fn color_pin_space_before_paren_rejected() {
    assert_finds_none(&Color::default(), "rgb (1,2,3)");
}

#[test]
fn color_pin_argument_contents_unvalidated() {
    // Structure-only design: argument contents are not validated.
    assert_finds(&Color::default(), "rgb(-1,999,hello)", "rgb(-1,999,hello)");
}

#[test]
fn color_pin_preceded_by_alpha_rejected() {
    assert_finds_none(&Color::default(), "srgb(1, 2, 3)");
}

// ============================================================================
// Scanner-vs-find parity over the whole corpus
// ============================================================================

const DATETIME_CORPUS: &[&str] = &[
    "2024-01-15T10:30:00-0800",
    "2024-01-15T10:30:00+0800",
    "2024-01-15T10:30:00-08",
    "2024-01-15T10:30:00+05",
    "2024-01-15T10:30:00-08:00",
    "2024-01-15T10:30:00+05:30",
    "2024-01-15T10:30:00+0530",
    "ts 2024-01-15 10:30:00-08 end",
    "2024-01-15t10:30:00z",
    "2024-01-15T10:30:00z",
    "2024-01-15-my-blog-post.md",
    "backup-2024-01-15-full.tar.gz",
    "notes-2024-01-15",
    "2024-01-15-01",
    "01-2024-01-15",
    "2024-01-15T10:30:00,5",
    "at 2024-01-15 10:30:00, next item",
    "2024-02-30",
    "2024-01-15T24:00:00Z",
    "20240115T103000Z",
    "2024-01-155",
    "x12024-01-15",
    "2024-01-15-post and draft-2024-02-20-v2.md",
    "2024-01-15-0800",
    "",
];

const SEMVER_CORPUS: &[&str] = &[
    "Upgrade to 1.2.3.",
    "pkg-1.2.3.tar.gz",
    "use 1.0.0-beta. done",
    "1.0.0-beta.",
    "1.0.0->2.0.0",
    "use 1.2.3- now",
    "1.2.3+",
    "bump 1.2.3+ done",
    "192.168.1.1",
    "1.2.3.4",
    "v1.0.0-rc.1 is out",
    "release 1.0.0-rc.1+build.42 ok",
    "1.02.3",
    "01.2.3",
    ".1.0.0",
    "a1.0.0",
    "from 1.0.0 to 2.0.0",
    "",
];

const PHONE_CORPUS: &[&str] = &[
    "x+415.555.1234",
    "+33 1 42 96 12 34",
    "+49 30 12 34 56 78",
    "+44 20 7946 0958",
    "+2024-01-15 fixed the bug",
    "call +14155551234",
    "+1 415 555 1234",
    "call (415) 555-1234",
    "call 415-555-1234 or 415.555.1234",
    "4155551234",
    "192.168.1.1",
    "4111-1111-1111-1111",
    "+1234567890123456",
    "x+14155551234",
    "415.555.12345",
    "+14155551234 and (212) 555-6789",
    "",
];

const COLOR_CORPUS: &[&str] = &[
    "#deadline",
    "#fadeout",
    "#decade",
    "#facade",
    "#dead_beef",
    "#dead;",
    "#dead",
    "fixes #1234",
    "rgb( 255 , 0 , 0 )",
    "rgb(255, 0, 170",
    "rgba(calc(1), 0, 0, 1)",
    "rgb (1,2,3)",
    "srgb(1, 2, 3)",
    "#ff0000 and rgb(0, 255, 0)",
    "color: #333;",
    "",
];

#[test]
fn datetime_scanner_find_parity() {
    assert_scanner_find_parity(|| Box::new(Datetime::default()), DATETIME_CORPUS);
}

#[test]
fn semver_scanner_find_parity() {
    assert_scanner_find_parity(|| Box::new(Semver::default()), SEMVER_CORPUS);
}

#[test]
fn phone_scanner_find_parity() {
    assert_scanner_find_parity(|| Box::new(Phone::default()), PHONE_CORPUS);
}

#[test]
fn color_scanner_find_parity() {
    assert_scanner_find_parity(|| Box::new(Color::default()), COLOR_CORPUS);
}
