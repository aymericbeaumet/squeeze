//! Adversarial single lines that used to make a finder rescan the same
//! bytes from every candidate. Each case runs through the scanner with the
//! full finder set and must finish in far less time than a quadratic scan
//! would take (a generous bound keeps the tests meaningful on loaded CI
//! machines: the quadratic versions took seconds to minutes).

use squeeze::Finder;
use squeeze::scanner::{ScanStats, Scanner};
use std::time::{Duration, Instant};

fn all_finders() -> Vec<Box<dyn Finder>> {
    let mut hash = squeeze::hash::Hash::default();
    for algorithm in ["md5", "sha1", "sha256", "sha512"] {
        assert!(hash.add_algorithm(algorithm));
    }
    vec![
        Box::new(squeeze::cidr::Cidr::default()),
        Box::new(squeeze::codetag::Codetag::default()),
        Box::new(squeeze::color::Color::default()),
        Box::new(squeeze::datetime::Datetime::default()),
        Box::new(squeeze::domain::Domain::default()),
        Box::new(squeeze::email::Email::default()),
        Box::new(squeeze::emoji::Emoji::default()),
        Box::new(squeeze::env::Env::default()),
        Box::new(squeeze::handle::Handle::default()),
        Box::new(hash),
        Box::new(squeeze::ip::Ip::default()),
        Box::new(squeeze::json::Json::default()),
        Box::new(squeeze::jwt::Jwt::default()),
        Box::new(squeeze::mac::Mac::default()),
        Box::new(squeeze::modeline::Modeline::default()),
        Box::new(squeeze::path::Path::default()),
        Box::new(squeeze::phone::Phone::default()),
        Box::new(squeeze::semver::Semver::default()),
        Box::new(squeeze::uri::URI::default()),
        Box::new(squeeze::uuid::Uuid::default()),
    ]
}

/// Scans `line` with every finder and returns the matches as `(finder id,
/// text)`, asserting the scan stayed well under the quadratic regime.
fn scan_bounded(line: &str) -> (Vec<(&'static str, String)>, ScanStats) {
    let scanner = Scanner::new(all_finders());
    let mut matches = Vec::new();
    let mut stats = ScanStats::for_scanner(&scanner);
    let started = Instant::now();
    scanner.scan_line_stats(line, &mut matches, &mut stats);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "scan of {} bytes took {elapsed:?}",
        line.len()
    );
    let texts = matches
        .iter()
        .map(|m| {
            (
                scanner.finders()[m.finder_index].id(),
                line[m.range.clone()].to_string(),
            )
        })
        .collect();
    (texts, stats)
}

#[test]
fn dotted_hex_run_is_scanned_once() {
    // Every element after a `.` used to rescan the whole `[hex:.]` run.
    let line = "1.".repeat(50_000);
    let (texts, _) = scan_bounded(&line);
    assert!(texts.iter().all(|(_, t)| !t.contains(':')));
    let line = "a.".repeat(50_000);
    scan_bounded(&line);
}

#[test]
fn colon_hex_run_with_dotted_quads_is_scanned_once() {
    // A quad after `:` used to walk back to the start of the run.
    let line = "1:1.".repeat(25_000);
    scan_bounded(&line);
    let line = format!("x{}", "1:".repeat(40_000));
    scan_bounded(&line);
}

#[test]
fn unclosed_brackets_are_bounded() {
    // `[` and `]` searches are bounded by the longest IPv6 address, and
    // every `[` of a too-deep run is answered from the memo.
    let line = "[".repeat(100_000);
    let (texts, stats) = scan_bounded(&line);
    assert!(texts.is_empty());
    assert!(stats.calls() <= 2 * line.len() as u64);
    let mut line = "[".repeat(100_000);
    line.push(']');
    scan_bounded(&line);
}

#[test]
fn too_deep_json_still_yields_no_inner_fragment() {
    let mut line = "[".repeat(300);
    line.push('1');
    line.push_str(&"]".repeat(300));
    let (texts, _) = scan_bounded(&line);
    assert!(texts.iter().all(|(_, t)| !t.starts_with('[')), "{texts:?}");
    // Below the limit the document is matched whole.
    let mut line = "[".repeat(100);
    line.push('1');
    line.push_str(&"]".repeat(100));
    let (texts, _) = scan_bounded(&line);
    assert_eq!(texts, vec![("json", line.clone())]);
}

#[test]
fn many_modeline_candidates_stay_linear() {
    // Every `ex:` is a modeline candidate whose option run has no `=`;
    // whatever other finders make of the tokens, modeline must not match.
    let line = "ex:a ".repeat(20_000);
    let (texts, _) = scan_bounded(&line);
    assert!(texts.iter().all(|(kind, _)| *kind != "modeline"));
}

#[test]
fn many_phone_candidates_stay_linear() {
    let line = "+1 ".repeat(30_000);
    scan_bounded(&line);
    let line = "(123) ".repeat(15_000);
    scan_bounded(&line);
    let line = "123-456-".repeat(12_000);
    scan_bounded(&line);
}

#[test]
fn many_codetag_candidates_stay_linear() {
    let line = "TODO( ".repeat(15_000);
    scan_bounded(&line);
    let line = "todo ".repeat(20_000);
    scan_bounded(&line);
}

#[test]
fn long_hex_and_digit_runs_stay_linear() {
    let line = "f".repeat(100_000);
    let (texts, stats) = scan_bounded(&line);
    assert!(texts.is_empty());
    assert!(stats.calls() < 100);
    let line = "9".repeat(100_000);
    let (_, stats) = scan_bounded(&line);
    assert!(stats.calls() < 100);
}

#[test]
fn many_domain_candidates_stay_linear() {
    // Every dot of a failing token used to walk the token again.
    let line = "a.b".repeat(30_000);
    let (texts, stats) = scan_bounded(&line);
    assert!(texts.iter().all(|(kind, _)| *kind != "domain"), "{texts:?}");
    assert!(stats.calls() <= 4 * line.len() as u64);
    let line = "x.y ".repeat(25_000);
    scan_bounded(&line);
    let line = "a.com.".repeat(15_000);
    scan_bounded(&line);
}
