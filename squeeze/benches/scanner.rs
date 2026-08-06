use squeeze::{
    Finder, cidr::Cidr, codetag::Codetag, color::Color, datetime::Datetime, domain::Domain,
    email::Email, emoji::Emoji, env::Env, handle::Handle, hash::Hash, ip::Ip, json::Json, jwt::Jwt,
    mac::Mac, modeline::Modeline, path::Path, phone::Phone, scanner::Scanner, semver::Semver,
    uri::URI, uuid::Uuid,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

fn all_finders() -> Vec<Box<dyn Finder>> {
    let mut hash = Hash::default();
    for algorithm in ["md5", "sha1", "sha256", "sha512"] {
        assert!(hash.add_algorithm(algorithm));
    }

    vec![
        Box::new(Cidr::default()),
        Box::new(Codetag::default()),
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
        Box::new(URI::default()),
        Box::new(Uuid::default()),
    ]
}

fn bench_case(name: &str, scanner: &Scanner, lines: &[String], min_duration: Duration) {
    let bytes: usize = lines.iter().map(|line| line.len()).sum();
    let mut iterations = 0u64;
    let mut matches = 0usize;
    let start = Instant::now();

    while start.elapsed() < min_duration {
        for line in lines {
            matches += black_box(scanner.scan_line(line)).len();
        }
        iterations += 1;
    }

    let elapsed = start.elapsed();
    let total_bytes = bytes as f64 * iterations as f64;
    let mib_per_s = total_bytes / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "{name:18} {:>8.1} MiB/s  {:>6} lines/iter  {:>8} matches",
        mib_per_s,
        lines.len(),
        matches
    );
}

fn repeated_lines(seed: &[&str], repeats: usize) -> Vec<String> {
    (0..repeats)
        .flat_map(|_| seed.iter().map(|line| (*line).to_string()))
        .collect()
}

fn main() {
    let uri_scanner = Scanner::new(vec![Box::new(URI::default())]);
    let all_scanner = Scanner::new(all_finders());

    let url_lines = repeated_lines(
        &[
            "visit https://example.com/path?q=1#frag",
            "mailto:alice@example.com and http://localhost:8080",
            "plain text without a url",
        ],
        2048,
    );
    let all_lines = repeated_lines(
        &[
            r#"TODO: email alice@example.com about https://example.com {"ok": true}"#,
            "$HOME 192.168.1.0/24 v1.2.3 #ff00aa 550e8400-e29b-41d4-a716-446655440000",
            "00:1A:2B:3C:4D:5E +1-415-555-1234 vim: set ts=4 sw=4 et:",
        ],
        2048,
    );
    let no_match_lines = repeated_lines(&["the quick brown text has no structured data"], 8192);
    let dense_lines = repeated_lines(&["$A $B $C $D $E $F $G $H $I $J"], 8192);
    let long_lines = vec![format!(
        "{} https://example.com {}",
        "x".repeat(8192),
        "y".repeat(8192)
    )];
    let unicode_lines = repeated_lines(
        &["日本語テキスト 🌐192.168.1.1 📧user@example.com 🎉"],
        4096,
    );

    let duration = Duration::from_millis(500);
    bench_case("url_only", &uri_scanner, &url_lines, duration);
    bench_case("all_finders", &all_scanner, &all_lines, duration);
    bench_case("no_match", &all_scanner, &no_match_lines, duration);
    bench_case("dense_matches", &all_scanner, &dense_lines, duration);
    bench_case("long_line", &uri_scanner, &long_lines, duration);
    bench_case("unicode", &all_scanner, &unicode_lines, duration);
}
