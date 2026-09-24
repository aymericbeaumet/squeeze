//! Scanner throughput and operation-count benchmark.
//!
//! Runs the scanner over deterministic synthetic corpora (plus the URI
//! fixture and any `--corpus` files) and reports throughput together with
//! the operation counters from [`ScanStats`], so that a change can be judged
//! both by wall-clock time and by the amount of work it dispatches.
//!
//! ```text
//! cargo bench -p squeeze --bench scanner -- [OPTIONS]
//!
//!   --stats             print operation counters next to throughput
//!   --per-finder        also time every finder alone on every corpus
//!   --strategy a,b|all  scanner strategies to compare, interleaved (default: vector)
//!   --finders a,b,c     restrict the "all" finder set to these ids
//!   --only NAME[,NAME]  run only the named cases
//!   --corpus PATH       add a file as a corpus (repeatable)
//!   --min-time SECS     minimum time per measurement (default 0.5)
//!   --save PATH         write results as key=value lines
//!   --compare PATH      show deltas against a saved run
//!   --write-corpus DIR  write the synthetic corpora to DIR and exit
//! ```

use squeeze::scanner::Strategy;
use squeeze::{
    Finder, cidr::Cidr, codetag::Codetag, color::Color, datetime::Datetime, domain::Domain,
    email::Email, emoji::Emoji, env::Env, handle::Handle, hash::Hash, ip::Ip, json::Json, jwt::Jwt,
    mac::Mac, modeline::Modeline, path::Path, phone::Phone, scanner::ScanStats, scanner::Scanner,
    semver::Semver, uri::URI, uuid::Uuid,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::{Duration, Instant};

/// Ask the scheduler for a performance core: on Apple silicon a default-QoS
/// thread may land on an efficiency core, which halves throughput at random.
#[cfg(target_os = "macos")]
fn pin_to_performance_cores() {
    unsafe extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
    // SAFETY: plain libc call with constant arguments; failure is harmless.
    unsafe {
        pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    }
}

#[cfg(not(target_os = "macos"))]
fn pin_to_performance_cores() {}

const FINDER_IDS: &[&str] = &[
    "cidr", "codetag", "color", "datetime", "domain", "email", "emoji", "env", "handle", "hash",
    "ip", "json", "jwt", "mac", "modeline", "path", "phone", "semver", "uri", "uuid",
];

fn make_finder(id: &str) -> Box<dyn Finder> {
    match id {
        "cidr" => Box::new(Cidr::default()),
        "codetag" => {
            let mut codetag = Codetag::default();
            codetag.build_mnemonics_regex().unwrap();
            Box::new(codetag)
        }
        "color" => Box::new(Color::default()),
        "datetime" => Box::new(Datetime::default()),
        "domain" => Box::new(Domain::default()),
        "email" => Box::new(Email::default()),
        "emoji" => Box::new(Emoji::default()),
        "env" => Box::new(Env::default()),
        "handle" => Box::new(Handle::default()),
        "hash" => {
            let mut hash = Hash::default();
            for algorithm in ["md5", "sha1", "sha256", "sha512"] {
                assert!(hash.add_algorithm(algorithm));
            }
            Box::new(hash)
        }
        "ip" => Box::new(Ip::default()),
        "json" => Box::new(Json::default()),
        "jwt" => Box::new(Jwt::default()),
        "mac" => Box::new(Mac::default()),
        "modeline" => Box::new(Modeline::default()),
        "path" => Box::new(Path::default()),
        "phone" => Box::new(Phone::default()),
        "semver" => Box::new(Semver::default()),
        "uri" => Box::new(URI::default()),
        "uuid" => Box::new(Uuid::default()),
        other => panic!("unknown finder id {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Deterministic corpora
// ---------------------------------------------------------------------------

/// xorshift64* generator: deterministic across platforms and runs.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len() as u64) as usize]
    }

    fn hex(&mut self, len: usize) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        (0..len)
            .map(|_| HEX[self.below(16) as usize] as char)
            .collect()
    }

    fn word(&mut self) -> &'static str {
        self.pick(WORDS)
    }

    fn ipv4(&mut self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.range(1, 223),
            self.below(256),
            self.below(256),
            self.range(1, 254)
        )
    }

    fn uuid(&mut self) -> String {
        format!(
            "{}-{}-4{}-{}{}-{}",
            self.hex(8),
            self.hex(4),
            self.hex(3),
            self.pick(&["8", "9", "a", "b"]),
            self.hex(3),
            self.hex(12)
        )
    }

    fn timestamp(&mut self) -> String {
        format!(
            "2024-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.range(1, 12),
            self.range(1, 28),
            self.below(24),
            self.below(60),
            self.below(60)
        )
    }

    fn semver(&mut self) -> String {
        format!("{}.{}.{}", self.below(10), self.below(30), self.below(60))
    }
}

const WORDS: &[&str] = &[
    "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "server", "request", "client",
    "value", "config", "error", "output", "input", "buffer", "thread", "memory", "network",
    "release", "version", "update", "record", "field", "table", "index", "query", "result",
    "stream", "handle", "socket", "packet", "header", "footer", "layout", "render", "window",
    "module", "import", "export", "public", "private", "static", "return", "branch", "commit",
    "merge", "rebase", "review", "deploy", "monitor", "metric", "signal", "worker", "queue",
    "cache", "token", "session", "cookie", "domain", "policy", "schema", "object", "array",
    "string", "number", "boolean", "option", "result", "vector", "matrix", "tensor", "kernel",
    "driver", "device", "sensor", "camera", "display", "battery", "charger", "adapter",
];

const LEVELS: &[&str] = &["INFO", "WARN", "ERROR", "DEBUG"];
const PATHS: &[&str] = &[
    "/var/log/syslog",
    "./src/main.rs:42:10",
    "~/projects/app/config.yaml",
    "/etc/nginx/nginx.conf",
    "../lib/util.js",
];
const HOSTS: &[&str] = &[
    "api.example.com",
    "cdn.example.net",
    "www.wikipedia.org",
    "localhost:8080",
    "internal.corp.example.co.uk",
];

fn gen_logs(rng: &mut Rng, target: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut size = 0;
    while size < target {
        let ts = rng.timestamp();
        let level = rng.pick(LEVELS);
        let line = match rng.below(8) {
            0 => format!(
                "{ts} {level} request from {} GET https://{}/v1/users/{}?page=2 200 {}ms",
                rng.ipv4(),
                rng.pick(HOSTS),
                rng.below(9999),
                rng.below(999)
            ),
            1 => format!(
                "{ts} {level} req_id={} user={}{}@example.com status=ok",
                rng.uuid(),
                rng.word(),
                rng.below(99)
            ),
            2 => format!(
                "{ts} {level} payload={{\"id\": {}, \"ok\": true, \"tags\": [\"a\", \"b\"]}}",
                rng.below(999)
            ),
            3 => format!(
                "{ts} {level} loaded {} version v{} $HOME=/home/user",
                rng.pick(PATHS),
                rng.semver()
            ),
            4 => format!(
                "{ts} {level} sha256={} mac=00:1A:2B:{:02X}:4D:5E",
                rng.hex(64),
                rng.below(256)
            ),
            5 => format!(
                "{ts} {level} TODO: review subnet {}/24 and 2001:db8::{:x} color #ff{:02x}aa",
                rng.ipv4(),
                rng.range(1, 65535),
                rng.below(256)
            ),
            6 => format!(
                "{ts} {level} worker {} processed {} items in {}.{:02}s",
                rng.range(1, 64),
                rng.below(100_000),
                rng.below(100),
                rng.below(100)
            ),
            _ => format!(
                "{ts} {level} call +1-415-555-{} about ticket #{} @{}",
                rng.range(1000, 9999),
                rng.below(9999),
                rng.word()
            ),
        };
        size += line.len() + 1;
        lines.push(line);
    }
    lines
}

fn gen_prose(rng: &mut Rng, target: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut size = 0;
    while size < target {
        let mut line = String::new();
        let sentences = rng.range(1, 3);
        for _ in 0..sentences {
            let words = rng.range(6, 16);
            for w in 0..words {
                let word = rng.word();
                if w == 0 {
                    let mut chars = word.chars();
                    if let Some(first) = chars.next() {
                        line.extend(first.to_uppercase());
                        line.push_str(chars.as_str());
                    }
                } else {
                    line.push_str(word);
                }
                match rng.below(24) {
                    0 => line.push(','),
                    1 => {
                        line.push(' ');
                        line.push_str(&rng.range(1900, 2030).to_string());
                    }
                    2 => line.push_str(" (e.g."),
                    3 => line.push(')'),
                    _ => {}
                }
                line.push(' ');
            }
            line.pop();
            line.push_str(rng.pick(&[".", ".", ".", "!", "?", ";"]));
            line.push(' ');
        }
        line.pop();
        size += line.len() + 1;
        lines.push(line);
    }
    lines
}

fn gen_source(rng: &mut Rng, target: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut size = 0;
    while size < target {
        let indent = " ".repeat(4 * rng.below(4) as usize);
        let body = match rng.below(14) {
            0 => format!(
                "let {} = {}({}, {});",
                rng.word(),
                rng.word(),
                rng.word(),
                rng.below(100)
            ),
            1 => format!(
                "// TODO: {} the {} before {}",
                rng.word(),
                rng.word(),
                rng.word()
            ),
            2 => format!("use std::{}::{};", rng.word(), rng.word()),
            3 => format!(
                "const {}: u32 = 0x{};",
                rng.word().to_uppercase(),
                rng.hex(8)
            ),
            4 => format!("// see https://{}/docs/{}", rng.pick(HOSTS), rng.word()),
            5 => format!("{} = \"{}\"", rng.word(), rng.semver()),
            6 => "#[derive(Debug, Clone, PartialEq)]".to_string(),
            7 => format!(
                "if {} > {} && {}.is_empty() {{",
                rng.word(),
                rng.below(50),
                rng.word()
            ),
            8 => "}".to_string(),
            9 => format!("let path = \"{}\";", rng.pick(PATHS)),
            10 => format!(
                "assert_eq!({}.len(), {}); // FIXME({}): flaky",
                rng.word(),
                rng.below(10),
                rng.word()
            ),
            11 => format!(
                "let json = r#\"{{\"{}\": [{}, {}]}}\"#;",
                rng.word(),
                rng.below(9),
                rng.below(9)
            ),
            12 => format!(
                "fn {}_{}(&self, {}: &str) -> Option<usize> {{",
                rng.word(),
                rng.word(),
                rng.word()
            ),
            _ => format!(
                "{}.push_str(&format!(\"{{}}\", {}));",
                rng.word(),
                rng.word()
            ),
        };
        let line = format!("{indent}{body}");
        size += line.len() + 1;
        lines.push(line);
    }
    lines
}

fn gen_jsonl(rng: &mut Rng, target: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut size = 0;
    while size < target {
        let line = format!(
            "{{\"id\": \"{}\", \"ts\": \"{}\", \"user\": {{\"email\": \"{}@{}\", \"ip\": \"{}\"}}, \"url\": \"https://{}/{}\", \"tags\": [\"{}\", \"{}\"], \"score\": {}.{}}}",
            rng.uuid(),
            rng.timestamp(),
            rng.word(),
            rng.pick(&["example.com", "mail.example.org", "corp.example.net"]),
            rng.ipv4(),
            rng.pick(HOSTS),
            rng.word(),
            rng.word(),
            rng.word(),
            rng.below(100),
            rng.below(100)
        );
        size += line.len() + 1;
        lines.push(line);
    }
    lines
}

fn gen_markdown(rng: &mut Rng, target: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut size = 0;
    while size < target {
        let line = match rng.below(10) {
            0 => format!("## {} {}", rng.word(), rng.word()),
            1 => format!(
                "- [{}]( https://{}/{}/{} ) by @{} on {}",
                rng.word(),
                rng.pick(HOSTS),
                rng.word(),
                rng.word(),
                rng.word(),
                &rng.timestamp()[..10]
            ),
            2 => format!(
                "Run `{} --{}` then open `{}`.",
                rng.word(),
                rng.word(),
                rng.pick(PATHS)
            ),
            3 => format!(
                "| {} | {} | {} |",
                rng.word(),
                rng.semver(),
                rng.pick(&["✅", "❌", "🚀", "🎉"])
            ),
            4 => format!(
                "> {} {} {} {}",
                rng.word(),
                rng.word(),
                rng.word(),
                rng.word()
            ),
            5 => format!(
                "Contact {}@example.com or +1 (415) 555-{}",
                rng.word(),
                rng.range(1000, 9999)
            ),
            6 => format!("![{}](./images/{}.png)", rng.word(), rng.word()),
            _ => {
                let mut line = String::new();
                for _ in 0..rng.range(8, 18) {
                    line.push_str(rng.word());
                    line.push(' ');
                }
                line.pop();
                line
            }
        };
        size += line.len() + 1;
        lines.push(line);
    }
    lines
}

fn gen_hexdense(rng: &mut Rng, target: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut size = 0;
    while size < target {
        let line = match rng.below(6) {
            0 => format!("checksum = \"{}\"", rng.hex(64)),
            1 => format!("version = \"{}\"", rng.semver()),
            2 => "source = \"registry+https://github.com/rust-lang/crates.io-index\"".to_string(),
            3 => format!("{} refs/heads/{}", rng.hex(40), rng.word()),
            4 => format!("{} {} {}", rng.uuid(), rng.hex(32), rng.uuid()),
            _ => format!(
                "00:{}:{}:{}:{}:{} {}",
                rng.hex(2),
                rng.hex(2),
                rng.hex(2),
                rng.hex(2),
                rng.hex(2),
                rng.hex(128)
            ),
        };
        size += line.len() + 1;
        lines.push(line);
    }
    lines
}

fn gen_unicode(rng: &mut Rng, target: usize) -> Vec<String> {
    const CJK: &[&str] = &["日本語", "テキスト", "中文", "한국어", "ありがとう", "世界"];
    const CYR: &[&str] = &["привет", "мир", "сервер", "запрос"];
    const EMOJI: &[&str] = &["🌐", "📧", "🎉", "👨‍👩‍👧‍👦", "1️⃣", "😀"];
    let mut lines = Vec::new();
    let mut size = 0;
    while size < target {
        let mut line = String::new();
        for _ in 0..rng.range(6, 14) {
            match rng.below(9) {
                0..=2 => line.push_str(rng.pick(CJK)),
                3..=4 => line.push_str(rng.pick(CYR)),
                5 => line.push_str(rng.pick(EMOJI)),
                6 => line.push_str(&rng.ipv4()),
                7 => {
                    line.push_str(rng.word());
                    line.push_str("@example.com");
                }
                _ => line.push_str(rng.word()),
            }
            line.push(' ');
        }
        line.pop();
        size += line.len() + 1;
        lines.push(line);
    }
    lines
}

fn gen_nomatch(rng: &mut Rng, target: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut size = 0;
    while size < target {
        let mut line = String::new();
        for _ in 0..rng.range(8, 16) {
            line.push_str(rng.word());
            line.push(' ');
        }
        line.pop();
        size += line.len() + 1;
        lines.push(line);
    }
    lines
}

fn gen_dense(target: usize) -> Vec<String> {
    let line = "$A $B $C $D $E $F $G $H $I $J";
    vec![line.to_string(); target / (line.len() + 1)]
}

fn gen_long_line() -> Vec<String> {
    vec![format!(
        "{} https://example.com {}",
        "x".repeat(32 * 1024),
        "y".repeat(32 * 1024)
    )]
}

struct Corpus {
    name: String,
    lines: Vec<String>,
}

impl Corpus {
    fn bytes(&self) -> usize {
        self.lines.iter().map(|l| l.len() + 1).sum()
    }
}

const CORPUS_TARGET: usize = 1 << 20;

fn synthetic_corpora() -> Vec<Corpus> {
    let mut rng = Rng::new(0x5EED_5EED_5EED_5EED);
    let mut corpora = vec![
        Corpus {
            name: "logs".into(),
            lines: gen_logs(&mut rng, CORPUS_TARGET),
        },
        Corpus {
            name: "prose".into(),
            lines: gen_prose(&mut rng, CORPUS_TARGET),
        },
        Corpus {
            name: "source".into(),
            lines: gen_source(&mut rng, CORPUS_TARGET),
        },
        Corpus {
            name: "jsonl".into(),
            lines: gen_jsonl(&mut rng, CORPUS_TARGET),
        },
        Corpus {
            name: "markdown".into(),
            lines: gen_markdown(&mut rng, CORPUS_TARGET),
        },
        Corpus {
            name: "hexdense".into(),
            lines: gen_hexdense(&mut rng, CORPUS_TARGET),
        },
        Corpus {
            name: "unicode".into(),
            lines: gen_unicode(&mut rng, CORPUS_TARGET),
        },
        Corpus {
            name: "nomatch".into(),
            lines: gen_nomatch(&mut rng, CORPUS_TARGET),
        },
        Corpus {
            name: "dense".into(),
            lines: gen_dense(CORPUS_TARGET / 4),
        },
        Corpus {
            name: "longline".into(),
            lines: gen_long_line(),
        },
    ];
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/uri-hacker-malware-websites.txt");
    if let Ok(text) = std::fs::read_to_string(&fixture) {
        corpora.push(Corpus {
            name: "urls".into(),
            lines: text.lines().map(str::to_string).collect(),
        });
    }
    corpora
}

fn file_corpus(path: &str) -> Corpus {
    let text = std::fs::read(path).unwrap_or_else(|e| panic!("cannot read corpus {path}: {e}"));
    let text = String::from_utf8_lossy(&text);
    let name = std::path::Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    Corpus {
        name,
        lines: text.lines().map(str::to_string).collect(),
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Measurement {
    case: String,
    finders: String,
    bytes: usize,
    lines: usize,
    iterations: u64,
    elapsed: Duration,
    matches: u64,
    stats: Option<ScanStats>,
}

impl Measurement {
    /// Throughput of the best pass.
    fn mib_per_s(&self) -> f64 {
        self.bytes as f64 / self.elapsed.as_secs_f64() / (1024.0 * 1024.0)
    }

    /// Cost per byte of the best pass.
    fn ns_per_byte(&self) -> f64 {
        self.elapsed.as_nanos() as f64 / self.bytes as f64
    }

    fn kv(&self) -> String {
        let mut s = format!(
            "case={} finders={} bytes={} lines={} rounds={} mib_s={:.2} ns_b={:.3} matches={}",
            self.case,
            self.finders,
            self.bytes,
            self.lines,
            self.iterations,
            self.mib_per_s(),
            self.ns_per_byte(),
            self.matches
        );
        if let Some(st) = &self.stats {
            let mut rejected: Vec<(usize, u64)> = st
                .coarse_rejected
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, n)| *n > 0)
                .collect();
            rejected.sort_by(|a, b| b.1.cmp(&a.1));
            let total: u64 = rejected.iter().map(|(_, n)| n).sum();
            if total > 0 {
                let _ = write!(s, " coarse_rejected={total} by byte:");
                for (b, n) in rejected.iter().take(12) {
                    let shown = if (*b as u8).is_ascii_graphic() {
                        format!("{}", *b as u8 as char)
                    } else {
                        format!("\\x{b:02x}")
                    };
                    let _ = write!(s, " {shown}={:.1}%", 100.0 * *n as f64 / total as f64);
                }
            }
            let _ = write!(
                s,
                " calls={} hits={} coarse_pos={} cand_pos={} positions={} finder_lines_skipped={} lines_skipped={} sorts={}",
                st.calls(),
                st.hits(),
                st.coarse_positions,
                st.candidate_positions,
                st.positions,
                st.finder_lines_skipped,
                st.lines_skipped,
                st.sorts
            );
        }
        s
    }
}

/// Times every scanner on `corpus` with interleaved rounds, so that machine
/// load drifting during the run affects all of them alike, and keeps the
/// best round of each: the minimum is the estimate least affected by noise.
fn measure_all(
    case: &str,
    scanners: &[(String, &Scanner)],
    corpus: &Corpus,
    min_duration: Duration,
    with_stats: bool,
) -> Vec<Measurement> {
    let bytes = corpus.bytes();
    let mut scratch = Vec::new();
    let mut results: Vec<Measurement> = scanners
        .iter()
        .map(|(label, scanner)| {
            // Warm-up pass, also collects the operation counters once.
            let stats = if with_stats {
                let mut stats = ScanStats::for_scanner(scanner);
                for line in &corpus.lines {
                    scanner.scan_line_stats(line, &mut scratch, &mut stats);
                }
                Some(stats)
            } else {
                for line in &corpus.lines {
                    scanner.scan_line_into(line, &mut scratch);
                }
                None
            };
            Measurement {
                case: case.to_string(),
                finders: label.clone(),
                bytes,
                lines: corpus.lines.len(),
                iterations: 0,
                elapsed: Duration::MAX,
                matches: 0,
                stats,
            }
        })
        .collect();

    let started = Instant::now();
    let mut rounds = 0;
    while rounds < 3 || started.elapsed() < min_duration {
        for (m, (_, scanner)) in results.iter_mut().zip(scanners) {
            let mut matches = 0u64;
            let start = Instant::now();
            for line in &corpus.lines {
                scanner.scan_line_into(black_box(line), &mut scratch);
                matches += scratch.len() as u64;
            }
            let elapsed = start.elapsed();
            if elapsed < m.elapsed {
                m.elapsed = elapsed;
            }
            m.iterations += 1;
            m.matches = matches;
        }
        rounds += 1;
    }
    results
}

fn print_header(with_stats: bool) {
    print!(
        "{:<10} {:<9} {:>7} {:>8} {:>7} {:>9}",
        "case", "finders", "KiB", "MiB/s", "ns/B", "matches"
    );
    if with_stats {
        print!(
            " {:>9} {:>6} {:>7} {:>6} {:>6} {:>5}",
            "calls/KB", "hit%", "coarse%", "cand%", "skip%", "sort%"
        );
    }
    println!();
}

fn print_row(m: &Measurement, with_stats: bool) {
    print!(
        "{:<10} {:<9} {:>7} {:>8.1} {:>7.2} {:>9}",
        m.case,
        m.finders,
        m.bytes / 1024,
        m.mib_per_s(),
        m.ns_per_byte(),
        m.matches
    );
    if with_stats && let Some(st) = &m.stats {
        let kib = (st.bytes.max(1)) as f64 / 1024.0;
        let calls = st.calls();
        let hit = if calls == 0 {
            0.0
        } else {
            100.0 * st.hits() as f64 / calls as f64
        };
        let cand = if st.positions == 0 {
            0.0
        } else {
            100.0 * st.candidate_positions as f64 / st.positions as f64
        };
        let coarse = if st.positions == 0 {
            0.0
        } else {
            100.0 * st.coarse_positions as f64 / st.positions as f64
        };
        let finder_lines = st.lines * st.finders.len() as u64;
        let skip = if finder_lines == 0 {
            0.0
        } else {
            100.0 * st.finder_lines_skipped as f64 / finder_lines as f64
        };
        let sort = if st.lines == 0 {
            0.0
        } else {
            100.0 * st.sorts as f64 / st.lines as f64
        };
        print!(
            " {:>9.1} {:>6.1} {:>7.1} {:>6.1} {:>6.1} {:>5.1}",
            calls as f64 / kib,
            hit,
            coarse,
            cand,
            skip,
            sort
        );
    }
    println!();
}

fn print_finder_breakdown(m: &Measurement, scanner: &Scanner) {
    let Some(st) = &m.stats else { return };
    let kib = (st.bytes.max(1)) as f64 / 1024.0;
    println!(
        "  {:<9} {:>9} {:>9} {:>6} {:>9} {:>6}",
        "finder", "calls/KB", "hits", "hit%", "matches", "run%"
    );
    for (i, f) in st.finders.iter().enumerate() {
        let calls = f.calls();
        if calls == 0 && f.matches == 0 {
            continue;
        }
        let hit = if calls == 0 {
            0.0
        } else {
            100.0 * f.hits as f64 / calls as f64
        };
        let run = if st.lines == 0 {
            0.0
        } else {
            100.0 * f.lines_run as f64 / st.lines as f64
        };
        println!(
            "  {:<9} {:>9.1} {:>9} {:>6.1} {:>9} {:>6.1}",
            scanner.finders()[i].id(),
            calls as f64 / kib,
            f.hits,
            hit,
            f.matches,
            run
        );
    }
    // Where the vector stage is imprecise: coarse positions the exact
    // gates rejected, by the byte at the position.
    let mut rejected: Vec<(usize, u64)> = st
        .coarse_rejected
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, n)| *n > 0)
        .collect();
    rejected.sort_by(|a, b| b.1.cmp(&a.1));
    let total: u64 = rejected.iter().map(|(_, n)| n).sum();
    if total > 0 {
        let mut line = format!("  coarse rejected: {:.1}/KB, by byte:", total as f64 / kib);
        for (b, n) in rejected.iter().take(14) {
            let shown = if (*b as u8).is_ascii_graphic() {
                format!("{}", *b as u8 as char)
            } else {
                format!("\\x{b:02x}")
            };
            line.push_str(&format!(" {shown} {:.1}", *n as f64 / kib));
        }
        println!("{line}");
    }
}

fn load_saved(path: &str) -> BTreeMap<(String, String), BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read saved results {path}: {e}"));
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let mut fields = BTreeMap::new();
        for kv in line.split_whitespace() {
            if let Some((k, v)) = kv.split_once('=') {
                fields.insert(k.to_string(), v.to_string());
            }
        }
        if let (Some(case), Some(finders)) = (fields.get("case"), fields.get("finders")) {
            map.insert((case.clone(), finders.clone()), fields);
        }
    }
    map
}

struct Options {
    stats: bool,
    per_finder: bool,
    strategies: Vec<Strategy>,
    finders: Vec<String>,
    only: Vec<String>,
    corpora: Vec<String>,
    min_time: Duration,
    save: Option<String>,
    compare: Option<String>,
    write_corpus: Option<String>,
}

fn parse_args() -> Options {
    let mut opts = Options {
        stats: false,
        per_finder: false,
        strategies: vec![Strategy::Vector],
        finders: FINDER_IDS.iter().map(|s| s.to_string()).collect(),
        only: Vec::new(),
        corpora: Vec::new(),
        min_time: Duration::from_millis(500),
        save: None,
        compare: None,
        write_corpus: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .unwrap_or_else(|| panic!("{name} requires a value"))
        };
        match arg.as_str() {
            "--stats" => opts.stats = true,
            "--per-finder" => opts.per_finder = true,
            "--strategy" => {
                let value = value("--strategy");
                opts.strategies = if value == "all" {
                    Strategy::ALL.to_vec()
                } else {
                    value
                        .split(',')
                        .map(|name| {
                            Strategy::parse(name.trim())
                                .unwrap_or_else(|| panic!("unknown strategy {name:?}"))
                        })
                        .collect()
                };
            }
            "--finders" => {
                opts.finders = value("--finders")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--only" => {
                opts.only = value("--only")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--corpus" => opts.corpora.push(value("--corpus")),
            "--min-time" => {
                opts.min_time = Duration::from_secs_f64(
                    value("--min-time")
                        .parse()
                        .expect("--min-time expects seconds"),
                );
            }
            "--save" => opts.save = Some(value("--save")),
            "--compare" => opts.compare = Some(value("--compare")),
            "--write-corpus" => opts.write_corpus = Some(value("--write-corpus")),
            // Cargo's bench harness flags, accepted and ignored.
            "--bench" | "--nocapture" | "--quiet" | "-q" => {}
            other => panic!("unknown argument {other:?}"),
        }
    }
    opts
}

fn main() {
    let opts = parse_args();

    let mut corpora = synthetic_corpora();
    for path in &opts.corpora {
        corpora.push(file_corpus(path));
    }
    if !opts.only.is_empty() {
        corpora.retain(|c| opts.only.iter().any(|o| o == &c.name));
    }

    if let Some(dir) = &opts.write_corpus {
        std::fs::create_dir_all(dir).expect("cannot create corpus directory");
        for corpus in &corpora {
            let path = std::path::Path::new(dir).join(format!("{}.txt", corpus.name));
            let mut text = corpus.lines.join("\n");
            text.push('\n');
            std::fs::write(&path, text).expect("cannot write corpus");
            println!("wrote {} ({} KiB)", path.display(), corpus.bytes() / 1024);
        }
        return;
    }

    let build_all = |strategy: Strategy| {
        let mut scanner = Scanner::new(opts.finders.iter().map(|id| make_finder(id)).collect());
        scanner.set_strategy(strategy);
        scanner
    };
    let finder_label = if opts.finders.len() == FINDER_IDS.len() {
        "all".to_string()
    } else {
        format!("{}", opts.finders.len())
    };
    // With a single strategy the label is just the finder set, so saved
    // results stay comparable across strategy changes.
    let label = |base: &str, strategy: Strategy| {
        if opts.strategies.len() == 1 {
            base.to_string()
        } else {
            format!("{base}/{}", strategy.name())
        }
    };
    let all_scanners: Vec<(String, Scanner)> = opts
        .strategies
        .iter()
        .map(|&st| (label(&finder_label, st), build_all(st)))
        .collect();
    let all_refs: Vec<(String, &Scanner)> =
        all_scanners.iter().map(|(l, s)| (l.clone(), s)).collect();

    pin_to_performance_cores();

    let mut results = Vec::new();
    print_header(opts.stats);
    for corpus in &corpora {
        let ms = measure_all(&corpus.name, &all_refs, corpus, opts.min_time, opts.stats);
        for m in ms {
            print_row(&m, opts.stats);
            if opts.stats {
                print_finder_breakdown(&m, &all_scanners[0].1);
            }
            results.push(m);
        }
    }

    if opts.per_finder {
        println!();
        println!("per finder (each finder alone; `sum` adds them up, `all` is the combined scan):");
        print_header(opts.stats);
        for corpus in &corpora {
            let mut sum_ns = 0.0;
            for id in &opts.finders {
                let scanners: Vec<(String, Scanner)> = opts
                    .strategies
                    .iter()
                    .map(|&st| {
                        let mut scanner = Scanner::new(vec![make_finder(id)]);
                        scanner.set_strategy(st);
                        (label(id, st), scanner)
                    })
                    .collect();
                let refs: Vec<(String, &Scanner)> =
                    scanners.iter().map(|(l, s)| (l.clone(), s)).collect();
                let ms = measure_all(&corpus.name, &refs, corpus, opts.min_time / 2, opts.stats);
                for m in ms {
                    if m.finders == label(id, opts.strategies[0]) {
                        sum_ns += m.ns_per_byte();
                    }
                    print_row(&m, opts.stats);
                    results.push(m);
                }
            }
            let all_label = label(&finder_label, opts.strategies[0]);
            let all = results
                .iter()
                .find(|m| m.case == corpus.name && m.finders == all_label)
                .map(|m| m.ns_per_byte())
                .unwrap_or(0.0);
            println!(
                "{:<10} {:<9} {:>7} {:>8} {:>7.2}   (all: {:.2} ns/B, {:.0}% of sum)",
                corpus.name,
                "sum",
                "",
                "",
                sum_ns,
                all,
                if sum_ns > 0.0 {
                    100.0 * all / sum_ns
                } else {
                    0.0
                }
            );
            println!();
        }
    }

    if let Some(path) = &opts.compare {
        let saved = load_saved(path);
        println!();
        println!("compared to {path}:");
        println!(
            "{:<10} {:<9} {:>8} {:>8} {:>7}   {:>9} {:>9} {:>7}",
            "case", "finders", "old MiB/s", "new", "delta", "old c/KB", "new", "delta"
        );
        for m in &results {
            let Some(old) = saved.get(&(m.case.clone(), m.finders.clone())) else {
                continue;
            };
            let old_mib: f64 = old.get("mib_s").and_then(|v| v.parse().ok()).unwrap_or(0.0);
            let new_mib = m.mib_per_s();
            let kib = m.bytes.max(1) as f64 / 1024.0;
            let old_calls: f64 = old
                .get("calls")
                .and_then(|v| v.parse::<f64>().ok())
                .map(|c| c / kib)
                .unwrap_or(f64::NAN);
            let new_calls = m
                .stats
                .as_ref()
                .map(|s| s.calls() as f64 / kib)
                .unwrap_or(f64::NAN);
            let pct = |old: f64, new: f64| {
                if old > 0.0 && new.is_finite() {
                    format!("{:+.0}%", 100.0 * (new - old) / old)
                } else {
                    "-".to_string()
                }
            };
            println!(
                "{:<10} {:<9} {:>8.1} {:>8.1} {:>7}   {:>9.1} {:>9.1} {:>7}",
                m.case,
                m.finders,
                old_mib,
                new_mib,
                pct(old_mib, new_mib),
                old_calls,
                new_calls,
                pct(old_calls, new_calls)
            );
        }
    }

    if let Some(path) = &opts.save {
        let text: String = results.iter().map(|m| m.kv() + "\n").collect();
        std::fs::write(path, text).expect("cannot write results");
        println!();
        println!("saved {} results to {path}", results.len());
    }
}
