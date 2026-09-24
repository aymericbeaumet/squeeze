//! The CLI reads input in large blocks and, with `--jobs`, scans whole
//! chunks on worker threads. These tests pin the behaviours that depend on
//! where block and chunk boundaries fall: exact output, ordering, line
//! numbers and columns, and invalid UTF-8 deep inside a block.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn squeeze() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("squeeze").unwrap()
}

fn temp_path(name: &str) -> PathBuf {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("squeeze-cli-io-{}-{}", id, name))
}

/// Deterministic filler so line lengths vary and boundaries fall inside
/// lines rather than on them.
fn filler(i: usize) -> String {
    let len = 20 + (i * 7919) % 173;
    let mut s = String::with_capacity(len);
    let mut x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while s.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push((b'a' + (x % 26) as u8) as char);
        if x.is_multiple_of(7) {
            s.push(' ');
        }
    }
    s
}

/// About 3 MiB of prose with a `$VAR<n>` every 300 lines; returns the input
/// and the (line number, prefix length, value) of every match.
fn big_input() -> (String, Vec<(usize, usize, String)>) {
    let mut input = String::new();
    let mut expected = Vec::new();
    let mut line = 0;
    while input.len() < 3 * 1024 * 1024 {
        line += 1;
        let prefix = filler(line);
        if line % 300 == 0 {
            let value = format!("$VAR{}", line);
            expected.push((line, prefix.len(), value.clone()));
            input.push_str(&prefix);
            input.push_str(&value);
        } else {
            input.push_str(&prefix);
        }
        input.push('\n');
    }
    (input, expected)
}

#[test]
fn big_input_sequential_streams_every_match_in_order() {
    let (input, expected) = big_input();
    let want: String = expected
        .iter()
        .map(|(_, _, value)| format!("{value}\n"))
        .collect();
    squeeze()
        .arg("--env")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::eq(want));
}

#[test]
fn big_input_parallel_output_is_identical_to_sequential() {
    let (input, _) = big_input();
    let sequential = squeeze()
        .args(["--all", "--jobs", "1"])
        .write_stdin(input.clone())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(!sequential.is_empty());
    for jobs in ["2", "4", "7"] {
        let parallel = squeeze()
            .args(["--all", "--jobs", jobs])
            .write_stdin(input.clone())
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        assert!(
            parallel == sequential,
            "--jobs {jobs} output differs from sequential output"
        );
    }
}

#[test]
fn big_input_line_numbers_and_columns_survive_chunk_boundaries() {
    let (input, expected) = big_input();
    let mut want = String::from("[");
    for (i, (line, prefix_len, value)) in expected.iter().enumerate() {
        if i > 0 {
            want.push(',');
        }
        // The prefix is ASCII, so the column is the prefix length plus one.
        write!(
            want,
            "{{\"kind\":\"env\",\"value\":\"{value}\",\"line\":{line},\"column\":{},\"start\":{prefix_len},\"end\":{},\"source\":null}}",
            prefix_len + 1,
            prefix_len + value.len()
        )
        .unwrap();
    }
    want.push_str("]\n");
    for jobs in ["1", "3"] {
        squeeze()
            .args(["--env", "--with-kind", "--output", "json", "--jobs", jobs])
            .write_stdin(input.clone())
            .assert()
            .success()
            .stdout(predicate::eq(want.clone()));
    }
}

#[test]
fn big_file_with_source_keeps_line_numbers_per_file() {
    let (input, expected) = big_input();
    let path = temp_path("big.txt");
    fs::write(&path, &input).unwrap();
    let source = path.to_str().unwrap().to_string();
    let last = expected.last().unwrap();
    let json_last = format!("\"value\":\"{}\",\"line\":{},", last.2, last.0);
    for jobs in ["1", "4"] {
        let json_last = json_last.clone();
        squeeze()
            .args(["--env", "--with-kind", "--output", "json", "--jobs", jobs])
            .arg(&source)
            .arg(&source)
            .assert()
            .success()
            // Both files start numbering at 1 again.
            .stdout(predicate::function(move |out: &str| {
                out.matches(&json_last).count() == 2 && out.matches("\"line\":300,").count() == 2
            }));
    }
    let _ = fs::remove_file(path);
}

#[test]
fn invalid_utf8_deep_inside_a_block_only_spoils_its_own_line() {
    // Over 400 KiB of valid text, then a line with invalid bytes in the
    // middle followed by a URL, then more valid lines with URLs.
    let mut input = Vec::new();
    for i in 0..6000 {
        input.extend_from_slice(filler(i).as_bytes());
        input.push(b'\n');
    }
    input.extend_from_slice(b"bad \xff\xfe bytes then https://mid.example.com here\n");
    for i in 0..3000 {
        input.extend_from_slice(filler(i).as_bytes());
        if i % 1000 == 999 {
            input.extend_from_slice(b" https://after.example.com");
        }
        input.push(b'\n');
    }
    input.extend_from_slice(b"tail https://end.example.com");
    let want = "https://mid.example.com\nhttps://after.example.com\nhttps://after.example.com\nhttps://after.example.com\nhttps://end.example.com\n";
    for jobs in ["1", "4"] {
        squeeze()
            .args(["--url", "--jobs", jobs])
            .write_stdin(input.clone())
            .assert()
            .success()
            .stdout(predicate::eq(want));
    }
}

#[test]
fn a_line_longer_than_a_chunk_is_scanned_whole() {
    // 1.5 MiB on a single line: longer than the read block and the chunk.
    let mut input = "x".repeat(1_500_000);
    input.push_str(" $TAIL\nnext $NEXT\n");
    for jobs in ["1", "2"] {
        squeeze()
            .args(["--env", "--jobs", jobs])
            .write_stdin(input.clone())
            .assert()
            .success()
            .stdout(predicate::eq("$TAIL\n$NEXT\n"));
    }
}

#[test]
fn last_and_sort_work_across_chunks() {
    let (input, expected) = big_input();
    let last = format!("{}\n", expected.last().unwrap().2);
    squeeze()
        .args(["--env", "--jobs", "4", "--last"])
        .write_stdin(input.clone())
        .assert()
        .success()
        .stdout(predicate::eq(last));
    let mut values: Vec<&str> = expected.iter().map(|(_, _, v)| v.as_str()).collect();
    values.sort();
    let sorted: String = values.iter().map(|v| format!("{v}\n")).collect();
    squeeze()
        .args(["--env", "--jobs", "4", "--sort"])
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::eq(sorted));
}

/// Sparse finders let the CLI skip whole lines with `memchr`; line numbers
/// and results must be exactly what a line-by-line scan produces, with
/// matches in the first, last (unterminated) and CRLF lines.
#[test]
fn sparse_finders_skip_lines_but_keep_numbering() {
    let mut input = String::new();
    let mut expected = Vec::new();
    for line in 1..=20_000usize {
        if line == 1 || line % 997 == 0 {
            input.push_str(&format!("user{line}@example.com in line {line}\r\n"));
            expected.push((line, format!("user{line}@example.com")));
        } else if line % 5 == 0 {
            input.push_str("@ alone and http://x.y here\n");
        } else {
            input.push_str("plain text without the trigger byte at all\n");
        }
    }
    input.push_str("last@example.org");
    expected.push((20_001, "last@example.org".to_string()));

    for jobs in ["1", "3"] {
        let output = squeeze()
            .args(["--email", "--output", "json", "--with-kind", "--jobs", jobs])
            .write_stdin(input.clone())
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        // One object per match: {"kind":..,"value":"..","line":N,...}
        let got: Vec<(usize, String)> = stdout
            .split("{\"kind\":")
            .skip(1)
            .map(|obj| {
                let value = obj
                    .split("\"value\":\"")
                    .nth(1)
                    .unwrap()
                    .split('"')
                    .next()
                    .unwrap()
                    .to_string();
                let line: usize = obj
                    .split("\"line\":")
                    .nth(1)
                    .unwrap()
                    .split(',')
                    .next()
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                (line, value)
            })
            .collect();
        assert_eq!(got, expected, "jobs={jobs}");
    }
}

/// Files are scanned from memory (mapped when large): the output must be
/// byte-identical to the streaming path for every thread count, with CRLF
/// lines, invalid UTF-8, a long line and an unterminated last line.
#[test]
fn mapped_files_match_the_streaming_path() {
    let mut input: Vec<u8> = Vec::new();
    for line in 1..=60_000usize {
        match line % 7 {
            0 => input.extend_from_slice(
                format!("user{line}@example.com and https://h{line}.example.org/p\r\n").as_bytes(),
            ),
            1 => {
                input.extend_from_slice(b"bad \xff\xfe bytes then ok@example.net\n");
            }
            2 => {
                input.extend_from_slice(format!("{}\n", "x".repeat(3000)).as_bytes());
            }
            _ => input.extend_from_slice(b"plain text line without anything interesting\n"),
        }
    }
    input.extend_from_slice(b"tail@example.io");
    assert!(
        input.len() > 8 * 1024 * 1024,
        "input must exceed the auto-parallel threshold"
    );
    let path = temp_path("mapped-input.txt");
    fs::write(&path, &input).unwrap();

    let stream = squeeze()
        .args([
            "--email",
            "--url",
            "--output",
            "json",
            "--with-kind",
            "--jobs",
            "1",
        ])
        .write_stdin(input.clone())
        .output()
        .unwrap();
    assert!(stream.status.success());
    assert!(stream.stdout.len() > 1000);
    // Sources differ between stdin and a file, so compare without them.
    let strip = |out: &[u8]| {
        String::from_utf8_lossy(out).replace(
            &format!("\"source\":\"{}\"", path.display()),
            "\"source\":null",
        )
    };
    let expected = strip(&stream.stdout);

    for jobs in ["1", "3", "auto"] {
        let output = squeeze()
            .args([
                "--email",
                "--url",
                "--output",
                "json",
                "--with-kind",
                "--jobs",
                jobs,
            ])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "jobs={jobs}");
        assert_eq!(strip(&output.stdout), expected, "jobs={jobs}");
    }
    // Plain text output through the mapped path, sequential and default.
    let text_stream = squeeze()
        .args(["--email", "--jobs", "1"])
        .write_stdin(input.clone())
        .output()
        .unwrap();
    for jobs in ["1", "auto"] {
        let output = squeeze()
            .args(["--email", "--jobs", jobs])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, text_stream.stdout, "jobs={jobs}");
    }
    fs::remove_file(&path).ok();
}

/// A small file is read whole; `--first` on a file stays sequential and
/// prints the first match only.
#[test]
fn small_files_and_first_match_use_the_buffer_path() {
    let path = temp_path("small-input.txt");
    fs::write(&path, "one a@b.co\ntwo c@d.org\n").unwrap();
    squeeze()
        .args(["--email"])
        .arg(&path)
        .assert()
        .success()
        .stdout("a@b.co\nc@d.org\n");
    squeeze()
        .args(["--email", "-1"])
        .arg(&path)
        .assert()
        .success()
        .stdout("a@b.co\n");
    fs::remove_file(&path).ok();
}
