use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn squeeze() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("squeeze").unwrap()
}

fn squeeze_raw() -> StdCommand {
    StdCommand::new(env!("CARGO_BIN_EXE_squeeze"))
}

fn temp_path(name: &str) -> PathBuf {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("squeeze-cli-hardening-{}-{}", id, name))
}

// ============================================================================
// Invalid UTF-8 resilience (grep behavior: bad bytes never abort the scan)
// ============================================================================

const MIXED_UTF8_INPUT: &[u8] =
    b"valid https://x.example.com\n\xff\xfe garbage\nafter https://y.example.com\n";

#[test]
fn invalid_utf8_mid_stream_should_scan_lines_before_and_after() {
    squeeze()
        .arg("--url")
        .write_stdin(MIXED_UTF8_INPUT)
        .assert()
        .success()
        .stdout(predicate::eq(
            "https://x.example.com\nhttps://y.example.com\n",
        ));
}

#[test]
fn invalid_utf8_mid_stream_should_keep_results_with_sort() {
    squeeze()
        .arg("--url")
        .arg("--sort")
        .write_stdin(MIXED_UTF8_INPUT)
        .assert()
        .success()
        .stdout(predicate::eq(
            "https://x.example.com\nhttps://y.example.com\n",
        ));
}

#[test]
fn invalid_utf8_mid_stream_should_keep_results_with_uniq() {
    squeeze()
        .arg("--url")
        .arg("--uniq")
        .write_stdin(&b"a https://a.example.com\n\xff\xfe\nb https://a.example.com\n"[..])
        .assert()
        .success()
        .stdout(predicate::eq("https://a.example.com\n"));
}

#[test]
fn invalid_utf8_mid_stream_should_keep_results_with_output_json() {
    squeeze()
        .arg("--url")
        .arg("--output")
        .arg("json")
        .write_stdin(MIXED_UTF8_INPUT)
        .assert()
        .success()
        .stdout(predicate::eq(
            "[\"https://x.example.com\",\"https://y.example.com\"]\n",
        ));
}

#[test]
fn line_with_invalid_utf8_should_still_have_its_valid_parts_scanned() {
    // The replacement characters are non-ASCII and match nothing, but the rest
    // of the line must still be scanned.
    squeeze()
        .arg("--url")
        .write_stdin(&b"\xff\xfe see https://mid.example.com ok\n"[..])
        .assert()
        .success()
        .stdout(predicate::eq("https://mid.example.com\n"));
}

#[test]
fn invalid_utf8_only_input_should_succeed_silently() {
    squeeze()
        .arg("--url")
        .write_stdin(&b"\xff\xfe\xfd\n"[..])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());
}

#[test]
fn invalid_utf8_in_file_input_should_scan_all_lines() {
    let path = temp_path("invalid-utf8.txt");
    fs::write(&path, MIXED_UTF8_INPUT).unwrap();

    squeeze()
        .arg("--url")
        .arg(path.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::eq(
            "https://x.example.com\nhttps://y.example.com\n",
        ));

    let _ = fs::remove_file(path);
}

#[test]
fn invalid_utf8_with_parallel_jobs_should_scan_all_lines() {
    squeeze()
        .arg("--url")
        .arg("--jobs")
        .arg("4")
        .arg("--sort")
        .write_stdin(MIXED_UTF8_INPUT)
        .assert()
        .success()
        .stdout(predicate::eq(
            "https://x.example.com\nhttps://y.example.com\n",
        ));
}

// ============================================================================
// Line-ending handling pins (the byte-level line reader must preserve these)
// ============================================================================

#[test]
fn crlf_line_endings_should_still_be_stripped() {
    squeeze()
        .arg("--url")
        .write_stdin("x https://a.example.com\r\n")
        .assert()
        .success()
        .stdout(predicate::eq("https://a.example.com\n"));
}

#[test]
fn missing_trailing_newline_should_still_be_scanned() {
    squeeze()
        .arg("--url")
        .write_stdin("x https://a.example.com")
        .assert()
        .success()
        .stdout(predicate::eq("https://a.example.com\n"));
}

#[test]
fn nul_bytes_should_not_break_scanning() {
    squeeze()
        .arg("--url")
        .write_stdin(&b"\x00 https://a.example.com\n"[..])
        .assert()
        .success()
        .stdout(predicate::str::contains("https://a.example.com"));
}

// ============================================================================
// -1/--first with --jobs must not hang on a slow stream
// ============================================================================

#[test]
fn first_with_jobs_should_exit_immediately_on_slow_stdin() {
    // -1 must force the sequential path: the parallel path blocks filling a
    // whole batch of lines before scanning any of them, so it would sit on a
    // match it already read while the stream stays open.
    let mut child = squeeze_raw()
        .args(["-1", "--url", "--jobs", "2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn squeeze");

    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(b"x https://a.example.com\n").unwrap();
    stdin.flush().unwrap();

    // Generous guard: the fixed binary exits in milliseconds, the buggy one
    // blocks until stdin closes (which this test never does before exit).
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("squeeze -1 --jobs 2 did not exit while stdin stayed open");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Only close stdin after exit, proving the process did not need EOF.
    drop(stdin);

    assert!(status.success(), "expected success, got {:?}", status);
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert_eq!(stdout, "https://a.example.com\n");
}

// ============================================================================
// Broken pipe is a normal end of pipeline (grep behavior): silent success
// ============================================================================

fn assert_broken_pipe_is_silent_success(extra_args: &[&str], lines: usize) {
    let mut child = squeeze_raw()
        .arg("--url")
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn squeeze");

    // Close the read end of stdout immediately: every later stdout write in
    // the child fails with EPIPE, like `squeeze ... | head -1` after head
    // exits.
    drop(child.stdout.take());

    let mut stdin = child.stdin.take().expect("stdin is piped");
    for _ in 0..lines {
        // The child may exit as soon as it hits the broken pipe; from then on
        // our own writes fail too, which is expected.
        if stdin
            .write_all(b"see https://example.com/aaaaaaaaaaaaaaaa\n")
            .is_err()
        {
            break;
        }
    }
    drop(stdin);

    let output = child
        .wait_with_output()
        .expect("failed to wait for squeeze");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "broken pipe must exit 0, got {:?} with stderr: {}",
        output.status,
        stderr
    );
    assert!(
        output.stderr.is_empty(),
        "broken pipe must be silent, got stderr: {}",
        stderr
    );
}

#[test]
fn broken_pipe_during_streaming_should_be_silent_success() {
    // Enough output to overflow the 8KiB writer mid-scan.
    assert_broken_pipe_is_silent_success(&[], 5000);
}

#[test]
fn broken_pipe_at_final_flush_should_be_silent_success() {
    // A single match only hits the pipe on the final flush.
    assert_broken_pipe_is_silent_success(&[], 1);
}

#[test]
fn broken_pipe_with_sort_should_be_silent_success() {
    // Buffered shaping writes everything from finalize_results instead.
    assert_broken_pipe_is_silent_success(&["--sort"], 5000);
}

// ============================================================================
// Unknown --hash algorithms are usage errors (clap-style, exit code 2)
// ============================================================================

#[test]
fn hash_unknown_algorithm_should_fail_with_usage_error() {
    squeeze()
        .arg("--hash=blake2")
        .write_stdin("5d41402abc4b2a76b9719d911017c592\n")
        .assert()
        .failure()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "invalid value 'blake2' for '--hash'",
        ))
        .stderr(predicate::str::contains("md5, sha1, sha256, sha512"));
}

#[test]
fn hash_unknown_algorithm_in_comma_list_should_fail_with_usage_error() {
    squeeze()
        .arg("--hash=md5,bogus")
        .write_stdin("5d41402abc4b2a76b9719d911017c592\n")
        .assert()
        .failure()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "invalid value 'bogus' for '--hash'",
        ));
}

#[test]
fn hash_hyphenated_algorithm_names_should_be_accepted() {
    squeeze()
        .arg("--hash=sha-256")
        .write_stdin(
            "5d41402abc4b2a76b9719d911017c592 and \
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
        )
        .assert()
        .success()
        .stdout(predicate::eq(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
        ));
}

// ============================================================================
// Bare flag + alias flags must union (never narrow)
// ============================================================================

#[test]
fn uri_bare_flag_with_http_alias_should_not_narrow() {
    squeeze()
        .arg("--uri")
        .arg("--http")
        .write_stdin("ftp://files.example.com/a and http://web.example.com\n")
        .assert()
        .success()
        .stdout(predicate::eq(
            "ftp://files.example.com/a\nhttp://web.example.com\n",
        ));
}

#[test]
fn hash_bare_flag_with_md5_alias_should_not_narrow() {
    squeeze()
        .arg("--hash")
        .arg("--md5")
        .write_stdin(
            "5d41402abc4b2a76b9719d911017c592 and \
             2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        )
        .assert()
        .success()
        .stdout(predicate::eq(
            "5d41402abc4b2a76b9719d911017c592\n2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        ));
}

#[test]
fn hash_alias_flags_alone_should_still_restrict() {
    squeeze()
        .arg("--md5")
        .arg("--sha256")
        .write_stdin(
            "5d41402abc4b2a76b9719d911017c592 then \
             2aae6c35c94fcfb415dbe95f408b9ce91ee846ed then \
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("5d41402abc4b2a76b9719d911017c592"))
        .stdout(predicate::str::contains(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ))
        .stdout(predicate::str::contains("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed").not());
}

#[test]
fn uri_scheme_value_with_alias_should_union_restrictions() {
    squeeze()
        .arg("--uri=https")
        .arg("--http")
        .write_stdin(
            "ftp://files.example.com/a http://web.example.com https://secure.example.com\n",
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("http://web.example.com"))
        .stdout(predicate::str::contains("https://secure.example.com"))
        .stdout(predicate::str::contains("ftp://files.example.com").not());
}

// ============================================================================
// Empty values behave like the bare flag (unrestricted)
// ============================================================================

#[test]
fn uri_empty_value_should_behave_like_bare_flag() {
    squeeze()
        .arg("--uri=")
        .write_stdin("ftp://files.example.com/a and http://web.example.com\n")
        .assert()
        .success()
        .stdout(predicate::eq(
            "ftp://files.example.com/a\nhttp://web.example.com\n",
        ));
}

#[test]
fn hash_empty_value_should_behave_like_bare_flag() {
    squeeze()
        .arg("--hash=")
        .write_stdin(
            "5d41402abc4b2a76b9719d911017c592 and \
             2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        )
        .assert()
        .success()
        .stdout(predicate::eq(
            "5d41402abc4b2a76b9719d911017c592\n2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        ));
}

#[test]
fn hash_empty_value_with_alias_should_stay_unrestricted() {
    squeeze()
        .arg("--hash=")
        .arg("--md5")
        .write_stdin(
            "5d41402abc4b2a76b9719d911017c592 and \
             2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        )
        .assert()
        .success()
        .stdout(predicate::eq(
            "5d41402abc4b2a76b9719d911017c592\n2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        ));
}

// ============================================================================
// Codetag mnemonic list hygiene
// ============================================================================

#[test]
fn codetag_trailing_comma_should_not_match_every_colon_line() {
    squeeze()
        .arg("--codetag=todo,")
        .write_stdin("word: something\nTODO: real\n")
        .assert()
        .success()
        .stdout(predicate::eq("TODO: real\n"));
}

#[test]
fn codetag_empty_value_should_behave_like_bare_flag() {
    squeeze()
        .arg("--codetag=")
        .write_stdin("// TODO: x\n// FIXME: y\nword: z\n")
        .assert()
        .success()
        .stdout(predicate::eq("TODO: x\nFIXME: y\n"));
}

#[test]
fn codetag_comma_only_value_should_behave_like_bare_flag() {
    squeeze()
        .arg("--codetag=,,")
        .write_stdin("word: x\nTODO: z\n")
        .assert()
        .success()
        .stdout(predicate::eq("TODO: z\n"));
}

// ============================================================================
// Cosmetics: help text and flag validation ordering
// ============================================================================

#[test]
fn hide_mnemonic_help_should_describe_hiding() {
    squeeze()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("hide the mnemonics"))
        .stdout(predicate::str::contains("whether to show the mnemonics").not());
}

#[test]
fn jobs_zero_without_finder_flags_should_fail() {
    squeeze()
        .arg("--jobs")
        .arg("0")
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--jobs must be >= 1"));
}
