use assert_cmd::Command;
use predicates::prelude::*;

fn squeeze() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("squeeze").unwrap()
}

// ============================================================================
// Help and version tests
// ============================================================================

#[test]
fn help_flag_should_display_usage() {
    squeeze()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Extract rich information from any text",
        ));
}

#[test]
fn version_flag_should_display_version() {
    squeeze()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

// ============================================================================
// URI extraction tests
// ============================================================================

#[test]
fn uri_flag_should_extract_uris() {
    squeeze()
        .arg("--uri")
        .write_stdin("Visit https://example.com for more info\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://example.com"));
}

#[test]
fn uri_flag_should_extract_multiple_uris() {
    squeeze()
        .arg("--uri")
        .write_stdin("Check https://foo.com and http://bar.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://foo.com"))
        .stdout(predicate::str::contains("http://bar.com"));
}

#[test]
fn uri_with_scheme_filter_should_only_match_specified_scheme() {
    squeeze()
        .arg("--uri=https")
        .write_stdin("https://secure.com and http://insecure.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://secure.com"))
        .stdout(predicate::str::contains("http://insecure.com").not());
}

#[test]
fn url_alias_should_extract_common_url_schemes() {
    squeeze()
        .arg("--url")
        .write_stdin("Visit https://example.com or mailto:test@example.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://example.com"))
        .stdout(predicate::str::contains("mailto:test@example.com"));
}

#[test]
fn http_alias_should_only_extract_http() {
    squeeze()
        .arg("--http")
        .write_stdin("http://example.com and https://secure.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("http://example.com"))
        .stdout(predicate::str::contains("https://secure.com").not());
}

#[test]
fn https_alias_should_only_extract_https() {
    squeeze()
        .arg("--https")
        .write_stdin("http://example.com and https://secure.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://secure.com"))
        .stdout(predicate::str::contains("http://example.com").not());
}

#[test]
fn strict_mode_should_include_trailing_parentheses() {
    squeeze()
        .arg("--uri")
        .arg("--strict")
        .write_stdin("See http://example.com/path) here\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("http://example.com/path)"));
}

// ============================================================================
// Codetag extraction tests
// ============================================================================

#[test]
fn codetag_flag_should_extract_codetags() {
    squeeze()
        .arg("--codetag")
        .write_stdin("// TODO: implement this\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("TODO: implement this"));
}

#[test]
fn codetag_with_mnemonic_should_filter_by_mnemonic() {
    squeeze()
        .arg("--codetag=TODO")
        .write_stdin("// TODO: do this\n// FIXME: fix this\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("TODO: do this"))
        .stdout(predicate::str::contains("FIXME").not());
}

#[test]
fn todo_alias_should_only_extract_todos() {
    squeeze()
        .arg("--todo")
        .write_stdin("// TODO: do this\n// FIXME: fix this\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("TODO: do this"))
        .stdout(predicate::str::contains("FIXME").not());
}

#[test]
fn fixme_alias_should_only_extract_fixmes() {
    squeeze()
        .arg("--fixme")
        .write_stdin("// TODO: do this\n// FIXME: fix this\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("FIXME: fix this"))
        .stdout(predicate::str::contains("TODO").not());
}

#[test]
fn hide_mnemonic_should_exclude_mnemonic_from_output() {
    squeeze()
        .arg("--codetag")
        .arg("--hide-mnemonic")
        .write_stdin("// TODO: implement feature\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("implement feature"))
        .stdout(predicate::str::contains("TODO:").not());
}

// ============================================================================
// First flag tests
// ============================================================================

#[test]
fn first_flag_should_only_output_first_result() {
    squeeze()
        .arg("--uri")
        .arg("--first")
        .write_stdin("https://first.com https://second.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://first.com"))
        .stdout(predicate::str::contains("https://second.com").not());
}

// ============================================================================
// Mirror tests
// ============================================================================

#[test]
fn mirror_flag_should_output_full_input() {
    squeeze()
        .arg("--mirror")
        .write_stdin("hello world\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world"));
}

// ============================================================================
// Empty input tests
// ============================================================================

#[test]
fn no_finder_flag_should_produce_no_output() {
    squeeze()
        .write_stdin("https://example.com\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn empty_input_should_produce_no_output() {
    squeeze()
        .arg("--uri")
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn no_matches_should_produce_no_output() {
    squeeze()
        .arg("--uri")
        .write_stdin("no urls here\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// Multiple finders tests
// ============================================================================

#[test]
fn multiple_finders_should_all_produce_output() {
    squeeze()
        .arg("--uri")
        .arg("--codetag")
        .write_stdin("https://example.com // TODO: test this\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://example.com"))
        .stdout(predicate::str::contains("TODO: test this"));
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn multiple_lines_should_be_processed() {
    squeeze()
        .arg("--uri")
        .write_stdin("https://line1.com\nhttps://line2.com\nhttps://line3.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://line1.com"))
        .stdout(predicate::str::contains("https://line2.com"))
        .stdout(predicate::str::contains("https://line3.com"));
}

#[test]
fn uri_should_handle_complex_urls() {
    squeeze()
        .arg("--uri")
        .write_stdin("https://api.example.com/v1/users?page=1&limit=10#section\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "https://api.example.com/v1/users?page=1&limit=10#section",
        ));
}

#[test]
fn codetag_should_be_case_insensitive() {
    squeeze()
        .arg("--codetag")
        .write_stdin("// todo: lowercase\n// TODO: uppercase\n// ToDo: mixed\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("todo: lowercase"))
        .stdout(predicate::str::contains("TODO: uppercase"))
        .stdout(predicate::str::contains("ToDo: mixed"));
}
