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
// Email extraction tests
// ============================================================================

#[test]
fn email_flag_should_extract_emails() {
    squeeze()
        .arg("--email")
        .write_stdin("contact user@example.com for info\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("user@example.com"));
}

#[test]
fn email_flag_should_extract_multiple_emails() {
    squeeze()
        .arg("--email")
        .write_stdin("cc: alice@one.com and bob@two.org\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@one.com"))
        .stdout(predicate::str::contains("bob@two.org"));
}

#[test]
fn email_flag_should_handle_plus_addressing() {
    squeeze()
        .arg("--email")
        .write_stdin("send to user+tag@example.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("user+tag@example.com"));
}

#[test]
fn email_flag_should_extract_from_angle_brackets() {
    squeeze()
        .arg("--email")
        .write_stdin("From: Author <author@example.com>\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("author@example.com"));
}

#[test]
fn email_flag_should_not_match_bare_at() {
    squeeze()
        .arg("--email")
        .write_stdin("user @ example\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// Path extraction tests
// ============================================================================

#[test]
fn path_flag_should_extract_absolute_path() {
    squeeze()
        .arg("--path")
        .write_stdin("see /etc/hosts for details\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("/etc/hosts"));
}

#[test]
fn path_flag_should_extract_relative_path() {
    squeeze()
        .arg("--path")
        .write_stdin("edit ./src/main.rs to fix it\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("./src/main.rs"));
}

#[test]
fn path_flag_should_extract_home_path() {
    squeeze()
        .arg("--path")
        .write_stdin("config at ~/.config/app.toml\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("~/.config/app.toml"));
}

#[test]
fn path_flag_should_extract_path_with_line_number() {
    squeeze()
        .arg("--path")
        .write_stdin("error in ./src/main.rs:42:10 here\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("./src/main.rs:42:10"));
}

#[test]
fn path_flag_should_not_match_uris() {
    squeeze()
        .arg("--path")
        .write_stdin("visit https://example.com/path\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn path_flag_should_extract_multiple_paths() {
    squeeze()
        .arg("--path")
        .write_stdin("copy /etc/hosts to /tmp/hosts\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("/etc/hosts"))
        .stdout(predicate::str::contains("/tmp/hosts"));
}

// ============================================================================
// Color extraction tests
// ============================================================================

#[test]
fn color_flag_should_extract_hex_color() {
    squeeze()
        .arg("--color")
        .write_stdin("color: #ff00aa\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("#ff00aa"));
}

#[test]
fn color_flag_should_extract_short_hex() {
    squeeze()
        .arg("--color")
        .write_stdin("color: #f0a\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("#f0a"));
}

#[test]
fn color_flag_should_extract_rgb() {
    squeeze()
        .arg("--color")
        .write_stdin("color: rgb(255, 0, 170)\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("rgb(255, 0, 170)"));
}

#[test]
fn color_flag_should_extract_hsl() {
    squeeze()
        .arg("--color")
        .write_stdin("color: hsl(120, 100%, 50%)\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("hsl(120, 100%, 50%)"));
}

#[test]
fn color_flag_should_extract_multiple_colors() {
    squeeze()
        .arg("--color")
        .write_stdin("#ff0000 and rgb(0, 255, 0)\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("#ff0000"))
        .stdout(predicate::str::contains("rgb(0, 255, 0)"));
}

// ============================================================================
// Env extraction tests
// ============================================================================

#[test]
fn env_flag_should_extract_simple_var() {
    squeeze()
        .arg("--env")
        .write_stdin("use $HOME for path\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("$HOME"));
}

#[test]
fn env_flag_should_extract_braced_var() {
    squeeze()
        .arg("--env")
        .write_stdin("use ${PATH} here\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("${PATH}"));
}

#[test]
fn env_flag_should_extract_multiple_vars() {
    squeeze()
        .arg("--env")
        .write_stdin("$HOME and ${PATH}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("$HOME"))
        .stdout(predicate::str::contains("${PATH}"));
}

#[test]
fn env_flag_should_not_match_bare_dollar() {
    squeeze()
        .arg("--env")
        .write_stdin("costs $5\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// Hash extraction tests
// ============================================================================

#[test]
fn hash_flag_should_extract_md5() {
    squeeze()
        .arg("--hash")
        .write_stdin("md5: 5d41402abc4b2a76b9719d911017c592\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("5d41402abc4b2a76b9719d911017c592"));
}

#[test]
fn hash_flag_should_extract_sha1() {
    squeeze()
        .arg("--hash")
        .write_stdin("sha1: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
        ));
}

#[test]
fn hash_flag_with_algo_filter_should_only_match_specified() {
    squeeze()
        .arg("--hash=md5")
        .write_stdin(
            "5d41402abc4b2a76b9719d911017c592 and 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("5d41402abc4b2a76b9719d911017c592"))
        .stdout(predicate::str::contains("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed").not());
}

#[test]
fn md5_alias_should_only_extract_md5() {
    squeeze()
        .arg("--md5")
        .write_stdin(
            "5d41402abc4b2a76b9719d911017c592 and 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("5d41402abc4b2a76b9719d911017c592"))
        .stdout(predicate::str::contains("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed").not());
}

#[test]
fn sha1_alias_should_only_extract_sha1() {
    squeeze()
        .arg("--sha1")
        .write_stdin(
            "5d41402abc4b2a76b9719d911017c592 and 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed\n",
        )
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
        ))
        .stdout(predicate::str::contains("5d41402abc4b2a76b9719d911017c592").not());
}

// ============================================================================
// IP extraction tests
// ============================================================================

#[test]
fn ip_flag_should_extract_ipv4() {
    squeeze()
        .arg("--ip")
        .write_stdin("server at 192.168.1.1\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.1"));
}

#[test]
fn ip_flag_should_extract_ipv6_bracketed() {
    squeeze()
        .arg("--ip")
        .write_stdin("connect to [::1]\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("[::1]"));
}

#[test]
fn ipv4_flag_should_only_extract_ipv4() {
    squeeze()
        .arg("--ipv4")
        .write_stdin("192.168.1.1 and [::1]\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.1"))
        .stdout(predicate::str::contains("[::1]").not());
}

#[test]
fn ipv6_flag_should_only_extract_ipv6() {
    squeeze()
        .arg("--ipv6")
        .write_stdin("192.168.1.1 and [::1]\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("[::1]"))
        .stdout(predicate::str::contains("192.168.1.1").not());
}

// ============================================================================
// JSON extraction tests
// ============================================================================

#[test]
fn json_flag_should_extract_object() {
    squeeze()
        .arg("--json")
        .write_stdin("data: {\"key\": \"value\"}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("{\"key\": \"value\"}"));
}

#[test]
fn json_flag_should_extract_array() {
    squeeze()
        .arg("--json")
        .write_stdin("data: [1, 2, 3]\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("[1, 2, 3]"));
}

#[test]
fn json_flag_should_extract_nested() {
    squeeze()
        .arg("--json")
        .write_stdin("{\"a\": {\"b\": [1, 2]}}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("{\"a\": {\"b\": [1, 2]}}"));
}

#[test]
fn json_flag_should_not_match_unclosed() {
    squeeze()
        .arg("--json")
        .write_stdin("{\"key\": \"value\"\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// Phone extraction tests
// ============================================================================

#[test]
fn phone_flag_should_extract_e164() {
    squeeze()
        .arg("--phone")
        .write_stdin("call +14155551234\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("+14155551234"));
}

#[test]
fn phone_flag_should_extract_parens_format() {
    squeeze()
        .arg("--phone")
        .write_stdin("call (415) 555-1234\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("(415) 555-1234"));
}

#[test]
fn phone_flag_should_extract_dashed_format() {
    squeeze()
        .arg("--phone")
        .write_stdin("call 415-555-1234\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("415-555-1234"));
}

#[test]
fn phone_flag_should_not_match_plain_digits() {
    squeeze()
        .arg("--phone")
        .write_stdin("number 1234567890\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// Semver extraction tests
// ============================================================================

#[test]
fn semver_flag_should_extract_version() {
    squeeze()
        .arg("--semver")
        .write_stdin("version 1.0.0 released\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("1.0.0"));
}

#[test]
fn semver_flag_should_extract_version_with_v() {
    squeeze()
        .arg("--semver")
        .write_stdin("tag v2.3.1\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("v2.3.1"));
}

#[test]
fn semver_flag_should_extract_prerelease() {
    squeeze()
        .arg("--semver")
        .write_stdin("v1.0.0-rc.1\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("v1.0.0-rc.1"));
}

#[test]
fn semver_flag_should_extract_with_build_meta() {
    squeeze()
        .arg("--semver")
        .write_stdin("1.0.0+build.42\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("1.0.0+build.42"));
}

#[test]
fn semver_flag_should_not_match_two_components() {
    squeeze()
        .arg("--semver")
        .write_stdin("version 1.0\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// UUID extraction tests
// ============================================================================

#[test]
fn uuid_flag_should_extract_uuid() {
    squeeze()
        .arg("--uuid")
        .write_stdin("id: 550e8400-e29b-41d4-a716-446655440000\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "550e8400-e29b-41d4-a716-446655440000",
        ));
}

#[test]
fn uuid_flag_should_extract_multiple_uuids() {
    squeeze()
        .arg("--uuid")
        .write_stdin(
            "550e8400-e29b-41d4-a716-446655440000 and 6ba7b810-9dad-11d1-80b4-00c04fd430c8\n",
        )
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "550e8400-e29b-41d4-a716-446655440000",
        ))
        .stdout(predicate::str::contains(
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ));
}

#[test]
fn uuid_flag_should_not_match_no_dashes() {
    squeeze()
        .arg("--uuid")
        .write_stdin("550e8400e29b41d4a716446655440000\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// CIDR extraction tests
// ============================================================================

#[test]
fn cidr_flag_should_extract_ipv4_cidr() {
    squeeze()
        .arg("--cidr")
        .write_stdin("network 192.168.1.0/24 configured\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.0/24"));
}

#[test]
fn cidr_flag_should_extract_multiple_cidrs() {
    squeeze()
        .arg("--cidr")
        .write_stdin("10.0.0.0/8 and 172.16.0.0/12\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.0/8"))
        .stdout(predicate::str::contains("172.16.0.0/12"));
}

#[test]
fn cidr_flag_should_extract_ipv6_cidr() {
    squeeze()
        .arg("--cidr")
        .write_stdin("subnet 2001:db8::/32 here\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("2001:db8::/32"));
}

#[test]
fn cidr_flag_should_not_match_plain_ip() {
    squeeze()
        .arg("--cidr")
        .write_stdin("host 192.168.1.1 only\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// Datetime extraction tests
// ============================================================================

#[test]
fn datetime_flag_should_extract_date() {
    squeeze()
        .arg("--datetime")
        .write_stdin("created on 2024-01-15 by admin\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("2024-01-15"));
}

#[test]
fn datetime_flag_should_extract_iso8601() {
    squeeze()
        .arg("--datetime")
        .write_stdin("timestamp: 2024-01-15T10:30:00Z\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("2024-01-15T10:30:00Z"));
}

#[test]
fn datetime_flag_should_extract_with_offset() {
    squeeze()
        .arg("--datetime")
        .write_stdin("2024-01-15T10:30:00+05:30\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("2024-01-15T10:30:00+05:30"));
}

#[test]
fn datetime_flag_should_not_match_invalid_date() {
    squeeze()
        .arg("--datetime")
        .write_stdin("2024-13-01\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// JWT extraction tests
// ============================================================================

#[test]
fn jwt_flag_should_extract_jwt() {
    squeeze()
        .arg("--jwt")
        .write_stdin("token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
}

#[test]
fn jwt_flag_should_not_match_non_jwt() {
    squeeze()
        .arg("--jwt")
        .write_stdin("abc.def.ghi\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ============================================================================
// MAC address extraction tests
// ============================================================================

#[test]
fn mac_flag_should_extract_colon_format() {
    squeeze()
        .arg("--mac")
        .write_stdin("device 00:1A:2B:3C:4D:5E connected\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("00:1A:2B:3C:4D:5E"));
}

#[test]
fn mac_flag_should_extract_dash_format() {
    squeeze()
        .arg("--mac")
        .write_stdin("device 00-1A-2B-3C-4D-5E connected\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("00-1A-2B-3C-4D-5E"));
}

#[test]
fn mac_flag_should_extract_dot_format() {
    squeeze()
        .arg("--mac")
        .write_stdin("device 001A.2B3C.4D5E connected\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("001A.2B3C.4D5E"));
}

#[test]
fn mac_flag_should_not_match_short_hex() {
    squeeze()
        .arg("--mac")
        .write_stdin("00:1A:2B:3C:4D\n")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
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
