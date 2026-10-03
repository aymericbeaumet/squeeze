//! Hardening regression tests for the data finders: json, jwt, env.
//!
//! Covers the fixed bugs (base64url alphabet, unsecured JWTs, short
//! payloads, depth-limit fragment extraction, lone UTF-16 surrogates,
//! `${VAR:-default}` operators) plus pins for every documented non-bug so
//! future changes to these finders are deliberate.
//!
//! serde_json is intentionally not a dependency: differential expectations
//! against it are encoded as hardcoded per-input assertions (see
//! `json_matches_agree_with_serde_verdicts`).

use squeeze::Finder;
use squeeze::env::Env;
use squeeze::json::Json;
use squeeze::jwt::Jwt;
use squeeze::scanner::Scanner;

// A realistic HS256 JWT: header.payload.signature.
const JWT_HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// An unsecured JWT (RFC 7519 section 6): `{"alg":"none"}` header,
// `{"sub":"1"}` payload, empty signature. The trailing dot is part of it.
const JWT_NONE: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.";

/// First match of `finder` in `input`, as text.
fn find_one(finder: &dyn Finder, input: &str) -> Option<String> {
    finder.find(input).map(|r| input[r].to_string())
}

/// All matches via repeated `find()` on the remaining suffix (the
/// documented iteration contract).
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

/// All matches via the Scanner (dispatch/try_at path), as text.
fn scan_all(finder: Box<dyn Finder>, input: &str) -> Vec<String> {
    let scanner = Scanner::new(vec![finder]);
    scanner
        .scan_line(input)
        .into_iter()
        .map(|m| input[m.range].to_string())
        .collect()
}

/// The Scanner (try_at) and find() iteration must agree exactly.
fn assert_parity(make: fn() -> Box<dyn Finder>, input: &str) {
    let old = find_all(make().as_ref(), input);
    let new = scan_all(make(), input);
    assert_eq!(old, new, "scanner/find mismatch on {input:?}");
}

// ===========================================================================
// JWT fix 1: base64url alphabet is exactly A-Za-z0-9-_ (no + / =)
// ===========================================================================

#[test]
fn jwt_after_equals_sign_matches() {
    // `TOKEN=eyJ...` is the most common habitat; `=` is not base64url and
    // must not block the boundary-before check.
    let finder = Jwt::default();
    let input = format!("TOKEN={JWT_HS256}");
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_HS256));
}

#[test]
fn jwt_after_equals_in_query_param_matches() {
    let finder = Jwt::default();
    let input = format!("https://api.example.com/cb?access_token={JWT_HS256}&state=xyz");
    // `&` terminates the signature.
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_HS256));
}

#[test]
fn jwt_after_slash_in_url_path_matches() {
    let finder = Jwt::default();
    let input = format!("https://example.com/verify/{JWT_HS256}");
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_HS256));
}

#[test]
fn jwt_after_plus_matches() {
    let finder = Jwt::default();
    let input = format!("a+{JWT_HS256}");
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_HS256));
}

#[test]
fn jwt_in_cookie_matches() {
    let finder = Jwt::default();
    let input = format!("Cookie: session={JWT_HS256}; Path=/");
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_HS256));
}

#[test]
fn jwt_in_authorization_bearer_header_matches() {
    let finder = Jwt::default();
    let input = format!("Authorization: Bearer {JWT_HS256}");
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_HS256));
}

#[test]
fn jwt_garbage_with_equals_inside_rejected() {
    // `=` inside a segment is not base64url, so this is not three dotted
    // base64url segments.
    let finder = Jwt::default();
    assert!(finder.find("eyJa=bcd.efgh.ijkl").is_none());
}

#[test]
fn jwt_garbage_with_plus_slash_rejected() {
    // `+` and `/` belong to standard base64, not base64url.
    let finder = Jwt::default();
    assert!(finder.find("eyJ+a/b.cd+ef.gh/ij").is_none());
}

#[test]
fn jwt_trailing_equals_padding_not_glued_into_signature() {
    // Signatures are unpadded base64url; trailing `=` is not part of the
    // token.
    let finder = Jwt::default();
    let input = format!("{JWT_HS256}==");
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_HS256));
}

// ===========================================================================
// JWT fix 2: unsecured (alg:none) tokens with an empty signature segment
// ===========================================================================

#[test]
fn jwt_unsecured_matches_including_trailing_dot() {
    let finder = Jwt::default();
    assert_eq!(find_one(&finder, JWT_NONE).as_deref(), Some(JWT_NONE));
}

#[test]
fn jwt_unsecured_followed_by_text_matches_including_dot() {
    let finder = Jwt::default();
    let input = format!("{JWT_NONE} next");
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_NONE));
}

#[test]
fn jwt_unsecured_in_authorization_header() {
    let finder = Jwt::default();
    let input = format!("Authorization: Bearer {JWT_NONE}");
    assert_eq!(find_one(&finder, &input).as_deref(), Some(JWT_NONE));
}

#[test]
fn jwt_two_segments_without_trailing_dot_still_rejected() {
    // Pin: without the trailing dot there is no (empty) signature segment.
    let finder = Jwt::default();
    assert!(
        finder
            .find("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0")
            .is_none()
    );
}

// ===========================================================================
// JWT fix 3: minimal payload `e30` (= `{}`) and payload starts with 'e'
// ===========================================================================

#[test]
fn jwt_e30_payload_with_signature_matches() {
    // `e30` is base64url for `{}`, a legal empty claims set.
    let finder = Jwt::default();
    let input =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert_eq!(find_one(&finder, input).as_deref(), Some(input));
}

#[test]
fn jwt_e30_payload_unsecured_matches() {
    let finder = Jwt::default();
    let input = "eyJhbGciOiJub25lIn0.e30.";
    assert_eq!(find_one(&finder, input).as_deref(), Some(input));
}

#[test]
fn jwt_payload_not_starting_with_e_rejected() {
    // Any base64url-encoded JSON object starts with 'e' ('{' = 0x7B ->
    // first sextet 011110 -> 'e'); `QUJD` cannot be a claims object.
    let finder = Jwt::default();
    assert!(
        finder
            .find("eyJhbGciOiJIUzI1NiJ9.QUJD.SflKxwRJSMeKKF2QT4fw")
            .is_none()
    );
}

#[test]
fn jwt_two_char_payload_rejected() {
    let finder = Jwt::default();
    assert!(
        finder
            .find("eyJhbGciOiJIUzI1NiJ9.ey.SflKxwRJSMeKKF2QT4fw")
            .is_none()
    );
}

#[test]
fn jwt_short_nonempty_signature_rejected() {
    // Non-empty signatures keep the >= 4 minimum.
    let finder = Jwt::default();
    assert!(finder.find("eyJhbGciOiJIUzI1NiJ9.e30.abc").is_none());
}

// ===========================================================================
// JWT pins: boundary rules that must not change
// ===========================================================================

#[test]
fn jwt_preceded_by_underscore_still_rejected() {
    // `_` is a genuine base64url character; the boundary stays.
    let finder = Jwt::default();
    let input = format!("x_{JWT_HS256}");
    assert!(finder.find(&input).is_none());
}

#[test]
fn jwt_preceded_by_dash_still_rejected() {
    // `-` is a genuine base64url character; the boundary stays.
    let finder = Jwt::default();
    let input = format!("-{JWT_HS256}");
    assert!(finder.find(&input).is_none());
}

#[test]
fn jwt_multiple_tokens_iterate() {
    let finder = Jwt::default();
    let input = format!("first={JWT_HS256} second={JWT_NONE} done");
    assert_eq!(find_all(&finder, &input), vec![JWT_HS256, JWT_NONE]);
}

// ===========================================================================
// JSON fix 4: depth limit yields no match instead of an inner fragment
// ===========================================================================

fn nested_array(depth: usize) -> String {
    format!("{}1{}", "[".repeat(depth), "]".repeat(depth))
}

#[test]
fn json_nested_at_exactly_256_parses_fully() {
    // MAX_DEPTH = 256 is the documented limit; a 256-deep document is
    // RFC 8259-valid and must match in full.
    let finder = Json::default();
    let input = nested_array(256);
    assert_eq!(find_one(&finder, &input).as_deref(), Some(input.as_str()));
}

#[test]
fn json_nested_at_257_yields_no_match() {
    // One past the limit: the whole document is refused; no inner
    // fragment may be emitted.
    let finder = Json::default();
    let input = nested_array(257);
    assert!(finder.find(&input).is_none());
    assert!(scan_all(Box::new(Json::default()), &input).is_empty());
}

#[test]
fn json_300_deep_line_yields_no_match() {
    // Regression: this used to emit an arbitrary 513-byte inner fragment
    // starting at byte 44.
    let finder = Json::default();
    let input = nested_array(300);
    assert!(finder.find(&input).is_none());
    assert!(scan_all(Box::new(Json::default()), &input).is_empty());
}

#[test]
fn json_shallow_document_before_deep_one_still_found() {
    let finder = Json::default();
    let input = format!("[[1]] {}", nested_array(300));
    assert_eq!(find_one(&finder, &input).as_deref(), Some("[[1]]"));
    // And it is the only match on the line.
    assert_eq!(find_all(&finder, &input), vec!["[[1]]"]);
}

#[test]
fn json_shallow_document_after_deep_one_still_found() {
    let finder = Json::default();
    let input = format!("{} [[1]]", nested_array(300));
    assert_eq!(find_all(&finder, &input), vec!["[[1]]"]);
}

#[test]
fn json_deep_run_with_whitespace_yields_no_match() {
    // Whitespace inside the bracket run must not resurrect inner
    // fragments.
    let finder = Json::default();
    let input = format!("{}1{}", "[ ".repeat(300), "]".repeat(300));
    assert!(finder.find(&input).is_none());
    assert!(scan_all(Box::new(Json::default()), &input).is_empty());
}

#[test]
fn json_pathological_open_brackets_completes() {
    // Sanity check on the previously O(MAX_DEPTH * n) input: 100k opening
    // brackets. Assert on correctness (no match: the document never
    // closes); linearity keeps this test fast.
    let finder = Json::default();
    let input = "[".repeat(100_000);
    assert!(finder.find(&input).is_none());
}

// ===========================================================================
// JSON fix 5: \uXXXX surrogate pairing
// ===========================================================================

#[test]
fn json_lone_high_surrogate_rejected() {
    // serde_json: "unexpected end of hex escape / lone leading surrogate".
    let finder = Json::default();
    assert!(finder.find(r#"["\ud800"]"#).is_none());
    assert!(finder.find(r#"{"k": "\uD800"}"#).is_none());
}

#[test]
fn json_lone_low_surrogate_rejected() {
    let finder = Json::default();
    assert!(finder.find(r#"["\udc00"]"#).is_none());
    assert!(finder.find(r#"["\uDFFF"]"#).is_none());
}

#[test]
fn json_valid_surrogate_pair_accepted() {
    // serde_json parses this to ["😀"].
    let finder = Json::default();
    let input = r#"["😀"]"#;
    assert_eq!(find_one(&finder, input).as_deref(), Some(input));
}

#[test]
fn json_uppercase_surrogate_pair_accepted() {
    let finder = Json::default();
    let input = r#"{"k": "😀"}"#;
    assert_eq!(find_one(&finder, input).as_deref(), Some(input));
}

#[test]
fn json_truncated_high_surrogate_at_eol_rejected() {
    let finder = Json::default();
    assert!(finder.find(r#"["\ud83d"#).is_none());
    assert!(finder.find(r#"["\ud83d\u"#).is_none());
}

#[test]
fn json_high_surrogate_before_closing_quote_rejected() {
    let finder = Json::default();
    assert!(finder.find(r#"["\ud83d"]"#).is_none());
}

#[test]
fn json_high_surrogate_followed_by_regular_escape_rejected() {
    let finder = Json::default();
    assert!(finder.find(r#"["\ud83d\n"]"#).is_none());
}

#[test]
fn json_high_surrogate_followed_by_high_surrogate_rejected() {
    let finder = Json::default();
    assert!(finder.find(r#"["\ud800\ud800"]"#).is_none());
}

#[test]
fn json_high_surrogate_followed_by_plain_text_rejected() {
    let finder = Json::default();
    assert!(finder.find(r#"["\ud800abcd"]"#).is_none());
}

#[test]
fn json_astral_literal_utf8_still_accepted() {
    // Raw (non-escaped) astral characters keep working.
    let finder = Json::default();
    let input = r#"{"emoji": "😀"}"#;
    assert_eq!(find_one(&finder, input).as_deref(), Some(input));
}

#[test]
fn json_bmp_escapes_still_accepted() {
    let finder = Json::default();
    for input in [
        r#"["A"]"#, // 'A'
        r#"["퟿"]"#, // last code point before the surrogate range
        r#"[""]"#, // first code point after the surrogate range
        r#"["￿"]"#,
    ] {
        assert_eq!(
            find_one(&finder, input).as_deref(),
            Some(input),
            "expected {input:?} to match in full"
        );
    }
}

// ===========================================================================
// JSON pins: strict rejections/acceptances that must not change
// ===========================================================================

#[test]
fn json_strict_rejections_pinned() {
    let finder = Json::default();
    let rejected = [
        "[01]",                    // leading zero
        "[.5]",                    // no digit before the dot
        "[1.]",                    // no digit after the dot
        "[1,,2]",                  // double comma
        "[1, 2,]",                 // trailing comma in array
        r#"{"a": 1,}"#,            // trailing comma in object
        "[True]",                  // wrong-case literal
        "[NaN]",                   // not a JSON literal
        r#"{'key': 'value'}"#,     // single-quoted strings
        r#"{"k": "bad \q here"}"#, // invalid escape
    ];
    for input in rejected {
        assert!(
            finder.find(input).is_none(),
            "expected no match in {input:?}"
        );
    }
    // Raw control character in a string.
    let ctrl = "{\"k\": \"a\tb\"}";
    assert!(finder.find(ctrl).is_none());
}

#[test]
fn json_strict_acceptances_pinned() {
    let finder = Json::default();
    for input in ["[-0]", "[0e0]", "[1.5e10]", "[1e999]"] {
        assert_eq!(
            find_one(&finder, input).as_deref(),
            Some(input),
            "expected {input:?} to match in full"
        );
    }
}

#[test]
fn json_bare_single_digit_arrays_still_match() {
    // Inherent: `[8]` and `[1]` are valid JSON documents.
    let finder = Json::default();
    for input in ["[8]", "[1]"] {
        assert_eq!(find_one(&finder, input).as_deref(), Some(input));
    }
}

#[test]
fn json_matches_agree_with_serde_verdicts() {
    // Differential expectations vs serde_json, hardcoded per input:
    // Some(text) means serde_json::from_str::<Value>(text) succeeds on the
    // exact matched text; None means the candidate document is rejected by
    // serde_json and the finder must not surface it.
    let finder = Json::default();
    let cases: &[(&str, Option<&str>)] = &[
        (r#"{"a": 1}"#, Some(r#"{"a": 1}"#)),
        (r#"["😀"]"#, Some(r#"["😀"]"#)),
        (r#"["\ud800"]"#, None), // serde: lone leading surrogate
        (r#"["\udc00"]"#, None), // serde: lone trailing surrogate
        (r#"["\ud83d"#, None),   // serde: unexpected EOF in escape
        ("[-0]", Some("[-0]")),
        ("[0e0]", Some("[0e0]")),
        ("[01]", None), // serde: invalid number
        ("[1.]", None), // serde: invalid number
        ("[.5]", None), // serde: expected value
        ("[1,,2]", None),
        (r#"{"k": "A"}"#, Some(r#"{"k": "A"}"#)),
    ];
    for (input, expected) in cases {
        assert_eq!(
            find_one(&finder, input).as_deref(),
            *expected,
            "differential mismatch on {input:?}"
        );
    }
}

// ===========================================================================
// Env fix 6: ${VAR<op>...} operator forms
// ===========================================================================

#[test]
fn env_colon_dash_default_matches_whole_reference() {
    let finder = Env::default();
    let input = "path=${VAR:-default} rest";
    assert_eq!(find_one(&finder, input).as_deref(), Some("${VAR:-default}"));
}

#[test]
fn env_operator_forms_match_whole_reference() {
    let finder = Env::default();
    let cases = [
        "${VAR:=default}",
        "${VAR:+alt}",
        "${VAR:?message}",
        "${VAR:0:2}",      // substring
        "${VAR-fallback}", // bare POSIX forms without the colon
        "${VAR=x}",
        "${VAR+x}",
        "${VAR?x}",
        "${FILE%.txt}",
        "${FILE%%.*}",
        "${PATH#*/}",
        "${PATH##*/}",
        "${FILE/pat/repl}",
        "${VAR^}",
        "${VAR^^}",
        "${VAR,}",
        "${VAR,,}",
        "${VAR@Q}",
        "${VAR:-}", // empty default is legal
    ];
    for reference in cases {
        let input = format!("use {reference} here");
        assert_eq!(
            find_one(&finder, &input).as_deref(),
            Some(reference),
            "expected {reference:?} to match in full"
        );
    }
}

#[test]
fn env_nested_simple_var_in_default_yields_one_outer_match() {
    // `${VAR:-$HOME}`: the Scanner must emit just the outer reference.
    let input = "${VAR:-$HOME}";
    assert_eq!(scan_all(Box::new(Env::default()), input), vec![input]);
    assert_eq!(find_all(&Env::default(), input), vec![input]);
}

#[test]
fn env_nested_braced_reference_two_deep_matches_outer() {
    let finder = Env::default();
    let input = "cfg=${A:-${B:-c}} tail";
    assert_eq!(find_one(&finder, input).as_deref(), Some("${A:-${B:-c}}"));
    assert_eq!(
        scan_all(Box::new(Env::default()), input),
        vec!["${A:-${B:-c}}"]
    );
}

#[test]
fn env_unclosed_operator_at_eol_stays_unmatched() {
    let finder = Env::default();
    assert!(finder.find("${VAR:-").is_none());
    assert!(scan_all(Box::new(Env::default()), "${VAR:-").is_empty());
}

#[test]
fn env_unclosed_outer_with_closed_inner_matches_inner_only() {
    // The outer reference never closes; the inner `${B}` is still a valid
    // reference on its own.
    let input = "${A:-${B}";
    assert_eq!(find_all(&Env::default(), input), vec!["${B}"]);
    assert_eq!(scan_all(Box::new(Env::default()), input), vec!["${B}"]);
}

#[test]
fn env_non_operator_char_after_name_still_rejected() {
    let finder = Env::default();
    assert!(finder.find("${HOME foo").is_none());
    assert!(finder.find("${A!B}").is_none());
}

// ===========================================================================
// Env pins: rejections and simple forms that must not change
// ===========================================================================

#[test]
fn env_empty_braces_still_rejected() {
    let finder = Env::default();
    assert!(finder.find("${} foo").is_none());
}

#[test]
fn env_digit_name_still_rejected() {
    let finder = Env::default();
    assert!(finder.find("${123}").is_none());
    assert!(finder.find("$1").is_none());
}

#[test]
fn env_double_dollar_still_rejected() {
    let finder = Env::default();
    assert!(finder.find("$$").is_none());
}

#[test]
fn env_windows_style_still_rejected() {
    let finder = Env::default();
    assert!(finder.find("%VAR%").is_none());
}

#[test]
fn env_simple_forms_unchanged() {
    let finder = Env::default();
    let input = "use $VAR and ${OTHER} here";
    assert_eq!(find_all(&finder, input), vec!["$VAR", "${OTHER}"]);
}

// ===========================================================================
// Scanner-vs-find parity on the whole hardening corpus
// ===========================================================================

#[test]
fn jwt_scanner_find_parity_on_corpus() {
    let corpus = [
        format!("TOKEN={JWT_HS256}"),
        format!("?access_token={JWT_HS256}&state=x"),
        format!("/verify/{JWT_HS256}"),
        format!("Cookie: session={JWT_HS256}; Path=/"),
        format!("{JWT_HS256}=="),
        JWT_NONE.to_string(),
        format!("{JWT_NONE} next"),
        format!("first={JWT_HS256} second={JWT_NONE} done"),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.SflKxwRJSMeKKF2QT4fw".to_string(),
        "eyJhbGciOiJub25lIn0.e30.".to_string(),
        "eyJa=bcd.efgh.ijkl".to_string(),
        "eyJ+a/b.cd+ef.gh/ij".to_string(),
        "eyJhbGciOiJIUzI1NiJ9.QUJD.SflKxwRJSMeKKF2QT4fw".to_string(),
        "eyJhbGciOiJIUzI1NiJ9.e30.abc".to_string(),
        format!("x_{JWT_HS256}"),
        format!("-{JWT_HS256}"),
        format!("{JWT_HS256}.extra"),
        "eyJab.eyJcd.eyJef.extra".to_string(),
        "eyJ.e30.abcd".to_string(),
        "e e. e.. eyJ eyJ. eyJ.. eyJa.e.".to_string(),
    ];
    for input in &corpus {
        assert_parity(|| Box::new(Jwt::default()), input);
    }
}

#[test]
fn json_scanner_find_parity_on_corpus() {
    let corpus = [
        r#"{"key": "value"}"#.to_string(),
        r#"log: {"a": [1, 2, {"b": null}]} done"#.to_string(),
        nested_array(256),
        nested_array(257),
        nested_array(300),
        format!("[[1]] {}", nested_array(300)),
        format!("{} [[1]]", nested_array(300)),
        format!("{}1{}", "[ ".repeat(300), "]".repeat(300)),
        format!("{{\"a\": {}}}", nested_array(300)),
        r#"["😀"]"#.to_string(),
        r#"["\ud800"]"#.to_string(),
        r#"["\ud83d"#.to_string(),
        "[1,,2] [1] {not json} {}".to_string(),
        "[".repeat(300),
        "[]{}[[".to_string(),
    ];
    for input in &corpus {
        assert_parity(|| Box::new(Json::default()), input);
    }
}

#[test]
fn env_scanner_find_parity_on_corpus() {
    let corpus = [
        "${VAR:-default}",
        "path=${VAR:-default} rest",
        "${VAR:-$HOME}",
        "${A:-${B:-c}}",
        "${A:-${B}",
        "${VAR:-",
        "${VAR@Q} ${FILE%%.*} ${PATH##*/}",
        "${HOME foo",
        "${A!B}",
        "${} ${123} $1 $$ %VAR%",
        "$VAR and ${OTHER} here",
        "$A$B ${C}${D:-e}",
        "$ ${ ${} ${_}",
    ];
    for input in corpus {
        assert_parity(|| Box::new(Env::default()), input);
    }
}
