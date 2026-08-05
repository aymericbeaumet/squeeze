//! Hardening regression tests for the path, modeline and codetag finders.
//!
//! Each section pins one verified bug fix (plus variants) and re-pins the
//! known non-bugs so future changes to these finders are deliberate.

use squeeze::{
    Finder, codetag::Codetag, modeline::Modeline, path::Path as PathFinder, scanner::Scanner,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_one<'a>(finder: &dyn Finder, input: &'a str) -> Option<&'a str> {
    finder.find(input).map(|r| &input[r])
}

fn path_one(input: &str) -> Option<&str> {
    find_one(&PathFinder::default(), input)
}

fn modeline_one(input: &str) -> Option<&str> {
    find_one(&Modeline::default(), input)
}

fn find_all_texts(finder: &dyn Finder, line: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut idx = 0;
    while idx < line.len() {
        if let Some(range) = finder.find(&line[idx..]) {
            results.push(line[idx + range.start..idx + range.end].to_string());
            idx += range.end;
        } else {
            break;
        }
    }
    results
}

/// Asserts that scanning through a `Scanner` yields the same set of spans as
/// iterated `find()` calls, for every input in the corpus.
fn assert_scanner_parity<F>(make: F, corpus: &[&str])
where
    F: Fn() -> Box<dyn Finder>,
{
    for input in corpus {
        let mut expected = find_all_texts(make().as_ref(), input);
        expected.sort();
        let scanner = Scanner::new(vec![make()]);
        let mut got: Vec<String> = scanner
            .scan_line(input)
            .into_iter()
            .map(|m| input[m.range].to_string())
            .collect();
        got.sort();
        assert_eq!(expected, got, "scanner/find divergence on {input:?}");
    }
}

// ===========================================================================
// path: fixpoint trailing-strip (bug 1)
// ===========================================================================

#[test]
fn path_strips_closer_then_period() {
    assert_eq!(Some("/etc/hosts"), path_one("(see /etc/hosts)."));
}

#[test]
fn path_strips_quote_then_period() {
    assert_eq!(Some("/etc/hosts"), path_one("see '/etc/hosts'."));
}

#[test]
fn path_strips_colon_then_period() {
    assert_eq!(Some("/a/b"), path_one("x /a/b:. y"));
}

#[test]
fn path_strips_nested_parens() {
    assert_eq!(Some("/a/b"), path_one("((/a/b))"));
}

#[test]
fn path_strips_bracket_then_period() {
    assert_eq!(Some("/a/b"), path_one("[/a/b]."));
}

#[test]
fn path_strips_quote_then_comma() {
    assert_eq!(Some("/a/b"), path_one("read '/a/b',"));
}

#[test]
fn path_strips_mixed_quote_colon_period_tail() {
    assert_eq!(Some("/a/b"), path_one("see \"/a/b\":."));
}

// ===========================================================================
// path: balance-aware closer stripping (bug 2)
// ===========================================================================

#[test]
fn path_keeps_balanced_paren() {
    assert_eq!(Some("/tmp/file(1)"), path_one("saved to /tmp/file(1)"));
}

#[test]
fn path_keeps_balanced_paren_and_strips_comma() {
    assert_eq!(Some("/tmp/file(1)"), path_one("/tmp/file(1),"));
}

#[test]
fn path_keeps_multiple_balanced_parens() {
    assert_eq!(Some("/tmp/a(1)(2)"), path_one("/tmp/a(1)(2)"));
}

#[test]
fn path_strips_wrapper_but_keeps_inner_paren() {
    assert_eq!(Some("/tmp/file(1)"), path_one("(/tmp/file(1))"));
}

#[test]
fn path_keeps_balanced_bracket() {
    assert_eq!(Some("/tmp/x[1]"), path_one("ls /tmp/x[1]"));
}

#[test]
fn path_keeps_balanced_brace() {
    assert_eq!(Some("/tmp/y{2}"), path_one("cat /tmp/y{2}"));
}

#[test]
fn path_strips_unbalanced_paren_wrapper() {
    assert_eq!(Some("/etc/hosts"), path_one("(see /etc/hosts)"));
}

#[test]
fn path_strips_unbalanced_bracket_wrapper() {
    assert_eq!(Some("/etc/config"), path_one("see [/etc/config] now"));
}

#[test]
fn path_strips_angle_wrapper() {
    assert_eq!(Some("/etc/x"), path_one("see </etc/x>"));
}

// ===========================================================================
// path: `=` and `>` allowed as boundary-before (bug 3)
// ===========================================================================

#[test]
fn path_after_equals_flag() {
    assert_eq!(Some("/etc/app.conf"), path_one("--config=/etc/app.conf"));
}

#[test]
fn path_after_equals_env_assignment() {
    assert_eq!(Some("/usr/local/bin"), path_one("PATH=/usr/local/bin"));
}

#[test]
fn path_after_redirect() {
    assert_eq!(Some("/tmp/out.txt"), path_one("echo hi >/tmp/out.txt"));
}

#[test]
fn path_after_stderr_redirect_yields_dev_null() {
    // Decision: `2>/dev/null` does yield `/dev/null` — the `2` stays outside
    // the match because `>` is a boundary.
    assert_eq!(Some("/dev/null"), path_one("2>/dev/null"));
}

#[test]
fn path_after_append_redirect() {
    assert_eq!(Some("/tmp/out"), path_one(">>/tmp/out"));
}

#[test]
fn path_after_equals_keeps_line_col_suffix() {
    assert_eq!(
        Some("/var/log/app.log:42"),
        path_one("--log=/var/log/app.log:42")
    );
}

#[test]
fn path_after_equals_home_prefix() {
    assert_eq!(Some("~/foo/bar"), path_one("X=~/foo/bar"));
}

#[test]
fn path_after_equals_relative_prefix() {
    assert_eq!(Some("./rel/path"), path_one("DIR=./rel/path"));
}

#[test]
fn path_after_equals_parent_prefix() {
    assert_eq!(Some("../up/one"), path_one("BASE=../up/one"));
}

#[test]
fn path_after_equals_without_path_prefix_still_none() {
    // `b/c` has no `/ ./ ../ ~/` prefix, so `=` alone must not create a match.
    assert_eq!(None, path_one("a=b/c"));
}

// ===========================================================================
// path: known non-bugs stay pinned
// ===========================================================================

#[test]
fn path_url_interiors_stay_protected() {
    assert_eq!(None, path_one("https://x.com/a/b"));
    assert_eq!(None, path_one("file:///etc/hosts"));
    assert_eq!(None, path_one("C:/Users/x"));
}

#[test]
fn path_prose_slashes_stay_rejected() {
    for input in [
        "and/or",
        "24/7",
        "I/O",
        "TCP/IP",
        "1/2",
        "01/15/2024",
        "s/foo/bar/",
    ] {
        assert_eq!(None, path_one(input), "{input:?}");
    }
}

#[test]
fn path_bare_relatives_stay_unmatched() {
    for input in ["src/main.rs", "file.txt", ".env", "~alice/docs"] {
        assert_eq!(None, path_one(input), "{input:?}");
    }
}

#[test]
fn path_protocol_relative_still_matches() {
    assert_eq!(
        Some("//cdn.example.com/lib.js"),
        path_one("//cdn.example.com/lib.js")
    );
}

#[test]
fn path_multibyte_segment_pin() {
    assert_eq!(Some("/tmp/文件.txt"), path_one("open /tmp/文件.txt now"));
}

#[test]
fn path_multibyte_home_pin() {
    assert_eq!(
        Some("~/ログ/app.log"),
        path_one("ログは ~/ログ/app.log です")
    );
}

// ===========================================================================
// path: try_at agrees with find on the new stripping rules
// ===========================================================================

#[test]
fn path_try_at_keeps_balanced_paren() {
    let finder = PathFinder::default();
    let input = b"/tmp/file(1) rest";
    assert_eq!(Some(0..12), finder.try_at(input, 0));
}

#[test]
fn path_try_at_strips_to_fixpoint() {
    let finder = PathFinder::default();
    let input = b"(see /etc/hosts).";
    assert_eq!(Some(5..15), finder.try_at(input, 5));
}

#[test]
fn path_try_at_matches_after_equals() {
    let finder = PathFinder::default();
    let input = b"--config=/etc/app.conf";
    assert_eq!(Some(9..22), finder.try_at(input, 9));
}

#[test]
fn path_scanner_parity_corpus() {
    assert_scanner_parity(
        || Box::new(PathFinder::default()),
        &[
            "(see /etc/hosts).",
            "see '/etc/hosts'.",
            "x /a/b:. y",
            "((/a/b))",
            "[/a/b].",
            "saved to /tmp/file(1)",
            "/tmp/file(1),",
            "/tmp/a(1)(2)",
            "(/tmp/file(1))",
            "ls /tmp/x[1]",
            "--config=/etc/app.conf",
            "PATH=/usr/local/bin",
            "echo hi >/tmp/out.txt",
            "2>/dev/null",
            ">>/tmp/out",
            "--log=/var/log/app.log:42",
            "X=~/foo/bar",
            "DIR=./rel/path",
            "a=b/c",
            "https://x.com/a/b",
            "file:///etc/hosts",
            "C:/Users/x",
            "//cdn.example.com/lib.js",
            "open /tmp/文件.txt now",
            "copy /etc/hosts to /tmp/hosts",
            "and/or 24/7 I/O",
            "see </etc/x>",
            "/",
            "/.",
            "",
        ],
    );
}

// ===========================================================================
// modeline: versioned prefixes (bug 5)
// ===========================================================================

#[test]
fn modeline_versioned_plain() {
    assert_eq!(
        Some("vim700: set foldmethod=marker:"),
        modeline_one("// vim700: set foldmethod=marker:")
    );
}

#[test]
fn modeline_versioned_less_than() {
    assert_eq!(
        Some("vim<702: set ts=4:"),
        modeline_one("vim<702: set ts=4:")
    );
}

#[test]
fn modeline_versioned_equals() {
    assert_eq!(Some("vim=703: ts=4"), modeline_one("vim=703: ts=4"));
}

#[test]
fn modeline_versioned_greater_than() {
    assert_eq!(Some("vim>702: sw=2"), modeline_one("vim>702: sw=2"));
}

#[test]
fn modeline_invalid_version_rejected() {
    assert_eq!(None, modeline_one("vim7x0: ts=4"));
}

#[test]
fn modeline_versioned_first_form_in_comment() {
    assert_eq!(
        Some("vim700: ts=4 sw=4"),
        modeline_one("# vim700: ts=4 sw=4")
    );
}

// ===========================================================================
// modeline: prose false positives (bug 6)
// ===========================================================================

#[test]
fn modeline_prose_vim_rejected() {
    assert_eq!(None, modeline_one("I prefer vim: it is great for editing"));
}

#[test]
fn modeline_prose_ex_rejected() {
    assert_eq!(None, modeline_one("for ex: see the docs"));
}

#[test]
fn modeline_space_before_colon_rejected() {
    // `vim : ts=4` is invalid in vim itself: no whitespace is allowed between
    // the token and the colon.
    assert_eq!(None, modeline_one("vim : ts=4"));
}

#[test]
fn modeline_first_form_without_equals_is_a_known_miss() {
    // All-boolean-flag first-form modelines are rare; requiring at least one
    // `=` in the first form is the accepted trade-off against prose false
    // positives. Pinned as a known miss.
    assert_eq!(None, modeline_one("vim: noet nowrap"));
}

#[test]
fn modeline_second_form_without_equals_still_matches() {
    // The `set ...:` structure is discriminating enough on its own.
    assert_eq!(Some("vim: set noet:"), modeline_one("// vim: set noet:"));
}

#[test]
fn modeline_uppercase_prefix_still_accepted() {
    assert_eq!(Some("VIM: ts=4"), modeline_one("// VIM: ts=4"));
    assert_eq!(Some("Vim: ts=4"), modeline_one("// Vim: ts=4"));
}

// ===========================================================================
// modeline: single-line contract (bug 7)
// ===========================================================================

#[test]
fn modeline_does_not_cross_newline() {
    assert_eq!(None, modeline_one("x vim:\nset ts=4 sw=2: y"));
}

#[test]
fn modeline_match_stops_at_newline() {
    assert_eq!(Some("vim: ts=4"), modeline_one("vim: ts=4\nrest"));
}

// ===========================================================================
// modeline: plain scan-mode finder, no quadratic scanning (bug 4)
// ===========================================================================

#[test]
fn modeline_is_a_plain_scan_mode_finder() {
    let finder = Modeline::default();
    assert!(!finder.dispatchable());
    assert!(!finder.triggerable());
    // Default try_at of a non-dispatchable finder returns None.
    assert_eq!(None, finder.try_at(b"vim: ts=4", 0));
}

#[test]
fn modeline_100kb_e_run_completes() {
    // Used to take ~6.7s through the scanner due to per-candidate rescans;
    // correctness-only assert, no timing.
    let line = "e".repeat(100_000);
    assert_eq!(None, Modeline::default().find(&line));

    let mut codetag = Codetag::default();
    codetag.build_mnemonics_regex().unwrap();
    let scanner = Scanner::new(vec![
        Box::new(Modeline::default()),
        Box::new(PathFinder::default()),
        Box::new(codetag),
    ]);
    assert!(scanner.scan_line(&line).is_empty());
}

#[test]
fn modeline_100kb_line_with_match_at_end() {
    let mut line = "e".repeat(100_000);
    line.push_str(" vim: ts=4");
    let finder = Modeline::default();
    let range = finder.find(&line).unwrap();
    assert_eq!("vim: ts=4", &line[range]);
}

#[test]
fn modeline_scanner_parity_corpus() {
    assert_scanner_parity(
        || Box::new(Modeline::default()),
        &[
            "// vim: set ts=4 sw=4 et:",
            "// vim: ts=4 sw=4",
            "vim700: set foldmethod=marker:",
            "vim<702: set ts=4:",
            "vim=703: ts=4",
            "vim>702: sw=2",
            "vim7x0: ts=4",
            "I prefer vim: it is great for editing",
            "for ex: see the docs",
            "vim : ts=4",
            "// vi: set noet ts=4:",
            "/* vim:ts=4:sw=4:et: */",
            "# vim: ts=4 sw=4",
            "devim:ts=4",
            "see https://example.com",
            "",
        ],
    );
}

// ===========================================================================
// codetag: empty / whitespace-only mnemonics ignored (bug 8)
// ===========================================================================

#[test]
fn codetag_empty_mnemonic_is_ignored() {
    let mut finder = Codetag::default();
    finder.add_mnemonic("");
    finder.build_mnemonics_regex().unwrap();
    // The empty mnemonic must not create an empty alternation branch that
    // matches every `word:`.
    assert_eq!(None, finder.find("hello: world"));
    // With no effective custom mnemonics, defaults remain active.
    assert!(finder.find("TODO: x").is_some());
}

#[test]
fn codetag_whitespace_only_mnemonics_are_ignored() {
    let mut finder = Codetag::default();
    finder.add_mnemonic("   ");
    finder.add_mnemonic("\t");
    finder.build_mnemonics_regex().unwrap();
    assert_eq!(None, finder.find("hello: world"));
    assert!(finder.find("FIXME: y").is_some());
}

#[test]
fn codetag_empty_mnemonic_alongside_real_one() {
    // Mirrors CLI usage `--codetag=todo,` (trailing comma).
    let mut finder = Codetag::default();
    finder.add_mnemonic("todo");
    finder.add_mnemonic("");
    finder.build_mnemonics_regex().unwrap();
    assert_eq!(None, finder.find("hello: world"));
    assert_eq!(
        Some("todo: x"),
        finder.find("todo: x").map(|r| &"todo: x"[r])
    );
    // Defaults must NOT be active once a real custom mnemonic exists.
    assert_eq!(None, finder.find("FIXME: z"));
}

#[test]
fn codetag_mnemonic_surrounding_whitespace_is_trimmed() {
    let mut finder = Codetag::default();
    finder.add_mnemonic(" custom ");
    finder.build_mnemonics_regex().unwrap();
    assert!(finder.find("custom: task").is_some());
}

#[test]
fn codetag_lazy_compilation_without_build_call() {
    // The regex compiles lazily on first use; build_mnemonics_regex is
    // optional (doc fix pin).
    let mut finder = Codetag::default();
    finder.add_mnemonic("");
    assert_eq!(None, finder.find("hello: world"));
}

// ===========================================================================
// codetag: known non-bugs stay pinned
// ===========================================================================

#[test]
fn codetag_special_chars_matched_literally() {
    let mut finder = Codetag::default();
    finder.add_mnemonic("a(b");
    finder.build_mnemonics_regex().unwrap();
    assert!(finder.find("a(b: x").is_some());
}

#[test]
fn codetag_word_boundary_pins() {
    let finder = Codetag::default();
    assert_eq!(None, finder.find("TODOS: not a tag"));
    assert_eq!(None, finder.find("mastodon: social"));
}

#[test]
fn codetag_first_match_consumes_rest_of_line() {
    let finder = Codetag::default();
    let input = "TODO: first FIXME: second";
    assert_eq!(Some("TODO: first FIXME: second"), find_one(&finder, input));
}

#[test]
fn codetag_scanner_parity_corpus() {
    assert_scanner_parity(
        || {
            let mut codetag = Codetag::default();
            codetag.build_mnemonics_regex().unwrap();
            Box::new(codetag)
        },
        &[
            "TODO: check this",
            "// FIXME(john): broken",
            "hello: world",
            "TODO: first FIXME: second",
            "mastodon: social",
            "no tags here",
            "",
        ],
    );
}
