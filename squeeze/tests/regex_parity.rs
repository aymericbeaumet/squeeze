//! The codetag, modeline and phone finders used to be regexes. Their
//! hand-written replacements must produce the same matches, so this suite
//! keeps the original regexes (as dev-dependencies only) and compares.

use proptest::prelude::*;
use regex::Regex;
use squeeze::Finder;
use squeeze::codetag::Codetag;
use squeeze::modeline::Modeline;
use squeeze::phone::Phone;
use std::ops::Range;
use std::sync::OnceLock;

const DEFAULT_MNEMONICS: &[&str] = &[
    "TODO",
    "MILESTONE",
    "MLSTN",
    "DONE",
    "YAGNI",
    "TBD",
    "TOBEDONE",
    "FIXME",
    "XXX",
    "DEBUG",
    "BROKEN",
    "REFACTOR",
    "REFACT",
    "RFCTR",
    "OOPS",
    "SMELL",
    "NEEDSWORK",
    "INSPECT",
    "BUG",
    "BUGFIX",
    "NOBUG",
    "NOFIX",
    "WONTFIX",
    "DONTFIX",
    "NEVERFIX",
    "UNFIXABLE",
    "CANTFIX",
    "REQ",
    "REQUIREMENT",
    "STORY",
    "RFE",
    "FEETCH",
    "NYI",
    "FR",
    "FTRQ",
    "FTR",
    "IDEA",
    "???",
    "QUESTION",
    "QUEST",
    "QSTN",
    "WTF",
    "!!!",
    "ALERT",
    "HACK",
    "CLEVER",
    "MAGIC",
    "PORT",
    "PORTABILITY",
    "WKRD",
    "CAVEAT",
    "CAV",
    "CAVT",
    "WARNING",
    "CAUTION",
    "NOTE",
    "HELP",
    "FAQ",
    "GLOSS",
    "GLOSSARY",
    "SEE",
    "REF",
    "REFERENCE",
    "TODOC",
    "DOCDO",
    "DODOC",
    "NEEDSDOC",
    "EXPLAIN",
    "DOCUMENT",
    "CRED",
    "CREDIT",
    "THANKS",
    "STAT",
    "STATUS",
    "RVD",
    "REVIEWED",
    "REVIEW",
];

/// The former codetag regex builder.
fn codetag_regex(mnemonics: &[&str]) -> Regex {
    let mut r = String::from("(?i)(?:");
    let alpha: Vec<&str> = mnemonics
        .iter()
        .copied()
        .filter(|m| m.chars().all(|c| c.is_alphanumeric()))
        .collect();
    let special: Vec<&str> = mnemonics
        .iter()
        .copied()
        .filter(|m| !m.chars().all(|c| c.is_alphanumeric()))
        .collect();
    let mut first = true;
    if !alpha.is_empty() {
        r.push_str("\\b(?:");
        for (i, m) in alpha.iter().enumerate() {
            if i > 0 {
                r.push('|');
            }
            regex_syntax::escape_into(m, &mut r);
        }
        r.push_str(")\\b");
        first = false;
    }
    for m in special {
        if !first {
            r.push('|');
        }
        regex_syntax::escape_into(m, &mut r);
        first = false;
    }
    r.push_str(")(?:\\([^)]*\\))?:");
    Regex::new(&r).unwrap()
}

fn codetag_find_regex(re: &Regex, s: &str, hide: bool) -> Option<Range<usize>> {
    let m = re.find(s)?;
    let from = if hide { m.end() } else { m.start() };
    let to = s.len();
    if from >= to { None } else { Some(from..to) }
}

fn default_codetag_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| codetag_regex(DEFAULT_MNEMONICS))
}

fn modeline_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:vim(?:[<=>]?\d+)?|vi|ex):[ \t]*(?:set[ \t]+[^:\r\n]+:|[A-Za-z][A-Za-z0-9_:.,/\t -]*=[A-Za-z0-9_=:.,/\t -]*)",
        )
        .unwrap()
    })
}

fn modeline_find_regex(s: &str) -> Option<Range<usize>> {
    let m = modeline_regex().find(s)?;
    let bytes = s.as_bytes();
    let (start, mut end) = (m.start(), m.end());
    while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    Some(start..end)
}

fn phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?:",
            r"\+[1-9]\d{0,2}[\s.\-]?(?:\(?\d{1,4}\)?[\s.\-]?){1,7}\d",
            r"|",
            r"\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}",
            r"|",
            r"\d{3}[\-\.]\d{3}[\-\.]\d{4}",
            r")",
        ))
        .unwrap()
    })
}

fn phone_validate(s: &str, start: usize, end: usize) -> Option<Range<usize>> {
    let input = s.as_bytes();
    let matched = &s[start..end];
    if start > 0 && input[start - 1].is_ascii_alphanumeric() {
        return None;
    }
    if end < input.len() && input[end].is_ascii_digit() {
        return None;
    }
    let digit_count = matched.bytes().filter(|b| b.is_ascii_digit()).count();
    if !(7..=15).contains(&digit_count) {
        return None;
    }
    let bytes = matched.as_bytes();
    if bytes[0] == b'+' {
        let first_group = bytes[1..].iter().take_while(|b| b.is_ascii_digit()).count();
        let has_separators = 1 + first_group < bytes.len();
        if has_separators && first_group > 3 {
            return None;
        }
    }
    Some(start..end)
}

fn phone_find_regex(s: &str) -> Option<Range<usize>> {
    let mut at = 0;
    while at < s.len() {
        let m = phone_regex().find_at(s, at)?;
        if let Some(range) = phone_validate(s, m.start(), m.end()) {
            return Some(range);
        }
        at = m.start() + 1;
    }
    None
}

/// Every match of a finder, the way the scanner-less API iterates.
fn find_all(finder: &dyn Finder, s: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut idx = 0;
    while idx < s.len() {
        match finder.find(&s[idx..]) {
            Some(r) => {
                out.push(idx + r.start..idx + r.end);
                idx += r.end;
            }
            None => break,
        }
    }
    out
}

fn find_all_with(mut f: impl FnMut(&str) -> Option<Range<usize>>, s: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut idx = 0;
    while idx < s.len() {
        match f(&s[idx..]) {
            Some(r) => {
                out.push(idx + r.start..idx + r.end);
                idx += r.end;
            }
            None => break,
        }
    }
    out
}

fn check_codetag(s: &str) {
    for hide in [false, true] {
        let mut finder = Codetag::default();
        finder.hide_mnemonic = hide;
        let expected = find_all_with(|t| codetag_find_regex(default_codetag_regex(), t, hide), s);
        assert_eq!(
            find_all(&finder, s),
            expected,
            "codetag (hide={hide}) on {s:?}"
        );
    }
}

fn check_modeline(s: &str) {
    let expected = find_all_with(modeline_find_regex, s);
    assert_eq!(
        find_all(&Modeline::default(), s),
        expected,
        "modeline on {s:?}"
    );
}

fn check_phone(s: &str) {
    let expected = find_all_with(phone_find_regex, s);
    assert_eq!(find_all(&Phone::default(), s), expected, "phone on {s:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn codetag_matches_the_former_regex(
        s in "( |:|\\(|\\)|_|-|é|😀|ß|K|[a-z]{1,3}|[0-9]{1,2}|TODO|todo|Todo|FIXME|fixme|XXX|\\?\\?\\?|!!!|BUG|BUGFIX|FIX|TBD|NOTE|note|REF|REFERENCE|STATUS|ſtatus|\\(john\\)|\\(#42|\\(\\)|:|::){0,12}"
    ) {
        check_codetag(&s);
    }

    #[test]
    fn codetag_matches_the_former_regex_on_arbitrary_input(s in "\\PC{0,30}") {
        check_codetag(&s);
    }

    #[test]
    fn modeline_matches_the_former_regex(
        s in "( |\t|:|=|,|/|\\.|_|-|é|x|vim|VIM|Vim|vi|ex|EX|vim700|vim<702|vim=703|vim>702|vim7x|set|SET|ts=4|sw=4|et|[a-z]{1,3}|[0-9]{1,3}|\r|foo=bar|:set ts=4 sw=4 et:|: set ts=4:){0,12}"
    ) {
        check_modeline(&s);
    }

    #[test]
    fn modeline_matches_the_former_regex_on_arbitrary_input(s in "\\PC{0,30}") {
        check_modeline(&s);
    }

    #[test]
    fn phone_matches_the_former_regex(
        s in "( |\\+|\\(|\\)|-|\\.|\u{a0}|\u{2003}|x|[0-9]{1,4}|[0-9]{3}-[0-9]{3}-[0-9]{4}|\\([0-9]{3}\\) [0-9]{3}-[0-9]{4}|\\+1 415 555 1234|\\+33 1 42 96 12 34|\\+2024-01-15|٣|３|١٢٣){0,14}"
    ) {
        check_phone(&s);
    }

    #[test]
    fn phone_matches_the_former_regex_on_arbitrary_input(s in "\\PC{0,30}") {
        check_phone(&s);
    }
}

#[test]
fn codetag_first_head_decides_like_the_former_regex() {
    // A hidden head that swallows the line yields nothing, even when a
    // later head sits inside its parenthesised note (found by the proptest
    // on one platform's seed).
    for s in [
        "TBD(TODO:():",
        "TBD(fixme:uinſtatusfixme():",
        "TODO(FIXME:):",
        "TODO: FIXME: x",
        "TODO:",
        "x TODO(a): FIXME(b): y",
    ] {
        check_codetag(s);
    }
}

#[test]
fn custom_mnemonics_match_the_former_regex() {
    let mnemonics = ["FIX-ME", "été", "OK", "???", "x"];
    let re = codetag_regex(
        &mnemonics
            .map(|m| m.to_uppercase())
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let mut finder = Codetag::default();
    for m in mnemonics {
        finder.add_mnemonic(m);
    }
    for s in [
        "fix-me: now",
        "FIX-ME(x): now",
        "été: soon",
        "ÉTÉ: soon",
        "xété: no",
        "ok: yes",
        "book: no",
        "x: single",
        "ax: no",
        "???: q",
        "a????: q",
        "OK(: no",
        "OK(): yes",
        "OK():",
    ] {
        let expected = find_all_with(|t| codetag_find_regex(&re, t, false), s);
        assert_eq!(find_all(&finder, s), expected, "custom codetag on {s:?}");
    }
}
