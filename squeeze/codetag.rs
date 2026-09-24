//! Codetag finder implementation based on [PEP 350](https://www.python.org/dev/peps/pep-0350/).
//!
//! This module provides a [`Codetag`] finder that extracts codetags (TODO, FIXME, etc.)
//! from source code comments.
//!
//! # Example
//!
//! ```
//! use squeeze::{codetag::Codetag, Finder};
//!
//! let mut finder = Codetag::default();
//! finder.add_mnemonic("TODO");
//! finder.build_mnemonics_regex().unwrap();
//!
//! let text = "// TODO: implement this feature";
//! if let Some(range) = finder.find(text) {
//!     assert_eq!(&text[range], "TODO: implement this feature");
//! }
//! ```

use super::{ByteSet, Finder};
use crate::word::{boundary_after, boundary_before, char_at};
use std::collections::HashSet;
use std::convert::Infallible;
use std::ops::Range;
use std::sync::OnceLock;

fn default_mnemonics() -> &'static HashSet<String> {
    static DEFAULT_MNEMONICS: OnceLock<HashSet<String>> = OnceLock::new();
    DEFAULT_MNEMONICS.get_or_init(|| {
        [
            // todo
            "TODO",
            "MILESTONE",
            "MLSTN",
            "DONE",
            "YAGNI",
            "TBD",
            "TOBEDONE",
            // fixme
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
            // bug
            "BUG",
            "BUGFIX",
            // nobug
            "NOBUG",
            "NOFIX",
            "WONTFIX",
            "DONTFIX",
            "NEVERFIX",
            "UNFIXABLE",
            "CANTFIX",
            // req
            "REQ",
            "REQUIREMENT",
            "STORY",
            // rfe
            "RFE",
            "FEETCH",
            "NYI",
            "FR",
            "FTRQ",
            "FTR",
            // idea
            "IDEA",
            // ???
            "???",
            "QUESTION",
            "QUEST",
            "QSTN",
            "WTF",
            // !!!
            "!!!",
            "ALERT",
            // hack
            "HACK",
            "CLEVER",
            "MAGIC",
            // port
            "PORT",
            "PORTABILITY",
            "WKRD",
            // caveat
            "CAVEAT",
            "CAV",
            "CAVT",
            "WARNING",
            "CAUTION",
            // note
            "NOTE",
            "HELP",
            // faq
            "FAQ",
            // gloss
            "GLOSS",
            "GLOSSARY",
            // see
            "SEE",
            "REF",
            "REFERENCE",
            // todoc
            "TODOC",
            "DOCDO",
            "DODOC",
            "NEEDSDOC",
            "EXPLAIN",
            "DOCUMENT",
            // cred
            "CRED",
            "CREDIT",
            "THANKS",
            // stat
            "STAT",
            "STATUS",
            // rvd
            "RVD",
            "REVIEWED",
            "REVIEW",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    })
}

/// A mnemonic prepared for matching.
struct Mnemonic {
    /// Case-folded characters; the input is folded the same way while
    /// comparing.
    folded: Vec<char>,
    /// Alphanumeric mnemonics must sit on word boundaries (`\b`); others
    /// (`???`, `!!!`) match anywhere.
    word: bool,
}

/// Simple case folding as used by regex `(?i)`: one character maps to one
/// character. Only the Kelvin sign and the long s fold onto ASCII letters;
/// everything else folds through its single-character lowercase form.
fn fold(c: char) -> char {
    match c {
        '\u{212A}' => 'k',
        '\u{017F}' => 's',
        _ => {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(l), None) => l,
                _ => c,
            }
        }
    }
}

impl Mnemonic {
    /// End of the mnemonic when it matches at `pos`, case-insensitively.
    fn match_at(&self, input: &[u8], pos: usize) -> Option<usize> {
        let mut p = pos;
        for &want in &self.folded {
            let (c, width) = char_at(input, p)?;
            let same = if c.is_ascii() && want.is_ascii() {
                c.eq_ignore_ascii_case(&want)
            } else {
                fold(c) == want
            };
            if !same {
                return None;
            }
            p += width;
        }
        Some(p)
    }
}

/// Matching tables derived from the mnemonic set.
struct Index {
    mnemonics: Vec<Mnemonic>,
    /// Mnemonic ids by first byte, word mnemonics first.
    by_first: Vec<Vec<u16>>,
    /// Bytes that may follow a given start byte inside a match.
    next_after: Vec<ByteSet>,
    /// Start bytes of mnemonics matching anywhere (no `\b`).
    anywhere: ByteSet,
}

impl Index {
    fn build(mnemonics: impl Iterator<Item = String>) -> Index {
        let mut prepared: Vec<Mnemonic> = mnemonics
            .map(|m| Mnemonic {
                word: m.chars().all(|c| c.is_alphanumeric()),
                folded: m.chars().map(fold).collect(),
            })
            .collect();
        // Deterministic priority: word mnemonics first, then by text.
        prepared.sort_by(|a, b| b.word.cmp(&a.word).then_with(|| a.folded.cmp(&b.folded)));

        let mut by_first = vec![Vec::new(); 256];
        let mut next_after = vec![ByteSet::EMPTY; 256];
        let mut anywhere = ByteSet::EMPTY;
        for (id, m) in prepared.iter().enumerate() {
            let Some(&first) = m.folded.first() else {
                continue;
            };
            let second = m.folded.get(1).copied();
            for variant in case_variants(first) {
                let mut buf = [0u8; 4];
                let bytes = variant.encode_utf8(&mut buf).as_bytes();
                let lead = bytes[0];
                if !by_first[lead as usize].contains(&(id as u16)) {
                    by_first[lead as usize].push(id as u16);
                }
                if !m.word {
                    anywhere = anywhere.with(lead);
                }
                let mut next = next_after[lead as usize];
                if bytes.len() > 1 {
                    next = next.with(bytes[1]);
                } else {
                    match second {
                        Some(c) => {
                            for v in case_variants(c) {
                                let mut buf = [0u8; 4];
                                next = next.with(v.encode_utf8(&mut buf).as_bytes()[0]);
                            }
                        }
                        None => next = next.with(b'(').with(b':'),
                    }
                }
                next_after[lead as usize] = next;
            }
        }
        Index {
            mnemonics: prepared,
            by_first,
            next_after,
            anywhere,
        }
    }
}

/// Characters that fold to the same character as `c`: its case variants
/// plus the two non-ASCII letters that fold onto ASCII.
fn case_variants(c: char) -> Vec<char> {
    let mut variants = vec![c];
    let extra = match fold(c) {
        'k' => Some('\u{212A}'),
        's' => Some('\u{017F}'),
        _ => None,
    };
    for v in c.to_lowercase().chain(c.to_uppercase()).chain(extra) {
        if !variants.contains(&v) {
            variants.push(v);
        }
    }
    variants
}

/// A finder that extracts codetags (TODO, FIXME, etc.) from text.
///
/// Codetags are special comments in source code that mark areas needing attention.
/// This finder supports all mnemonics defined in PEP 350, plus common variants.
///
/// # Usage
///
/// 1. Create a default instance or configure with specific mnemonics
/// 2. Optionally call [`Codetag::build_mnemonics_regex`] to build the
///    matching tables eagerly ([`Finder::find`] builds them lazily otherwise)
/// 3. Use the [`Finder::find`] method to extract codetags
///
/// # Example
///
/// ```
/// use squeeze::{codetag::Codetag, Finder};
///
/// let mut finder = Codetag::default();
/// finder.build_mnemonics_regex().unwrap();
///
/// let text = "// FIXME(john): this is broken";
/// if let Some(range) = finder.find(text) {
///     println!("Found: {}", &text[range]);
/// }
/// ```
pub struct Codetag {
    /// When `true`, the mnemonic (e.g., "TODO:") is excluded from the result.
    pub hide_mnemonic: bool,
    mnemonics: HashSet<String>,
    index: OnceLock<Index>,
}

impl Default for Codetag {
    fn default() -> Self {
        Codetag {
            hide_mnemonic: false,
            mnemonics: HashSet::new(),
            index: OnceLock::new(),
        }
    }
}

impl Codetag {
    fn index(&self) -> &Index {
        self.index.get_or_init(|| self.build_index())
    }

    fn build_index(&self) -> Index {
        let mnemonics = if self.mnemonics.is_empty() {
            default_mnemonics().iter()
        } else {
            self.mnemonics.iter()
        };
        Index::build(mnemonics.cloned())
    }

    /// End of the whole codetag head (mnemonic, optional parenthesised
    /// note, colon) when one starts at `pos`, with the end of the mnemonic.
    fn match_at(&self, input: &[u8], pos: usize) -> Option<(usize, usize)> {
        let index = self.index();
        for &id in &index.by_first[input[pos] as usize] {
            let m = &index.mnemonics[id as usize];
            let Some(end) = m.match_at(input, pos) else {
                continue;
            };
            if m.word && !(boundary_before(input, pos) && boundary_after(input, end)) {
                continue;
            }
            let mut p = end;
            if input.get(p) == Some(&b'(') {
                match input[p + 1..].iter().position(|&b| b == b')') {
                    Some(close) => p = p + 1 + close + 1,
                    None => continue,
                }
            }
            if input.get(p) == Some(&b':') {
                return Some((end, p + 1));
            }
        }
        None
    }

    fn range_from(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        let (_, head_end) = self.match_at(input, pos)?;
        let from = if self.hide_mnemonic { head_end } else { pos };
        let to = input.len();
        if from >= to { None } else { Some(from..to) }
    }
}

impl Finder for Codetag {
    fn id(&self) -> &'static str {
        "codetag"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        !self.index().by_first[byte as usize].is_empty()
    }

    fn could_start_after(&self, prev: u8, cur: u8) -> bool {
        // Word mnemonics need `\b`; a non-ASCII previous byte is decoded
        // by `try_at`.
        self.index().anywhere.contains(cur)
            || prev >= 0x80
            || !(prev.is_ascii_alphanumeric() || prev == b'_')
    }

    fn could_continue_with(&self, cur: u8, next: u8) -> bool {
        self.index().next_after[cur as usize].contains(next)
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        self.range_from(input, pos)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        for pos in 0..input.len() {
            if self.could_start_at(input[pos])
                && let Some(range) = self.range_from(input, pos)
            {
                return Some(range);
            }
        }
        None
    }
}

impl Codetag {
    /// Adds a custom mnemonic to search for.
    ///
    /// When at least one mnemonic is added, only those mnemonics will be matched.
    /// If no mnemonics are added, all default PEP 350 mnemonics are used.
    ///
    /// Mnemonic matching is case-insensitive. Surrounding whitespace is
    /// trimmed; empty and whitespace-only mnemonics are ignored, as they
    /// would otherwise match every `word:`.
    pub fn add_mnemonic(&mut self, mnemonic: &str) {
        let mnemonic = mnemonic.trim();
        if mnemonic.is_empty() {
            return;
        }
        self.mnemonics.insert(mnemonic.to_uppercase());
        self.index = OnceLock::new();
    }

    /// Builds the matching tables for the configured mnemonics.
    ///
    /// Calling this is optional: [`Finder::find`] builds them lazily on
    /// first use. The name is kept from the regex-based implementation; it
    /// cannot fail.
    pub fn build_mnemonics_regex(&mut self) -> Result<(), Infallible> {
        let index = self.build_index();
        self.index = OnceLock::new();
        let _ = self.index.set(index);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::useless_vec)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn default_finder_is_ready_to_use() {
        let finder = Codetag::default();
        let input = "TODO: check if cmd is installed";
        assert_eq!(
            Some("TODO: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_at_start_of_line() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();
        let input = "TODO: check if cmd is installed";
        assert_eq!(
            Some("TODO: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_at_middle_of_line() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();
        let input = "foobar // TODO: check if cmd is installed";
        assert_eq!(
            Some("TODO: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_uppercase() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();
        let input = "TODO: check if cmd is installed";
        assert_eq!(
            Some("TODO: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_lowercase() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();
        let input = "todo: check if cmd is installed";
        assert_eq!(
            Some("todo: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_mnemonics_with_empty_description() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();
        let input = "todo:";
        assert_eq!(Some("todo:"), finder.find(input).map(|r| &input[r]));
    }

    #[test]
    fn it_should_hide_mnemonics_if_asked_to() {
        let mut finder = Codetag::default();
        finder.hide_mnemonic = true;
        finder.build_mnemonics_regex().unwrap();
        let input = "todo: foobar";
        assert_eq!(Some(" foobar"), finder.find(input).map(|r| &input[r]));
    }

    #[test]
    fn it_should_limit_results_to_the_given_mnemonics() {
        let mut finder = Codetag::default();
        finder.add_mnemonic("test");
        finder.build_mnemonics_regex().unwrap();
        let input = "test: check if cmd is installed";
        assert_eq!(
            Some("test: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
        let input = "test2: check if cmd is installed";
        assert_eq!(None, finder.find(input).map(|r| &input[r]));
    }

    #[test]
    fn it_should_ignore_invalid_inputs() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();
        for input in vec!["", " "] {
            assert_eq!(None, finder.find(input));
        }
    }

    #[test]
    fn it_should_find_codetags_with_fields() {
        // PEP 350 defines optional fields: TODO(author):
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let input = "TODO(john): implement feature";
        assert_eq!(
            Some("TODO(john): implement feature"),
            finder.find(input).map(|r| &input[r])
        );

        let input = "FIXME(#123): fix this bug";
        assert_eq!(
            Some("FIXME(#123): fix this bug"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_mixed_case_mnemonics() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        for input in vec!["Todo: task", "ToDo: task", "tOdO: task"] {
            assert!(finder.find(input).is_some(), "{}", input);
        }
    }

    #[test]
    fn it_should_not_match_partial_mnemonics() {
        let mut finder = Codetag::default();
        finder.add_mnemonic("TODO");
        finder.build_mnemonics_regex().unwrap();

        // Should not match TODOS or MYTODO
        assert_eq!(None, finder.find("TODOS: not a match"));
        assert_eq!(None, finder.find("MYTODO: not a match"));
    }

    #[test]
    fn it_should_handle_codetags_at_end_of_line() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let input = "code here // TODO:";
        assert_eq!(Some("TODO:"), finder.find(input).map(|r| &input[r]));
    }

    #[test]
    fn it_should_find_special_mnemonics() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        // Test ??? and !!! mnemonics
        let input = "// ???: what does this do?";
        assert_eq!(
            Some("???: what does this do?"),
            finder.find(input).map(|r| &input[r])
        );

        let input = "// !!!: urgent issue here";
        assert_eq!(
            Some("!!!: urgent issue here"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_codetags_after_various_delimiters() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        // After various comment styles
        for input in vec![
            "// TODO: c-style",
            "# TODO: shell-style",
            "/* TODO: block comment",
            "-- TODO: sql-style",
            "; TODO: lisp-style",
            "' TODO: vb-style",
        ] {
            assert!(finder.find(input).is_some(), "{}", input);
        }
    }

    // ============================================================================
    // Edge case tests
    // ============================================================================

    #[test]
    fn it_should_handle_empty_string() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();
        assert_eq!(None, finder.find(""));
    }

    #[test]
    fn it_should_handle_mnemonic_only_with_colon() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        // Just the mnemonic with colon, nothing after
        let input = "TODO:";
        assert_eq!(Some("TODO:"), finder.find(input).map(|r| &input[r]));
    }

    #[test]
    fn it_should_handle_whitespace_only_after_mnemonic() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        // Mnemonic with only whitespace after
        let input = "TODO:   ";
        let result = finder.find(input);
        assert!(result.is_some());
    }

    #[test]
    fn it_should_handle_nested_parentheses_in_field() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        // The field parser captures content up to first )
        // So nested parens break the field, but simple parens work
        let input = "TODO(author): description";
        assert!(finder.find(input).is_some());

        // Nested parentheses - the field regex [^)]* stops at first )
        // so TODO(a(b)): won't match as the field doesn't close properly
        let input2 = "TODO(a(b)): description";
        // This won't match because the regex expects TODO(...)colon pattern
        // but the nested ( breaks it - this documents the current behavior
        assert!(finder.find(input2).is_none());
    }

    #[test]
    fn it_should_handle_multiple_mnemonics_per_line() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        // Only finds the first one
        let input = "TODO: first FIXME: second";
        let result = finder.find(input).map(|r| &input[r]);
        assert!(result.is_some());
        // Should find TODO and include the rest of the line
        assert!(result.unwrap().starts_with("TODO:"));
    }

    #[test]
    fn it_should_handle_mnemonic_at_exact_start() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let input = "TODO: at start";
        let result = finder.find(input);
        assert!(result.is_some());
        assert_eq!(0, result.unwrap().start);
    }

    #[test]
    fn it_should_handle_mnemonic_at_exact_end() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let input = "comment TODO:";
        let result = finder.find(input);
        assert!(result.is_some());
        // Range should extend to end of string
        assert_eq!(input.len(), result.unwrap().end);
    }

    #[test]
    fn it_should_handle_very_long_description() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let long_desc = "a".repeat(10000);
        let input = format!("TODO: {}", long_desc);
        let result = finder.find(&input);
        assert!(result.is_some());
        assert_eq!(input.len(), result.unwrap().end);
    }

    #[test]
    fn it_should_handle_unicode_in_description() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let input = "TODO: 修复这个问题 🐛";
        let result = finder.find(input);
        assert!(result.is_some());
        assert_eq!(Some("TODO: 修复这个问题 🐛"), result.map(|r| &input[r]));
    }

    #[test]
    fn it_should_handle_all_default_mnemonics() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let mnemonics = vec![
            "TODO", "FIXME", "XXX", "HACK", "BUG", "NOTE", "WARNING", "REVIEW",
        ];

        for mnemonic in mnemonics {
            let input = format!("{}: description", mnemonic);
            assert!(
                finder.find(&input).is_some(),
                "Should find mnemonic: {}",
                mnemonic
            );
        }
    }

    #[test]
    fn it_should_handle_hide_mnemonic_with_no_content() {
        let mut finder = Codetag::default();
        finder.hide_mnemonic = true;
        finder.build_mnemonics_regex().unwrap();

        // When hiding mnemonic and there's nothing after, should return None
        let input = "TODO:";
        assert_eq!(None, finder.find(input));
    }

    #[test]
    fn it_should_handle_custom_mnemonic_case_insensitivity() {
        let mut finder = Codetag::default();
        finder.add_mnemonic("CUSTOM");
        finder.build_mnemonics_regex().unwrap();

        // Should match regardless of case
        assert!(finder.find("custom: test").is_some());
        assert!(finder.find("CUSTOM: test").is_some());
        assert!(finder.find("Custom: test").is_some());
        assert!(finder.find("cUsToM: test").is_some());
    }

    #[test]
    fn it_should_handle_multiple_custom_mnemonics() {
        let mut finder = Codetag::default();
        finder.add_mnemonic("AAA");
        finder.add_mnemonic("BBB");
        finder.add_mnemonic("CCC");
        finder.build_mnemonics_regex().unwrap();

        assert!(finder.find("AAA: test").is_some());
        assert!(finder.find("BBB: test").is_some());
        assert!(finder.find("CCC: test").is_some());
        assert!(finder.find("TODO: test").is_none()); // Not in custom list
    }

    #[test]
    fn it_should_handle_field_with_special_characters() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let inputs = vec![
            "TODO(@user): mention",
            "TODO(#123): issue number",
            "TODO(v1.2.3): version",
            "TODO(2024-01-01): date",
        ];

        for input in inputs {
            assert!(finder.find(input).is_some(), "{}", input);
        }
    }

    #[test]
    fn it_should_not_match_without_colon() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        // Mnemonic without colon should not match
        assert!(finder.find("TODO is not a codetag").is_none());
        assert!(finder.find("FIXME this").is_none());
    }

    #[test]
    fn it_should_handle_colon_inside_description() {
        let mut finder = Codetag::default();
        finder.build_mnemonics_regex().unwrap();

        let input = "TODO: time is 12:30:45";
        let result = finder.find(input);
        assert!(result.is_some());
        // Should capture the entire rest of the line including colons
        assert_eq!(Some("TODO: time is 12:30:45"), result.map(|r| &input[r]));
    }

    #[test]
    fn it_should_ignore_empty_and_whitespace_only_mnemonics() {
        // Reachable via CLI `--codetag=todo,` (trailing comma): an empty
        // mnemonic must not become an empty alternation branch that matches
        // every `word:`.
        let mut finder = Codetag::default();
        finder.add_mnemonic("");
        finder.add_mnemonic("   ");
        finder.add_mnemonic("\t");
        finder.build_mnemonics_regex().unwrap();
        assert_eq!(None, finder.find("hello: world"));
        // No effective custom mnemonics were added, so defaults stay active.
        assert!(finder.find("TODO: x").is_some());

        let mut finder = Codetag::default();
        finder.add_mnemonic("todo");
        finder.add_mnemonic("");
        finder.build_mnemonics_regex().unwrap();
        assert_eq!(None, finder.find("hello: world"));
        assert!(finder.find("todo: x").is_some());
        assert_eq!(None, finder.find("FIXME: z"));
    }
}
