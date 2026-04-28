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

use super::Finder;
use regex::Regex;
use std::collections::HashSet;
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

/// A finder that extracts codetags (TODO, FIXME, etc.) from text.
///
/// Codetags are special comments in source code that mark areas needing attention.
/// This finder supports all mnemonics defined in PEP 350, plus common variants.
///
/// # Usage
///
/// 1. Create a default instance or configure with specific mnemonics
/// 2. Call [`Codetag::build_mnemonics_regex`] before using
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
#[derive(Default)]
pub struct Codetag {
    /// When `true`, the mnemonic (e.g., "TODO:") is excluded from the result.
    pub hide_mnemonic: bool,
    mnemonics: HashSet<String>,
    mnemonics_regex: Option<Regex>,
}

impl Finder for Codetag {
    fn id(&self) -> &'static str {
        "codetag"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let m = self
            .mnemonics_regex
            .as_ref()
            .expect(
                "implementation error: please call .build_mnemonics_regex() on the codetag instance",
            )
            .find(s)?;
        let from = if self.hide_mnemonic {
            m.end()
        } else {
            m.start()
        };
        let to = s.len();
        if from >= to {
            None
        } else {
            Some(from..to)
        }
    }
}

impl Codetag {
    /// Adds a custom mnemonic to search for.
    ///
    /// When at least one mnemonic is added, only those mnemonics will be matched.
    /// If no mnemonics are added, all default PEP 350 mnemonics are used.
    ///
    /// Mnemonic matching is case-insensitive.
    pub fn add_mnemonic(&mut self, mnemonic: &str) {
        self.mnemonics.insert(mnemonic.to_uppercase());
    }

    /// Builds the internal regex for matching mnemonics.
    ///
    /// **This must be called before using the finder.** Calling [`Finder::find`]
    /// without building the regex will panic.
    ///
    /// # Errors
    ///
    /// Returns an error if the regex compilation fails (should not happen with
    /// valid mnemonics).
    pub fn build_mnemonics_regex(&mut self) -> Result<(), regex::Error> {
        let mnemonics = if self.mnemonics.is_empty() {
            default_mnemonics().iter()
        } else {
            self.mnemonics.iter()
        };
        let mut r = String::with_capacity(mnemonics.len() * 16);
        // Use \b word boundary for alphanumeric mnemonics to prevent MYTODO matching TODO
        // Special mnemonics like ??? and !!! are handled separately
        r.push_str("(?i)(?:");

        let mut alpha_mnemonics = Vec::new();
        let mut special_mnemonics = Vec::new();

        for m in mnemonics {
            if m.chars().all(|c| c.is_alphanumeric()) {
                alpha_mnemonics.push(m.clone());
            } else {
                special_mnemonics.push(m.clone());
            }
        }

        let mut first = true;
        if !alpha_mnemonics.is_empty() {
            r.push_str("\\b(?:");
            for (i, m) in alpha_mnemonics.iter().enumerate() {
                if i > 0 {
                    r.push('|');
                }
                regex_syntax::escape_into(m, &mut r);
            }
            r.push_str(")\\b");
            first = false;
        }

        for m in special_mnemonics.iter() {
            if !first {
                r.push('|');
            }
            regex_syntax::escape_into(m, &mut r);
            first = false;
        }

        r.push_str(")(?:\\([^)]*\\))?:");
        self.mnemonics_regex = Some(Regex::new(&r)?);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::useless_vec)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

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
}
