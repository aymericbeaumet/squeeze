// https://www.python.org/dev/peps/pep-0350/

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

#[derive(Default)]
pub struct Codetag {
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
    pub fn add_mnemonic(&mut self, mnemonic: &str) {
        self.mnemonics.insert(mnemonic.to_uppercase());
    }

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
}
