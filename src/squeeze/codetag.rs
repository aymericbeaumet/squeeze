use super::Finder;
use regex::Regex;
use std::ops::Range;

pub struct Codetag {
    mnemonics_regex: Regex,
    pub show_mnemonic: bool,
}

impl Codetag {
    pub fn new(mut mnemonics: Vec<&str>) -> Self {
        if mnemonics.is_empty() {
            mnemonics = vec![
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
            ];
        }
        let mut r = String::with_capacity(mnemonics.len() * 16);
        r.push_str("(?i)(?:");
        for (i, m) in mnemonics.iter().enumerate() {
            if i > 0 {
                r.push('|');
            }
            regex_syntax::escape_into(m, &mut r);
        }
        r.push_str(")(?:\\([^)]*\\))?:");
        Self {
            mnemonics_regex: Regex::new(&r).unwrap(),
            show_mnemonic: true,
        }
    }
}

impl Finder for Codetag {
    fn find(&self, s: &str) -> Option<Range<usize>> {
        let m = self.mnemonics_regex.find(s)?;
        let from = if self.show_mnemonic {
            m.start()
        } else {
            m.end()
        };
        let to = s.len();
        if from >= to {
            None
        } else {
            Some(from..to)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_find_at_start_of_line() {
        let finder = Codetag::new(vec![]);
        let input = "TODO: check if cmd is installed";
        assert_eq!(
            Some("TODO: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_at_middle_of_line() {
        let finder = Codetag::new(vec![]);
        let input = "foobar // TODO: check if cmd is installed";
        assert_eq!(
            Some("TODO: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_uppercase() {
        let finder = Codetag::new(vec![]);
        let input = "TODO: check if cmd is installed";
        assert_eq!(
            Some("TODO: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_lowercase() {
        let finder = Codetag::new(vec![]);
        let input = "todo: check if cmd is installed";
        assert_eq!(
            Some("todo: check if cmd is installed"),
            finder.find(input).map(|r| &input[r])
        );
    }

    #[test]
    fn it_should_find_mnemonics_with_empty_description() {
        let finder = Codetag::new(vec![]);
        let input = "todo:";
        assert_eq!(Some("todo:"), finder.find(input).map(|r| &input[r]));
    }

    #[test]
    fn it_should_hide_mnemonics_if_asked_to() {
        let mut finder = Codetag::new(vec![]);
        finder.show_mnemonic = false;
        let input = "todo: foobar";
        assert_eq!(Some(" foobar"), finder.find(input).map(|r| &input[r]));
    }

    #[test]
    fn it_should_limit_results_to_the_given_mnemonics() {
        let finder = Codetag::new(vec!["test"]);
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
        let finder = Codetag::new(vec![]);
        for input in vec!["", " "] {
            assert_eq!(None, finder.find(input));
        }
    }
}
