use super::Finder;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use std::ops::Range;

lazy_static! {
  static ref DEFAULT_MNEMONICS: HashSet<String> = {
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
    ].iter().map(|s| s.to_string()).collect()
  };
}

#[derive(Default)]
pub struct Codetag {
    pub hide_mnemonic: bool,
    mnemonics: HashSet<String>,
    mnemonics_regex: Option<Regex>,
}

impl Codetag {
    pub fn add_mnemonic(&mut self, mnemonic: &str) {
        self.mnemonics.insert(mnemonic.to_uppercase());
    }

    pub fn build_mnemonics_regex(&mut self) -> Result<(), regex::Error> {
        let mnemonics = if self.mnemonics.is_empty() {
            DEFAULT_MNEMONICS.iter()
        } else {
            self.mnemonics.iter()
        };
        let mut r = String::with_capacity(mnemonics.len() * 16);
        r.push_str("(?i)(?:");
        for (i, m) in mnemonics.enumerate() {
            if i > 0 {
                r.push('|');
            }
            regex_syntax::escape_into(m, &mut r);
        }
        r.push_str(")(?:\\([^)]*\\))?:");
        self.mnemonics_regex = Some(Regex::new(&r)?);
        Ok(())
    }
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

#[cfg(test)]
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
}
