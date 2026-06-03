//! Vim modeline finder.
//!
//! Extracts vim modelines such as `vim: set ts=4 sw=4 et:` or `vi: ts=4 sw=4`.
//! Supports the `vim`, `vi`, and `ex` prefixes and both the bare and `set` forms.

use super::Finder;
use regex::Regex;
use std::ops::Range;
use std::sync::OnceLock;

#[derive(Default)]
pub struct Modeline {}

fn regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Forms:
        //   vim: set ts=4 sw=4 et:
        //   vi: ts=4 sw=4
        //   ex: ts=4
        //   vim:ts=4:sw=4
        // Pattern captures everything between the prefix and either a closing
        // colon (for `set` form) or end-of-line / non-modeline char.
        Regex::new(r"(?i)\b(?:vim?|ex)\s*:\s*(?:set\s+[^:\r\n]+:|[A-Za-z][A-Za-z0-9_=:.,\-/ ]*)")
            .unwrap()
    })
}

impl Finder for Modeline {
    fn id(&self) -> &'static str {
        "modeline"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let m = regex().find(s)?;
        let start = m.start();
        let mut end = m.end();
        // Trim trailing whitespace.
        let bytes = s.as_bytes();
        while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        Some(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_modeline() {
        assert_eq!("modeline", Modeline::default().id());
    }

    #[test]
    fn find_vim_set_form() {
        let f = Modeline::default();
        let input = "// vim: set ts=4 sw=4 et:";
        let r = f.find(input).unwrap();
        assert_eq!("vim: set ts=4 sw=4 et:", &input[r]);
    }

    #[test]
    fn find_vim_bare_form() {
        let f = Modeline::default();
        let input = "// vim: ts=4 sw=4";
        let r = f.find(input).unwrap();
        assert_eq!("vim: ts=4 sw=4", &input[r]);
    }

    #[test]
    fn find_vi_prefix() {
        let f = Modeline::default();
        let input = "// vi: ts=2";
        let r = f.find(input).unwrap();
        assert_eq!("vi: ts=2", &input[r]);
    }

    #[test]
    fn find_ex_prefix() {
        let f = Modeline::default();
        let input = "/* ex: ts=8 */";
        let r = f.find(input).unwrap();
        assert!(input[r].starts_with("ex: ts=8"));
    }

    #[test]
    fn find_returns_none_for_plain_text() {
        let f = Modeline::default();
        assert!(f.find("hello world").is_none());
    }

    #[test]
    fn find_returns_none_for_only_prefix() {
        let f = Modeline::default();
        assert!(f.find("vim").is_none());
    }
}
