//! Vim modeline finder.
//!
//! Extracts vim modelines such as `vim: set ts=4 sw=4 et:`, `vi: ts=4 sw=4`,
//! or version-gated forms like `vim700:` / `vim<702:` / `vim=703:` /
//! `vim>702:`. Supports the `vim`, `vi`, and `ex` prefixes and both the bare
//! (first) and `set` (second) modeline forms. The bare form must contain at
//! least one `option=value` assignment so prose such as "I prefer vim: it is
//! great" is not misread as a modeline.

use super::{Finder, Memo};
use crate::word::boundary_before;
use std::ops::Range;

#[derive(Default)]
pub struct Modeline {}

// Forms:
//   vim: set ts=4 sw=4 et:   (second form: `set` + terminating colon)
//   vim: ts=4 sw=4           (first form: options to end of line)
//   vim:ts=4:sw=4
//   vim700: / vim<702: / vim=703: / vim>702: (version-gated prefixes)
//
// Constraints:
//   - no whitespace between the vi/vim/ex token and the `:` (vim
//     itself rejects `vim : ...`);
//   - the first form requires at least one `=` so plain prose after
//     `vim:` does not match; the second form is discriminating enough
//     through its `set ...:` structure;
//   - `[ \t]` instead of `\s` everywhere: finders are single-line by
//     contract, the match must never cross a newline.
//
// This is a hand-written equivalent of the former regex
// `(?i)\b(?:vim(?:[<=>]?\d+)?|vi|ex):[ \t]*(?:set[ \t]+[^:\r\n]+:|[A-Za-z][A-Za-z0-9_:.,/\t -]*=[A-Za-z0-9_=:.,/\t -]*)`.
impl Modeline {
    fn is_option_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b':' | b'.' | b',' | b'/' | b'\t' | b' ' | b'-')
    }

    fn eq_ci(input: &[u8], pos: usize, word: &[u8]) -> bool {
        input.len() >= pos + word.len() && input[pos..pos + word.len()].eq_ignore_ascii_case(word)
    }

    /// Position after the `:` that ends the `vim`/`vi`/`ex` token at `pos`.
    fn keyword_end(input: &[u8], pos: usize) -> Option<usize> {
        if Self::eq_ci(input, pos, b"vim") {
            let p = pos + 3;
            // Optional version: `[<=>]?\d+`, then the colon.
            let mut q = p;
            if matches!(input.get(q), Some(b'<' | b'=' | b'>')) {
                q += 1;
            }
            let digits_start = q;
            while input.get(q).is_some_and(u8::is_ascii_digit) {
                q += 1;
            }
            if q > digits_start && input.get(q) == Some(&b':') {
                return Some(q + 1);
            }
            return (input.get(p) == Some(&b':')).then_some(p + 1);
        }
        if Self::eq_ci(input, pos, b"vi") || Self::eq_ci(input, pos, b"ex") {
            return (input.get(pos + 2) == Some(&b':')).then_some(pos + 3);
        }
        None
    }

    /// End of the options after the colon: `set ...:` first, then
    /// `name=value...`.
    ///
    /// The `name=value` form scans the run of option bytes for its `=`. A
    /// run without one fails for every candidate inside it, so `memo`
    /// remembers the failed run and later candidates in it fail at once,
    /// which keeps a line with many `ex:` tokens linear.
    fn options_end(input: &[u8], after_colon: usize, memo: &mut Memo) -> Option<usize> {
        let mut q = after_colon;
        while matches!(input.get(q), Some(b' ' | b'\t')) {
            q += 1;
        }
        if Self::eq_ci(input, q, b"set") {
            let p = q + 3;
            let mut r = p;
            while matches!(input.get(r), Some(b' ' | b'\t')) {
                r += 1;
            }
            let spaces = r - p;
            if spaces >= 1 {
                while input
                    .get(r)
                    .is_some_and(|&b| !matches!(b, b':' | b'\r' | b'\n'))
                {
                    r += 1;
                }
                // `[ \t]+[^:\r\n]+`: at least one space and one more byte.
                if input.get(r) == Some(&b':') && r > p + 1 {
                    return Some(r + 1);
                }
            }
        }
        if input.get(q).is_some_and(u8::is_ascii_alphabetic) {
            if memo.covers(q) {
                // Inside a run already known to end without `=`.
                return None;
            }
            let mut r = q + 1;
            while input.get(r).is_some_and(|&b| Self::is_option_byte(b)) {
                r += 1;
            }
            if input.get(r) == Some(&b'=') {
                r += 1;
                while input
                    .get(r)
                    .is_some_and(|&b| Self::is_option_byte(b) || b == b'=')
                {
                    r += 1;
                }
                return Some(r);
            }
            *memo = Memo {
                start: q,
                end: r,
                aux: 0,
            };
        }
        None
    }

    fn match_at(input: &[u8], pos: usize, memo: &mut Memo) -> Option<Range<usize>> {
        if !boundary_before(input, pos) {
            return None;
        }
        let after_colon = Self::keyword_end(input, pos)?;
        let end = Self::options_end(input, after_colon, memo)?;
        Self::trim_range(input, pos, end)
    }

    fn trim_range(input: &[u8], start: usize, mut end: usize) -> Option<Range<usize>> {
        // Trim trailing whitespace.
        while end > start && matches!(input[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        Some(start..end)
    }
}

impl Finder for Modeline {
    fn id(&self) -> &'static str {
        "modeline"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        matches!(byte, b'v' | b'V' | b'e' | b'E')
    }

    fn could_start_after(&self, prev: u8, _cur: u8) -> bool {
        // `\b`: a non-ASCII previous byte is decoded by `try_at`.
        prev >= 0x80 || !(prev.is_ascii_alphanumeric() || prev == b'_')
    }

    fn could_continue_with(&self, cur: u8, next: u8) -> bool {
        match cur {
            b'v' | b'V' => matches!(next, b'i' | b'I'),
            _ => matches!(next, b'x' | b'X'),
        }
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        Self::match_at(input, pos, &mut Memo::default())
    }

    fn try_at_memo(&self, input: &[u8], pos: usize, memo: &mut Memo) -> Option<Range<usize>> {
        Self::match_at(input, pos, memo)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut memo = Memo::default();
        for pos in 0..input.len() {
            if self.could_start_at(input[pos])
                && let Some(range) = Self::match_at(input, pos, &mut memo)
            {
                return Some(range);
            }
        }
        None
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

    // --- Format variants ---

    #[test]
    fn find_vim_colon_separated_options() {
        let f = Modeline::default();
        let input = "/* vim:ts=4:sw=4:et: */";
        let r = f.find(input).unwrap();
        assert_eq!("vim:ts=4:sw=4:et:", &input[r]);
    }

    #[test]
    fn find_vim_no_space_after_colon() {
        let f = Modeline::default();
        let input = "// vim:ts=4 sw=4";
        let r = f.find(input).unwrap();
        assert_eq!("vim:ts=4 sw=4", &input[r]);
    }

    #[test]
    fn find_vim_uppercase_prefix() {
        let f = Modeline::default();
        let input = "// VIM: ts=4";
        let r = f.find(input).unwrap();
        assert_eq!("VIM: ts=4", &input[r]);
    }

    #[test]
    fn find_vim_with_filetype() {
        let f = Modeline::default();
        let input = "// vim: set ft=rust ts=4:";
        let r = f.find(input).unwrap();
        assert_eq!("vim: set ft=rust ts=4:", &input[r]);
    }

    // --- Boundaries ---

    #[test]
    fn find_at_start_of_input() {
        let f = Modeline::default();
        let input = "vim: ts=4";
        let r = f.find(input).unwrap();
        assert_eq!("vim: ts=4", &input[r]);
    }

    #[test]
    fn find_trailing_whitespace_trimmed() {
        let f = Modeline::default();
        let input = "vim: ts=4   ";
        let r = f.find(input).unwrap();
        assert_eq!("vim: ts=4", &input[r]);
    }

    // --- Negative cases ---

    #[test]
    fn find_rejects_random_colon_word() {
        let f = Modeline::default();
        assert!(f.find("https://example.com").is_none());
    }

    #[test]
    fn find_rejects_prefix_glued_to_alpha() {
        let f = Modeline::default();
        // 'devim:' — the `vim:` is preceded by 'e', so \b makes it not match
        assert!(f.find("devim:ts=4").is_none());
    }

    #[test]
    fn find_rejects_url_with_scheme_like_prefix() {
        let f = Modeline::default();
        assert!(f.find("see http: //example.com").is_none());
    }

    #[test]
    fn find_empty_input() {
        let f = Modeline::default();
        assert!(f.find("").is_none());
    }

    // --- In source comments ---

    #[test]
    fn find_inside_c_block_comment() {
        let f = Modeline::default();
        let input = "/* vim: set ts=4 et: */";
        let r = f.find(input).unwrap();
        assert!(input[r].starts_with("vim: set ts=4"));
    }

    #[test]
    fn find_inside_hash_comment() {
        let f = Modeline::default();
        let input = "# vim: ts=4 sw=4";
        let r = f.find(input).unwrap();
        assert_eq!("vim: ts=4 sw=4", &input[r]);
    }

    #[test]
    fn find_inside_html_comment() {
        let f = Modeline::default();
        let input = "<!-- vim: ts=2 -->";
        let r = f.find(input).unwrap();
        assert!(input[r].starts_with("vim: ts=2"));
    }

    // --- Multiple modelines (per-line basis) ---

    #[test]
    fn find_returns_first_modeline_when_multiple_in_same_input() {
        let f = Modeline::default();
        let input = "vim: ts=4 something vim: ts=2";
        let r = f.find(input).unwrap();
        // Both forms are matched; first wins.
        assert!(input[r].starts_with("vim: ts=4"));
    }

    // --- vi/ex variants ---

    #[test]
    fn find_vi_with_set_form() {
        let f = Modeline::default();
        let input = "// vi: set noet ts=4:";
        let r = f.find(input).unwrap();
        assert_eq!("vi: set noet ts=4:", &input[r]);
    }
}
