//! Vim modeline finder.
//!
//! Extracts vim modelines such as `vim: set ts=4 sw=4 et:`, `vi: ts=4 sw=4`,
//! or version-gated forms like `vim700:` / `vim<702:` / `vim=703:` /
//! `vim>702:`. Supports the `vim`, `vi`, and `ex` prefixes and both the bare
//! (first) and `set` (second) modeline forms. The bare form must contain at
//! least one `option=value` assignment so prose such as "I prefer vim: it is
//! great" is not misread as a modeline.

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
        Regex::new(
            r"(?i)\b(?:vim(?:[<=>]?\d+)?|vi|ex):[ \t]*(?:set[ \t]+[^:\r\n]+:|[A-Za-z][A-Za-z0-9_:.,/\t -]*=[A-Za-z0-9_=:.,/\t -]*)",
        )
        .unwrap()
    })
}

// Modeline is a plain scan-mode finder: `find()` performs a single regex
// pass over the input. It intentionally does not implement `dispatchable` /
// `could_start_at` / `try_at` — the previous dispatch-mode implementation
// re-ran an unanchored regex search from every candidate byte, which was
// O(N²) on adversarial lines (a 100KB run of 'e' took seconds).
impl Finder for Modeline {
    fn id(&self) -> &'static str {
        "modeline"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let m = regex().find(s)?;
        Self::trim_range(s, m.start(), m.end())
    }
}

impl Modeline {
    fn trim_range(s: &str, start: usize, mut end: usize) -> Option<Range<usize>> {
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
