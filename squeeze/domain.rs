//! Domain name finder.
//!
//! Extracts standalone DNS-style domain names (e.g. `example.com`,
//! `sub.example.co.uk`) whose TLD exists. Anything preceded by `@` or `://`
//! is skipped to avoid eating the host part of emails and URLs.
//!
//! The scanner triggers the finder at every `.` between an alphanumeric
//! byte and a letter; the finder walks back to the start of the token and
//! evaluates it exactly as [`Finder::find`] does, remembering a failed
//! token so its other dots cost nothing.

use super::{Finder, Memo};
use std::ops::Range;

#[inline]
pub(crate) fn is_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

#[inline]
pub(crate) fn looks_like_tld(s: &[u8]) -> bool {
    (2..=24).contains(&s.len()) && s.iter().all(|b| b.is_ascii_alphabetic())
}

/// A TLD-shaped label that is delegated in the root zone or reserved for
/// special use (RFC 6761, RFC 7686, RFC 9476, ICANN's `.internal`), so
/// `printer.local` matches while `out.write` does not.
fn is_known_tld(s: &[u8]) -> bool {
    if !looks_like_tld(s) {
        return false;
    }
    let mut buf = [0u8; 24];
    let lower = &mut buf[..s.len()];
    lower.copy_from_slice(s);
    lower.make_ascii_lowercase();
    let Ok(tld) = std::str::from_utf8(lower) else {
        return false;
    };
    crate::iana::TLDS.contains(tld)
        || matches!(
            tld,
            "alt" | "example" | "internal" | "invalid" | "local" | "localhost" | "onion" | "test"
        )
}

/// True when the byte immediately before `pos` ends a two-byte UTF-8
/// sequence (Latin-1 Supplement through Greek/Cyrillic and friends).
///
/// An identifier candidate glued to such a character is a truncation of a
/// word (`bücher.de` must not yield `cher.de`), so callers reject it.
/// Three- and four-byte sequences (CJK, emoji) are kept as legitimate
/// delimiters, matching the pinned behavior in tests/multibyte.rs.
#[inline]
pub(crate) fn glued_to_two_byte_char(input: &[u8], pos: usize) -> bool {
    pos >= 2 && input[pos - 1] & 0xC0 == 0x80 && input[pos - 2] & 0xE0 == 0xC0
}

/// Bytes that may make up an email local part, used to detect domain
/// candidates that are really the local part of an email address.
#[inline]
fn is_email_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

/// Whether `prev`, the byte before a token, makes the token part of a
/// larger one (an email local part, a URL path, a scheme).
#[inline]
fn continues_token(prev: u8) -> bool {
    prev == b'@'
        || prev == b'/'
        || prev == b':'
        || prev.is_ascii_alphanumeric()
        || prev == b'.'
        || prev == b'-'
        || prev == b'_'
}

/// Outcome of evaluating the token that starts at a candidate position.
enum Eval {
    /// A domain ends at this position.
    Match(usize),
    /// No domain; `find` resumes its search at this position.
    Skip(usize),
}

#[derive(Default)]
pub struct Domain {}

impl Domain {
    /// Evaluates the token starting at `start`, an alphanumeric byte that
    /// does not continue a previous token.
    fn evaluate(input: &[u8], start: usize) -> Eval {
        // Walk through labels separated by '.'.
        let mut end = start;
        let mut label_start = start;
        let mut dot_count = 0u32;
        let mut last_dot = 0usize;
        let mut valid = true;

        while end < input.len() {
            let b = input[end];
            if is_label_byte(b) {
                end += 1;
            } else if b == b'.' {
                // A dot not followed by a label byte (ellipsis, end of
                // sentence or token) ends the domain here instead of
                // invalidating the candidate.
                if end + 1 >= input.len() || !is_label_byte(input[end + 1]) {
                    break;
                }
                let label_len = end - label_start;
                if label_len == 0
                    || label_len > 63
                    || input[label_start] == b'-'
                    || input[end - 1] == b'-'
                {
                    valid = false;
                    break;
                }
                dot_count += 1;
                last_dot = end;
                label_start = end + 1;
                end += 1;
            } else {
                break;
            }
        }

        if !valid || dot_count == 0 || end <= last_dot + 1 {
            return Eval::Skip(if end > start { end + 1 } else { start + 1 });
        }

        // Disallow trailing characters that would make this part of a
        // path/URL or of code (`e.to_string()`, `source.map(f)`).
        if end < input.len() {
            let next = input[end];
            if matches!(next, b'/' | b':' | b'_' | b'(') {
                return Eval::Skip(end + 1);
            }
            // If the token continues as an email local part that ends at
            // '@', this candidate sits inside an email address (e.g. the
            // `first.last` of `first.last+tag@company.co.uk`): suppress
            // it and skip past the token.
            let mut probe = end;
            while probe < input.len() && is_email_local_byte(input[probe]) {
                probe += 1;
            }
            if probe < input.len() && input[probe] == b'@' {
                return Eval::Skip(probe + 1);
            }
        }

        // Validate final label as TLD.
        let tld = &input[last_dot + 1..end];
        if !is_known_tld(tld) {
            return Eval::Skip(end);
        }

        // Reject all-numeric labels (avoid eating IPs).
        if input[start..end]
            .iter()
            .all(|b| b.is_ascii_digit() || *b == b'.')
        {
            return Eval::Skip(end);
        }

        Eval::Match(end)
    }

    /// The domain, if any, whose last dot (the one before the TLD) or an
    /// inner dot is at `pos`: walks back over the token the dot belongs to
    /// and evaluates it from its start, exactly as [`Finder::find`] would
    /// have when reaching that start.
    fn from_dot(input: &[u8], pos: usize, memo: &mut Memo) -> Option<Range<usize>> {
        if input[pos] != b'.' {
            return None;
        }
        // The label before the dot ends with an alphanumeric byte and the
        // TLD (or the next label) starts with one; a dot elsewhere cannot be
        // the last dot of a domain.
        if pos == 0
            || !input[pos - 1].is_ascii_alphanumeric()
            || pos + 1 >= input.len()
            || !input[pos + 1].is_ascii_alphabetic()
        {
            return None;
        }
        if memo.covers(pos) {
            return None;
        }
        // Every dot of a token walks back to the same start, so a token
        // that fails once fails for all its dots.
        let mut start = pos;
        while start > 0 && (is_label_byte(input[start - 1]) || input[start - 1] == b'.') {
            start -= 1;
        }
        let mut run_end = pos + 1;
        while run_end < input.len() && (is_label_byte(input[run_end]) || input[run_end] == b'.') {
            run_end += 1;
        }
        let ok = input[start].is_ascii_alphanumeric()
            && (start == 0
                || (!continues_token(input[start - 1]) && !glued_to_two_byte_char(input, start)));
        if ok && let Eval::Match(end) = Self::evaluate(input, start) {
            return Some(start..end);
        }
        memo.start = start;
        memo.end = run_end;
        None
    }
}

impl Finder for Domain {
    fn id(&self) -> &'static str {
        "domain"
    }

    fn triggerable(&self) -> bool {
        true
    }

    fn line_agnostic(&self) -> bool {
        // Tokens consist of label bytes and dots; every walk stops at a
        // line terminator like at the end of the input.
        true
    }

    fn could_trigger_at(&self, byte: u8) -> bool {
        byte == b'.'
    }

    fn could_start_after(&self, prev: u8, _cur: u8) -> bool {
        prev.is_ascii_alphanumeric()
    }

    fn could_continue_with(&self, _cur: u8, next: u8) -> bool {
        next.is_ascii_alphabetic()
    }

    fn try_trigger_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        Self::from_dot(input, pos, &mut Memo::default())
    }

    fn try_trigger_at_memo(
        &self,
        input: &[u8],
        pos: usize,
        memo: &mut Memo,
    ) -> Option<Range<usize>> {
        Self::from_dot(input, pos, memo)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut i = 0;

        while i < input.len() {
            // Find the start of a candidate label.
            if !input[i].is_ascii_alphanumeric() {
                i += 1;
                continue;
            }

            // Skip if the previous byte makes this part of a larger token
            // (e.g. email local part, url path, scheme).
            if i > 0 && (continues_token(input[i - 1]) || glued_to_two_byte_char(input, i)) {
                i += 1;
                continue;
            }

            match Self::evaluate(input, i) {
                Eval::Match(end) => return Some(i..end),
                Eval::Skip(next) => i = next,
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_domain() {
        assert_eq!("domain", Domain::default().id());
    }

    #[test]
    fn find_simple_domain() {
        let f = Domain::default();
        let input = "visit example.com today";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    #[test]
    fn find_subdomain() {
        let f = Domain::default();
        let input = "see mail.example.co.uk for details";
        let r = f.find(input).unwrap();
        assert_eq!("mail.example.co.uk", &input[r]);
    }

    #[test]
    fn find_skips_email() {
        let f = Domain::default();
        assert!(f.find("user@example.com").is_none());
    }

    #[test]
    fn find_skips_inside_url() {
        let f = Domain::default();
        assert!(f.find("https://example.com").is_none());
    }

    #[test]
    fn find_rejects_no_dot() {
        let f = Domain::default();
        assert!(f.find("localhost").is_none());
    }

    #[test]
    fn find_rejects_ip() {
        let f = Domain::default();
        assert!(f.find("192.168.1.1").is_none());
    }

    #[test]
    fn find_strips_trailing_dot() {
        let f = Domain::default();
        let input = "example.com.";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    #[test]
    fn find_hyphenated_domain() {
        let f = Domain::default();
        let input = "go to my-site.example.com okay";
        let r = f.find(input).unwrap();
        assert_eq!("my-site.example.com", &input[r]);
    }

    #[test]
    fn find_rejects_label_starting_with_hyphen() {
        let f = Domain::default();
        assert!(f.find("-bad.example.com").is_none());
    }

    #[test]
    fn find_handles_empty() {
        assert!(Domain::default().find("").is_none());
    }

    // --- Positions ---

    #[test]
    fn find_domain_at_start() {
        let f = Domain::default();
        let input = "example.com is great";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    #[test]
    fn find_domain_at_end() {
        let f = Domain::default();
        let input = "see example.com";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    #[test]
    fn find_domain_inside_parens() {
        let f = Domain::default();
        let input = "(example.com)";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    #[test]
    fn find_domain_in_markdown_link() {
        let f = Domain::default();
        let input = "[link](example.com)";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    #[test]
    fn find_domain_followed_by_comma() {
        let f = Domain::default();
        let input = "example.com, foo";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    #[test]
    fn find_domain_followed_by_period_end_of_sentence() {
        let f = Domain::default();
        let input = "go to example.com.";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    #[test]
    fn find_domain_followed_by_question_mark() {
        let f = Domain::default();
        let input = "is it example.com?";
        let r = f.find(input).unwrap();
        assert_eq!("example.com", &input[r]);
    }

    // --- Case sensitivity ---

    #[test]
    fn find_uppercase_domain() {
        let f = Domain::default();
        let input = "go to EXAMPLE.COM today";
        let r = f.find(input).unwrap();
        assert_eq!("EXAMPLE.COM", &input[r]);
    }

    #[test]
    fn find_mixed_case_domain() {
        let f = Domain::default();
        let input = "see Example.Com";
        let r = f.find(input).unwrap();
        assert_eq!("Example.Com", &input[r]);
    }

    // --- Labels ---

    #[test]
    fn find_long_subdomain_chain() {
        let f = Domain::default();
        let input = "a.b.c.d.e.example.com";
        let r = f.find(input).unwrap();
        assert_eq!("a.b.c.d.e.example.com", &input[r]);
    }

    #[test]
    fn find_domain_with_numeric_subdomain() {
        let f = Domain::default();
        let input = "v2.example.com";
        let r = f.find(input).unwrap();
        assert_eq!("v2.example.com", &input[r]);
    }

    #[test]
    fn find_rejects_label_ending_with_hyphen() {
        let f = Domain::default();
        assert!(f.find("bad-.example.com").is_none());
    }

    #[test]
    fn find_rejects_consecutive_dots() {
        let f = Domain::default();
        assert!(f.find("foo..bar.com").is_none());
    }

    #[test]
    fn find_rejects_tld_too_short() {
        let f = Domain::default();
        assert!(f.find("foo.x").is_none());
    }

    #[test]
    fn find_rejects_numeric_tld() {
        let f = Domain::default();
        assert!(f.find("foo.123").is_none());
    }

    // --- Multiple ---

    #[test]
    fn find_multiple_domains_iteratively() {
        let f = Domain::default();
        let input = "example.com and other.org";
        let mut results = Vec::new();
        let mut idx = 0;
        while idx < input.len() {
            if let Some(r) = f.find(&input[idx..]) {
                results.push(&input[idx + r.start..idx + r.end]);
                idx += r.end;
            } else {
                break;
            }
        }
        assert_eq!(vec!["example.com", "other.org"], results);
    }

    // --- Avoid eating other tokens ---

    #[test]
    fn find_skips_inside_path() {
        let f = Domain::default();
        // Looks like a domain but is inside a path; we want to skip.
        assert!(f.find("/usr/example.com/files").is_none());
    }

    #[test]
    fn find_skips_ipv6_like() {
        let f = Domain::default();
        assert!(f.find("2001:db8::1").is_none());
    }

    #[test]
    fn find_skips_when_followed_by_at() {
        // domain immediately followed by '@' might be confusable with email tail
        let f = Domain::default();
        assert!(f.find("foo.com@bar").is_none());
    }

    #[test]
    fn find_skips_when_followed_by_path() {
        let f = Domain::default();
        // domain.com/ would be the start of a URL — skip
        assert!(f.find("example.com/path").is_none());
    }

    #[test]
    fn find_skips_when_followed_by_port() {
        let f = Domain::default();
        // domain:8080 is more URL-like
        assert!(f.find("example.com:8080").is_none());
    }

    // --- TLDs ---

    #[test]
    fn find_long_alpha_tld() {
        let f = Domain::default();
        let input = "example.museum";
        let r = f.find(input).unwrap();
        assert_eq!("example.museum", &input[r]);
    }

    #[test]
    fn find_two_letter_country_tld() {
        let f = Domain::default();
        let input = "see example.uk";
        let r = f.find(input).unwrap();
        assert_eq!("example.uk", &input[r]);
    }

    // --- Boundary characters ---

    #[test]
    fn find_matches_full_token_not_inner() {
        let f = Domain::default();
        // "abcdexample.com" is itself a valid domain, so the full token matches.
        // The inner "example.com" must not be reported separately at offset 4.
        let input = "abcdexample.com";
        let r = f.find(input).unwrap();
        assert_eq!(0..input.len(), r);
    }

    #[test]
    fn find_skips_glued_to_underscore_prefix() {
        let f = Domain::default();
        assert!(f.find("_example.com").is_none());
    }

    #[test]
    fn find_skips_in_dotted_chain_preceded_by_dot() {
        let f = Domain::default();
        // prev '.' should disqualify start (avoid mid-chain re-matches)
        assert!(f.find(".example.com").is_none());
    }
}
