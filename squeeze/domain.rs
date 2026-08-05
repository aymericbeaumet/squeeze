//! Domain name finder.
//!
//! Extracts standalone DNS-style domain names (e.g. `example.com`,
//! `sub.example.co.uk`). Anything preceded by `@` or `://` is skipped
//! to avoid eating the host part of emails and URLs.

use super::Finder;
use std::ops::Range;

#[inline]
pub(crate) fn is_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

#[inline]
pub(crate) fn looks_like_tld(s: &[u8]) -> bool {
    (2..=24).contains(&s.len()) && s.iter().all(|b| b.is_ascii_alphabetic())
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

#[derive(Default)]
pub struct Domain {}

impl Finder for Domain {
    fn id(&self) -> &'static str {
        "domain"
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
            if i > 0 {
                let prev = input[i - 1];
                if prev == b'@'
                    || prev == b'/'
                    || prev == b':'
                    || prev.is_ascii_alphanumeric()
                    || prev == b'.'
                    || prev == b'-'
                    || prev == b'_'
                    || glued_to_two_byte_char(input, i)
                {
                    i += 1;
                    continue;
                }
            }

            // Walk through labels separated by '.'.
            let start = i;
            let mut end = i;
            let mut label_start = i;
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
                i = if end > i { end + 1 } else { i + 1 };
                continue;
            }

            // Disallow trailing characters that would make this part of a path/URL.
            if end < input.len() {
                let next = input[end];
                if next == b'/' || next == b':' {
                    i = end + 1;
                    continue;
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
                    i = probe + 1;
                    continue;
                }
            }

            // Validate final label as TLD.
            let tld = &input[last_dot + 1..end];
            if !looks_like_tld(tld) {
                i = end;
                continue;
            }

            // Reject all-numeric labels (avoid eating IPs).
            if input[start..end]
                .iter()
                .all(|b| b.is_ascii_digit() || *b == b'.')
            {
                i = end;
                continue;
            }

            return Some(start..end);
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
