//! Social handle finder.
//!
//! Extracts `@username` style mentions used by Twitter, GitHub, Mastodon, etc.
//! Accepts handles of the form `@[A-Za-z0-9][A-Za-z0-9_-]{0,38}` and the
//! Mastodon-style `@user@host.tld`.

use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Handle {}

#[inline]
fn is_handle_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

impl Finder for Handle {
    fn id(&self) -> &'static str {
        "handle"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        byte == b'@'
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        if input.get(pos)? != &b'@' {
            return None;
        }
        // Must not be glued to a preceding alphanumeric (avoid email tails).
        if pos > 0 {
            let prev = input[pos - 1];
            if prev.is_ascii_alphanumeric() || prev == b'.' || prev == b'_' {
                return None;
            }
        }
        let start = pos;
        let name_start = pos + 1;
        if name_start >= input.len() || !input[name_start].is_ascii_alphanumeric() {
            return None;
        }
        let mut end = name_start + 1;
        while end < input.len() && is_handle_char(input[end]) {
            end += 1;
        }
        // Strip trailing hyphens.
        while end > name_start && input[end - 1] == b'-' {
            end -= 1;
        }
        let len = end - name_start;
        if !(1..=39).contains(&len) {
            return None;
        }

        // Optional Mastodon-style suffix: @host.tld
        if end < input.len() && input[end] == b'@' {
            let host_start = end + 1;
            let mut host_end = host_start;
            let mut had_dot = false;
            while host_end < input.len() {
                let b = input[host_end];
                if b.is_ascii_alphanumeric() || b == b'-' {
                    host_end += 1;
                } else if b == b'.' {
                    had_dot = true;
                    host_end += 1;
                } else {
                    break;
                }
            }
            // Strip trailing dots and hyphens.
            while host_end > host_start
                && (input[host_end - 1] == b'.' || input[host_end - 1] == b'-')
            {
                host_end -= 1;
            }
            if had_dot && host_end > host_start {
                end = host_end;
            }
        }

        Some(start..end)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut i = 0;
        while i < input.len() {
            if input[i] == b'@'
                && let Some(r) = self.try_at(input, i)
            {
                return Some(r);
            }
            i += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_handle() {
        assert_eq!("handle", Handle::default().id());
    }

    #[test]
    fn find_simple_handle() {
        let f = Handle::default();
        let input = "ping @alice please";
        let r = f.find(input).unwrap();
        assert_eq!("@alice", &input[r]);
    }

    #[test]
    fn find_github_style() {
        let f = Handle::default();
        let input = "cc @user-name on this";
        let r = f.find(input).unwrap();
        assert_eq!("@user-name", &input[r]);
    }

    #[test]
    fn find_mastodon_style() {
        let f = Handle::default();
        let input = "follow @alice@example.social to see";
        let r = f.find(input).unwrap();
        assert_eq!("@alice@example.social", &input[r]);
    }

    #[test]
    fn find_skips_email() {
        let f = Handle::default();
        assert!(f.find("user@example.com").is_none());
    }

    #[test]
    fn find_handle_at_start() {
        let f = Handle::default();
        let input = "@bob hi";
        let r = f.find(input).unwrap();
        assert_eq!("@bob", &input[r]);
    }

    #[test]
    fn find_rejects_lone_at() {
        let f = Handle::default();
        assert!(f.find("@ alone").is_none());
    }

    #[test]
    fn find_rejects_trailing_hyphen() {
        let f = Handle::default();
        let input = "@bob- here";
        let r = f.find(input).unwrap();
        assert_eq!("@bob", &input[r]);
    }

    #[test]
    fn find_returns_none_for_empty() {
        assert!(Handle::default().find("").is_none());
    }

    // --- Numbers + underscores ---

    #[test]
    fn find_handle_with_numbers() {
        let f = Handle::default();
        let input = "@user42 done";
        let r = f.find(input).unwrap();
        assert_eq!("@user42", &input[r]);
    }

    #[test]
    fn find_handle_with_underscore() {
        let f = Handle::default();
        let input = "ping @snake_case";
        let r = f.find(input).unwrap();
        assert_eq!("@snake_case", &input[r]);
    }

    #[test]
    fn find_handle_starting_with_digit() {
        let f = Handle::default();
        let input = "@42alice hi";
        let r = f.find(input).unwrap();
        assert_eq!("@42alice", &input[r]);
    }

    // --- Length limits ---

    #[test]
    fn find_handle_at_max_length() {
        let f = Handle::default();
        let name: String = std::iter::repeat('a').take(39).collect();
        let input = format!("hi @{} hi", name);
        let r = f.find(&input).unwrap();
        assert_eq!(format!("@{}", name), input[r]);
    }

    #[test]
    fn find_handle_over_max_length_truncates_to_max() {
        // Our impl accepts up to 39 chars; the 40th wouldn't pass `1..=39`.
        // If the entire run is 40 chars, we currently report None (full check).
        // This documents that strictness explicitly.
        let f = Handle::default();
        let name: String = std::iter::repeat('a').take(40).collect();
        let input = format!("@{}", name);
        assert!(f.find(&input).is_none());
    }

    // --- Boundary checks ---

    #[test]
    fn find_skips_handle_after_word_char() {
        let f = Handle::default();
        // No space before '@' but preceded by alphanumeric → email-like → skip
        assert!(f.find("abc@bob").is_none());
    }

    #[test]
    fn find_skips_handle_after_dot() {
        let f = Handle::default();
        // ".alice@bob" — prev byte before '@' is alphanumeric 'e'; skip
        assert!(f.find(".alice@bob").is_none());
    }

    #[test]
    fn find_handle_after_punctuation() {
        let f = Handle::default();
        let input = "[@alice]";
        let r = f.find(input).unwrap();
        assert_eq!("@alice", &input[r]);
    }

    #[test]
    fn find_handle_after_comma() {
        let f = Handle::default();
        let input = "cc, @bob";
        let r = f.find(input).unwrap();
        assert_eq!("@bob", &input[r]);
    }

    // --- Mastodon variations ---

    #[test]
    fn find_mastodon_with_subdomain() {
        let f = Handle::default();
        let input = "@user@mastodon.example.social";
        let r = f.find(input).unwrap();
        assert_eq!("@user@mastodon.example.social", &input[r]);
    }

    #[test]
    fn find_mastodon_without_dot_in_host_rejects_suffix() {
        let f = Handle::default();
        // host has no dot → falls back to bare handle
        let input = "@user@localhost";
        let r = f.find(input).unwrap();
        assert_eq!("@user", &input[r]);
    }

    #[test]
    fn find_mastodon_trailing_dot_excluded() {
        let f = Handle::default();
        let input = "@user@example.social.";
        let r = f.find(input).unwrap();
        assert_eq!("@user@example.social", &input[r]);
    }

    // --- Multiple handles ---

    #[test]
    fn find_multiple_handles_iteratively() {
        let f = Handle::default();
        let input = "@alice and @bob and @carol";
        let mut results = Vec::new();
        let mut idx = 0;
        while idx < input.len() {
            if let Some(r) = f.find(&input[idx..]) {
                results.push(input[idx + r.start..idx + r.end].to_string());
                idx += r.end;
            } else {
                break;
            }
        }
        assert_eq!(vec!["@alice", "@bob", "@carol"], results);
    }

    #[test]
    fn find_adjacent_handles() {
        let f = Handle::default();
        // "@a@b" — `@a` is bare, then `@b` follows but host has no '.', so first match is "@a"
        let input = "@a@b cool";
        let r = f.find(input).unwrap();
        assert_eq!("@a", &input[r]);
    }

    // --- Reject conditions ---

    #[test]
    fn find_rejects_handle_with_only_underscore() {
        let f = Handle::default();
        // first char must be alphanumeric (not '_')
        assert!(f.find("@_alice").is_none());
    }

    #[test]
    fn find_rejects_handle_with_only_hyphen() {
        let f = Handle::default();
        assert!(f.find("@-alice").is_none());
    }

    #[test]
    fn find_handle_in_email_address_skipped() {
        // The handle finder must not match the @ in "user@example.com"
        let f = Handle::default();
        let input = "send to user@example.com today";
        assert!(f.find(input).is_none());
    }

    #[test]
    fn find_handle_after_newline_break() {
        let f = Handle::default();
        let input = "hello\n@bob";
        let r = f.find(input).unwrap();
        assert_eq!("@bob", &input[r]);
    }

    #[test]
    fn find_handle_with_unicode_after() {
        // unicode follows handle; should still match handle correctly
        let f = Handle::default();
        let input = "@alice 🎉";
        let r = f.find(input).unwrap();
        assert_eq!("@alice", &input[r]);
    }
}
