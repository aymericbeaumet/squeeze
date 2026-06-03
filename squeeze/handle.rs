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
            if had_dot && host_end > host_start && input[host_end - 1] != b'.' {
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
}
