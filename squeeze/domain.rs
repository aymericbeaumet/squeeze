//! Domain name finder.
//!
//! Extracts standalone DNS-style domain names (e.g. `example.com`,
//! `sub.example.co.uk`). Anything preceded by `@` or `://` is skipped
//! to avoid eating the host part of emails and URLs.

use super::Finder;
use std::ops::Range;

/// Common TLDs we accept without further validation. Anything else must look
/// alphabetic and be between 2 and 24 chars to be considered a TLD.
static COMMON_TLDS: phf::Set<&'static str> = phf::phf_set! {
    "com", "net", "org", "io", "dev", "app", "co", "uk", "us", "ca", "de",
    "fr", "jp", "cn", "ru", "br", "au", "in", "mx", "es", "it", "nl", "se",
    "no", "fi", "pl", "ch", "at", "be", "dk", "ie", "nz", "za", "ai", "ly",
    "me", "tv", "info", "biz", "name", "pro", "museum", "tech", "xyz",
    "online", "site", "store", "edu", "gov", "mil", "int",
};

#[inline]
fn is_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

#[inline]
fn looks_like_tld(s: &[u8]) -> bool {
    if s.len() < 2 || s.len() > 24 {
        return false;
    }
    if !s.iter().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    // Accept any all-alpha label of reasonable length, OR a common TLD.
    // The all-alpha-only constraint already filters out IPs and most noise.
    if s.len() >= 2 {
        return true;
    }
    let lowered: String = s.iter().map(|b| b.to_ascii_lowercase() as char).collect();
    COMMON_TLDS.contains(lowered.as_str())
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

            // Strip trailing dot.
            if end > start && input[end - 1] == b'.' {
                if dot_count > 0 && last_dot == end - 1 {
                    dot_count -= 1;
                    last_dot = input[start..end - 1]
                        .iter()
                        .rposition(|&b| b == b'.')
                        .map(|p| start + p)
                        .unwrap_or(0);
                }
                end -= 1;
            }

            if !valid || dot_count == 0 || end <= last_dot + 1 {
                i = if end > i { end + 1 } else { i + 1 };
                continue;
            }

            // Disallow trailing characters that would make this part of a path/email.
            if end < input.len() {
                let next = input[end];
                if next == b'@' || next == b'/' || next == b':' {
                    i = end + 1;
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
}
