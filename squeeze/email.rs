use super::Finder;
use memchr::memchr;
use std::ops::Range;

const LOCAL_CHARS: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0u16;
    while i < 256 {
        let b = i as u8;
        table[i as usize] = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'/'
                    | b'='
                    | b'?'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
                    | b'-'
            );
        i += 1;
    }
    table
};

#[derive(Default)]
pub struct Email {}

impl Finder for Email {
    fn id(&self) -> &'static str {
        "email"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            let at_pos = idx + memchr(b'@', &input[idx..])?;

            let mut local_start = at_pos;
            while local_start > idx && LOCAL_CHARS[input[local_start - 1] as usize] {
                local_start -= 1;
            }

            // Local part must be non-empty and not start/end with '.'
            if local_start == at_pos || input[local_start] == b'.' || input[at_pos - 1] == b'.' {
                idx = at_pos + 1;
                continue;
            }

            // Walk forwards for domain, validating in a single pass
            let domain_start = at_pos + 1;
            let mut domain_end = domain_start;
            let mut dot_count = 0u32;
            let mut last_dot = 0usize;
            let mut label_start = domain_start;
            let mut label_valid = true;

            while domain_end < input.len() {
                let b = input[domain_end];
                if b == b'.' {
                    let label_len = domain_end - label_start;
                    if label_len == 0 || input[label_start] == b'-' || input[domain_end - 1] == b'-'
                    {
                        label_valid = false;
                        break;
                    }
                    dot_count += 1;
                    last_dot = domain_end;
                    label_start = domain_end + 1;
                    domain_end += 1;
                } else if b.is_ascii_alphanumeric() || b == b'-' {
                    domain_end += 1;
                } else {
                    break;
                }
            }

            if domain_end == domain_start || !label_valid {
                idx = at_pos + 1;
                continue;
            }

            // Strip trailing dots/hyphens
            while domain_end > domain_start && matches!(input[domain_end - 1], b'.' | b'-') {
                if input[domain_end - 1] == b'.' && domain_end - 1 == last_dot {
                    dot_count -= 1;
                    if dot_count > 0 {
                        // Recalculate last_dot
                        last_dot = input[domain_start..domain_end - 1]
                            .iter()
                            .rposition(|&b| b == b'.')
                            .map(|p| domain_start + p)
                            .unwrap_or(0);
                    }
                }
                domain_end -= 1;
            }

            if dot_count == 0 {
                idx = at_pos + 1;
                continue;
            }

            // Validate final label (after last strip)
            let final_label_start = if last_dot >= domain_start {
                last_dot + 1
            } else {
                domain_start
            };
            let final_label_len = domain_end - final_label_start;
            if final_label_len == 0
                || input[final_label_start] == b'-'
                || input[domain_end - 1] == b'-'
            {
                idx = at_pos + 1;
                continue;
            }

            // TLD must be >= 2 chars and all alpha
            let tld = &input[last_dot + 1..domain_end];
            if tld.len() < 2 || !tld.iter().all(|b| b.is_ascii_alphabetic()) {
                idx = at_pos + 1;
                continue;
            }

            return Some(local_start..domain_end);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_email() {
        let finder = Email::default();
        assert_eq!("email", finder.id());
    }

    #[test]
    fn find_should_extract_simple_email() {
        let finder = Email::default();
        let input = "contact user@example.com for info";
        let range = finder.find(input).unwrap();
        assert_eq!("user@example.com", &input[range]);
    }

    #[test]
    fn find_should_extract_email_at_start() {
        let finder = Email::default();
        let input = "alice@example.org is here";
        let range = finder.find(input).unwrap();
        assert_eq!("alice@example.org", &input[range]);
    }

    #[test]
    fn find_should_extract_email_at_end() {
        let finder = Email::default();
        let input = "send to bob@test.co";
        let range = finder.find(input).unwrap();
        assert_eq!("bob@test.co", &input[range]);
    }

    #[test]
    fn find_should_handle_plus_addressing() {
        let finder = Email::default();
        let input = "user+tag@example.com";
        let range = finder.find(input).unwrap();
        assert_eq!("user+tag@example.com", &input[range]);
    }

    #[test]
    fn find_should_handle_dots_in_local_part() {
        let finder = Email::default();
        let input = "first.last@example.com";
        let range = finder.find(input).unwrap();
        assert_eq!("first.last@example.com", &input[range]);
    }

    #[test]
    fn find_should_handle_subdomain() {
        let finder = Email::default();
        let input = "user@mail.example.co.uk";
        let range = finder.find(input).unwrap();
        assert_eq!("user@mail.example.co.uk", &input[range]);
    }

    #[test]
    fn find_should_handle_hyphenated_domain() {
        let finder = Email::default();
        let input = "user@my-company.example.com";
        let range = finder.find(input).unwrap();
        assert_eq!("user@my-company.example.com", &input[range]);
    }

    #[test]
    fn find_should_reject_no_at_sign() {
        let finder = Email::default();
        assert!(finder.find("not an email").is_none());
    }

    #[test]
    fn find_should_reject_no_domain_dot() {
        let finder = Email::default();
        assert!(finder.find("user@localhost").is_none());
    }

    #[test]
    fn find_should_reject_empty_local_part() {
        let finder = Email::default();
        assert!(finder.find("@example.com").is_none());
    }

    #[test]
    fn find_should_reject_dot_start_local() {
        let finder = Email::default();
        assert!(finder.find(".user@example.com").is_none());
    }

    #[test]
    fn find_should_reject_dot_end_local() {
        let finder = Email::default();
        assert!(finder.find("user.@example.com").is_none());
    }

    #[test]
    fn find_should_reject_single_char_tld() {
        let finder = Email::default();
        assert!(finder.find("user@example.x").is_none());
    }

    #[test]
    fn find_should_reject_numeric_tld() {
        let finder = Email::default();
        assert!(finder.find("user@example.123").is_none());
    }

    #[test]
    fn find_should_reject_domain_starting_with_hyphen() {
        let finder = Email::default();
        assert!(finder.find("user@-example.com").is_none());
    }

    #[test]
    fn find_should_reject_domain_ending_with_hyphen() {
        let finder = Email::default();
        assert!(finder.find("user@example-.com").is_none());
    }

    #[test]
    fn find_should_extract_email_from_angle_brackets() {
        let finder = Email::default();
        let input = "Author <author@example.com>";
        let range = finder.find(input).unwrap();
        assert_eq!("author@example.com", &input[range]);
    }

    #[test]
    fn find_should_extract_multiple_emails_iteratively() {
        let finder = Email::default();
        let input = "cc: alice@one.com and bob@two.org";

        let mut results = Vec::new();
        let mut idx = 0;
        while idx < input.len() {
            if let Some(range) = finder.find(&input[idx..]) {
                results.push(&input[idx + range.start..idx + range.end]);
                idx += range.end;
            } else {
                break;
            }
        }

        assert_eq!(vec!["alice@one.com", "bob@two.org"], results);
    }

    #[test]
    fn find_should_extract_email_in_parentheses() {
        let finder = Email::default();
        let input = "(support@example.com)";
        let range = finder.find(input).unwrap();
        assert_eq!("support@example.com", &input[range]);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Email::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_handle_bare_at() {
        let finder = Email::default();
        assert!(finder.find("@").is_none());
    }

    #[test]
    fn find_should_skip_invalid_and_find_valid() {
        let finder = Email::default();
        let input = "@invalid then real@example.com";
        let range = finder.find(input).unwrap();
        assert_eq!("real@example.com", &input[range]);
    }

    // --- Regression: single-pass domain validation ---

    #[test]
    fn find_should_handle_domain_with_many_labels() {
        let finder = Email::default();
        let input = "user@a.b.c.d.example.com";
        let range = finder.find(input).unwrap();
        assert_eq!("user@a.b.c.d.example.com", &input[range]);
    }

    #[test]
    fn find_should_reject_consecutive_dots_in_domain() {
        let finder = Email::default();
        assert!(finder.find("user@example..com").is_none());
    }

    #[test]
    fn find_should_strip_trailing_dot_from_domain() {
        let finder = Email::default();
        let input = "user@example.com.";
        let range = finder.find(input).unwrap();
        assert_eq!("user@example.com", &input[range]);
    }

    #[test]
    fn find_should_handle_trailing_dot_strip_and_still_validate() {
        let finder = Email::default();
        let input = "user@example.com. next";
        let range = finder.find(input).unwrap();
        assert_eq!("user@example.com", &input[range]);
    }

    #[test]
    fn find_should_reject_label_starting_with_hyphen_deep() {
        let finder = Email::default();
        assert!(finder.find("user@sub.-example.com").is_none());
    }

    #[test]
    fn find_should_reject_label_ending_with_hyphen_deep() {
        let finder = Email::default();
        assert!(finder.find("user@sub.example-.com").is_none());
    }

    #[test]
    fn find_should_handle_max_length_tld() {
        let finder = Email::default();
        let input = "user@example.museum";
        let range = finder.find(input).unwrap();
        assert_eq!("user@example.museum", &input[range]);
    }

    #[test]
    fn find_should_extract_email_adjacent_to_punctuation() {
        let finder = Email::default();
        let input = "email:user@example.com,next";
        let range = finder.find(input).unwrap();
        assert_eq!("user@example.com", &input[range]);
    }
}
