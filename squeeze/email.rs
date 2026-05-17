use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Email {}

impl Email {
    fn is_local_char(b: u8) -> bool {
        b.is_ascii_alphanumeric()
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
            )
    }
}

impl Finder for Email {
    fn id(&self) -> &'static str {
        "email"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            let at_pos = idx + input[idx..].iter().position(|&b| b == b'@')?;

            // Walk backwards for local part
            let mut local_start = at_pos;
            while local_start > idx && Self::is_local_char(input[local_start - 1]) {
                local_start -= 1;
            }

            // Local part must be non-empty and not start/end with '.'
            if local_start == at_pos
                || input[local_start] == b'.'
                || input[at_pos - 1] == b'.'
            {
                idx = at_pos + 1;
                continue;
            }

            // Walk forwards for domain
            let domain_start = at_pos + 1;
            let mut domain_end = domain_start;
            while domain_end < input.len()
                && (input[domain_end].is_ascii_alphanumeric()
                    || input[domain_end] == b'-'
                    || input[domain_end] == b'.')
            {
                domain_end += 1;
            }

            if domain_end == domain_start {
                idx = at_pos + 1;
                continue;
            }

            // Strip trailing dots/hyphens
            while domain_end > domain_start
                && matches!(input[domain_end - 1], b'.' | b'-')
            {
                domain_end -= 1;
            }

            let domain = &s[domain_start..domain_end];

            // Must have at least one dot
            if !domain.contains('.') {
                idx = at_pos + 1;
                continue;
            }

            // Validate each label
            let valid = domain.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });

            if !valid {
                idx = at_pos + 1;
                continue;
            }

            // TLD must be >= 2 chars and all alpha
            let tld = domain.rsplit('.').next().unwrap();
            if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
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
}
