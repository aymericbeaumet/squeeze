use super::Finder;
use regex::Regex;
use std::ops::Range;
use std::sync::OnceLock;

pub struct Phone {
    regex: &'static Regex,
}

impl Default for Phone {
    fn default() -> Self {
        static RE: OnceLock<Regex> = OnceLock::new();
        let regex = RE.get_or_init(|| {
            Regex::new(concat!(
                r"(?:",
                // E.164 international: +CC with digits/separators
                r"\+[1-9]\d{0,2}[\s.\-]?(?:\(?\d{1,4}\)?[\s.\-]?){1,4}\d",
                r"|",
                // North American: (XXX) XXX-XXXX
                r"\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}",
                r"|",
                // North American: XXX-XXX-XXXX or XXX.XXX.XXXX (require separator)
                r"\d{3}[\-\.]\d{3}[\-\.]\d{4}",
                r")",
            ))
            .unwrap()
        });
        Phone { regex }
    }
}

impl Phone {
    fn count_digits(s: &str) -> usize {
        s.bytes().filter(|b| b.is_ascii_digit()).count()
    }
}

impl Finder for Phone {
    fn id(&self) -> &'static str {
        "phone"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();

        for m in self.regex.find_iter(s) {
            let start = m.start();
            let end = m.end();
            let matched = &s[start..end];

            // Boundary before: not preceded by alphanumeric
            if start > 0 && input[start - 1].is_ascii_alphanumeric() {
                continue;
            }

            // Boundary after: not followed by digit
            if end < input.len() && input[end].is_ascii_digit() {
                continue;
            }

            let digit_count = Self::count_digits(matched);
            if !(7..=15).contains(&digit_count) {
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
    fn id_should_return_phone() {
        let finder = Phone::default();
        assert_eq!("phone", finder.id());
    }

    // E.164 format
    #[test]
    fn find_should_extract_e164() {
        let finder = Phone::default();
        let input = "call +14155551234";
        let range = finder.find(input).unwrap();
        assert_eq!("+14155551234", &input[range]);
    }

    #[test]
    fn find_should_extract_e164_with_separators() {
        let finder = Phone::default();
        let input = "call +1-415-555-1234";
        let range = finder.find(input).unwrap();
        assert_eq!("+1-415-555-1234", &input[range]);
    }

    #[test]
    fn find_should_extract_e164_with_spaces() {
        let finder = Phone::default();
        let input = "call +1 415 555 1234";
        let range = finder.find(input).unwrap();
        assert_eq!("+1 415 555 1234", &input[range]);
    }

    #[test]
    fn find_should_extract_international_with_country_code() {
        let finder = Phone::default();
        let input = "+44 20 7946 0958";
        let range = finder.find(input).unwrap();
        assert_eq!("+44 20 7946 0958", &input[range]);
    }

    #[test]
    fn find_should_extract_e164_with_dots() {
        let finder = Phone::default();
        let input = "+1.415.555.1234";
        let range = finder.find(input).unwrap();
        assert_eq!("+1.415.555.1234", &input[range]);
    }

    // North American with parens
    #[test]
    fn find_should_extract_parens_format() {
        let finder = Phone::default();
        let input = "call (415) 555-1234";
        let range = finder.find(input).unwrap();
        assert_eq!("(415) 555-1234", &input[range]);
    }

    #[test]
    fn find_should_extract_parens_no_space() {
        let finder = Phone::default();
        let input = "(415)555-1234";
        let range = finder.find(input).unwrap();
        assert_eq!("(415)555-1234", &input[range]);
    }

    // North American with dashes
    #[test]
    fn find_should_extract_dashed_format() {
        let finder = Phone::default();
        let input = "call 415-555-1234";
        let range = finder.find(input).unwrap();
        assert_eq!("415-555-1234", &input[range]);
    }

    #[test]
    fn find_should_extract_dotted_format() {
        let finder = Phone::default();
        let input = "call 415.555.1234";
        let range = finder.find(input).unwrap();
        assert_eq!("415.555.1234", &input[range]);
    }

    // Rejection tests
    #[test]
    fn find_should_reject_plain_digits() {
        let finder = Phone::default();
        assert!(finder.find("1234567890").is_none());
    }

    #[test]
    fn find_should_reject_short_number() {
        let finder = Phone::default();
        assert!(finder.find("+123").is_none());
    }

    #[test]
    fn find_should_reject_preceded_by_alpha() {
        let finder = Phone::default();
        assert!(finder.find("x+14155551234").is_none());
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Phone::default();
        assert!(finder.find("").is_none());
    }

    // Multiple
    #[test]
    fn find_should_extract_multiple_phones_iteratively() {
        let finder = Phone::default();
        let input = "+14155551234 and (212) 555-6789";

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

        assert_eq!(vec!["+14155551234", "(212) 555-6789"], results);
    }

    #[test]
    fn find_should_extract_phone_in_text() {
        let finder = Phone::default();
        let input = "Call us at +1-800-555-0199 for support";
        let range = finder.find(input).unwrap();
        assert_eq!("+1-800-555-0199", &input[range]);
    }
}
