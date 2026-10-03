use super::{ByteSet, Finder, RunClass, RunRule};
use crate::word::{digit_at, digit_lead_bytes, space_at};
use std::ops::Range;
use std::sync::OnceLock;

/// Phone number finder.
///
/// Hand-written equivalent of the former regex
/// `\+[1-9]\d{0,2}[\s.\-]?(?:\(?\d{1,4}\)?[\s.\-]?){1,7}\d` (E.164 with
/// optional separators), `\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}` and
/// `\d{3}[\-\.]\d{3}[\-\.]\d{4}` (North American forms), including the
/// regex crate's Unicode `\d` and `\s`, followed by the same validation.
#[derive(Default)]
pub struct Phone {}

/// Longest run of E.164 digit groups.
const MAX_GROUPS: usize = 7;

impl Phone {
    fn count_digits(s: &[u8]) -> usize {
        s.iter().filter(|b| b.is_ascii_digit()).count()
    }

    /// `[\s.\-]` at `pos`: byte length of the separator.
    #[inline]
    fn separator_at(input: &[u8], pos: usize) -> Option<usize> {
        match input.get(pos) {
            Some(b'.' | b'-') => Some(1),
            _ => space_at(input, pos),
        }
    }

    /// Ends of `\d{1,max}` at `pos`, longest first.
    fn digit_ends(input: &[u8], pos: usize, max: usize) -> Vec<usize> {
        let mut ends = Vec::with_capacity(max);
        let mut p = pos;
        for _ in 0..max {
            match digit_at(input, p) {
                Some(width) => {
                    p += width;
                    ends.push(p);
                }
                None => break,
            }
        }
        ends.reverse();
        ends
    }

    /// `(?:\(?\d{1,4}\)?[\s.\-]?){1,7}\d` from `pos` with `count` groups
    /// already matched, in backtracking order: more groups first.
    fn e164_groups(input: &[u8], pos: usize, count: usize) -> Option<usize> {
        if count < MAX_GROUPS {
            let opens: &[usize] = if input.get(pos) == Some(&b'(') {
                &[1, 0]
            } else {
                &[0]
            };
            for &open in opens {
                let a = pos + open;
                for b in Self::digit_ends(input, a, 4) {
                    let closes: &[usize] = if input.get(b) == Some(&b')') {
                        &[1, 0]
                    } else {
                        &[0]
                    };
                    for &close in closes {
                        let c = b + close;
                        let seps: [Option<usize>; 2] = [Self::separator_at(input, c), Some(0)];
                        for sep in seps.into_iter().flatten() {
                            if let Some(end) = Self::e164_groups(input, c + sep, count + 1) {
                                return Some(end);
                            }
                        }
                    }
                }
            }
        }
        if count >= 1 {
            return digit_at(input, pos).map(|width| pos + width);
        }
        None
    }

    /// `\+[1-9]\d{0,2}[\s.\-]?` then the groups.
    fn match_e164(input: &[u8], pos: usize) -> Option<usize> {
        if input.get(pos) != Some(&b'+') || !matches!(input.get(pos + 1), Some(b'1'..=b'9')) {
            return None;
        }
        let p = pos + 2;
        let mut ends = Self::digit_ends(input, p, 2);
        ends.push(p);
        for q in ends {
            let seps: [Option<usize>; 2] = [Self::separator_at(input, q), Some(0)];
            for sep in seps.into_iter().flatten() {
                if let Some(end) = Self::e164_groups(input, q + sep, 0) {
                    return Some(end);
                }
            }
        }
        None
    }

    /// Exactly `n` `\d` at `pos`.
    fn digits(input: &[u8], pos: usize, n: usize) -> Option<usize> {
        let mut p = pos;
        for _ in 0..n {
            p += digit_at(input, p)?;
        }
        Some(p)
    }

    /// `\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}`.
    fn match_paren(input: &[u8], pos: usize) -> Option<usize> {
        if input.get(pos) != Some(&b'(') {
            return None;
        }
        let p = Self::digits(input, pos + 1, 3)?;
        if input.get(p) != Some(&b')') {
            return None;
        }
        let p = p + 1;
        let p = p + Self::separator_at(input, p).unwrap_or(0);
        let p = Self::digits(input, p, 3)?;
        let p = p + Self::separator_at(input, p).unwrap_or(0);
        Self::digits(input, p, 4)
    }

    /// `\d{3}[\-\.]\d{3}[\-\.]\d{4}`.
    fn match_dashed(input: &[u8], pos: usize) -> Option<usize> {
        let p = Self::digits(input, pos, 3)?;
        if !matches!(input.get(p), Some(b'-' | b'.')) {
            return None;
        }
        let p = Self::digits(input, p + 1, 3)?;
        if !matches!(input.get(p), Some(b'-' | b'.')) {
            return None;
        }
        Self::digits(input, p + 1, 4)
    }

    fn match_at(input: &[u8], pos: usize) -> Option<usize> {
        match input.get(pos)? {
            b'+' => Self::match_e164(input, pos),
            b'(' => Self::match_paren(input, pos),
            _ => Self::match_dashed(input, pos),
        }
    }

    fn start_bytes() -> &'static ByteSet {
        static SET: OnceLock<ByteSet> = OnceLock::new();
        SET.get_or_init(|| {
            let mut set = ByteSet::from_bytes(b"+(");
            for b in digit_lead_bytes() {
                set = set.with(b);
            }
            set
        })
    }

    fn digit_leads() -> &'static ByteSet {
        static SET: OnceLock<ByteSet> = OnceLock::new();
        SET.get_or_init(|| {
            let mut set = ByteSet::EMPTY;
            for b in digit_lead_bytes() {
                set = set.with(b);
            }
            set
        })
    }

    fn validate_match(input: &[u8], start: usize, end: usize) -> Option<Range<usize>> {
        let matched = &input[start..end];

        // Boundary before: not preceded by alphanumeric
        if start > 0 && input[start - 1].is_ascii_alphanumeric() {
            return None;
        }

        // Boundary after: not followed by digit
        if end < input.len() && input[end].is_ascii_digit() {
            return None;
        }

        let digit_count = Self::count_digits(matched);
        if !(7..=15).contains(&digit_count) {
            return None;
        }

        // A '+' number written with separators must lead with a plausible
        // country code (1-3 digits before the first separator):
        // `+2024-01-15 ...` is a diff-line date, not a phone number.
        // Compact `+14155551234` (no separators) is unaffected.
        let bytes = matched;
        if bytes[0] == b'+' {
            let first_group = bytes[1..].iter().take_while(|b| b.is_ascii_digit()).count();
            let has_separators = 1 + first_group < bytes.len();
            if has_separators && first_group > 3 {
                return None;
            }
        }

        Some(start..end)
    }

    fn range_at(input: &[u8], pos: usize) -> Option<Range<usize>> {
        let end = Self::match_at(input, pos)?;
        Self::validate_match(input, pos, end)
    }
}

impl Finder for Phone {
    fn id(&self) -> &'static str {
        "phone"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        Self::start_bytes().contains(byte)
    }

    fn could_start_after(&self, prev: u8, _cur: u8) -> bool {
        !prev.is_ascii_alphanumeric()
    }

    fn could_continue_with(&self, cur: u8, next: u8) -> bool {
        match cur {
            b'+' => matches!(next, b'1'..=b'9'),
            b'(' => Self::digit_leads().contains(next),
            b'0'..=b'9' => Self::digit_leads().contains(next),
            _ => next & 0xC0 == 0x80,
        }
    }

    fn run_rules(&self) -> Vec<RunRule> {
        // `\d{3}[-.]\d{3}[-.]\d{4}` where `\d` also matches non-ASCII
        // digits: the ASCII digit run of a group is either the whole group,
        // followed by a separator, or is completed by a non-ASCII digit.
        let mut leads = ByteSet::EMPTY;
        for b in digit_lead_bytes().filter(|&b| b >= 0x80) {
            leads = leads.with(b);
        }
        let mixed = |rule: RunRule| {
            let mut rule = rule;
            let last = rule.then.iter_mut().rev().find_map(Option::as_mut);
            match last {
                Some(step) => {
                    step.after = leads;
                    step.after_end = false;
                }
                None => {
                    rule.after = leads;
                    rule.after_end = false;
                }
            }
            rule
        };
        vec![
            // All three groups ASCII.
            RunRule::new(RunClass::Digit, 3, 3)
                .followed_by(b"-.")
                .then(RunClass::Digit, 3, 3)
                .followed_by(b"-.")
                .then(RunClass::Digit, 4, 4),
            // A non-ASCII digit completes the first, second or third group.
            mixed(RunRule::new(RunClass::Digit, 1, 3)),
            mixed(RunRule::new(RunClass::Digit, 3, 3).followed_by(b"-.").then(
                RunClass::Digit,
                0,
                3,
            )),
            mixed(
                RunRule::new(RunClass::Digit, 3, 3)
                    .followed_by(b"-.")
                    .then(RunClass::Digit, 3, 3)
                    .followed_by(b"-.")
                    .then(RunClass::Digit, 0, 4),
            ),
        ]
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        Self::range_at(input, pos)
    }

    // Candidates are tried in position order; a rejected candidate is
    // simply followed by the next position, which may lie inside it.
    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        for pos in 0..input.len() {
            if self.could_start_at(input[pos])
                && let Some(end) = Self::match_at(input, pos)
                && let Some(range) = Self::validate_match(input, pos, end)
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
