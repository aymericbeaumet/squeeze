use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Datetime {}

impl Datetime {
    fn try_date(input: &[u8], idx: usize) -> Option<Range<usize>> {
        // YYYY-MM-DD with optional time component
        if idx + 10 > input.len() {
            return None;
        }

        // Boundary before: not preceded by digit or dash
        if idx > 0 && (input[idx - 1].is_ascii_digit() || input[idx - 1] == b'-') {
            return None;
        }

        // YYYY
        if !Self::is_4_digits(input, idx) {
            return None;
        }
        let year = Self::parse_num(input, idx, 4);
        if !(1000..=9999).contains(&year) {
            return None;
        }

        if input[idx + 4] != b'-' {
            return None;
        }

        // MM
        if !Self::is_2_digits(input, idx + 5) {
            return None;
        }
        let month = Self::parse_num(input, idx + 5, 2);
        if !(1..=12).contains(&month) {
            return None;
        }

        if input[idx + 7] != b'-' {
            return None;
        }

        // DD
        if !Self::is_2_digits(input, idx + 8) {
            return None;
        }
        let day = Self::parse_num(input, idx + 8, 2);
        if !(1..=31).contains(&day) {
            return None;
        }

        let mut end = idx + 10;

        // Optional time component: T or space followed by HH:MM
        if end < input.len() && (input[end] == b'T' || input[end] == b' ') {
            if let Some(time_end) = Self::try_time(input, end + 1) {
                // Only accept space separator if it's 'T' or if followed by valid time
                if input[end] == b'T' || time_end > end + 1 {
                    end = time_end;
                }
            }
        }

        // Boundary after: not followed by digit or dash
        if end < input.len() && (input[end].is_ascii_digit() || input[end] == b'-') {
            return None;
        }

        Some(idx..end)
    }

    fn try_time(input: &[u8], idx: usize) -> Option<usize> {
        // HH:MM[:SS[.fractional]]
        if idx + 5 > input.len() {
            return None;
        }

        if !Self::is_2_digits(input, idx) {
            return None;
        }
        let hour = Self::parse_num(input, idx, 2);
        if hour > 23 {
            return None;
        }

        if input[idx + 2] != b':' {
            return None;
        }

        if !Self::is_2_digits(input, idx + 3) {
            return None;
        }
        let minute = Self::parse_num(input, idx + 3, 2);
        if minute > 59 {
            return None;
        }

        let mut end = idx + 5;

        // Optional :SS
        if end + 3 <= input.len() && input[end] == b':' && Self::is_2_digits(input, end + 1) {
            let second = Self::parse_num(input, end + 1, 2);
            if second <= 60 {
                end += 3;

                // Optional fractional seconds
                if end < input.len() && input[end] == b'.' {
                    let frac_start = end + 1;
                    let mut frac_end = frac_start;
                    while frac_end < input.len() && input[frac_end].is_ascii_digit() {
                        frac_end += 1;
                    }
                    if frac_end > frac_start {
                        end = frac_end;
                    }
                }
            }
        }

        // Optional timezone: Z, +HH:MM, -HH:MM
        if end < input.len() && input[end] == b'Z' {
            end += 1;
        } else if end + 6 <= input.len()
            && (input[end] == b'+' || input[end] == b'-')
            && Self::is_2_digits(input, end + 1)
            && input[end + 3] == b':'
            && Self::is_2_digits(input, end + 4)
        {
            end += 6;
        }

        Some(end)
    }

    fn is_2_digits(input: &[u8], pos: usize) -> bool {
        pos + 2 <= input.len() && input[pos].is_ascii_digit() && input[pos + 1].is_ascii_digit()
    }

    fn is_4_digits(input: &[u8], pos: usize) -> bool {
        pos + 4 <= input.len()
            && input[pos].is_ascii_digit()
            && input[pos + 1].is_ascii_digit()
            && input[pos + 2].is_ascii_digit()
            && input[pos + 3].is_ascii_digit()
    }

    fn parse_num(input: &[u8], pos: usize, len: usize) -> u32 {
        let mut n = 0u32;
        for i in 0..len {
            n = n * 10 + (input[pos + i] - b'0') as u32;
        }
        n
    }
}

impl Finder for Datetime {
    fn id(&self) -> &'static str {
        "datetime"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        byte.is_ascii_digit()
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        if !input[pos].is_ascii_digit() {
            return None;
        }
        Self::try_date(input, pos)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx + 10 <= input.len() {
            if input[idx].is_ascii_digit() {
                if let Some(range) = Self::try_date(input, idx) {
                    return Some(range);
                }
            }
            idx += 1;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_datetime() {
        let finder = Datetime::default();
        assert_eq!("datetime", finder.id());
    }

    #[test]
    fn find_should_extract_date() {
        let finder = Datetime::default();
        let input = "created on 2024-01-15 by admin";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15", &input[range]);
    }

    #[test]
    fn find_should_extract_datetime_with_t() {
        let finder = Datetime::default();
        let input = "timestamp: 2024-01-15T10:30:00";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15T10:30:00", &input[range]);
    }

    #[test]
    fn find_should_extract_datetime_with_timezone_z() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:30:00Z";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15T10:30:00Z", &input[range]);
    }

    #[test]
    fn find_should_extract_datetime_with_timezone_offset() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:30:00+05:30";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15T10:30:00+05:30", &input[range]);
    }

    #[test]
    fn find_should_extract_datetime_with_negative_offset() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:30:00-08:00";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15T10:30:00-08:00", &input[range]);
    }

    #[test]
    fn find_should_extract_datetime_with_fractional_seconds() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:30:00.123Z";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15T10:30:00.123Z", &input[range]);
    }

    #[test]
    fn find_should_extract_datetime_with_fractional_and_offset() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:30:00.123456+02:00";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15T10:30:00.123456+02:00", &input[range]);
    }

    #[test]
    fn find_should_extract_datetime_without_seconds() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:30Z";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15T10:30Z", &input[range]);
    }

    #[test]
    fn find_should_extract_date_in_text() {
        let finder = Datetime::default();
        let input = "deployed on 2024-12-25 successfully";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-12-25", &input[range]);
    }

    #[test]
    fn find_should_reject_invalid_month() {
        let finder = Datetime::default();
        assert!(finder.find("2024-13-01").is_none());
    }

    #[test]
    fn find_should_reject_invalid_day() {
        let finder = Datetime::default();
        assert!(finder.find("2024-01-32").is_none());
    }

    #[test]
    fn find_should_reject_month_zero() {
        let finder = Datetime::default();
        assert!(finder.find("2024-00-15").is_none());
    }

    #[test]
    fn find_should_reject_day_zero() {
        let finder = Datetime::default();
        assert!(finder.find("2024-01-00").is_none());
    }

    #[test]
    fn find_should_reject_preceded_by_digit() {
        let finder = Datetime::default();
        assert!(finder.find("x12024-01-15").is_none());
    }

    #[test]
    fn find_should_reject_followed_by_digit() {
        let finder = Datetime::default();
        assert!(finder.find("2024-01-155").is_none());
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Datetime::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_multiple_datetimes_iteratively() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:00:00Z to 2024-01-16T12:00:00Z";

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

        assert_eq!(
            vec!["2024-01-15T10:00:00Z", "2024-01-16T12:00:00Z"],
            results
        );
    }

    #[test]
    fn find_should_extract_date_at_start() {
        let finder = Datetime::default();
        let input = "2024-01-15 is the date";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15", &input[range]);
    }

    #[test]
    fn find_should_extract_date_at_end() {
        let finder = Datetime::default();
        let input = "the date is 2024-01-15";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15", &input[range]);
    }

    #[test]
    fn find_should_reject_invalid_hour() {
        let finder = Datetime::default();
        let input = "2024-01-15T25:00:00";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15", &input[range]);
    }

    #[test]
    fn find_should_reject_invalid_minute() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:61:00";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15", &input[range]);
    }

    #[test]
    fn find_should_extract_datetime_with_space_separator() {
        let finder = Datetime::default();
        let input = "log: 2024-01-15 10:30:00";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15 10:30:00", &input[range]);
    }

    #[test]
    fn try_at_date_at_start() {
        let finder = Datetime::default();
        let input = b"2024-01-15 rest";
        assert_eq!(finder.try_at(input, 0), Some(0..10));
    }

    #[test]
    fn try_at_non_digit() {
        let finder = Datetime::default();
        let input = b"abc";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn try_at_short_input() {
        let finder = Datetime::default();
        let input = b"2024";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn try_at_preceded_by_digit() {
        let finder = Datetime::default();
        let input = b"12024-01-15";
        assert!(finder.try_at(input, 1).is_none());
    }

    #[test]
    fn find_boundary_year_1000() {
        let finder = Datetime::default();
        let input = "1000-01-01";
        assert!(finder.find(input).is_some());
    }

    #[test]
    fn find_boundary_year_9999() {
        let finder = Datetime::default();
        let input = "9999-12-31";
        assert!(finder.find(input).is_some());
    }

    #[test]
    fn find_leap_second() {
        let finder = Datetime::default();
        let input = "2024-06-30T23:59:60Z";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-06-30T23:59:60Z", &input[range]);
    }

    #[test]
    fn find_fractional_seconds_many_digits() {
        let finder = Datetime::default();
        let input = "2024-01-15T10:30:00.123456789Z";
        let range = finder.find(input).unwrap();
        assert_eq!("2024-01-15T10:30:00.123456789Z", &input[range]);
    }

    #[test]
    fn find_single_digit_input() {
        let finder = Datetime::default();
        assert!(finder.find("1").is_none());
    }
}
