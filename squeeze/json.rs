//! Strict JSON finder.
//!
//! Finds the first valid JSON value rooted at an object (`{...}`) or array
//! (`[...]`) in the input. Bare numbers, strings, and literals are intentionally
//! not surfaced — they're too easy to false-positive on prose.
//!
//! Validation follows RFC 8259: it checks string escapes (including `\uXXXX`),
//! number shape, and that the only allowed JSON literals are `true`, `false`,
//! and `null`. Inputs whose braces happen to balance but contain garbage
//! (`{not really json}`) are rejected.

use super::Finder;
use std::ops::Range;

const MAX_DEPTH: usize = 256;

#[inline]
fn memchr2(n1: u8, n2: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == n1 || b == n2)
}

#[inline]
fn skip_ws(input: &[u8], mut pos: usize) -> usize {
    while pos < input.len() && matches!(input[pos], b' ' | b'\t' | b'\n' | b'\r') {
        pos += 1;
    }
    pos
}

fn parse_value(input: &[u8], pos: usize, depth: usize) -> Option<usize> {
    if depth > MAX_DEPTH {
        return None;
    }
    let pos = skip_ws(input, pos);
    if pos >= input.len() {
        return None;
    }
    match input[pos] {
        b'{' => parse_object(input, pos, depth + 1),
        b'[' => parse_array(input, pos, depth + 1),
        b'"' => parse_string(input, pos),
        b't' => parse_literal(input, pos, b"true"),
        b'f' => parse_literal(input, pos, b"false"),
        b'n' => parse_literal(input, pos, b"null"),
        b'-' | b'0'..=b'9' => parse_number(input, pos),
        _ => None,
    }
}

fn parse_object(input: &[u8], start: usize, depth: usize) -> Option<usize> {
    debug_assert_eq!(input[start], b'{');
    let mut pos = start + 1;
    pos = skip_ws(input, pos);
    if pos < input.len() && input[pos] == b'}' {
        return Some(pos + 1);
    }
    loop {
        pos = skip_ws(input, pos);
        if pos >= input.len() || input[pos] != b'"' {
            return None;
        }
        pos = parse_string(input, pos)?;
        pos = skip_ws(input, pos);
        if pos >= input.len() || input[pos] != b':' {
            return None;
        }
        pos += 1;
        pos = parse_value(input, pos, depth)?;
        pos = skip_ws(input, pos);
        if pos >= input.len() {
            return None;
        }
        match input[pos] {
            b',' => pos += 1,
            b'}' => return Some(pos + 1),
            _ => return None,
        }
    }
}

fn parse_array(input: &[u8], start: usize, depth: usize) -> Option<usize> {
    debug_assert_eq!(input[start], b'[');
    let mut pos = start + 1;
    pos = skip_ws(input, pos);
    if pos < input.len() && input[pos] == b']' {
        return Some(pos + 1);
    }
    loop {
        pos = parse_value(input, pos, depth)?;
        pos = skip_ws(input, pos);
        if pos >= input.len() {
            return None;
        }
        match input[pos] {
            b',' => pos += 1,
            b']' => return Some(pos + 1),
            _ => return None,
        }
    }
}

fn parse_string(input: &[u8], start: usize) -> Option<usize> {
    debug_assert_eq!(input[start], b'"');
    let mut pos = start + 1;
    while pos < input.len() {
        let b = input[pos];
        if b == b'"' {
            return Some(pos + 1);
        }
        if b == b'\\' {
            pos += 1;
            if pos >= input.len() {
                return None;
            }
            match input[pos] {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => pos += 1,
                b'u' => {
                    if pos + 4 >= input.len() {
                        return None;
                    }
                    for i in 1..=4 {
                        if !input[pos + i].is_ascii_hexdigit() {
                            return None;
                        }
                    }
                    pos += 5;
                }
                _ => return None,
            }
        } else if b < 0x20 {
            // Unescaped control character is illegal in JSON strings.
            return None;
        } else {
            pos += 1;
        }
    }
    None
}

fn parse_number(input: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    if input[pos] == b'-' {
        pos += 1;
        if pos >= input.len() {
            return None;
        }
    }
    // Integer part.
    match input.get(pos)? {
        b'0' => pos += 1,
        b'1'..=b'9' => {
            pos += 1;
            while pos < input.len() && input[pos].is_ascii_digit() {
                pos += 1;
            }
        }
        _ => return None,
    }
    // Fraction.
    if pos < input.len() && input[pos] == b'.' {
        pos += 1;
        let frac_start = pos;
        while pos < input.len() && input[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == frac_start {
            return None;
        }
    }
    // Exponent.
    if pos < input.len() && (input[pos] == b'e' || input[pos] == b'E') {
        pos += 1;
        if pos < input.len() && (input[pos] == b'+' || input[pos] == b'-') {
            pos += 1;
        }
        let exp_start = pos;
        while pos < input.len() && input[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == exp_start {
            return None;
        }
    }
    Some(pos)
}

fn parse_literal(input: &[u8], start: usize, lit: &[u8]) -> Option<usize> {
    let end = start + lit.len();
    if end <= input.len() && &input[start..end] == lit {
        Some(end)
    } else {
        None
    }
}

#[derive(Default)]
pub struct Json {}

impl Finder for Json {
    fn id(&self) -> &'static str {
        "json"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        matches!(byte, b'{' | b'[')
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        if !matches!(input[pos], b'{' | b'[') {
            return None;
        }
        parse_value(input, pos, 0).map(|end| pos..end)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;
        while let Some(offset) = memchr2(b'{', b'[', &input[idx..]) {
            idx += offset;
            if let Some(end) = parse_value(input, idx, 0) {
                return Some(idx..end);
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
    fn id_should_return_json() {
        let finder = Json::default();
        assert_eq!("json", finder.id());
    }

    #[test]
    fn try_at_extracts_json_at_exact_position() {
        let finder = Json::default();
        let input = br#"x {"key": "value"} y"#;
        assert_eq!(Some(2..18), finder.try_at(input, 2));
        assert_eq!(None, finder.try_at(input, 0));
    }

    // Objects
    #[test]
    fn find_should_extract_simple_object() {
        let finder = Json::default();
        let input = r#"data: {"key": "value"}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"key": "value"}"#, &input[range]);
    }

    #[test]
    fn find_should_extract_nested_object() {
        let finder = Json::default();
        let input = r#"{"a": {"b": "c"}}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"a": {"b": "c"}}"#, &input[range]);
    }

    #[test]
    fn find_should_extract_object_with_array() {
        let finder = Json::default();
        let input = r#"{"items": [1, 2, 3]}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"items": [1, 2, 3]}"#, &input[range]);
    }

    #[test]
    fn find_should_extract_empty_object() {
        let finder = Json::default();
        let input = "result: {}";
        let range = finder.find(input).unwrap();
        assert_eq!("{}", &input[range]);
    }

    // Arrays
    #[test]
    fn find_should_extract_simple_array() {
        let finder = Json::default();
        let input = "data: [1, 2, 3]";
        let range = finder.find(input).unwrap();
        assert_eq!("[1, 2, 3]", &input[range]);
    }

    #[test]
    fn find_should_extract_nested_array() {
        let finder = Json::default();
        let input = "[[1, 2], [3, 4]]";
        let range = finder.find(input).unwrap();
        assert_eq!("[[1, 2], [3, 4]]", &input[range]);
    }

    #[test]
    fn find_should_extract_empty_array() {
        let finder = Json::default();
        let input = "items: []";
        let range = finder.find(input).unwrap();
        assert_eq!("[]", &input[range]);
    }

    // String handling
    #[test]
    fn find_should_handle_escaped_quotes() {
        let finder = Json::default();
        let input = r#"{"msg": "say \"hello\""}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"msg": "say \"hello\""}"#, &input[range]);
    }

    #[test]
    fn find_should_handle_braces_in_strings() {
        let finder = Json::default();
        let input = r#"{"template": "{name}"}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"template": "{name}"}"#, &input[range]);
    }

    #[test]
    fn find_should_handle_brackets_in_strings() {
        let finder = Json::default();
        let input = r#"{"pattern": "[a-z]"}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"pattern": "[a-z]"}"#, &input[range]);
    }

    #[test]
    fn find_should_handle_escaped_backslash() {
        let finder = Json::default();
        let input = r#"{"path": "C:\\Users\\foo"}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"path": "C:\\Users\\foo"}"#, &input[range]);
    }

    // Edge cases
    #[test]
    fn find_should_reject_unclosed_object() {
        let finder = Json::default();
        assert!(finder.find(r#"{"key": "value""#).is_none());
    }

    #[test]
    fn find_should_reject_unclosed_array() {
        let finder = Json::default();
        assert!(finder.find("[1, 2, 3").is_none());
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Json::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_json_from_log_line() {
        let finder = Json::default();
        let input = r#"2024-01-15 INFO: {"event": "login", "user": "alice"} processed"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"event": "login", "user": "alice"}"#, &input[range]);
    }

    #[test]
    fn find_should_extract_first_json_object() {
        let finder = Json::default();
        let input = r#"{"a": 1} and {"b": 2}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"a": 1}"#, &input[range]);
    }

    // Multiple
    #[test]
    fn find_should_extract_multiple_json_iteratively() {
        let finder = Json::default();
        let input = r#"{"a": 1} and [2, 3]"#;

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

        assert_eq!(vec![r#"{"a": 1}"#, "[2, 3]"], results);
    }

    #[test]
    fn find_should_handle_deeply_nested() {
        let finder = Json::default();
        let input = r#"{"a": {"b": {"c": {"d": "deep"}}}}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(input, &input[range]);
    }

    #[test]
    fn find_should_skip_unclosed_and_find_next() {
        let finder = Json::default();
        let input = r#"{unclosed and {"valid": true}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"valid": true}"#, &input[range]);
    }

    // --- Regression: memchr-accelerated string scanning ---

    #[test]
    fn find_should_handle_long_string_value() {
        let finder = Json::default();
        let long_val = "a".repeat(10000);
        let input = format!(r#"{{"key": "{}"}}"#, long_val);
        let range = finder.find(&input).unwrap();
        assert_eq!(&input, &input[range]);
    }

    #[test]
    fn find_should_handle_string_with_many_escapes() {
        let finder = Json::default();
        let escapes = r#"\\\\\\\\\\\\\\\\\\\\\"end"#;
        let input = format!(r#"{{"key": "{}"}}"#, escapes);
        let range = finder.find(&input).unwrap();
        assert_eq!(&input, &input[range]);
    }

    #[test]
    fn find_should_handle_string_with_braces_inside() {
        let finder = Json::default();
        let input = r#"{"template": "{{not nested}}"}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(input, &input[range]);
    }

    #[test]
    fn find_should_handle_unclosed_string_in_object() {
        let finder = Json::default();
        let input = r#"{"key": "unterminated"#;
        assert!(finder.find(input).is_none());
    }

    #[test]
    fn find_should_handle_empty_strings() {
        let finder = Json::default();
        let input = r#"{"": ""}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(r#"{"": ""}"#, &input[range]);
    }

    #[test]
    fn find_should_handle_escape_at_string_end() {
        let finder = Json::default();
        let input = r#"{"key": "val\\"}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(input, &input[range]);
    }

    // --- Strict-mode rejections ---

    #[test]
    fn find_should_reject_balanced_garbage() {
        let finder = Json::default();
        assert!(finder.find("{not really json}").is_none());
    }

    #[test]
    fn find_should_reject_object_without_colon() {
        let finder = Json::default();
        assert!(finder.find(r#"{"key" "value"}"#).is_none());
    }

    #[test]
    fn find_should_reject_object_unquoted_key() {
        let finder = Json::default();
        assert!(finder.find(r#"{key: "value"}"#).is_none());
    }

    #[test]
    fn find_should_reject_trailing_comma_in_object() {
        let finder = Json::default();
        assert!(finder.find(r#"{"a": 1,}"#).is_none());
    }

    #[test]
    fn find_should_reject_trailing_comma_in_array() {
        let finder = Json::default();
        assert!(finder.find("[1, 2,]").is_none());
    }

    #[test]
    fn find_should_reject_single_quoted_strings() {
        let finder = Json::default();
        assert!(finder.find(r#"{'key': 'value'}"#).is_none());
    }

    #[test]
    fn find_should_reject_javascript_undefined() {
        let finder = Json::default();
        assert!(finder.find(r#"{"k": undefined}"#).is_none());
    }

    #[test]
    fn find_should_reject_bare_number_with_leading_zero() {
        let finder = Json::default();
        assert!(finder.find("[01]").is_none());
    }

    #[test]
    fn find_should_reject_bare_dot_number() {
        let finder = Json::default();
        // JSON numbers must have a digit before the dot.
        assert!(finder.find("[.5]").is_none());
    }

    #[test]
    fn find_should_reject_trailing_dot_number() {
        let finder = Json::default();
        // JSON numbers must have at least one digit after the dot.
        assert!(finder.find("[1.]").is_none());
    }

    #[test]
    fn find_should_reject_invalid_escape_sequence() {
        let finder = Json::default();
        assert!(finder.find(r#"{"k": "bad \q escape"}"#).is_none());
    }

    #[test]
    fn find_should_reject_short_unicode_escape() {
        let finder = Json::default();
        assert!(finder.find(r#"{"k": "\u12"}"#).is_none());
    }

    #[test]
    fn find_should_reject_non_hex_unicode_escape() {
        let finder = Json::default();
        assert!(finder.find(r#"{"k": "\uZZZZ"}"#).is_none());
    }

    #[test]
    fn find_should_reject_unescaped_control_char_in_string() {
        let finder = Json::default();
        let input = "{\"k\": \"line1\nline2\"}";
        assert!(finder.find(input).is_none());
    }

    #[test]
    fn find_should_accept_number_with_exponent() {
        let finder = Json::default();
        let input = "[1.5e10, -2.0E-3]";
        let range = finder.find(input).unwrap();
        assert_eq!(input, &input[range]);
    }

    #[test]
    fn find_should_accept_literals() {
        let finder = Json::default();
        let input = "[true, false, null]";
        let range = finder.find(input).unwrap();
        assert_eq!(input, &input[range]);
    }

    #[test]
    fn find_should_reject_truncated_literal() {
        let finder = Json::default();
        assert!(finder.find("[tru]").is_none());
    }

    #[test]
    fn find_should_reject_uppercase_literal() {
        let finder = Json::default();
        assert!(finder.find("[True]").is_none());
    }

    #[test]
    fn find_should_accept_whitespace_around_values() {
        let finder = Json::default();
        let input = "{  \"k\"  :  \"v\"  ,  \"n\"  :  42  }";
        let range = finder.find(input).unwrap();
        assert_eq!(input, &input[range]);
    }

    #[test]
    fn find_should_accept_unicode_escapes() {
        let finder = Json::default();
        let input = r#"{"k": "éclair"}"#;
        let range = finder.find(input).unwrap();
        assert_eq!(input, &input[range]);
    }

    #[test]
    fn find_should_reject_array_with_two_consecutive_commas() {
        let finder = Json::default();
        assert!(finder.find("[1,,2]").is_none());
    }

    #[test]
    fn find_should_reject_extra_close_brace() {
        let finder = Json::default();
        // The first valid object is `{"a":1}`. We stop at its end; trailing
        // `}` is not the finder's concern.
        let input = r#"{"a":1}}"#;
        let r = finder.find(input).unwrap();
        assert_eq!(r#"{"a":1}"#, &input[r]);
    }
}
