use super::Finder;
use std::ops::Range;

const MAX_DEPTH: usize = 256;

#[derive(Default)]
pub struct Json {}

impl Json {
    fn try_extract(input: &[u8], start: usize) -> Option<Range<usize>> {
        if !matches!(input[start], b'{' | b'[') {
            return None;
        }

        let mut depth: usize = 1;
        let mut pos = start + 1;

        while pos < input.len() && depth > 0 {
            match input[pos] {
                b'"' => {
                    pos += 1;
                    while pos < input.len() {
                        if input[pos] == b'\\' {
                            pos += 2;
                            continue;
                        }
                        if input[pos] == b'"' {
                            pos += 1;
                            break;
                        }
                        pos += 1;
                    }
                    continue;
                }
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return None;
                    }
                }
                b'}' | b']' => {
                    depth -= 1;
                }
                _ => {}
            }
            pos += 1;
        }

        if depth == 0 {
            Some(start..pos)
        } else {
            None
        }
    }
}

impl Finder for Json {
    fn id(&self) -> &'static str {
        "json"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            if input[idx] == b'{' || input[idx] == b'[' {
                if let Some(range) = Self::try_extract(input, idx) {
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
    fn id_should_return_json() {
        let finder = Json::default();
        assert_eq!("json", finder.id());
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
}
