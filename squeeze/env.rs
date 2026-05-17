use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Env {}

impl Env {
    fn is_name_start(b: u8) -> bool {
        b.is_ascii_alphabetic() || b == b'_'
    }

    fn is_name_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }
}

impl Finder for Env {
    fn id(&self) -> &'static str {
        "env"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            let dollar = idx + input[idx..].iter().position(|&b| b == b'$')?;

            let after = dollar + 1;
            if after >= input.len() {
                return None;
            }

            if input[after] == b'{' {
                let name_start = after + 1;
                if name_start < input.len() && Self::is_name_start(input[name_start]) {
                    let mut name_end = name_start + 1;
                    while name_end < input.len() && Self::is_name_char(input[name_end]) {
                        name_end += 1;
                    }
                    if name_end < input.len() && input[name_end] == b'}' {
                        return Some(dollar..name_end + 1);
                    }
                }
                idx = after + 1;
                continue;
            }

            if Self::is_name_start(input[after]) {
                let mut name_end = after + 1;
                while name_end < input.len() && Self::is_name_char(input[name_end]) {
                    name_end += 1;
                }
                return Some(dollar..name_end);
            }

            idx = after;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_env() {
        let finder = Env::default();
        assert_eq!("env", finder.id());
    }

    #[test]
    fn find_should_extract_simple_var() {
        let finder = Env::default();
        let input = "use $HOME for path";
        let range = finder.find(input).unwrap();
        assert_eq!("$HOME", &input[range]);
    }

    #[test]
    fn find_should_extract_braced_var() {
        let finder = Env::default();
        let input = "use ${HOME} for path";
        let range = finder.find(input).unwrap();
        assert_eq!("${HOME}", &input[range]);
    }

    #[test]
    fn find_should_extract_var_with_underscores() {
        let finder = Env::default();
        let input = "set $MY_VAR_123 here";
        let range = finder.find(input).unwrap();
        assert_eq!("$MY_VAR_123", &input[range]);
    }

    #[test]
    fn find_should_extract_var_starting_with_underscore() {
        let finder = Env::default();
        let input = "$_private";
        let range = finder.find(input).unwrap();
        assert_eq!("$_private", &input[range]);
    }

    #[test]
    fn find_should_reject_dollar_followed_by_digit() {
        let finder = Env::default();
        assert!(finder.find("$123").is_none());
    }

    #[test]
    fn find_should_reject_bare_dollar() {
        let finder = Env::default();
        assert!(finder.find("$ foo").is_none());
    }

    #[test]
    fn find_should_reject_dollar_at_end() {
        let finder = Env::default();
        assert!(finder.find("cost is $").is_none());
    }

    #[test]
    fn find_should_reject_empty_braces() {
        let finder = Env::default();
        assert!(finder.find("${} foo").is_none());
    }

    #[test]
    fn find_should_reject_unclosed_brace() {
        let finder = Env::default();
        assert!(finder.find("${HOME foo").is_none());
    }

    #[test]
    fn find_should_reject_brace_with_digit_start() {
        let finder = Env::default();
        assert!(finder.find("${123}").is_none());
    }

    #[test]
    fn find_should_extract_var_at_start() {
        let finder = Env::default();
        let input = "$PATH is set";
        let range = finder.find(input).unwrap();
        assert_eq!("$PATH", &input[range]);
    }

    #[test]
    fn find_should_extract_var_at_end() {
        let finder = Env::default();
        let input = "see $PATH";
        let range = finder.find(input).unwrap();
        assert_eq!("$PATH", &input[range]);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Env::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_multiple_vars_iteratively() {
        let finder = Env::default();
        let input = "$HOME and ${PATH} here";

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

        assert_eq!(vec!["$HOME", "${PATH}"], results);
    }

    #[test]
    fn find_should_skip_invalid_and_find_valid() {
        let finder = Env::default();
        let input = "$123 then $VALID";
        let range = finder.find(input).unwrap();
        assert_eq!("$VALID", &input[range]);
    }

    #[test]
    fn find_should_extract_var_in_quotes() {
        let finder = Env::default();
        let input = r#"echo "$HOME""#;
        let range = finder.find(input).unwrap();
        assert_eq!("$HOME", &input[range]);
    }
}
