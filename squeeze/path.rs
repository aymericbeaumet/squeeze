use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Path {}

impl Path {
    fn is_boundary(b: u8) -> bool {
        b.is_ascii_whitespace() || matches!(b, b'(' | b'[' | b'{' | b'<' | b'"' | b'\'' | b'`')
    }

    fn find_prefix(&self, input: &[u8], from: usize) -> Option<(usize, usize)> {
        let mut idx = from;
        while idx < input.len() {
            match input[idx] {
                b'~' if idx + 1 < input.len() && input[idx + 1] == b'/' => {
                    if idx == 0 || Self::is_boundary(input[idx - 1]) {
                        return Some((idx, 2));
                    }
                    idx += 2;
                }
                b'.' => {
                    if idx + 2 < input.len()
                        && input[idx + 1] == b'.'
                        && input[idx + 2] == b'/'
                        && (idx == 0 || Self::is_boundary(input[idx - 1]))
                    {
                        return Some((idx, 3));
                    }
                    if idx + 1 < input.len()
                        && input[idx + 1] == b'/'
                        && (idx == 0 || Self::is_boundary(input[idx - 1]))
                    {
                        return Some((idx, 2));
                    }
                    idx += 1;
                }
                b'/' => {
                    if idx > 0 && input[idx - 1] == b':' {
                        idx += 1;
                        continue;
                    }
                    if (idx == 0 || Self::is_boundary(input[idx - 1]))
                        && idx + 1 < input.len()
                        && !input[idx + 1].is_ascii_whitespace()
                    {
                        return Some((idx, 1));
                    }
                    idx += 1;
                }
                _ => {
                    idx += 1;
                }
            }
        }
        None
    }
}

impl Finder for Path {
    fn id(&self) -> &'static str {
        "path"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        matches!(byte, b'/' | b'.' | b'~')
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        let prefix_len = match input[pos] {
            b'~' if pos + 1 < input.len() && input[pos + 1] == b'/' => {
                if pos > 0 && !Self::is_boundary(input[pos - 1]) {
                    return None;
                }
                2
            }
            b'.' if pos + 2 < input.len()
                && input[pos + 1] == b'.'
                && input[pos + 2] == b'/' =>
            {
                if pos > 0 && !Self::is_boundary(input[pos - 1]) {
                    return None;
                }
                3
            }
            b'.' if pos + 1 < input.len() && input[pos + 1] == b'/' => {
                if pos > 0 && !Self::is_boundary(input[pos - 1]) {
                    return None;
                }
                2
            }
            b'/' => {
                if pos > 0 && input[pos - 1] == b':' {
                    return None;
                }
                if pos > 0 && !Self::is_boundary(input[pos - 1]) {
                    return None;
                }
                if pos + 1 >= input.len() || input[pos + 1].is_ascii_whitespace() {
                    return None;
                }
                1
            }
            _ => return None,
        };

        let start = pos;
        let mut end = pos + prefix_len;
        while end < input.len() && !input[end].is_ascii_whitespace() {
            end += 1;
        }
        while end > start + prefix_len
            && matches!(
                input[end - 1],
                b',' | b';' | b')' | b']' | b'}' | b'>' | b'\'' | b'"' | b'`'
            )
        {
            end -= 1;
        }
        while end > start + prefix_len && input[end - 1] == b':' {
            end -= 1;
        }
        while end > start + prefix_len && input[end - 1] == b'.' {
            end -= 1;
        }

        if end > start + prefix_len {
            Some(start..end)
        } else {
            None
        }
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut search_from = 0;

        while search_from < input.len() {
            let (start, prefix_len) = self.find_prefix(input, search_from)?;

            let mut end = start + prefix_len;
            while end < input.len() && !input[end].is_ascii_whitespace() {
                end += 1;
            }

            // Strip trailing punctuation that's likely sentence-level, not path-level
            while end > start + prefix_len
                && matches!(
                    input[end - 1],
                    b',' | b';' | b')' | b']' | b'}' | b'>' | b'\'' | b'"' | b'`'
                )
            {
                end -= 1;
            }
            // Strip trailing colons (but `:digits` line references are kept because
            // the colon won't be trailing — it's followed by digits)
            while end > start + prefix_len && input[end - 1] == b':' {
                end -= 1;
            }
            // Strip trailing periods (sentence endings)
            while end > start + prefix_len && input[end - 1] == b'.' {
                end -= 1;
            }

            if end > start + prefix_len {
                return Some(start..end);
            }

            search_from = start + 1;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_path() {
        let finder = Path::default();
        assert_eq!("path", finder.id());
    }

    // Absolute paths
    #[test]
    fn find_should_extract_absolute_path() {
        let finder = Path::default();
        let input = "see /etc/hosts for details";
        let range = finder.find(input).unwrap();
        assert_eq!("/etc/hosts", &input[range]);
    }

    #[test]
    fn find_should_extract_deep_absolute_path() {
        let finder = Path::default();
        let input = "binary at /usr/local/bin/squeeze";
        let range = finder.find(input).unwrap();
        assert_eq!("/usr/local/bin/squeeze", &input[range]);
    }

    #[test]
    fn find_should_extract_absolute_path_at_start() {
        let finder = Path::default();
        let input = "/var/log/syslog contains errors";
        let range = finder.find(input).unwrap();
        assert_eq!("/var/log/syslog", &input[range]);
    }

    // Relative paths
    #[test]
    fn find_should_extract_relative_path() {
        let finder = Path::default();
        let input = "edit ./src/main.rs to fix it";
        let range = finder.find(input).unwrap();
        assert_eq!("./src/main.rs", &input[range]);
    }

    #[test]
    fn find_should_extract_parent_relative_path() {
        let finder = Path::default();
        let input = "see ../README.md";
        let range = finder.find(input).unwrap();
        assert_eq!("../README.md", &input[range]);
    }

    #[test]
    fn find_should_extract_home_path() {
        let finder = Path::default();
        let input = "config at ~/config/settings.json";
        let range = finder.find(input).unwrap();
        assert_eq!("~/config/settings.json", &input[range]);
    }

    // Line references
    #[test]
    fn find_should_include_line_number() {
        let finder = Path::default();
        let input = "error in ./src/main.rs:42 here";
        let range = finder.find(input).unwrap();
        assert_eq!("./src/main.rs:42", &input[range]);
    }

    #[test]
    fn find_should_include_line_and_column() {
        let finder = Path::default();
        let input = "error at ./src/main.rs:42:10 found";
        let range = finder.find(input).unwrap();
        assert_eq!("./src/main.rs:42:10", &input[range]);
    }

    // Punctuation stripping
    #[test]
    fn find_should_strip_trailing_comma() {
        let finder = Path::default();
        let input = "files /etc/hosts, /etc/passwd";
        let range = finder.find(input).unwrap();
        assert_eq!("/etc/hosts", &input[range]);
    }

    #[test]
    fn find_should_strip_trailing_period() {
        let finder = Path::default();
        let input = "see /etc/hosts.";
        let range = finder.find(input).unwrap();
        assert_eq!("/etc/hosts", &input[range]);
    }

    #[test]
    fn find_should_strip_trailing_paren() {
        let finder = Path::default();
        let input = "(see /etc/hosts)";
        let range = finder.find(input).unwrap();
        assert_eq!("/etc/hosts", &input[range]);
    }

    #[test]
    fn find_should_strip_trailing_colon() {
        let finder = Path::default();
        let input = "/etc/hosts: permission denied";
        let range = finder.find(input).unwrap();
        assert_eq!("/etc/hosts", &input[range]);
    }

    // Should NOT match
    #[test]
    fn find_should_not_match_uri_path() {
        let finder = Path::default();
        assert!(finder.find("https://example.com/path").is_none());
    }

    #[test]
    fn find_should_not_match_bare_slash() {
        let finder = Path::default();
        assert!(finder.find("a / b").is_none());
    }

    #[test]
    fn find_should_not_match_empty_input() {
        let finder = Path::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_not_match_no_paths() {
        let finder = Path::default();
        assert!(finder.find("just some text").is_none());
    }

    // Iterative extraction
    #[test]
    fn find_should_extract_multiple_paths_iteratively() {
        let finder = Path::default();
        let input = "copy /etc/hosts to /tmp/hosts";

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

        assert_eq!(vec!["/etc/hosts", "/tmp/hosts"], results);
    }

    // Path in quotes/brackets
    #[test]
    fn find_should_extract_path_in_quotes() {
        let finder = Path::default();
        let input = r#"open "/var/log/app.log" now"#;
        let range = finder.find(input).unwrap();
        assert_eq!("/var/log/app.log", &input[range]);
    }

    #[test]
    fn find_should_extract_path_in_brackets() {
        let finder = Path::default();
        let input = "see [/etc/config] for details";
        let range = finder.find(input).unwrap();
        assert_eq!("/etc/config", &input[range]);
    }

    #[test]
    fn find_should_extract_path_in_backticks() {
        let finder = Path::default();
        let input = "run `./script.sh` to start";
        let range = finder.find(input).unwrap();
        assert_eq!("./script.sh", &input[range]);
    }

    // Dotfiles
    #[test]
    fn find_should_handle_dotfiles() {
        let finder = Path::default();
        let input = "edit ~/.bashrc for settings";
        let range = finder.find(input).unwrap();
        assert_eq!("~/.bashrc", &input[range]);
    }

    #[test]
    fn find_should_handle_hidden_dirs() {
        let finder = Path::default();
        let input = "see ~/.config/app/settings.toml";
        let range = finder.find(input).unwrap();
        assert_eq!("~/.config/app/settings.toml", &input[range]);
    }

    // Extension preservation
    #[test]
    fn find_should_preserve_file_extension() {
        let finder = Path::default();
        let input = "compile ./src/lib.rs now";
        let range = finder.find(input).unwrap();
        assert_eq!("./src/lib.rs", &input[range]);
    }

    #[test]
    fn find_should_handle_multiple_extensions() {
        let finder = Path::default();
        let input = "extract /archive/data.tar.gz here";
        let range = finder.find(input).unwrap();
        assert_eq!("/archive/data.tar.gz", &input[range]);
    }

    #[test]
    fn find_should_not_match_mid_word_slash() {
        let finder = Path::default();
        assert!(finder.find("and/or").is_none());
    }

    // Slash followed by space should not match
    #[test]
    fn find_should_not_match_slash_space() {
        let finder = Path::default();
        assert!(finder.find("/ foo").is_none());
    }

    #[test]
    fn try_at_absolute_path() {
        let finder = Path::default();
        let input = b"/etc/hosts rest";
        assert_eq!(finder.try_at(input, 0), Some(0..10));
    }

    #[test]
    fn try_at_relative_path() {
        let finder = Path::default();
        let input = b"./src/main.rs rest";
        assert_eq!(finder.try_at(input, 0), Some(0..13));
    }

    #[test]
    fn try_at_parent_path() {
        let finder = Path::default();
        let input = b"../README.md rest";
        assert_eq!(finder.try_at(input, 0), Some(0..12));
    }

    #[test]
    fn try_at_home_path() {
        let finder = Path::default();
        let input = b"~/.bashrc rest";
        assert_eq!(finder.try_at(input, 0), Some(0..9));
    }

    #[test]
    fn try_at_rejects_mid_word() {
        let finder = Path::default();
        let input = b"and/or";
        assert!(finder.try_at(input, 3).is_none());
    }

    #[test]
    fn try_at_slash_at_end() {
        let finder = Path::default();
        let input = b"/";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn try_at_tilde_no_slash() {
        let finder = Path::default();
        let input = b"~x";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn try_at_dot_no_slash() {
        let finder = Path::default();
        let input = b".x";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn find_strips_trailing_multiple_periods() {
        let finder = Path::default();
        let input = "/etc/hosts...";
        let range = finder.find(input).unwrap();
        assert_eq!("/etc/hosts", &input[range]);
    }

    #[test]
    fn find_preserves_internal_dots() {
        let finder = Path::default();
        let input = "/path/to/file.tar.gz more";
        let range = finder.find(input).unwrap();
        assert_eq!("/path/to/file.tar.gz", &input[range]);
    }

    #[test]
    fn find_strips_trailing_colons() {
        let finder = Path::default();
        let input = "/etc/hosts: error";
        let range = finder.find(input).unwrap();
        assert_eq!("/etc/hosts", &input[range]);
    }
}
