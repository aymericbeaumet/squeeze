use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Color {}

impl Color {
    fn is_hex(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }

    fn try_hex_color(input: &[u8], pos: usize) -> Option<Range<usize>> {
        if input[pos] != b'#' {
            return None;
        }

        let start = pos;
        let after_hash = pos + 1;
        if after_hash >= input.len() || !Self::is_hex(input[after_hash]) {
            return None;
        }

        let mut hex_end = after_hash;
        while hex_end < input.len() && Self::is_hex(input[hex_end]) {
            hex_end += 1;
        }

        let hex_len = hex_end - after_hash;

        // Check boundary after: must not be followed by a hex digit
        let has_boundary = hex_end >= input.len() || !Self::is_hex(input[hex_end]);
        if !has_boundary {
            return None;
        }

        // Match longest valid: 8, 6, 4, 3
        for &valid_len in &[8, 6, 4, 3] {
            if hex_len == valid_len {
                return Some(start..after_hash + valid_len);
            }
        }

        None
    }

    fn try_css_function(input: &[u8], pos: usize) -> Option<Range<usize>> {
        let remaining = &input[pos..];

        let prefixes: &[&[u8]] = &[b"rgba(", b"rgb(", b"hsla(", b"hsl("];

        let mut matched_len = 0;
        for prefix in prefixes {
            if remaining.len() >= prefix.len()
                && remaining[..prefix.len()].eq_ignore_ascii_case(prefix)
            {
                matched_len = prefix.len();
                break;
            }
        }

        if matched_len == 0 {
            return None;
        }

        // Check boundary before: not preceded by alphanumeric
        if pos > 0 && input[pos - 1].is_ascii_alphanumeric() {
            return None;
        }

        let mut end = pos + matched_len;
        let mut depth = 1;

        while end < input.len() && depth > 0 {
            match input[end] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            end += 1;
        }

        if depth == 0 {
            Some(pos..end)
        } else {
            None
        }
    }
}

impl Finder for Color {
    fn id(&self) -> &'static str {
        "color"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        byte == b'#' || matches!(byte, b'r' | b'R' | b'h' | b'H')
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        if input[pos] == b'#' {
            if let Some(range) = Self::try_hex_color(input, pos) {
                return Some(range);
            }
        }
        if matches!(input[pos], b'r' | b'R' | b'h' | b'H') {
            if let Some(range) = Self::try_css_function(input, pos) {
                return Some(range);
            }
        }
        None
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            if input[idx] == b'#' {
                if let Some(range) = Self::try_hex_color(input, idx) {
                    return Some(range);
                }
            }

            if matches!(input[idx], b'r' | b'R' | b'h' | b'H') {
                if let Some(range) = Self::try_css_function(input, idx) {
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
    fn id_should_return_color() {
        let finder = Color::default();
        assert_eq!("color", finder.id());
    }

    // Hex colors
    #[test]
    fn find_should_extract_6_digit_hex() {
        let finder = Color::default();
        let input = "color: #ff00aa";
        let range = finder.find(input).unwrap();
        assert_eq!("#ff00aa", &input[range]);
    }

    #[test]
    fn find_should_extract_3_digit_hex() {
        let finder = Color::default();
        let input = "color: #f0a";
        let range = finder.find(input).unwrap();
        assert_eq!("#f0a", &input[range]);
    }

    #[test]
    fn find_should_extract_8_digit_hex() {
        let finder = Color::default();
        let input = "#ff00aa80 with alpha";
        let range = finder.find(input).unwrap();
        assert_eq!("#ff00aa80", &input[range]);
    }

    #[test]
    fn find_should_extract_4_digit_hex() {
        let finder = Color::default();
        let input = "#f0a8 short alpha";
        let range = finder.find(input).unwrap();
        assert_eq!("#f0a8", &input[range]);
    }

    #[test]
    fn find_should_extract_uppercase_hex() {
        let finder = Color::default();
        let input = "#FF00AA";
        let range = finder.find(input).unwrap();
        assert_eq!("#FF00AA", &input[range]);
    }

    #[test]
    fn find_should_reject_5_digit_hex() {
        let finder = Color::default();
        assert!(finder.find("#ff00a").is_none());
    }

    #[test]
    fn find_should_reject_1_digit_hex() {
        let finder = Color::default();
        assert!(finder.find("#f ").is_none());
    }

    #[test]
    fn find_should_reject_hash_with_non_hex() {
        let finder = Color::default();
        assert!(finder.find("#gghhii").is_none());
    }

    // CSS functions
    #[test]
    fn find_should_extract_rgb() {
        let finder = Color::default();
        let input = "color: rgb(255, 0, 170)";
        let range = finder.find(input).unwrap();
        assert_eq!("rgb(255, 0, 170)", &input[range]);
    }

    #[test]
    fn find_should_extract_rgba() {
        let finder = Color::default();
        let input = "rgba(255, 0, 170, 0.5)";
        let range = finder.find(input).unwrap();
        assert_eq!("rgba(255, 0, 170, 0.5)", &input[range]);
    }

    #[test]
    fn find_should_extract_hsl() {
        let finder = Color::default();
        let input = "hsl(120, 100%, 50%)";
        let range = finder.find(input).unwrap();
        assert_eq!("hsl(120, 100%, 50%)", &input[range]);
    }

    #[test]
    fn find_should_extract_hsla() {
        let finder = Color::default();
        let input = "hsla(120, 100%, 50%, 0.8)";
        let range = finder.find(input).unwrap();
        assert_eq!("hsla(120, 100%, 50%, 0.8)", &input[range]);
    }

    #[test]
    fn find_should_not_match_rgb_preceded_by_alpha() {
        let finder = Color::default();
        assert!(finder.find("srgb(1, 2, 3)").is_none());
    }

    #[test]
    fn find_should_reject_unclosed_rgb() {
        let finder = Color::default();
        assert!(finder.find("rgb(255, 0, 170").is_none());
    }

    // Multiple
    #[test]
    fn find_should_extract_multiple_colors_iteratively() {
        let finder = Color::default();
        let input = "#ff0000 and rgb(0, 255, 0)";

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

        assert_eq!(vec!["#ff0000", "rgb(0, 255, 0)"], results);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Color::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_hex_in_css() {
        let finder = Color::default();
        let input = "background-color: #333;";
        let range = finder.find(input).unwrap();
        assert_eq!("#333", &input[range]);
    }

    #[test]
    fn try_at_hex_color() {
        let finder = Color::default();
        let input = b"#ff00aa rest";
        assert_eq!(finder.try_at(input, 0), Some(0..7));
    }

    #[test]
    fn try_at_rgb_function() {
        let finder = Color::default();
        let input = b"rgb(255, 0, 0) rest";
        assert_eq!(finder.try_at(input, 0), Some(0..14));
    }

    #[test]
    fn try_at_hsl_function() {
        let finder = Color::default();
        let input = b"hsl(120, 100%, 50%) rest";
        assert_eq!(finder.try_at(input, 0), Some(0..19));
    }

    #[test]
    fn try_at_rejects_bare_hash() {
        let finder = Color::default();
        let input = b"# not a color";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn try_at_rejects_too_many_hex() {
        let finder = Color::default();
        let input = b"#123456789";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn find_css_case_insensitive() {
        let finder = Color::default();
        let input = "RGB(1, 2, 3)";
        assert!(finder.find(input).is_some());
        let input = "HSL(0, 0%, 0%)";
        assert!(finder.find(input).is_some());
    }

    #[test]
    fn find_hash_only() {
        let finder = Color::default();
        assert!(finder.find("#").is_none());
    }

    #[test]
    fn find_hash_two_hex() {
        let finder = Color::default();
        assert!(finder.find("#ab").is_none());
    }

    #[test]
    fn try_at_non_color_byte() {
        let finder = Color::default();
        let input = b"xyz";
        assert!(finder.try_at(input, 0).is_none());
    }
}
