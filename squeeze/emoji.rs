use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Emoji {}

impl Emoji {
    fn is_emoji(c: char) -> bool {
        let cp = c as u32;
        if (0x1F000..=0x1FAFF).contains(&cp) {
            return true;
        }
        if (0x2600..=0x27BF).contains(&cp) {
            return true;
        }
        matches!(
            cp,
            0x203C
                | 0x2049
                | 0x2122
                | 0x2139
                | 0x2194..=0x2199
                | 0x21A9..=0x21AA
                | 0x231A..=0x231B
                | 0x2328
                | 0x23CF
                | 0x23E9..=0x23F3
                | 0x23F8..=0x23FA
                | 0x24C2
                | 0x25AA..=0x25AB
                | 0x25B6
                | 0x25C0
                | 0x25FB..=0x25FE
                | 0x2934..=0x2935
                | 0x2B05..=0x2B07
                | 0x2B1B..=0x2B1C
                | 0x2B50
                | 0x2B55
                | 0x3030
                | 0x303D
                | 0x3297
                | 0x3299
        )
    }

    fn is_regional_indicator(c: char) -> bool {
        (0x1F1E6..=0x1F1FF).contains(&(c as u32))
    }

    fn is_skin_tone(c: char) -> bool {
        (0x1F3FB..=0x1F3FF).contains(&(c as u32))
    }

    fn is_zwj(c: char) -> bool {
        c == '\u{200D}'
    }

    fn is_variation_selector(c: char) -> bool {
        c == '\u{FE0F}'
    }

    fn is_tag_char(c: char) -> bool {
        (0xE0020..=0xE007E).contains(&(c as u32))
    }

    fn is_tag_cancel(c: char) -> bool {
        c == '\u{E007F}'
    }

    fn consume_sequence(s: &str) -> usize {
        let mut iter = s.char_indices().peekable();

        let first = match iter.next() {
            Some((_, c)) => c,
            None => return 0,
        };

        let mut end = first.len_utf8();

        if Self::is_regional_indicator(first) {
            if let Some(&(pos, c)) = iter.peek() {
                if Self::is_regional_indicator(c) {
                    end = pos + c.len_utf8();
                }
            }
            return end;
        }

        if first == '\u{1F3F4}' {
            let saved = iter.clone();
            let mut has_tags = false;
            let mut tag_end = end;
            loop {
                match iter.peek() {
                    Some(&(pos, c)) if Self::is_tag_char(c) => {
                        has_tags = true;
                        tag_end = pos + c.len_utf8();
                        iter.next();
                    }
                    Some(&(pos, c)) if Self::is_tag_cancel(c) => {
                        has_tags = true;
                        tag_end = pos + c.len_utf8();
                        iter.next();
                        break;
                    }
                    _ => break,
                }
            }
            if has_tags {
                return tag_end;
            }
            iter = saved;
        }

        loop {
            if let Some(&(pos, c)) = iter.peek() {
                if Self::is_variation_selector(c) {
                    end = pos + c.len_utf8();
                    iter.next();
                }
            }

            if let Some(&(pos, c)) = iter.peek() {
                if Self::is_skin_tone(c) {
                    end = pos + c.len_utf8();
                    iter.next();
                }
            }

            if let Some(&(_, c)) = iter.peek() {
                if Self::is_zwj(c) {
                    let mut peek = iter.clone();
                    peek.next();
                    if let Some(&(pos, c)) = peek.peek() {
                        if Self::is_emoji(c) && !Self::is_zwj(c) {
                            end = pos + c.len_utf8();
                            peek.next();
                            iter = peek;
                            continue;
                        }
                    }
                }
            }

            break;
        }

        end
    }
}

impl Finder for Emoji {
    fn id(&self) -> &'static str {
        "emoji"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        matches!(byte, 0xE2 | 0xE3 | 0xF0)
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        let s = std::str::from_utf8(&input[pos..]).ok()?;
        let c = s.chars().next()?;

        if !Self::is_emoji(c) || Self::is_zwj(c) {
            return None;
        }

        if pos > 0 {
            if let Ok(before) = std::str::from_utf8(&input[..pos]) {
                if let Some(prev) = before.chars().last() {
                    if Self::is_zwj(prev) {
                        return None;
                    }
                }
            }
        }

        let end = Self::consume_sequence(s);
        if end > 0 {
            Some(pos..pos + end)
        } else {
            None
        }
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        for (byte_pos, c) in s.char_indices() {
            if Self::is_emoji(c) && !Self::is_zwj(c) {
                let end = Self::consume_sequence(&s[byte_pos..]);
                if end > 0 {
                    return Some(byte_pos..byte_pos + end);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_emoji() {
        let finder = Emoji::default();
        assert_eq!("emoji", finder.id());
    }

    #[test]
    fn find_should_extract_simple_emoji() {
        let finder = Emoji::default();
        let input = "hello 😀 world";
        let range = finder.find(input).unwrap();
        assert_eq!("😀", &input[range]);
    }

    #[test]
    fn find_should_extract_emoji_at_start() {
        let finder = Emoji::default();
        let input = "🎉 party";
        let range = finder.find(input).unwrap();
        assert_eq!("🎉", &input[range]);
    }

    #[test]
    fn find_should_extract_emoji_at_end() {
        let finder = Emoji::default();
        let input = "done ✅";
        let range = finder.find(input).unwrap();
        assert_eq!("✅", &input[range]);
    }

    #[test]
    fn find_should_extract_emoji_with_skin_tone() {
        let finder = Emoji::default();
        let input = "wave 👋🏽 here";
        let range = finder.find(input).unwrap();
        assert_eq!("👋🏽", &input[range]);
    }

    #[test]
    fn find_should_extract_zwj_sequence() {
        let finder = Emoji::default();
        let input = "family 👨\u{200D}👩\u{200D}👧 end";
        let range = finder.find(input).unwrap();
        assert_eq!("👨\u{200D}👩\u{200D}👧", &input[range]);
    }

    #[test]
    fn find_should_extract_flag() {
        let finder = Emoji::default();
        let input = "flag 🇺🇸 end";
        let range = finder.find(input).unwrap();
        assert_eq!("🇺🇸", &input[range]);
    }

    #[test]
    fn find_should_extract_emoji_with_variation_selector() {
        let finder = Emoji::default();
        let input = "heart ❤\u{FE0F} end";
        let range = finder.find(input).unwrap();
        assert_eq!("❤\u{FE0F}", &input[range]);
    }

    #[test]
    fn find_should_extract_tag_sequence() {
        let finder = Emoji::default();
        let input =
            "flag 🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F} end";
        let range = finder.find(input).unwrap();
        assert_eq!(
            "🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}",
            &input[range]
        );
    }

    #[test]
    fn find_should_extract_zwj_with_skin_tone() {
        let finder = Emoji::default();
        let input = "👩🏽\u{200D}🔬 scientist";
        let range = finder.find(input).unwrap();
        assert_eq!("👩🏽\u{200D}🔬", &input[range]);
    }

    #[test]
    fn find_should_extract_zwj_with_variation_selector() {
        let finder = Emoji::default();
        let input = "❤\u{FE0F}\u{200D}🔥";
        let range = finder.find(input).unwrap();
        assert_eq!("❤\u{FE0F}\u{200D}🔥", &input[range]);
    }

    #[test]
    fn find_should_extract_multiple_emojis_iteratively() {
        let finder = Emoji::default();
        let input = "😀🎉✅";

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

        assert_eq!(vec!["😀", "🎉", "✅"], results);
    }

    #[test]
    fn find_should_extract_adjacent_flags() {
        let finder = Emoji::default();
        let input = "🇺🇸🇬🇧";

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

        assert_eq!(vec!["🇺🇸", "🇬🇧"], results);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Emoji::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_reject_plain_ascii() {
        let finder = Emoji::default();
        assert!(finder.find("hello world 123").is_none());
    }

    #[test]
    fn find_should_not_start_with_zwj() {
        let finder = Emoji::default();
        assert!(finder.find("\u{200D}hello").is_none());
    }

    #[test]
    fn find_should_extract_misc_symbol() {
        let finder = Emoji::default();
        let input = "sun ☀ here";
        let range = finder.find(input).unwrap();
        assert_eq!("☀", &input[range]);
    }

    #[test]
    fn find_should_extract_dingbat() {
        let finder = Emoji::default();
        let input = "check ✂ here";
        let range = finder.find(input).unwrap();
        assert_eq!("✂", &input[range]);
    }

    #[test]
    fn find_should_extract_supplemental_arrow() {
        let finder = Emoji::default();
        let input = "go ➡ there";
        let range = finder.find(input).unwrap();
        assert_eq!("➡", &input[range]);
    }

    #[test]
    fn find_should_extract_emoji_in_brackets() {
        let finder = Emoji::default();
        let input = "[😀]";
        let range = finder.find(input).unwrap();
        assert_eq!("😀", &input[range]);
    }
}
