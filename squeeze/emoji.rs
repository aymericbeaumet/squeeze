use super::Finder;
use std::ops::Range;

/// UTF-8 encoding of U+FE0E VARIATION SELECTOR-15 (text presentation).
const VS15_BYTES: [u8; 3] = [0xEF, 0xB8, 0x8E];
/// UTF-8 encoding of U+FE0F VARIATION SELECTOR-16 (emoji presentation).
const VS16_BYTES: [u8; 3] = [0xEF, 0xB8, 0x8F];
/// UTF-8 encoding of U+20E3 COMBINING ENCLOSING KEYCAP.
const KEYCAP_BYTES: [u8; 3] = [0xE2, 0x83, 0xA3];

/// Codepoints with `Emoji_Presentation=Yes` per UTS #51 (plus all SMP
/// `Emoji=Yes` pictographs, which are unambiguous, and the commonly
/// emoji-rendered negative-squared letters 1F170/1F171/1F17E/1F17F).
/// These match bare, without requiring a variation selector.
///
/// Sorted, inclusive, non-overlapping ranges for binary search.
const EMOJI_PRESENTATION: &[(u32, u32)] = &[
    (0x231A, 0x231B),
    (0x23E9, 0x23EC),
    (0x23F0, 0x23F0),
    (0x23F3, 0x23F3),
    (0x25FD, 0x25FE),
    (0x2614, 0x2615),
    (0x2648, 0x2653),
    (0x267F, 0x267F),
    (0x2693, 0x2693),
    (0x26A1, 0x26A1),
    (0x26AA, 0x26AB),
    (0x26BD, 0x26BE),
    (0x26C4, 0x26C5),
    (0x26CE, 0x26CE),
    (0x26D4, 0x26D4),
    (0x26EA, 0x26EA),
    (0x26F2, 0x26F3),
    (0x26F5, 0x26F5),
    (0x26FA, 0x26FA),
    (0x26FD, 0x26FD),
    (0x2705, 0x2705),
    (0x270A, 0x270B),
    (0x2728, 0x2728),
    (0x274C, 0x274C),
    (0x274E, 0x274E),
    (0x2753, 0x2755),
    (0x2757, 0x2757),
    (0x2795, 0x2797),
    (0x27B0, 0x27B0),
    (0x27BF, 0x27BF),
    (0x2B1B, 0x2B1C),
    (0x2B50, 0x2B50),
    (0x2B55, 0x2B55),
    (0x1F004, 0x1F004),
    (0x1F0CF, 0x1F0CF),
    (0x1F170, 0x1F171),
    (0x1F17E, 0x1F17F),
    (0x1F18E, 0x1F18E),
    (0x1F191, 0x1F19A),
    (0x1F1E6, 0x1F1FF),
    (0x1F201, 0x1F202),
    (0x1F21A, 0x1F21A),
    (0x1F22F, 0x1F22F),
    (0x1F232, 0x1F23A),
    (0x1F250, 0x1F251),
    (0x1F300, 0x1F321),
    (0x1F324, 0x1F393),
    (0x1F396, 0x1F397),
    (0x1F399, 0x1F39B),
    (0x1F39E, 0x1F3F0),
    (0x1F3F3, 0x1F3F5),
    (0x1F3F7, 0x1F4FD),
    (0x1F4FF, 0x1F53D),
    (0x1F549, 0x1F54E),
    (0x1F550, 0x1F567),
    (0x1F56F, 0x1F570),
    (0x1F573, 0x1F57A),
    (0x1F587, 0x1F587),
    (0x1F58A, 0x1F58D),
    (0x1F590, 0x1F590),
    (0x1F595, 0x1F596),
    (0x1F5A4, 0x1F5A5),
    (0x1F5A8, 0x1F5A8),
    (0x1F5B1, 0x1F5B2),
    (0x1F5BC, 0x1F5BC),
    (0x1F5C2, 0x1F5C4),
    (0x1F5D1, 0x1F5D3),
    (0x1F5DC, 0x1F5DE),
    (0x1F5E1, 0x1F5E1),
    (0x1F5E3, 0x1F5E3),
    (0x1F5E8, 0x1F5E8),
    (0x1F5EF, 0x1F5EF),
    (0x1F5F3, 0x1F5F3),
    (0x1F5FA, 0x1F64F),
    (0x1F680, 0x1F6C5),
    (0x1F6CB, 0x1F6D2),
    (0x1F6D5, 0x1F6D7),
    (0x1F6DC, 0x1F6E5),
    (0x1F6E9, 0x1F6E9),
    (0x1F6EB, 0x1F6EC),
    (0x1F6F0, 0x1F6F0),
    (0x1F6F3, 0x1F6FC),
    (0x1F7E0, 0x1F7EB),
    (0x1F7F0, 0x1F7F0),
    (0x1F90C, 0x1F93A),
    (0x1F93C, 0x1F945),
    (0x1F947, 0x1F9FF),
    (0x1FA70, 0x1FA7C),
    (0x1FA80, 0x1FA88),
    (0x1FA90, 0x1FABD),
    (0x1FABF, 0x1FAC5),
    (0x1FACE, 0x1FADB),
    (0x1FAE0, 0x1FAE8),
    (0x1FAF0, 0x1FAF8),
];

/// Codepoints that are `Emoji=Yes` but `Emoji_Presentation=No` per UTS #51:
/// they render as text by default and only count as emoji when immediately
/// followed by VS16 (U+FE0F). Bare `™`, `©`, `☀`, `✔`, ... are everyday text.
///
/// Sorted, inclusive, non-overlapping ranges for binary search.
const TEXT_DEFAULT_EMOJI: &[(u32, u32)] = &[
    (0x00A9, 0x00A9),
    (0x00AE, 0x00AE),
    (0x203C, 0x203C),
    (0x2049, 0x2049),
    (0x2122, 0x2122),
    (0x2139, 0x2139),
    (0x2194, 0x2199),
    (0x21A9, 0x21AA),
    (0x2328, 0x2328),
    (0x23CF, 0x23CF),
    (0x23ED, 0x23EF),
    (0x23F1, 0x23F2),
    (0x23F8, 0x23FA),
    (0x24C2, 0x24C2),
    (0x25AA, 0x25AB),
    (0x25B6, 0x25B6),
    (0x25C0, 0x25C0),
    (0x25FB, 0x25FC),
    (0x2600, 0x2604),
    (0x260E, 0x260E),
    (0x2611, 0x2611),
    (0x2618, 0x2618),
    (0x261D, 0x261D),
    (0x2620, 0x2620),
    (0x2622, 0x2623),
    (0x2626, 0x2626),
    (0x262A, 0x262A),
    (0x262E, 0x262F),
    (0x2638, 0x263A),
    (0x2640, 0x2640),
    (0x2642, 0x2642),
    (0x265F, 0x2660),
    (0x2663, 0x2663),
    (0x2665, 0x2666),
    (0x2668, 0x2668),
    (0x267B, 0x267B),
    (0x267E, 0x267E),
    (0x2692, 0x2692),
    (0x2694, 0x2697),
    (0x2699, 0x2699),
    (0x269B, 0x269C),
    (0x26A0, 0x26A0),
    (0x26A7, 0x26A7),
    (0x26B0, 0x26B1),
    (0x26C8, 0x26C8),
    (0x26CF, 0x26CF),
    (0x26D1, 0x26D1),
    (0x26D3, 0x26D3),
    (0x26E9, 0x26E9),
    (0x26F0, 0x26F1),
    (0x26F4, 0x26F4),
    (0x26F7, 0x26F9),
    (0x2702, 0x2702),
    (0x2708, 0x2709),
    (0x270C, 0x270D),
    (0x270F, 0x270F),
    (0x2712, 0x2712),
    (0x2714, 0x2714),
    (0x2716, 0x2716),
    (0x271D, 0x271D),
    (0x2721, 0x2721),
    (0x2733, 0x2734),
    (0x2744, 0x2744),
    (0x2747, 0x2747),
    (0x2763, 0x2764),
    (0x27A1, 0x27A1),
    (0x2934, 0x2935),
    (0x2B05, 0x2B07),
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3297),
    (0x3299, 0x3299),
];

#[derive(Default)]
pub struct Emoji {}

impl Emoji {
    fn in_table(table: &[(u32, u32)], cp: u32) -> bool {
        table
            .binary_search_by(|&(lo, hi)| {
                if hi < cp {
                    std::cmp::Ordering::Less
                } else if lo > cp {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Matches bare (emoji presentation by default).
    fn is_emoji_presentation(c: char) -> bool {
        Self::in_table(EMOJI_PRESENTATION, c as u32)
    }

    /// Matches only when immediately followed by VS16 (U+FE0F).
    fn is_text_default_emoji(c: char) -> bool {
        Self::in_table(TEXT_DEFAULT_EMOJI, c as u32)
    }

    /// A char that may continue a ZWJ chain.
    fn is_pictographic(c: char) -> bool {
        Self::is_emoji_presentation(c) || Self::is_text_default_emoji(c)
    }

    /// Keycap bases match only as part of a keycap sequence, never bare.
    fn is_keycap_base(byte: u8) -> bool {
        matches!(byte, b'0'..=b'9' | b'#' | b'*')
    }

    fn is_regional_indicator(c: char) -> bool {
        (0x1F1E6..=0x1F1FF).contains(&(c as u32))
    }

    fn is_skin_tone(c: char) -> bool {
        (0x1F3FB..=0x1F3FF).contains(&(c as u32))
    }

    fn is_tag_char(c: char) -> bool {
        (0xE0020..=0xE007E).contains(&(c as u32))
    }

    fn is_tag_cancel(c: char) -> bool {
        c == '\u{E007F}'
    }

    /// Decode the single char whose UTF-8 sequence starts at `pos`.
    ///
    /// O(1): validates at most 4 bytes, never the rest of the input. Returns
    /// `None` at end of input, on a continuation/invalid lead byte, or on a
    /// truncated/overlong sequence, so `try_at` stays safe on arbitrary bytes.
    fn decode_char(input: &[u8], pos: usize) -> Option<(char, usize)> {
        let lead = *input.get(pos)?;
        let len = match lead {
            0x00..=0x7F => 1,
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return None,
        };
        let bytes = input.get(pos..pos.checked_add(len)?)?;
        let c = std::str::from_utf8(bytes).ok()?.chars().next()?;
        Some((c, len))
    }

    /// Whether the 3 bytes at `pos` are exactly `pat` (O(1) byte compare).
    fn bytes_at(input: &[u8], pos: usize, pat: &[u8; 3]) -> bool {
        pos.checked_add(3)
            .and_then(|end| input.get(pos..end))
            .is_some_and(|window| window == pat)
    }

    /// Match a keycap sequence at `pos`: base + optional U+FE0F + U+20E3.
    /// Pure byte comparisons so digit-heavy lines bail out in O(1).
    fn keycap_len(input: &[u8], pos: usize) -> Option<usize> {
        if Self::bytes_at(input, pos + 1, &KEYCAP_BYTES) {
            return Some(1 + KEYCAP_BYTES.len());
        }
        if Self::bytes_at(input, pos + 1, &VS16_BYTES)
            && Self::bytes_at(input, pos + 1 + VS16_BYTES.len(), &KEYCAP_BYTES)
        {
            return Some(1 + VS16_BYTES.len() + KEYCAP_BYTES.len());
        }
        None
    }

    /// Length of the emoji (sequence) starting exactly at `pos`, if any.
    ///
    /// This is the single source of truth used by both `find` and `try_at`,
    /// which keeps the two dispatch paths in exact parity. It only ever looks
    /// forward from `pos` and decodes incrementally, so the cost is O(1) for
    /// a non-match and O(sequence length) for a match.
    fn match_len_at(input: &[u8], pos: usize) -> Option<usize> {
        let lead = *input.get(pos)?;

        if lead.is_ascii() {
            if !Self::is_keycap_base(lead) {
                return None;
            }
            return Self::keycap_len(input, pos);
        }

        let (first, first_len) = Self::decode_char(input, pos)?;
        let after = pos + first_len;

        if Self::is_emoji_presentation(first) {
            // VS15 explicitly demotes the char to text presentation: no
            // match, and the selector is skipped along with its base.
            if Self::bytes_at(input, after, &VS15_BYTES) {
                return None;
            }
            return Some(Self::consume_sequence(input, pos, first, first_len));
        }

        if Self::is_text_default_emoji(first) && Self::bytes_at(input, after, &VS16_BYTES) {
            return Some(Self::consume_sequence(input, pos, first, first_len));
        }

        None
    }

    /// Extend a confirmed emoji at `pos` over its full sequence (RI pairs,
    /// tag sequences, VS16, skin tones, ZWJ chains). Returns the total length.
    fn consume_sequence(input: &[u8], pos: usize, first: char, first_len: usize) -> usize {
        let mut end = pos + first_len;

        if Self::is_regional_indicator(first) {
            if let Some((c, len)) = Self::decode_char(input, end)
                && Self::is_regional_indicator(c)
            {
                end += len;
            }
            return end - pos;
        }

        if first == '\u{1F3F4}' {
            let mut cursor = end;
            let mut has_tags = false;
            loop {
                match Self::decode_char(input, cursor) {
                    Some((c, len)) if Self::is_tag_char(c) => {
                        has_tags = true;
                        cursor += len;
                    }
                    Some((c, len)) if Self::is_tag_cancel(c) => {
                        has_tags = true;
                        cursor += len;
                        break;
                    }
                    _ => break,
                }
            }
            if has_tags {
                return cursor - pos;
            }
        }

        loop {
            if let Some((c, len)) = Self::decode_char(input, end)
                && c == '\u{FE0F}'
            {
                end += len;
            }

            if let Some((c, len)) = Self::decode_char(input, end)
                && Self::is_skin_tone(c)
            {
                end += len;
            }

            if let Some((c, zwj_len)) = Self::decode_char(input, end)
                && c == '\u{200D}'
                && let Some((next, next_len)) = Self::decode_char(input, end + zwj_len)
                && Self::is_pictographic(next)
            {
                end += zwj_len + next_len;
                continue;
            }

            break;
        }

        end - pos
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
        // 0xC2: © ®; 0xE2: U+2000-2FFF symbols and U+20E3-bearing keycaps;
        // 0xE3: U+3030/303D/3297/3299; 0xF0: all SMP pictographs;
        // ASCII digits/#/*: keycap sequence bases.
        matches!(byte, 0xC2 | 0xE2 | 0xE3 | 0xF0) || Self::is_keycap_base(byte)
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        let len = Self::match_len_at(input, pos)?;
        Some(pos..pos + len)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        for (byte_pos, _) in s.char_indices() {
            if let Some(len) = Self::match_len_at(input, byte_pos) {
                return Some(byte_pos..byte_pos + len);
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
    fn tables_are_sorted_and_disjoint() {
        for table in [EMOJI_PRESENTATION, TEXT_DEFAULT_EMOJI] {
            let mut prev_hi: Option<u32> = None;
            for &(lo, hi) in table {
                assert!(lo <= hi, "range {lo:#X}..={hi:#X} is reversed");
                if let Some(p) = prev_hi {
                    assert!(p < lo, "range starting at {lo:#X} overlaps or is unsorted");
                }
                prev_hi = Some(hi);
            }
        }
        // The two tiers must not overlap each other.
        for &(lo, hi) in TEXT_DEFAULT_EMOJI {
            for cp in lo..=hi {
                assert!(
                    !Emoji::in_table(EMOJI_PRESENTATION, cp),
                    "{cp:#X} is in both tiers"
                );
            }
        }
    }

    #[test]
    fn in_table_hits_boundaries_and_rejects_gaps() {
        for cp in [0x231A, 0x231B, 0x2B55, 0x1F004, 0x1F600, 0x1FAF8] {
            assert!(Emoji::in_table(EMOJI_PRESENTATION, cp), "{cp:#X}");
        }
        for cp in [0x2605, 0x2713, 0x2717, 0x1F000, 0x1F031, 0x1FAF9, 0x0041] {
            assert!(!Emoji::in_table(EMOJI_PRESENTATION, cp), "{cp:#X}");
            assert!(!Emoji::in_table(TEXT_DEFAULT_EMOJI, cp), "{cp:#X}");
        }
        for cp in [0x00A9, 0x00AE, 0x2122, 0x2600, 0x2764, 0x3299] {
            assert!(Emoji::in_table(TEXT_DEFAULT_EMOJI, cp), "{cp:#X}");
        }
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
        let input = "flag 🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F} end";
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
    fn find_should_extract_misc_symbol_with_vs16_only() {
        // Pin flipped with the UTS #51 tables: U+2600 is text-default, so
        // bare `☀` is plain text and only `☀️` (with VS16) is an emoji.
        let finder = Emoji::default();
        assert!(finder.find("sun ☀ here").is_none());
        let input = "sun ☀\u{FE0F} here";
        let range = finder.find(input).unwrap();
        assert_eq!("☀\u{FE0F}", &input[range]);
    }

    #[test]
    fn find_should_extract_dingbat_with_vs16_only() {
        // Pin flipped: U+2702 is text-default (was matched bare before).
        let finder = Emoji::default();
        assert!(finder.find("check ✂ here").is_none());
        let input = "check ✂\u{FE0F} here";
        let range = finder.find(input).unwrap();
        assert_eq!("✂\u{FE0F}", &input[range]);
    }

    #[test]
    fn find_should_extract_supplemental_arrow_with_vs16_only() {
        // Pin flipped: U+27A1 is text-default (was matched bare before).
        let finder = Emoji::default();
        assert!(finder.find("go ➡ there").is_none());
        let input = "go ➡\u{FE0F} there";
        let range = finder.find(input).unwrap();
        assert_eq!("➡\u{FE0F}", &input[range]);
    }

    #[test]
    fn find_should_extract_emoji_in_brackets() {
        let finder = Emoji::default();
        let input = "[😀]";
        let range = finder.find(input).unwrap();
        assert_eq!("😀", &input[range]);
    }

    // --- Regression: try_at with unchecked UTF-8 ---

    #[test]
    fn try_at_simple_emoji() {
        let finder = Emoji::default();
        let input = "😀 rest".as_bytes();
        let range = finder.try_at(input, 0).unwrap();
        assert_eq!(range, 0..4);
    }

    #[test]
    fn try_at_emoji_after_ascii() {
        let finder = Emoji::default();
        let input = "hi 😀 rest";
        let bytes = input.as_bytes();
        let range = finder.try_at(bytes, 3).unwrap();
        assert_eq!(&input[range], "😀");
    }

    #[test]
    fn try_at_emoji_with_skin_tone() {
        let finder = Emoji::default();
        let input = "👋🏽";
        let bytes = input.as_bytes();
        let range = finder.try_at(bytes, 0).unwrap();
        assert_eq!(&input[range], "👋🏽");
    }

    #[test]
    fn try_at_non_emoji_multibyte() {
        let finder = Emoji::default();
        let input = "héllo";
        let bytes = input.as_bytes();
        assert!(finder.try_at(bytes, 0).is_none());
    }

    #[test]
    fn try_at_zwj_sequence_via_dispatch() {
        let finder = Emoji::default();
        let input = "👨\u{200D}👩\u{200D}👧";
        let bytes = input.as_bytes();
        let range = finder.try_at(bytes, 0).unwrap();
        assert_eq!(&input[range], "👨\u{200D}👩\u{200D}👧");
    }

    #[test]
    fn try_at_flag_sequence() {
        let finder = Emoji::default();
        let input = "🇺🇸";
        let bytes = input.as_bytes();
        let range = finder.try_at(bytes, 0).unwrap();
        assert_eq!(&input[range], "🇺🇸");
    }

    #[test]
    fn try_at_mid_zwj_matches_and_scanner_suppresses() {
        // Pin flipped: the old preceding-ZWJ veto made this return None, which
        // broke find()/try_at parity on dangling ZWJs. try_at only looks
        // forward; positions inside an already-consumed sequence are skipped
        // by the Scanner via finder_pos, not by the finder itself.
        let finder = Emoji::default();
        let input = "👨\u{200D}👩";
        let bytes = input.as_bytes();
        let emoji2_start = "👨\u{200D}".len();
        assert_eq!(
            finder.try_at(bytes, emoji2_start),
            Some(emoji2_start..input.len())
        );
    }
}
