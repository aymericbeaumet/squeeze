//! Word-boundary and Unicode class helpers shared by hand-written matchers
//! that replaced regexes; they mirror the regex crate's Unicode-aware `\b`,
//! `\d` and `\s`.

/// Byte length of the UTF-8 sequence introduced by `lead`.
#[inline]
pub(crate) fn utf8_width(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// The character starting at `pos` and its byte length.
#[inline]
pub(crate) fn char_at(input: &[u8], pos: usize) -> Option<(char, usize)> {
    let lead = *input.get(pos)?;
    if lead < 0x80 {
        return Some((lead as char, 1));
    }
    let width = utf8_width(lead);
    let end = pos.checked_add(width)?;
    let c = std::str::from_utf8(input.get(pos..end)?)
        .ok()?
        .chars()
        .next()?;
    Some((c, width))
}

/// The character ending right before `pos`.
#[inline]
pub(crate) fn char_before(input: &[u8], pos: usize) -> Option<char> {
    if pos == 0 {
        return None;
    }
    let last = input[pos - 1];
    if last < 0x80 {
        return Some(last as char);
    }
    let mut start = pos - 1;
    while start > 0 && pos - start < 4 && input[start] & 0xC0 == 0x80 {
        start -= 1;
    }
    char_at(input, start).map(|(c, _)| c)
}

/// Regex `\w`: alphanumerics, marks, connector punctuation and join
/// controls. Marks and connectors are approximated by their common blocks.
#[inline]
pub(crate) fn is_word_char(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric() || c == '_';
    }
    c.is_alphanumeric()
        || matches!(
            c,
            '\u{0300}'..='\u{036F}'
                | '\u{1AB0}'..='\u{1AFF}'
                | '\u{1DC0}'..='\u{1DFF}'
                | '\u{20D0}'..='\u{20FF}'
                | '\u{FE20}'..='\u{FE2F}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{203F}'
                | '\u{2040}'
                | '\u{2054}'
                | '\u{FE33}'
                | '\u{FE34}'
                | '\u{FE4D}'..='\u{FE4F}'
                | '\u{FF3F}'
        )
}

/// Regex `\b` before `pos`: the previous character is not a word
/// character (or there is none).
#[inline]
pub(crate) fn boundary_before(input: &[u8], pos: usize) -> bool {
    match char_before(input, pos) {
        None => true,
        Some(c) => !is_word_char(c),
    }
}

/// Regex `\b` at `pos` looking forward: the character at `pos` is not a
/// word character (or the input ends).
#[inline]
pub(crate) fn boundary_after(input: &[u8], pos: usize) -> bool {
    match char_at(input, pos) {
        None => true,
        Some((c, _)) => !is_word_char(c),
    }
}

/// Unicode `Nd` (decimal digit) ranges, as matched by regex `\d`.
const DECIMAL_DIGIT_RANGES: &[(u32, u32)] = &[
    (0x0030, 0x0039),
    (0x0660, 0x0669),
    (0x06F0, 0x06F9),
    (0x07C0, 0x07C9),
    (0x0966, 0x096F),
    (0x09E6, 0x09EF),
    (0x0A66, 0x0A6F),
    (0x0AE6, 0x0AEF),
    (0x0B66, 0x0B6F),
    (0x0BE6, 0x0BEF),
    (0x0C66, 0x0C6F),
    (0x0CE6, 0x0CEF),
    (0x0D66, 0x0D6F),
    (0x0DE6, 0x0DEF),
    (0x0E50, 0x0E59),
    (0x0ED0, 0x0ED9),
    (0x0F20, 0x0F29),
    (0x1040, 0x1049),
    (0x1090, 0x1099),
    (0x17E0, 0x17E9),
    (0x1810, 0x1819),
    (0x1946, 0x194F),
    (0x19D0, 0x19D9),
    (0x1A80, 0x1A89),
    (0x1A90, 0x1A99),
    (0x1B50, 0x1B59),
    (0x1BB0, 0x1BB9),
    (0x1C40, 0x1C49),
    (0x1C50, 0x1C59),
    (0xA620, 0xA629),
    (0xA8D0, 0xA8D9),
    (0xA900, 0xA909),
    (0xA9D0, 0xA9D9),
    (0xA9F0, 0xA9F9),
    (0xAA50, 0xAA59),
    (0xABF0, 0xABF9),
    (0xFF10, 0xFF19),
    (0x104A0, 0x104A9),
    (0x10D30, 0x10D39),
    (0x11066, 0x1106F),
    (0x110F0, 0x110F9),
    (0x11136, 0x1113F),
    (0x111D0, 0x111D9),
    (0x112F0, 0x112F9),
    (0x11450, 0x11459),
    (0x114D0, 0x114D9),
    (0x11650, 0x11659),
    (0x116C0, 0x116C9),
    (0x11730, 0x11739),
    (0x118E0, 0x118E9),
    (0x11950, 0x11959),
    (0x11C50, 0x11C59),
    (0x11D50, 0x11D59),
    (0x11DA0, 0x11DA9),
    (0x11F50, 0x11F59),
    (0x16A60, 0x16A69),
    (0x16AC0, 0x16AC9),
    (0x16B50, 0x16B59),
    (0x1D7CE, 0x1D7FF),
    (0x1E140, 0x1E149),
    (0x1E2F0, 0x1E2F9),
    (0x1E4F0, 0x1E4F9),
    (0x1E950, 0x1E959),
    (0x1FBF0, 0x1FBF9),
];

/// Regex `\d` at `pos`: the byte length of the decimal digit there.
#[inline]
pub(crate) fn digit_at(input: &[u8], pos: usize) -> Option<usize> {
    let lead = *input.get(pos)?;
    if lead < 0x80 {
        return lead.is_ascii_digit().then_some(1);
    }
    let (c, width) = char_at(input, pos)?;
    let code = c as u32;
    DECIMAL_DIGIT_RANGES
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&code))
        .then_some(width)
}

/// Whether `lead` can begin a `\d` character.
pub(crate) fn digit_lead_bytes() -> impl Iterator<Item = u8> {
    let mut leads = [false; 256];
    for &(lo, hi) in DECIMAL_DIGIT_RANGES {
        for code in lo..=hi {
            if let Some(c) = char::from_u32(code) {
                let mut buf = [0u8; 4];
                leads[c.encode_utf8(&mut buf).as_bytes()[0] as usize] = true;
            }
        }
    }
    (0..=255u8).filter(move |&b| leads[b as usize])
}

/// Regex `\s` at `pos`: the byte length of the whitespace there.
#[inline]
pub(crate) fn space_at(input: &[u8], pos: usize) -> Option<usize> {
    let lead = *input.get(pos)?;
    if lead < 0x80 {
        return matches!(lead, b'\t' | b'\n' | 0x0B | 0x0C | b'\r' | b' ').then_some(1);
    }
    let (c, width) = char_at(input, pos)?;
    matches!(
        c,
        '\u{0085}' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
    .then_some(width)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_follow_word_characters() {
        let s = "a_ é1 😀x".as_bytes();
        assert!(boundary_before(s, 0));
        assert!(!boundary_before(s, 1));
        assert!(!boundary_before(s, 2));
        assert!(boundary_before(s, 3));
        assert!(!boundary_before(s, 5)); // after é
        assert!(boundary_after(s, 6)); // space
        assert!(boundary_after(s, 7)); // emoji
        assert!(!boundary_after(s, 11)); // x
        assert!(boundary_after(s, 12)); // end
    }

    #[test]
    fn digits_and_spaces_follow_unicode_classes() {
        let s = "5٣３ \u{a0}x".as_bytes();
        assert_eq!(digit_at(s, 0), Some(1));
        assert_eq!(digit_at(s, 1), Some(2));
        assert_eq!(digit_at(s, 3), Some(3));
        assert_eq!(digit_at(s, 6), None);
        assert_eq!(space_at(s, 6), Some(1));
        assert_eq!(space_at(s, 7), Some(2));
        assert_eq!(space_at(s, 9), None);
        assert!(digit_lead_bytes().any(|b| b == b'7'));
        assert!(digit_lead_bytes().any(|b| b == 0xD9));
    }
}
