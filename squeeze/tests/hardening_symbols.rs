//! Hardening tests for the emoji finder: UTS #51 three-tier tables
//! (emoji-presentation / text-default+VS16 / keycap sequences), VS15 text
//! presentation, find()/Scanner parity on ZWJ/VS/RI-heavy corpora, and
//! O(1)-per-position `try_at` behavior on large non-emoji lines.
//!
//! Every helper asserts the core contracts on each returned range:
//! `start < end` and both ends land on char boundaries.

use squeeze::emoji::Emoji;
use squeeze::scanner::Scanner;
use squeeze::Finder;

/// Collect all matches using the documented `find()` loop (relative ranges).
fn find_matches(input: &str) -> Vec<String> {
    let finder = Emoji::default();
    let mut out = Vec::new();
    let mut idx = 0;
    while idx < input.len() {
        if let Some(range) = finder.find(&input[idx..]) {
            assert!(range.start < range.end, "empty/reversed range on {input:?}");
            let start = idx + range.start;
            let end = idx + range.end;
            assert!(
                input.is_char_boundary(start),
                "find start {start} not a char boundary in {input:?}"
            );
            assert!(
                input.is_char_boundary(end),
                "find end {end} not a char boundary in {input:?}"
            );
            out.push(input[start..end].to_string());
            idx = end;
        } else {
            break;
        }
    }
    out
}

/// Collect all matches through the Scanner (dispatch mode / `try_at`).
fn scanner_matches(input: &str) -> Vec<String> {
    let scanner = Scanner::new(vec![Box::new(Emoji::default())]);
    scanner
        .scan_line(input)
        .into_iter()
        .map(|m| {
            assert!(
                m.range.start < m.range.end,
                "empty/reversed range on {input:?}"
            );
            assert!(
                input.is_char_boundary(m.range.start),
                "scanner start {} not a char boundary in {input:?}",
                m.range.start
            );
            assert!(
                input.is_char_boundary(m.range.end),
                "scanner end {} not a char boundary in {input:?}",
                m.range.end
            );
            input[m.range].to_string()
        })
        .collect()
}

/// Assert find() and Scanner agree, then return the common match list.
fn assert_parity(input: &str) -> Vec<String> {
    let via_find = find_matches(input);
    let via_scanner = scanner_matches(input);
    assert_eq!(
        via_find, via_scanner,
        "find() vs Scanner parity broke on {input:?}"
    );
    via_find
}

// ============================================================================
// Bug 1: preceding-ZWJ veto removed — find()/try_at parity
// ============================================================================

#[test]
fn emoji_after_dangling_zwj_is_found_by_both_paths() {
    // The old try_at veto rejected any position preceded by ZWJ bytes, so the
    // Scanner missed this emoji while find() reported it.
    assert_eq!(assert_parity("ab\u{200D}\u{1F600}cd"), vec!["\u{1F600}"]);
}

#[test]
fn double_zwj_between_emojis_yields_both() {
    assert_eq!(
        assert_parity("\u{1F600}\u{200D}\u{200D}\u{1F600}"),
        vec!["\u{1F600}", "\u{1F600}"]
    );
}

#[test]
fn dangling_zwj_at_eol_is_not_consumed() {
    let input = "\u{1F600}\u{200D}";
    assert_eq!(assert_parity(input), vec!["\u{1F600}"]);
    // The dangling ZWJ must not be part of the match.
    let finder = Emoji::default();
    assert_eq!(finder.find(input), Some(0.."\u{1F600}".len()));
}

#[test]
fn leading_zwj_alone_does_not_match() {
    assert!(assert_parity("\u{200D}\u{200D}\u{200D}").is_empty());
}

#[test]
fn try_at_position_preceded_by_zwj_matches() {
    // Containment of positions inside consumed sequences is the Scanner's job
    // (finder_pos); try_at itself must not look backwards.
    let finder = Emoji::default();
    let input = "a\u{200D}\u{1F600}";
    let pos = "a\u{200D}".len();
    assert_eq!(finder.try_at(input.as_bytes(), pos), Some(pos..input.len()));
}

#[test]
fn zwj_to_bare_fire_surfaces_fire_only() {
    // Degenerate `❤‍🔥` without VS16: the text-default heart cannot match bare,
    // and with the veto gone the fire pictograph surfaces in both paths.
    assert_eq!(
        assert_parity("\u{2764}\u{200D}\u{1F525}"),
        vec!["\u{1F525}"]
    );
}

// ============================================================================
// Bug 2: try_at must not validate the whole remaining line (O(n^2) blow-up)
// ============================================================================

#[test]
fn large_en_dash_line_scans_correctly() {
    // ~1MB of en-dashes: every 0xE2 lead byte hits could_start_at. Each try_at
    // must bail in O(1); before the fix this took over a minute.
    let mut line = "\u{2013}".repeat(350_000);
    assert!(line.len() >= 1_000_000);
    line.push('\u{1F680}');
    assert_eq!(assert_parity(&line), vec!["\u{1F680}"]);
}

#[test]
fn large_cjk_line_scans_correctly() {
    // 0xE3-lead CJK also trains could_start_at; 60k chars = 180KB.
    let mut line = "\u{3042}".repeat(60_000);
    assert!(line.len() >= 100_000);
    line.push('\u{2705}');
    assert_eq!(assert_parity(&line), vec!["\u{2705}"]);
}

#[test]
fn large_digit_line_scans_correctly() {
    // Digits are dispatch bytes for keycaps now; the bail-out must be O(1).
    let mut line = "1234567890".repeat(15_000);
    line.push_str("7\u{FE0F}\u{20E3}");
    assert_eq!(assert_parity(&line), vec!["7\u{FE0F}\u{20E3}"]);
}

// ============================================================================
// Bug 3a: emoji-presentation tier matches bare
// ============================================================================

#[test]
fn watch_matches_bare() {
    assert_eq!(assert_parity("at \u{231A} now"), vec!["\u{231A}"]);
}

#[test]
fn check_mark_button_matches_bare() {
    assert_eq!(assert_parity("done \u{2705}"), vec!["\u{2705}"]);
}

#[test]
fn white_medium_star_2b50_matches_bare() {
    assert_eq!(assert_parity("rate \u{2B50}"), vec!["\u{2B50}"]);
}

#[test]
fn mahjong_red_dragon_matches_bare() {
    assert_eq!(assert_parity("\u{1F004}"), vec!["\u{1F004}"]);
}

#[test]
fn playing_card_joker_matches_bare() {
    assert_eq!(assert_parity("\u{1F0CF}"), vec!["\u{1F0CF}"]);
}

#[test]
fn negative_squared_letters_match_bare() {
    // 1F170/1F171/1F17E/1F17F are commonly emoji-rendered.
    assert_eq!(
        assert_parity("\u{1F170}\u{1F171}\u{1F17E}\u{1F17F}"),
        vec!["\u{1F170}", "\u{1F171}", "\u{1F17E}", "\u{1F17F}"]
    );
}

#[test]
fn orange_circle_matches_bare() {
    assert_eq!(assert_parity("\u{1F7E0}"), vec!["\u{1F7E0}"]);
}

#[test]
fn nazar_amulet_matches_bare() {
    assert_eq!(assert_parity("\u{1F9FF}"), vec!["\u{1F9FF}"]);
}

#[test]
fn lone_skin_tone_matches_alone() {
    // Skin-tone modifiers are emoji-presentation on their own (color swatch).
    assert_eq!(assert_parity("\u{1F3FD}"), vec!["\u{1F3FD}"]);
}

// ============================================================================
// Bug 3: over-broad tables tightened — non-emoji symbols must not match
// ============================================================================

#[test]
fn black_star_ratings_are_not_emoji() {
    // U+2605 is not Emoji=Yes; `★★★` is everyday text.
    assert!(assert_parity("rated \u{2605}\u{2605}\u{2605} stars").is_empty());
}

#[test]
fn check_mark_2713_is_not_emoji() {
    assert!(assert_parity("\u{2713} done").is_empty());
}

#[test]
fn ballot_x_2717_is_not_emoji() {
    assert!(assert_parity("\u{2717} failed").is_empty());
}

#[test]
fn ballot_box_2610_is_not_emoji() {
    assert!(assert_parity("\u{2610} todo").is_empty());
}

#[test]
fn mahjong_east_wind_is_not_emoji() {
    // U+1F000 mahjong east wind: only U+1F004 is an emoji in that block.
    assert!(assert_parity("\u{1F000}").is_empty());
}

#[test]
fn domino_tiles_are_not_emoji() {
    assert!(assert_parity("\u{1F031}\u{1F062}").is_empty());
}

#[test]
fn playing_cards_other_than_joker_are_not_emoji() {
    assert!(assert_parity("\u{1F0A1}\u{1F0B2}\u{1F0D1}").is_empty());
}

#[test]
fn thunderstorm_2608_is_not_emoji() {
    assert!(assert_parity("\u{2608}").is_empty());
}

#[test]
fn unassigned_1f7f1_is_not_emoji() {
    assert!(assert_parity("\u{1F7F1}").is_empty());
}

// ============================================================================
// Bug 3b: text-default tier matches only with VS16 (U+FE0F)
// ============================================================================

#[test]
fn double_exclamation_bare_does_not_match() {
    assert!(assert_parity("\u{203C} wow").is_empty());
}

#[test]
fn double_exclamation_with_vs16_matches() {
    assert_eq!(
        assert_parity("\u{203C}\u{FE0F} wow"),
        vec!["\u{203C}\u{FE0F}"]
    );
}

#[test]
fn copyright_bare_does_not_match() {
    assert!(assert_parity("\u{00A9} 2026 Corp").is_empty());
}

#[test]
fn copyright_with_vs16_matches() {
    assert_eq!(assert_parity("\u{00A9}\u{FE0F}"), vec!["\u{00A9}\u{FE0F}"]);
}

#[test]
fn registered_bare_does_not_match() {
    assert!(assert_parity("Acme\u{00AE}").is_empty());
}

#[test]
fn registered_with_vs16_matches() {
    assert_eq!(assert_parity("\u{00AE}\u{FE0F}"), vec!["\u{00AE}\u{FE0F}"]);
}

#[test]
fn trademark_bare_does_not_match() {
    // Flipped pin: `™` used to match bare (while ©/® did not). All three are
    // text-default per UTS #51, so bare `™` is now plain text.
    assert!(assert_parity("Rust\u{2122} rocks").is_empty());
}

#[test]
fn trademark_with_vs16_matches() {
    assert_eq!(assert_parity("\u{2122}\u{FE0F}"), vec!["\u{2122}\u{FE0F}"]);
}

#[test]
fn sun_2600_bare_does_not_match() {
    assert!(assert_parity("sun \u{2600} here").is_empty());
}

#[test]
fn sun_2600_with_vs16_matches() {
    assert_eq!(
        assert_parity("sun \u{2600}\u{FE0F} here"),
        vec!["\u{2600}\u{FE0F}"]
    );
}

#[test]
fn umbrella_with_vs16_matches() {
    assert_eq!(assert_parity("\u{2602}\u{FE0F}"), vec!["\u{2602}\u{FE0F}"]);
}

#[test]
fn heavy_check_mark_with_vs16_matches() {
    assert_eq!(
        assert_parity("ok \u{2714}\u{FE0F}"),
        vec!["\u{2714}\u{FE0F}"]
    );
    assert!(assert_parity("ok \u{2714}").is_empty());
}

#[test]
fn warning_sign_with_vs16_matches() {
    assert_eq!(
        assert_parity("\u{26A0}\u{FE0F} risk"),
        vec!["\u{26A0}\u{FE0F}"]
    );
    assert!(assert_parity("\u{26A0} risk").is_empty());
}

#[test]
fn right_arrow_with_vs16_matches() {
    assert_eq!(assert_parity("\u{27A1}\u{FE0F}"), vec!["\u{27A1}\u{FE0F}"]);
    assert!(assert_parity("\u{27A1}").is_empty());
}

#[test]
fn medical_symbol_requires_vs16() {
    assert!(assert_parity("\u{2695}").is_empty());
    assert_eq!(assert_parity("\u{2695}\u{FE0F}"), vec!["\u{2695}\u{FE0F}"]);
}

// ============================================================================
// Bug 4: VS15 (U+FE0E) forces text presentation — no match, skip both
// ============================================================================

#[test]
fn umbrella_with_vs15_does_not_match() {
    assert!(assert_parity("\u{2602}\u{FE0E}").is_empty());
}

#[test]
fn watch_with_vs15_does_not_match() {
    // Emoji-presentation char explicitly demoted to text via VS15.
    assert!(assert_parity("\u{231A}\u{FE0E}").is_empty());
}

#[test]
fn vs15_skips_selector_and_later_bare_emoji_still_matches() {
    let input = "\u{23F3}\u{FE0E} then \u{23F3}";
    let matches = assert_parity(input);
    assert_eq!(matches, vec!["\u{23F3}"]);
    // The surviving match is the trailing bare hourglass, not the VS15 one.
    let finder = Emoji::default();
    let range = finder.find(input).unwrap();
    assert_eq!(range.start, input.len() - "\u{23F3}".len());
    assert_eq!(range.end, input.len());
}

#[test]
fn heavy_check_with_vs15_does_not_match() {
    assert!(assert_parity("\u{2714}\u{FE0E}").is_empty());
}

#[test]
fn keycap_with_vs15_does_not_match() {
    // Only FE0F is allowed inside a keycap sequence.
    assert!(assert_parity("1\u{FE0E}\u{20E3}").is_empty());
}

#[test]
fn lone_vs16_does_not_match() {
    assert!(assert_parity("\u{FE0F}").is_empty());
}

// ============================================================================
// Bug 3c + 5: keycap sequences (base + optional FE0F + U+20E3), never bare
// ============================================================================

#[test]
fn keycap_all_bases_full_form_match() {
    for base in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '#', '*'] {
        let seq = format!("{base}\u{FE0F}\u{20E3}");
        assert_eq!(assert_parity(&seq), vec![seq.clone()], "base {base:?}");
    }
}

#[test]
fn keycap_all_bases_legacy_form_match() {
    for base in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '#', '*'] {
        let seq = format!("{base}\u{20E3}");
        assert_eq!(assert_parity(&seq), vec![seq.clone()], "base {base:?}");
    }
}

#[test]
fn bare_digit_runs_yield_nothing() {
    assert!(assert_parity("123").is_empty());
    assert!(assert_parity("call 555 0123 x42").is_empty());
}

#[test]
fn bare_hash_and_asterisk_yield_nothing() {
    assert!(assert_parity("#hashtag *bold* # * 42").is_empty());
}

#[test]
fn hex_color_hash_is_not_a_keycap() {
    assert!(assert_parity("#ff0000").is_empty());
}

#[test]
fn keycap_embedded_in_digits_matches_exactly() {
    assert_eq!(assert_parity("1\u{20E3}23"), vec!["1\u{20E3}"]);
}

#[test]
fn keycap_in_sentence_has_exact_boundaries() {
    let input = "press 1\u{FE0F}\u{20E3} now";
    assert_eq!(assert_parity(input), vec!["1\u{FE0F}\u{20E3}"]);
    let finder = Emoji::default();
    let range = finder.find(input).unwrap();
    assert_eq!(range, 6..6 + "1\u{FE0F}\u{20E3}".len());
}

#[test]
fn keycap_digit_only_line_dispatches_without_class_mask() {
    // required_classes("emoji") is [] so an all-digit line still reaches the
    // emoji finder in dispatch mode.
    assert_eq!(scanner_matches("5\u{20E3}"), vec!["5\u{20E3}"]);
}

#[test]
fn stranded_combining_keycap_does_not_match() {
    assert!(assert_parity("a\u{20E3}b").is_empty());
}

// ============================================================================
// Bug 6: pinned sequences keep working as single matches
// ============================================================================

#[test]
fn zwj_family_is_single_match() {
    let fam = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}";
    let input = format!("family {fam} end");
    assert_eq!(assert_parity(&input), vec![fam]);
}

#[test]
fn thumbs_up_with_skin_tone_is_single_match() {
    assert_eq!(
        assert_parity("ok \u{1F44D}\u{1F3FD} done"),
        vec!["\u{1F44D}\u{1F3FD}"]
    );
}

#[test]
fn french_flag_ri_pair_is_single_match() {
    assert_eq!(
        assert_parity("in \u{1F1EB}\u{1F1F7} paris"),
        vec!["\u{1F1EB}\u{1F1F7}"]
    );
}

#[test]
fn odd_ri_run_pairs_greedily_lone_trailing_matches_alone() {
    assert_eq!(
        assert_parity("\u{1F1E6}\u{1F1E7}\u{1F1E8}"),
        vec!["\u{1F1E6}\u{1F1E7}", "\u{1F1E8}"]
    );
}

#[test]
fn even_ri_run_yields_two_pairs() {
    assert_eq!(
        assert_parity("\u{1F1FA}\u{1F1F8}\u{1F1EC}\u{1F1E7}"),
        vec!["\u{1F1FA}\u{1F1F8}", "\u{1F1EC}\u{1F1E7}"]
    );
}

#[test]
fn england_tag_sequence_is_single_match() {
    let flag = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";
    let input = format!("flag {flag} end");
    assert_eq!(assert_parity(&input), vec![flag]);
}

#[test]
fn tag_sequence_without_cancel_still_consumes_tags() {
    // Pin existing behavior: tags without the cancel char are still consumed.
    let partial = "\u{1F3F4}\u{E0067}\u{E0062}";
    assert_eq!(assert_parity(partial), vec![partial]);
}

#[test]
fn black_flag_without_tags_matches_alone() {
    assert_eq!(assert_parity("\u{1F3F4} flag"), vec!["\u{1F3F4}"]);
}

#[test]
fn adjacent_emojis_are_two_matches() {
    assert_eq!(
        assert_parity("\u{1F600}\u{1F603}"),
        vec!["\u{1F600}", "\u{1F603}"]
    );
}

#[test]
fn emoji_between_ascii_has_exact_boundaries() {
    let input = "hi\u{1F600}there";
    assert_eq!(assert_parity(input), vec!["\u{1F600}"]);
    let finder = Emoji::default();
    assert_eq!(finder.find(input), Some(2..2 + "\u{1F600}".len()));
}

#[test]
fn heart_on_fire_zwj_with_vs16_is_single_match() {
    let seq = "\u{2764}\u{FE0F}\u{200D}\u{1F525}";
    assert_eq!(assert_parity(seq), vec![seq]);
}

#[test]
fn scientist_zwj_with_skin_tone_is_single_match() {
    let seq = "\u{1F469}\u{1F3FD}\u{200D}\u{1F52C}";
    assert_eq!(assert_parity(seq), vec![seq]);
}

#[test]
fn police_officer_zwj_female_sign_is_single_match() {
    // ZWJ chain into a text-default element (U+2640) carrying VS16.
    let seq = "\u{1F46E}\u{200D}\u{2640}\u{FE0F}";
    assert_eq!(assert_parity(seq), vec![seq]);
}

#[test]
fn rainbow_flag_zwj_is_single_match() {
    let seq = "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}";
    assert_eq!(assert_parity(seq), vec![seq]);
}

// ============================================================================
// find() vs Scanner parity over a ZWJ/VS/RI-heavy corpus
// ============================================================================

#[test]
fn find_scanner_parity_over_hardened_corpus() {
    let corpus: &[&str] = &[
        "",
        "plain ascii text 123 #tag *x*",
        "ab\u{200D}\u{1F600}cd",
        "\u{1F600}\u{200D}\u{200D}\u{1F600}",
        "\u{1F600}\u{200D}",
        "\u{200D}\u{1F600}\u{200D}\u{200D}",
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466} fam",
        "x\u{1F469}\u{1F3FD}\u{200D}\u{1F52C}y",
        "\u{2764}\u{FE0F}\u{200D}\u{1F525}",
        "\u{2764}\u{200D}\u{1F525}",
        "\u{2764}\u{FE0F}\u{200D}\u{1F525}\u{200D}",
        "\u{1F46E}\u{200D}\u{2640}\u{FE0F} cop",
        "\u{1F46E}\u{200D}\u{2640} degenerate",
        "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}",
        "\u{1F1EB}\u{1F1F7}\u{1F1EB}",
        "\u{1F1E6}\u{1F1E7}\u{1F1E8}\u{1F1E9}",
        "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F} tag",
        "\u{1F3F4}\u{E0067}\u{E0062}",
        "\u{1F3F4} bare",
        "\u{231A}\u{FE0E} \u{231A}",
        "\u{2602}\u{FE0E}\u{2602}\u{FE0F}",
        "\u{2122} tm \u{2122}\u{FE0F}",
        "\u{00A9}\u{FE0F}\u{00AE}\u{FE0F}\u{2122}",
        "1\u{FE0F}\u{20E3}2\u{20E3}34#\u{FE0F}\u{20E3}*",
        "1\u{FE0E}\u{20E3}5\u{20E3}\u{20E3}",
        "#tag *x* 123 \u{00A9}",
        "\u{1F600}\u{1F603}",
        "hi\u{1F600}there",
        "\u{2605}\u{2605}\u{2605} \u{2713} \u{2610} \u{1F000} \u{2013}\u{2013} \u{1F004}",
        "\u{2013} en dash \u{2013} \u{231A} \u{2013} \u{4E2D}\u{6587} \u{2705}",
        "\u{1F3FD} lone skin",
        "\u{1F44D}\u{1F3FD}\u{1F3FD}",
        "\u{FE0F} lone vs16",
        "\u{20E3} lone keycap mark",
        "\u{1F469}\u{200D}\u{2695} zwj to bare text-default",
        "mix \u{1F680}\u{2B50}\u{2705} \u{2600}\u{FE0F} \u{2600} end",
    ];
    for input in corpus {
        assert_parity(input);
    }
}

// ============================================================================
// try_at public-API safety (must stay panic-free without unsafe)
// ============================================================================

#[test]
fn try_at_out_of_bounds_position_returns_none() {
    let finder = Emoji::default();
    assert_eq!(finder.try_at(b"abc", 10), None);
    assert_eq!(finder.try_at(b"", 0), None);
}

#[test]
fn try_at_on_truncated_utf8_returns_none() {
    let finder = Emoji::default();
    // Truncated 😀 (missing last byte).
    assert_eq!(finder.try_at(&[0xF0, 0x9F, 0x98], 0), None);
    // Lone continuation bytes.
    assert_eq!(finder.try_at(&[0x80, 0x80], 0), None);
}

#[test]
fn try_at_mid_char_position_returns_none() {
    let finder = Emoji::default();
    let bytes = "\u{1F600}".as_bytes();
    for pos in 1..bytes.len() {
        assert_eq!(finder.try_at(bytes, pos), None, "pos {pos}");
    }
}

#[test]
fn try_at_returns_absolute_ranges() {
    let finder = Emoji::default();
    let input = "xy \u{1F389}!";
    let pos = 3;
    assert_eq!(
        finder.try_at(input.as_bytes(), pos),
        Some(pos..pos + "\u{1F389}".len())
    );
}
