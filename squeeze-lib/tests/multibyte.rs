use squeeze::Finder;
use squeeze::scanner::Scanner;

fn scan(finders: Vec<Box<dyn Finder>>, input: &str) -> Vec<String> {
    let scanner = Scanner::new(finders);
    scanner
        .scan_line(input)
        .into_iter()
        .map(|m| input[m.range].to_string())
        .collect()
}

fn find_all(finder: &dyn Finder, input: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut idx = 0;
    while idx < input.len() {
        if let Some(range) = finder.find(&input[idx..]) {
            results.push(input[idx + range.start..idx + range.end].to_string());
            idx += range.end;
        } else {
            break;
        }
    }
    results
}

// --- Hash with multi-byte context ---

#[test]
fn hash_surrounded_by_emoji() {
    let finder = squeeze::hash::Hash::default();
    let input = "🔑5d41402abc4b2a76b9719d911017c592🔑";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["5d41402abc4b2a76b9719d911017c592"]);
}

#[test]
fn hash_between_cjk() {
    let finder = squeeze::hash::Hash::default();
    let input = "ハッシュ5d41402abc4b2a76b9719d911017c592確認";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["5d41402abc4b2a76b9719d911017c592"]);
}

#[test]
fn hash_after_accented_chars() {
    let finder = squeeze::hash::Hash::default();
    let input = "résumé: 5d41402abc4b2a76b9719d911017c592";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["5d41402abc4b2a76b9719d911017c592"]);
}

// --- IP with multi-byte context ---

#[test]
fn ip_in_japanese_text() {
    let finder = squeeze::ip::Ip::default();
    let input = "サーバー 192.168.1.1 接続";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["192.168.1.1"]);
}

#[test]
fn ip_with_emoji_separators() {
    let finder = squeeze::ip::Ip::default();
    let input = "🖥️10.0.0.1🌐10.0.0.2";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["10.0.0.1", "10.0.0.2"]);
}

// --- Email with multi-byte context ---

#[test]
fn email_in_chinese_text() {
    let finder = squeeze::email::Email::default();
    let input = "联系我们 user@example.com 获取帮助";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["user@example.com"]);
}

#[test]
fn email_with_emoji_around() {
    let finder = squeeze::email::Email::default();
    let input = "📧user@example.com📧";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["user@example.com"]);
}

#[test]
fn email_unicode_local_part_rejected() {
    let finder = squeeze::email::Email::default();
    assert!(finder.find("ñ@example.com").is_none());
}

#[test]
fn email_unicode_domain_rejected() {
    let finder = squeeze::email::Email::default();
    assert!(finder.find("user@例え.com").is_none());
}

// --- JSON with multi-byte content ---

#[test]
fn json_with_unicode_values() {
    let finder = squeeze::json::Json::default();
    let input = r#"{"名前": "太郎", "emoji": "🎉"}"#;
    let results = find_all(&finder, input);
    assert_eq!(results, vec![r#"{"名前": "太郎", "emoji": "🎉"}"#]);
}

#[test]
fn json_between_emoji() {
    let finder = squeeze::json::Json::default();
    let input = r#"🎯{"key": "value"}🎯"#;
    let results = find_all(&finder, input);
    assert_eq!(results, vec![r#"{"key": "value"}"#]);
}

#[test]
fn json_with_escaped_unicode() {
    let finder = squeeze::json::Json::default();
    let input = r#"{"text": "é"}"#;
    let results = find_all(&finder, input);
    assert_eq!(results, vec![r#"{"text": "é"}"#]);
}

// --- Path with multi-byte context ---

#[test]
fn path_in_japanese_text() {
    let finder = squeeze::path::Path::default();
    let input = "ファイル ./src/main.rs を編集";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["./src/main.rs"]);
}

#[test]
fn path_with_unicode_segment() {
    let finder = squeeze::path::Path::default();
    let input = "/home/ユーザー/ドキュメント";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["/home/ユーザー/ドキュメント"]);
}

// --- Env with multi-byte context ---

#[test]
fn env_in_japanese_text() {
    let finder = squeeze::env::Env::default();
    let input = "ホーム $HOME ディレクトリ";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["$HOME"]);
}

#[test]
fn env_after_emoji() {
    let finder = squeeze::env::Env::default();
    let input = "📂$HOME";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["$HOME"]);
}

// --- Datetime with multi-byte context ---

#[test]
fn datetime_in_cjk() {
    let finder = squeeze::datetime::Datetime::default();
    let input = "日付：2024-01-15T10:30:00Z 確認";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["2024-01-15T10:30:00Z"]);
}

// --- Color with multi-byte ---

#[test]
fn color_hex_after_emoji() {
    let finder = squeeze::color::Color::default();
    let input = "🎨#ff00aa";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["#ff00aa"]);
}

// --- UUID with multi-byte ---

#[test]
fn uuid_in_japanese() {
    let finder = squeeze::uuid::Uuid::default();
    let input = "識別子 550e8400-e29b-41d4-a716-446655440000 です";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["550e8400-e29b-41d4-a716-446655440000"]);
}

// --- MAC with multi-byte ---

#[test]
fn mac_after_emoji() {
    let finder = squeeze::mac::Mac::default();
    let input = "🔌00:1A:2B:3C:4D:5E";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["00:1A:2B:3C:4D:5E"]);
}

// --- Semver with multi-byte ---

#[test]
fn semver_in_unicode_text() {
    let finder = squeeze::semver::Semver::default();
    let input = "バージョン v1.2.3 リリース";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["v1.2.3"]);
}

// --- CIDR with multi-byte ---

#[test]
fn cidr_in_cjk() {
    let finder = squeeze::cidr::Cidr::default();
    let input = "ネットワーク 192.168.1.0/24 設定";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["192.168.1.0/24"]);
}

// --- Scanner: multi-finder with multi-byte ---

#[test]
fn scanner_multibyte_multi_finder() {
    let finders: Vec<Box<dyn Finder>> = vec![
        Box::new(squeeze::ip::Ip::default()),
        Box::new(squeeze::email::Email::default()),
        Box::new(squeeze::env::Env::default()),
    ];
    let input = "🌐192.168.1.1 📧user@example.com 📂$HOME";
    let results = scan(finders, input);
    assert_eq!(results, vec!["192.168.1.1", "user@example.com", "$HOME"]);
}

#[test]
fn scanner_pure_unicode_no_panic() {
    let finders: Vec<Box<dyn Finder>> = vec![
        Box::new(squeeze::hash::Hash::default()),
        Box::new(squeeze::email::Email::default()),
        Box::new(squeeze::ip::Ip::default()),
        Box::new(squeeze::json::Json::default()),
    ];
    let scanner = Scanner::new(finders);
    let inputs = [
        "日本語テキスト",
        "🎉🎊🎈🎁",
        "Ñoño café résumé naïve",
        "Ελληνικά Кириллица العربية",
        "\u{200B}\u{FEFF}\u{00AD}",
        "🇺🇸🇬🇧🇯🇵",
        "",
        "\u{0000}",
    ];
    for input in &inputs {
        let matches = scanner.scan_line(input);
        for m in &matches {
            assert!(m.range.start <= m.range.end);
            assert!(m.range.end <= input.len());
            assert!(input.is_char_boundary(m.range.start));
            assert!(input.is_char_boundary(m.range.end));
        }
    }
}

// --- Stress: many matches in unicode-heavy text ---

#[test]
fn scanner_many_matches_interspersed_with_unicode() {
    let finders: Vec<Box<dyn Finder>> = vec![Box::new(squeeze::hash::Hash::default())];
    let hash = "5d41402abc4b2a76b9719d911017c592";
    let input = format!("🔑{}🔑{}🔑{}", hash, hash, hash);
    let results = scan(finders, &input);
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r == hash));
}

// --- Scanner with mirror and unicode ---

#[test]
fn scanner_mirror_preserves_unicode() {
    let finders: Vec<Box<dyn Finder>> = vec![Box::new(squeeze::mirror::Mirror::default())];
    let input = "日本語 🎉 café";
    let results = scan(finders, input);
    assert_eq!(results, vec!["日本語 🎉 café"]);
}

// --- UTF-8 continuation byte edge cases ---

#[test]
fn finders_dont_match_utf8_continuation_bytes_as_hex() {
    // UTF-8 continuation bytes (0x80-0xBF) contain values like 0xAB, 0xBE
    // that look like hex digits in isolation. Finders must not treat them as hex.
    let finder = squeeze::hash::Hash::default();
    // 32 copies of '你' = 32 * 3 bytes = 96 bytes, many continuation bytes
    let input = "你".repeat(32);
    assert!(finder.find(&input).is_none());
}

#[test]
fn uuid_not_found_in_pure_unicode() {
    let finder = squeeze::uuid::Uuid::default();
    let input = "文字列データ漢字テスト";
    assert!(finder.find(input).is_none());
}

#[test]
fn ip_not_found_in_pure_unicode() {
    let finder = squeeze::ip::Ip::default();
    let input = "日本語テキストのみ";
    assert!(finder.find(input).is_none());
}

// --- Mixed byte length contexts ---

#[test]
fn hash_between_2byte_chars() {
    let finder = squeeze::hash::Hash::default();
    // é is 2 bytes (0xC3 0xA9), ñ is 2 bytes (0xC3 0xB1)
    let input = "é5d41402abc4b2a76b9719d911017c592ñ";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["5d41402abc4b2a76b9719d911017c592"]);
}

#[test]
fn hash_between_3byte_chars() {
    let finder = squeeze::hash::Hash::default();
    // 中 is 3 bytes
    let input = "中5d41402abc4b2a76b9719d911017c592中";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["5d41402abc4b2a76b9719d911017c592"]);
}

#[test]
fn hash_between_4byte_chars() {
    let finder = squeeze::hash::Hash::default();
    // 🔑 is 4 bytes (F0 9F 94 91)
    let input = "🔑5d41402abc4b2a76b9719d911017c592🔑";
    let results = find_all(&finder, input);
    assert_eq!(results, vec!["5d41402abc4b2a76b9719d911017c592"]);
}

// --- Verify scanner match ranges land on char boundaries ---

#[test]
fn scanner_ranges_on_char_boundaries_with_cjk() {
    let finders: Vec<Box<dyn Finder>> = vec![
        Box::new(squeeze::email::Email::default()),
        Box::new(squeeze::hash::Hash::default()),
        Box::new(squeeze::ip::Ip::default()),
        Box::new(squeeze::env::Env::default()),
        Box::new(squeeze::json::Json::default()),
        Box::new(squeeze::datetime::Datetime::default()),
        Box::new(squeeze::uuid::Uuid::default()),
        Box::new(squeeze::path::Path::default()),
    ];
    let scanner = Scanner::new(finders);

    let inputs = [
        "日192.168.1.1本",
        "中user@example.com文",
        "🔑$HOME🔑",
        r#"日{"k":"v"}本"#,
        "日2024-01-15本",
        "中550e8400-e29b-41d4-a716-446655440000文",
        "日/etc/hosts本",
    ];

    for input in &inputs {
        for m in scanner.scan_line(input) {
            assert!(
                input.is_char_boundary(m.range.start),
                "start {} not char boundary in {:?}",
                m.range.start,
                input
            );
            assert!(
                input.is_char_boundary(m.range.end),
                "end {} not char boundary in {:?}",
                m.range.end,
                input
            );
        }
    }
}
