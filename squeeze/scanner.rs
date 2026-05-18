use crate::Finder;
use std::ops::Range;

const CL_DIGIT: u16 = 1 << 0;
const CL_HEX_ALPHA: u16 = 1 << 1;
const CL_ALPHA_OTHER: u16 = 1 << 2;
const CL_AT: u16 = 1 << 3;
const CL_DOLLAR: u16 = 1 << 4;
const CL_HASH: u16 = 1 << 5;
const CL_OPEN_BRACE: u16 = 1 << 6;
const CL_OPEN_BRACKET: u16 = 1 << 7;
const CL_COLON: u16 = 1 << 8;
const CL_DOT: u16 = 1 << 9;
const CL_SLASH: u16 = 1 << 10;
const CL_TILDE: u16 = 1 << 11;
const CL_PLUS: u16 = 1 << 12;
const CL_OPEN_PAREN: u16 = 1 << 13;
const CL_DASH: u16 = 1 << 14;

const CL_HEX: u16 = CL_DIGIT | CL_HEX_ALPHA;

const fn build_byte_class_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0u16;
    while i < 256 {
        let b = i as u8;
        let mut c = 0u16;
        if b >= b'0' && b <= b'9' {
            c |= CL_DIGIT;
        }
        if (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F') {
            c |= CL_HEX_ALPHA;
        }
        if (b >= b'g' && b <= b'z') || (b >= b'G' && b <= b'Z') {
            c |= CL_ALPHA_OTHER;
        }
        if b == b'@' {
            c |= CL_AT;
        }
        if b == b'$' {
            c |= CL_DOLLAR;
        }
        if b == b'#' {
            c |= CL_HASH;
        }
        if b == b'{' {
            c |= CL_OPEN_BRACE;
        }
        if b == b'[' {
            c |= CL_OPEN_BRACKET;
        }
        if b == b':' {
            c |= CL_COLON;
        }
        if b == b'.' {
            c |= CL_DOT;
        }
        if b == b'/' {
            c |= CL_SLASH;
        }
        if b == b'~' {
            c |= CL_TILDE;
        }
        if b == b'+' {
            c |= CL_PLUS;
        }
        if b == b'(' {
            c |= CL_OPEN_PAREN;
        }
        if b == b'-' {
            c |= CL_DASH;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

static BYTE_CLASSES: [u16; 256] = build_byte_class_table();

fn prescan(input: &[u8]) -> u16 {
    let mut classes = 0u16;
    for &b in input {
        classes |= BYTE_CLASSES[b as usize];
    }
    classes
}

fn can_skip_finder(id: &str, cl: u16) -> bool {
    match id {
        "cidr" => (cl & CL_DIGIT) == 0 || (cl & CL_SLASH) == 0,
        "codetag" => (cl & CL_COLON) == 0,
        "color" => (cl & CL_HASH) == 0 && (cl & (CL_ALPHA_OTHER | CL_HEX_ALPHA)) == 0,
        "datetime" => (cl & CL_DIGIT) == 0,
        "email" => (cl & CL_AT) == 0,
        "emoji" => false,
        "env" => (cl & CL_DOLLAR) == 0,
        "hash" => (cl & CL_HEX) == 0,
        "ip" => (cl & (CL_DIGIT | CL_HEX_ALPHA | CL_COLON | CL_OPEN_BRACKET)) == 0,
        "json" => (cl & (CL_OPEN_BRACE | CL_OPEN_BRACKET)) == 0,
        "jwt" => (cl & CL_HEX_ALPHA) == 0,
        "mac" => {
            (cl & CL_HEX) == 0
                || ((cl & CL_COLON) == 0 && (cl & CL_DASH) == 0 && (cl & CL_DOT) == 0)
        }
        "mirror" => false,
        "path" => (cl & (CL_SLASH | CL_DOT | CL_TILDE)) == 0,
        "phone" => (cl & (CL_DIGIT | CL_PLUS | CL_OPEN_PAREN)) == 0,
        "semver" => (cl & CL_DIGIT) == 0 || (cl & CL_DOT) == 0,
        "uri" => (cl & CL_COLON) == 0,
        "uuid" => (cl & CL_HEX) == 0 || (cl & CL_DASH) == 0,
        _ => false,
    }
}

pub struct Match {
    pub finder_index: usize,
    pub range: Range<usize>,
}

pub struct Scanner {
    finders: Vec<Box<dyn Finder>>,
    dispatch: [u32; 256],
    dispatch_mask: u32,
    scan_mask: u32,
}

impl Scanner {
    pub fn new(finders: Vec<Box<dyn Finder>>) -> Self {
        assert!(finders.len() <= 32);

        let mut dispatch = [0u32; 256];
        let mut dispatch_mask = 0u32;
        let mut scan_mask = 0u32;

        for (i, finder) in finders.iter().enumerate() {
            let bit = 1u32 << i;
            if finder.dispatchable() {
                dispatch_mask |= bit;
                for b in 0..=255u8 {
                    if finder.could_start_at(b) {
                        dispatch[b as usize] |= bit;
                    }
                }
            } else {
                scan_mask |= bit;
            }
        }

        Scanner {
            finders,
            dispatch,
            dispatch_mask,
            scan_mask,
        }
    }

    pub fn finders(&self) -> &[Box<dyn Finder>] {
        &self.finders
    }

    pub fn scan_line(&self, line: &str) -> Vec<Match> {
        let input = line.as_bytes();
        if input.is_empty() {
            return Vec::new();
        }

        let line_classes = prescan(input);

        let mut active = 0u32;
        for (i, finder) in self.finders.iter().enumerate() {
            if !can_skip_finder(finder.id(), line_classes) {
                active |= 1u32 << i;
            }
        }
        if active == 0 {
            return Vec::new();
        }

        let mut matches = Vec::new();

        let active_scan = active & self.scan_mask;
        if active_scan != 0 {
            for i in 0..self.finders.len() {
                if (active_scan & (1u32 << i)) == 0 {
                    continue;
                }
                let finder = &self.finders[i];
                let mut idx = 0;
                while idx < line.len() {
                    if let Some(range) = finder.find(&line[idx..]) {
                        matches.push(Match {
                            finder_index: i,
                            range: (idx + range.start)..(idx + range.end),
                        });
                        idx += range.end;
                    } else {
                        break;
                    }
                }
            }
        }

        let active_dispatch = active & self.dispatch_mask;
        if active_dispatch != 0 {
            let mut finder_pos = vec![0usize; self.finders.len()];

            for pos in 0..input.len() {
                let mut candidates = self.dispatch[input[pos] as usize] & active_dispatch;
                while candidates != 0 {
                    let i = candidates.trailing_zeros() as usize;
                    candidates &= candidates - 1;

                    if pos < finder_pos[i] {
                        continue;
                    }
                    if let Some(range) = self.finders[i].try_at(input, pos) {
                        matches.push(Match {
                            finder_index: i,
                            range: range.clone(),
                        });
                        finder_pos[i] = range.end;
                    }
                }
            }
        }

        matches.sort_by(|a, b| {
            a.range
                .start
                .cmp(&b.range.start)
                .then(a.finder_index.cmp(&b.finder_index))
        });

        matches
    }

    pub fn scan_line_first(&self, line: &str) -> Option<Match> {
        let input = line.as_bytes();
        if input.is_empty() {
            return None;
        }

        let line_classes = prescan(input);

        let mut active = 0u32;
        for (i, finder) in self.finders.iter().enumerate() {
            if !can_skip_finder(finder.id(), line_classes) {
                active |= 1u32 << i;
            }
        }
        if active == 0 {
            return None;
        }

        let mut best: Option<Match> = None;

        for (i, finder) in self.finders.iter().enumerate() {
            if (active & (1u32 << i)) == 0 {
                continue;
            }
            if let Some(range) = finder.find(line) {
                let is_better = match &best {
                    None => true,
                    Some(b) => range.start < b.range.start,
                };
                if is_better {
                    best = Some(Match {
                        finder_index: i,
                        range,
                    });
                }
            }
        }

        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prescan_empty_input() {
        assert_eq!(prescan(b""), 0);
    }

    #[test]
    fn prescan_detects_digit() {
        assert_ne!(prescan(b"abc123") & CL_DIGIT, 0);
    }

    #[test]
    fn prescan_detects_at() {
        assert_ne!(prescan(b"user@host") & CL_AT, 0);
    }

    #[test]
    fn prescan_detects_dollar() {
        assert_ne!(prescan(b"$HOME") & CL_DOLLAR, 0);
    }

    #[test]
    fn prescan_no_false_positives() {
        let cl = prescan(b"hello world");
        assert_eq!(cl & CL_AT, 0);
        assert_eq!(cl & CL_DOLLAR, 0);
        assert_eq!(cl & CL_DIGIT, 0);
    }

    #[test]
    fn can_skip_email_without_at() {
        let cl = prescan(b"hello world");
        assert!(can_skip_finder("email", cl));
    }

    #[test]
    fn cannot_skip_email_with_at() {
        let cl = prescan(b"user@example.com");
        assert!(!can_skip_finder("email", cl));
    }

    #[test]
    fn can_skip_env_without_dollar() {
        let cl = prescan(b"no vars here");
        assert!(can_skip_finder("env", cl));
    }

    #[test]
    fn can_skip_json_without_brackets() {
        let cl = prescan(b"no json here");
        assert!(can_skip_finder("json", cl));
    }

    #[test]
    fn can_skip_uri_without_colon() {
        let cl = prescan(b"no uris here");
        assert!(can_skip_finder("uri", cl));
    }

    #[test]
    fn can_skip_uuid_without_dash() {
        let cl = prescan(b"abcdef1234567890");
        assert!(can_skip_finder("uuid", cl));
    }

    #[test]
    fn cannot_skip_mirror() {
        let cl = prescan(b"anything");
        assert!(!can_skip_finder("mirror", cl));
    }

    #[test]
    fn can_skip_hash_without_hex() {
        let cl = prescan(b"no hx zzz");
        assert!(can_skip_finder("hash", cl));
    }

    #[test]
    fn can_skip_mac_without_separator() {
        let cl = prescan(b"aabbccddeeff");
        assert!(can_skip_finder("mac", cl));
    }

    #[test]
    fn can_skip_semver_without_dot() {
        let cl = prescan(b"version 100");
        assert!(can_skip_finder("semver", cl));
    }

    #[test]
    fn can_skip_cidr_without_slash() {
        let cl = prescan(b"192.168.1.0");
        assert!(can_skip_finder("cidr", cl));
    }

    #[test]
    fn can_skip_path_without_prefix() {
        let cl = prescan(b"no paths here");
        assert!(can_skip_finder("path", cl));
    }

    #[test]
    fn scanner_empty_finders() {
        let scanner = Scanner::new(Vec::new());
        assert!(scanner.scan_line("hello").is_empty());
    }

    #[test]
    fn scanner_empty_line() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::mirror::Mirror::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("").is_empty());
    }

    #[test]
    fn scanner_mirror_matches_everything() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::mirror::Mirror::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line("hello world");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].range, 0..11);
    }

    #[test]
    fn scanner_prescan_skips_impossible_finders() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::email::Email::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line("no at sign here");
        assert!(matches.is_empty());
    }

    #[test]
    fn scanner_dispatch_finds_hash() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::hash::Hash::default())];
        let scanner = Scanner::new(finders);
        let input = "md5: 5d41402abc4b2a76b9719d911017c592";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].range.clone()],
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    #[test]
    fn scanner_dispatch_finds_multiple_hashes() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::hash::Hash::default())];
        let scanner = Scanner::new(finders);
        let input = "5d41402abc4b2a76b9719d911017c592 and 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert_eq!(
            &input[matches[0].range.clone()],
            "5d41402abc4b2a76b9719d911017c592"
        );
        assert_eq!(
            &input[matches[1].range.clone()],
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        );
    }

    #[test]
    fn scanner_mixed_dispatch_and_scan() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
        ];
        let scanner = Scanner::new(finders);
        let input = "user@example.com 5d41402abc4b2a76b9719d911017c592";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert_eq!(&input[matches[0].range.clone()], "user@example.com");
        assert_eq!(
            &input[matches[1].range.clone()],
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    #[test]
    fn scanner_position_ordered_output() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::env::Env::default()),
            Box::new(crate::hash::Hash::default()),
        ];
        let scanner = Scanner::new(finders);
        let input = "5d41402abc4b2a76b9719d911017c592 $HOME";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert!(matches[0].range.start < matches[1].range.start);
    }

    #[test]
    fn scanner_first_returns_earliest() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::env::Env::default()),
            Box::new(crate::hash::Hash::default()),
        ];
        let scanner = Scanner::new(finders);
        let input = "$HOME then 5d41402abc4b2a76b9719d911017c592";
        let m = scanner.scan_line_first(input).unwrap();
        assert_eq!(&input[m.range], "$HOME");
    }

    #[test]
    fn scanner_dispatch_finds_env() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        let input = "use $HOME and ${PATH}";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert_eq!(&input[matches[0].range.clone()], "$HOME");
        assert_eq!(&input[matches[1].range.clone()], "${PATH}");
    }

    #[test]
    fn scanner_dispatch_finds_json() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::json::Json::default())];
        let scanner = Scanner::new(finders);
        let input = r#"data: {"key": "value"} end"#;
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].range.clone()], r#"{"key": "value"}"#);
    }

    #[test]
    fn scanner_dispatch_finds_uuid() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::uuid::Uuid::default())];
        let scanner = Scanner::new(finders);
        let input = "id: 550e8400-e29b-41d4-a716-446655440000 end";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].range.clone()],
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn scanner_dispatch_finds_color() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::color::Color::default())];
        let scanner = Scanner::new(finders);
        let input = "color: #ff00aa and rgb(0, 255, 0)";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert_eq!(&input[matches[0].range.clone()], "#ff00aa");
        assert_eq!(&input[matches[1].range.clone()], "rgb(0, 255, 0)");
    }

    #[test]
    fn scanner_dispatch_finds_ip() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::ip::Ip::default())];
        let scanner = Scanner::new(finders);
        let input = "connect to 192.168.1.1 now";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].range.clone()], "192.168.1.1");
    }

    #[test]
    fn scanner_dispatch_finds_datetime() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::datetime::Datetime::default())];
        let scanner = Scanner::new(finders);
        let input = "at 2024-01-15T10:30:00Z end";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].range.clone()], "2024-01-15T10:30:00Z");
    }

    #[test]
    fn scanner_many_finders() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
            Box::new(crate::env::Env::default()),
            Box::new(crate::json::Json::default()),
            Box::new(crate::ip::Ip::default()),
        ];
        let scanner = Scanner::new(finders);
        let input = r#"192.168.1.1 user@example.com $HOME {"key": "val"} 5d41402abc4b2a76b9719d911017c592"#;
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 5);
        assert_eq!(&input[matches[0].range.clone()], "192.168.1.1");
        assert_eq!(&input[matches[1].range.clone()], "user@example.com");
        assert_eq!(&input[matches[2].range.clone()], "$HOME");
        assert_eq!(&input[matches[3].range.clone()], r#"{"key": "val"}"#);
        assert_eq!(
            &input[matches[4].range.clone()],
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    // --- Edge cases: single byte inputs ---

    #[test]
    fn scanner_single_byte_inputs() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
            Box::new(crate::env::Env::default()),
            Box::new(crate::ip::Ip::default()),
            Box::new(crate::json::Json::default()),
            Box::new(crate::color::Color::default()),
            Box::new(crate::uuid::Uuid::default()),
        ];
        let scanner = Scanner::new(finders);
        for b in 0..=127u8 {
            let s = String::from(b as char);
            let _ = scanner.scan_line(&s);
        }
    }

    #[test]
    fn scanner_two_byte_combinations() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::env::Env::default()),
            Box::new(crate::json::Json::default()),
            Box::new(crate::color::Color::default()),
        ];
        let scanner = Scanner::new(finders);
        let interesting = b"${}[]#rgb()0aA@:/.~+-\"\\";
        for &a in interesting {
            for &b in interesting {
                let s = String::from_utf8(vec![a, b]).unwrap();
                let _ = scanner.scan_line(&s);
            }
        }
    }

    // --- Edge cases: repeated delimiters ---

    #[test]
    fn scanner_repeated_dollars() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("$$$").is_empty());
        assert!(scanner.scan_line("$$$$").is_empty());
    }

    #[test]
    fn scanner_repeated_hashes() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::color::Color::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("###").is_empty());
    }

    #[test]
    fn scanner_repeated_brackets() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::json::Json::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line("{}{}{}");
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn scanner_repeated_dots() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::ip::Ip::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("....").is_empty());
    }

    // --- Edge cases: only whitespace ---

    #[test]
    fn scanner_whitespace() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
        ];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("   \t\n  ").is_empty());
    }

    // --- Edge cases: very long lines ---

    #[test]
    fn scanner_long_hex_run() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::hash::Hash::default())];
        let scanner = Scanner::new(finders);
        let long_hex = "a".repeat(10000);
        assert!(scanner.scan_line(&long_hex).is_empty());
    }

    #[test]
    fn scanner_many_matches_in_line() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        let input = (0..100).map(|i| format!("$VAR{}", i)).collect::<Vec<_>>().join(" ");
        let matches = scanner.scan_line(&input);
        assert_eq!(matches.len(), 100);
    }

    // --- Edge cases: adjacent matches ---

    #[test]
    fn scanner_adjacent_env_vars() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        let input = "$A$B$C";
        let matches = scanner.scan_line(input);
        let texts: Vec<&str> = matches.iter().map(|m| &input[m.range.clone()]).collect();
        assert_eq!(texts, vec!["$A", "$B", "$C"]);
    }

    #[test]
    fn scanner_adjacent_json_objects() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::json::Json::default())];
        let scanner = Scanner::new(finders);
        let input = r#"{"a":1}{"b":2}[3]"#;
        let matches = scanner.scan_line(input);
        let texts: Vec<&str> = matches.iter().map(|m| &input[m.range.clone()]).collect();
        assert_eq!(texts, vec![r#"{"a":1}"#, r#"{"b":2}"#, "[3]"]);
    }

    // --- Edge cases: prescan correctness ---

    #[test]
    fn prescan_all_byte_classes() {
        let input = b"09afAF gZ@$#{}[]:./~+(- ";
        let cl = prescan(input);
        assert_ne!(cl & CL_DIGIT, 0);
        assert_ne!(cl & CL_HEX_ALPHA, 0);
        assert_ne!(cl & CL_ALPHA_OTHER, 0);
        assert_ne!(cl & CL_AT, 0);
        assert_ne!(cl & CL_DOLLAR, 0);
        assert_ne!(cl & CL_HASH, 0);
        assert_ne!(cl & CL_OPEN_BRACE, 0);
        assert_ne!(cl & CL_OPEN_BRACKET, 0);
        assert_ne!(cl & CL_COLON, 0);
        assert_ne!(cl & CL_DOT, 0);
        assert_ne!(cl & CL_SLASH, 0);
        assert_ne!(cl & CL_TILDE, 0);
        assert_ne!(cl & CL_PLUS, 0);
        assert_ne!(cl & CL_OPEN_PAREN, 0);
        assert_ne!(cl & CL_DASH, 0);
    }

    #[test]
    fn prescan_high_bytes_have_no_class() {
        for b in 128..=255u8 {
            assert_eq!(BYTE_CLASSES[b as usize], 0, "byte {} should have no class", b);
        }
    }

    // --- Edge cases: dispatch table ---

    #[test]
    fn dispatch_table_env_only_dollar() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        for b in 0..=255u8 {
            if b == b'$' {
                assert_ne!(scanner.dispatch[b as usize], 0);
            } else {
                assert_eq!(scanner.dispatch[b as usize], 0);
            }
        }
    }

    #[test]
    fn dispatch_table_color_selective() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::color::Color::default())];
        let scanner = Scanner::new(finders);
        assert_ne!(scanner.dispatch[b'#' as usize], 0);
        assert_ne!(scanner.dispatch[b'r' as usize], 0);
        assert_ne!(scanner.dispatch[b'R' as usize], 0);
        assert_ne!(scanner.dispatch[b'h' as usize], 0);
        assert_ne!(scanner.dispatch[b'H' as usize], 0);
        assert_eq!(scanner.dispatch[b'x' as usize], 0);
        assert_eq!(scanner.dispatch[b' ' as usize], 0);
    }

    #[test]
    fn scanner_scan_line_first_with_no_matches() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::email::Email::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line_first("no at sign").is_none());
    }

    #[test]
    fn scanner_scan_line_first_prescan_skip() {
        let finders: Vec<Box<dyn Finder>> =
            vec![Box::new(crate::email::Email::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line_first("no matches possible").is_none());
    }
}
