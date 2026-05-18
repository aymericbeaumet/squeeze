use super::Finder;
use std::ops::Range;

const MD5_LEN: usize = 32;
const SHA1_LEN: usize = 40;
const SHA256_LEN: usize = 64;
const SHA512_LEN: usize = 128;

const MD5_BIT: u8 = 1;
const SHA1_BIT: u8 = 2;
const SHA256_BIT: u8 = 4;
const SHA512_BIT: u8 = 8;
const ALL_BITS: u8 = MD5_BIT | SHA1_BIT | SHA256_BIT | SHA512_BIT;

#[derive(Default)]
pub struct Hash {
    lengths: u8,
}

impl Hash {
    pub fn add_algorithm(&mut self, name: &str) {
        let bit = match name.to_lowercase().as_str() {
            "md5" => MD5_BIT,
            "sha1" | "sha-1" => SHA1_BIT,
            "sha256" | "sha-256" => SHA256_BIT,
            "sha512" | "sha-512" => SHA512_BIT,
            _ => return,
        };
        self.lengths |= bit;
    }

    fn is_target_length(&self, len: usize) -> bool {
        let bit = match len {
            MD5_LEN => MD5_BIT,
            SHA1_LEN => SHA1_BIT,
            SHA256_LEN => SHA256_BIT,
            SHA512_LEN => SHA512_BIT,
            _ => return false,
        };
        let mask = if self.lengths == 0 { ALL_BITS } else { self.lengths };
        (mask & bit) != 0
    }

    fn is_hex(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }
}

impl Finder for Hash {
    fn id(&self) -> &'static str {
        "hash"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        byte.is_ascii_hexdigit()
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        if !Self::is_hex(input[pos]) {
            return None;
        }
        if pos > 0 && Self::is_hex(input[pos - 1]) {
            return None;
        }
        let mut end = pos;
        while end < input.len() && Self::is_hex(input[end]) {
            end += 1;
        }
        if self.is_target_length(end - pos) {
            Some(pos..end)
        } else {
            None
        }
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            if !Self::is_hex(input[idx]) {
                idx += 1;
                continue;
            }

            // Check boundary before
            if idx > 0 && Self::is_hex(input[idx - 1]) {
                idx += 1;
                continue;
            }

            let start = idx;
            let mut end = start;
            while end < input.len() && Self::is_hex(input[end]) {
                end += 1;
            }

            let len = end - start;

            if self.is_target_length(len) {
                return Some(start..end);
            }

            idx = end;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_hash() {
        let finder = Hash::default();
        assert_eq!("hash", finder.id());
    }

    #[test]
    fn find_should_extract_md5() {
        let finder = Hash::default();
        let input = "md5: 5d41402abc4b2a76b9719d911017c592";
        let range = finder.find(input).unwrap();
        assert_eq!("5d41402abc4b2a76b9719d911017c592", &input[range]);
    }

    #[test]
    fn find_should_extract_sha1() {
        let finder = Hash::default();
        let input = "sha1: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
        let range = finder.find(input).unwrap();
        assert_eq!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed", &input[range]);
    }

    #[test]
    fn find_should_extract_sha256() {
        let finder = Hash::default();
        let input = "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let range = finder.find(input).unwrap();
        assert_eq!(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            &input[range]
        );
    }

    #[test]
    fn find_should_extract_sha512() {
        let finder = Hash::default();
        let input = "sha512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let range = finder.find(input).unwrap();
        assert_eq!(128, input[range].len());
    }

    #[test]
    fn find_should_extract_uppercase_hash() {
        let finder = Hash::default();
        let input = "5D41402ABC4B2A76B9719D911017C592";
        let range = finder.find(input).unwrap();
        assert_eq!("5D41402ABC4B2A76B9719D911017C592", &input[range]);
    }

    #[test]
    fn find_should_filter_by_algorithm() {
        let mut finder = Hash::default();
        finder.add_algorithm("sha256");

        let md5 = "5d41402abc4b2a76b9719d911017c592";
        assert!(finder.find(md5).is_none());

        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(finder.find(sha256).is_some());
    }

    #[test]
    fn find_should_filter_md5_only() {
        let mut finder = Hash::default();
        finder.add_algorithm("md5");

        let input = "5d41402abc4b2a76b9719d911017c592";
        assert!(finder.find(input).is_some());

        let sha1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
        assert!(finder.find(sha1).is_none());
    }

    #[test]
    fn find_should_not_match_short_hex() {
        let finder = Hash::default();
        assert!(finder.find("deadbeef").is_none());
    }

    #[test]
    fn find_should_not_match_within_longer_hex() {
        let finder = Hash::default();
        // 33 hex chars — not a valid hash length, and should not partially match
        let input = "a5d41402abc4b2a76b9719d911017c592";
        assert!(finder.find(input).is_none());
    }

    #[test]
    fn find_should_not_match_with_trailing_hex() {
        let finder = Hash::default();
        let input = "5d41402abc4b2a76b9719d911017c592a";
        assert!(finder.find(input).is_none());
    }

    #[test]
    fn find_should_extract_hash_in_text() {
        let finder = Hash::default();
        let input = "commit 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed in main";
        let range = finder.find(input).unwrap();
        assert_eq!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed", &input[range]);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Hash::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_extract_multiple_hashes_iteratively() {
        let finder = Hash::default();
        let input = "5d41402abc4b2a76b9719d911017c592 and 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";

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

        assert_eq!(
            vec![
                "5d41402abc4b2a76b9719d911017c592",
                "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
            ],
            results
        );
    }

    #[test]
    fn add_algorithm_should_accept_various_names() {
        let mut finder = Hash::default();
        finder.add_algorithm("sha-256");
        assert!(finder.lengths & SHA256_BIT != 0);

        finder.add_algorithm("SHA1");
        assert!(finder.lengths & SHA1_BIT != 0);

        finder.add_algorithm("SHA-512");
        assert!(finder.lengths & SHA512_BIT != 0);
    }

    #[test]
    fn add_algorithm_should_ignore_unknown() {
        let mut finder = Hash::default();
        finder.add_algorithm("blake2");
        assert_eq!(0, finder.lengths);
    }

    #[test]
    fn try_at_matches_find_at_start() {
        let finder = Hash::default();
        let input = b"5d41402abc4b2a76b9719d911017c592 trail";
        assert!(finder.try_at(input, 0).is_some());
        assert_eq!(finder.try_at(input, 0).unwrap(), 0..32);
    }

    #[test]
    fn try_at_rejects_mid_hex_run() {
        let finder = Hash::default();
        let input = b"a5d41402abc4b2a76b9719d911017c592";
        assert!(finder.try_at(input, 1).is_none());
    }

    #[test]
    fn try_at_at_last_byte() {
        let finder = Hash::default();
        let input = b"x";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn try_at_single_hex_byte() {
        let finder = Hash::default();
        let input = b"a";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn find_should_not_match_non_hex_chars() {
        let finder = Hash::default();
        assert!(finder.find("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }

    #[test]
    fn find_should_match_all_hex_letters() {
        let finder = Hash::default();
        let input = "abcdefABCDEFabcdefABCDEFabcdefAB";
        assert_eq!(finder.find(input).unwrap(), 0..32);
    }
}
