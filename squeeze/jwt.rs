use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Jwt {}

impl Jwt {
    fn is_base64url(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_' || b == b'='
    }

    fn is_base64url_no_pad(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_'
    }

    fn read_segment(input: &[u8], start: usize) -> Option<usize> {
        let mut pos = start;
        if pos >= input.len() || !Self::is_base64url_no_pad(input[pos]) {
            return None;
        }
        while pos < input.len() && Self::is_base64url(input[pos]) {
            pos += 1;
        }
        // Minimum segment length for a valid JWT part (header is at least ~20 chars base64)
        if pos - start < 4 {
            return None;
        }
        Some(pos)
    }

    fn looks_like_jwt_header(input: &[u8], start: usize, end: usize) -> bool {
        // JWT header is base64url-encoded JSON containing "alg"
        // The base64 of {"alg": always starts with "eyJ"
        end - start >= 4
            && input[start] == b'e'
            && input[start + 1] == b'y'
            && input[start + 2] == b'J'
    }
}

impl Finder for Jwt {
    fn id(&self) -> &'static str {
        "jwt"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        byte == b'e'
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        if input[pos] != b'e' {
            return None;
        }
        if pos > 0 && Self::is_base64url(input[pos - 1]) {
            return None;
        }
        let header_end = Self::read_segment(input, pos)?;
        if !Self::looks_like_jwt_header(input, pos, header_end) {
            return None;
        }
        if header_end >= input.len() || input[header_end] != b'.' {
            return None;
        }
        let payload_end = Self::read_segment(input, header_end + 1)?;
        if payload_end >= input.len() || input[payload_end] != b'.' {
            return None;
        }
        let sig_end = Self::read_segment(input, payload_end + 1)?;
        if sig_end < input.len() && (Self::is_base64url(input[sig_end]) || input[sig_end] == b'.') {
            return None;
        }
        Some(pos..sig_end)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            // JWT headers always start with "eyJ" (base64 of '{"')
            if input[idx] == b'e' {
                // Boundary before
                if idx > 0 && Self::is_base64url(input[idx - 1]) {
                    idx += 1;
                    continue;
                }

                let header_end = match Self::read_segment(input, idx) {
                    Some(end) => end,
                    None => {
                        idx += 1;
                        continue;
                    }
                };

                if !Self::looks_like_jwt_header(input, idx, header_end) {
                    idx += 1;
                    continue;
                }

                // First dot
                if header_end >= input.len() || input[header_end] != b'.' {
                    idx += 1;
                    continue;
                }

                // Payload
                let payload_end = match Self::read_segment(input, header_end + 1) {
                    Some(end) => end,
                    None => {
                        idx += 1;
                        continue;
                    }
                };

                // Second dot
                if payload_end >= input.len() || input[payload_end] != b'.' {
                    idx += 1;
                    continue;
                }

                // Signature
                let sig_end = match Self::read_segment(input, payload_end + 1) {
                    Some(end) => end,
                    None => {
                        idx += 1;
                        continue;
                    }
                };

                // Boundary after: not followed by base64url chars or dot
                if sig_end < input.len()
                    && (Self::is_base64url(input[sig_end]) || input[sig_end] == b'.')
                {
                    idx += 1;
                    continue;
                }

                return Some(idx..sig_end);
            }
            idx += 1;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A realistic JWT (HS256): header.payload.signature
    const JWT_HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // RS256 JWT (longer signature)
    const JWT_RS256: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_5RU8VuLeas";

    #[test]
    fn id_should_return_jwt() {
        let finder = Jwt::default();
        assert_eq!("jwt", finder.id());
    }

    #[test]
    fn find_should_extract_jwt() {
        let finder = Jwt::default();
        let input = format!("token: {}", JWT_HS256);
        let range = finder.find(&input).unwrap();
        assert_eq!(JWT_HS256, &input[range]);
    }

    #[test]
    fn find_should_extract_jwt_at_start() {
        let finder = Jwt::default();
        let input = format!("{} is the token", JWT_HS256);
        let range = finder.find(&input).unwrap();
        assert_eq!(JWT_HS256, &input[range]);
    }

    #[test]
    fn find_should_extract_rs256_jwt() {
        let finder = Jwt::default();
        let range = finder.find(JWT_RS256).unwrap();
        assert_eq!(JWT_RS256, &JWT_RS256[range]);
    }

    #[test]
    fn find_should_extract_jwt_in_text() {
        let finder = Jwt::default();
        let input = format!("Authorization: Bearer {} end", JWT_HS256);
        let range = finder.find(&input).unwrap();
        assert_eq!(JWT_HS256, &input[range]);
    }

    #[test]
    fn find_should_reject_two_segments() {
        let finder = Jwt::default();
        assert!(
            finder
                .find("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0")
                .is_none()
        );
    }

    #[test]
    fn find_should_reject_non_eyj_prefix() {
        let finder = Jwt::default();
        assert!(finder.find("abc.def.ghi").is_none());
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Jwt::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_reject_preceded_by_alphanumeric() {
        let finder = Jwt::default();
        let input = format!("x{}", JWT_HS256);
        assert!(finder.find(&input).is_none());
    }

    #[test]
    fn find_should_extract_multiple_jwts_iteratively() {
        let finder = Jwt::default();
        let input = format!("{} and {}", JWT_HS256, JWT_RS256);

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

        assert_eq!(vec![JWT_HS256, JWT_RS256], results);
    }

    #[test]
    fn find_should_reject_short_segments() {
        let finder = Jwt::default();
        assert!(finder.find("eyJ.ab.cd").is_none());
    }

    #[test]
    fn try_at_valid_jwt() {
        let finder = Jwt::default();
        let input = JWT_HS256.as_bytes();
        assert_eq!(finder.try_at(input, 0), Some(0..input.len()));
    }

    #[test]
    fn try_at_preceded_by_base64() {
        let finder = Jwt::default();
        let input = format!("x{}", JWT_HS256);
        assert!(finder.try_at(input.as_bytes(), 1).is_none());
    }

    #[test]
    fn try_at_non_e() {
        let finder = Jwt::default();
        assert!(finder.try_at(b"abc", 0).is_none());
    }

    #[test]
    fn try_at_single_e() {
        let finder = Jwt::default();
        assert!(finder.try_at(b"e", 0).is_none());
    }

    #[test]
    fn try_at_eyj_only() {
        let finder = Jwt::default();
        assert!(finder.try_at(b"eyJ", 0).is_none());
    }

    #[test]
    fn find_four_segments_finds_inner_jwt() {
        let finder = Jwt::default();
        let input = format!("{}.extra", JWT_HS256);
        let range = finder.find(&input).unwrap();
        let found = &input[range];
        assert!(found.starts_with("eyJzdWIi"));
        assert!(found.ends_with("extra"));
    }

    #[test]
    fn find_should_extract_jwt_after_space() {
        let finder = Jwt::default();
        let input = format!(" {}", JWT_HS256);
        let range = finder.find(&input).unwrap();
        assert_eq!(JWT_HS256, &input[range]);
    }
}
