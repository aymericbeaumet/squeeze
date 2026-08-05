use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Jwt {}

impl Jwt {
    /// Unpadded base64url alphabet (RFC 4648 section 5): `A-Z a-z 0-9 - _`.
    /// `+`, `/` and `=` are *not* part of it: treating them as segment
    /// characters both missed JWTs after `TOKEN=` / `?t=` / `/verify/`
    /// (boundary-before check) and glued `=` padding into signatures.
    fn is_base64url(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
    }

    /// End of the run of base64url characters starting at `start`.
    fn run_end(input: &[u8], start: usize) -> usize {
        let mut pos = start;
        while pos < input.len() && Self::is_base64url(input[pos]) {
            pos += 1;
        }
        pos
    }

    /// Match a JWT starting exactly at `pos` (which must hold `e`).
    /// Returns the exclusive end of the match.
    fn match_end(input: &[u8], pos: usize) -> Option<usize> {
        // Header: base64url-encoded JSON containing "alg"; the base64 of
        // `{"` always starts with "eyJ".
        let header_end = Self::run_end(input, pos);
        if header_end - pos < 4 || &input[pos..pos + 3] != b"eyJ" {
            return None;
        }
        if header_end >= input.len() || input[header_end] != b'.' {
            return None;
        }
        // Payload: base64url of a JSON claims object. `{` = 0x7B, so the
        // first sextet is 011110 -> 'e'; the shortest legal payload is
        // `e30` (= `{}`).
        let payload_start = header_end + 1;
        if payload_start >= input.len() || input[payload_start] != b'e' {
            return None;
        }
        let payload_end = Self::run_end(input, payload_start);
        if payload_end - payload_start < 3 {
            return None;
        }
        if payload_end >= input.len() || input[payload_end] != b'.' {
            return None;
        }
        // Signature: empty for unsecured JWTs (RFC 7519 section 6), in
        // which case the match includes the trailing dot; otherwise at
        // least 4 base64url characters.
        let sig_start = payload_end + 1;
        let sig_end = Self::run_end(input, sig_start);
        if sig_end == sig_start {
            return Some(sig_start);
        }
        if sig_end - sig_start < 4 {
            return None;
        }
        // Boundary after: a fourth dotted segment means this candidate is
        // not the signature; the caller retries further in.
        if sig_end < input.len() && input[sig_end] == b'.' {
            return None;
        }
        Some(sig_end)
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
        // Boundary before: an immediately preceding base64url character
        // means `pos` is inside a longer run.
        if pos > 0 && Self::is_base64url(input[pos - 1]) {
            return None;
        }
        Self::match_end(input, pos).map(|end| pos..end)
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            // JWT headers always start with "eyJ" (base64 of '{"').
            if input[idx] == b'e'
                && (idx == 0 || !Self::is_base64url(input[idx - 1]))
                && let Some(end) = Self::match_end(input, idx)
            {
                return Some(idx..end);
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
    fn find_four_segments_with_non_json_tail_yields_none() {
        // `JWT.extra`: the only inner candidate would use the original
        // signature ("SflK...") as its payload, which cannot be a base64url
        // JSON object (no leading 'e'), so nothing matches.
        let finder = Jwt::default();
        let input = format!("{}.extra", JWT_HS256);
        assert!(finder.find(&input).is_none());
    }

    #[test]
    fn find_four_eyj_segments_finds_inner_jwt() {
        let finder = Jwt::default();
        let input = "eyJab.eyJcd.eyJef.extra";
        let range = finder.find(input).unwrap();
        assert_eq!("eyJcd.eyJef.extra", &input[range]);
    }

    #[test]
    fn find_should_extract_jwt_after_space() {
        let finder = Jwt::default();
        let input = format!(" {}", JWT_HS256);
        let range = finder.find(&input).unwrap();
        assert_eq!(JWT_HS256, &input[range]);
    }
}
