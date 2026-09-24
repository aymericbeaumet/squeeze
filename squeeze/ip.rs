use super::{Anchor, ByteSet, Finder, Memo, RunClass, RunRule};
use std::ops::Range;

pub struct Ip {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Default for Ip {
    fn default() -> Self {
        Ip {
            ipv4: true,
            ipv6: true,
        }
    }
}

/// Longest textual IPv6 address (with an embedded IPv4 tail) plus brackets.
const MAX_BRACKETED_IPV6: usize = 47;

impl Ip {
    /// Maximal run of `[0-9a-fA-F:.]` bytes containing `idx`, remembered in
    /// `memo` so every candidate inside the same run costs O(1): both the
    /// bare IPv6 forward scan and the IPv4 boundary walk need it.
    pub(crate) fn run_bounds(input: &[u8], idx: usize, memo: &mut Memo) -> (usize, usize) {
        if memo.covers(idx) {
            return (memo.start, memo.end);
        }
        let is_run = |b: u8| b.is_ascii_hexdigit() || b == b':' || b == b'.';
        let mut start = idx;
        while start > 0 && is_run(input[start - 1]) {
            start -= 1;
        }
        let mut end = idx;
        while end < input.len() && is_run(input[end]) {
            end += 1;
        }
        // Where a candidate ending at the run's end lands after the lone
        // trailing colon and sentence-dot strips of `try_bare_ipv6`; shared
        // so those strips do not rescan a long tail for every candidate.
        let mut stripped = end;
        if stripped > start
            && input[stripped - 1] == b':'
            && !(stripped - start >= 2 && input[stripped - 2] == b':')
        {
            stripped -= 1;
        }
        while stripped > start && input[stripped - 1] == b'.' {
            stripped -= 1;
        }
        *memo = Memo {
            start,
            end,
            aux: stripped,
        };
        (start, end)
    }

    fn try_ipv4(input: &[u8], idx: usize, memo: &mut Memo) -> Option<Range<usize>> {
        if !input[idx].is_ascii_digit() {
            return None;
        }
        // Boundary before: not preceded by digit or dot
        if idx > 0 && (input[idx - 1].is_ascii_digit() || input[idx - 1] == b'.') {
            return None;
        }
        // A quad directly after ':' sits inside an IPv6-shaped run
        // (`1::2::1.2.3.4`, `:::1.2.3.4`). If that run starts at a token
        // boundary it was an IPv6 candidate, and the dotted interior of a
        // failed candidate must not be re-extracted as bare IPv4. Only a run
        // glued to a non-hex alphanumeric (`port:10.0.0.1`) was never an IPv6
        // candidate, so its quad may still match.
        if idx > 0 && input[idx - 1] == b':' {
            let (run_start, _) = Self::run_bounds(input, idx, memo);
            if run_start == 0 || !input[run_start - 1].is_ascii_alphanumeric() {
                return None;
            }
        }

        let start = idx;
        let mut pos = idx;

        for octet_idx in 0..4 {
            if octet_idx > 0 {
                if pos >= input.len() || input[pos] != b'.' {
                    return None;
                }
                pos += 1;
            }

            let octet_start = pos;
            while pos < input.len() && input[pos].is_ascii_digit() {
                pos += 1;
            }
            let octet_len = pos - octet_start;
            if octet_len == 0 || octet_len > 3 {
                return None;
            }

            // No leading zeros (except "0" itself)
            if octet_len > 1 && input[octet_start] == b'0' {
                return None;
            }

            let mut value: u16 = 0;
            for &b in &input[octet_start..pos] {
                value = value * 10 + (b - b'0') as u16;
            }
            if value > 255 {
                return None;
            }
        }

        // Boundary after: not followed by digit or dot
        if pos < input.len() && (input[pos].is_ascii_digit() || input[pos] == b'.') {
            return None;
        }

        Some(start..pos)
    }

    fn try_bracketed_ipv6(input: &[u8], idx: usize) -> Option<Range<usize>> {
        if input[idx] != b'[' {
            return None;
        }

        // A closing bracket further away than the longest address cannot
        // enclose a valid one, so the search is bounded.
        let window = &input[idx..input.len().min(idx + MAX_BRACKETED_IPV6)];
        let close = window.iter().position(|&b| b == b']')?;
        let close_pos = idx + close;
        let inner = &input[idx + 1..close_pos];

        if crate::ipv6::is_valid_ipv6(inner) {
            Some(idx..close_pos + 1)
        } else {
            None
        }
    }

    fn try_bare_ipv6(input: &[u8], idx: usize, memo: &mut Memo) -> Option<Range<usize>> {
        // Must start with hex digit or ':'
        if !input[idx].is_ascii_hexdigit() && input[idx] != b':' {
            return None;
        }

        // Boundary before: not preceded by hex digit, colon, or alphanumeric
        if idx > 0 && (input[idx - 1].is_ascii_alphanumeric() || input[idx - 1] == b':') {
            return None;
        }

        let start = idx;
        let (_, mut end) = Self::run_bounds(input, idx, memo);

        // Boundary after: a letter glued to the run means the run is part of a
        // larger token (`2001:db8::1x`). The maximal run never stops on ':'
        // or '.', so this is the only live rejection; the strips below may
        // re-expose a ':' or '.' at the new end, which is fine by design.
        if end < input.len() && input[end].is_ascii_alphanumeric() {
            return None;
        }

        // Strip a lone trailing colon (`fe80::1:` -> `fe80::1`), preserving
        // a trailing `::`.
        while end > start && input[end - 1] == b':' && !(end - start >= 2 && input[end - 2] == b':')
        {
            end -= 1;
        }

        // Sentence-dot recovery target: trailing '.'s cannot belong to an
        // embedded IPv4 tail (the run is maximal, so the next byte is not a
        // digit), so `see 2001:db8::1. next` still yields the address. The
        // run's stripped end was computed once by `run_bounds`.
        let dot_end = memo.aux.clamp(start, end);

        // Neither the candidate nor its dot-stripped form can be an address
        // when even the shorter one is longer than any address; checking
        // this first keeps a candidate spanning a huge run O(1).
        if dot_end - start > crate::ipv6::MAX_IPV6_LEN {
            return None;
        }

        // Must contain at least one colon (dots carry none, so the shorter
        // form decides for both).
        if !input[start..dot_end].contains(&b':') {
            return None;
        }

        if crate::ipv6::is_valid_ipv6(&input[start..end]) {
            return Some(start..end);
        }

        if dot_end < end && crate::ipv6::is_valid_ipv6(&input[start..dot_end]) {
            return Some(start..dot_end);
        }

        None
    }
}

impl Finder for Ip {
    fn line_agnostic(&self) -> bool {
        // Matches never contain a line terminator and `\n`/`\r` end every
        // walk exactly like the end of the input does.
        true
    }

    fn id(&self) -> &'static str {
        "ip"
    }

    fn dispatchable(&self) -> bool {
        true
    }

    fn could_start_at(&self, byte: u8) -> bool {
        (self.ipv4 && byte.is_ascii_digit())
            || (self.ipv6 && (byte.is_ascii_hexdigit() || byte == b':' || byte == b'['))
    }

    fn could_start_after(&self, prev: u8, cur: u8) -> bool {
        if cur == b'[' {
            return true;
        }
        let v6 = self.ipv6
            && (cur.is_ascii_hexdigit() || cur == b':')
            && !(prev.is_ascii_alphanumeric() || prev == b':');
        let v4 = self.ipv4 && cur.is_ascii_digit() && !(prev.is_ascii_digit() || prev == b'.');
        v6 || v4
    }

    fn could_continue_with(&self, cur: u8, next: u8) -> bool {
        cur == b'[' || next.is_ascii_hexdigit() || next == b':' || next == b'.'
    }

    fn anchor(&self) -> Option<Anchor> {
        let mut bytes = ByteSet::EMPTY;
        if self.ipv4 {
            bytes = bytes.with(b'.');
        }
        if self.ipv6 {
            bytes = bytes.with(b':');
        }
        Some(Anchor {
            bytes,
            walk: ByteSet::from_fn(|b| b.is_ascii_hexdigit() || matches!(b, b'.' | b':' | b'[')),
        })
    }

    fn run_rules(&self) -> Vec<RunRule> {
        let mut rules = Vec::new();
        if self.ipv4 {
            rules.push(RunRule::new(RunClass::Digit, 1, 3).followed_by(b"."));
        }
        if self.ipv6 {
            rules.push(RunRule::new(RunClass::Hex, 1, 4).followed_by(b":"));
        }
        rules
    }

    fn try_at(&self, input: &[u8], pos: usize) -> Option<Range<usize>> {
        self.try_at_memo(input, pos, &mut Memo::default())
    }

    fn try_at_memo(&self, input: &[u8], pos: usize, memo: &mut Memo) -> Option<Range<usize>> {
        if self.ipv6 {
            if input[pos] == b'['
                && let Some(range) = Self::try_bracketed_ipv6(input, pos)
            {
                return Some(range);
            }
            if (input[pos].is_ascii_hexdigit() || input[pos] == b':')
                && let Some(range) = Self::try_bare_ipv6(input, pos, memo)
            {
                return Some(range);
            }
        }
        if self.ipv4
            && input[pos].is_ascii_digit()
            && let Some(range) = Self::try_ipv4(input, pos, memo)
        {
            return Some(range);
        }
        None
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            if self.ipv6 {
                if input[idx] == b'['
                    && let Some(range) = Self::try_bracketed_ipv6(input, idx)
                {
                    return Some(range);
                }

                if (input[idx].is_ascii_hexdigit() || input[idx] == b':')
                    && let Some(range) = Self::try_bare_ipv6(input, idx, &mut Memo::default())
                {
                    return Some(range);
                }
            }

            if self.ipv4
                && input[idx].is_ascii_digit()
                && let Some(range) = Self::try_ipv4(input, idx, &mut Memo::default())
            {
                return Some(range);
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
    fn id_should_return_ip() {
        let finder = Ip::default();
        assert_eq!("ip", finder.id());
    }

    // IPv4 tests
    #[test]
    fn find_should_extract_ipv4() {
        let finder = Ip::default();
        let input = "server at 192.168.1.1 running";
        let range = finder.find(input).unwrap();
        assert_eq!("192.168.1.1", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv4_at_start() {
        let finder = Ip::default();
        let input = "10.0.0.1 is gateway";
        let range = finder.find(input).unwrap();
        assert_eq!("10.0.0.1", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv4_at_end() {
        let finder = Ip::default();
        let input = "connect to 172.16.0.1";
        let range = finder.find(input).unwrap();
        assert_eq!("172.16.0.1", &input[range]);
    }

    #[test]
    fn find_should_extract_localhost() {
        let finder = Ip::default();
        let input = "127.0.0.1";
        let range = finder.find(input).unwrap();
        assert_eq!("127.0.0.1", &input[range]);
    }

    #[test]
    fn find_should_extract_all_zeros() {
        let finder = Ip::default();
        let input = "0.0.0.0";
        let range = finder.find(input).unwrap();
        assert_eq!("0.0.0.0", &input[range]);
    }

    #[test]
    fn find_should_extract_max_values() {
        let finder = Ip::default();
        let input = "255.255.255.255";
        let range = finder.find(input).unwrap();
        assert_eq!("255.255.255.255", &input[range]);
    }

    #[test]
    fn find_should_reject_octet_over_255() {
        let finder = Ip::default();
        assert!(finder.find("256.1.1.1").is_none());
    }

    #[test]
    fn find_should_reject_three_octets() {
        let finder = Ip::default();
        assert!(finder.find("192.168.1 only").is_none());
    }

    #[test]
    fn find_should_reject_five_octets() {
        let finder = Ip::default();
        assert!(finder.find("192.168.1.1.1").is_none());
    }

    #[test]
    fn find_should_reject_leading_zeros() {
        let finder = Ip::default();
        assert!(finder.find("192.168.01.1").is_none());
    }

    #[test]
    fn find_should_reject_preceded_by_digit() {
        let finder = Ip::default();
        assert!(finder.find("9192.168.1.1").is_none());
    }

    // IPv6 tests
    #[test]
    fn find_should_extract_bracketed_ipv6() {
        let finder = Ip::default();
        let input = "connect to [::1] now";
        let range = finder.find(input).unwrap();
        assert_eq!("[::1]", &input[range]);
    }

    #[test]
    fn find_should_extract_full_ipv6() {
        let finder = Ip::default();
        let input = "addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 here";
        let range = finder.find(input).unwrap();
        assert_eq!("2001:0db8:85a3:0000:0000:8a2e:0370:7334", &input[range]);
    }

    #[test]
    fn find_should_extract_compressed_ipv6() {
        let finder = Ip::default();
        let input = "addr 2001:db8::1 here";
        let range = finder.find(input).unwrap();
        assert_eq!("2001:db8::1", &input[range]);
    }

    #[test]
    fn find_should_extract_loopback_ipv6() {
        let finder = Ip::default();
        let input = "[::1]";
        let range = finder.find(input).unwrap();
        assert_eq!("[::1]", &input[range]);
    }

    #[test]
    fn find_should_extract_bare_double_colon() {
        let finder = Ip::default();
        let input = "addr :: here";
        let range = finder.find(input).unwrap();
        assert_eq!("::", &input[range]);
    }

    #[test]
    fn find_should_extract_ipv6_with_prefix_groups() {
        let finder = Ip::default();
        let input = "fe80::1";
        let range = finder.find(input).unwrap();
        assert_eq!("fe80::1", &input[range]);
    }

    // Filter tests
    #[test]
    fn find_should_only_match_ipv4_when_configured() {
        let finder = Ip {
            ipv4: true,
            ipv6: false,
        };
        let input = "192.168.1.1 and [::1]";
        let range = finder.find(input).unwrap();
        assert_eq!("192.168.1.1", &input[range]);
    }

    #[test]
    fn find_should_only_match_ipv6_when_configured() {
        let finder = Ip {
            ipv4: false,
            ipv6: true,
        };
        let input = "192.168.1.1 and [::1]";
        let range = finder.find(input).unwrap();
        assert_eq!("[::1]", &input[range]);
    }

    // Multiple
    #[test]
    fn find_should_extract_multiple_ips_iteratively() {
        let finder = Ip::default();
        let input = "10.0.0.1 and 10.0.0.2";

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

        assert_eq!(vec!["10.0.0.1", "10.0.0.2"], results);
    }

    #[test]
    fn find_should_handle_empty_input() {
        let finder = Ip::default();
        assert!(finder.find("").is_none());
    }

    #[test]
    fn find_should_handle_no_ip() {
        let finder = Ip::default();
        assert!(finder.find("just some text").is_none());
    }

    #[test]
    fn try_at_ipv4_at_start() {
        let finder = Ip::default();
        let input = b"192.168.1.1 rest";
        assert_eq!(finder.try_at(input, 0), Some(0..11));
    }

    #[test]
    fn try_at_ipv4_mid_string() {
        let finder = Ip::default();
        let input = b"host 10.0.0.1 port";
        assert_eq!(finder.try_at(input, 5), Some(5..13));
    }

    #[test]
    fn try_at_rejects_non_digit() {
        let finder = Ip::default();
        let input = b"abc";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn try_at_single_digit() {
        let finder = Ip::default();
        let input = b"1";
        assert!(finder.try_at(input, 0).is_none());
    }

    #[test]
    fn find_should_reject_empty_octets() {
        let finder = Ip::default();
        assert!(finder.find("192..1.1").is_none());
    }

    #[test]
    fn find_should_reject_all_dots() {
        let finder = Ip::default();
        assert!(finder.find("...").is_none());
    }

    #[test]
    fn try_at_bracketed_ipv6() {
        let finder = Ip::default();
        let input = b"[::1]";
        assert_eq!(finder.try_at(input, 0), Some(0..5));
    }

    #[test]
    fn find_ipv6_link_local() {
        let finder = Ip::default();
        let input = "addr fe80::1 here";
        let range = finder.find(input).unwrap();
        assert_eq!("fe80::1", &input[range]);
    }
}
