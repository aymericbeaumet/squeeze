// https://tools.ietf.org/html/rfc3986#appendix-A

use super::Finder;
use std::collections::HashSet;
use std::ops::Range;

#[derive(Clone, Copy)]
struct SchemeConfig(u8);

impl SchemeConfig {
    fn has(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }
}

impl Default for SchemeConfig {
    fn default() -> Self {
        SchemeConfig(0)
    }
}

struct SchemeConfigs(phf::Map<&'static str, SchemeConfig>);

impl SchemeConfigs {
    fn get(&self, key: &str) -> SchemeConfig {
        if let Some(sc) = self.0.get(key) {
            *sc
        } else {
            SchemeConfig::default()
        }
    }
}

const DISALLOW_EMPTY_HOST: u8 = 1 << 0;

static SCHEMES_CONFIGS: SchemeConfigs = SchemeConfigs(phf::phf_map! {
    "ftp" => SchemeConfig(DISALLOW_EMPTY_HOST),
    "http" => SchemeConfig(DISALLOW_EMPTY_HOST),
    "https" => SchemeConfig(DISALLOW_EMPTY_HOST),
});

#[derive(Default)]
pub struct URI {
    schemes: HashSet<String>,
}

impl URI {
    pub fn add_scheme(&mut self, s: &str) {
        self.schemes.insert(s.to_lowercase());
    }
}

impl Finder for URI {
    fn id(&self) -> &'static str {
        "uri"
    }

    // scheme ":" hier-part [ "?" query ] [ "#" fragment ]
    fn find(&self, s: &str) -> Option<Range<usize>> {
        let input = s.as_bytes();
        let mut idx = 0;

        while idx < input.len() {
            let start = idx;

            let colon_idx = start + &input[start..].iter().position(|&b| b == b':')?;
            idx = colon_idx + 1;

            let scheme_idx = match rlook_scheme(&input[start..colon_idx]) {
                Some(i) => start + i,
                None => continue,
            };
            let scheme = &s[scheme_idx..colon_idx];
            let scheme_config = SCHEMES_CONFIGS.get(scheme);

            idx += look_hier_part(&input[idx..], scheme_config)?;
            idx += look_question_mark_query(&input[idx..]).unwrap_or(0);
            idx += look_sharp_fragment(&input[idx..]).unwrap_or(0);

            // we cannot early exit as soon as we know the scheme as we need to advance idx even if the
            // url should be discarded
            if self.schemes.is_empty() || self.schemes.contains(scheme) {
                return Some(scheme_idx..idx);
            }
        }

        None
    }
}

// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
fn rlook_scheme(input: &[u8]) -> Option<usize> {
    let mut idx = None;
    for (i, &c) in input.iter().enumerate().rev() {
        if is_alpha(c) {
            idx = Some(i);
        } else if is_digit(c) || [b'+', b'-', b'.'].contains(&c) {
            // noop
        } else {
            break;
        }
    }
    idx
}

// hier-part = "//" authority path-abempty
//           / path-absolute
//           / path-rootless
//           / path-empty
fn look_hier_part(input: &[u8], sc: SchemeConfig) -> Option<usize> {
    // "//" authority path-abempty
    if let Some(idx) = look_slash_slash(input)
        .and_then(|idx| Some(idx + look_authority(&input[idx..], sc)?))
        .map(|idx| idx + look_path_abempty(&input[idx..]))
    {
        return Some(idx);
    }

    // Some protocols disallow empty hosts
    if sc.has(DISALLOW_EMPTY_HOST) {
        return None;
    }

    // "/" [ segment-nz path-abempty ]
    if let Some(idx) = look_slash(input).map(|idx| {
        idx + look_segment_nz(&input[idx..])
            .map(|i| i + look_path_abempty(&input[idx + i..]))
            .unwrap_or(0)
    }) {
        return Some(idx);
    }

    // segment-nz path-abempty
    if let Some(idx) = look_segment_nz(input).map(|idx| idx + look_path_abempty(&input[idx..])) {
        return Some(idx);
    }

    // 0<pchar>
    Some(0)
}

// [ userinfo "@" ] host [ ":" port ]
fn look_authority(input: &[u8], sc: SchemeConfig) -> Option<usize> {
    let mut idx = 0;
    idx += look_userinfo_at(&input[idx..]).unwrap_or(0);
    idx += look_host(&input[idx..]).and_then(|i| {
        if i == 0 {
            if sc.has(DISALLOW_EMPTY_HOST) {
                return None;
            }
        }
        Some(i)
    })?;
    idx += look_colon_port(&input[idx..]).unwrap_or(0);
    Some(idx)
}

fn look_colon_port(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += look_colon(&input[idx..])?;
    idx += look_port(&input[idx..]);
    Some(idx)
}

// *( "/" segment )
fn look_path_abempty(input: &[u8]) -> usize {
    let mut idx = 0;
    while idx < input.len() {
        idx += match look_slash(&input[idx..]).map(|i| i + look_segment(&input[idx + i..])) {
            Some(n) => n,
            None => break,
        };
    }
    idx
}

// *pchar
fn look_segment(input: &[u8]) -> usize {
    let mut idx = 0;
    while idx < input.len() {
        idx += match look_pchar(&input[idx..]) {
            Some(n) => n,
            None => break,
        };
    }
    idx
}

// 1*pchar
fn look_segment_nz(input: &[u8]) -> Option<usize> {
    match look_segment(input) {
        0 => None,
        n => Some(n),
    }
}

// userinfo "@"
fn look_userinfo_at(input: &[u8]) -> Option<usize> {
    let arobase_idx = input.iter().take(256).position(|&b| b == b'@')?;
    if is_userinfo(&input[..arobase_idx]) {
        Some(arobase_idx + 1)
    } else {
        None
    }
}

// IP-literal / IPv4address / reg-name
fn look_host(input: &[u8]) -> Option<usize> {
    look_ip_literal(input)
        .or_else(|| look_ipv4_address(input))
        .or_else(|| look_hostname(input))
}

// "[" ( IPv6address / IPvFuture  ) "]"
fn look_ip_literal(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += look_left_bracket(&input[idx..])?;
    let right_bracket_index = (&input[idx..]).iter().take(64).position(|&b| b == b']')?;
    if right_bracket_index > 0 {
        let end = idx + right_bracket_index;
        let slice = &input[idx..end];
        if is_ipv6address(slice) || is_ipvfuture(slice) {
            return Some(end + 1);
        }
    }
    None
}

// https://tools.ietf.org/html/rfc4291#section-2.2
fn is_ipv6address(input: &[u8]) -> bool {
    let mut idx = 0;

    let mut bytes_count = 0;
    let mut double_colon_found = false;

    while idx < input.len() {
        let mut last_is_colon = false;
        while let Some(i) = look_colon(&input[idx..]) {
            if last_is_colon {
                if double_colon_found {
                    return false;
                }
                double_colon_found = true;
                bytes_count += 2;
            }
            last_is_colon = true;
            idx += i;
        }

        if last_is_colon || idx == 0 {
            if bytes_count == 12 || double_colon_found {
                if let Some(i) = look_ipv4_address(&input[idx..]) {
                    bytes_count += 4;
                    idx += i;
                    break;
                }
            }
            if let Some(i) = look_h16(&input[idx..]) {
                bytes_count += 2;
                idx += i;
                continue;
            }
        }

        break;
    }

    idx == input.len() && (bytes_count == 16 || (double_colon_found && bytes_count <= 12))
}

// 1*4HEXDIG
fn look_h16(input: &[u8]) -> Option<usize> {
    let idx = input.iter().take_while(|&&b| is_hexdig(b)).take(4).count();
    if idx >= 1 {
        Some(idx)
    } else {
        None
    }
}

// "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
fn is_ipvfuture(_input: &[u8]) -> bool {
    // TODO: implementation
    false
}

// dec-octet "." dec-octet "." dec-octet "." dec-octet
fn look_ipv4_address(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += look_dec_octet(&input[idx..])?;
    idx += look_period(&input[idx..])?;
    idx += look_dec_octet(&input[idx..])?;
    idx += look_period(&input[idx..])?;
    idx += look_dec_octet(&input[idx..])?;
    idx += look_period(&input[idx..])?;
    idx += look_dec_octet(&input[idx..])?;
    Some(idx)
}

// dec-octet     = DIGIT                 ; 0-9
//               / %x31-39 DIGIT         ; 10-99
//               / "1" 2DIGIT            ; 100-199
//               / "2" %x30-34 DIGIT     ; 200-249
//               / "25" %x30-35          ; 250-255
fn look_dec_octet(input: &[u8]) -> Option<usize> {
    if input.len() >= 3 && input[0] == b'2' && input[1] == b'5' && is_digit_0_to_5(input[2]) {
        return Some(3);
    }

    if input.len() >= 3 && input[0] == b'2' && is_digit_0_to_4(input[1]) && is_digit(input[2]) {
        return Some(3);
    }

    if input.len() >= 3 && input[0] == b'1' && is_digit(input[1]) && is_digit(input[2]) {
        return Some(3);
    }

    if input.len() >= 2 && is_digit_1_to_9(input[0]) && is_digit(input[1]) {
        return Some(2);
    }

    if input.len() >= 1 && is_digit(input[0]) {
        return Some(1);
    }

    None
}

// https://en.wikipedia.org/wiki/Hostname#Restrictions_on_valid_hostnames
fn look_hostname(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    while idx < input.len() && idx < 253 {
        if idx > 0 {
            if let Some(i) = look_dot(&input[idx..]) {
                idx += i;
            } else {
                break;
            }
        }
        if let Some(i) = look_label(&input[idx..]) {
            idx += i;
        } else {
            break;
        }
    }
    Some(idx)
}

fn look_label(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    if idx < input.len() && (is_alpha(input[idx]) || is_digit(input[idx]) || input[idx] == b'_') {
        idx += 1;
    } else {
        return None;
    }
    while idx < input.len()
        && idx < 62
        && (is_alpha(input[idx])
            || is_digit(input[idx])
            || input[idx] == b'_'
            || input[idx] == b'-')
    {
        idx += 1;
    }
    Some(idx)
}

fn look_dot(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b'.' {
        Some(1)
    } else {
        None
    }
}

// *DIGIT
fn look_port(input: &[u8]) -> usize {
    input.iter().take_while(|&&c| is_digit(c)).count()
}

fn look_question_mark_query(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += look_question_mark(&input[idx..])?;
    idx += look_query(&input[idx..]);
    Some(idx)
}

// *( pchar / "/" / "?" )
fn look_query(input: &[u8]) -> usize {
    let mut idx = 0;
    while idx < input.len() {
        if let Some(i) = look_pchar(&input[idx..]) {
            idx += i;
            continue;
        }
        if [b'/', b'?'].contains(&input[idx]) {
            idx += 1;
            continue;
        }
        break;
    }
    idx
}

fn look_sharp_fragment(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += look_sharp(&input[idx..])?;
    idx += look_fragment(&input[idx..]);
    Some(idx)
}

// *( pchar / "/" / "?" )
fn look_fragment(input: &[u8]) -> usize {
    let mut idx = 0;
    while idx < input.len() {
        if let Some(i) = look_pchar(&input[idx..]) {
            idx += i;
            continue;
        }
        if [b'/', b'?'].contains(&input[idx]) {
            idx += 1;
            continue;
        }
        break;
    }
    idx
}

// unreserved / pct-encoded / sub-delims / ":" / "@"
fn look_pchar(input: &[u8]) -> Option<usize> {
    look_pct_encoded(input).or_else(|| {
        if input.len() >= 1
            && (is_unreserved(input[0])
                || is_sub_delim(input[0])
                || [b':', b'@'].contains(&input[0]))
        {
            Some(1)
        } else {
            None
        }
    })
}

// "%" HEXDIG HEXDIG
fn look_pct_encoded(input: &[u8]) -> Option<usize> {
    if input.len() >= 3 && input[0] == b'%' && is_hexdig(input[1]) && is_hexdig(input[2]) {
        Some(3)
    } else {
        None
    }
}

fn look_period(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b'.' {
        Some(1)
    } else {
        None
    }
}

fn look_left_bracket(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b'[' {
        Some(1)
    } else {
        None
    }
}

fn look_colon(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b':' {
        Some(1)
    } else {
        None
    }
}

fn look_question_mark(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b'?' {
        Some(1)
    } else {
        None
    }
}

fn look_sharp(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b'#' {
        Some(1)
    } else {
        None
    }
}

fn look_slash(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b'/' {
        Some(1)
    } else {
        None
    }
}

fn look_slash_slash(input: &[u8]) -> Option<usize> {
    if input.len() >= 2 && input[0] == b'/' && input[1] == b'/' {
        Some(2)
    } else {
        None
    }
}

// *( unreserved / pct-encoded / sub-delims / ":" )
fn is_userinfo(input: &[u8]) -> bool {
    let mut idx = 0;
    while idx < input.len() {
        if let Some(i) = look_pct_encoded(&input[idx..]) {
            idx += i;
            continue;
        }
        let c = input[idx];
        if is_unreserved(c) || is_sub_delim(c) || c == b':' {
            idx += 1;
            continue;
        }
        return false;
    }
    true
}

// ALPHA / DIGIT / "-" / "." / "_" / "~"
fn is_unreserved(c: u8) -> bool {
    is_alpha(c) || is_digit(c) || c == b'-' || c == b'.' || c == b'_' || c == b'~'
}

// "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
fn is_sub_delim(c: u8) -> bool {
    [
        b'!', b'$', b'&', b'\'', b'(', b')', b'*', b'+', b',', b';', b'=',
    ]
    .contains(&c)
}

// ALPHA
fn is_alpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

// DIGIT
fn is_digit(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}
fn is_digit_1_to_9(c: u8) -> bool {
    c >= b'1' && c <= b'9'
}
fn is_digit_0_to_4(c: u8) -> bool {
    c >= b'0' && c <= b'4'
}
fn is_digit_0_to_5(c: u8) -> bool {
    c >= b'0' && c <= b'5'
}

// HEXDIG
fn is_hexdig(c: u8) -> bool {
    is_digit(c) || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ipv6address_should_identify_valid_ipv6s() {
        for input in vec![
            "::",
            "::1",
            "1::",
            "1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6::7",
            "1:2:3:4:5:6:127.0.0.1",
            "1::127.0.0.1",
        ] {
            assert_eq!(true, is_ipv6address(input.as_bytes()), "{}", input);
        }
    }

    #[test]
    fn is_ipv6address_should_identify_invalid_ipv6s() {
        for input in vec![
            " ",
            " ::",
            ":: ",
            " :: ",
            ":::",
            "::1::",
            ":1:",
            "1:2:3:4:5:6:7:8:9",
            "1:2:3:4:5:6:7:127.0.0.1",
            "1:2:3:4:5:6::7:8",
            "1:2:3:4:5:6::127.0.0.1",
            "1:127.0.0.1::",
        ] {
            assert_eq!(false, is_ipv6address(input.as_bytes()), "{}", input);
        }
    }

    #[test]
    fn look_path_abempty_should_mirror_the_len_of_valid_inputs() {
        for input in vec![
            "",
            "/",
            "//",
            "///",
            "/foo/bar",
            "/rfc/rfc1808.txt",
            "/with/trailing/",
        ] {
            assert_eq!(
                input.len(),
                look_path_abempty(input.as_bytes()),
                "{}",
                input
            );
        }
    }

    #[test]
    fn look_path_abempty_should_skip_invalid_inputs() {
        for input in vec!["foobar"] {
            assert_eq!(0, look_path_abempty(input.as_bytes()), "{}", input);
        }
    }
}
