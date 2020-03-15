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
    pub strict: bool,
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

            let scheme_idx = match self.rlook_scheme(&input[start..colon_idx]) {
                Some(i) => start + i,
                None => continue,
            };
            let scheme = &s[scheme_idx..colon_idx];
            let scheme_config = SCHEMES_CONFIGS.get(scheme);

            idx += self.look_hier_part(&input[idx..], scheme_config)?;
            idx += self.look_question_mark_query(&input[idx..]).unwrap_or(0);
            idx += self.look_sharp_fragment(&input[idx..]).unwrap_or(0);

            // we cannot early exit as soon as we know the scheme as we need to advance idx even if the
            // url should be discarded
            if self.schemes.is_empty() || self.schemes.contains(scheme) {
                return Some(scheme_idx..idx);
            }
        }

        None
    }
}

impl URI {
    pub fn add_scheme(&mut self, s: &str) {
        self.schemes.insert(s.to_lowercase());
    }

    // ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    fn rlook_scheme(&self, input: &[u8]) -> Option<usize> {
        let mut idx = None;
        for (i, &c) in input.iter().enumerate().rev() {
            if self.is_alpha(c) {
                idx = Some(i);
            } else if self.is_digit(c) || [b'+', b'-', b'.'].contains(&c) {
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
    fn look_hier_part(&self, input: &[u8], sc: SchemeConfig) -> Option<usize> {
        // "//" authority path-abempty
        if let Some(idx) = self
            .look_slash_slash(input)
            .and_then(|idx| Some(idx + self.look_authority(&input[idx..], sc)?))
            .map(|idx| idx + self.look_path_abempty(&input[idx..]))
        {
            return Some(idx);
        }

        // Some protocols disallow empty hosts
        if sc.has(DISALLOW_EMPTY_HOST) {
            return None;
        }

        // "/" [ segment-nz path-abempty ]
        if let Some(idx) = self.look_slash(input).map(|idx| {
            idx + self
                .look_segment_nz(&input[idx..])
                .map(|i| i + self.look_path_abempty(&input[idx + i..]))
                .unwrap_or(0)
        }) {
            return Some(idx);
        }

        // segment-nz path-abempty
        if let Some(idx) = self
            .look_segment_nz(input)
            .map(|idx| idx + self.look_path_abempty(&input[idx..]))
        {
            return Some(idx);
        }

        // 0<pchar>
        Some(0)
    }

    // [ userinfo "@" ] host [ ":" port ]
    fn look_authority(&self, input: &[u8], sc: SchemeConfig) -> Option<usize> {
        let mut idx = 0;
        idx += self.look_userinfo_at(&input[idx..]).unwrap_or(0);
        idx += self.look_host(&input[idx..]).and_then(|i| {
            if i == 0 {
                if sc.has(DISALLOW_EMPTY_HOST) {
                    return None;
                }
            }
            Some(i)
        })?;
        idx += self.look_colon_port(&input[idx..]).unwrap_or(0);
        Some(idx)
    }

    fn look_colon_port(&self, input: &[u8]) -> Option<usize> {
        let mut idx = 0;
        idx += self.look_colon(&input[idx..])?;
        idx += self.look_port(&input[idx..]);
        Some(idx)
    }

    // *( "/" segment )
    fn look_path_abempty(&self, input: &[u8]) -> usize {
        let mut idx = 0;
        while idx < input.len() {
            idx += match self
                .look_slash(&input[idx..])
                .map(|i| i + self.look_segment(&input[idx + i..]))
            {
                Some(n) => n,
                None => break,
            };
        }
        idx
    }

    // *pchar
    fn look_segment(&self, input: &[u8]) -> usize {
        let mut idx = 0;
        while idx < input.len() {
            idx += match self.look_pchar(&input[idx..]) {
                Some(n) => n,
                None => break,
            };
        }
        idx
    }

    // 1*pchar
    fn look_segment_nz(&self, input: &[u8]) -> Option<usize> {
        match self.look_segment(input) {
            0 => None,
            n => Some(n),
        }
    }

    // userinfo "@"
    fn look_userinfo_at(&self, input: &[u8]) -> Option<usize> {
        let arobase_idx = input.iter().take(256).position(|&b| b == b'@')?;
        if self.is_userinfo(&input[..arobase_idx]) {
            Some(arobase_idx + 1)
        } else {
            None
        }
    }

    // IP-literal / IPv4address / reg-name
    fn look_host(&self, input: &[u8]) -> Option<usize> {
        self.look_ip_literal(input)
            .or_else(|| self.look_ipv4_address(input))
            .or_else(|| self.look_hostname(input))
    }

    // "[" ( IPv6address / IPvFuture  ) "]"
    fn look_ip_literal(&self, input: &[u8]) -> Option<usize> {
        let mut idx = 0;
        idx += self.look_left_bracket(&input[idx..])?;
        let right_bracket_index = (&input[idx..]).iter().take(64).position(|&b| b == b']')?;
        if right_bracket_index > 0 {
            let end = idx + right_bracket_index;
            let slice = &input[idx..end];
            if self.is_ipv6address(slice) || self.is_ipvfuture(slice) {
                return Some(end + 1);
            }
        }
        None
    }

    // https://tools.ietf.org/html/rfc4291#section-2.2
    fn is_ipv6address(&self, input: &[u8]) -> bool {
        let mut idx = 0;

        let mut bytes_count = 0;
        let mut double_colon_found = false;

        while idx < input.len() {
            let mut last_is_colon = false;
            while let Some(i) = self.look_colon(&input[idx..]) {
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
                    if let Some(i) = self.look_ipv4_address(&input[idx..]) {
                        bytes_count += 4;
                        idx += i;
                        break;
                    }
                }
                if let Some(i) = self.look_h16(&input[idx..]) {
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
    fn look_h16(&self, input: &[u8]) -> Option<usize> {
        let idx = input
            .iter()
            .take_while(|&&b| self.is_hexdig(b))
            .take(4)
            .count();
        if idx >= 1 {
            Some(idx)
        } else {
            None
        }
    }

    // "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
    fn is_ipvfuture(&self, _input: &[u8]) -> bool {
        // TODO: implementation
        false
    }

    // dec-octet "." dec-octet "." dec-octet "." dec-octet
    fn look_ipv4_address(&self, input: &[u8]) -> Option<usize> {
        let mut idx = 0;
        idx += self.look_dec_octet(&input[idx..])?;
        idx += self.look_period(&input[idx..])?;
        idx += self.look_dec_octet(&input[idx..])?;
        idx += self.look_period(&input[idx..])?;
        idx += self.look_dec_octet(&input[idx..])?;
        idx += self.look_period(&input[idx..])?;
        idx += self.look_dec_octet(&input[idx..])?;
        Some(idx)
    }

    // dec-octet     = DIGIT                 ; 0-9
    //               / %x31-39 DIGIT         ; 10-99
    //               / "1" 2DIGIT            ; 100-199
    //               / "2" %x30-34 DIGIT     ; 200-249
    //               / "25" %x30-35          ; 250-255
    fn look_dec_octet(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 3
            && input[0] == b'2'
            && input[1] == b'5'
            && self.is_digit_0_to_5(input[2])
        {
            return Some(3);
        }

        if input.len() >= 3
            && input[0] == b'2'
            && self.is_digit_0_to_4(input[1])
            && self.is_digit(input[2])
        {
            return Some(3);
        }

        if input.len() >= 3
            && input[0] == b'1'
            && self.is_digit(input[1])
            && self.is_digit(input[2])
        {
            return Some(3);
        }

        if input.len() >= 2 && self.is_digit_1_to_9(input[0]) && self.is_digit(input[1]) {
            return Some(2);
        }

        if input.len() >= 1 && self.is_digit(input[0]) {
            return Some(1);
        }

        None
    }

    // https://en.wikipedia.org/wiki/Hostname#Restrictions_on_valid_hostnames
    fn look_hostname(&self, input: &[u8]) -> Option<usize> {
        let mut idx = 0;
        while idx < input.len() && idx < 253 {
            if idx > 0 {
                if let Some(i) = self.look_dot(&input[idx..]) {
                    idx += i;
                } else {
                    break;
                }
            }
            if let Some(i) = self.look_label(&input[idx..]) {
                idx += i;
            } else {
                break;
            }
        }
        Some(idx)
    }

    fn look_label(&self, input: &[u8]) -> Option<usize> {
        let mut idx = 0;
        if idx < input.len()
            && (self.is_alpha(input[idx]) || self.is_digit(input[idx]) || input[idx] == b'_')
        {
            idx += 1;
        } else {
            return None;
        }
        while idx < input.len()
            && idx < 62
            && (self.is_alpha(input[idx])
                || self.is_digit(input[idx])
                || input[idx] == b'_'
                || input[idx] == b'-')
        {
            idx += 1;
        }
        Some(idx)
    }

    fn look_dot(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 1 && input[0] == b'.' {
            Some(1)
        } else {
            None
        }
    }

    // *DIGIT
    fn look_port(&self, input: &[u8]) -> usize {
        input.iter().take_while(|&&c| self.is_digit(c)).count()
    }

    fn look_question_mark_query(&self, input: &[u8]) -> Option<usize> {
        let mut idx = 0;
        idx += self.look_question_mark(&input[idx..])?;
        idx += self.look_query(&input[idx..]);
        Some(idx)
    }

    // *( pchar / "/" / "?" )
    fn look_query(&self, input: &[u8]) -> usize {
        let mut idx = 0;
        while idx < input.len() {
            if let Some(i) = self.look_pchar(&input[idx..]) {
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

    fn look_sharp_fragment(&self, input: &[u8]) -> Option<usize> {
        let mut idx = 0;
        idx += self.look_sharp(&input[idx..])?;
        idx += self.look_fragment(&input[idx..]);
        Some(idx)
    }

    // *( pchar / "/" / "?" )
    fn look_fragment(&self, input: &[u8]) -> usize {
        let mut idx = 0;
        while idx < input.len() {
            if let Some(i) = self.look_pchar(&input[idx..]) {
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
    fn look_pchar(&self, input: &[u8]) -> Option<usize> {
        self.look_pct_encoded(input).or_else(|| {
            if input.len() >= 1
                && (self.is_unreserved(input[0])
                    || self.is_sub_delim(input[0])
                    || [b':', b'@'].contains(&input[0]))
            {
                Some(1)
            } else {
                None
            }
        })
    }

    // "%" HEXDIG HEXDIG
    fn look_pct_encoded(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 3
            && input[0] == b'%'
            && self.is_hexdig(input[1])
            && self.is_hexdig(input[2])
        {
            Some(3)
        } else {
            None
        }
    }

    fn look_period(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 1 && input[0] == b'.' {
            Some(1)
        } else {
            None
        }
    }

    fn look_left_bracket(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 1 && input[0] == b'[' {
            Some(1)
        } else {
            None
        }
    }

    fn look_colon(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 1 && input[0] == b':' {
            Some(1)
        } else {
            None
        }
    }

    fn look_question_mark(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 1 && input[0] == b'?' {
            Some(1)
        } else {
            None
        }
    }

    fn look_sharp(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 1 && input[0] == b'#' {
            Some(1)
        } else {
            None
        }
    }

    fn look_slash(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 1 && input[0] == b'/' {
            Some(1)
        } else {
            None
        }
    }

    fn look_slash_slash(&self, input: &[u8]) -> Option<usize> {
        if input.len() >= 2 && input[0] == b'/' && input[1] == b'/' {
            Some(2)
        } else {
            None
        }
    }

    // *( unreserved / pct-encoded / sub-delims / ":" )
    fn is_userinfo(&self, input: &[u8]) -> bool {
        let mut idx = 0;
        while idx < input.len() {
            if let Some(i) = self.look_pct_encoded(&input[idx..]) {
                idx += i;
                continue;
            }
            let c = input[idx];
            if self.is_unreserved(c) || self.is_sub_delim(c) || c == b':' {
                idx += 1;
                continue;
            }
            return false;
        }
        true
    }

    // ALPHA / DIGIT / "-" / "." / "_" / "~"
    fn is_unreserved(&self, c: u8) -> bool {
        self.is_alpha(c) || self.is_digit(c) || c == b'-' || c == b'.' || c == b'_' || c == b'~'
    }

    // "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
    fn is_sub_delim(&self, c: u8) -> bool {
        if self.strict {
            [
                b'!', b'$', b'&', b'\'', b'(', b')', b'*', b'+', b',', b';', b'=',
            ]
            .contains(&c)
        } else {
            [b'!', b'$', b'&', b'(', b'*', b'+', b',', b';', b'='].contains(&c) // without ' and )
        }
    }

    // ALPHA
    fn is_alpha(&self, c: u8) -> bool {
        (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
    }

    // DIGIT
    fn is_digit(&self, c: u8) -> bool {
        c >= b'0' && c <= b'9'
    }
    fn is_digit_1_to_9(&self, c: u8) -> bool {
        c >= b'1' && c <= b'9'
    }
    fn is_digit_0_to_4(&self, c: u8) -> bool {
        c >= b'0' && c <= b'4'
    }
    fn is_digit_0_to_5(&self, c: u8) -> bool {
        c >= b'0' && c <= b'5'
    }

    // HEXDIG
    fn is_hexdig(&self, c: u8) -> bool {
        self.is_digit(c) || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ipv6address_should_identify_valid_ipv6s() {
        let finder = URI::default();
        for input in vec![
            "::",
            "::1",
            "1::",
            "1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6::7",
            "1:2:3:4:5:6:127.0.0.1",
            "1::127.0.0.1",
        ] {
            assert_eq!(true, finder.is_ipv6address(input.as_bytes()), "{}", input);
        }
    }

    #[test]
    fn is_ipv6address_should_identify_invalid_ipv6s() {
        let finder = URI::default();
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
            assert_eq!(false, finder.is_ipv6address(input.as_bytes()), "{}", input);
        }
    }

    #[test]
    fn look_path_abempty_should_mirror_the_len_of_valid_inputs() {
        let finder = URI::default();
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
                finder.look_path_abempty(input.as_bytes()),
                "{}",
                input
            );
        }
    }

    #[test]
    fn look_path_abempty_should_skip_invalid_inputs() {
        let finder = URI::default();
        for input in vec!["foobar"] {
            assert_eq!(0, finder.look_path_abempty(input.as_bytes()), "{}", input);
        }
    }

    #[test]
    fn it_should_mirror_valid_uris() {
        let finder = URI::default();
        for input in vec![
            // basic
            "http://localhost",
            // userinfo
            "http://foobar:@localhost",
            "http://foobar:baz@localhost",
            // port
            "http://foobar:@localhost:",
            "http://foobar:@localhost:8080",
            // path
            "http://localhost/lorem",
            // query
            "http://foobar:@localhost:8080?",
            "http://foobar:@localhost:8080?a=b",
            // fragment
            "http://foobar:@localhost:8080#",
            "http://foobar:@localhost:8080?#",
            "http://foobar:@localhost:8080?a=b#",
            "http://foobar:@localhost:8080?a=b#c=d",
            // meh
            "http://:@localhost:/?#",
            // ipv4
            "http://127.0.0.0",
            "http://127.0.0.10",
            "http://127.0.0.100",
            "http://127.0.0.200",
            "http://127.0.0.250",
            "http://192.0.2.235",
            // ipv6
            "http://[::]",
            "http://[::1]",
            "http://[2001:db8::1]",
            "http://[2001:0db8::0001]",
            "http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
            "http://[::ffff:192.0.2.128]",
            "http://[::ffff:c000:0280]",
            // scheme only
            "foobar:",
            // rfc examples
            "file:///etc/hosts",
            "http://localhost/",
            "mailto:fred@example.com",
            "foo://info.example.com?fred",
            "ftp://ftp.is.co.za/rfc/rfc1808.txt",
            "http://www.ietf.org/rfc/rfc2396.txt",
            "ldap://[2001:db8::7]/c=GB?objectClass?one",
            "mailto:John.Doe@example.com",
            "news:comp.infosystems.www.servers.unix",
            "tel:+1-816-555-1212",
            "telnet://192.0.2.16:80/",
            "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        ] {
            for i in vec![
                input.to_owned(),
                format!(" {} ", input),
                format!("<{}>", input),
                format!("[{}]", input),
                format!("<a href=\"{}\">link</a>", input),
                format!("{{{}}}", input),
                format!("\"{}\"", input),
                format!("[link]({})", input),
                format!("'{}'", input),
            ] {
                assert_eq!(Some(input), finder.find(&i).map(|r| &i[r]), "{}", input);
            }
        }
    }

    #[test]
    fn it_should_properly_behave_in_strict_mode() {
        let mut finder = URI::default();
        finder.strict = true;
        for &input in &["http://localhost/)", "http://localhost/'"] {
            assert_eq!(Some(input), finder.find(input).map(|r| &input[r]));
        }
    }

    #[test]
    fn it_should_ignore_invalid_uris() {
        let finder = URI::default();
        for input in vec![
            // some protocols require a host
            "ftp:///test",
            "http:///test",
            "https:///test",
        ] {
            assert_eq!(None, finder.find(input), "{}", input);
        }
    }
}
