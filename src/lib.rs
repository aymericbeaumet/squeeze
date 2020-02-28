// https://tools.ietf.org/html/rfc3986#appendix-A
pub fn squeeze_uri(s: &str) -> Option<&str> {
    let input = s.as_bytes();

    let colon_idx = input.iter().position(|&b| b == b':')?;
    let scheme_idx = find_scheme(&input[..colon_idx])?;

    let mut idx = colon_idx + 1;
    if idx >= s.len() {
        return None;
    }
    idx += look_hier_part(&input[idx..])?;
    idx += look_question_mark(&input[idx..])
        .map(|j| j + look_query(&input[idx + j..]))
        .unwrap_or(0);
    idx += look_sharp(&input[idx..])
        .map(|j| j + look_fragment(&input[idx + j..]))
        .unwrap_or(0);

    Some(&s[scheme_idx..idx])
}

// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
fn find_scheme(input: &[u8]) -> Option<usize> {
    let mut scheme_idx = None;
    for (i, &c) in input.iter().enumerate().rev() {
        if is_alpha(c) {
            scheme_idx = Some(i);
        } else if is_digit(c) || [b'+', b'-', b'.'].contains(&c) {
            // noop
        } else {
            break;
        }
    }
    scheme_idx
}

// hier-part = "//" authority path-abempty
//           / path-absolute
//           / path-rootless
//           / path-empty
fn look_hier_part(input: &[u8]) -> Option<usize> {
    // "//" authority path-abempty
    if let Some(idx) = look_slash_slash(input)
        .and_then(|idx| Some(idx + look_authority(&input[idx..])?))
        .map(|idx| idx + look_path_abempty(&input[idx..]))
    {
        return Some(idx);
    }

    // "/" [ segment-nz path-abempty ]
    if let Some(idx) = look_slash(input).map(|idx| {
        idx + look_segment_nz(&input[idx..])
            .map(|idx| idx + look_path_abempty(&input[idx..]))
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
fn look_authority(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += look_userinfo_at(&input[idx..]).unwrap_or(0);
    idx += look_host(&input[idx..])?;
    idx += look_colon_port(&input[idx..]).unwrap_or(0);
    Some(idx)
}

// ":" port
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
        idx += match look_slash(&input[idx..]).map(|idx| idx + look_segment(&input[idx..])) {
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
    let arobase_idx = input.iter().position(|&b| b == b'@')?;
    if is_userinfo(&input[..arobase_idx]) {
        Some(arobase_idx + 1)
    } else {
        None
    }
}

// IP-literal / IPv4address / reg-name
fn look_host(input: &[u8]) -> Option<usize> {
    if let Some(idx) = look_ip_literal(input) {
        return Some(idx);
    }

    if let Some(idx) = look_ipv4_address(input) {
        return Some(idx);
    }

    if let Some(idx) = look_reg_name(input) {
        return Some(idx);
    }

    None
}

// "[" ( IPv6address / IPvFuture  ) "]"
fn look_ip_literal(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += look_left_bracket(&input[idx..])?;
    if let Some(i) = look_ipv6_address(&input[idx..]) {
        idx += i;
    } else if let Some(i) = look_ipvfuture(&input[idx..]) {
        idx += i;
    } else {
        return None;
    }
    idx += look_right_bracket(&input[idx..])?;
    Some(idx)
}

// IPv6address   =                            6( h16 ":" ) ls32
//               /                       "::" 5( h16 ":" ) ls32
//               / [               h16 ] "::" 4( h16 ":" ) ls32
//               / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
//               / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
//               / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
//               / [ *4( h16 ":" ) h16 ] "::"              ls32
//               / [ *5( h16 ":" ) h16 ] "::"              h16
//               / [ *6( h16 ":" ) h16 ] "::"
fn look_ipv6_address(input: &[u8]) -> Option<usize> {
    None
}

// TODO
// "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
fn look_ipvfuture(input: &[u8]) -> Option<usize> {
    None
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

// TODO
// *( unreserved / pct-encoded / sub-delims )
fn look_reg_name(input: &[u8]) -> Option<usize> {
    if input.starts_with(&[b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't']) {
        Some("localhost".len())
    } else {
        None
    }
}

// *DIGIT
fn look_port(input: &[u8]) -> usize {
    input.iter().take_while(|&&c| is_digit(c)).count()
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
    if let Some(idx) = look_pct_encoded(input) {
        return Some(idx);
    }
    let c = input[0];
    if is_unreserved(c) || is_sub_delim(c) || [b':', b'@'].contains(&c) {
        return Some(1);
    }
    None
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

fn look_right_bracket(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b']' {
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
    if input.len() > 1 && input[0] == b'/' && input[1] == b'/' {
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

// CR
fn is_cr(c: u8) -> bool {
    c == b'\r'
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

// DQUOTE
fn is_dquote(c: u8) -> bool {
    c == b'"'
}

// HEXDIG
fn is_hexdig(c: u8) -> bool {
    is_digit(c) && (c >= b'a' && c <= b'f' || c >= b'A' && c <= b'F')
}

// LF
fn is_lf(c: u8) -> bool {
    c == b'\n'
}

// SP
fn is_sp(c: u8) -> bool {
    c == b' '
}
