// https://tools.ietf.org/html/rfc3986#appendix-A
pub fn squeeze_uri(s: &str) -> Option<&str> {
    let input = s.as_bytes();

    let colon_idx = input.iter().position(|&b| b == b':')?;
    let scheme_idx = find_scheme(&input[..colon_idx])?;

    let mut idx = colon_idx + 1;
    if idx >= s.len() {
        return None;
    }
    idx += advance_hier_part(&input[idx..])?;
    idx += advance_query(&input[idx..]).unwrap_or(0);
    idx += advance_fragment(&input[idx..]).unwrap_or(0);

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

fn advance_hier_part(input: &[u8]) -> Option<usize> {
    // "//" authority path-abempty
    if let Some(idx) = advance_slash_slash(input)
        .and_then(|idx| Some(idx + advance_authority(&input[idx..])?))
        .map(|idx| idx + advance_path_abempty(&input[idx..]))
    {
        return Some(idx);
    }

    // "/" [ segment-nz path-abempty ]
    if let Some(idx) = advance_slash(input).map(|idx| {
        idx + advance_segment_nz(&input[idx..])
            .map(|idx| idx + advance_path_abempty(&input[idx..]))
            .unwrap_or(0)
    }) {
        return Some(idx);
    }

    // segment-nz path-abempty
    if let Some(idx) =
        advance_segment_nz(input).map(|idx| idx + advance_path_abempty(&input[idx..]))
    {
        return Some(idx);
    }

    // 0<pchar>
    Some(0)
}

// "/"
fn advance_slash(input: &[u8]) -> Option<usize> {
    if input.len() >= 1 && input[0] == b'/' {
        Some(1)
    } else {
        None
    }
}

// "//"
fn advance_slash_slash(input: &[u8]) -> Option<usize> {
    if input.len() >= 2 && input[0] == b'/' && input[1] == b'/' {
        Some(2)
    } else {
        None
    }
}

// [ userinfo "@" ] host [ ":" port ]
fn advance_authority(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += advance_user_info(&input[idx..]).unwrap_or(0);
    idx += advance_hostname(&input[idx..])?;
    idx += advance_port(&input[idx..]).unwrap_or(0);
    Some(idx)
}

// *( "/" segment )
fn advance_path_abempty(input: &[u8]) -> usize {
    let mut idx = 0;
    while idx < input.len() {
        idx += match advance_slash(&input[idx..]).map(|idx| idx + advance_segment(&input[idx..])) {
            Some(n) => n,
            None => break,
        };
    }
    idx
}

// *pchar
fn advance_segment(input: &[u8]) -> usize {
    let mut idx = 0;
    while idx < input.len() {
        idx += match advance_pchar(&input[idx..]) {
            Some(n) => n,
            None => break,
        };
    }
    idx
}

// 1*pchar
fn advance_segment_nz(input: &[u8]) -> Option<usize> {
    match advance_segment(input) {
        0 => None,
        n => Some(n),
    }
}

fn advance_user_info(input: &[u8]) -> Option<usize> {
    let arobase_idx = input.iter().position(|&b| b == b'@')?;
    if is_user_info(&input[..arobase_idx]) {
        Some(arobase_idx + 1)
    } else {
        None
    }
}

// todo
fn advance_hostname(input: &[u8]) -> Option<usize> {
    if input.starts_with(&[b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't']) {
        Some("localhost".len())
    } else {
        None
    }
}

fn advance_port(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    if input[idx] != b':' {
        return None;
    }
    idx += 1;
    idx += &input[idx..].iter().take_while(|&&c| is_digit(c)).count();
    Some(idx)
}

// https://tools.ietf.org/html/rfc3986#section-3.4
fn advance_query(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    if input[idx] != b'?' {
        return None;
    }
    idx += 1;
    while idx < input.len() {
        if let Some(i) = advance_pchar(&input[idx..]) {
            idx += i;
            continue;
        }
        let c = input[idx];
        if c == b'/' || c == b'?' {
            idx += 1;
            continue;
        }
        break;
    }
    Some(idx)
}

// https://tools.ietf.org/html/rfc3986#section-3.5
fn advance_fragment(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    if input[idx] != b'#' {
        return None;
    }
    idx += 1;
    while idx < input.len() {
        if let Some(i) = advance_pchar(&input[idx..]) {
            idx += i;
            continue;
        }
        let c = input[idx];
        if c == b'/' || c == b'?' {
            idx += 1;
            continue;
        }
        break;
    }
    Some(idx)
}

fn advance_pchar(input: &[u8]) -> Option<usize> {
    if let Some(idx) = advance_pct_encoded(input) {
        return Some(idx);
    }
    let c = input[0];
    if is_unreserved(c) || is_sub_delim(c) || c == b':' || c == b'@' {
        return Some(1);
    }
    None
}

fn advance_pct_encoded(input: &[u8]) -> Option<usize> {
    if input.len() >= 3 && input[0] == b'%' && is_hexa(input[1]) && is_hexa(input[2]) {
        Some(3)
    } else {
        None
    }
}

fn is_user_info(input: &[u8]) -> bool {
    let mut idx = 0;
    while idx < input.len() {
        if let Some(i) = advance_pct_encoded(&input[idx..]) {
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

fn is_segment(input: &[u8]) -> bool {
    let mut idx = 0;
    while idx < input.len() {
        if let Some(i) = advance_pchar(&input[idx..]) {
            idx += i;
            continue;
        }
        return false;
    }
    true
}

fn is_unreserved(c: u8) -> bool {
    is_alpha(c) || is_digit(c) || c == b'-' || c == b'.' || c == b'_' || c == b'~'
}

fn is_sub_delim(c: u8) -> bool {
    [
        b'!', b'$', b'&', b'\'', b'(', b')', b'*', b'+', b',', b';', b'=',
    ]
    .contains(&c)
}

fn is_alpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

fn is_hexa(c: u8) -> bool {
    is_digit(c) && (c >= b'a' && c <= b'f' || c >= b'A' && c <= b'F')
}

fn is_digit(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}
