// https://tools.ietf.org/html/rfc3986#appendix-A
pub fn squeeze_uri(s: &str) -> Option<&str> {
    let input = s.as_bytes();

    let colon_idx = find_colon(input)?;
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

fn find_colon(input: &[u8]) -> Option<usize> {
    input.iter().position(|&b| b == b':')
}

// https://tools.ietf.org/html/rfc3986#section-3.1
fn find_scheme(input: &[u8]) -> Option<usize> {
    let mut scheme_index = None;

    for (i, &c) in input.iter().enumerate().rev() {
        if is_alpha(c) {
            scheme_index = Some(i);
        } else if !(is_digit(c) || c == b'+' || c == b'-' || c == b'.') {
            break;
        }
    }

    scheme_index
}

fn advance_hier_part(input: &[u8]) -> Option<usize> {
    let mut idx = 0;

    idx += advance_slash_slash(&input[idx..])?;
    idx += advance_authority(&input[idx..])?;
    idx += advance_path_abempty(&input[idx..]);

    // / path-absolute

    // / path-rootless

    // / path-empty

    Some(idx)
}

fn advance_slash_slash(input: &[u8]) -> Option<usize> {
    if input[0] == b'/' && input[1] == b'/' {
        Some(2)
    } else {
        None
    }
}

fn advance_path_abempty(input: &[u8]) -> usize {
    let mut idx = 0;
    while idx < input.len() {
        if input[idx] != b'/' {
            break;
        }
        idx += 1;
        idx += advance_segment(&input[idx..]);
    }
    idx
}

fn advance_segment(input: &[u8]) -> usize {
    let mut idx = 0;
    while idx < input.len() {
        if let Some(i) = advance_pchar(&input[idx..]) {
            idx += i;
        } else {
            break;
        }
    }
    idx
}

// https://tools.ietf.org/html/rfc3986#section-3.2
fn advance_authority(input: &[u8]) -> Option<usize> {
    let mut idx = 0;
    idx += advance_user_info(&input[idx..]).unwrap_or(0);
    idx += advance_hostname(&input[idx..])?;
    idx += advance_port(&input[idx..]).unwrap_or(0);
    Some(idx)
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

// https://tools.ietf.org/html/rfc3986#section-3.2.1
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

// https://tools.ietf.org/html/rfc3986#section-2.3
fn is_unreserved(c: u8) -> bool {
    is_alpha(c) || is_digit(c) || c == b'-' || c == b'.' || c == b'_' || c == b'~'
}

// https://tools.ietf.org/html/rfc3986#section-2.2
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
