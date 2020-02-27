// https://tools.ietf.org/html/rfc3986#section-3
pub fn squeeze_uri(input: &str) -> Option<&str> {
    let colon_idx = find_colon(input)?;
    let scheme_idx = find_scheme(&input[..colon_idx])?;

    let mut idx = colon_idx + 1;
    idx += advance_hier_part(&input[idx..])?;
    idx += advance_query(&input[idx..]).unwrap_or(0);
    idx += advance_fragment(&input[idx..]).unwrap_or(0);

    Some(&input[scheme_idx..idx])
}

// https://tools.ietf.org/html/rfc3986#section-3.1
fn find_scheme(input: &str) -> Option<usize> {
    let mut scheme_index = None;

    for (i, c) in input.bytes().enumerate().rev() {
        let c = c as char;
        if is_alpha(c) {
            scheme_index = Some(i);
        } else if !(is_digit(c) || c == '+' || c == '-' || c == '.') {
            break;
        }
    }

    scheme_index
}

fn find_colon(input: &str) -> Option<usize> {
    input.find(':')
}

fn advance_hier_part(input: &str) -> Option<usize> {
    let mut idx = 0;
    idx += advance_slash_slash(&input[idx..])?;
    idx += advance_authority(&input[idx..])?;
    Some(idx)
}

fn advance_slash_slash(input: &str) -> Option<usize> {
    let slash_slash = "//";
    if input.starts_with(slash_slash) {
        Some(slash_slash.len())
    } else {
        None
    }
}

// https://tools.ietf.org/html/rfc3986#section-3.2
fn advance_authority(input: &str) -> Option<usize> {
    let mut idx = 0;
    idx += advance_user_info(&input[idx..]).unwrap_or(0);
    idx += advance_hostname(&input[idx..])?;
    idx += advance_port(&input[idx..]).unwrap_or(0);
    Some(idx)
}

fn advance_user_info(input: &str) -> Option<usize> {
    let arobase_idx = input.find('@')?;
    if is_user_info(&input[..arobase_idx]) {
        Some(arobase_idx + 1)
    } else {
        None
    }
}

fn advance_hostname(input: &str) -> Option<usize> {
    if input.starts_with("localhost") {
        Some("localhost".len())
    } else {
        None
    }
}

fn advance_port(input: &str) -> Option<usize> {
    if !input.starts_with(":") {
        return None;
    }
    Some(1 + input.chars().skip(1).take_while(|&c| is_digit(c)).count())
}

fn advance_query(input: &str) -> Option<usize> {
    None
}

fn advance_fragment(input: &str) -> Option<usize> {
    None
}

// https://tools.ietf.org/html/rfc3986#section-3.2.1
fn is_user_info(s: &str) -> bool {
    let chars: Vec<_> = s.chars().collect();

    let mut i = 0;
    let l = chars.len();
    while i < l {
        if i + 2 < l && is_pct_encoded(&chars[i..i + 2]) {
            i += 2;
            continue;
        }
        if is_unreserved(chars[i]) || is_sub_delims(chars[i]) || chars[i] == ':' {
            i += 1;
            continue;
        }
        return false;
    }

    true
}

fn is_pct_encoded(chars: &[char]) -> bool {
    chars.len() == 3 && chars[0] == '%' && is_hexa(chars[1]) && is_hexa(chars[2])
}

// https://tools.ietf.org/html/rfc3986#section-2.3
fn is_unreserved(c: char) -> bool {
    is_alpha(c) || is_digit(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

// https://tools.ietf.org/html/rfc3986#section-2.2
fn is_sub_delims(c: char) -> bool {
    ['!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '='].contains(&c)
}

fn is_alpha(c: char) -> bool {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

fn is_hexa(c: char) -> bool {
    is_digit(c) && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')
}

fn is_digit(c: char) -> bool {
    return c >= '0' && c <= '9';
}
