use std::io::{self, BufRead};

fn main() {
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line = &line.unwrap();
        if let Some(uri) = squeeze_uri(line) {
            println!("{}", uri);
        }
    }
}

// https://tools.ietf.org/html/rfc3986#section-3
fn squeeze_uri(input: &str) -> Option<&str> {
    let colon_idx = find_colon(input)?;
    let scheme_idx = find_scheme(&input[..colon_idx])?;

    let mut idx = colon_idx + 1;
    idx += advance_hier_part(&input[idx..])?;
    idx += advance_query(&input[idx..]).unwrap_or(0);
    idx += advance_fragment(&input[idx..]).unwrap_or(0);

    Some(&input[scheme_idx..idx])
}

fn find_scheme(input: &str) -> Option<usize> {
    let mut scheme_index = None;

    for (i, _) in input.bytes().enumerate().rev() {
        if is_scheme(&input[i..]) {
            scheme_index = Some(i)
        } else {
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

fn advance_authority(input: &str) -> Option<usize> {
    let mut idx = 0;
    idx += advance_user_info(&input[idx..]).unwrap_or(0);
    idx += advance_hostname(&input[idx..])?;
    idx += advance_port(&input[idx..]).unwrap_or(0);
    Some(idx)
}

fn advance_user_info(input: &str) -> Option<usize> {
    None
}

fn advance_hostname(input: &str) -> Option<usize> {
    if input.starts_with("localhost") {
        Some("localhost".len())
    } else {
        None
    }
}

fn advance_port(input: &str) -> Option<usize> {
    None
}

fn advance_query(input: &str) -> Option<usize> {
    None
}

fn advance_fragment(input: &str) -> Option<usize> {
    None
}

// https://tools.ietf.org/html/rfc3986#section-3.1
fn is_scheme(input: &str) -> bool {
    input.chars().enumerate().all(|(i, c)| match i {
        0 => is_alpha(c),
        _ => is_alpha(c) || is_digit(c) || c == '+' || c == '-' || c == '.',
    })
}

fn is_alpha(c: char) -> bool {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

fn is_digit(c: char) -> bool {
    return c >= '0' && c <= '9';
}
