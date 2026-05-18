pub(crate) fn is_valid_ipv6(bytes: &[u8]) -> bool {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if let Some(last_colon) = s.rfind(':') {
        let suffix = &s[last_colon + 1..];
        if suffix.contains('.') {
            let prefix = &s[..last_colon + 1];
            let prefix_bytes = prefix.as_bytes();
            let parts: Vec<&str> = suffix.split('.').collect();
            if parts.len() == 4 {
                let ipv4_valid = parts.iter().all(|p| {
                    if p.is_empty() || p.len() > 3 {
                        return false;
                    }
                    if p.len() > 1 && p.starts_with('0') {
                        return false;
                    }
                    p.parse::<u16>().is_ok_and(|v| v <= 255)
                });
                if ipv4_valid {
                    let trimmed = prefix.trim_end_matches(':');
                    if trimmed.is_empty() {
                        return prefix_bytes.windows(2).any(|w| w == b"::");
                    }
                    return validate_groups(trimmed, true);
                }
            }
        }
    }

    validate_groups(s, false)
}

pub(crate) fn validate_groups(s: &str, has_ipv4_suffix: bool) -> bool {
    let max_groups = if has_ipv4_suffix { 6 } else { 8 };

    if s == "::" {
        return true;
    }

    let has_double_colon = s.contains("::");

    if has_double_colon {
        let parts: Vec<&str> = s.splitn(2, "::").collect();
        if parts.len() != 2 {
            return false;
        }

        let left: Vec<&str> = if parts[0].is_empty() {
            vec![]
        } else {
            parts[0].split(':').collect()
        };

        let right: Vec<&str> = if parts[1].is_empty() {
            vec![]
        } else {
            parts[1].split(':').collect()
        };

        let total = left.len() + right.len();
        if total >= max_groups {
            return false;
        }

        left.iter()
            .chain(right.iter())
            .all(|g| is_valid_hex_group(g))
    } else {
        let groups: Vec<&str> = s.split(':').collect();
        groups.len() == max_groups && groups.iter().all(|g| is_valid_hex_group(g))
    }
}

pub(crate) fn is_valid_hex_group(g: &str) -> bool {
    !g.is_empty() && g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit())
}
