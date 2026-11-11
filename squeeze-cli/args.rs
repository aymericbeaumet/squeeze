//! Command-line rewrites applied before clap parses the arguments.

use squeeze::{codetag::Codetag, hash::Hash, uri::URI};
use std::ffi::OsString;

/// Whether a flag accepts a value.
type Accepts = fn(&str) -> bool;

/// Flags whose value is optional, with the values they accept. clap only
/// reads an optional value after `=`, so `--hash sha256` would scan a file
/// named `sha256`.
const OPTIONAL_VALUES: [(&str, Accepts); 4] = [
    ("--codetag", is_mnemonic),
    ("--hash", is_algorithm),
    ("--open", is_open_kind),
    ("--uri", is_known_scheme),
];

/// Values `--color` accepts.
pub const COLOR_WHEN: [&str; 3] = ["auto", "always", "never"];

fn is_mnemonic(value: &str) -> bool {
    Codetag::default().add_mnemonic(value).is_ok()
}

fn is_algorithm(value: &str) -> bool {
    Hash::default().add_algorithm(value).is_ok()
}

fn is_open_kind(value: &str) -> bool {
    matches!(value, "url" | "uri" | "path")
}

fn is_known_scheme(value: &str) -> bool {
    URI::is_registered_scheme(value) || URI::URL_SCHEMES.contains(&value)
}

/// Joins an optional-value flag with the next argument when every
/// comma-separated entry of that argument is a value the flag accepts:
/// `--hash sha256 notes.md` becomes `--hash=sha256 notes.md`, while
/// `--hash notes.md` keeps `notes.md` a path. Arguments after `--` are left
/// alone.
///
/// Fails with a hint when `--color` is given something other than
/// [`COLOR_WHEN`], which is what the color finder, now `--css-color`, used to
/// look like.
pub fn normalize(args: impl IntoIterator<Item = OsString>) -> Result<Vec<OsString>, String> {
    let mut out = Vec::new();
    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        if arg == "--" {
            out.push(arg);
            out.extend(args);
            break;
        }
        if let Some(text) = arg.to_str() {
            check_color(text, args.peek())?;
            if let Some((flag, accepts)) = OPTIONAL_VALUES.iter().find(|(flag, _)| text == *flag)
                && let Some(value) = args.peek().and_then(|next| next.to_str())
                && is_value_of(value, *accepts)
            {
                out.push(format!("{flag}={value}").into());
                args.next();
                continue;
            }
        }
        out.push(arg);
    }
    Ok(out)
}

fn is_value_of(value: &str, accepts: Accepts) -> bool {
    !value.starts_with('-')
        && value.split(',').any(|entry| !entry.trim().is_empty())
        && value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .all(accepts)
}

fn check_color(arg: &str, next: Option<&OsString>) -> Result<(), String> {
    let value = match arg.strip_prefix("--color") {
        Some("") => next.and_then(|next| next.to_str()),
        Some(rest) => match rest.strip_prefix('=') {
            Some(value) => Some(value),
            None => return Ok(()),
        },
        None => return Ok(()),
    };
    if value.is_some_and(|value| COLOR_WHEN.contains(&value)) {
        return Ok(());
    }
    Err(
        "--color sets when to color the output (auto, always, or never); search for colors with --css-color"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Vec<String>, String> {
        normalize(args.iter().map(OsString::from)).map(|args| {
            args.into_iter()
                .map(|arg| arg.into_string().unwrap())
                .collect()
        })
    }

    #[test]
    fn joins_valid_values() {
        assert_eq!(
            run(&["squeeze", "--hash", "sha256", "notes.md"]).unwrap(),
            ["squeeze", "--hash=sha256", "notes.md"]
        );
        assert_eq!(
            run(&["--codetag", "todo,fixme", "."]).unwrap(),
            ["--codetag=todo,fixme", "."]
        );
        assert_eq!(
            run(&["--uri", "https,ssh", "-"]).unwrap(),
            ["--uri=https,ssh", "-"]
        );
        assert_eq!(run(&["--open", "url,path"]).unwrap(), ["--open=url,path"]);
    }

    #[test]
    fn keeps_paths_and_unknown_values_as_arguments() {
        for args in [
            &["--hash", "notes.md"][..],
            &["--hash", "sha265"],
            &["--codetag", "tood"],
            &["--uri", "notes.md"],
            &["--open", "src"],
            &["--hash", "-1"],
            &["--hash", ","],
            &["--hash"],
            &["--", "--hash", "md5"],
            &["--hash=md5", "sha1"],
        ] {
            assert_eq!(
                Ok(args.iter().map(|arg| arg.to_string()).collect()),
                run(args),
                "{args:?}"
            );
        }
    }

    #[test]
    fn color_takes_when_and_points_to_the_finder() {
        assert!(run(&["--color", "never", "x"]).is_ok());
        assert!(run(&["--color=always"]).is_ok());
        assert!(run(&["--colors"]).is_ok());
        for args in [
            &["--color"][..],
            &["--color", "notes.css"],
            &["--color=red"],
        ] {
            let err = run(args).unwrap_err();
            assert!(err.contains("--css-color"), "{args:?}: {err}");
        }
    }
}
