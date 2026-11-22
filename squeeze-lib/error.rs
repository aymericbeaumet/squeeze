//! Errors returned while configuring finders and scanners.
//!
//! Scanning itself never fails: once a [`Scanner`](crate::scanner::Scanner)
//! and its finders are built, every input yields matches or none.

use std::fmt;

/// An invalid finder or scanner configuration.
///
/// # Example
///
/// ```
/// use squeeze::{Error, hash::Hash};
///
/// let mut finder = Hash::default();
/// assert_eq!(
///     finder.add_algorithm("sha265"),
///     Err(Error::UnknownHashAlgorithm {
///         name: "sha265".to_string(),
///         suggestion: Some("sha256"),
///     })
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// More finders than one [`Scanner`](crate::scanner::Scanner) can run.
    TooManyFinders { len: usize, max: usize },
    /// A hash algorithm other than md5, sha1, sha256 and sha512.
    UnknownHashAlgorithm {
        name: String,
        suggestion: Option<&'static str>,
    },
    /// A codetag mnemonic outside [PEP 350](https://peps.python.org/pep-0350/);
    /// [`Codetag::add_custom_mnemonic`](crate::codetag::Codetag::add_custom_mnemonic)
    /// accepts any.
    UnknownMnemonic {
        name: String,
        suggestion: Option<&'static str>,
    },
    /// An empty or whitespace-only codetag mnemonic, which would match every
    /// `word:`.
    EmptyMnemonic,
    /// A URI scheme that [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.1)
    /// does not allow: a letter followed by letters, digits, `+`, `-` and `.`.
    InvalidScheme { name: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooManyFinders { len, max } => {
                write!(f, "too many finders: got {len}, max is {max}")
            }
            Error::UnknownHashAlgorithm { name, suggestion } => {
                write!(f, "unknown hash algorithm '{name}'")?;
                match suggestion {
                    Some(s) => write!(f, ", did you mean '{s}'?"),
                    None => write!(f, " (expected md5, sha1, sha256, or sha512)"),
                }
            }
            Error::UnknownMnemonic { name, suggestion } => {
                write!(f, "unknown codetag mnemonic '{name}'")?;
                match suggestion {
                    Some(s) => write!(f, ", did you mean '{s}'?"),
                    None => write!(f, " (expected a PEP 350 mnemonic such as todo or fixme)"),
                }
            }
            Error::EmptyMnemonic => write!(f, "empty codetag mnemonic"),
            Error::InvalidScheme { name } => write!(
                f,
                "invalid URI scheme '{name}' (expected a letter followed by letters, digits, '+', '-', or '.')"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// The candidate closest to `name`, ignoring ASCII case, when it is near
/// enough to be a typo: one edit for names of up to four characters, two
/// beyond (a swap of adjacent letters counts as one). Ties go to the earlier
/// candidate.
pub(crate) fn suggest(name: &str, candidates: &[&'static str]) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    let max = match name.chars().count() {
        0 | 1 => 0,
        2..=4 => 1,
        _ => 2,
    };
    candidates
        .iter()
        .map(|&c| (edit_distance(&name, &c.to_ascii_lowercase()), c))
        .filter(|&(d, _)| d <= max)
        .min_by_key(|&(d, _)| d)
        .map(|(_, c)| c)
}

/// Optimal string alignment distance: Levenshtein plus adjacent swaps.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut rows = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in rows.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut d = (rows[i - 1][j] + 1)
                .min(rows[i][j - 1] + 1)
                .min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d = d.min(rows[i - 2][j - 2] + 1);
            }
            rows[i][j] = d;
        }
    }
    rows[a.len()][b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggest_catches_swaps_and_single_edits() {
        let algorithms = ["md5", "sha1", "sha256", "sha512"];
        assert_eq!(Some("sha256"), suggest("sha265", &algorithms));
        assert_eq!(Some("sha256"), suggest("SHA-256", &algorithms));
        assert_eq!(Some("md5"), suggest("md4", &algorithms));
        assert_eq!(None, suggest("nope", &algorithms));
    }

    #[test]
    fn suggest_allows_fewer_edits_on_short_names() {
        assert_eq!(None, suggest("x", &["xx"]));
        assert_eq!(None, suggest("", &["a"]));
        assert_eq!(Some("todo"), suggest("tood", &["todo", "tbd"]));
        assert_eq!(None, suggest("perf", &["port", "ref"]));
        assert_eq!(Some("fixme"), suggest("fxmie", &["fixme"]));
    }

    #[test]
    fn display_explains_each_error() {
        let unknown = Error::UnknownHashAlgorithm {
            name: "nope".to_string(),
            suggestion: None,
        };
        assert_eq!(
            "unknown hash algorithm 'nope' (expected md5, sha1, sha256, or sha512)",
            unknown.to_string()
        );
        let typo = Error::UnknownMnemonic {
            name: "tood".to_string(),
            suggestion: Some("todo"),
        };
        assert_eq!(
            "unknown codetag mnemonic 'tood', did you mean 'todo'?",
            typo.to_string()
        );
    }
}
