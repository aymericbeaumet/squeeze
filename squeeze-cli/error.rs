//! Errors that stop the CLI, printed as `squeeze: <message>` on stderr.
//!
//! Invalid arguments are not here: clap reports them as usage errors, and
//! `squeeze::Error`s from configuring finders go through the same path.

use std::fmt;
use std::io;
use std::process::ExitCode;

/// Exit status when nothing was found and `--exit-code` is given.
pub const EXIT_NOT_FOUND: u8 = 1;
/// Exit status of every error, usage errors included, like grep.
pub const EXIT_ERROR: u8 = 2;

#[derive(Debug)]
pub enum Error {
    /// A path or glob pattern that names nothing readable.
    Input { path: String, reason: String },
    /// Reading an input or writing its results failed midway.
    Scan { source: String, error: io::Error },
    /// The results could not be written to stdout.
    Output(io::Error),
    /// The results could not be copied to the clipboard.
    Clipboard(String),
    /// A result could not be opened with the default application.
    Open { value: String, error: io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Input { path, reason } => write!(f, "{path}: {reason}"),
            Error::Scan { source, error } => write!(f, "{source}: {error}"),
            Error::Output(error) => write!(f, "cannot write the results: {error}"),
            Error::Clipboard(reason) => write!(f, "cannot copy to the clipboard: {reason}"),
            Error::Open { value, error } => write!(f, "cannot open {value}: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Scan { error, .. } | Error::Output(error) | Error::Open { error, .. } => {
                Some(error)
            }
            Error::Input { .. } | Error::Clipboard(_) => None,
        }
    }
}

impl Error {
    /// Reports the error on stderr and returns the exit status.
    pub fn report(&self) -> ExitCode {
        eprintln!("squeeze: {self}");
        ExitCode::from(EXIT_ERROR)
    }
}
