//! # Squeeze
//!
//! A library for extracting rich information from any text.
//!
//! This crate provides finders for extracting structured data from text:
//! - [`uri::URI`] - Extract URIs/URLs/URNs as defined by [RFC 3986](https://tools.ietf.org/html/rfc3986/)
//! - [`codetag::Codetag`] - Extract codetags (TODO, FIXME, etc.) as defined by [PEP 350](https://www.python.org/dev/peps/pep-0350/)
//! - [`mirror::Mirror`] - A passthrough finder that returns the entire input
//!
//! ## Example
//!
//! ```
//! use squeeze::{uri::URI, Finder};
//!
//! let finder = URI::default();
//! let text = "Visit https://example.com for more info";
//!
//! if let Some(range) = finder.find(text) {
//!     println!("Found: {}", &text[range]);
//! }
//! ```

pub mod codetag;
pub mod mirror;
pub mod uri;

use std::ops::Range;

/// A trait for finding patterns in text.
///
/// All finders implement this trait. A finder implementation should be stateless;
/// it's up to the caller to call it repeatedly until no more results can be extracted.
///
/// # Example
///
/// ```
/// use squeeze::{uri::URI, Finder};
///
/// let finder = URI::default();
/// let text = "Check https://foo.com and https://bar.com";
///
/// let mut results = Vec::new();
/// let mut idx = 0;
///
/// while idx < text.len() {
///     if let Some(range) = finder.find(&text[idx..]) {
///         results.push(&text[idx + range.start..idx + range.end]);
///         idx += range.end;
///     } else {
///         break;
///     }
/// }
///
/// assert_eq!(results, vec!["https://foo.com", "https://bar.com"]);
/// ```
pub trait Finder {
    /// Returns a unique identifier for this finder.
    ///
    /// This is used for logging and debugging purposes.
    fn id(&self) -> &'static str;

    /// Finds the first match in the given string.
    ///
    /// Returns `Some(range)` containing the byte range of the match, or `None` if no match is found.
    /// The range is relative to the input string slice.
    fn find(&self, s: &str) -> Option<Range<usize>>;
}
