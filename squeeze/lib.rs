//! # Squeeze
//!
//! A library for extracting rich information from any text.
//!
//! This crate provides finders for extracting structured data from text:
//! - [`uri::URI`] - Extract URIs/URLs/URNs as defined by [RFC 3986](https://tools.ietf.org/html/rfc3986/)
//! - [`cidr::Cidr`] - Extract CIDR notation (IPv4/IPv6 network ranges)
//! - [`codetag::Codetag`] - Extract codetags (TODO, FIXME, etc.) as defined by [PEP 350](https://www.python.org/dev/peps/pep-0350/)
//! - [`color::Color`] - Extract colors (hex, rgb, hsl)
//! - [`datetime::Datetime`] - Extract ISO 8601 datetimes
//! - [`email::Email`] - Extract email addresses
//! - [`emoji::Emoji`] - Extract emojis and emoji sequences
//! - [`env::Env`] - Extract environment variable references
//! - [`hash::Hash`] - Extract hashes (MD5, SHA-1, SHA-256, SHA-512)
//! - [`ip::Ip`] - Extract IP addresses (IPv4, IPv6)
//! - [`json::Json`] - Extract JSON objects and arrays
//! - [`jwt::Jwt`] - Extract JSON Web Tokens
//! - [`mac::Mac`] - Extract MAC addresses
//! - [`path::Path`] - Extract file paths (absolute, relative, and home-relative)
//! - [`phone::Phone`] - Extract phone numbers
//! - [`semver::Semver`] - Extract semantic versions
//! - [`uuid::Uuid`] - Extract UUIDs
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

pub mod cidr;
pub mod codetag;
pub mod color;
pub mod datetime;
pub mod email;
pub mod emoji;
pub mod env;
pub mod hash;
pub mod ip;
pub(crate) mod ipv6;
pub mod json;
pub mod jwt;
pub mod mac;
pub mod mirror;
pub mod path;
pub mod phone;
pub mod scanner;
pub mod semver;
pub mod uri;
pub mod uuid;

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
    fn id(&self) -> &'static str;

    /// Finds the first match in the given string.
    ///
    /// Returns `Some(range)` containing the byte range of the match, or `None` if no match is found.
    /// The range is relative to the input string slice.
    fn find(&self, s: &str) -> Option<Range<usize>>;

    /// Whether this finder supports dispatch-mode scanning via [`try_at`](Finder::try_at).
    fn dispatchable(&self) -> bool {
        false
    }

    /// Whether the given byte could be the first byte of a match.
    /// Only meaningful when [`dispatchable`](Finder::dispatchable) returns true.
    fn could_start_at(&self, _byte: u8) -> bool {
        true
    }

    /// Try to find a match starting exactly at `pos` in the full input.
    /// Only called when [`dispatchable`](Finder::dispatchable) returns true.
    fn try_at(&self, _input: &[u8], _pos: usize) -> Option<Range<usize>> {
        None
    }
}
