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
//! - [`domain::Domain`] - Extract DNS-style domain names
//! - [`email::Email`] - Extract email addresses
//! - [`emoji::Emoji`] - Extract emojis and emoji sequences
//! - [`env::Env`] - Extract environment variable references
//! - [`handle::Handle`] - Extract social `@handle` mentions
//! - [`hash::Hash`] - Extract hashes (MD5, SHA-1, SHA-256, SHA-512)
//! - [`ip::Ip`] - Extract IP addresses (IPv4, IPv6)
//! - [`json::Json`] - Extract JSON objects and arrays
//! - [`jwt::Jwt`] - Extract JSON Web Tokens
//! - [`mac::Mac`] - Extract MAC addresses
//! - [`modeline::Modeline`] - Extract vim/vi/ex modelines
//! - [`path::Path`] - Extract file paths (absolute, relative, and home-relative)
//! - [`phone::Phone`] - Extract phone numbers
//! - [`semver::Semver`] - Extract semantic versions
//! - [`uuid::Uuid`] - Extract UUIDs
//! - [`mirror::Mirror`] - A passthrough finder that returns the entire input
//!
//! The [`scanner::Scanner`] runs any set of finders over a line in one pass:
//! a prescan disables finders whose bytes are absent, SIMD classification
//! and per-finder context gates keep finder calls to the positions where a
//! match can start, and declarative run rules gate several finders at once
//! from a single measurement of the digit and hex runs. See
//! `docs/performance.md` in the repository for the architecture, the
//! contracts finders follow, and how to measure.
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
pub(crate) mod classify;
pub mod codetag;
pub mod color;
pub mod datetime;
pub mod domain;
pub mod email;
pub mod emoji;
pub mod env;
pub mod handle;
pub mod hash;
pub(crate) mod iana;
pub mod ip;
pub(crate) mod ipv6;
pub mod json;
pub mod jwt;
pub mod mac;
pub mod mirror;
pub mod modeline;
pub mod path;
pub mod phone;
pub mod scanner;
pub mod semver;
pub mod uri;
pub mod uuid;
pub(crate) mod word;

use std::ops::Range;

/// A set of bytes, used by [`RunRule`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSet([u64; 4]);

impl ByteSet {
    pub const EMPTY: ByteSet = ByteSet([0; 4]);
    pub const ALL: ByteSet = ByteSet([u64::MAX; 4]);

    pub const fn from_bytes(bytes: &[u8]) -> ByteSet {
        let mut set = ByteSet::EMPTY;
        let mut i = 0;
        while i < bytes.len() {
            set = set.with(bytes[i]);
            i += 1;
        }
        set
    }

    /// Every byte for which `f` holds.
    pub fn from_fn(f: impl Fn(u8) -> bool) -> ByteSet {
        let mut set = ByteSet::EMPTY;
        for b in 0..=255u8 {
            if f(b) {
                set = set.with(b);
            }
        }
        set
    }

    pub const fn with(mut self, byte: u8) -> ByteSet {
        self.0[(byte >> 6) as usize] |= 1u64 << (byte & 63);
        self
    }

    #[inline]
    pub const fn contains(&self, byte: u8) -> bool {
        self.0[(byte >> 6) as usize] & (1u64 << (byte & 63)) != 0
    }
}

/// The byte class a [`RunRule`] measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunClass {
    /// ASCII digits.
    Digit,
    /// ASCII hexadecimal digits.
    Hex,
}

/// Longest run length the scanner distinguishes; longer runs are reported
/// as this value with [`Run::capped`] set.
pub const RUN_CAP: u8 = 129;

/// A maximal run of one [`RunClass`] starting at a candidate position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    /// Length of the run, at most [`RUN_CAP`].
    pub len: u8,
    /// Whether the run reached [`RUN_CAP`] and may continue.
    pub capped: bool,
    /// The byte after the run, `None` at the end of the input.
    pub after: Option<u8>,
}

/// The digit and hex runs at a candidate position, measured once by the
/// scanner and shared by every finder's [`RunRule`]s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Runs {
    pub digit: Run,
    pub hex: Run,
}

impl Runs {
    /// Measures the runs starting at `pos`.
    pub fn at(input: &[u8], pos: usize) -> Runs {
        let cap = RUN_CAP as usize;
        let end = input.len().min(pos + cap);
        let mut hex = pos;
        while hex < end && input[hex].is_ascii_hexdigit() {
            hex += 1;
        }
        let mut digit = pos;
        while digit < hex && input[digit].is_ascii_digit() {
            digit += 1;
        }
        let run = |stop: usize| Run {
            len: (stop - pos) as u8,
            capped: stop - pos >= cap,
            after: input.get(stop).copied(),
        };
        Runs {
            digit: run(digit),
            hex: run(hex),
        }
    }

    fn get(&self, class: RunClass) -> &Run {
        match class {
            RunClass::Digit => &self.digit,
            RunClass::Hex => &self.hex,
        }
    }
}

/// A declarative rule on the run starting at a candidate position, see
/// [`Finder::run_rules`].
///
/// A rule applies when the start byte is in `cur`; it accepts when the
/// `class` run has a length in `min..=max` and the byte after it is in
/// `after` (or the input ends there and `after_end` is set). A capped run
/// always satisfies the `after` part, since its true end is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunRule {
    pub cur: ByteSet,
    pub class: RunClass,
    pub min: u8,
    pub max: u8,
    pub after: ByteSet,
    pub after_end: bool,
}

impl RunRule {
    /// A rule for `class` runs of `min..=max` bytes starting at any byte of
    /// the class and followed by any byte, including the end of the input.
    pub fn new(class: RunClass, min: u8, max: u8) -> RunRule {
        let cur = match class {
            RunClass::Digit => ByteSet::from_fn(|b| b.is_ascii_digit()),
            RunClass::Hex => ByteSet::from_fn(|b| b.is_ascii_hexdigit()),
        };
        RunRule {
            cur,
            class,
            min,
            max,
            after: ByteSet::ALL,
            after_end: true,
        }
    }

    /// Requires the byte after the run to be one of `bytes`.
    pub fn followed_by(mut self, bytes: &[u8]) -> RunRule {
        self.after = ByteSet::from_bytes(bytes);
        self.after_end = false;
        self
    }

    #[inline]
    fn applies(&self, cur: u8) -> bool {
        self.cur.contains(cur)
    }

    #[inline]
    fn accepts(&self, runs: &Runs) -> bool {
        let run = runs.get(self.class);
        if run.len < self.min || run.len > self.max {
            return false;
        }
        if run.capped {
            return true;
        }
        match run.after {
            Some(b) => self.after.contains(b),
            None => self.after_end,
        }
    }

    /// Evaluates a finder's rules: a match may start when no rule applies
    /// to `cur`, or when at least one applicable rule accepts `runs`.
    pub fn allow(rules: &[RunRule], cur: u8, runs: &Runs) -> bool {
        let mut applicable = false;
        for rule in rules {
            if rule.applies(cur) {
                if rule.accepts(runs) {
                    return true;
                }
                applicable = true;
            }
        }
        !applicable
    }
}

/// Per-line, per-finder scratch handed to
/// [`Finder::try_at_memo`]/[`Finder::try_trigger_at_memo`].
///
/// A finder may record what it learned about the current line (typically
/// the extent of a run that cannot match) so that later attempts on the same
/// line stay cheap. It is a cache only: results must not depend on it. The
/// scanner resets it to `Memo::default()` (an empty range) for every line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Memo {
    pub start: usize,
    pub end: usize,
    /// Free slot for one more position the finder wants to remember.
    pub aux: usize,
}

impl Memo {
    /// Whether `pos` lies in the remembered range.
    #[inline]
    pub fn covers(&self, pos: usize) -> bool {
        self.start <= pos && pos < self.end
    }
}

/// A trait for finding patterns in text.
///
/// All finders implement this trait. A finder implementation should be stateless;
/// it's up to the caller to call it repeatedly until no more results can be extracted.
///
/// # Contract
///
/// - Returned ranges are non-empty (`start < end`) and lie on UTF-8 character
///   boundaries.
/// - [`try_at`](Finder::try_at)/[`try_trigger_at`](Finder::try_trigger_at)
///   receive positions into the whole line and return absolute ranges.
/// - Matches produced through the [`scanner::Scanner`] are disjoint per
///   finder and position-sorted.
///
/// Note that iterating with `find` over advancing sub-slices (as below) erases
/// the left context at each slice boundary, so finders that reject matches
/// based on what precedes them (e.g. a handle glued to a word) can accept a
/// match at position 0 of a sub-slice that the [`scanner::Scanner`] — which
/// always sees the whole line — would reject. The Scanner behavior is
/// authoritative; prefer it over hand-rolled `find` loops.
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
pub trait Finder: Send + Sync {
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

    /// Whether a dispatch-mode match could start at byte `cur` when the byte
    /// immediately before it is `prev`.
    ///
    /// Only meaningful when [`dispatchable`](Finder::dispatchable) returns
    /// true. Must agree with [`try_at`](Finder::try_at): whenever this returns
    /// `false`, `try_at` must return `None` in that context. The
    /// [`scanner::Scanner`] folds the answers into lookup tables so positions
    /// that cannot start a match never reach the finder.
    fn could_start_after(&self, _prev: u8, _cur: u8) -> bool {
        true
    }

    /// Whether a dispatch-mode match starting at byte `cur` could have `next`
    /// as its second byte. Same contract as
    /// [`could_start_after`](Finder::could_start_after).
    fn could_continue_with(&self, _cur: u8, _next: u8) -> bool {
        true
    }

    /// [`try_at`](Finder::try_at) with a per-line [`Memo`]; the scanner
    /// calls this variant. Finders whose attempts can rescan the same bytes
    /// override it to remember what already failed. Must return exactly what
    /// `try_at` returns.
    fn try_at_memo(&self, input: &[u8], pos: usize, memo: &mut Memo) -> Option<Range<usize>> {
        let _ = memo;
        self.try_at(input, pos)
    }

    /// [`try_trigger_at`](Finder::try_trigger_at) with a per-line
    /// [`Memo`], same contract as [`try_at_memo`](Finder::try_at_memo).
    fn try_trigger_at_memo(
        &self,
        input: &[u8],
        pos: usize,
        memo: &mut Memo,
    ) -> Option<Range<usize>> {
        let _ = memo;
        self.try_trigger_at(input, pos)
    }

    /// Rules on the digit or hex run starting at a candidate position,
    /// evaluated with [`RunRule::allow`] before [`try_at`](Finder::try_at)
    /// is called. Same contract as
    /// [`could_start_after`](Finder::could_start_after): when the rules
    /// reject a position, `try_at` must return `None` there. The scanner
    /// measures the runs once per position for all finders.
    fn run_rules(&self) -> Vec<RunRule> {
        Vec::new()
    }

    /// Whether this finder supports trigger-mode scanning.
    ///
    /// Trigger-mode is for finders whose cheapest reliable signal is inside the
    /// match rather than at the first byte, such as the `@` in an email address
    /// or `:` in a URI.
    fn triggerable(&self) -> bool {
        false
    }

    /// Whether the given byte could trigger a match for this finder.
    /// Only meaningful when [`triggerable`](Finder::triggerable) returns true.
    fn could_trigger_at(&self, _byte: u8) -> bool {
        false
    }

    /// Try to find a match triggered by `pos` in the full input.
    /// Only called when [`triggerable`](Finder::triggerable) returns true.
    fn try_trigger_at(&self, _input: &[u8], _pos: usize) -> Option<Range<usize>> {
        None
    }
}
