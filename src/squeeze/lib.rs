pub mod codetag;
pub mod mirror;
pub mod uri;

use std::ops::Range;

/// `Finder` must be implemented by all the finders. A finder implementation must be stateless,
/// it's up to the caller to call it until no more results can be extracted.
pub trait Finder {
    /// `id` must return a unique id for the finder.
    fn id(&self) -> &'static str;

    /// `find` should return the range of the first result it finds. None shall only be returned if
    /// the input string is exhausted.
    fn find(&self, s: &str) -> Option<Range<usize>>;
}
