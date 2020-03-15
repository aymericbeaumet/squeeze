pub mod codetag;
pub mod uri;

use std::ops::Range;

pub trait Finder {
    fn find(&self, input: &str) -> Option<Range<usize>>;
}
