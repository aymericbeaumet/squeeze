use super::Finder;
use std::ops::Range;

#[derive(Default)]
pub struct Mirror {}

impl Finder for Mirror {
    fn id(&self) -> &'static str {
        "mirror"
    }

    fn find(&self, s: &str) -> Option<Range<usize>> {
        Some(0..s.len())
    }
}
