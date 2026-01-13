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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_should_return_mirror() {
        let finder = Mirror::default();
        assert_eq!("mirror", finder.id());
    }

    #[test]
    fn find_should_return_full_range_for_non_empty_string() {
        let finder = Mirror::default();
        let input = "hello world";
        assert_eq!(Some(0..11), finder.find(input));
    }

    #[test]
    fn find_should_return_empty_range_for_empty_string() {
        let finder = Mirror::default();
        assert_eq!(Some(0..0), finder.find(""));
    }

    #[test]
    fn find_should_return_full_range_for_unicode() {
        let finder = Mirror::default();
        let input = "héllo 世界 🦀";
        assert_eq!(Some(0..input.len()), finder.find(input));
    }

    #[test]
    fn find_should_return_full_range_for_whitespace() {
        let finder = Mirror::default();
        assert_eq!(Some(0..3), finder.find("   "));
        assert_eq!(Some(0..2), finder.find("\t\n"));
    }
}
