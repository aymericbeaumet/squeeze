use squeeze::{uri, Finder};
use std::fs::File;
use std::io::{prelude::*, BufReader};

#[test]
fn it_should_succeed_to_mirror_the_fixtures_uris() {
    let mut finder = uri::URI::default();
    finder.strict = true;
    let fixtures_glob = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("uri-*");

    for filepath in glob::glob(fixtures_glob.to_str().unwrap()).unwrap() {
        let file = File::open(filepath.unwrap()).unwrap();
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let input = &line.unwrap();
            assert_eq!(Some(0..input.len()), finder.find(input), "{}", input);
        }
    }
}
