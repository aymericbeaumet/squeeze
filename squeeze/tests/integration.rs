use squeeze::{codetag::Codetag, mirror::Mirror, uri::URI, Finder};

#[test]
fn finder_trait_id_should_be_unique() {
    let uri = URI::default();
    let mut codetag = Codetag::default();
    codetag.build_mnemonics_regex().unwrap();
    let mirror = Mirror::default();

    let ids: Vec<&str> = vec![uri.id(), codetag.id(), mirror.id()];
    let mut unique_ids = ids.clone();
    unique_ids.sort();
    unique_ids.dedup();

    assert_eq!(ids.len(), unique_ids.len(), "Finder IDs must be unique");
}

#[test]
fn uri_finder_should_extract_multiple_uris_from_text() {
    let finder = URI::default();
    let text = "Check https://example.com and http://localhost:8080/path for info";

    let mut results = Vec::new();
    let mut idx = 0;

    while idx < text.len() {
        if let Some(range) = finder.find(&text[idx..]) {
            results.push(&text[idx + range.start..idx + range.end]);
            idx += range.end;
        } else {
            break;
        }
    }

    assert_eq!(2, results.len());
    assert_eq!("https://example.com", results[0]);
    assert_eq!("http://localhost:8080/path", results[1]);
}

#[test]
fn codetag_finder_should_extract_codetags_from_code() {
    let mut finder = Codetag::default();
    finder.build_mnemonics_regex().unwrap();

    let lines = vec![
        "// TODO: implement feature",
        "fn main() {}",
        "// FIXME: this is broken",
        "let x = 1;",
    ];

    let mut results = Vec::new();
    for line in &lines {
        if let Some(range) = finder.find(line) {
            results.push(&line[range]);
        }
    }

    assert_eq!(2, results.len());
    assert!(results[0].contains("TODO"));
    assert!(results[1].contains("FIXME"));
}

#[test]
fn uri_finder_with_scheme_filter_should_only_match_specified_schemes() {
    let mut finder = URI::default();
    finder.add_scheme("https");

    let text = "Visit https://secure.com or http://insecure.com";

    let mut results = Vec::new();
    let mut idx = 0;

    while idx < text.len() {
        if let Some(range) = finder.find(&text[idx..]) {
            results.push(&text[idx + range.start..idx + range.end]);
            idx += range.end;
        } else {
            break;
        }
    }

    assert_eq!(1, results.len());
    assert_eq!("https://secure.com", results[0]);
}

#[test]
fn codetag_finder_with_custom_mnemonic_should_only_match_that_mnemonic() {
    let mut finder = Codetag::default();
    finder.add_mnemonic("CUSTOM");
    finder.build_mnemonics_regex().unwrap();

    assert!(finder.find("CUSTOM: this should match").is_some());
    assert!(finder.find("TODO: this should not match").is_none());
}

#[test]
fn mirror_finder_should_always_return_full_input() {
    let finder = Mirror::default();

    for input in &["", "hello", "https://example.com", "TODO: test", "   "] {
        let result = finder.find(input);
        assert!(result.is_some());
        assert_eq!(0..input.len(), result.unwrap());
    }
}

#[test]
fn uri_finder_should_handle_complex_real_world_urls() {
    let finder = URI::default();

    let urls = vec![
        "https://api.example.com/v1/users?page=1&limit=10#section",
        "ftp://user:password@ftp.example.com:21/files/document.pdf",
        "mailto:test@example.com?subject=Hello%20World",
        "file:///home/user/documents/file.txt",
        "ssh://git@github.com:22/user/repo.git",
    ];

    for url in urls {
        let result = finder.find(url);
        assert!(result.is_some(), "Should find: {}", url);
        assert_eq!(
            url,
            &url[result.unwrap()],
            "Should match entire URL: {}",
            url
        );
    }
}

#[test]
fn uri_finder_should_handle_urls_in_markdown() {
    let finder = URI::default();

    let markdown = "[Click here](https://example.com/page) for more info";
    let result = finder.find(markdown);

    assert!(result.is_some());
    assert_eq!("https://example.com/page", &markdown[result.unwrap()]);
}

#[test]
fn codetag_finder_should_handle_pep350_fields() {
    let mut finder = Codetag::default();
    finder.build_mnemonics_regex().unwrap();

    let inputs = vec![
        ("TODO(author): message", "TODO(author): message"),
        (
            "FIXME(#123): bug description",
            "FIXME(#123): bug description",
        ),
        (
            "NOTE(v2.0): deprecation warning",
            "NOTE(v2.0): deprecation warning",
        ),
    ];

    for (input, expected) in inputs {
        let result = finder.find(input);
        assert!(result.is_some(), "Should find codetag in: {}", input);
        assert_eq!(expected, &input[result.unwrap()]);
    }
}

#[test]
fn codetag_finder_hide_mnemonic_should_exclude_mnemonic_from_result() {
    let mut finder = Codetag::default();
    finder.hide_mnemonic = true;
    finder.build_mnemonics_regex().unwrap();

    let input = "TODO: implement this feature";
    let result = finder.find(input);

    assert!(result.is_some());
    let extracted = &input[result.unwrap()];
    assert!(!extracted.starts_with("TODO"));
    assert!(extracted.contains("implement this feature"));
}
