use squeeze;

#[test]
fn it_extracts_valid_urls() {
    assert_eq!(
        Some("http://localhost"),
        squeeze::squeeze_uri("-> http://localhost <-")
    );
    assert_eq!(
        Some("http://foobar:@localhost"),
        squeeze::squeeze_uri("-> http://foobar:@localhost <-")
    );
}
