use squeeze;

#[test]
fn it_should_extract_valid_uris() {
    assert_eq!(
        Some("http://localhost"),
        squeeze::squeeze_uri("-> http://localhost <-")
    );
    assert_eq!(
        Some("http://foobar:@localhost"),
        squeeze::squeeze_uri("-> http://foobar:@localhost <-")
    );
    assert_eq!(
        Some("http://foobar:@localhost:"),
        squeeze::squeeze_uri("-> http://foobar:@localhost: <-")
    );
    assert_eq!(
        Some("http://foobar:@localhost:8080"),
        squeeze::squeeze_uri("-> http://foobar:@localhost:8080 <-")
    );
    assert_eq!(
        Some("http://foobar:@localhost:8080?"),
        squeeze::squeeze_uri("-> http://foobar:@localhost:8080? <-")
    );
    assert_eq!(
        Some("http://foobar:@localhost:8080?a=b"),
        squeeze::squeeze_uri("-> http://foobar:@localhost:8080?a=b <-")
    );
}

#[test]
fn it_should_not_extract_invalid_uris() {
    assert_eq!(None, squeeze::squeeze_uri("-> : <-"));
    assert_eq!(None, squeeze::squeeze_uri("-> http: <-"));
}
