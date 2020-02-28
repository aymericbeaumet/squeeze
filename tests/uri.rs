use squeeze;

#[test]
fn it_should_extract_valid_uris() {
    for input in vec![
        // basic
        "http://localhost",
        // userinfo
        "http://foobar:@localhost",
        "http://foobar:baz@localhost",
        // port
        "http://foobar:@localhost:",
        "http://foobar:@localhost:8080",
        // path
        "http://localhost/lorem",
        // query
        "http://foobar:@localhost:8080?",
        "http://foobar:@localhost:8080?a=b",
        // fragment
        "http://foobar:@localhost:8080#",
        "http://foobar:@localhost:8080?#",
        "http://foobar:@localhost:8080?a=b#",
        "http://foobar:@localhost:8080?a=b#c=d",
        // meh
        "http://:@localhost:/?#",
        // various examples from the rfc
        //("file:///etc/hosts", "file:///etc/hosts"),
        "http://localhost/",
        "mailto:fred@example.com",
        //"foo://info.example.com?fred",
        //("ftp://ftp.is.co.za/rfc/rfc1808.txt"),
        //("http://www.ietf.org/rfc/rfc2396.txt"),
        //("ldap://[2001:db8::7]/c=GB?objectClass?one"),
        "mailto:John.Doe@example.com",
        "news:comp.infosystems.www.servers.unix",
        "tel:+1-816-555-1212",
        //"telnet://192.0.2.16:80/",
        "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
    ] {
        // - input by itself
        assert_eq!(Some(input), squeeze::squeeze_uri(input));
        // - input surrounded by spaces
        let surrounded = format!(" {} ", input);
        assert_eq!(Some(input), squeeze::squeeze_uri(&surrounded));
        // - input surrounded by < >
        let surrounded = format!("<{}>", input);
        assert_eq!(Some(input), squeeze::squeeze_uri(&surrounded));
        // - input surrounded by [ ]
        let surrounded = format!("[{}]", input);
        assert_eq!(Some(input), squeeze::squeeze_uri(&surrounded));
    }
}

#[test]
fn it_should_not_extract_invalid_uris() {
    for input in vec!["", " ", ":", ":/", "::", "-:"] {
        assert_eq!(None, squeeze::squeeze_uri(input));
    }
}
