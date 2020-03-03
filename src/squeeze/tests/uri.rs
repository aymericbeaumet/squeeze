use squeeze;

#[test]
fn it_should_mirror_valid_uris() {
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
        // ipv4
        "http://127.0.0.0",
        "http://127.0.0.10",
        "http://127.0.0.100",
        "http://127.0.0.200",
        "http://127.0.0.250",
        "http://192.0.2.235",
        // ipv6
        "http://[::]",
        "http://[::1]",
        "http://[2001:db8::1]",
        "http://[2001:0db8::0001]",
        "http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
        "http://[::ffff:192.0.2.128]",
        "http://[::ffff:c000:0280]",
        // rfc examples
        //"file:///etc/hosts",
        "http://localhost/",
        "mailto:fred@example.com",
        "foo://info.example.com?fred",
        //"ftp://ftp.is.co.za/rfc/rfc1808.txt",
        //"http://www.ietf.org/rfc/rfc2396.txt",
        "ldap://[2001:db8::7]/c=GB?objectClass?one",
        "mailto:John.Doe@example.com",
        "news:comp.infosystems.www.servers.unix",
        "tel:+1-816-555-1212",
        "telnet://192.0.2.16:80/",
        "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
    ] {
        for i in vec![
            input.to_owned(),
            format!(" {} ", input),
            format!("<{}>", input),
            format!("[{}]", input),
            format!("<a href=\"{}\">link</a>", input),
            format!("{{{}}}", input),
            //format!("[link]({})", input);
        ] {
            assert_eq!(Some(input), squeeze::uri::find(&i), "{}", input);
        }
    }
}

#[test]
fn it_should_skip_invalid_uris() {
    for input in vec![
        "", " ", ":", ":/", "://", "::", "-:",
        // meh
        //"http://test@",
    ] {
        assert_eq!(None, squeeze::uri::find(input), "{}", input);
    }
}

#[test]
fn it_should_properly_identify_valid_ipv6s() {
    for input in vec![
        "::",
        "::1",
        "1::",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6::7",
        "1:2:3:4:5:6:127.0.0.1",
        "1::127.0.0.1",
    ] {
        assert_eq!(
            true,
            squeeze::uri::is_ipv6address(input.as_bytes()),
            "{}",
            input
        );
    }
}

#[test]
fn it_should_properly_identify_invalid_ipv6s() {
    for input in vec![
        " ",
        " ::",
        ":: ",
        " :: ",
        ":::",
        "::1::",
        ":1:",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7:127.0.0.1",
        "1:2:3:4:5:6::7:8",
        "1:2:3:4:5:6::127.0.0.1",
        "1:127.0.0.1::",
    ] {
        assert_eq!(
            false,
            squeeze::uri::is_ipv6address(input.as_bytes()),
            "{}",
            input
        );
    }
}
