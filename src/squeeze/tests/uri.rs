use squeeze::{uri, Finder};
use std::fs::File;
use std::io::{prelude::*, BufReader};

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
        // scheme only
        "foobar:",
        // rfc examples
        "file:///etc/hosts",
        "http://localhost/",
        "mailto:fred@example.com",
        "foo://info.example.com?fred",
        "ftp://ftp.is.co.za/rfc/rfc1808.txt",
        "http://www.ietf.org/rfc/rfc2396.txt",
        "ldap://[2001:db8::7]/c=GB?objectClass?one",
        "mailto:John.Doe@example.com",
        "news:comp.infosystems.www.servers.unix",
        "tel:+1-816-555-1212",
        "telnet://192.0.2.16:80/",
        "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        // found in the wild
        // "http://hellmann-eickeloh.de/images/galerie/Linkedin/index.php?login=%0%" // TODO: support invalid % encoding?
    ] {
        let finder = uri::URI::default();
        for i in vec![
            input.to_owned(),
            format!(" {} ", input),
            format!("<{}>", input),
            format!("[{}]", input),
            format!("<a href=\"{}\">link</a>", input),
            format!("{{{}}}", input),
            format!("\"{}\"", input),
            //format!("[link]({})", input), // TODO: markdown links
            //format!("'{}'", input), // TODO: links in single quotes
        ] {
            assert_eq!(Some(input), finder.find(&i).map(|r| &i[r]), "{}", input);
        }
    }
}

#[test]
fn it_should_ignore_invalid_uris() {
    let finder = uri::URI::default();
    for input in vec![
        // some protocols require a host
        "ftp:///test",
        "http:///test",
        "https:///test",
    ] {
        assert_eq!(None, finder.find(input), "{}", input);
    }
}

#[test]
fn it_should_succeed_to_mirror_the_fixtures_uris() {
    let finder = uri::URI::default();
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
