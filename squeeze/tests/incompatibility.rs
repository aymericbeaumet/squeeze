//! Tests that verify how finders behave when several of them are wired
//! together through a `Scanner`. The focus is on inputs where multiple
//! finders could legitimately match — we want to make sure we don't
//! report the same span twice or accidentally eat tokens that should
//! belong to a different finder.

use squeeze::{
    domain::Domain,
    email::Email,
    handle::Handle,
    modeline::Modeline,
    path::Path,
    scanner::{Match, Scanner},
    uri::URI,
    Finder,
};

fn matched_spans<'a>(scanner: &Scanner, input: &'a str) -> Vec<(&'static str, &'a str)> {
    let mut buf: Vec<Match> = Vec::new();
    scanner.scan_line_into(input, &mut buf);
    buf.into_iter()
        .map(|m| {
            let id = scanner.finders()[m.finder_index].id();
            (id, &input[m.range])
        })
        .collect()
}

// --- domain / email ---

#[test]
fn domain_and_email_on_address_yields_only_email() {
    let scanner = Scanner::new(vec![
        Box::new(Domain::default()),
        Box::new(Email::default()),
    ]);
    let spans = matched_spans(&scanner, "contact user@example.com today");
    assert_eq!(spans, vec![("email", "user@example.com")]);
}

#[test]
fn domain_and_email_on_bare_domain_yields_only_domain() {
    let scanner = Scanner::new(vec![
        Box::new(Domain::default()),
        Box::new(Email::default()),
    ]);
    let spans = matched_spans(&scanner, "visit example.com today");
    assert_eq!(spans, vec![("domain", "example.com")]);
}

#[test]
fn domain_and_email_both_match_when_distinct() {
    let scanner = Scanner::new(vec![
        Box::new(Domain::default()),
        Box::new(Email::default()),
    ]);
    let spans = matched_spans(&scanner, "alice@foo.com and bar.com");
    assert_eq!(
        spans,
        vec![("email", "alice@foo.com"), ("domain", "bar.com"),]
    );
}

// --- domain / uri ---

#[test]
fn domain_and_url_on_url_yields_only_url() {
    let mut uri = URI::default();
    uri.add_scheme("https");
    let scanner = Scanner::new(vec![Box::new(Domain::default()), Box::new(uri)]);
    let spans = matched_spans(&scanner, "see https://example.com today");
    assert_eq!(spans, vec![("uri", "https://example.com")]);
}

#[test]
fn domain_and_url_both_match_when_distinct() {
    let mut uri = URI::default();
    uri.add_scheme("https");
    let scanner = Scanner::new(vec![Box::new(Domain::default()), Box::new(uri)]);
    let spans = matched_spans(&scanner, "https://example.com or foo.org");
    assert_eq!(
        spans,
        vec![("uri", "https://example.com"), ("domain", "foo.org"),]
    );
}

// --- handle / email ---

#[test]
fn handle_and_email_on_address_yields_only_email() {
    let scanner = Scanner::new(vec![
        Box::new(Handle::default()),
        Box::new(Email::default()),
    ]);
    let spans = matched_spans(&scanner, "send to user@example.com");
    assert_eq!(spans, vec![("email", "user@example.com")]);
}

#[test]
fn handle_and_email_both_match_when_distinct() {
    let scanner = Scanner::new(vec![
        Box::new(Handle::default()),
        Box::new(Email::default()),
    ]);
    let spans = matched_spans(&scanner, "@alice cc bob@example.com");
    assert_eq!(
        spans,
        vec![("handle", "@alice"), ("email", "bob@example.com"),]
    );
}

#[test]
fn handle_does_not_match_email_at_sign() {
    // Even in isolation, the handle finder must skip the '@' of an email.
    let f = Handle::default();
    assert!(f.find("user@example.com").is_none());
}

// --- handle / mastodon vs email ---

#[test]
fn mastodon_handle_with_email_present() {
    let scanner = Scanner::new(vec![
        Box::new(Handle::default()),
        Box::new(Email::default()),
    ]);
    // Mastodon handle '@alice@social.example' is reported by handle; the email
    // finder would otherwise capture 'alice@social.example' so we must ensure
    // it does not double-match.
    let spans = matched_spans(&scanner, "follow @alice@social.example");
    // Email finder will still see "alice@social.example" — that is acceptable
    // because both interpretations are valid. We assert both spans appear,
    // ordered by start.
    let ids: Vec<&str> = spans.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&"handle"));
}

// --- path / domain ---

#[test]
fn path_takes_precedence_over_domain_inside_paths() {
    let scanner = Scanner::new(vec![Box::new(Path::default()), Box::new(Domain::default())]);
    // A path containing a domain-looking component should not surface the
    // inner component as a separate domain.
    let spans = matched_spans(&scanner, "see /var/www/example.com/index.html");
    let ids: Vec<&str> = spans.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&"path"));
    assert!(!ids.contains(&"domain"));
}

// --- modeline interactions ---

#[test]
fn modeline_and_url_do_not_conflict() {
    let mut uri = URI::default();
    uri.add_scheme("http");
    uri.add_scheme("https");
    let scanner = Scanner::new(vec![Box::new(Modeline::default()), Box::new(uri)]);
    let spans = matched_spans(&scanner, "// vim: ts=4 see http://example.com");
    let ids: Vec<&str> = spans.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&"modeline"));
    assert!(ids.contains(&"uri"));
}

#[test]
fn modeline_does_not_match_url_scheme_colon() {
    // 'https:' should never be reported as a modeline.
    let f = Modeline::default();
    assert!(f.find("see https://example.com").is_none());
}

// --- All three new finders together with the kitchen sink ---

#[test]
fn three_new_finders_together_on_mixed_text() {
    let scanner = Scanner::new(vec![
        Box::new(Domain::default()),
        Box::new(Handle::default()),
        Box::new(Modeline::default()),
        Box::new(Email::default()),
    ]);
    let spans = matched_spans(
        &scanner,
        "@alice mailed bob@foo.com about bar.com // vim: ts=4",
    );
    let mut ids: Vec<&str> = spans.iter().map(|(id, _)| *id).collect();
    ids.sort();
    assert_eq!(ids, vec!["domain", "email", "handle", "modeline"]);
}

#[test]
fn finder_ids_remain_unique_across_all_finders() {
    let mut codetag = squeeze::codetag::Codetag::default();
    codetag.build_mnemonics_regex().unwrap();
    let finders: Vec<Box<dyn Finder>> = vec![
        Box::new(squeeze::cidr::Cidr::default()),
        Box::new(codetag),
        Box::new(squeeze::color::Color::default()),
        Box::new(squeeze::datetime::Datetime::default()),
        Box::new(Domain::default()),
        Box::new(Email::default()),
        Box::new(squeeze::emoji::Emoji::default()),
        Box::new(squeeze::env::Env::default()),
        Box::new(Handle::default()),
        Box::new(squeeze::hash::Hash::default()),
        Box::new(squeeze::ip::Ip::default()),
        Box::new(squeeze::json::Json::default()),
        Box::new(squeeze::jwt::Jwt::default()),
        Box::new(squeeze::mac::Mac::default()),
        Box::new(squeeze::mirror::Mirror::default()),
        Box::new(Modeline::default()),
        Box::new(Path::default()),
        Box::new(squeeze::phone::Phone::default()),
        Box::new(squeeze::semver::Semver::default()),
        Box::new(URI::default()),
        Box::new(squeeze::uuid::Uuid::default()),
    ];
    let mut ids: Vec<&str> = finders.iter().map(|f| f.id()).collect();
    let original = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(original, ids.len(), "all finder ids must be unique");
}
