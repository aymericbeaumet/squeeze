use clap::{Args, CommandFactory, Parser, ValueEnum};
use rayon::{ThreadPool, prelude::*};
use squeeze::{
    Finder,
    cidr::Cidr,
    codetag::Codetag,
    color::Color,
    datetime::Datetime,
    domain::Domain,
    email::Email,
    emoji::Emoji,
    env::Env,
    handle::Handle,
    hash::Hash,
    ip::Ip,
    json::Json,
    jwt::Jwt,
    mac::Mac,
    mirror::Mirror,
    modeline::Modeline,
    path::Path,
    phone::Phone,
    scanner::{Match, Scanner},
    semver::Semver,
    uri::URI,
    uuid::Uuid,
};
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::{
    io::Read,
    process::{Command, Stdio},
};

const VERSION: &str = match option_env!("SQUEEZE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Marker argument that puts the process into clipboard helper mode. It is matched before clap
/// runs, so it never becomes part of the public command line surface.
#[cfg(target_os = "linux")]
const CLIPBOARD_HELPER_ARG: &str = "__squeeze_clipboard_helper";
#[cfg(target_os = "linux")]
const CLIPBOARD_HELPER_READY: &str = "ready";

#[derive(Copy, Clone, Debug, ValueEnum, Default, PartialEq, Eq)]
enum Format {
    #[default]
    Text,
    Json,
    Yaml,
    Csv,
    None,
}

#[derive(Copy, Clone, Debug, ValueEnum, Default, PartialEq, Eq)]
enum Precedence {
    #[default]
    First,
    Longest,
}

#[derive(Parser)]
#[command(
    name = "squeeze",
    version = VERSION,
    author = "Aymeric Beaumet <hi@aymericbeaumet.com>",
    about = "Extract URLs, emails, IPs, hashes, TODOs, and more from any text",
    after_help = "\
Examples:
  echo 'docs at https://example.com' | squeeze --url
  git log | squeeze --email --sort --uniq
  squeeze --todo --fixme --with-location 'src/**/*.rs'
  kubectl logs my-pod | squeeze --ip --uuid --with-kind
  squeeze --all --with-kind --output json notes.md"
)]
struct Opts {
    // flags
    #[arg(short = '1', long = "first", help = "only show the first result")]
    first: bool,
    #[arg(
        long = "last",
        conflicts_with = "first",
        help = "only show the last result"
    )]
    last: bool,
    #[arg(long = "sort", help = "sort results before printing")]
    sort: bool,
    #[arg(long = "uniq", help = "deduplicate results")]
    uniq: bool,
    #[arg(long = "copy", help = "copy the results to the clipboard")]
    copy: bool,
    #[arg(long = "open", help = "open the results with the default application")]
    open: bool,
    #[arg(
        long = "output",
        value_enum,
        default_value_t = Format::Text,
        help = "output format"
    )]
    output: Format,
    #[arg(
        long = "jobs",
        short = 'j',
        default_value_t = 1,
        help = "scan lines in parallel (1 = sequential streaming)"
    )]
    jobs: usize,
    #[arg(
        long = "with-kind",
        help = "include the finder kind (and match position in structured output)"
    )]
    with_kind: bool,
    #[arg(
        long = "with-location",
        help = "include the match position (path:line:column: in text output)"
    )]
    with_location: bool,
    #[arg(long = "no-overlap", help = "suppress overlapping matches")]
    no_overlap: bool,
    #[arg(
        long = "precedence",
        value_enum,
        default_value_t = Precedence::First,
        help = "overlap policy used with --no-overlap"
    )]
    precedence: Precedence,

    #[arg(
        value_name = "INPUT",
        help = "files or glob patterns to scan; omit for stdin"
    )]
    inputs: Vec<String>,

    #[command(flatten)]
    finders: FinderOpts,
}

/// Which finders to run, and their modifiers.
#[derive(Args)]
#[command(next_help_heading = "Finders")]
struct FinderOpts {
    #[arg(long = "all", help = "enable all finders")]
    all: bool,

    // cidr
    #[arg(long = "cidr", help = "search for CIDR notation")]
    cidr: bool,

    // codetag
    #[arg(long = "codetag", require_equals = true, help = "search for codetags")]
    mnemonic: Option<Option<String>>,
    #[arg(long = "hide-mnemonic", help = "hide the mnemonics in the results")]
    hide_mnemonic: bool,
    #[arg(long = "fixme", help = "alias for: --codetag=fixme")]
    fixme: bool,
    #[arg(long = "todo", help = "alias for: --codetag=todo")]
    todo: bool,

    // color
    #[arg(long = "color", help = "search for colors")]
    color: bool,

    // datetime
    #[arg(long = "datetime", help = "search for datetimes")]
    datetime: bool,

    // domain
    #[arg(long = "domain", help = "search for domain names")]
    domain: bool,

    // email
    #[arg(long = "email", help = "search for email addresses")]
    email: bool,

    // emoji
    #[arg(long = "emoji", help = "search for emojis")]
    emoji: bool,

    // env
    #[arg(long = "env", help = "search for environment variables")]
    env: bool,

    // handle
    #[arg(long = "handle", help = "search for @handles")]
    handle: bool,

    // hash
    #[arg(long = "hash", require_equals = true, help = "search for hashes")]
    hash_algo: Option<Option<String>>,
    #[arg(long = "md5", help = "alias for: --hash=md5")]
    md5: bool,
    #[arg(long = "sha1", help = "alias for: --hash=sha1")]
    sha1: bool,
    #[arg(long = "sha256", help = "alias for: --hash=sha256")]
    sha256: bool,
    #[arg(long = "sha512", help = "alias for: --hash=sha512")]
    sha512: bool,

    // ip
    #[arg(long = "ip", help = "search for IP addresses")]
    ip: bool,
    #[arg(long = "ipv4", help = "search for IPv4 addresses")]
    ipv4: bool,
    #[arg(long = "ipv6", help = "search for IPv6 addresses")]
    ipv6: bool,

    // json
    #[arg(long = "json", help = "search for JSON objects and arrays")]
    json: bool,

    // jwt
    #[arg(long = "jwt", help = "search for JSON Web Tokens")]
    jwt: bool,

    // mac
    #[arg(long = "mac", help = "search for MAC addresses")]
    mac: bool,

    // mirror
    #[arg(long = "mirror", hide = true, help = "[debug] mirror the input")]
    mirror: bool,

    // modeline
    #[arg(long = "modeline", help = "search for vim modelines")]
    modeline: bool,

    // path
    #[arg(long = "path", help = "search for file paths")]
    path: bool,

    // phone
    #[arg(long = "phone", help = "search for phone numbers")]
    phone: bool,

    // semver
    #[arg(long = "semver", help = "search for semantic versions")]
    semver: bool,

    // uri
    #[arg(long = "uri", require_equals = true, help = "search for URIs")]
    scheme: Option<Option<String>>,
    #[arg(
        long = "strict",
        help = "match URIs exactly as RFC 3986 allows: any scheme, trailing ' and )"
    )]
    strict: bool,
    #[arg(
        long = "url",
        help = "alias for: --uri=data,ftp,ftps,http,https,mailto,sftp,ws,wss"
    )]
    url: bool,
    #[arg(long = "http", help = "alias for: --uri=http")]
    http: bool,
    #[arg(long = "https", help = "alias for: --uri=https")]
    https: bool,

    // uuid
    #[arg(long = "uuid", help = "search for UUIDs")]
    uuid: bool,
}

impl TryFrom<&FinderOpts> for Cidr {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.cidr) {
            return Err(());
        }
        Ok(Cidr::default())
    }
}

impl TryFrom<&FinderOpts> for Color {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.color) {
            return Err(());
        }
        Ok(Color::default())
    }
}

impl TryFrom<&FinderOpts> for Datetime {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.datetime) {
            return Err(());
        }
        Ok(Datetime::default())
    }
}

impl TryFrom<&FinderOpts> for Domain {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.domain) {
            return Err(());
        }
        Ok(Domain::default())
    }
}

impl TryFrom<&FinderOpts> for Email {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.email) {
            return Err(());
        }
        Ok(Email::default())
    }
}

impl TryFrom<&FinderOpts> for Emoji {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.emoji) {
            return Err(());
        }
        Ok(Emoji::default())
    }
}

impl TryFrom<&FinderOpts> for Env {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.env) {
            return Err(());
        }
        Ok(Env::default())
    }
}

impl TryFrom<&FinderOpts> for Handle {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.handle) {
            return Err(());
        }
        Ok(Handle::default())
    }
}

/// Why a finder could not be built from the command-line options.
enum FinderError {
    /// The finder's flags were not given: simply skip it.
    Disabled,
    /// A flag value is invalid: abort with a usage error.
    Invalid(String),
}

/// Splits a `--flag=a,b` value into its non-empty entries. Empty entries are
/// dropped so `--flag=a,` or `--flag=` never install an empty filter.
fn explicit_entries(value: &Option<Option<String>>) -> Vec<&str> {
    match value {
        Some(Some(list)) => list
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

impl TryFrom<&FinderOpts> for Hash {
    type Error = FinderError;
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all
            || opts.hash_algo.is_some()
            || opts.md5
            || opts.sha1
            || opts.sha256
            || opts.sha512)
        {
            return Err(FinderError::Disabled);
        }
        let mut finder = Hash::default();
        if opts.all {
            return Ok(finder);
        }
        let algorithms = explicit_entries(&opts.hash_algo);
        for algo in &algorithms {
            if !finder.add_algorithm(algo) {
                return Err(FinderError::Invalid(format!(
                    "invalid value '{algo}' for '--hash': expected one of md5, sha1, sha256, sha512"
                )));
            }
        }
        // A bare `--hash` (or an empty `--hash=`) requests every algorithm;
        // alias flags like `--md5` must widen, never narrow, so they only
        // restrict when the bare form is absent.
        if opts.hash_algo.is_some() && algorithms.is_empty() {
            return Ok(finder);
        }
        for (enabled, name) in [
            (opts.md5, "md5"),
            (opts.sha1, "sha1"),
            (opts.sha256, "sha256"),
            (opts.sha512, "sha512"),
        ] {
            if enabled {
                // These names are known-valid, the rejection path cannot hit.
                let _ = finder.add_algorithm(name);
            }
        }
        Ok(finder)
    }
}

impl TryFrom<&FinderOpts> for Ip {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.ip || opts.ipv4 || opts.ipv6) {
            return Err(());
        }
        Ok(Ip {
            ipv4: opts.all || opts.ip || opts.ipv4,
            ipv6: opts.all || opts.ip || opts.ipv6,
        })
    }
}

impl TryFrom<&FinderOpts> for Json {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.json) {
            return Err(());
        }
        Ok(Json::default())
    }
}

impl TryFrom<&FinderOpts> for Jwt {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.jwt) {
            return Err(());
        }
        Ok(Jwt::default())
    }
}

impl TryFrom<&FinderOpts> for Mac {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.mac) {
            return Err(());
        }
        Ok(Mac::default())
    }
}

impl TryFrom<&FinderOpts> for Modeline {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.modeline) {
            return Err(());
        }
        Ok(Modeline::default())
    }
}

impl TryFrom<&FinderOpts> for Codetag {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.mnemonic.is_some() || opts.fixme || opts.todo) {
            return Err(());
        }
        let mut finder = Codetag::default();
        finder.hide_mnemonic = opts.hide_mnemonic;
        // Empty entries are dropped so `--codetag=todo,` does not install an
        // empty mnemonic matching every `word:` line, and `--codetag=` falls
        // back to the default mnemonics like the bare flag.
        for m in explicit_entries(&opts.mnemonic) {
            finder.add_mnemonic(m);
        }
        if opts.fixme {
            finder.add_mnemonic("fixme");
        }
        if opts.todo {
            finder.add_mnemonic("todo");
        }
        finder
            .build_mnemonics_regex()
            .expect("failed to build codetag regex");
        Ok(finder)
    }
}

impl TryFrom<&FinderOpts> for Mirror {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !opts.mirror {
            return Err(());
        }
        Ok(Mirror::default())
    }
}

impl TryFrom<&FinderOpts> for Path {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.path) {
            return Err(());
        }
        Ok(Path::default())
    }
}

impl TryFrom<&FinderOpts> for Phone {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.phone) {
            return Err(());
        }
        Ok(Phone::default())
    }
}

impl TryFrom<&FinderOpts> for Semver {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.semver) {
            return Err(());
        }
        Ok(Semver::default())
    }
}

impl TryFrom<&FinderOpts> for URI {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.scheme.is_some() || opts.url || opts.http || opts.https) {
            return Err(());
        }
        let mut finder = URI::default();
        finder.strict = opts.strict;
        if opts.all {
            return Ok(finder);
        }
        let schemes = explicit_entries(&opts.scheme);
        // A bare `--uri` (or an empty `--uri=`) requests every scheme; alias
        // flags like `--http` must widen, never narrow, so they only restrict
        // when the bare form is absent.
        if opts.scheme.is_some() && schemes.is_empty() {
            return Ok(finder);
        }
        for s in schemes {
            finder.add_scheme(s);
        }
        if opts.url {
            for s in [
                "data", "ftp", "ftps", "http", "https", "mailto", "sftp", "ws", "wss",
            ] {
                finder.add_scheme(s);
            }
        }
        if opts.http {
            finder.add_scheme("http");
        }
        if opts.https {
            finder.add_scheme("https");
        }
        Ok(finder)
    }
}

impl TryFrom<&FinderOpts> for Uuid {
    type Error = ();
    fn try_from(opts: &FinderOpts) -> Result<Self, Self::Error> {
        if !(opts.all || opts.uuid) {
            return Err(());
        }
        Ok(Uuid::default())
    }
}

fn build_finders(opts: &FinderOpts) -> Result<Vec<Box<dyn Finder>>, String> {
    let mut finders: Vec<Box<dyn Finder>> = Vec::new();
    if let Ok(f) = TryInto::<Cidr>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Codetag>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Color>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Datetime>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Domain>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Email>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Emoji>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Env>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Handle>::try_into(opts) {
        finders.push(Box::new(f));
    }
    match TryInto::<Hash>::try_into(opts) {
        Ok(f) => finders.push(Box::new(f)),
        Err(FinderError::Disabled) => {}
        Err(FinderError::Invalid(message)) => return Err(message),
    }
    if let Ok(f) = TryInto::<Ip>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Json>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Jwt>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Mac>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Mirror>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Modeline>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Path>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Phone>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Semver>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<URI>::try_into(opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Uuid>::try_into(opts) {
        finders.push(Box::new(f));
    }
    Ok(finders)
}

/// Whether the requested options require collecting all matches before output.
fn must_buffer(opts: &Opts) -> bool {
    opts.last || opts.sort || opts.uniq || opts.copy || opts.output != Format::Text
}

/// Whether to scan with the parallel batch path. First-only mode must stay
/// sequential: the parallel path blocks until a whole batch of lines has been
/// read before scanning any of them, so `-1 --jobs N` on a slow stream would
/// sit on a match it had already read instead of printing it and exiting.
fn use_parallel(opts: &Opts) -> bool {
    opts.jobs > 1 && !opts.first
}

/// A closed downstream reader (`squeeze ... | head -1`) is a normal way for a
/// pipeline to end: finish silently and successfully, like grep does.
fn is_broken_pipe(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::BrokenPipe
}

#[derive(Clone, Debug)]
struct ResultItem {
    kind: &'static str,
    value: String,
    source: Option<String>,
    line: usize,
    column: usize,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug)]
struct LineRecord {
    source: Option<String>,
    line: usize,
    text: String,
}

#[derive(Debug)]
enum InputTarget {
    Stdin,
    File(PathBuf),
}

struct OutputState {
    buffer: Option<Vec<ResultItem>>,
    last_match: Option<ResultItem>,
    /// Whether to flush after every streamed result: enabled when stdout is a
    /// terminal so matches appear as they are found; piped output stays fully
    /// buffered (grep behavior).
    flush_streaming: bool,
}

impl OutputState {
    fn new(opts: &Opts) -> Self {
        let buffer = if must_buffer(opts) && !opts.last {
            Some(Vec::new())
        } else {
            None
        };
        OutputState {
            buffer,
            last_match: None,
            flush_streaming: !must_buffer(opts) && io::stdout().is_terminal(),
        }
    }
}

/// Optional fields printed alongside each result value.
#[derive(Clone, Copy, Debug, Default)]
struct Detail {
    kind: bool,
    location: bool,
}

impl Detail {
    fn new(opts: &Opts) -> Self {
        Detail {
            kind: opts.with_kind,
            location: opts.with_location,
        }
    }

    /// Structured formats emit the full match metadata once any detail is
    /// requested.
    fn structured(self) -> bool {
        self.kind || self.location
    }
}

/// Where a result was found, printed grep-style as `path:line:column:`.
struct Location<'a> {
    source: Option<&'a str>,
    line: usize,
    column: usize,
}

impl<'a> Location<'a> {
    fn of(result: &'a ResultItem) -> Self {
        Location {
            source: result.source.as_deref(),
            line: result.line,
            column: result.column,
        }
    }
}

fn write_formatted<W: Write>(
    out: &mut W,
    results: &[ResultItem],
    format: Format,
    detail: Detail,
) -> io::Result<()> {
    let with_kind = detail.structured();
    match format {
        Format::None => {}
        Format::Text => {
            for r in results {
                let location = detail.location.then(|| Location::of(r));
                let kind = detail.kind.then_some(r.kind);
                write_text_line(out, location.as_ref(), kind, &r.value)?;
            }
        }
        Format::Json => {
            out.write_all(b"[")?;
            for (i, r) in results.iter().enumerate() {
                if i > 0 {
                    out.write_all(b",")?;
                }
                if with_kind {
                    write_json_result(out, r)?;
                } else {
                    write_json_string(out, &r.value)?;
                }
            }
            out.write_all(b"]\n")?;
        }
        Format::Yaml => {
            for r in results {
                if with_kind {
                    write_yaml_result(out, r)?;
                } else {
                    write!(out, "- ")?;
                    write_yaml_scalar(out, &r.value)?;
                    writeln!(out)?;
                }
            }
        }
        Format::Csv => {
            if with_kind {
                out.write_all(b"kind,value,line,column,start,end,source\n")?;
            }
            for r in results {
                if with_kind {
                    write_csv_result(out, r)?;
                } else {
                    write_csv_field(out, &r.value)?;
                    writeln!(out)?;
                }
            }
        }
    }
    Ok(())
}

fn write_text_line<W: Write + ?Sized>(
    out: &mut W,
    location: Option<&Location>,
    kind: Option<&str>,
    value: &str,
) -> io::Result<()> {
    if let Some(location) = location {
        if let Some(source) = location.source {
            write!(out, "{source}:")?;
        }
        write!(out, "{}:{}:", location.line, location.column)?;
    }
    if let Some(kind) = kind {
        write!(out, "{kind}\t")?;
    }
    writeln!(out, "{value}")
}

fn write_json_string<W: Write>(out: &mut W, s: &str) -> io::Result<()> {
    out.write_all(b"\"")?;
    for c in s.chars() {
        match c {
            '"' => out.write_all(b"\\\"")?,
            '\\' => out.write_all(b"\\\\")?,
            '\n' => out.write_all(b"\\n")?,
            '\r' => out.write_all(b"\\r")?,
            '\t' => out.write_all(b"\\t")?,
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32)?,
            c => {
                let mut buf = [0u8; 4];
                out.write_all(c.encode_utf8(&mut buf).as_bytes())?;
            }
        }
    }
    out.write_all(b"\"")?;
    Ok(())
}

fn write_yaml_scalar<W: Write>(out: &mut W, s: &str) -> io::Result<()> {
    let needs_quoting = s.is_empty()
        || s.contains(['\n', '"', '\'', ':', '#', '\\'])
        || s.starts_with([' ', '-', '?', '!', '&', '*', '|', '>'])
        || s.ends_with(' ');
    if needs_quoting {
        write_json_string(out, s)
    } else {
        out.write_all(s.as_bytes())
    }
}

fn write_json_result<W: Write>(out: &mut W, result: &ResultItem) -> io::Result<()> {
    out.write_all(b"{\"kind\":")?;
    write_json_string(out, result.kind)?;
    out.write_all(b",\"value\":")?;
    write_json_string(out, &result.value)?;
    write!(out, ",\"line\":{}", result.line)?;
    write!(out, ",\"column\":{}", result.column)?;
    write!(out, ",\"start\":{}", result.start)?;
    write!(out, ",\"end\":{}", result.end)?;
    out.write_all(b",\"source\":")?;
    if let Some(source) = &result.source {
        write_json_string(out, source)?;
    } else {
        out.write_all(b"null")?;
    }
    out.write_all(b"}")?;
    Ok(())
}

fn write_yaml_result<W: Write>(out: &mut W, result: &ResultItem) -> io::Result<()> {
    out.write_all(b"- kind: ")?;
    write_yaml_scalar(out, result.kind)?;
    out.write_all(b"\n  value: ")?;
    write_yaml_scalar(out, &result.value)?;
    writeln!(out, "\n  line: {}", result.line)?;
    writeln!(out, "  column: {}", result.column)?;
    writeln!(out, "  start: {}", result.start)?;
    writeln!(out, "  end: {}", result.end)?;
    out.write_all(b"  source: ")?;
    if let Some(source) = &result.source {
        write_yaml_scalar(out, source)?;
    } else {
        out.write_all(b"null")?;
    }
    writeln!(out)?;
    Ok(())
}

fn write_csv_result<W: Write>(out: &mut W, result: &ResultItem) -> io::Result<()> {
    write_csv_field(out, result.kind)?;
    out.write_all(b",")?;
    write_csv_field(out, &result.value)?;
    write!(
        out,
        ",{},{},{},{}",
        result.line, result.column, result.start, result.end
    )?;
    out.write_all(b",")?;
    if let Some(source) = &result.source {
        write_csv_field(out, source)?;
    }
    writeln!(out)?;
    Ok(())
}

fn write_csv_field<W: Write>(out: &mut W, s: &str) -> io::Result<()> {
    let needs_quoting = s.contains([',', '"', '\n', '\r']);
    if needs_quoting {
        out.write_all(b"\"")?;
        for c in s.chars() {
            if c == '"' {
                out.write_all(b"\"\"")?;
            } else {
                let mut buf = [0u8; 4];
                out.write_all(c.encode_utf8(&mut buf).as_bytes())?;
            }
        }
        out.write_all(b"\"")?;
    } else {
        out.write_all(s.as_bytes())?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(text).map_err(|e| e.to_string())?;
    Ok(())
}

// X11 and Wayland have no clipboard storage of their own: the contents live inside whichever
// process owns the selection, and vanish the moment it exits. Hand the text to a copy of this
// binary that stays alive answering paste requests, so the interactive command can return.
#[cfg(target_os = "linux")]
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|e| format!("failed to locate squeeze: {e}"))?;
    let mut helper = Command::new(executable)
        .arg(CLIPBOARD_HELPER_ARG)
        // Redirecting stdout serves double duty: it is the channel the helper reports its status
        // on, and it stops the helper from holding the caller's pipe open once we exit, which
        // would otherwise hang `$(squeeze --copy)` for as long as the clipboard lives.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .current_dir("/")
        .spawn()
        .map_err(|e| format!("failed to start clipboard helper: {e}"))?;

    // The helper reads to EOF before it replies, so sending the whole payload first cannot
    // deadlock on a full pipe.
    let mut stdin = helper.stdin.take().expect("stdin is piped");
    stdin
        .write_all(text.as_bytes())
        .map_err(|e| format!("failed to send clipboard contents to helper: {e}"))?;
    drop(stdin);

    let stdout = helper.stdout.take().expect("stdout is piped");
    let mut status = String::new();
    BufReader::new(stdout)
        .read_line(&mut status)
        .map_err(|e| format!("failed to read clipboard helper status: {e}"))?;

    match status.trim_end() {
        CLIPBOARD_HELPER_READY => Ok(()),
        "" => Err("clipboard helper exited before taking ownership".to_string()),
        error => Err(error.to_string()),
    }
}

// Runs in the helper process: takes the payload from stdin, then keeps serving it until another
// application replaces the clipboard contents. Anything written to stdout here is the status the
// invoking process reports back to the user.
#[cfg(target_os = "linux")]
fn run_clipboard_helper() -> Result<(), String> {
    use arboard::SetExtLinux;

    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| format!("failed to read clipboard contents: {e}"))?;

    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    // Claim the selection first so `--copy` only reports success once the contents are really
    // ours, then re-assert and block, which is what keeps this process around to serve pastes.
    clipboard
        .set_text(text.as_str())
        .map_err(|e| e.to_string())?;

    println!("{CLIPBOARD_HELPER_READY}");
    io::stdout()
        .flush()
        .map_err(|e| format!("failed to report clipboard readiness: {e}"))?;

    clipboard.set().wait().text(text).map_err(|e| e.to_string())
}

fn clipboard_format(output_format: Format) -> Format {
    if output_format == Format::None {
        Format::Text
    } else {
        output_format
    }
}

fn byte_column(line: &str, byte_pos: usize) -> usize {
    line[..byte_pos].chars().count() + 1
}

/// Only locations and structured formats print the column, so the char-count
/// walk over the line prefix in [`byte_column`] is skipped everywhere else.
fn output_needs_column(opts: &Opts) -> bool {
    let needs = |format| match format {
        Format::Text => opts.with_location,
        Format::Json | Format::Yaml | Format::Csv => Detail::new(opts).structured(),
        Format::None => false,
    };
    needs(opts.output) || (opts.copy && needs(clipboard_format(opts.output)))
}

fn apply_overlap_policy(matches: &mut Vec<Match>, precedence: Precedence) {
    if matches.len() < 2 {
        return;
    }

    match precedence {
        Precedence::First => {
            let mut end = 0;
            matches.retain(|m| {
                if m.range.start >= end {
                    end = m.range.end;
                    true
                } else {
                    false
                }
            });
        }
        Precedence::Longest => {
            let original = std::mem::take(matches);
            let mut filtered = Vec::new();
            let mut i = 0;
            while i < original.len() {
                let mut cluster_end = original[i].range.end;
                let mut best = i;
                let mut j = i + 1;
                while j < original.len() && original[j].range.start < cluster_end {
                    cluster_end = cluster_end.max(original[j].range.end);
                    let best_len = original[best].range.end - original[best].range.start;
                    let candidate_len = original[j].range.end - original[j].range.start;
                    if candidate_len > best_len
                        || (candidate_len == best_len
                            && original[j].finder_index < original[best].finder_index)
                    {
                        best = j;
                    }
                    j += 1;
                }
                filtered.push(original[best].clone());
                i = j;
            }
            filtered.sort_unstable_by(|a, b| {
                a.range
                    .start
                    .cmp(&b.range.start)
                    .then(a.finder_index.cmp(&b.finder_index))
            });
            *matches = filtered;
        }
    }
}

/// Scans one line, leaving the matches (with the overlap policy applied) in
/// `matches`. The buffer is reused across lines to avoid per-line allocations.
fn scan_line_matches_into(scanner: &Scanner, opts: &Opts, line: &str, matches: &mut Vec<Match>) {
    if opts.first {
        matches.clear();
        if let Some(m) = scanner.scan_line_first(line) {
            matches.push(m);
        }
    } else {
        scanner.scan_line_into(line, matches);
    }

    if opts.no_overlap {
        apply_overlap_policy(matches, opts.precedence);
    }
}

fn make_result_item(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    line_number: usize,
    line: &str,
    m: &Match,
) -> Option<ResultItem> {
    let value = &line[m.range.clone()];
    if value.is_empty() {
        return None;
    }
    Some(ResultItem {
        kind: scanner.finders()[m.finder_index].id(),
        value: value.to_string(),
        source: source.map(ToOwned::to_owned),
        line: line_number,
        column: if output_needs_column(opts) {
            byte_column(line, m.range.start)
        } else {
            0
        },
        start: m.range.start,
        end: m.range.end,
    })
}

fn collect_line_matches(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    line_number: usize,
    line: &str,
    scratch: &mut Vec<Match>,
) -> Vec<ResultItem> {
    scan_line_matches_into(scanner, opts, line, scratch);
    scratch
        .iter()
        .filter_map(|m| make_result_item(scanner, opts, source, line_number, line, m))
        .collect()
}

fn emit_streaming_value(
    out: &mut dyn Write,
    opts: &Opts,
    flush: bool,
    location: Option<&Location>,
    kind: &str,
    value: &str,
) -> io::Result<()> {
    write_text_line(out, location, opts.with_kind.then_some(kind), value)?;
    if flush {
        out.flush()?;
    }
    if opts.open {
        open_url(value)?;
    }
    Ok(())
}

fn handle_result(
    out: &mut dyn Write,
    opts: &Opts,
    state: &mut OutputState,
    result: ResultItem,
) -> io::Result<bool> {
    if opts.last {
        state.last_match = Some(result);
        return Ok(false);
    }

    if let Some(buffer) = state.buffer.as_mut() {
        buffer.push(result);
    } else {
        let location = opts.with_location.then(|| Location::of(&result));
        emit_streaming_value(
            out,
            opts,
            state.flush_streaming,
            location.as_ref(),
            result.kind,
            &result.value,
        )?;
    }

    Ok(opts.first)
}

/// Strips the line terminator (`\n`, `\r\n`, and any extra `\r`s) from a raw
/// line, mirroring the previous `trim_end_matches('\n')`/`('\r')` behavior.
fn trim_line_ending(mut line: &[u8]) -> &[u8] {
    if let [rest @ .., b'\n'] = line {
        line = rest;
    }
    while let [rest @ .., b'\r'] = line {
        line = rest;
    }
    line
}

fn scan_lines_sequential(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    reader: &mut dyn BufRead,
    out: &mut dyn Write,
    state: &mut OutputState,
) -> io::Result<bool> {
    let mut raw_line = Vec::new();
    let mut matches: Vec<Match> = Vec::new();
    let mut line_number = 0;
    // In the plain streaming text path the match value is written straight
    // from the line slice, without allocating a ResultItem per match.
    let streaming = !must_buffer(opts);

    loop {
        raw_line.clear();
        if reader.read_until(b'\n', &mut raw_line)? == 0 {
            break;
        }
        line_number += 1;
        // Lines are read as bytes and converted lossily so invalid UTF-8
        // cannot abort the scan (grep behavior): the U+FFFD replacement
        // characters are non-ASCII and match nothing, and every other line
        // keeps being scanned. `from_utf8_lossy` borrows when the line is
        // valid UTF-8, so the common case does not allocate.
        let line = String::from_utf8_lossy(trim_line_ending(&raw_line));
        scan_line_matches_into(scanner, opts, &line, &mut matches);
        for m in &matches {
            let value = &line[m.range.clone()];
            if value.is_empty() {
                continue;
            }
            if streaming {
                let kind = scanner.finders()[m.finder_index].id();
                let location = opts.with_location.then(|| Location {
                    source,
                    line: line_number,
                    column: byte_column(&line, m.range.start),
                });
                emit_streaming_value(
                    out,
                    opts,
                    state.flush_streaming,
                    location.as_ref(),
                    kind,
                    value,
                )?;
                if opts.first {
                    return Ok(true);
                }
            } else if let Some(result) =
                make_result_item(scanner, opts, source, line_number, &line, m)
                && handle_result(out, opts, state, result)?
            {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

const PARALLEL_BATCH_LINES: usize = 4096;

fn scan_lines_parallel(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    reader: &mut dyn BufRead,
    out: &mut dyn Write,
    state: &mut OutputState,
    pool: &ThreadPool,
) -> io::Result<bool> {
    let mut raw_line = Vec::new();
    let mut line_number = 0;

    loop {
        let mut batch = Vec::with_capacity(PARALLEL_BATCH_LINES);
        for _ in 0..PARALLEL_BATCH_LINES {
            raw_line.clear();
            if reader.read_until(b'\n', &mut raw_line)? == 0 {
                break;
            }
            line_number += 1;
            batch.push(LineRecord {
                source: source.map(ToOwned::to_owned),
                line: line_number,
                // Lossy conversion mirrors the sequential path: invalid
                // UTF-8 must not abort the scan.
                text: String::from_utf8_lossy(trim_line_ending(&raw_line)).into_owned(),
            });
        }

        if batch.is_empty() {
            break;
        }

        let batch_results: Vec<Vec<ResultItem>> = pool.install(|| {
            batch
                .par_iter()
                .map_init(Vec::new, |scratch, record| {
                    collect_line_matches(
                        scanner,
                        opts,
                        record.source.as_deref(),
                        record.line,
                        &record.text,
                        scratch,
                    )
                })
                .collect()
        });

        for line_results in batch_results {
            for result in line_results {
                if handle_result(out, opts, state, result)? {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn has_glob_magic(input: &str) -> bool {
    input.contains('*') || input.contains('?') || input.contains('[')
}

fn expand_inputs(inputs: &[String]) -> Result<Vec<InputTarget>, String> {
    if inputs.is_empty() {
        return Ok(vec![InputTarget::Stdin]);
    }

    let mut targets = Vec::new();
    for input in inputs {
        if input == "-" {
            targets.push(InputTarget::Stdin);
            continue;
        }

        if has_glob_magic(input) {
            let mut matched = false;
            for entry in glob::glob(input).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?;
                if path.is_file() {
                    matched = true;
                    targets.push(InputTarget::File(path));
                }
            }
            if !matched {
                return Err(format!("no files matched pattern '{}'", input));
            }
        } else {
            targets.push(InputTarget::File(PathBuf::from(input)));
        }
    }

    Ok(targets)
}

fn scan_reader(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    reader: &mut dyn BufRead,
    out: &mut dyn Write,
    state: &mut OutputState,
    pool: Option<&ThreadPool>,
) -> io::Result<bool> {
    if let Some(pool) = pool {
        scan_lines_parallel(scanner, opts, source, reader, out, state, pool)
    } else {
        scan_lines_sequential(scanner, opts, source, reader, out, state)
    }
}

fn finalize_results(
    out: &mut dyn Write,
    opts: &Opts,
    mut results: Vec<ResultItem>,
) -> io::Result<()> {
    if opts.sort {
        results.sort_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then(a.kind.cmp(b.kind))
                .then(a.source.cmp(&b.source))
                .then(a.line.cmp(&b.line))
                .then(a.start.cmp(&b.start))
        });
    }
    if opts.uniq {
        let mut seen = HashSet::new();
        results.retain(|r| seen.insert(r.value.clone()));
    }

    let mut formatted = Vec::new();
    write_formatted(&mut formatted, &results, opts.output, Detail::new(opts))?;
    // Print before copying: on Linux the copy waits for a display server round-trip, and a
    // clipboard that is unavailable should not cost the user their results.
    out.write_all(&formatted)?;

    if opts.copy {
        let mut clipboard = Vec::new();
        write_formatted(
            &mut clipboard,
            &results,
            clipboard_format(opts.output),
            Detail::new(opts),
        )?;
        let text = String::from_utf8_lossy(&clipboard);
        copy_to_clipboard(&text).map_err(io::Error::other)?;
    }

    if opts.open {
        for r in &results {
            open_url(&r.value)?;
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    // Checked ahead of clap so the marker stays invisible to the argument parser.
    #[cfg(target_os = "linux")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == CLIPBOARD_HELPER_ARG)
    {
        return match run_clipboard_helper() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                println!("{e}");
                ExitCode::FAILURE
            }
        };
    }

    env_logger::init();

    let opts = Opts::parse();

    // Validated before the empty-finders check so `--jobs 0` reports its own
    // error even when no finder flags are given.
    if opts.jobs == 0 {
        eprintln!("--jobs must be >= 1");
        return ExitCode::FAILURE;
    }

    let finders = match build_finders(&opts.finders) {
        Ok(finders) => finders,
        Err(message) => {
            // Same path clap takes for its own invalid values: usage error on
            // stderr, exit code 2.
            let mut cmd = Opts::command();
            cmd.error(clap::error::ErrorKind::InvalidValue, message)
                .exit()
        }
    };

    if finders.is_empty() {
        let mut cmd = Opts::command();
        cmd.error(
            clap::error::ErrorKind::MissingRequiredArgument,
            "no finder selected; pass one such as --url or --email, or --all to enable every finder",
        )
        .exit()
    }

    let scanner = match Scanner::try_new(finders) {
        Ok(scanner) => scanner,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };
    let targets = match expand_inputs(&opts.inputs) {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };

    let pool = if use_parallel(&opts) {
        match rayon::ThreadPoolBuilder::new()
            .num_threads(opts.jobs)
            .build()
        {
            Ok(pool) => Some(pool),
            Err(e) => {
                eprintln!("failed to build thread pool: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let stdout = io::stdout().lock();
    let mut out = BufWriter::new(stdout);
    let mut state = OutputState::new(&opts);

    for target in targets {
        let result = match target {
            InputTarget::Stdin => {
                let stdin = io::stdin();
                let mut reader = stdin.lock();
                scan_reader(
                    &scanner,
                    &opts,
                    None,
                    &mut reader,
                    &mut out,
                    &mut state,
                    pool.as_ref(),
                )
            }
            InputTarget::File(path) => {
                let source = path.display().to_string();
                let file = match File::open(&path) {
                    Ok(file) => file,
                    Err(e) => {
                        eprintln!("failed to open '{}': {}", source, e);
                        return ExitCode::FAILURE;
                    }
                };
                let mut reader = BufReader::new(file);
                scan_reader(
                    &scanner,
                    &opts,
                    Some(&source),
                    &mut reader,
                    &mut out,
                    &mut state,
                    pool.as_ref(),
                )
            }
        };

        match result {
            Ok(true) => {
                break;
            }
            Ok(false) => {}
            Err(e) if is_broken_pipe(&e) => {
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("error during scanning: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    let buffered_results = if opts.last {
        state.last_match.into_iter().collect()
    } else {
        state.buffer.take().unwrap_or_default()
    };

    if (opts.last || must_buffer(&opts))
        && let Err(e) = finalize_results(&mut out, &opts, buffered_results)
    {
        if is_broken_pipe(&e) {
            return ExitCode::SUCCESS;
        }
        eprintln!("output failed: {}", e);
        return ExitCode::FAILURE;
    }

    match out.flush() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if is_broken_pipe(&e) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("output failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn open_url(url: &str) -> io::Result<()> {
    open::that(url).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(value: &str) -> ResultItem {
        ResultItem {
            kind: "env",
            value: value.to_string(),
            source: None,
            line: 1,
            column: 1,
            start: 0,
            end: value.len(),
        }
    }

    #[test]
    fn clipboard_format_should_use_text_when_stdout_is_suppressed() {
        let results = vec![result("$A")];
        let mut stdout = Vec::new();
        let mut clipboard = Vec::new();

        write_formatted(&mut stdout, &results, Format::None, Detail::default()).unwrap();
        write_formatted(
            &mut clipboard,
            &results,
            clipboard_format(Format::None),
            Detail::default(),
        )
        .unwrap();

        assert_eq!(stdout, b"");
        assert_eq!(clipboard, b"$A\n");
    }

    #[test]
    fn first_mode_should_force_the_sequential_path() {
        // The parallel path blocks filling a whole batch before scanning, so
        // -1 has to dispatch to the sequential streaming path.
        let opts = Opts::try_parse_from(["squeeze", "--url", "--jobs", "4", "--first"]).unwrap();
        assert!(!use_parallel(&opts));

        let opts = Opts::try_parse_from(["squeeze", "--url", "--jobs", "4"]).unwrap();
        assert!(use_parallel(&opts));

        let opts = Opts::try_parse_from(["squeeze", "--url"]).unwrap();
        assert!(!use_parallel(&opts));
    }

    #[test]
    fn buffered_output_should_never_flush_per_result() {
        let opts = Opts::try_parse_from(["squeeze", "--env", "--sort"]).unwrap();
        let state = OutputState::new(&opts);
        assert!(!state.flush_streaming);
    }

    #[test]
    fn broken_pipe_errors_should_be_recognized() {
        assert!(is_broken_pipe(&io::Error::from(io::ErrorKind::BrokenPipe)));
        assert!(!is_broken_pipe(&io::Error::other("boom")));
    }

    #[test]
    fn hash_options_should_reject_unknown_algorithms() {
        let opts = Opts::try_parse_from(["squeeze", "--hash=md5,bogus"]).unwrap();
        match TryInto::<Hash>::try_into(&opts.finders) {
            Err(FinderError::Invalid(message)) => assert!(message.contains("bogus")),
            _ => panic!("expected an invalid-value error"),
        }
    }

    #[test]
    fn bare_hash_with_alias_should_stay_unrestricted() {
        let opts = Opts::try_parse_from(["squeeze", "--hash", "--md5"]).unwrap();
        let Ok(finder) = TryInto::<Hash>::try_into(&opts.finders) else {
            panic!("expected the hash finder to be built");
        };
        // sha1 still matches: the bare --hash means every algorithm.
        assert!(
            finder
                .find("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
                .is_some()
        );
    }
}
