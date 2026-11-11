use clap::{Args, CommandFactory, Parser, ValueEnum};
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
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
#[cfg(target_os = "linux")]
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

mod args;
mod error;

use error::{EXIT_ERROR, EXIT_NOT_FOUND, Error};

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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

#[derive(Copy, Clone, Debug, ValueEnum, Default, PartialEq, Eq)]
enum ColorWhen {
    #[default]
    Auto,
    Always,
    Never,
}

/// Which results `--open` opens: URIs with a scheme from `--url`, URIs with
/// any scheme, or file paths. Variants stay undocumented so clap keeps the
/// one-line help.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum OpenKind {
    Url,
    Uri,
    Path,
}

/// How text lines look: the kind column's width (0 separates it with a tab)
/// and whether kinds and locations are colored.
#[derive(Clone, Copy, Debug, Default)]
struct TextStyle {
    kind_width: usize,
    color: bool,
}

#[derive(Parser)]
#[command(
    name = "squeeze",
    version = VERSION,
    author = "Aymeric Beaumet <hi@aymericbeaumet.com>",
    about = "Extract URLs, emails, IPs, hashes, TODOs, and more from any text",
    after_help = "\
Without a finder, every finder runs and prints plain values.

Examples:
  squeeze notes.md
  echo 'docs at https://example.com' | squeeze --url
  git log | squeeze --email --sort --uniq
  squeeze --todo --fixme --with-location .
  squeeze --todo --fixme --with-location 'src/**/*.rs'
  kubectl logs my-pod | squeeze --ip --uuid --with-kind
  squeeze --all --with-kind --output json notes.md",
    disable_help_flag = true,
    disable_version_flag = true
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
    #[arg(
        long = "open",
        value_name = "KINDS",
        value_enum,
        num_args = 0..=1,
        require_equals = true,
        value_delimiter = ',',
        default_missing_value = "url",
        help = "open the results with the default application, only URLs unless KINDS are given"
    )]
    open: Vec<OpenKind>,
    #[arg(long = "exit-code", help = "exit with status 1 when nothing was found")]
    exit_code: bool,
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
        default_value = "auto",
        value_parser = parse_jobs,
        help = "scanning threads, or auto for every core on directories, stdin, and files of 8 MiB or more"
    )]
    jobs: Jobs,
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
        help = "which of overlapping matches to keep, first by default (implies --no-overlap)"
    )]
    precedence: Option<Precedence>,
    #[arg(
        long = "color",
        value_name = "WHEN",
        value_enum,
        default_value_t = ColorWhen::Auto,
        help = "color kinds and locations; auto colors a terminal"
    )]
    color: ColorWhen,

    #[arg(
        long = "hidden",
        help = "search hidden files and directories when walking a directory"
    )]
    hidden: bool,
    #[arg(
        long = "no-ignore",
        help = "do not respect .gitignore, .ignore and git exclude rules when walking a directory"
    )]
    no_ignore: bool,
    #[arg(
        long = "follow",
        help = "follow symbolic links when walking a directory"
    )]
    follow: bool,
    #[arg(
        long = "completions",
        value_name = "SHELL",
        help = "print the completion script for SHELL and exit"
    )]
    completions: Option<clap_complete::Shell>,
    #[arg(short = 'h', long = "help", action = clap::ArgAction::Help, help = "print help")]
    help: Option<bool>,
    #[arg(short = 'V', long = "version", action = clap::ArgAction::Version, help = "print the version")]
    version: Option<bool>,
    /// Resolved from `--color`, `--output` and the terminal after parsing.
    #[arg(skip)]
    text_style: TextStyle,

    #[arg(
        value_name = "PATH",
        help = "files, directories (walked like ripgrep, skipping hidden, ignored, and binary files), or glob patterns; none or - reads stdin"
    )]
    inputs: Vec<String>,

    #[command(flatten)]
    finders: FinderOpts,
}

/// Which finders to run, and their modifiers.
#[derive(Args)]
#[command(next_help_heading = "Finders")]
struct FinderOpts {
    #[arg(
        long = "all",
        help = "enable all finders (the default when none is given)"
    )]
    all: bool,

    // cidr
    #[arg(long = "cidr", help = "search for CIDR notation")]
    cidr: bool,

    // codetag
    #[arg(
        long = "codetag",
        value_name = "MNEMONICS",
        require_equals = true,
        help = "search for codetags, or only the given PEP 350 mnemonics (todo, fixme, ...)"
    )]
    mnemonic: Option<Option<String>>,
    #[arg(long = "hide-mnemonic", help = "print codetags without their mnemonic")]
    hide_mnemonic: bool,
    #[arg(long = "fixme", help = "alias for: --codetag=fixme")]
    fixme: bool,
    #[arg(long = "todo", help = "alias for: --codetag=todo")]
    todo: bool,

    // color
    #[arg(long = "css-color", help = "search for CSS colors")]
    css_color: bool,

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
    #[arg(
        long = "hash",
        value_name = "ALGORITHMS",
        require_equals = true,
        help = "search for hashes, or only md5, sha1, sha256, or sha512 ones"
    )]
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
    #[arg(
        long = "uri",
        value_name = "SCHEMES",
        require_equals = true,
        help = "search for URIs, or only those with the given schemes"
    )]
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

/// The finders the options select, in a fixed order; none when no finder
/// flag is given.
fn build_finders(opts: &FinderOpts) -> Result<Vec<Box<dyn Finder>>, squeeze::Error> {
    let all = opts.all;
    let mut finders: Vec<Box<dyn Finder>> = Vec::new();
    if all || opts.cidr {
        finders.push(Box::new(Cidr::default()));
    }
    if all || opts.mnemonic.is_some() || opts.fixme || opts.todo {
        finders.push(Box::new(codetag_finder(opts)?));
    }
    if all || opts.css_color {
        finders.push(Box::new(Color::default()));
    }
    if all || opts.datetime {
        finders.push(Box::new(Datetime::default()));
    }
    if all || opts.domain {
        finders.push(Box::new(Domain::default()));
    }
    if all || opts.email {
        finders.push(Box::new(Email::default()));
    }
    if all || opts.emoji {
        finders.push(Box::new(Emoji::default()));
    }
    if all || opts.env {
        finders.push(Box::new(Env::default()));
    }
    if all || opts.handle {
        finders.push(Box::new(Handle::default()));
    }
    if all || opts.hash_algo.is_some() || opts.md5 || opts.sha1 || opts.sha256 || opts.sha512 {
        finders.push(Box::new(hash_finder(opts)?));
    }
    if all || opts.ip || opts.ipv4 || opts.ipv6 {
        finders.push(Box::new(Ip {
            ipv4: all || opts.ip || opts.ipv4,
            ipv6: all || opts.ip || opts.ipv6,
        }));
    }
    if all || opts.json {
        finders.push(Box::new(Json::default()));
    }
    if all || opts.jwt {
        finders.push(Box::new(Jwt::default()));
    }
    if all || opts.mac {
        finders.push(Box::new(Mac::default()));
    }
    if opts.mirror {
        finders.push(Box::new(Mirror::default()));
    }
    if all || opts.modeline {
        finders.push(Box::new(Modeline::default()));
    }
    if all || opts.path {
        finders.push(Box::new(Path::default()));
    }
    if all || opts.phone {
        finders.push(Box::new(Phone::default()));
    }
    if all || opts.semver {
        finders.push(Box::new(Semver::default()));
    }
    if all || opts.scheme.is_some() || opts.url || opts.http || opts.https {
        finders.push(Box::new(uri_finder(opts)?));
    }
    if all || opts.uuid {
        finders.push(Box::new(Uuid::default()));
    }
    Ok(finders)
}

fn codetag_finder(opts: &FinderOpts) -> Result<Codetag, squeeze::Error> {
    let mut finder = Codetag::default();
    finder.hide_mnemonic = opts.hide_mnemonic;
    for m in explicit_entries(&opts.mnemonic) {
        finder.add_mnemonic(m)?;
    }
    if opts.fixme {
        finder.add_mnemonic("fixme")?;
    }
    if opts.todo {
        finder.add_mnemonic("todo")?;
    }
    Ok(finder)
}

fn hash_finder(opts: &FinderOpts) -> Result<Hash, squeeze::Error> {
    let mut finder = Hash::default();
    if opts.all {
        return Ok(finder);
    }
    let algorithms = explicit_entries(&opts.hash_algo);
    for algorithm in &algorithms {
        finder.add_algorithm(algorithm)?;
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
            finder.add_algorithm(name)?;
        }
    }
    Ok(finder)
}

fn uri_finder(opts: &FinderOpts) -> Result<URI, squeeze::Error> {
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
    for scheme in schemes {
        finder.add_scheme(scheme)?;
    }
    if opts.url {
        for scheme in URI::URL_SCHEMES {
            finder.add_scheme(scheme)?;
        }
    }
    if opts.http {
        finder.add_scheme("http")?;
    }
    if opts.https {
        finder.add_scheme("https")?;
    }
    Ok(finder)
}

/// Whether the requested options require collecting all matches before output.
fn must_buffer(opts: &Opts) -> bool {
    opts.last || opts.sort || opts.uniq || opts.copy || opts.output != Format::Text
}

impl Opts {
    fn opens(&self) -> bool {
        !self.open.is_empty()
    }

    fn no_overlap(&self) -> bool {
        self.no_overlap || self.precedence.is_some()
    }

    fn precedence(&self) -> Precedence {
        self.precedence.unwrap_or_default()
    }
}

/// Set once any result is found, by whichever thread finds it.
static FOUND: AtomicBool = AtomicBool::new(false);
/// Results `--open` opened, and results it left alone because of their kind.
static OPENED: AtomicBool = AtomicBool::new(false);
static NOT_OPENED: AtomicBool = AtomicBool::new(false);

/// Records a result for `--exit-code`. Loading first keeps the parallel
/// workers from contending on the flag's cache line once it is set.
fn record_found() {
    if !FOUND.load(Ordering::Relaxed) {
        FOUND.store(true, Ordering::Relaxed);
    }
}

/// Whether `--open` opens a result of finder `kind`.
fn opens_kind(kinds: &[OpenKind], kind: &str, value: &str) -> bool {
    kinds.iter().any(|open| match open {
        OpenKind::Url => {
            kind == "uri"
                && value.split_once(':').is_some_and(|(scheme, _)| {
                    URI::URL_SCHEMES
                        .iter()
                        .any(|url| url.eq_ignore_ascii_case(scheme))
                })
        }
        OpenKind::Uri => kind == "uri",
        OpenKind::Path => kind == "path",
    })
}

/// Opens a result with the default application when `--open` covers its
/// kind.
fn open_result(opts: &Opts, kind: &str, value: &str) -> Result<(), Error> {
    if !opens_kind(&opts.open, kind, value) {
        NOT_OPENED.store(true, Ordering::Relaxed);
        return Ok(());
    }
    OPENED.store(true, Ordering::Relaxed);
    open::that(value).map_err(|error| Error::Open {
        value: value.to_string(),
        error,
    })
}

/// The error behind a failed scan: an [`Error`] raised inside the scan
/// functions, which carry it in an `io::Error`, or the I/O error itself,
/// blamed on the input `source` or, without one, on writing the output.
fn scan_error(source: Option<&str>, error: io::Error) -> Error {
    if error.get_ref().is_some_and(|inner| inner.is::<Error>()) {
        let inner = error.into_inner().expect("checked above");
        return *inner.downcast::<Error>().expect("checked above");
    }
    match source {
        Some(source) => Error::Scan {
            source: source.to_string(),
            error,
        },
        None => Error::Output(error),
    }
}

/// Whether to scan with the parallel chunk pipeline. First-only mode must
/// stay sequential: the pipeline reads a whole chunk before scanning any of
/// it, so `-1 --jobs N` on a slow stream would sit on a match it had already
/// read instead of printing it and exiting.
/// `--jobs`: an explicit thread count, or `auto`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Jobs {
    Auto,
    Count(usize),
}

fn parse_jobs(value: &str) -> Result<Jobs, String> {
    if value.eq_ignore_ascii_case("auto") {
        return Ok(Jobs::Auto);
    }
    match value.parse() {
        Ok(0) | Err(_) => Err("expected a thread count of at least 1, or auto".to_string()),
        Ok(count) => Ok(Jobs::Count(count)),
    }
}

/// Inputs at least this large are scanned on every core under `--jobs auto`.
const AUTO_PARALLEL_MIN_BYTES: u64 = 8 * 1024 * 1024;

/// Threads to scan one input with. `--first` must stay sequential: the
/// parallel path scans a whole chunk before printing, so `-1` on a slow
/// stream would sit on a match it had already read. `auto` uses every core
/// for streams and for files large enough to amortise the threads; a small
/// file is scanned on one.
fn effective_jobs(opts: &Opts, input_len: Option<u64>) -> usize {
    if opts.first {
        return 1;
    }
    match opts.jobs {
        Jobs::Count(n) => n,
        Jobs::Auto => match input_len {
            // A small regular file is not worth the threads; a stream of
            // unknown length may be terabytes.
            Some(len) if len < AUTO_PARALLEL_MIN_BYTES => 1,
            _ => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        },
    }
}

/// Threads walking a directory tree: one per core, or one when the output
/// order matters (`--first`, `--last`) or results are acted on as they come
/// (`--open`).
fn tree_threads(opts: &Opts) -> usize {
    if opts.first || opts.last || opts.opens() {
        return 1;
    }
    match opts.jobs {
        Jobs::Count(n) => n,
        Jobs::Auto => std::thread::available_parallelism()
            .map(|n| n.get().min(TREE_MAX_THREADS))
            .unwrap_or(1),
    }
}

/// Walker threads by default. Past this, the kernel's file system locks,
/// not the scan, set the pace: on macOS, opening and reading files from
/// more than four threads mostly adds system time (a walk of 89,000 files
/// spends 3.4 s in the kernel on 4 threads and 7.3 s on 12, for no gain in
/// wall time); elsewhere ripgrep's cap of a dozen holds.
#[cfg(target_os = "macos")]
const TREE_MAX_THREADS: usize = 4;
#[cfg(not(target_os = "macos"))]
const TREE_MAX_THREADS: usize = 12;

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

#[derive(Debug)]
enum InputTarget {
    Stdin,
    File(PathBuf),
    Dir(PathBuf),
    /// Files and directories walked together, one file per thread.
    Tree(Vec<PathBuf>),
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
    style: TextStyle,
}

impl Detail {
    fn new(opts: &Opts) -> Self {
        Detail {
            kind: opts.with_kind,
            location: opts.with_location,
            style: opts.text_style,
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
                write_text_line(out, location.as_ref(), kind, detail.style, &r.value)?;
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

/// SGR codes of the colored parts of a text line, ripgrep's for locations.
const PATH_COLOR: &str = "35";
const POSITION_COLOR: &str = "32";
const KIND_COLOR: &str = "36";

fn write_text_line<W: Write + ?Sized>(
    out: &mut W,
    location: Option<&Location>,
    kind: Option<&str>,
    style: TextStyle,
    value: &str,
) -> io::Result<()> {
    if let Some(location) = location {
        if let Some(source) = location.source {
            write_painted(out, style.color, PATH_COLOR, source)?;
            out.write_all(b":")?;
        }
        if style.color {
            write!(
                out,
                "\x1b[{POSITION_COLOR}m{}\x1b[0m:\x1b[{POSITION_COLOR}m{}\x1b[0m:",
                location.line, location.column
            )?;
        } else {
            write!(out, "{}:{}:", location.line, location.column)?;
        }
    }
    if let Some(kind) = kind {
        write_painted(out, style.color, KIND_COLOR, kind)?;
        if style.kind_width > 0 {
            let pad = style.kind_width.saturating_sub(kind.len());
            write!(out, "{:pad$}", "")?;
        } else {
            out.write_all(b"\t")?;
        }
    }
    out.write_all(value.as_bytes())?;
    out.write_all(b"\n")
}

fn write_painted<W: Write + ?Sized>(
    out: &mut W,
    color: bool,
    code: &str,
    text: &str,
) -> io::Result<()> {
    if color {
        write!(out, "\x1b[{code}m{text}\x1b[0m")
    } else {
        out.write_all(text.as_bytes())
    }
}

/// Whether to color text output. `auto` colors a terminal unless NO_COLOR is
/// set, CLICOLOR is 0, or TERM is dumb; CLICOLOR_FORCE colors a pipe too.
fn use_color(when: ColorWhen, terminal: bool) -> bool {
    let wanted = match when {
        ColorWhen::Always => true,
        ColorWhen::Never => false,
        ColorWhen::Auto => {
            !anstyle_query::no_color()
                && (anstyle_query::clicolor_force()
                    || (terminal
                        && anstyle_query::clicolor() != Some(false)
                        && anstyle_query::term_supports_color()))
        }
    };
    // Windows consoles interpret ANSI codes once asked to; `None` elsewhere.
    wanted
        && (anstyle_query::windows::enable_ansi_colors() != Some(false)
            || when == ColorWhen::Always)
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(text).map_err(|e| e.to_string())?;
    Ok(())
}

// `pbcopy` rather than a clipboard crate: linking AppKit costs every run a
// millisecond and a half of startup, and `--copy` is the only user.
#[cfg(target_os = "macos")]
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut child = std::process::Command::new("/usr/bin/pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start pbcopy: {e}"))?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(text.as_bytes())
        .map_err(|e| format!("failed to send clipboard contents to pbcopy: {e}"))?;
    let status = child
        .wait()
        .map_err(|e| format!("failed to wait for pbcopy: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("pbcopy failed: {status}"))
    }
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
/// Whether any output shows line numbers; when none does, newlines are
/// never counted (a whole pass over the input, serial in the parallel
/// pipeline).
fn output_needs_line(opts: &Opts) -> bool {
    output_needs_column(opts)
}

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

    if opts.no_overlap() {
        apply_overlap_policy(matches, opts.precedence());
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
    record_found();
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

fn emit_streaming_value(
    out: &mut (dyn Write + Send),
    opts: &Opts,
    flush: bool,
    location: Option<&Location>,
    kind: &str,
    value: &str,
) -> io::Result<()> {
    record_found();
    write_text_line(
        out,
        location,
        opts.with_kind.then_some(kind),
        opts.text_style,
        value,
    )?;
    if flush {
        out.flush()?;
    }
    if opts.opens() {
        open_result(opts, kind, value).map_err(io::Error::other)?;
    }
    Ok(())
}

fn handle_result(
    out: &mut (dyn Write + Send),
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

/// Views a trimmed line as text. Lines are scanned as UTF-8; invalid bytes
/// cannot abort the scan (grep behavior), so an invalid line is converted
/// lossily into `scratch` instead: the U+FFFD replacement characters are
/// non-ASCII and match nothing, and the rest of the line is still scanned.
/// Valid lines, the common case, borrow the input directly.
#[inline]
/// The line as text. `valid` says the bytes were already validated as part
/// of a larger UTF-8 block (lines are cut at ASCII newlines, so a line of a
/// valid block is valid); otherwise the line is checked here and, when
/// invalid, converted lossily into `scratch`.
fn line_text<'a>(bytes: &'a [u8], valid: bool, scratch: &'a mut String) -> &'a str {
    if valid {
        debug_assert!(std::str::from_utf8(bytes).is_ok());
        // SAFETY: `valid` is only passed for a slice cut at newline
        // boundaries out of a block that `validate_block` accepted.
        return unsafe { std::str::from_utf8_unchecked(bytes) };
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            scratch.clear();
            scratch.push_str(&String::from_utf8_lossy(bytes));
            scratch.as_str()
        }
    }
}

/// Whether a whole block is valid UTF-8. `simdutf8` validates with SIMD,
/// which matters: the standard validator is the single largest cost of a
/// sparse scan once nothing else touches every byte.
fn validate_block(block: &[u8]) -> bool {
    simdutf8::basic::from_utf8(block).is_ok()
}

/// Initial size of the read buffer; it grows to hold a line longer than
/// this.
const READ_BLOCK: usize = 256 * 1024;

/// A reusable read buffer that hands out complete lines. Data is read in
/// large blocks and lines are located with `memchr`, so the per-line cost is
/// a slice, not a syscall or an allocation.
struct LineBuffer {
    buf: Vec<u8>,
    /// Unconsumed data lives in `buf[start..end]`.
    start: usize,
    end: usize,
}

impl LineBuffer {
    fn with_capacity(capacity: usize) -> Self {
        LineBuffer {
            buf: vec![0; capacity],
            start: 0,
            end: 0,
        }
    }

    fn pending(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// Every complete line that is buffered (up to the last newline).
    fn complete_lines(&self) -> &[u8] {
        let pending = self.pending();
        match memchr::memrchr(b'\n', pending) {
            Some(nl) => &pending[..nl + 1],
            None => &pending[..0],
        }
    }

    fn consume(&mut self, len: usize) {
        self.start += len;
    }

    /// Reads once into the free space, compacting or growing the buffer as
    /// needed. Returns the number of bytes read; 0 means end of input. A
    /// single `read` is enough: it returns as soon as some data is
    /// available, so a slow stream still gets its lines processed promptly.
    fn fill(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.end == self.buf.len() {
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            } else {
                let new_len = self.buf.len().saturating_mul(2).max(READ_BLOCK);
                self.buf.resize(new_len, 0);
            }
        }
        loop {
            match reader.read(&mut self.buf[self.end..]) {
                Ok(n) => {
                    self.end += n;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Everything still buffered, as a final unterminated line.
    fn take_rest(&mut self) -> Option<&[u8]> {
        if self.start == self.end {
            return None;
        }
        let rest = &self.buf[self.start..self.end];
        self.start = self.end;
        Some(rest)
    }
}

/// Per-scan scratch reused across lines.
struct LineScratch {
    matches: Vec<Match>,
    lossy: String,
}

impl LineScratch {
    fn new() -> Self {
        LineScratch {
            matches: Vec::new(),
            lossy: String::new(),
        }
    }
}

/// Emits the matches of one line. Returns `Ok(true)` when scanning must
/// stop (`--first` found its match).
#[allow(clippy::too_many_arguments)]
fn emit_line_matches(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    line_number: usize,
    line: &str,
    matches: &[Match],
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    streaming: bool,
) -> io::Result<bool> {
    for m in matches {
        let value = &line[m.range.clone()];
        if value.is_empty() {
            continue;
        }
        if streaming {
            let kind = scanner.finders()[m.finder_index].id();
            let location = opts.with_location.then(|| Location {
                source,
                line: line_number,
                column: byte_column(line, m.range.start),
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
        } else if let Some(result) = make_result_item(scanner, opts, source, line_number, line, m)
            && handle_result(out, opts, state, result)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Counts lines lazily: only the newlines between emitted lines are
/// counted, so lines without matches cost one `memchr` pass at most.
struct LineCounter {
    counted_upto: usize,
    newlines: usize,
    /// Whether the output shows line numbers at all.
    enabled: bool,
}

impl LineCounter {
    fn new(opts: &Opts, first_line: usize) -> Self {
        LineCounter {
            counted_upto: 0,
            newlines: first_line - 1,
            enabled: output_needs_line(opts),
        }
    }

    /// 1-based number of the line starting at `line_start` in `data`.
    #[inline]
    fn number(&mut self, data: &[u8], line_start: usize) -> usize {
        if self.enabled && line_start > self.counted_upto {
            self.newlines +=
                memchr::memchr_iter(b'\n', &data[self.counted_upto..line_start]).count();
            self.counted_upto = line_start;
        }
        self.newlines + 1
    }
}

/// Scans a block of whole lines. A valid UTF-8 block goes through
/// `Scanner::scan_buffer` in one pass; an invalid one falls back to a scan
/// per line with lossy conversion. `first_line` numbers the block's first
/// line. Returns `Ok(true)` when scanning must stop.
#[allow(clippy::too_many_arguments)]
fn scan_block(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    first_line: usize,
    block: &[u8],
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    scratch: &mut LineScratch,
    streaming: bool,
) -> io::Result<bool> {
    if !validate_block(block) {
        let mut line_number = first_line;
        let mut pos = 0;
        while pos < block.len() {
            let end = memchr::memchr(b'\n', &block[pos..]).map_or(block.len(), |nl| pos + nl + 1);
            if scan_raw_line(
                scanner,
                opts,
                source,
                line_number,
                &block[pos..end],
                false,
                out,
                state,
                scratch,
                streaming,
            )? {
                return Ok(true);
            }
            line_number += 1;
            pos = end;
        }
        return Ok(false);
    }
    // SAFETY: `validate_block` accepted the whole block.
    let text = unsafe { std::str::from_utf8_unchecked(block) };
    let mut failure: Option<io::Error> = None;
    let mut stop = false;
    if streaming && !opts.with_location && !opts.no_overlap() {
        // Plain values: neither the line nor its number is needed.
        let flush = state.flush_streaming;
        let stopped = scanner.scan_buffer_matches(text, |finder, range| {
            let value = &text[range];
            if value.is_empty() {
                return false;
            }
            let kind = scanner.finders()[finder].id();
            match emit_streaming_value(out, opts, flush, None, kind, value) {
                Ok(()) => {
                    stop = opts.first;
                    stop
                }
                Err(e) => {
                    failure = Some(e);
                    true
                }
            }
        });
        if let Some(e) = failure {
            return Err(e);
        }
        return Ok(stopped && stop);
    }
    let mut counter = LineCounter::new(opts, first_line);
    let mut kept = Vec::new();
    let stopped = scanner.scan_buffer(text, |start, end, matches| {
        let line_number = counter.number(block, start);
        let matches = if opts.no_overlap() {
            kept.clear();
            kept.extend_from_slice(matches);
            apply_overlap_policy(&mut kept, opts.precedence());
            &kept[..]
        } else {
            matches
        };
        match emit_line_matches(
            scanner,
            opts,
            source,
            line_number,
            &text[start..end],
            matches,
            out,
            state,
            streaming,
        ) {
            Ok(done) => {
                stop = done;
                done
            }
            Err(e) => {
                failure = Some(e);
                true
            }
        }
    });
    if let Some(e) = failure {
        return Err(e);
    }
    Ok(stopped && stop)
}

/// Scans one raw line (terminator included) and emits its results. Returns
/// `Ok(true)` when scanning must stop (`--first` found its match).
#[allow(clippy::too_many_arguments)]
fn scan_raw_line(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    line_number: usize,
    raw: &[u8],
    valid: bool,
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    scratch: &mut LineScratch,
    streaming: bool,
) -> io::Result<bool> {
    let line = line_text(trim_line_ending(raw), valid, &mut scratch.lossy);
    scan_line_matches_into(scanner, opts, line, &mut scratch.matches);
    emit_line_matches(
        scanner,
        opts,
        source,
        line_number,
        line,
        &scratch.matches,
        out,
        state,
        streaming,
    )
}

fn scan_lines_sequential(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    reader: &mut dyn Read,
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
) -> io::Result<bool> {
    let mut lines = LineBuffer::with_capacity(READ_BLOCK);
    let mut scratch = LineScratch::new();
    let mut line_number = 1;
    // In the plain streaming text path the match value is written straight
    // from the line slice, without allocating a ResultItem per match.
    let streaming = !must_buffer(opts);

    loop {
        // Every complete line that is buffered, as one block.
        let block = lines.complete_lines();
        if !block.is_empty() {
            let count = if output_needs_line(opts) {
                memchr::memchr_iter(b'\n', block).count()
            } else {
                0
            };
            let len = block.len();
            if scan_block(
                scanner,
                opts,
                source,
                line_number,
                block,
                out,
                state,
                &mut scratch,
                streaming,
            )? {
                return Ok(true);
            }
            line_number += count;
            lines.consume(len);
        }
        if lines.fill(reader)? == 0 {
            if let Some(raw) = lines.take_rest()
                && scan_raw_line(
                    scanner,
                    opts,
                    source,
                    line_number,
                    raw,
                    false,
                    out,
                    state,
                    &mut scratch,
                    streaming,
                )?
            {
                return Ok(true);
            }
            return Ok(false);
        }
    }
}

/// Bytes validated and scanned per step of the whole-buffer path: large
/// enough to amortise the block validation, small enough to stay in cache.
const BUFFER_WINDOW: usize = 1024 * 1024;

/// Sequential scan of an input held entirely in memory (a mapped file):
/// windows of whole lines, each scanned as one block.
#[allow(clippy::too_many_arguments)]
fn scan_buffer_sequential(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    data: &[u8],
    mapped: bool,
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
) -> io::Result<bool> {
    let mut scratch = LineScratch::new();
    let streaming = !must_buffer(opts);
    let mut line_number = 1;
    let mut pos = 0;
    let mut prefetch = Prefetch::new(data, mapped);
    while pos < data.len() {
        prefetch.ahead_of(pos);
        let window_end = if pos + BUFFER_WINDOW >= data.len() {
            data.len()
        } else {
            let limit = pos + BUFFER_WINDOW;
            match memchr::memrchr(b'\n', &data[pos..limit]) {
                Some(nl) => pos + nl + 1,
                None => {
                    memchr::memchr(b'\n', &data[limit..]).map_or(data.len(), |nl| limit + nl + 1)
                }
            }
        };
        let block = &data[pos..window_end];
        if scan_block(
            scanner,
            opts,
            source,
            line_number,
            block,
            out,
            state,
            &mut scratch,
            streaming,
        )? {
            return Ok(true);
        }
        if output_needs_line(opts) {
            line_number += memchr::memchr_iter(b'\n', block).count();
        }
        pos = window_end;
    }
    Ok(false)
}

/// Target size of a parallel chunk; a chunk always holds whole lines, so a
/// longer line makes a longer chunk.
const CHUNK_SIZE: usize = 512 * 1024;

/// A read returning fewer bytes than this comes from a producer that is
/// not keeping up: the pipeline scans what it has instead of waiting for a
/// full chunk. Pipes hand out 64 KiB at a time on most systems, so a fast
/// producer still fills whole chunks.
const SHORT_READ_BYTES: usize = 16 * 1024;

/// A run of whole lines handed to a worker: copied out of a stream, or a
/// slice of a mapped file.
struct Chunk<'a> {
    index: usize,
    /// 1-based number of the first line in the chunk.
    first_line: usize,
    data: ChunkData<'a>,
}

enum ChunkData<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a [u8]),
}

impl ChunkData<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            ChunkData::Owned(data) => data,
            ChunkData::Borrowed(data) => data,
        }
    }
}

/// What a worker produced for one chunk: formatted text for the streaming
/// path, result items when the output must be shaped afterwards.
enum ChunkOutput {
    Text(Vec<u8>),
    Items(Vec<ResultItem>),
}

struct ChunkResult {
    index: usize,
    output: ChunkOutput,
}

/// Whether the parallel workers can format text directly; `--open` needs
/// the values on the main thread, so it goes through items.
fn stream_text_in_workers(opts: &Opts) -> bool {
    !must_buffer(opts) && !opts.opens()
}

fn scan_chunk(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    chunk: &Chunk,
    scratch: &mut LineScratch,
) -> ChunkOutput {
    let streaming = stream_text_in_workers(opts);
    let mut text = Vec::new();
    let mut items = Vec::new();
    let data = chunk.data.as_slice();
    let valid = validate_block(data);
    let mut emit = |line: &str, line_number: usize, matches: &[Match]| {
        for m in matches {
            let value = &line[m.range.clone()];
            if value.is_empty() {
                continue;
            }
            if streaming {
                let kind = scanner.finders()[m.finder_index].id();
                let location = opts.with_location.then(|| Location {
                    source,
                    line: line_number,
                    column: byte_column(line, m.range.start),
                });
                record_found();
                // Writing into a Vec cannot fail.
                let _ = write_text_line(
                    &mut text,
                    location.as_ref(),
                    opts.with_kind.then_some(kind),
                    opts.text_style,
                    value,
                );
            } else if let Some(item) = make_result_item(scanner, opts, source, line_number, line, m)
            {
                items.push(item);
            }
        }
    };
    if valid && streaming && !opts.with_location && !opts.no_overlap() {
        // Plain values: neither the line nor its number is needed.
        // SAFETY: `validate_block` accepted the whole chunk.
        let whole = unsafe { std::str::from_utf8_unchecked(data) };
        scanner.scan_buffer_matches(whole, |finder, range| {
            let value = &whole[range];
            if !value.is_empty() {
                let kind = scanner.finders()[finder].id();
                record_found();
                // Writing into a Vec cannot fail.
                let _ = write_text_line(
                    &mut text,
                    None,
                    opts.with_kind.then_some(kind),
                    opts.text_style,
                    value,
                );
            }
            false
        });
    } else if valid {
        // SAFETY: `validate_block` accepted the whole chunk.
        let text = unsafe { std::str::from_utf8_unchecked(data) };
        let mut counter = LineCounter::new(opts, chunk.first_line);
        let mut kept = Vec::new();
        scanner.scan_buffer(text, |start, end, matches| {
            let line_number = counter.number(data, start);
            let matches = if opts.no_overlap() {
                kept.clear();
                kept.extend_from_slice(matches);
                apply_overlap_policy(&mut kept, opts.precedence());
                &kept[..]
            } else {
                matches
            };
            emit(&text[start..end], line_number, matches);
            false
        });
    } else {
        let mut line_number = chunk.first_line;
        let mut pos = 0;
        while pos < data.len() {
            let end = memchr::memchr(b'\n', &data[pos..]).map_or(data.len(), |nl| pos + nl + 1);
            let line = line_text(trim_line_ending(&data[pos..end]), false, &mut scratch.lossy);
            scan_line_matches_into(scanner, opts, line, &mut scratch.matches);
            emit(line, line_number, &scratch.matches);
            line_number += 1;
            pos = end;
        }
    }
    if streaming {
        ChunkOutput::Text(text)
    } else {
        ChunkOutput::Items(items)
    }
}

/// Runs the parallel pipeline over the chunks `next_chunk` yields, in order:
/// `jobs` workers scan them, and the main thread writes results back in
/// chunk order through a reorder buffer while producing further chunks.
fn parallel_pipeline<'s, 'a>(
    scanner: &'s Scanner,
    opts: &'s Opts,
    source: Option<&'s str>,
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    jobs: usize,
    mut next_chunk: impl FnMut() -> io::Result<Option<Chunk<'a>>>,
) -> io::Result<bool> {
    // Chunks read but not yet written: the reader waits while `window` of
    // them are in flight, so a stalled writer (a slow or blocked stdout)
    // stops the reading instead of piling up results.
    let window = jobs * 4;
    let progress = WriteProgress::default();
    let progress = &progress;
    std::thread::scope(|scope| -> io::Result<bool> {
        // Bounded work queue keeps memory proportional to the worker count;
        // results go through an unbounded channel so a worker never blocks
        // on the main thread, which is busy reading; the window bounds it.
        let (work_tx, work_rx) = sync_channel::<Chunk<'a>>(jobs * 2);
        let (result_tx, result_rx) = channel::<ChunkResult>();
        let work_rx = Arc::new(Mutex::new(work_rx));
        for _ in 0..jobs {
            let work_rx = Arc::clone(&work_rx);
            let result_tx = result_tx.clone();
            scope.spawn(move || {
                let mut scratch = LineScratch::new();
                loop {
                    let chunk = match work_rx.lock() {
                        Ok(rx) => rx.recv(),
                        Err(_) => break,
                    };
                    let Ok(chunk) = chunk else { break };
                    let output = scan_chunk(scanner, opts, source, &chunk, &mut scratch);
                    if result_tx
                        .send(ChunkResult {
                            index: chunk.index,
                            output,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        drop(result_tx);

        // The writer runs on its own thread so a result never waits for the
        // reader, which may sit in a blocking read on a slow stream.
        let writer = scope.spawn(move || -> io::Result<bool> {
            // However the writer ends, the reader must not wait for it.
            let _done = progress.finish_on_drop();
            let mut pending: BTreeMap<usize, ChunkOutput> = BTreeMap::new();
            let mut next_index = 0;
            while let Ok(result) = result_rx.recv() {
                pending.insert(result.index, result.output);
                while let Some(output) = pending.remove(&next_index) {
                    next_index += 1;
                    progress.written(next_index);
                    match output {
                        ChunkOutput::Text(text) => {
                            out.write_all(&text)?;
                            if state.flush_streaming {
                                out.flush()?;
                            }
                        }
                        ChunkOutput::Items(items) => {
                            for item in items {
                                if handle_result(out, opts, state, item)? {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }
            }
            Ok(false)
        });

        let mut read_error = None;
        let mut sent = 0;
        loop {
            if !progress.wait_below(sent, window) {
                break;
            }
            let chunk = match next_chunk() {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(e) => {
                    read_error = Some(e);
                    break;
                }
            };
            // Every worker has gone (the writer stopped): nothing to do.
            if work_tx.send(chunk).is_err() {
                break;
            }
            sent += 1;
        }
        drop(work_tx);
        let written = writer.join().unwrap_or(Ok(false));
        match read_error {
            Some(e) => Err(e),
            None => written,
        }
    })
}

/// How far the writer of the parallel pipeline got: chunks written, and
/// whether it stopped.
#[derive(Default)]
struct WriteProgress {
    state: Mutex<(usize, bool)>,
    changed: Condvar,
}

impl WriteProgress {
    fn written(&self, count: usize) {
        if let Ok(mut state) = self.state.lock() {
            state.0 = count;
        }
        self.changed.notify_one();
    }

    /// Waits until fewer than `window` of the `sent` chunks are unwritten;
    /// `false` when the writer stopped.
    fn wait_below(&self, sent: usize, window: usize) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        while !state.1 && sent >= state.0 + window {
            match self.changed.wait(state) {
                Ok(next) => state = next,
                Err(_) => return false,
            }
        }
        !state.1
    }

    /// Marks the writer as stopped when the guard drops.
    fn finish_on_drop(&self) -> impl Drop + '_ {
        struct Finish<'a>(&'a WriteProgress);
        impl Drop for Finish<'_> {
            fn drop(&mut self) {
                if let Ok(mut state) = self.0.state.lock() {
                    state.1 = true;
                }
                self.0.changed.notify_one();
            }
        }
        Finish(self)
    }
}

fn scan_lines_parallel(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    reader: &mut dyn Read,
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    jobs: usize,
) -> io::Result<bool> {
    // Each chunk owns the buffer the stream was read into: the only copy
    // is the kernel's. The incomplete last line carries over to the next.
    let mut carry: Vec<u8> = Vec::new();
    let mut index = 0;
    let mut first_line = 1;
    let mut eof = false;
    let next_chunk = || -> io::Result<Option<Chunk<'static>>> {
        if eof && carry.is_empty() {
            return Ok(None);
        }
        let mut buf = std::mem::take(&mut carry);
        let mut len = buf.len();
        loop {
            // Fill up to a chunk's worth of whole lines, except when the
            // producer is slower than the scan (a short read): what is
            // complete now goes out at once, so a live stream (`tail -f`,
            // `kubectl logs -f`) is scanned as it arrives.
            while len < CHUNK_SIZE && !eof {
                if buf.len() < len + READ_BLOCK {
                    buf.resize(len + READ_BLOCK, 0);
                }
                let read = loop {
                    match reader.read(&mut buf[len..]) {
                        Ok(n) => break n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                };
                len += read;
                if read == 0 {
                    eof = true;
                } else if read < SHORT_READ_BYTES && len > 0 {
                    break;
                }
            }
            if len == 0 {
                return Ok(None);
            }
            let cut = if eof {
                len
            } else {
                match memchr::memrchr(b'\n', &buf[..len]) {
                    Some(nl) => nl + 1,
                    // One line longer than a chunk: keep reading it.
                    None => {
                        if buf.len() < len + READ_BLOCK {
                            buf.resize(len + READ_BLOCK, 0);
                        }
                        let read = reader.read(&mut buf[len..])?;
                        len += read;
                        if read == 0 {
                            eof = true;
                        }
                        continue;
                    }
                }
            };
            carry.extend_from_slice(&buf[cut..len]);
            buf.truncate(cut);
            let line_count = if output_needs_line(opts) {
                memchr::memchr_iter(b'\n', &buf).count() + usize::from(!buf.ends_with(b"\n"))
            } else {
                0
            };
            let chunk = Chunk {
                index,
                first_line,
                data: ChunkData::Owned(buf),
            };
            index += 1;
            first_line += line_count;
            return Ok(Some(chunk));
        }
    };
    parallel_pipeline(scanner, opts, source, out, state, jobs, next_chunk)
}

/// Parallel scan of an input held entirely in memory: chunks are slices,
/// nothing is copied.
#[allow(clippy::too_many_arguments)]
fn scan_buffer_parallel<'a>(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    data: &'a [u8],
    mapped: bool,
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    jobs: usize,
) -> io::Result<bool> {
    let mut pos = 0;
    let mut index = 0;
    let mut first_line = 1;
    let mut prefetch = Prefetch::new(data, mapped);
    let next_chunk = || -> io::Result<Option<Chunk<'a>>> {
        if pos >= data.len() {
            return Ok(None);
        }
        prefetch.ahead_of(pos);
        let end = if pos + CHUNK_SIZE >= data.len() {
            data.len()
        } else {
            let limit = pos + CHUNK_SIZE;
            match memchr::memrchr(b'\n', &data[pos..limit]) {
                Some(nl) => pos + nl + 1,
                None => {
                    memchr::memchr(b'\n', &data[limit..]).map_or(data.len(), |nl| limit + nl + 1)
                }
            }
        };
        let slice = &data[pos..end];
        let line_count = if output_needs_line(opts) {
            memchr::memchr_iter(b'\n', slice).count() + usize::from(!slice.ends_with(b"\n"))
        } else {
            0
        };
        let chunk = Chunk {
            index,
            first_line,
            data: ChunkData::Borrowed(slice),
        };
        index += 1;
        first_line += line_count;
        pos = end;
        Ok(Some(chunk))
    };
    parallel_pipeline(scanner, opts, source, out, state, jobs, next_chunk)
}

fn has_glob_magic(input: &str) -> bool {
    input.contains('*') || input.contains('?') || input.contains('[')
}

fn expand_inputs(inputs: &[String]) -> Result<Vec<InputTarget>, Error> {
    // Like grep: no path means standard input; `.` searches here.
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
            let entries = glob::glob(input).map_err(|e| Error::Input {
                path: input.clone(),
                reason: e.to_string(),
            })?;
            for entry in entries {
                let path = entry.map_err(|e| Error::Input {
                    path: e.path().display().to_string(),
                    reason: e.error().to_string(),
                })?;
                if path.is_dir() {
                    matched = true;
                    targets.push(InputTarget::Dir(path));
                } else if path.is_file() {
                    matched = true;
                    targets.push(InputTarget::File(path));
                }
            }
            if !matched {
                return Err(Error::Input {
                    path: input.clone(),
                    reason: "no files match this pattern".to_string(),
                });
            }
        } else {
            let path = PathBuf::from(input);
            if path.is_dir() {
                targets.push(InputTarget::Dir(path));
            } else {
                targets.push(InputTarget::File(path));
            }
        }
    }

    Ok(targets)
}

/// Bytes of a file inspected for a NUL byte, which marks it as binary.
const BINARY_PROBE_BYTES: usize = 8 * 1024;

/// The writer and buffered results shared by the threads of a tree walk.
struct TreeShared<'a> {
    out: &'a mut (dyn Write + Send),
    state: &'a mut OutputState,
    failure: Option<io::Error>,
}

/// Regular files at least this large are mapped during a tree walk; smaller
/// ones are read into the thread's buffer, which is cheaper per file.
const TREE_MMAP_MIN_BYTES: u64 = 4 * 1024 * 1024;

/// Size of the first read of a tree file; a file filling it is stat'ed to
/// choose between mapping it and reading the rest.
const TREE_FIRST_READ: usize = 256 * 1024;

/// Per-thread state of a tree walk: the output of the file being scanned
/// and the file's bytes when it is read rather than mapped.
struct TreeLocal {
    text: Vec<u8>,
    state: OutputState,
    data: Vec<u8>,
}

/// Scans one regular file of a tree into `local`, sequentially. Binary files
/// (a NUL byte within the first 8 KiB) are skipped. Returns `Ok(true)` when
/// scanning must stop (`--first` found its match).
fn scan_tree_file(
    scanner: &Scanner,
    opts: &Opts,
    path: &std::path::Path,
    local: &mut TreeLocal,
) -> io::Result<bool> {
    let mut file = File::open(path)?;
    // No stat up front: most files fit the first read, so a file costs an
    // open, a read, the read seeing its end, and a close. The buffer keeps
    // its length across files (bytes past `filled` are stale), so it is
    // never zeroed again.
    if local.data.len() < TREE_FIRST_READ {
        local.data.resize(TREE_FIRST_READ, 0);
    }
    let mut filled = read_some(&mut file, &mut local.data[..TREE_FIRST_READ])?;
    if filled == TREE_FIRST_READ {
        let len = file.metadata()?.len();
        if len >= TREE_MMAP_MIN_BYTES {
            // SAFETY: read-only mapping that lives for this scan only; a
            // file truncated by another process during the scan is
            // undefined, as for every mapped read.
            if let Ok(map) = unsafe { memmap2::Mmap::map(&file) } {
                #[cfg(unix)]
                let _ = map.advise(memmap2::Advice::Sequential);
                return scan_tree_data(scanner, opts, path, &map, true, local);
            }
        }
        loop {
            if filled == local.data.len() {
                let grown = (local.data.len() * 2).max(len as usize + 1);
                local.data.resize(grown, 0);
            }
            match read_some(&mut file, &mut local.data[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
    }
    // The buffer is borrowed by the scan while its output goes to `text`.
    let data = std::mem::take(&mut local.data);
    let result = scan_tree_data(scanner, opts, path, &data[..filled], false, local);
    local.data = data;
    result
}

/// Fills `buf` from `file` until it is full or the file ends; returns the
/// bytes read.
fn read_some(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Scans the contents of a tree file, unless empty or binary (a NUL byte
/// within the first 8 KiB).
fn scan_tree_data(
    scanner: &Scanner,
    opts: &Opts,
    path: &std::path::Path,
    data: &[u8],
    mapped: bool,
    local: &mut TreeLocal,
) -> io::Result<bool> {
    if data.is_empty() || memchr::memchr(0, &data[..data.len().min(BINARY_PROBE_BYTES)]).is_some() {
        return Ok(false);
    }
    let display = path.display().to_string();
    let source = display.strip_prefix("./").unwrap_or(&display);
    scan_buffer_sequential(
        scanner,
        opts,
        Some(source),
        data,
        mapped,
        &mut local.text,
        &mut local.state,
    )
}

/// Walks `roots` (files and directories) like ripgrep does, hidden entries,
/// ignore rules and binary files skipped, scanning files on every core and
/// writing each file's results in one piece. With one thread the walk is
/// sorted by name and the output deterministic. Returns `Ok(true)` when
/// scanning must stop.
/// Entries that cannot be read are reported on stderr and set `failed`;
/// the walk goes on.
fn scan_tree(
    scanner: &Scanner,
    opts: &Opts,
    roots: &[PathBuf],
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    failed: &mut bool,
) -> io::Result<bool> {
    let threads = tree_threads(opts);
    let mut builder = ignore::WalkBuilder::new(&roots[0]);
    for root in &roots[1..] {
        builder.add(root);
    }
    builder
        .hidden(!opts.hidden)
        .git_ignore(!opts.no_ignore)
        .git_global(!opts.no_ignore)
        .git_exclude(!opts.no_ignore)
        .ignore(!opts.no_ignore)
        .parents(!opts.no_ignore)
        .follow_links(opts.follow)
        .threads(threads);
    // Version control internals are never text to extract from.
    builder.filter_entry(|entry| {
        !(entry.file_type().is_some_and(|t| t.is_dir()) && entry.file_name() == ".git")
    });

    let shared = Mutex::new(TreeShared {
        out,
        state,
        failure: None,
    });
    let stop = AtomicBool::new(false);
    let reported = AtomicBool::new(false);
    let flush_streaming = shared
        .lock()
        .map(|s| s.state.flush_streaming)
        .unwrap_or(false);

    let stop = &stop;
    let reported_ref = &reported;
    let shared_ref = &shared;
    let local = || TreeLocal {
        text: Vec::new(),
        state: OutputState::new(opts),
        data: Vec::new(),
    };
    if threads == 1 {
        // Sequential and sorted: the output order is reproducible.
        builder.sort_by_file_name(|a, b| a.cmp(b));
        let mut visit = tree_visitor(
            scanner,
            opts,
            flush_streaming,
            stop,
            reported_ref,
            shared_ref,
            local(),
        );
        for entry in builder.build() {
            if visit(entry) == ignore::WalkState::Quit {
                break;
            }
        }
    } else {
        builder.build_parallel().run(|| {
            Box::new(tree_visitor(
                scanner,
                opts,
                flush_streaming,
                stop,
                reported_ref,
                shared_ref,
                local(),
            ))
        });
    }

    *failed |= reported.load(Ordering::Relaxed);
    let mut shared = shared
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(e) = shared.failure.take() {
        return Err(e);
    }
    Ok(stop.load(Ordering::Relaxed) && opts.first)
}

/// The per-entry work of a tree walk: scan a regular file into `local`
/// and hand its output to the shared writer.
#[allow(clippy::too_many_arguments)]
fn tree_visitor<'a, 'b: 'a>(
    scanner: &'a Scanner,
    opts: &'a Opts,
    flush_streaming: bool,
    stop: &'a AtomicBool,
    reported: &'a AtomicBool,
    shared: &'a Mutex<TreeShared<'b>>,
    mut local: TreeLocal,
) -> impl FnMut(Result<ignore::DirEntry, ignore::Error>) -> ignore::WalkState + 'a {
    move |entry| {
        if stop.load(Ordering::Relaxed) {
            return ignore::WalkState::Quit;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("squeeze: {err}");
                reported.store(true, Ordering::Relaxed);
                return ignore::WalkState::Continue;
            }
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            return ignore::WalkState::Continue;
        }
        let path = entry.path();
        let done = match scan_tree_file(scanner, opts, path, &mut local) {
            Ok(done) => done,
            Err(e) => {
                eprintln!("squeeze: {}: {}", path.display(), e);
                reported.store(true, Ordering::Relaxed);
                false
            }
        };
        let has_output = !local.text.is_empty()
            || local.state.buffer.as_ref().is_some_and(|b| !b.is_empty())
            || local.state.last_match.is_some();
        if has_output {
            let Ok(mut shared) = shared.lock() else {
                return ignore::WalkState::Quit;
            };
            if !local.text.is_empty() {
                let written = shared.out.write_all(&local.text).and_then(|()| {
                    if flush_streaming {
                        shared.out.flush()
                    } else {
                        Ok(())
                    }
                });
                local.text.clear();
                if let Err(e) = written {
                    shared.failure = Some(e);
                    stop.store(true, Ordering::Relaxed);
                    return ignore::WalkState::Quit;
                }
            }
            if let Some(items) = local.state.buffer.as_mut()
                && let Some(all) = shared.state.buffer.as_mut()
            {
                all.append(items);
            }
            if let Some(last) = local.state.last_match.take() {
                shared.state.last_match = Some(last);
            }
        }
        if done {
            stop.store(true, Ordering::Relaxed);
            return ignore::WalkState::Quit;
        }
        ignore::WalkState::Continue
    }
}

fn scan_reader(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    reader: &mut dyn Read,
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    jobs: usize,
) -> io::Result<bool> {
    if jobs > 1 {
        scan_lines_parallel(scanner, opts, source, reader, out, state, jobs)
    } else {
        scan_lines_sequential(scanner, opts, source, reader, out, state)
    }
}

/// Scans an input held in memory; `mapped` says it is a file mapping.
#[allow(clippy::too_many_arguments)]
fn scan_buffer(
    scanner: &Scanner,
    opts: &Opts,
    source: Option<&str>,
    data: &[u8],
    mapped: bool,
    out: &mut (dyn Write + Send),
    state: &mut OutputState,
    jobs: usize,
) -> io::Result<bool> {
    if jobs > 1 {
        scan_buffer_parallel(scanner, opts, source, data, mapped, out, state, jobs)
    } else {
        scan_buffer_sequential(scanner, opts, source, data, mapped, out, state)
    }
}

/// Bytes of a mapped input the kernel is asked to map ahead of the scan.
const PREFETCH_AHEAD: usize = 8 * 1024 * 1024;

/// Asks the kernel to map the pages of a memory-mapped input ahead of the
/// scan (`MADV_WILLNEED`): faulting them in one at a time from the
/// scanning threads costs far more than the kernel's batched mapping (half
/// the user time of a sparse scan). The window is bounded, so an input
/// larger than memory is never requested at once.
struct Prefetch<'a> {
    data: &'a [u8],
    /// Bytes advised so far; the whole input when nothing is to be done.
    done: usize,
}

impl<'a> Prefetch<'a> {
    fn new(data: &'a [u8], mapped: bool) -> Self {
        let done = if mapped && cfg!(unix) { 0 } else { data.len() };
        Prefetch { data, done }
    }

    /// Advises the next window once the scan at `pos` gets within half a
    /// window of the advised bytes.
    fn ahead_of(&mut self, pos: usize) {
        if self.done >= self.data.len() || self.done >= pos + PREFETCH_AHEAD / 2 {
            return;
        }
        let end = (pos + PREFETCH_AHEAD).min(self.data.len());
        advise_will_need(&self.data[self.done..end]);
        self.done = end;
    }
}

#[cfg(unix)]
fn advise_will_need(range: &[u8]) {
    // SAFETY: `sysconf` has no preconditions.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
    let start = range.as_ptr() as usize;
    // madvise wants a page-aligned start; the page holding `start` belongs
    // to the same mapping.
    let aligned = start & !(page - 1);
    // SAFETY: the advice only affects how the pages of a mapping we borrow
    // are paged in, never their contents; failure is harmless.
    unsafe {
        libc::madvise(
            aligned as *mut libc::c_void,
            range.len() + (start - aligned),
            libc::MADV_WILLNEED,
        );
    }
}

#[cfg(not(unix))]
fn advise_will_need(_range: &[u8]) {}

/// Regular files at least this large are memory-mapped; smaller ones are
/// read whole. Either way the file is scanned from memory without copies.
const MMAP_MIN_BYTES: u64 = 64 * 1024;

fn finalize_results(
    out: &mut (dyn Write + Send),
    opts: &Opts,
    mut results: Vec<ResultItem>,
) -> Result<(), Error> {
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
    write_formatted(&mut formatted, &results, opts.output, Detail::new(opts))
        .map_err(Error::Output)?;
    // Print before copying: on Linux the copy waits for a display server round-trip, and a
    // clipboard that is unavailable should not cost the user their results.
    out.write_all(&formatted).map_err(Error::Output)?;

    if opts.copy {
        let mut clipboard = Vec::new();
        write_formatted(
            &mut clipboard,
            &results,
            clipboard_format(opts.output),
            Detail {
                style: TextStyle::default(),
                ..Detail::new(opts)
            },
        )
        .map_err(Error::Output)?;
        let text = String::from_utf8_lossy(&clipboard);
        copy_to_clipboard(&text).map_err(Error::Clipboard)?;
    }

    if opts.opens() {
        for r in &results {
            open_result(opts, r.kind, &r.value)?;
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

    let args = args::normalize(std::env::args_os()).unwrap_or_else(|message| usage_error(message));
    let mut opts = Opts::parse_from(args);

    if let Some(shell) = opts.completions {
        clap_complete::generate(shell, &mut Opts::command(), "squeeze", &mut io::stdout());
        return ExitCode::SUCCESS;
    }

    let finders = match build_finders(&opts.finders) {
        // Without a finder, scan everything and keep the normal output default.
        Ok(finders) if finders.is_empty() => {
            opts.finders.all = true;
            build_finders(&opts.finders)
        }
        result => result,
    };
    let scanner = finders
        .and_then(Scanner::try_new)
        .unwrap_or_else(|e| usage_error(e));

    let text = opts.output == Format::Text;
    let terminal = io::stdout().is_terminal();
    opts.text_style = TextStyle {
        kind_width: if text && terminal {
            scanner
                .finders()
                .iter()
                .map(|f| f.id().len())
                .max()
                .unwrap_or(0)
                + 2
        } else {
            0
        },
        color: text && use_color(opts.color, terminal),
    };

    match run(&opts, &scanner) {
        Ok(complete) => {
            if opts.open == [OpenKind::Url]
                && NOT_OPENED.load(Ordering::Relaxed)
                && !OPENED.load(Ordering::Relaxed)
            {
                eprintln!(
                    "squeeze: --open only opens URLs; pass --open=uri or --open=path to open other results"
                );
            }
            if !complete {
                ExitCode::from(EXIT_ERROR)
            } else if opts.exit_code && !FOUND.load(Ordering::Relaxed) {
                ExitCode::from(EXIT_NOT_FOUND)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(Error::Output(e)) if is_broken_pipe(&e) => ExitCode::SUCCESS,
        Err(e) => e.report(),
    }
}

/// Exits like clap does on its own invalid values: a usage error on stderr,
/// with exit status 2.
fn usage_error(message: impl std::fmt::Display) -> ! {
    Opts::command()
        .error(clap::error::ErrorKind::InvalidValue, message)
        .exit()
}

/// Scans every input and writes the results. Returns `Ok(false)` when
/// entries of a directory walk could not be read; each was reported as it
/// happened.
fn run(opts: &Opts, scanner: &Scanner) -> Result<bool, Error> {
    let targets = expand_inputs(&opts.inputs)?;

    // A bare `squeeze` typed in a terminal would otherwise wait on stdin in
    // silence; pasting text there stays supported.
    if opts.inputs.is_empty() && io::stdin().is_terminal() {
        let eof = if cfg!(windows) {
            "Ctrl-Z, Enter"
        } else {
            "Ctrl-D"
        };
        eprintln!(
            "squeeze: reading stdin; paste text and press {eof}, or pass a path such as . (see --help)"
        );
    }

    // Unlocked: the tree walker writes from several threads, each file's
    // results in one piece; the buffer keeps the per-write locking rare.
    let mut out = BufWriter::new(io::stdout());
    let mut state = OutputState::new(opts);

    // Directories, and several files, go through the tree walker (every
    // core, one file per thread); a single file keeps the chunked scan that
    // spreads one big file over every core.
    let tree_roots: Vec<PathBuf> = targets
        .iter()
        .filter_map(|target| match target {
            InputTarget::Dir(path) => Some(path.clone()),
            InputTarget::File(path) => Some(path.clone()),
            InputTarget::Stdin | InputTarget::Tree(_) => None,
        })
        .collect();
    let walk_tree = tree_roots.len() > 1
        || targets
            .iter()
            .any(|target| matches!(target, InputTarget::Dir(_)));
    let mut targets = targets;
    if walk_tree {
        targets.retain(|target| matches!(target, InputTarget::Stdin));
        targets.push(InputTarget::Tree(tree_roots));
    }

    // An unreadable entry of a walk is reported and skipped; the exit status
    // still says the scan was incomplete.
    let mut walk_failed = false;
    for target in targets {
        let (source, result) = match target {
            InputTarget::Tree(roots) => (
                None,
                scan_tree(
                    scanner,
                    opts,
                    &roots,
                    &mut out,
                    &mut state,
                    &mut walk_failed,
                ),
            ),
            InputTarget::Dir(path) => (
                None,
                scan_tree(
                    scanner,
                    opts,
                    &[path],
                    &mut out,
                    &mut state,
                    &mut walk_failed,
                ),
            ),
            InputTarget::Stdin => {
                let stdin = io::stdin();
                let mut reader = stdin.lock();
                let jobs = effective_jobs(opts, None);
                let result =
                    scan_reader(scanner, opts, None, &mut reader, &mut out, &mut state, jobs);
                (Some("<stdin>".to_string()), result)
            }
            InputTarget::File(path) => {
                let source = path.display().to_string();
                let mut file = File::open(&path).map_err(|e| Error::Input {
                    path: source.clone(),
                    reason: e.to_string(),
                })?;
                let regular_len = file
                    .metadata()
                    .ok()
                    .filter(|m| m.is_file())
                    .map(|m| m.len());
                let jobs = effective_jobs(opts, regular_len);
                let result = match regular_len {
                    Some(len) if len >= MMAP_MIN_BYTES => {
                        // SAFETY: the mapping is read-only and lives for the
                        // scan only. As with any mapped file, truncation by
                        // another process during the scan is undefined
                        // (SIGBUS); squeeze accepts that for the same reason
                        // grep tools do: it avoids copying every byte.
                        match unsafe { memmap2::Mmap::map(&file) } {
                            Ok(map) => {
                                // Read-ahead for a single forward pass (Unix only).
                                #[cfg(unix)]
                                let _ = map.advise(memmap2::Advice::Sequential);
                                scan_buffer(
                                    scanner,
                                    opts,
                                    Some(&source),
                                    &map,
                                    true,
                                    &mut out,
                                    &mut state,
                                    jobs,
                                )
                            }
                            Err(_) => scan_reader(
                                scanner,
                                opts,
                                Some(&source),
                                &mut file,
                                &mut out,
                                &mut state,
                                jobs,
                            ),
                        }
                    }
                    Some(_) => {
                        let mut data = Vec::new();
                        match file.read_to_end(&mut data) {
                            Ok(_) => scan_buffer(
                                scanner,
                                opts,
                                Some(&source),
                                &data,
                                false,
                                &mut out,
                                &mut state,
                                jobs,
                            ),
                            Err(e) => Err(e),
                        }
                    }
                    None => scan_reader(
                        scanner,
                        opts,
                        Some(&source),
                        &mut file,
                        &mut out,
                        &mut state,
                        jobs,
                    ),
                };
                (Some(source), result)
            }
        };

        match result {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) if is_broken_pipe(&e) => return Ok(!walk_failed),
            Err(e) => return Err(scan_error(source.as_deref(), e)),
        }
    }

    let buffered_results = if opts.last {
        state.last_match.into_iter().collect()
    } else {
        state.buffer.take().unwrap_or_default()
    };

    if opts.last || must_buffer(opts) {
        match finalize_results(&mut out, opts, buffered_results) {
            Err(Error::Output(e)) if is_broken_pipe(&e) => return Ok(!walk_failed),
            result => result?,
        }
    }

    match out.flush() {
        Err(e) if !is_broken_pipe(&e) => Err(Error::Output(e)),
        _ => Ok(!walk_failed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_path_reads_standard_input_even_from_a_terminal() {
        assert!(matches!(
            expand_inputs(&[]).unwrap().as_slice(),
            [InputTarget::Stdin]
        ));
    }

    #[test]
    fn kinds_align_in_a_terminal_and_are_tab_separated_otherwise() {
        let mut out = Vec::new();
        let aligned = TextStyle {
            kind_width: 10,
            color: false,
        };
        write_text_line(&mut out, None, Some("ip"), aligned, "10.0.4.2").unwrap();
        write_text_line(&mut out, None, Some("datetime"), aligned, "2026-01-15").unwrap();
        write_text_line(&mut out, None, Some("ip"), TextStyle::default(), "10.0.4.2").unwrap();
        write_text_line(&mut out, None, None, aligned, "bare").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "ip        10.0.4.2\ndatetime  2026-01-15\nip\t10.0.4.2\nbare\n"
        );
    }

    #[test]
    fn colors_paint_locations_and_kinds_but_not_values_or_padding() {
        let mut out = Vec::new();
        let location = Location {
            source: Some("app.log"),
            line: 3,
            column: 7,
        };
        let style = TextStyle {
            kind_width: 6,
            color: true,
        };
        write_text_line(&mut out, Some(&location), Some("ip"), style, "10.0.4.2").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\x1b[35mapp.log\x1b[0m:\x1b[32m3\x1b[0m:\x1b[32m7\x1b[0m:\x1b[36mip\x1b[0m    10.0.4.2\n"
        );
    }

    #[test]
    fn color_follows_when_unless_auto() {
        assert!(use_color(ColorWhen::Always, false));
        assert!(!use_color(ColorWhen::Never, true));
    }

    #[test]
    fn open_only_opens_the_requested_kinds() {
        let url = [OpenKind::Url];
        assert!(opens_kind(&url, "uri", "https://example.com"));
        assert!(opens_kind(&url, "uri", "MAILTO:hi@example.com"));
        assert!(!opens_kind(&url, "uri", "file:///etc/passwd"));
        assert!(!opens_kind(&url, "path", "/Applications/Calculator.app"));
        assert!(!opens_kind(&url, "email", "hi@example.com"));
        let uri_and_path = [OpenKind::Uri, OpenKind::Path];
        assert!(opens_kind(&uri_and_path, "uri", "file:///etc/hosts"));
        assert!(opens_kind(&uri_and_path, "path", "/etc/hosts"));
    }

    #[test]
    fn open_defaults_to_urls_and_takes_kinds() {
        let opts = Opts::try_parse_from(["squeeze", "--open"]).unwrap();
        assert_eq!(opts.open, [OpenKind::Url]);
        let opts = Opts::try_parse_from(["squeeze", "--open=uri,path", "x"]).unwrap();
        assert_eq!(opts.open, [OpenKind::Uri, OpenKind::Path]);
        assert_eq!(opts.inputs, ["x"]);
        let opts = Opts::try_parse_from(["squeeze", "x"]).unwrap();
        assert!(!opts.opens());
    }

    #[test]
    fn precedence_implies_no_overlap() {
        let opts = Opts::try_parse_from(["squeeze", "--precedence", "longest"]).unwrap();
        assert!(opts.no_overlap());
        assert_eq!(opts.precedence(), Precedence::Longest);
        let opts = Opts::try_parse_from(["squeeze"]).unwrap();
        assert!(!opts.no_overlap());
    }

    #[test]
    fn jobs_must_be_positive() {
        assert!(Opts::try_parse_from(["squeeze", "-j", "0"]).is_err());
        assert!(Opts::try_parse_from(["squeeze", "-j", "2"]).is_ok());
        assert!(Opts::try_parse_from(["squeeze", "-j", "auto"]).is_ok());
    }

    #[test]
    fn reader_waits_for_the_writer_once_the_window_is_full() {
        let progress = WriteProgress::default();
        assert!(progress.wait_below(3, 4));
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| progress.wait_below(4, 4));
            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(!waiter.is_finished());
            progress.written(1);
            assert!(waiter.join().unwrap());
        });
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| progress.wait_below(9, 4));
            drop(progress.finish_on_drop());
            assert!(!waiter.join().unwrap());
        });
    }

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
        // The parallel path reads a whole chunk before scanning, so -1 has
        // to dispatch to the sequential streaming path.
        let opts = Opts::try_parse_from(["squeeze", "--url", "--jobs", "4", "--first"]).unwrap();
        assert_eq!(effective_jobs(&opts, Some(1 << 30)), 1);

        let opts = Opts::try_parse_from(["squeeze", "--url", "--jobs", "4"]).unwrap();
        assert_eq!(effective_jobs(&opts, None), 4);
        assert_eq!(effective_jobs(&opts, Some(10)), 4);

        // `auto`: small files stay sequential; streams and large files use
        // every core.
        let opts = Opts::try_parse_from(["squeeze", "--url"]).unwrap();
        assert_eq!(opts.jobs, Jobs::Auto);
        assert_eq!(
            effective_jobs(&opts, None),
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        );
        assert_eq!(effective_jobs(&opts, Some(AUTO_PARALLEL_MIN_BYTES - 1)), 1);
        assert_eq!(
            effective_jobs(&opts, Some(AUTO_PARALLEL_MIN_BYTES)),
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        );
        assert_eq!(parse_jobs("AUTO"), Ok(Jobs::Auto));
        assert!(parse_jobs("0").is_err());
        assert!(parse_jobs("many").is_err());
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
        assert!(matches!(
            hash_finder(&opts.finders),
            Err(squeeze::Error::UnknownHashAlgorithm { name, .. }) if name == "bogus"
        ));
    }

    #[test]
    fn bare_hash_with_alias_should_stay_unrestricted() {
        let opts = Opts::try_parse_from(["squeeze", "--hash", "--md5"]).unwrap();
        let finder = hash_finder(&opts.finders).unwrap();
        // sha1 still matches: the bare --hash means every algorithm.
        assert!(
            finder
                .find("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
                .is_some()
        );
    }
}
