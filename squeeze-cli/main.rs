use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use squeeze::{
    Finder, cidr::Cidr, codetag::Codetag, color::Color, datetime::Datetime, domain::Domain,
    email::Email, emoji::Emoji, env::Env, handle::Handle, hash::Hash, ip::Ip, json::Json, jwt::Jwt,
    mac::Mac, mirror::Mirror, modeline::Modeline, path::Path, phone::Phone, scanner::Scanner,
    semver::Semver, uri::URI, uuid::Uuid,
};
use std::convert::{TryFrom, TryInto};
use std::io::{self, BufRead, BufWriter, Read, Write};
use std::process::ExitCode;

const VERSION: &str = match option_env!("SQUEEZE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Copy, Clone, Debug, ValueEnum, Default, PartialEq, Eq)]
enum Format {
    #[default]
    Text,
    Json,
    Yaml,
    Csv,
}

#[derive(Parser)]
#[command(
    name = "squeeze",
    version = VERSION,
    author = "Aymeric Beaumet <hi@aymericbeaumet.com>",
    about = "Extract rich information from any text"
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
    #[arg(long = "open", help = "open the results")]
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

    // cidr
    #[arg(long = "cidr", help = "search for CIDR notation")]
    cidr: bool,

    // codetag
    #[arg(long = "codetag", help = "search for codetags")]
    mnemonic: Option<Option<String>>,
    #[arg(
        long = "hide-mnemonic",
        help = "whether to show the mnemonics in the results"
    )]
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
    #[arg(long = "hash", help = "search for hashes")]
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
    #[arg(long = "mirror", help = "[debug] mirror the input")]
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
    #[arg(long = "uri", help = "search for uris")]
    scheme: Option<Option<String>>,
    #[arg(
        long = "strict",
        help = "strictly respect the URI RFC in regards to closing ' and )"
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

impl TryFrom<&Opts> for Cidr {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.cidr {
            return Err(());
        }
        Ok(Cidr::default())
    }
}

impl TryFrom<&Opts> for Color {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.color {
            return Err(());
        }
        Ok(Color::default())
    }
}

impl TryFrom<&Opts> for Datetime {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.datetime {
            return Err(());
        }
        Ok(Datetime::default())
    }
}

impl TryFrom<&Opts> for Domain {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.domain {
            return Err(());
        }
        Ok(Domain::default())
    }
}

impl TryFrom<&Opts> for Email {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.email {
            return Err(());
        }
        Ok(Email::default())
    }
}

impl TryFrom<&Opts> for Emoji {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.emoji {
            return Err(());
        }
        Ok(Emoji::default())
    }
}

impl TryFrom<&Opts> for Env {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.env {
            return Err(());
        }
        Ok(Env::default())
    }
}

impl TryFrom<&Opts> for Handle {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.handle {
            return Err(());
        }
        Ok(Handle::default())
    }
}

impl TryFrom<&Opts> for Hash {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !(opts.hash_algo.is_some() || opts.md5 || opts.sha1 || opts.sha256 || opts.sha512) {
            return Err(());
        }
        let mut finder = Hash::default();
        if let Some(Some(ref algo)) = opts.hash_algo {
            for a in algo.split(',') {
                finder.add_algorithm(a);
            }
        }
        if opts.md5 {
            finder.add_algorithm("md5");
        }
        if opts.sha1 {
            finder.add_algorithm("sha1");
        }
        if opts.sha256 {
            finder.add_algorithm("sha256");
        }
        if opts.sha512 {
            finder.add_algorithm("sha512");
        }
        Ok(finder)
    }
}

impl TryFrom<&Opts> for Ip {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !(opts.ip || opts.ipv4 || opts.ipv6) {
            return Err(());
        }
        Ok(Ip {
            ipv4: opts.ip || opts.ipv4,
            ipv6: opts.ip || opts.ipv6,
        })
    }
}

impl TryFrom<&Opts> for Json {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.json {
            return Err(());
        }
        Ok(Json::default())
    }
}

impl TryFrom<&Opts> for Jwt {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.jwt {
            return Err(());
        }
        Ok(Jwt::default())
    }
}

impl TryFrom<&Opts> for Mac {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.mac {
            return Err(());
        }
        Ok(Mac::default())
    }
}

impl TryFrom<&Opts> for Modeline {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.modeline {
            return Err(());
        }
        Ok(Modeline::default())
    }
}

impl TryFrom<&Opts> for Codetag {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !(opts.mnemonic.is_some() || opts.fixme || opts.todo) {
            return Err(());
        }
        let mut finder = Codetag::default();
        finder.hide_mnemonic = opts.hide_mnemonic;
        if let Some(Some(ref mnemonic)) = opts.mnemonic {
            for m in mnemonic.split(',') {
                finder.add_mnemonic(m);
            }
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

impl TryFrom<&Opts> for Mirror {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.mirror {
            return Err(());
        }
        Ok(Mirror::default())
    }
}

impl TryFrom<&Opts> for Path {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.path {
            return Err(());
        }
        Ok(Path::default())
    }
}

impl TryFrom<&Opts> for Phone {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.phone {
            return Err(());
        }
        Ok(Phone::default())
    }
}

impl TryFrom<&Opts> for Semver {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.semver {
            return Err(());
        }
        Ok(Semver::default())
    }
}

impl TryFrom<&Opts> for URI {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !(opts.scheme.is_some() || opts.url || opts.http || opts.https) {
            return Err(());
        }
        let mut finder = URI::default();
        finder.strict = opts.strict;
        if let Some(Some(ref scheme)) = opts.scheme {
            for s in scheme.split(',') {
                finder.add_scheme(s);
            }
        }
        if opts.url {
            finder.add_scheme("data");
            finder.add_scheme("ftp");
            finder.add_scheme("ftps");
            finder.add_scheme("http");
            finder.add_scheme("https");
            finder.add_scheme("mailto");
            finder.add_scheme("sftp");
            finder.add_scheme("ws");
            finder.add_scheme("wss");
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

impl TryFrom<&Opts> for Uuid {
    type Error = ();
    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !opts.uuid {
            return Err(());
        }
        Ok(Uuid::default())
    }
}

fn build_finders(opts: &Opts) -> Vec<Box<dyn Finder>> {
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
    if let Ok(f) = TryInto::<Hash>::try_into(opts) {
        finders.push(Box::new(f));
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
    finders
}

/// Whether the requested options require collecting all matches before output.
fn must_buffer(opts: &Opts) -> bool {
    opts.last || opts.sort || opts.uniq || opts.copy || opts.output != Format::Text
}

fn write_formatted<W: Write>(out: &mut W, results: &[String], format: Format) -> io::Result<()> {
    match format {
        Format::Text => {
            for r in results {
                writeln!(out, "{}", r)?;
            }
        }
        Format::Json => {
            out.write_all(b"[")?;
            for (i, r) in results.iter().enumerate() {
                if i > 0 {
                    out.write_all(b",")?;
                }
                write_json_string(out, r)?;
            }
            out.write_all(b"]\n")?;
        }
        Format::Yaml => {
            for r in results {
                write!(out, "- ")?;
                write_yaml_scalar(out, r)?;
                writeln!(out)?;
            }
        }
        Format::Csv => {
            for r in results {
                write_csv_field(out, r)?;
                writeln!(out)?;
            }
        }
    }
    Ok(())
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

fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(text).map_err(|e| e.to_string())?;
    Ok(())
}

fn scan_lines_sequential(
    scanner: &Scanner,
    opts: &Opts,
    reader: &mut dyn BufRead,
    out: &mut dyn Write,
    buffered: &mut Option<Vec<String>>,
) -> io::Result<bool> {
    let mut line = String::new();
    let mut matches_buf = Vec::new();
    let mut last_match: Option<String> = None;

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                log::error!("failed to read line: {}", e);
                continue;
            }
        }
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

        if opts.first {
            if let Some(m) = scanner.scan_line_first(trimmed) {
                let found = &trimmed[m.range];
                if !found.is_empty() {
                    if let Some(b) = buffered.as_mut() {
                        b.push(found.to_string());
                    } else {
                        writeln!(out, "{}", found)?;
                        if opts.open
                            && let Err(e) = open_url(found)
                        {
                            eprintln!("failed to open '{}': {}", found, e);
                        }
                    }
                    return Ok(true);
                }
            }
        } else {
            scanner.scan_line_into(trimmed, &mut matches_buf);
            for m in &matches_buf {
                let found = &trimmed[m.range.clone()];
                if found.is_empty() {
                    continue;
                }
                if let Some(b) = buffered.as_mut() {
                    if opts.last {
                        last_match = Some(found.to_string());
                    } else {
                        b.push(found.to_string());
                    }
                } else {
                    writeln!(out, "{}", found)?;
                    if opts.open
                        && let Err(e) = open_url(found)
                    {
                        eprintln!("failed to open '{}': {}", found, e);
                    }
                }
            }
        }
    }

    if opts.last
        && let (Some(b), Some(last)) = (buffered.as_mut(), last_match)
    {
        b.push(last);
    }

    Ok(false)
}

fn scan_lines_parallel(scanner: &Scanner, opts: &Opts, lines: Vec<String>) -> Vec<String> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.jobs)
        .build()
        .expect("failed to build thread pool");

    pool.install(|| {
        lines
            .par_iter()
            .map(|line| {
                let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                let mut out = Vec::new();
                if opts.first {
                    if let Some(m) = scanner.scan_line_first(trimmed) {
                        let f = &trimmed[m.range];
                        if !f.is_empty() {
                            out.push(f.to_string());
                        }
                    }
                } else {
                    let mut buf = Vec::new();
                    scanner.scan_line_into(trimmed, &mut buf);
                    for m in &buf {
                        let f = &trimmed[m.range.clone()];
                        if !f.is_empty() {
                            out.push(f.to_string());
                        }
                    }
                }
                out
            })
            .reduce(Vec::new, |mut a, mut b| {
                a.append(&mut b);
                a
            })
    })
}

fn main() -> ExitCode {
    env_logger::init();

    let opts = Opts::parse();
    let finders = build_finders(&opts);

    if finders.is_empty() {
        return ExitCode::SUCCESS;
    }

    if opts.jobs == 0 {
        eprintln!("--jobs must be >= 1");
        return ExitCode::FAILURE;
    }

    let scanner = Scanner::new(finders);
    let stdout = io::stdout().lock();
    let mut out = BufWriter::new(stdout);

    let buffered = must_buffer(&opts);
    let mut buffer: Option<Vec<String>> = if buffered { Some(Vec::new()) } else { None };

    if opts.jobs > 1 {
        // Parallel mode: read all input then process.
        let mut input = String::new();
        if let Err(e) = io::stdin().lock().read_to_string(&mut input) {
            log::error!("failed to read stdin: {}", e);
            return ExitCode::FAILURE;
        }
        let lines: Vec<String> = input.lines().map(String::from).collect();
        let mut results = scan_lines_parallel(&scanner, &opts, lines);
        if opts.first {
            results.truncate(1);
        }
        if opts.last && !results.is_empty() {
            let last = results.pop().unwrap();
            results.clear();
            results.push(last);
        }
        if let Some(b) = buffer.as_mut() {
            *b = results;
        } else {
            for r in &results {
                let _ = writeln!(out, "{}", r);
                if opts.open
                    && let Err(e) = open_url(r)
                {
                    eprintln!("failed to open '{}': {}", r, e);
                }
            }
        }
    } else {
        let mut stdin = io::stdin().lock();
        if let Err(e) = scan_lines_sequential(&scanner, &opts, &mut stdin, &mut out, &mut buffer) {
            log::error!("error during scanning: {}", e);
            return ExitCode::FAILURE;
        }
    }

    if let Some(mut results) = buffer {
        if opts.sort {
            results.sort();
        }
        if opts.uniq {
            let mut seen = std::collections::HashSet::new();
            results.retain(|r| seen.insert(r.clone()));
        }

        let mut formatted = Vec::new();
        if let Err(e) = write_formatted(&mut formatted, &results, opts.output) {
            log::error!("formatting failed: {}", e);
            return ExitCode::FAILURE;
        }

        if opts.copy {
            let text = String::from_utf8_lossy(&formatted);
            if let Err(e) = copy_to_clipboard(&text) {
                eprintln!("failed to copy to clipboard: {}", e);
            }
        }

        if let Err(e) = out.write_all(&formatted) {
            log::error!("output failed: {}", e);
            return ExitCode::FAILURE;
        }

        if opts.open {
            for r in &results {
                if let Err(e) = open_url(r) {
                    eprintln!("failed to open '{}': {}", r, e);
                }
            }
        }
    }

    ExitCode::SUCCESS
}

fn open_url(url: &str) -> io::Result<()> {
    open::that(url).map_err(io::Error::other)
}
