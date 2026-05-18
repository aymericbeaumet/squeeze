use clap::Parser;
use squeeze::{
    cidr::Cidr, codetag::Codetag, color::Color, datetime::Datetime, email::Email, emoji::Emoji,
    env::Env, hash::Hash, ip::Ip, json::Json, jwt::Jwt, mac::Mac, mirror::Mirror, path::Path,
    phone::Phone, scanner::Scanner, semver::Semver, uri::URI, uuid::Uuid, Finder,
};
use std::convert::{TryFrom, TryInto};
use std::io::{self, BufRead, BufWriter, Write};
use std::process::ExitCode;

const VERSION: &str = match option_env!("SQUEEZE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

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
    #[arg(long = "open", help = "open the results")]
    open: bool,

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

    // email
    #[arg(long = "email", help = "search for email addresses")]
    email: bool,

    // emoji
    #[arg(long = "emoji", help = "search for emojis")]
    emoji: bool,

    // env
    #[arg(long = "env", help = "search for environment variables")]
    env: bool,

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

fn main() -> ExitCode {
    env_logger::init();

    let opts = Opts::parse();

    let mut finders: Vec<Box<dyn Finder>> = Vec::new();
    if let Ok(f) = TryInto::<Cidr>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Codetag>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Color>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Datetime>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Email>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Emoji>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Env>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Hash>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Ip>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Json>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Jwt>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Mac>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Mirror>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Path>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Phone>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Semver>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<URI>::try_into(&opts) {
        finders.push(Box::new(f));
    }
    if let Ok(f) = TryInto::<Uuid>::try_into(&opts) {
        finders.push(Box::new(f));
    }

    if finders.is_empty() {
        return ExitCode::SUCCESS;
    }

    let scanner = Scanner::new(finders);

    let stdout = io::stdout().lock();
    let mut out = BufWriter::new(stdout);

    for line in io::stdin().lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                log::error!("failed to read line: {}", e);
                continue;
            }
        };

        if opts.first {
            if let Some(m) = scanner.scan_line_first(&line) {
                let found = &line[m.range];
                if !found.is_empty() {
                    let _ = writeln!(out, "{}", found);
                    if opts.open {
                        if let Err(e) = open_url(found) {
                            eprintln!("failed to open '{}': {}", found, e);
                        }
                    }
                    return ExitCode::SUCCESS;
                }
            }
        } else {
            for m in scanner.scan_line(&line) {
                let found = &line[m.range];
                if !found.is_empty() {
                    let _ = writeln!(out, "{}", found);
                    if opts.open {
                        if let Err(e) = open_url(found) {
                            eprintln!("failed to open '{}': {}", found, e);
                        }
                    }
                }
            }
        }
    }

    ExitCode::SUCCESS
}

fn open_url(url: &str) -> io::Result<()> {
    open::that(url).map_err(io::Error::other)
}
