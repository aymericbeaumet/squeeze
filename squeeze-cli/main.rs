use clap::Parser;
use squeeze::{codetag::Codetag, mirror::Mirror, uri::URI, Finder};
use std::convert::{TryFrom, TryInto};
use std::io::{self, BufRead};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "squeeze",
    version = env!("CARGO_PKG_VERSION"),
    author = "Aymeric Beaumet <hi@aymericbeaumet.com>",
    about = "Extract rich information from any text"
)]
struct Opts {
    // flags
    #[arg(short = '1', long = "first", help = "only show the first result")]
    first: bool,
    #[arg(long = "open", help = "open the results")]
    open: bool,

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

    // mirror
    #[arg(long = "mirror", help = "[debug] mirror the input")]
    mirror: bool,

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

        let finder = Mirror::default();
        Ok(finder)
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

fn main() -> ExitCode {
    env_logger::init();

    let opts = Opts::parse();
    let codetag = TryInto::<Codetag>::try_into(&opts);
    let mirror = TryInto::<Mirror>::try_into(&opts);
    let uri = TryInto::<URI>::try_into(&opts);

    let finders: Vec<_> = [
        codetag.as_ref().map(|f| f as &dyn Finder),
        mirror.as_ref().map(|f| f as &dyn Finder),
        uri.as_ref().map(|f| f as &dyn Finder),
    ]
    .into_iter()
    .filter_map(|finder| finder.ok())
    .collect();

    if finders.is_empty() {
        return ExitCode::SUCCESS;
    }

    for line in io::stdin().lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                log::error!("failed to read line: {}", e);
                continue;
            }
        };

        for finder in &finders {
            log::debug!("[{}] line \"{}\"", finder.id(), line);
            let mut idx = 0;
            while idx < line.len() {
                let segment = &line[idx..];
                log::debug!("[{}] searching in \"{}\"", finder.id(), segment);
                if let Some(range) = finder.find(segment) {
                    log::debug!("[{}] found at [{};{}[", finder.id(), range.start, range.end);
                    idx += range.end;
                    let found = &segment[range].trim();
                    if !found.is_empty() {
                        println!("{}", found);
                        if opts.open {
                            if let Err(e) = open_url(found) {
                                eprintln!("failed to open '{}': {}", found, e);
                            }
                        }
                        if opts.first {
                            return ExitCode::SUCCESS;
                        }
                    }
                } else {
                    break;
                }
            }
        }
    }

    ExitCode::SUCCESS
}

fn open_url(url: &str) -> io::Result<()> {
    open::that(url).map_err(io::Error::other)
}
