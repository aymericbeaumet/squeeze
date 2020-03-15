use clap::Clap;
use log::debug;
use squeeze::{codetag::Codetag, uri::URI, Finder};
use std::convert::{TryFrom, TryInto};
use std::io::{self, BufRead};

#[derive(Clap)]
#[clap(
    name = "squeeze",
    version = "1.0",
    author = "Aymeric Beaumet <hi@aymericbeaumet.com>"
)]
struct Opts {
    // flags
    #[clap(short = "1", long = "--first", help = "only show the first result")]
    first: bool,

    // codetag
    #[clap(long = "codetag", help = "search for codetags")]
    codetag: Option<Option<String>>,
    #[clap(
        long = "hide-mnemonic",
        help = "whether to show the mnemonics in the results"
    )]
    hide_mnemonic: bool,
    #[clap(long = "fixme", help = "alias for: --codetag=fixme")]
    fixme: bool,
    #[clap(long = "todo", help = "alias for: --codetag=todo")]
    todo: bool,

    // uri
    #[clap(long = "uri", help = "search for uris")]
    uri: Option<Option<String>>,
    #[clap(
        long = "url",
        help = "alias for: --uri=data,ftp,ftps,http,https,mailto,sftp,ws,wss"
    )]
    url: bool,
    #[clap(long = "http", help = "alias for: --uri=http")]
    http: bool,
    #[clap(long = "https", help = "alias for: --uri=https")]
    https: bool,
}

impl TryFrom<&Opts> for Codetag {
    type Error = ();

    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !(opts.codetag.is_some() || opts.fixme || opts.todo) {
            return Err(());
        }

        let mut finder = Codetag::default();
        finder.hide_mnemonic = opts.hide_mnemonic;
        if let Some(Some(ref mnemonic)) = opts.codetag {
            for m in mnemonic.split(",") {
                finder.add_mnemonic(m);
            }
        }
        if opts.fixme {
            finder.add_mnemonic("fixme");
        }
        if opts.todo {
            finder.add_mnemonic("todo");
        }
        finder.build_mnemonics_regex().unwrap();
        Ok(finder)
    }
}

impl TryFrom<&Opts> for URI {
    type Error = ();

    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !(opts.uri.is_some() || opts.url || opts.http || opts.https) {
            return Err(());
        }

        let mut finder = URI::default();
        if let Some(Some(ref uri)) = opts.uri {
            for s in uri.split(",") {
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

fn main() {
    pretty_env_logger::init();
    let opts = Opts::parse();

    let codetag = TryInto::<Codetag>::try_into(&opts);
    let uri = TryInto::<URI>::try_into(&opts);

    let finders: Vec<_> = [
        codetag.as_ref().map(|f| f as &dyn Finder),
        uri.as_ref().map(|f| f as &dyn Finder),
    ]
    .iter()
    .filter_map(|finder| finder.ok())
    .collect();

    if finders.is_empty() {
        return;
    }

    for line in io::stdin().lock().lines() {
        let line = &line.unwrap();
        for finder in &finders {
            debug!("[{}] line \"{}\"", finder.id(), line);
            let mut idx = 0;
            while idx < line.len() {
                let segment = &line[idx..];
                debug!("[{}] searching in \"{}\"", finder.id(), segment);
                if let Some(range) = finder.find(segment) {
                    debug!("[{}] found at [{};{}[", finder.id(), range.start, range.end);
                    idx += range.end;
                    let found = &segment[range].trim();
                    if found.len() > 0 {
                        println!("{}", found);
                        if opts.first {
                            return;
                        }
                    }
                } else {
                    break;
                }
            }
        }
    }
}
