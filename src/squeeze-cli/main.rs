use clap::Clap;
use log::debug;
use squeeze::{codetag::Codetag, uri, Finder};
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
    uri: bool,
    #[clap(long = "schemes", help = "limit uris search to these schemes")]
    scheme: Option<String>,
    #[clap(
        long = "url",
        help = "alias for: --uri --scheme=data,ftp,ftps,http,https,mailto,sftp,ws,wss"
    )]
    url: bool,
    #[clap(long = "http", help = "alias for: --uri --scheme=http")]
    http: bool,
    #[clap(long = "https", help = "alias for: --uri --scheme=https")]
    https: bool,
}

impl TryFrom<&Opts> for Codetag {
    type Error = ();

    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !(opts.codetag.is_some() || opts.fixme || opts.todo) {
            return Err(());
        }
        let codetag = opts.codetag.as_ref().unwrap();

        let mut mnemonics = codetag
            .as_ref()
            .map(|m| m.split(",").collect::<Vec<_>>())
            .unwrap_or(vec![]);

        if opts.fixme {
            mnemonics.push("fixme");
        }

        if opts.todo {
            mnemonics.push("todo");
        }

        let mut finder = Codetag::new(mnemonics);
        finder.show_mnemonic = !opts.hide_mnemonic;
        Ok(finder)
    }
}

impl TryFrom<&Opts> for uri::Config {
    type Error = ();

    fn try_from(opts: &Opts) -> Result<Self, Self::Error> {
        if !(opts.uri || opts.url || opts.http || opts.https) {
            return Err(());
        }

        let mut c = uri::Config::default();
        if opts.url {
            c.scheme("data");
            c.scheme("ftp");
            c.scheme("ftps");
            c.scheme("http");
            c.scheme("https");
            c.scheme("mailto");
            c.scheme("sftp");
            c.scheme("ws");
            c.scheme("wss");
        }
        if opts.http {
            c.scheme("http");
        }
        if opts.https {
            c.scheme("https");
        }
        if let Some(ref scheme) = opts.scheme {
            for s in scheme.split(",") {
                c.scheme(s);
            }
        }
        Ok(c)
    }
}

fn main() {
    pretty_env_logger::init();
    let opts = Opts::parse();

    let codetag: Result<Codetag, _> = (&opts).try_into();
    let uri_config = (&opts).try_into();

    if codetag.is_err() && uri_config.is_err() {
        return;
    }

    for line in io::stdin().lock().lines() {
        let line = &line.unwrap();

        if let Ok(ref finder) = codetag {
            debug!("[CODETAG] LINE \"{}\"", line);
            let segment = line;
            debug!("[CODETAG] SEARCHING IN \"{}\"", segment);
            if let Some(range) = finder.find(segment) {
                debug!("[CODETAG] FOUND AT [{};{}[", range.start, range.end);
                println!("{}", &segment[range].trim());
                if opts.first {
                    return;
                }
            }
        }

        if let Ok(ref config) = uri_config {
            debug!("[URI] LINE \"{}\"", line);
            let mut idx = 0;
            while idx < line.len() {
                let segment = &line[idx..];
                debug!("[URI] SEARCHING IN \"{}\"", segment);
                if let Some(range) = uri::find(segment, config) {
                    debug!("[URI] FOUND AT [{};{}[", range.start, range.end);
                    idx += range.end;
                    println!("{}", &segment[range].trim());
                    if opts.first {
                        return;
                    }
                } else {
                    break;
                }
            }
        }
    }
}
