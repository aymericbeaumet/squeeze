use clap::Clap;
use log::debug;
use squeeze::uri;
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
    #[clap(short = "1", long = "--first", help = "stop after the first result")]
    first: bool,

    // uri
    #[clap(long = "uri", help = "search for absolute uris")]
    uri: bool,
    #[clap(long = "scheme", help = "limit uris search to the following schemes")]
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

    let uri_config = (&opts).try_into();

    for line in io::stdin().lock().lines() {
        let line = &line.unwrap();

        if let Ok(ref config) = uri_config {
            debug!("[URI] LINE \"{}\"", line);
            let mut idx = 0;
            while idx < line.len() {
                let segment = &line[idx..];
                debug!("[URI] SEARCHING IN \"{}\"", segment);
                if let Some(range) = uri::find(segment, config) {
                    debug!("[URI] FOUND AT [{};{}[", range.start, range.end);
                    idx += range.end;
                    println!("{}", &segment[range]);
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
