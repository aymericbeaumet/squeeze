use clap::Clap;
use log::debug;
use std::io::{self, BufRead};

#[derive(Clap)]
#[clap(
    name = "squeeze",
    version = "1.0",
    author = "Aymeric Beaumet <hi@aymericbeaumet.com>"
)]
struct Opts {
    #[clap(short = "1", long = "--first", help = "stop after the first result")]
    first: bool,
    #[clap(long = "uri", help = "search for absolute uris")]
    uri: bool,
}

fn main() {
    pretty_env_logger::init();
    let opts = Opts::parse();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = &line.unwrap();

        if opts.uri {
            debug!("[URI] LINE \"{}\"", line);
            let mut idx = 0;
            while idx < line.len() {
                let segment = &line[idx..];
                debug!("[URI] SEARCHING IN \"{}\"", segment);
                if let Some(range) = squeeze::uri::find(segment) {
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

        // TODO: add other finders :)
    }
}
