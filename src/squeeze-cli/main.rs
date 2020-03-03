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
    #[clap(short = "1", long = "--first", help = "only keep the first result")]
    one: bool,
    #[clap(long = "uri", help = "attempt to match absolute uris")]
    uri: bool,
}

fn main() {
    pretty_env_logger::init();
    let opts = Opts::parse();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = &line.unwrap();
        debug!("INPUT LINE \"{}\"", line);
        if opts.uri {
            if let Some(uri) = squeeze::uri::find(line) {
                println!("{}", uri);
                if opts.one {
                    break;
                }
            }
        }
    }
}
