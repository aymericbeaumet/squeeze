use clap::Clap;
use std::io::{self, BufRead};

#[derive(Clap)]
#[clap(version = "1.0", author = "Aymeric Beaumet <hi@aymericbeaumet.com>")]
struct Opts {
    #[clap(short = "1")]
    one: bool,
    #[clap(long = "uri")]
    uri: bool,
}

fn main() {
    let opts = Opts::parse();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = &line.unwrap();
        if let (true, Some(uri)) = (opts.uri, squeeze::uri::find(line)) {
            println!("{}", uri);
            if opts.one {
                break;
            }
        }
    }
}
