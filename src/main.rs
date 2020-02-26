mod lib;

use std::io::{self, BufRead};

fn main() {
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line = &line.unwrap();
        if let Some(uri) = lib::squeeze_uri(line) {
            println!("{}", uri);
        }
    }
}
