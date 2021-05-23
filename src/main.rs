//
// ABNF parser - main.
//   Copyright (C) 2021 Toshiaki Takada
//

use abnf_parser::parser;
use std::env;

/// Show help.
fn print_help(program: &str) {
    println!("{} FILENAME", program);
}

/// Main.
fn main() {
    // Command line arguments.
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    if args.len() == 1 {
        print_help(&program);
    } else {
        match parser::parse_file(&args[1]) {
            Ok(_) => {}
            Err(e) => println!("Error: {:?}", e.to_string()),
        }
    }
}
