//! GUI binary — loads a file when given a path; egui shell comes next.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut state = ceasta_ui::AppState::default();
    println!("ceasta (rust native)");
    println!(
        "protect_host={}, break_on_tls={}",
        state.dbg.options().protect_host,
        state.dbg.options().break_on_tls
    );

    if let Some(path) = env::args().nth(1) {
        match state.load_file(std::path::Path::new(&path)) {
            Ok(()) => println!("{}", state.summary()),
            Err(e) => {
                eprintln!("error: {e:#}");
                return ExitCode::from(1);
            }
        }
    } else {
        println!("{}", state.summary());
        println!("usage: ceasta <file>   or   ceasta-cli info <file>");
    }
    ExitCode::SUCCESS
}
