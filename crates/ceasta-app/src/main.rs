//! GUI binary — eframe shell around `ceasta_ui::CeastaApp`.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let initial = env::args().nth(1).map(PathBuf::from);

    let options = ceasta_ui::native_options();
    let result = eframe::run_native(
        "ceasta",
        options,
        Box::new(move |cc| Ok(Box::new(ceasta_ui::CeastaApp::new(cc, initial)))),
    );

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("eframe error: {e}");
            ExitCode::from(1)
        }
    }
}
