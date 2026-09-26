//! GUI binary scaffold — prints status until egui is wired.

fn main() {
    let state = ceasta_ui::AppState::default();
    println!("ceasta (rust native) — gui scaffold");
    println!("{}", state.summary());
    println!("protect_host={}, break_on_tls={}", state.dbg.options.protect_host, state.dbg.options.break_on_tls);
    println!("open a file with: ceasta-cli info <path>");
}
