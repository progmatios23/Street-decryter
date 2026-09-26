//! `ceasta-cli` — Rust native entrypoint (parity with the C++ CLI grows over time).

use anyhow::{bail, Context, Result};
use ceasta_analysis::run as analyze;
use ceasta_binary::{open, Binary};
use ceasta_db::Database;
use ceasta_decompiler::decompile_function;
use ceasta_debugger::attach_allowed;
use ceasta_disasm::decode_at;
use ceasta_mcp::McpServer;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ceasta-cli",
    version,
    about = "ceasta — disassembler / debugger (Rust native rewrite)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Headers, arch, TLS callbacks, segment summary
    Info { file: PathBuf },
    /// Functions discovered so far
    Funcs { file: PathBuf },
    /// Disassemble n instructions from where (hex or entry)
    Disasm {
        file: PathBuf,
        #[arg(default_value = "entry")]
        where_: String,
        #[arg(default_value_t = 20)]
        n: usize,
    },
    /// Pseudocode scaffold for a function
    Decompile {
        file: PathBuf,
        where_: String,
    },
    /// List PE TLS callbacks
    Tls { file: PathBuf },
    /// Why attach to a pid is refused (host protect)
    Protect { pid: u32 },
    /// MCP tool list / file info JSON (stdio scaffold)
    Mcp {
        file: PathBuf,
        #[arg(long)]
        allow_debug: bool,
    },
}

fn load_db(path: &PathBuf) -> Result<Database> {
    let bin = open(path).with_context(|| format!("open {}", path.display()))?;
    let analysis = analyze(&bin);
    Ok(Database::new(bin, analysis))
}

fn resolve(bin: &Binary, where_: &str) -> Result<u64> {
    if where_ == "entry" {
        if !bin.has_entry {
            bail!("file has no entry");
        }
        return Ok(bin.entry);
    }
    let s = where_.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).with_context(|| format!("bad address {where_}"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Info { file } => {
            let db = load_db(&file)?;
            let b = &db.bin;
            println!("{}  —  {} {}, {}", b.name, b.format.as_str(), b.arch.as_str(), b.kind);
            println!("  path   {}", b.path);
            println!("  base   {:X}", b.base);
            if b.has_entry {
                println!("  entry  {:X}", b.entry);
            }
            println!(
                "  {} segments, {} imports, {} exports, {} functions, {} strings",
                b.segments.len(),
                b.imports.len(),
                b.exports.len(),
                db.analysis.functions.len(),
                db.analysis.strings.len()
            );
            if !b.tls_callbacks.is_empty() {
                println!("  tls callbacks: {}", b.tls_callbacks.len());
                for (i, a) in b.tls_callbacks.iter().enumerate() {
                    println!("    tls_callback_{i}  {a:X}  ({})", db.location(*a));
                }
            }
            for n in &b.notes {
                println!("  note: {n}");
            }
        }
        Command::Funcs { file } => {
            let db = load_db(&file)?;
            for f in &db.analysis.functions {
                println!(
                    "{:016X}  {:>6}  {}",
                    f.start,
                    f.end - f.start,
                    f.name
                );
            }
        }
        Command::Disasm { file, where_, n } => {
            let db = load_db(&file)?;
            let mut addr = resolve(&db.bin, &where_)?;
            for _ in 0..n {
                match decode_at(&db.bin, addr) {
                    Ok(insn) => {
                        println!("{addr:016X}  {}", insn.text);
                        addr += u64::from(insn.size);
                    }
                    Err(e) => {
                        eprintln!("{addr:016X}  ({e})");
                        break;
                    }
                }
            }
        }
        Command::Decompile { file, where_ } => {
            let db = load_db(&file)?;
            let addr = resolve(&db.bin, &where_)?;
            let func = db
                .analysis
                .functions
                .iter()
                .find(|f| addr >= f.start && addr < f.end)
                .with_context(|| format!("no function at {addr:X}"))?;
            print!("{}", decompile_function(&db.bin, func));
        }
        Command::Tls { file } => {
            let db = load_db(&file)?;
            if db.bin.tls_callbacks.is_empty() {
                println!("no tls callbacks");
            } else {
                for (i, a) in db.bin.tls_callbacks.iter().enumerate() {
                    println!("{i}\t{a:X}\t{}", db.location(*a));
                }
            }
        }
        Command::Protect { pid } => match attach_allowed(pid, true) {
            Ok(()) => println!("{pid}: ok to attach"),
            Err(e) => {
                println!("{e}");
                std::process::exit(2);
            }
        },
        Command::Mcp { file, allow_debug } => {
            let db = load_db(&file)?;
            let mcp = McpServer {
                db: &db,
                allow_debug,
            };
            println!("{}", serde_json::to_string_pretty(&mcp.tool_list())?);
            println!("{}", serde_json::to_string_pretty(&mcp.file_info())?);
        }
    }
    Ok(())
}
