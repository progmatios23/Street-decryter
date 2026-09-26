//! `ceasta-cli` — Rust native entrypoint (parity with the C++ CLI).

use anyhow::{bail, Context, Result};
use ceasta_analysis::{build_cfg, find_bytes, run as analyze};
use ceasta_binary::{open_with, Arch, LoadOptions, PERM_R, PERM_W, PERM_X};
use ceasta_db::{
    diff_databases, export_ghidra, export_ida, export_x64dbg, import_names, make_signatures,
    match_signatures, search_everything, signatures_from_text, signatures_to_text, Database,
};
use ceasta_decompiler::decompile_function;
use ceasta_debugger::{attach_allowed, create as create_debugger, State as DbgState};
use ceasta_disasm::decode_at;
use ceasta_fileinfo;
use ceasta_mcp::{McpOptions, McpServer};
use ceasta_script::LuaHost;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "ceasta-cli",
    version = VERSION,
    about = "ceasta — disassembler / debugger (Rust native rewrite)",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,

    /// Load the file as raw x86 code
    #[arg(long = "raw32", global = true)]
    raw32: bool,
    /// Load the file as raw x64 code
    #[arg(long = "raw64", global = true)]
    raw64: bool,
    /// Load the file as raw arm64 code
    #[arg(long = "raw-arm64", global = true)]
    raw_arm64: bool,
    /// Base address for raw files
    #[arg(long = "base", global = true, value_name = "HEX")]
    base: Option<String>,
    /// Which part of a universal (fat) mach-o to open
    #[arg(long = "arch", global = true, value_name = "x64|arm64")]
    arch: Option<String>,
    /// Decompile with kuna when available
    #[arg(long = "kuna", global = true)]
    kuna: bool,
    #[arg(long = "kuna-path", global = true, value_name = "FILE")]
    kuna_path: Option<PathBuf>,
    /// For `run`: start the file under the debugger first
    #[arg(long = "debug", global = true)]
    debug: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Headers, security flags, hashes, sections
    Info { file: PathBuf },
    /// Functions: address, size, name
    Funcs { file: PathBuf },
    /// Imported functions
    Imports { file: PathBuf },
    /// Exported symbols
    Exports { file: PathBuf },
    /// Strings found by analysis
    Strings { file: PathBuf },
    /// n listing lines starting at where (default: entry)
    Disasm {
        file: PathBuf,
        #[arg(default_value = "entry")]
        where_: String,
        #[arg(default_value_t = 40)]
        n: usize,
    },
    /// Listing of one function
    Func {
        file: PathBuf,
        where_: String,
    },
    /// Pseudocode for one function
    Decompile {
        file: PathBuf,
        where_: String,
    },
    /// Alias for decompile
    Pseudo {
        file: PathBuf,
        where_: String,
    },
    /// Basic blocks and edges of a function
    Graph {
        file: PathBuf,
        where_: String,
    },
    /// References to an address
    Xrefs {
        file: PathBuf,
        where_: String,
    },
    /// Byte search, like "48 8b ?? 05"
    Find {
        file: PathBuf,
        pattern: String,
    },
    /// Text search across functions, names, imports, exports, strings, …
    Search {
        file: PathBuf,
        text: String,
    },
    /// Match functions between two files
    Diff {
        old: PathBuf,
        new: PathBuf,
    },
    /// Write a project file (.ceasta) or tool exports
    Export {
        file: PathBuf,
        #[arg(long)]
        ida: Option<PathBuf>,
        #[arg(long)]
        ghidra: Option<PathBuf>,
        #[arg(long)]
        x64dbg: Option<PathBuf>,
    },
    /// Import names from .ceasta / .map / names JSON
    Import {
        file: PathBuf,
        names: PathBuf,
    },
    /// Make library signatures from a file that has symbols
    Sigmake {
        file: PathBuf,
        out: Option<PathBuf>,
    },
    /// Name matching functions from a .sig file
    Sigapply {
        file: PathBuf,
        sigs: PathBuf,
        #[arg(long)]
        save: bool,
    },
    /// Run a lua script against the file
    Run {
        file: PathBuf,
        script: PathBuf,
    },
    /// Interactive debugger
    Dbg {
        program: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Serve the file over the Model Context Protocol
    Mcp {
        file: PathBuf,
        #[arg(long)]
        allow_debug: bool,
        #[arg(long)]
        allow_lua: bool,
        /// Serve HTTP on [addr:]port instead of stdio (not yet ported)
        #[arg(long, value_name = "ADDR:PORT")]
        http: Option<String>,
        /// Print tool list + file info JSON and exit (no stdio loop)
        #[arg(long)]
        dump: bool,
    },
    /// Debugger smoke test
    Debug {
        exe: PathBuf,
        #[arg(default_value_t = 5)]
        steps: u32,
    },
    /// List PE TLS callbacks
    Tls { file: PathBuf },
    /// Why attach to a pid is refused (host protect)
    Protect { pid: u32 },
}

fn load_opts(cli: &Cli) -> Result<LoadOptions> {
    let mut opts = LoadOptions::default();
    if cli.raw32 {
        opts.force_raw = true;
        opts.raw_arch = Arch::X86;
    } else if cli.raw64 {
        opts.force_raw = true;
        opts.raw_arch = Arch::X64;
    } else if cli.raw_arm64 {
        opts.force_raw = true;
        opts.raw_arch = Arch::Arm64;
    }
    if let Some(ref b) = cli.base {
        let s = b.trim().trim_start_matches("0x").trim_start_matches("0X");
        opts.raw_base =
            u64::from_str_radix(s, 16).with_context(|| format!("bad base address {b}"))?;
    }
    if let Some(ref a) = cli.arch {
        opts.slice = Some(match a.as_str() {
            "x64" | "x86_64" | "amd64" => Arch::X64,
            "arm64" | "aarch64" => Arch::Arm64,
            other => bail!("--arch takes x64 or arm64, not {other}"),
        });
    }
    Ok(opts)
}

fn load_db(path: &PathBuf, opts: &LoadOptions) -> Result<Database> {
    let bin = open_with(path, opts).with_context(|| format!("open {}", path.display()))?;
    let analysis = analyze(&bin);
    let mut db = Database::new(bin, analysis);
    let proj = db.project_path();
    if proj.is_file() {
        if let Err(e) = db.load_project_file(&proj) {
            eprintln!("note: couldn't load {}: {e}", proj.display());
        }
    }
    Ok(db)
}

fn wait_dbg_stop(dbg: &mut dyn ceasta_debugger::Debugger, timeout_ms: u32) -> bool {
    let start = std::time::Instant::now();
    let limit = std::time::Duration::from_millis(timeout_ms as u64);
    while start.elapsed() < limit {
        if dbg.state() != DbgState::Running {
            return true;
        }
        dbg.poll(50);
    }
    dbg.state() != DbgState::Running
}

fn resolve_where(db: &Database, where_: &str) -> Result<u64> {
    db.resolve(where_)
        .ok_or_else(|| anyhow::anyhow!("unknown address or name: {where_}"))
}

fn escape(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn perms(p: u32) -> String {
    format!(
        "{}{}{}",
        if p & PERM_R != 0 { 'r' } else { '-' },
        if p & PERM_W != 0 { 'w' } else { '-' },
        if p & PERM_X != 0 { 'x' } else { '-' }
    )
}

fn print_disasm(db: &Database, mut addr: u64, n: usize) {
    for _ in 0..n {
        match decode_at(&db.bin, addr) {
            Ok(insn) => {
                let comment = db.comments.get(&addr);
                let mut line = format!(
                    "{}  {:<24} {}",
                    db.fmt_addr(addr),
                    hex_bytes(&insn.bytes[..insn.size as usize]),
                    insn.text
                );
                if let Some(c) = comment {
                    line.push_str("  ; ");
                    line.push_str(c);
                }
                println!("{line}");
                addr = insn.next();
            }
            Err(e) => {
                eprintln!("{}  ({e})", db.fmt_addr(addr));
                break;
            }
        }
    }
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn cmd_info(db: &Database) {
    let b = &db.bin;
    println!("file      {}", b.path);
    println!(
        "format    {} {} ({})",
        b.format.as_str(),
        b.arch.as_str(),
        b.kind
    );
    println!("base      {}", db.fmt_addr(b.base));
    if b.has_entry {
        println!(
            "entry     {} {}",
            db.fmt_addr(b.entry),
            db.name_at(b.entry)
        );
    } else {
        println!("entry     none");
    }
    println!(
        "counts    {} functions, {} imports, {} exports, {} strings, {} instructions",
        db.analysis.functions.len(),
        b.imports.len(),
        b.exports.len(),
        db.analysis.strings.len(),
        db.analysis.insn_count
    );
    if !b.libs.is_empty() {
        print!("libs     ");
        for l in &b.libs {
            print!(" {l}");
        }
        println!();
    }
    println!("segments");
    for s in &b.segments {
        println!(
            "  {:<10} {} - {}  {}  file 0x{:x}",
            s.name,
            db.fmt_addr(s.start),
            db.fmt_addr(s.end),
            perms(s.perms),
            s.file_size
        );
    }
    for n in &b.notes {
        println!("note: {n}");
    }

    let fi = ceasta_fileinfo::collect(b);
    println!();
    for (k, v) in &fi.header {
        if matches!(k.as_str(), "file" | "entry" | "base") {
            continue;
        }
        println!("{k:<14} {v}");
    }
    println!("sections (entropy: 8 is random)");
    for s in &fi.sections {
        println!(
            "  {:<12} {}  {:8x}  {}  {:.2}",
            s.name,
            db.fmt_addr(s.addr),
            s.size,
            s.perms,
            s.entropy
        );
    }
    for w in &fi.warnings {
        println!("warning: {w}");
    }
}

fn cmd_decompile(db: &Database, where_: &str, use_kuna: bool, kuna_path: Option<&PathBuf>) -> Result<()> {
    let addr = resolve_where(db, where_)?;
    let f = db
        .func_at(addr)
        .with_context(|| format!("no function at {}", db.fmt_addr(addr)))?;
    if use_kuna {
        let hint = match kuna_path {
            Some(p) => format!(" (looked for {})", p.display()),
            None => String::new(),
        };
        bail!("kuna decompiler not yet ported{hint}");
    }
    print!("{}", decompile_function(&db.bin, f));
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let opts = load_opts(&cli)?;

    match cli.cmd {
        Command::Info { file } => {
            let db = load_db(&file, &opts)?;
            cmd_info(&db);
        }
        Command::Funcs { file } => {
            let db = load_db(&file, &opts)?;
            for f in &db.analysis.functions {
                let name = {
                    let n = db.name_at(f.start);
                    if n.is_empty() {
                        f.name.clone()
                    } else {
                        n
                    }
                };
                println!(
                    "{}  {:6x}  {name}",
                    db.fmt_addr(f.start),
                    f.end - f.start
                );
            }
        }
        Command::Imports { file } => {
            let db = load_db(&file, &opts)?;
            for e in &db.bin.imports {
                let lib = if e.lib.is_empty() { "?" } else { &e.lib };
                println!("{}  {lib}!{}", db.fmt_addr(e.slot), e.name);
            }
        }
        Command::Exports { file } => {
            let db = load_db(&file, &opts)?;
            for e in &db.bin.exports {
                if e.forward.is_empty() {
                    println!(
                        "{}  {:5}  {}",
                        db.fmt_addr(e.addr),
                        e.ordinal,
                        e.name
                    );
                } else {
                    println!(
                        "{:<width$}  {:5}  {} -> {}",
                        "forward",
                        e.ordinal,
                        e.name,
                        e.forward,
                        width = db.fmt_addr(0).len()
                    );
                }
            }
        }
        Command::Strings { file } => {
            let db = load_db(&file, &opts)?;
            for s in &db.analysis.strings {
                let wide = if s.wide { "L" } else { "" };
                println!(
                    "{}  {wide}\"{}\"",
                    db.fmt_addr(s.addr),
                    escape(&s.text, 200)
                );
            }
        }
        Command::Disasm { file, where_, n } => {
            let db = load_db(&file, &opts)?;
            let addr = if where_ == "entry" {
                if !db.bin.has_entry {
                    bail!("no entry point, give an address");
                }
                db.bin.entry
            } else {
                resolve_where(&db, &where_)?
            };
            print_disasm(&db, addr, n);
        }
        Command::Func { file, where_ } => {
            let db = load_db(&file, &opts)?;
            let addr = resolve_where(&db, &where_)?;
            let f = db
                .func_at(addr)
                .with_context(|| format!("no function at {}", db.fmt_addr(addr)))?;
            let n = ((f.end - f.start) as usize).clamp(1, 4096);
            print_disasm(&db, f.start, n);
        }
        Command::Decompile { file, where_ } | Command::Pseudo { file, where_ } => {
            let db = load_db(&file, &opts)?;
            cmd_decompile(&db, &where_, cli.kuna, cli.kuna_path.as_ref())?;
        }
        Command::Graph { file, where_ } => {
            let db = load_db(&file, &opts)?;
            let addr = resolve_where(&db, &where_)?;
            let g = build_cfg(&db.bin, &db.analysis, addr)
                .with_context(|| format!("no function at {}", db.fmt_addr(addr)))?;
            for (i, blk) in g.blocks.iter().enumerate() {
                println!(
                    "block {i}  {} - {}  ({} insns)",
                    db.fmt_addr(blk.start),
                    db.fmt_addr(blk.end),
                    blk.insn_addrs.len()
                );
                for e in &blk.succ {
                    println!("    -> {} {}", e.to, e.kind.as_str());
                }
            }
            if g.truncated {
                println!("(truncated)");
            }
        }
        Command::Xrefs { file, where_ } => {
            let db = load_db(&file, &opts)?;
            let addr = resolve_where(&db, &where_)?;
            for x in db.analysis.refs_to(addr) {
                println!(
                    "{}  {:<6} {}",
                    db.fmt_addr(x.from),
                    x.kind.as_str(),
                    db.location(x.from)
                );
            }
        }
        Command::Find { file, pattern } => {
            let db = load_db(&file, &opts)?;
            let hits = find_bytes(&db.bin, &pattern, 1000).map_err(|e| anyhow::anyhow!(e))?;
            for a in hits {
                println!("{}  {}", db.fmt_addr(a), db.location(a));
            }
        }
        Command::Search { file, text } => {
            let db = load_db(&file, &opts)?;
            let (hits, cut) = search_everything(&db, &text, 200);
            for h in &hits {
                let at = if h.addr != 0 || h.kind != ceasta_db::HitKind::Export {
                    db.fmt_addr(h.addr)
                } else {
                    format!("{:<width$}", "forward", width = db.fmt_addr(0).len())
                };
                println!(
                    "{:<8}  {at}  {}{}{}",
                    h.kind.as_str(),
                    h.text,
                    if h.extra.is_empty() { "" } else { "    " },
                    h.extra
                );
            }
            if cut {
                println!("(there are more: this shows up to 200 of each kind)");
            }
            if hits.is_empty() {
                eprintln!("nothing matches \"{text}\"");
                return Ok(ExitCode::from(1));
            }
        }
        Command::Diff { old, new } => {
            let a = load_db(&old, &opts)?;
            let mut ob = opts.clone();
            if ob.slice.is_none() && a.bin.format == ceasta_binary::Format::MachO {
                ob.slice = Some(a.bin.arch);
            }
            let b = load_db(&new, &ob)?;
            let d = diff_databases(&a, &b);
            println!(
                "a: {}  ({} functions)",
                a.bin.name, d.funcs_a
            );
            println!(
                "b: {}  ({} functions)",
                b.bin.name, d.funcs_b
            );
            println!(
                "identical {}, changed {}, added {}, removed {}\n",
                d.identical.len(),
                d.changed.len(),
                d.added.len(),
                d.removed.len()
            );
            if !d.changed.is_empty() {
                println!("changed (most different first):");
                for p in &d.changed {
                    println!(
                        "  {:3.0}%  {:<30}  {} -> {}",
                        p.similarity * 100.0,
                        p.name,
                        a.fmt_addr(p.a),
                        b.fmt_addr(p.b)
                    );
                }
                println!();
            }
            if !d.added.is_empty() {
                println!("added (only in b):");
                for x in &d.added {
                    println!("  {}  {}", b.fmt_addr(*x), b.location(*x));
                }
                println!();
            }
            if !d.removed.is_empty() {
                println!("removed (only in a):");
                for x in &d.removed {
                    println!("  {}  {}", a.fmt_addr(*x), a.location(*x));
                }
            }
        }
        Command::Export {
            file,
            ida,
            ghidra,
            x64dbg,
        } => {
            let db = load_db(&file, &opts)?;
            let mut other = false;
            if let Some(path) = ida {
                std::fs::write(&path, export_ida(&db))
                    .with_context(|| format!("can't write {}", path.display()))?;
                println!(
                    "wrote {} ({} names, {} comments)",
                    path.display(),
                    db.names.len(),
                    db.comments.len()
                );
                other = true;
            }
            if let Some(path) = ghidra {
                std::fs::write(&path, export_ghidra(&db))
                    .with_context(|| format!("can't write {}", path.display()))?;
                println!(
                    "wrote {} ({} names, {} comments)",
                    path.display(),
                    db.names.len(),
                    db.comments.len()
                );
                other = true;
            }
            if let Some(path) = x64dbg {
                std::fs::write(&path, export_x64dbg(&db))
                    .with_context(|| format!("can't write {}", path.display()))?;
                println!(
                    "wrote {} ({} names, {} comments)",
                    path.display(),
                    db.names.len(),
                    db.comments.len()
                );
                other = true;
            }
            if !other {
                let path = db.save_project()?;
                println!("wrote {}", path.display());
            }
        }
        Command::Import { file, names } => {
            let mut db = load_db(&file, &opts)?;
            let r = import_names(&mut db, &names);
            if let Some(e) = r.error {
                eprintln!("{e}");
                return Ok(ExitCode::from(1));
            }
            let path = db.save_project()?;
            println!("{}\nsaved to {}", r.summary(), path.display());
        }
        Command::Sigmake { file, out } => {
            let db = load_db(&file, &opts)?;
            let sigs = make_signatures(&db);
            let out = out.unwrap_or_else(|| PathBuf::from(format!("{}.sig", db.bin.path)));
            std::fs::write(&out, signatures_to_text(&sigs))
                .with_context(|| format!("can't write {}", out.display()))?;
            println!("wrote {} signatures to {}", sigs.len(), out.display());
        }
        Command::Sigapply { file, sigs, save } => {
            let mut db = load_db(&file, &opts)?;
            let text = std::fs::read_to_string(&sigs)
                .with_context(|| format!("can't read {}", sigs.display()))?;
            let sigs = signatures_from_text(&text);
            let m = match_signatures(&mut db, &sigs, save);
            for hit in &m {
                println!("{}  {}", db.fmt_addr(hit.addr), hit.name);
            }
            println!(
                "{} signatures, matched {} function{}{}",
                sigs.len(),
                m.len(),
                if m.len() == 1 { "" } else { "s" },
                if save {
                    " (saved to the project file)"
                } else {
                    ""
                }
            );
            if save && !m.is_empty() {
                let _ = db.save_project()?;
            }
        }
        Command::Run { file, script } => {
            let db = load_db(&file, &opts)?;
            if cli.debug {
                let mut dbg = create_debugger();
                if let Err(e) = dbg.start(&file, "") {
                    eprintln!("--debug: {e}");
                    return Ok(ExitCode::from(1));
                }
                dbg.kill();
            }
            let mut host = LuaHost::new(db).map_err(|e| anyhow::anyhow!(e))?;
            host.exec_file(&script).map_err(|e| anyhow::anyhow!(e))?;
            host.run_registered().map_err(|e| anyhow::anyhow!(e))?;
            if host.command_names().is_empty() {
                println!("script finished (no commands registered)");
            } else {
                println!(
                    "ran {} command(s): {}",
                    host.command_names().len(),
                    host.command_names().join(", ")
                );
            }
        }
        Command::Dbg { program, args } => {
            // Minimal interactive smoke: start, wait for stop, print RIP, step a few times.
            let mut dbg = create_debugger();
            let arg_str = args.join(" ");
            match dbg.start(&program, &arg_str) {
                Err(ceasta_debugger::Error::Unsupported) => {
                    eprintln!("dbg: no debugger backend on this platform");
                    return Ok(ExitCode::from(1));
                }
                Err(e) => {
                    eprintln!("dbg: start failed: {e}");
                    return Ok(ExitCode::from(1));
                }
                Ok(()) => {}
            }
            if !wait_dbg_stop(&mut *dbg, 15_000) || dbg.state() != DbgState::Stopped {
                eprintln!("dbg: timed out waiting for the first stop");
                dbg.kill();
                return Ok(ExitCode::from(1));
            }
            let rip = dbg.pc().unwrap_or(0);
            println!(
                "stopped ({}) rip={:X}  reason={}",
                program.display(),
                rip,
                dbg.stop_reason()
            );
            for r in dbg.registers().unwrap_or_default() {
                if r.name == "rip" || r.name == "rsp" || r.name == "rax" {
                    println!("  {:6} {:X}", r.name, r.value);
                }
            }
            for i in 0..5 {
                if dbg.state() != DbgState::Stopped {
                    break;
                }
                let before = dbg.pc().unwrap_or(0);
                if let Err(e) = dbg.step_into() {
                    eprintln!("step {}: {e}", i + 1);
                    break;
                }
                if !wait_dbg_stop(&mut *dbg, 5_000) {
                    eprintln!("step {}: timed out", i + 1);
                    break;
                }
                let after = dbg.pc().unwrap_or(0);
                println!("step {}: {:X} -> {:X}", i + 1, before, after);
            }
            dbg.kill();
        }
        Command::Mcp {
            file,
            allow_debug,
            allow_lua,
            http,
            dump,
        } => {
            let db = load_db(&file, &opts)?;
            let mop = McpOptions {
                allow_debug,
                allow_lua,
            };
            let mcp = McpServer::new(&db, &mop);
            if let Some(addr) = http {
                eprintln!(
                    "mcp --http {addr}: HTTP transport not yet ported (use stdio without --http)"
                );
                return Ok(ExitCode::from(1));
            }
            if dump {
                println!("{}", serde_json::to_string_pretty(&mcp.tool_list())?);
                println!("{}", serde_json::to_string_pretty(&mcp.file_info())?);
            } else {
                mcp.serve_stdio().map_err(|e| anyhow::anyhow!(e))?;
            }
        }
        Command::Debug { exe, steps } => {
            let _db = load_db(&exe, &opts)?;
            let mut dbg = create_debugger();
            match dbg.start(&exe, "") {
                Err(ceasta_debugger::Error::Unsupported) => {
                    eprintln!("debug: no debugger backend on this platform");
                    return Ok(ExitCode::from(1));
                }
                Err(e) => {
                    eprintln!("debug: start failed: {e}");
                    return Ok(ExitCode::from(1));
                }
                Ok(()) => {}
            }
            if !wait_dbg_stop(&mut *dbg, 15_000) || dbg.state() != DbgState::Stopped {
                eprintln!("debug: timed out waiting for entry stop");
                dbg.kill();
                return Ok(ExitCode::from(1));
            }
            let rip = dbg.pc().unwrap_or(0);
            println!(
                "ok   stopped at entry rip={:X} ({})",
                rip,
                dbg.stop_reason()
            );
            for i in 0..steps {
                if dbg.state() != DbgState::Stopped {
                    break;
                }
                let before = dbg.pc().unwrap_or(0);
                if let Err(e) = dbg.step_into() {
                    eprintln!("FAIL step {}: {e}", i + 1);
                    break;
                }
                if !wait_dbg_stop(&mut *dbg, 5_000) || dbg.state() != DbgState::Stopped {
                    eprintln!("FAIL step {}: no stop", i + 1);
                    break;
                }
                let after = dbg.pc().unwrap_or(0);
                println!("ok   step {}: {:X} -> {:X}", i + 1, before, after);
            }
            for r in dbg.registers().unwrap_or_default() {
                println!("  {:8} {:016X}", r.name, r.value);
            }
            dbg.kill();
            println!("debugger smoke done");
        }
        Command::Tls { file } => {
            let db = load_db(&file, &opts)?;
            if db.bin.tls_callbacks.is_empty() {
                println!("no tls callbacks");
            } else {
                for (i, a) in db.bin.tls_callbacks.iter().enumerate() {
                    println!("{i}\t{:X}\t{}", a, db.location(*a));
                }
            }
        }
        Command::Protect { pid } => match attach_allowed(pid, true) {
            Ok(()) => println!("{pid}: ok to attach"),
            Err(e) => {
                println!("{e}");
                return Ok(ExitCode::from(2));
            }
        },
    }
    Ok(ExitCode::SUCCESS)
}
