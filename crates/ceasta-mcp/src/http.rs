//! Localhost HTTP transport: MCP JSON-RPC + analysis/debug control API.

use crate::{disasm_lines, Error, McpOptions, McpServer, Result};
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ceasta_db::Database;
use ceasta_debugger::{create_shared, Debugger, SharedDebugger, State as DbgState};
use ceasta_decompiler::decompile_function;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Shared app state for all HTTP handlers. The debugger is behind a `Mutex` so
/// axum workers can share one Linux/ptrace (or stub) backend from `create()`.
#[derive(Clone)]
pub struct HttpState {
    pub db: Arc<Database>,
    pub allow_debug: bool,
    pub allow_lua: bool,
    pub debugger: SharedDebugger,
}

impl HttpState {
    pub fn new(db: Database, opts: &McpOptions) -> Self {
        Self {
            db: Arc::new(db),
            allow_debug: opts.allow_debug,
            allow_lua: opts.allow_lua,
            debugger: create_shared(),
        }
    }

    fn mcp<'a>(&'a self) -> McpServer<'a> {
        McpServer {
            db: &self.db,
            allow_debug: self.allow_debug,
            allow_lua: self.allow_lua,
            debugger: Some(self.debugger.as_ref()),
        }
    }
}

/// Parse `--http` specs: `8744`, `:8744`, or `127.0.0.1:8744`.
/// Bare ports bind **127.0.0.1** only (localhost). An explicit host is honored.
pub fn parse_bind_addr(spec: &str) -> Result<SocketAddr> {
    let s = spec.trim();
    if s.is_empty() {
        return Err(Error::Msg("empty --http address".into()));
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }
    if let Some(rest) = s.strip_prefix(':') {
        if let Ok(port) = rest.parse::<u16>() {
            return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
    }
    s.parse::<SocketAddr>()
        .map_err(|e| Error::Msg(format!("bad --http address `{s}`: {e}")))
}

/// Build the router (also used by unit tests via `oneshot`).
pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/", get(health))
        .route("/info", get(info))
        .route("/tools", get(tools))
        .route("/mcp", post(mcp_rpc).get(mcp_hint))
        .route("/functions", get(functions))
        .route("/strings", get(strings))
        .route("/imports", get(imports))
        .route("/exports", get(exports))
        .route("/disasm", get(disasm))
        .route("/decompile", get(decompile))
        .route("/xrefs", get(xrefs))
        .route("/debug/start", post(debug_start))
        .route("/debug/attach", post(debug_attach))
        .route("/debug/step", post(debug_step))
        .route("/debug/cont", post(debug_cont))
        .route("/debug/kill", post(debug_kill))
        .route("/debug/state", get(debug_state))
        .layer(middleware::from_fn(local_only_guard))
        .with_state(state)
}

/// Bind and serve until Ctrl-C (or fatal accept error).
pub async fn serve_http(db: Database, opts: &McpOptions, addr: SocketAddr) -> Result<()> {
    let state = HttpState::new(db, opts);
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Msg(format!("couldn't listen on {addr}: {e}")))?;
    let bound = listener
        .local_addr()
        .map_err(|e| Error::Msg(e.to_string()))?;
    eprintln!("ceasta mcp http://{bound}/mcp  (analysis + control API on same port)");
    eprintln!("  GET  /health /info /tools /functions /strings /imports /exports");
    eprintln!("  GET  /disasm?addr=&n=  /decompile?addr=  /xrefs?addr=");
    eprintln!("  POST /mcp  (JSON-RPC)   POST /debug/{{start,attach,step,cont,kill}}  GET /debug/state");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| Error::Msg(format!("http server error: {e}")))?;
    Ok(())
}

/// Blocking entry used by the CLI (`ceasta-cli mcp FILE --http …`).
pub fn serve_http_blocking(db: Database, opts: &McpOptions, bind: &str) -> Result<()> {
    let addr = parse_bind_addr(bind)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Msg(format!("tokio runtime: {e}")))?;
    rt.block_on(serve_http(db, opts, addr))
}

// --- local-only guard (Origin / Host), matching the C++ transport ---

async fn local_only_guard(req: Request, next: Next) -> Response {
    let headers = req.headers();
    let origin = header_str(headers, header::ORIGIN);
    let host = header_str(headers, header::HOST);
    if let Some(o) = origin {
        if !is_local_origin(o) {
            return (
                StatusCode::FORBIDDEN,
                "only clients on this machine may use this server\n",
            )
                .into_response();
        }
    }
    if let Some(h) = host {
        if !is_local_host(h) {
            return (
                StatusCode::FORBIDDEN,
                "only clients on this machine may use this server\n",
            )
                .into_response();
        }
    }
    next.run(req).await
}

fn header_str<'a>(headers: &'a HeaderMap, name: axum::http::HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn is_local_host(host: &str) -> bool {
    let host = host.trim();
    let host = if host.starts_with('[') {
        host.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
}

fn is_local_origin(origin: &str) -> bool {
    let o = origin.trim();
    if o.eq_ignore_ascii_case("null") {
        return true;
    }
    if let Ok(url) = o.parse::<LiteUrl>() {
        return is_local_host(&url.host);
    }
    let lower = o.to_ascii_lowercase();
    lower.contains("://localhost") || lower.contains("://127.0.0.1") || lower.contains("://[::1]")
}

struct LiteUrl {
    host: String,
}

impl std::str::FromStr for LiteUrl {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, ()> {
        let rest = s.split_once("://").map(|(_, r)| r).ok_or(())?;
        let hostport = rest.split('/').next().unwrap_or(rest);
        let host = if hostport.starts_with('[') {
            hostport
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or("")
                .to_string()
        } else {
            hostport.split(':').next().unwrap_or(hostport).to_string()
        };
        if host.is_empty() {
            return Err(());
        }
        Ok(Self { host })
    }
}

// --- handlers ---

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ceasta mcp\n")
}

async fn mcp_hint() -> impl IntoResponse {
    (
        StatusCode::OK,
        "POST JSON-RPC to /mcp (initialize, tools/list, tools/call)\n",
    )
}

async fn info(State(st): State<HttpState>) -> Json<Value> {
    Json(st.mcp().file_info())
}

async fn tools(State(st): State<HttpState>) -> Json<Value> {
    Json(json!({ "tools": st.mcp().tools_schema() }))
}

async fn mcp_rpc(State(st): State<HttpState>, body: String) -> Response {
    let req: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": -32700, "message": format!("parse error: {e}") }
            }))
            .into_response();
        }
    };
    match st.mcp().handle_rpc(&req) {
        Some(resp) => Json(resp).into_response(),
        None => (StatusCode::NO_CONTENT, Body::empty()).into_response(),
    }
}

async fn functions(State(st): State<HttpState>) -> JsonResult {
    JsonResult(st.mcp().call_tool("list_functions", &json!({})))
}

async fn strings(State(st): State<HttpState>) -> JsonResult {
    JsonResult(st.mcp().call_tool("list_strings", &json!({})))
}

async fn imports(State(st): State<HttpState>) -> JsonResult {
    JsonResult(st.mcp().call_tool("list_imports", &json!({})))
}

async fn exports(State(st): State<HttpState>) -> JsonResult {
    JsonResult(st.mcp().call_tool("list_exports", &json!({})))
}

#[derive(Debug, Deserialize)]
struct AddrQuery {
    addr: Option<String>,
    address: Option<String>,
    n: Option<u64>,
    count: Option<u64>,
}

fn query_addr(db: &Database, q: &AddrQuery) -> Result<u64> {
    let raw = q
        .addr
        .as_deref()
        .or(q.address.as_deref())
        .ok_or_else(|| Error::Msg("addr required".into()))?;
    db.resolve(raw)
        .or_else(|| {
            let s = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).ok()
        })
        .ok_or_else(|| Error::Msg(format!("unknown address: {raw}")))
}

async fn disasm(State(st): State<HttpState>, Query(q): Query<AddrQuery>) -> JsonResult {
    let addr = match query_addr(&st.db, &q) {
        Ok(a) => a,
        Err(e) => return JsonResult(Err(e)),
    };
    let n = q.n.or(q.count).unwrap_or(20) as usize;
    JsonResult(Ok(json!(disasm_lines(&st.db, addr, n))))
}

async fn decompile(State(st): State<HttpState>, Query(q): Query<AddrQuery>) -> JsonResult {
    let addr = match query_addr(&st.db, &q) {
        Ok(a) => a,
        Err(e) => return JsonResult(Err(e)),
    };
    let f = match st.db.func_at(addr) {
        Some(f) => f,
        None => {
            return JsonResult(Err(Error::Msg(format!("no function at {addr:X}"))));
        }
    };
    JsonResult(Ok(json!({ "code": decompile_function(&st.db.bin, f) })))
}

async fn xrefs(State(st): State<HttpState>, Query(q): Query<AddrQuery>) -> JsonResult {
    let addr = match query_addr(&st.db, &q) {
        Ok(a) => a,
        Err(e) => return JsonResult(Err(e)),
    };
    JsonResult(
        st.mcp()
            .call_tool("get_xrefs_to", &json!({ "address": format!("{addr:X}") })),
    )
}

#[derive(Debug, Deserialize)]
struct StartBody {
    exe: Option<String>,
    args: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct AttachBody {
    pid: u32,
}

fn require_debug(st: &HttpState) -> Result<()> {
    if st.allow_debug {
        Ok(())
    } else {
        Err(Error::Msg(
            "debug API disabled (pass --allow-debug to ceasta-cli mcp)".into(),
        ))
    }
}

fn lock_dbg(st: &HttpState) -> Result<std::sync::MutexGuard<'_, Box<dyn Debugger>>> {
    st.debugger
        .lock()
        .map_err(|_| Error::Msg("debugger lock poisoned".into()))
}

fn wait_stop(dbg: &mut dyn Debugger, timeout_ms: u32) -> bool {
    let start = Instant::now();
    let limit = Duration::from_millis(timeout_ms as u64);
    while start.elapsed() < limit {
        if dbg.state() != DbgState::Running {
            return true;
        }
        dbg.poll(50);
    }
    dbg.state() != DbgState::Running
}

fn args_to_string(args: Option<&Value>) -> String {
    match args {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>()
            .join(" "),
        Some(other) => other.to_string(),
    }
}

fn dbg_err(e: ceasta_debugger::Error) -> Error {
    Error::Msg(e.to_string())
}

async fn debug_start(State(st): State<HttpState>, Json(body): Json<StartBody>) -> JsonResult {
    if let Err(e) = require_debug(&st) {
        return JsonResult(Err(e));
    }
    let exe = body
        .exe
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&st.db.bin.path));
    let arg_str = args_to_string(body.args.as_ref());
    let mut dbg = match lock_dbg(&st) {
        Ok(g) => g,
        Err(e) => return JsonResult(Err(e)),
    };
    if let Err(e) = dbg.start(&exe, &arg_str) {
        return JsonResult(Err(dbg_err(e)));
    }
    let stopped = wait_stop(&mut **dbg, 15_000);
    JsonResult(Ok(json!({
        "ok": true,
        "stopped": stopped,
        "state": format!("{:?}", dbg.state()).to_ascii_lowercase(),
        "pc": dbg.pc().ok().map(|p| format!("{p:X}")),
        "reason": dbg.stop_reason(),
        "pid": dbg.pid(),
    })))
}

async fn debug_attach(State(st): State<HttpState>, Json(body): Json<AttachBody>) -> JsonResult {
    if let Err(e) = require_debug(&st) {
        return JsonResult(Err(e));
    }
    // Explicit host-protect check before attach (also enforced inside the backend).
    if let Some(reason) = ceasta_host::protect_reason(body.pid, None) {
        return JsonResult(Err(Error::Msg(format!(
            "refusing to attach to {}: {reason} (protect this machine)",
            body.pid
        ))));
    }
    let mut dbg = match lock_dbg(&st) {
        Ok(g) => g,
        Err(e) => return JsonResult(Err(e)),
    };
    if let Err(e) = dbg.attach(body.pid) {
        return JsonResult(Err(dbg_err(e)));
    }
    JsonResult(Ok(json!({
        "ok": true,
        "state": format!("{:?}", dbg.state()).to_ascii_lowercase(),
        "pc": dbg.pc().ok().map(|p| format!("{p:X}")),
        "reason": dbg.stop_reason(),
        "pid": dbg.pid(),
    })))
}

async fn debug_step(State(st): State<HttpState>) -> JsonResult {
    if let Err(e) = require_debug(&st) {
        return JsonResult(Err(e));
    }
    let mut dbg = match lock_dbg(&st) {
        Ok(g) => g,
        Err(e) => return JsonResult(Err(e)),
    };
    let before = dbg.pc().ok();
    if let Err(e) = dbg.step_into() {
        return JsonResult(Err(dbg_err(e)));
    }
    let _ = wait_stop(&mut **dbg, 5_000);
    JsonResult(Ok(json!({
        "ok": true,
        "before": before.map(|p| format!("{p:X}")),
        "pc": dbg.pc().ok().map(|p| format!("{p:X}")),
        "state": format!("{:?}", dbg.state()).to_ascii_lowercase(),
        "reason": dbg.stop_reason(),
    })))
}

async fn debug_cont(State(st): State<HttpState>) -> JsonResult {
    if let Err(e) = require_debug(&st) {
        return JsonResult(Err(e));
    }
    let mut dbg = match lock_dbg(&st) {
        Ok(g) => g,
        Err(e) => return JsonResult(Err(e)),
    };
    if let Err(e) = dbg.cont() {
        return JsonResult(Err(dbg_err(e)));
    }
    JsonResult(Ok(json!({
        "ok": true,
        "state": format!("{:?}", dbg.state()).to_ascii_lowercase(),
    })))
}

async fn debug_kill(State(st): State<HttpState>) -> JsonResult {
    if let Err(e) = require_debug(&st) {
        return JsonResult(Err(e));
    }
    let mut dbg = match lock_dbg(&st) {
        Ok(g) => g,
        Err(e) => return JsonResult(Err(e)),
    };
    dbg.kill();
    JsonResult(Ok(json!({
        "ok": true,
        "state": format!("{:?}", dbg.state()).to_ascii_lowercase(),
    })))
}

async fn debug_state(State(st): State<HttpState>) -> JsonResult {
    if let Err(e) = require_debug(&st) {
        return JsonResult(Err(e));
    }
    let dbg = match lock_dbg(&st) {
        Ok(g) => g,
        Err(e) => return JsonResult(Err(e)),
    };
    let regs = dbg.registers().unwrap_or_default();
    let regs_json: Vec<Value> = regs
        .iter()
        .map(|r| json!({ "name": r.name, "value": format!("{:X}", r.value) }))
        .collect();
    JsonResult(Ok(json!({
        "state": format!("{:?}", dbg.state()).to_ascii_lowercase(),
        "pc": dbg.pc().ok().map(|p| format!("{p:X}")),
        "regs": regs_json,
        "reason": dbg.stop_reason(),
        "pid": dbg.pid(),
    })))
}

struct JsonResult(Result<Value>);

impl IntoResponse for JsonResult {
    fn into_response(self) -> Response {
        match self.0 {
            Ok(v) => Json(v).into_response(),
            Err(e) => {
                let msg = e.to_string();
                let status = if msg.contains("disabled") || msg.contains("refusing") {
                    StatusCode::FORBIDDEN
                } else if msg.contains("required") || msg.contains("unknown address") {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                (status, Json(json!({ "error": msg }))).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ceasta_analysis::run as analyze;
    use ceasta_binary::{Arch, Binary, Format, Segment, PERM_R, PERM_X};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn toy_db() -> Database {
        let bytes = vec![
            0x90, 0x90, 0xc3, // nop; nop; ret
        ];
        let mut bin = Binary::empty("toy.bin", Format::Raw, Arch::X64);
        bin.base = 0x1000;
        bin.entry = 0x1000;
        bin.has_entry = true;
        bin.path = "toy.bin".into();
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1000 + bytes.len() as u64,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: bytes.len() as u64,
            data: bytes,
        });
        let analysis = analyze(&bin);
        Database::new(bin, analysis)
    }

    async fn body_string(resp: Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn health_info_tools_mcp() {
        let st = HttpState::new(toy_db(), &McpOptions::default());
        let app = router(st);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("Host", "127.0.0.1:8741")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("ceasta"));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/info")
                    .header("Host", "127.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let info: Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(info["name"], "toy.bin");

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/tools")
                    .header("Host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rpc = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("Host", "127.0.0.1")
                    .header("content-type", "application/json")
                    .body(Body::from(rpc.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert!(v["result"]["tools"].as_array().unwrap().len() > 5);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/disasm?addr=1000&n=2")
                    .header("Host", "127.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let lines: Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert!(!lines.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn attach_refuses_protected_pid() {
        let opts = McpOptions {
            allow_debug: true,
            allow_lua: false,
        };
        let st = HttpState::new(toy_db(), &opts);
        let app = router(st);
        let body = json!({ "pid": std::process::id() });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/debug/attach")
                    .header("Host", "127.0.0.1")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let v: Value = serde_json::from_str(&body_string(resp).await).unwrap();
        let err = v["error"].as_str().unwrap_or("");
        assert!(err.contains("refusing") || err.contains("protect"), "{err}");
    }

    #[tokio::test]
    async fn foreign_origin_blocked() {
        let st = HttpState::new(toy_db(), &McpOptions::default());
        let app = router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("Host", "127.0.0.1")
                    .header("Origin", "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn parse_bind_defaults_localhost() {
        assert_eq!(
            parse_bind_addr("8741").unwrap(),
            "127.0.0.1:8741".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr(":9000").unwrap(),
            "127.0.0.1:9000".parse().unwrap()
        );
        assert_eq!(
            parse_bind_addr("127.0.0.1:8741").unwrap(),
            "127.0.0.1:8741".parse().unwrap()
        );
    }
}
