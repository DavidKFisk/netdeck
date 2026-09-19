//! NetDeck desktop backend. Mirrors server.js: the same commands.json whitelist, the same
//! parameter validation, streaming output — but over Tauri IPC instead of a local HTTP server.

use std::{
    collections::HashMap,
    fs,
    io::{ErrorKind, Read},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tauri::{
    ipc::Channel,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, State, WindowEvent,
};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;

const BUILTIN: &str = include_str!("../../commands.json");
const RUN_TIMEOUT: Duration = Duration::from_secs(180);
const PLATFORM: &str = if cfg!(windows) {
    "win32"
} else if cfg!(target_os = "macos") {
    "darwin"
} else {
    "linux"
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

struct AppState {
    builtin: Vec<Value>,
    custom: Mutex<Vec<Value>>,
    custom_file: PathBuf,
    context: Mutex<Option<Value>>,
    /// run id → child pid, for Stop and the timeout watchdog
    runs: Mutex<HashMap<u64, u32>>,
}

impl AppState {
    fn find(&self, id: &str) -> Option<Value> {
        self.builtin
            .iter()
            .chain(self.custom.lock().unwrap().iter())
            .find(|c| c["id"] == id)
            .cloned()
    }
}

/* ---------------- process helpers ---------------- */

fn command(exe: &str, args: &[String]) -> Command {
    let mut c = Command::new(exe);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

/// Run to completion with a wall-clock limit; returns combined stdout (lossy UTF-8).
fn capture(exe: &str, args: &[String], limit: Duration) -> Option<String> {
    let mut child = command(exe, args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.read_to_end(&mut buf);
        buf
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() > limit => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(40)),
            Err(_) => break,
        }
    }
    reader.join().ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        let _ = command("taskkill", &["/PID".into(), pid.to_string(), "/T".into(), "/F".into()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = command("kill", &["-9".into(), pid.to_string()]).status();
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/* ---------------- run specs (same rules as server.js) ---------------- */

fn run_spec_for(cmd: &Value) -> Option<Value> {
    if cmd["safe"] != Value::Bool(true) {
        return None;
    }
    if cfg!(windows) {
        return cmd.get("run").cloned();
    }
    let mut spec = cmd.get("runUnix")?.clone();
    if cfg!(target_os = "macos") {
        if let Some(Value::Object(darwin)) = spec.get("darwin").cloned() {
            for (k, v) in darwin {
                spec[k] = v;
            }
        }
    }
    if let Some(o) = spec.as_object_mut() {
        o.remove("darwin");
    }
    Some(spec)
}

fn help_spec_for(cmd: &Value) -> Option<(String, Vec<String>)> {
    let h = if cfg!(windows) { cmd.get("help") } else { cmd.get("helpUnix") }?;
    if let Value::Array(parts) = h {
        let list: Vec<String> = parts.iter().filter_map(|p| p.as_str().map(String::from)).collect();
        return list.split_first().map(|(exe, rest)| (exe.clone(), rest.to_vec()));
    }
    if cfg!(windows) {
        if let Some(name) = h.get("ps").and_then(Value::as_str) {
            return Some(ps_invocation(&format!("Get-Help {name} -Detailed")));
        }
    }
    None
}

fn ps_invocation(script: &str) -> (String, Vec<String>) {
    (
        "powershell.exe".into(),
        vec!["-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), script.to_string()],
    )
}

fn client_shape(cmd: &Value) -> Value {
    let mut out = cmd.clone();
    let obj = out.as_object_mut().unwrap();
    for k in ["run", "runUnix", "help", "helpUnix"] {
        obj.remove(k);
    }
    let runnable = run_spec_for(cmd).map(|spec| {
        let presets: Vec<Value> = spec["presets"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .map(|p| {
                        json!({
                            "key": p["key"], "label": p["label"], "args": p["args"], "command": p["command"],
                            "display": p["display"], "admin": p["admin"].as_bool().unwrap_or(false)
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        json!({
            "kind": spec["kind"], "exe": spec["exe"], "args": spec["args"], "command": spec["command"], "display": spec["display"],
            "params": spec["params"].as_array().cloned().unwrap_or_default(), "presets": presets
        })
    });
    obj.insert("runnable".into(), runnable.unwrap_or(Value::Null));
    obj.insert("hasHelp".into(), Value::Bool(help_spec_for(cmd).is_some()));
    out
}

/* ---------------- parameter validation ---------------- */

fn valid_host(v: &str) -> bool {
    let b = v.as_bytes();
    !b.is_empty()
        && b.len() <= 253
        // underscore: DNS service labels such as _dmarc
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'.' || *c == b'-' || *c == b'_')
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b[b.len() - 1].is_ascii_alphanumeric()
}

fn valid_port(v: &str) -> bool {
    !v.is_empty() && v.len() <= 5 && v.bytes().all(|c| c.is_ascii_digit()) && v.parse::<u32>().map_or(false, |n| (1..=65535).contains(&n))
}

fn valid_url(v: &str) -> bool {
    v.len() <= 2048
        && (v.starts_with("http://") || v.starts_with("https://"))
        && v.len() > 8
        && !v.chars().any(|c| "\"'`$;&|<> \t\r\n".contains(c))
}

fn param_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn fill_params(template: &str, params: &Map<String, Value>, specs: &[Value]) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        // %{name} belongs to the tool (curl's -w format), not to us: pass it through untouched.
        if out.ends_with('%') {
            out.push('{');
            rest = &rest[start + 1..];
            continue;
        }
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let key = &after[..end];
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            out.push_str(&rest[start..start + 1]);
            rest = after;
            continue;
        }
        let spec = specs
            .iter()
            .find(|p| p["key"] == key)
            .ok_or_else(|| format!("unknown param {{{key}}}"))?;
        let value = params.get(key).map(param_string).unwrap_or_default();
        let ok = match spec["type"].as_str().unwrap_or("") {
            "host" => valid_host(&value),
            "port" => valid_port(&value),
            "url" => valid_url(&value),
            _ => false,
        };
        if !ok {
            return Err(format!("Invalid value for \"{key}\"."));
        }
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/* ---------------- commands ---------------- */

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunPayload {
    id: String,
    #[serde(default)]
    params: Map<String, Value>,
    #[serde(default)]
    preset: Option<u64>,
    #[serde(default)]
    help: bool,
    run_id: u64,
}

#[derive(Serialize, Clone)]
#[serde(tag = "type", rename_all = "camelCase")]
enum RunEvent {
    Chunk { data: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunResult {
    exit_code: Option<i32>,
}

fn build_invocation(cmd: &Value, payload: &RunPayload, state: &AppState) -> Result<(String, Vec<String>), String> {
    if payload.help {
        return help_spec_for(cmd).ok_or_else(|| "No built-in help is available for this command on this system.".to_string());
    }
    let base = run_spec_for(cmd).ok_or_else(|| {
        if cfg!(windows) {
            "This command is not runnable from the interface.".to_string()
        } else {
            "This command has no Linux/macOS form to run.".to_string()
        }
    })?;
    let mut spec = base.clone();
    if let Some(idx) = payload.preset {
        let preset = base["presets"]
            .get(idx as usize)
            .cloned()
            .ok_or_else(|| "Unknown preset.".to_string())?;
        if preset["admin"] == Value::Bool(true) {
            let admin = state
                .context
                .lock()
                .unwrap()
                .as_ref()
                .map(|c| c["admin"] == Value::Bool(true))
                .unwrap_or(false);
            if !admin {
                return Err("This variant needs administrator rights — use the \"Run as admin\" button next to the STANDARD USER badge.".into());
            }
        }
        if let Some(a) = preset.get("args") {
            spec["args"] = a.clone();
        }
        if let Some(c) = preset.get("command") {
            spec["command"] = c.clone();
        }
    }
    let specs = base["params"].as_array().cloned().unwrap_or_default();
    if spec["kind"] == "ps" {
        let script = fill_params(spec["command"].as_str().unwrap_or(""), &payload.params, &specs)?;
        return Ok(ps_invocation(&script));
    }
    let exe = spec["exe"].as_str().unwrap_or("").to_string();
    let args = spec["args"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|a| fill_params(a.as_str().unwrap_or(""), &payload.params, &specs))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((exe, args))
}

fn pump<R: Read>(mut reader: R, channel: Channel<RunEvent>) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = channel.send(RunEvent::Chunk { data: String::from_utf8_lossy(&buf[..n]).into_owned() });
            }
        }
    }
}

#[tauri::command]
async fn run_command(state: State<'_, Arc<AppState>>, payload: RunPayload, on_event: Channel<RunEvent>) -> Result<RunResult, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let cmd = st.find(&payload.id).ok_or_else(|| "Unknown command.".to_string())?;
        let (exe, args) = build_invocation(&cmd, &payload, &st)?;
        let mut child = command(&exe, &args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == ErrorKind::NotFound {
                    format!("could not start: {exe} is not installed or not in PATH")
                } else {
                    format!("could not start: {e}")
                }
            })?;
        let pid = child.id();
        st.runs.lock().unwrap().insert(payload.run_id, pid);

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (c1, c2, c3) = (on_event.clone(), on_event.clone(), on_event.clone());
        let t_out = thread::spawn(move || pump(stdout, c1));
        let t_err = thread::spawn(move || pump(stderr, c2));

        let watchdog_state = st.clone();
        let run_id = payload.run_id;
        thread::spawn(move || {
            thread::sleep(RUN_TIMEOUT);
            if watchdog_state.runs.lock().unwrap().contains_key(&run_id) {
                kill_pid(pid);
                let _ = c3.send(RunEvent::Chunk { data: "\n[timed out after 3 minutes]\n".into() });
            }
        });

        let status = child.wait();
        let _ = t_out.join();
        let _ = t_err.join();
        st.runs.lock().unwrap().remove(&payload.run_id);
        Ok(RunResult { exit_code: status.ok().and_then(|s| s.code()) })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn stop_run(state: State<'_, Arc<AppState>>, run_id: u64) {
    if let Some(pid) = state.runs.lock().unwrap().remove(&run_id) {
        kill_pid(pid);
    }
}

#[tauri::command]
fn list_commands(state: State<'_, Arc<AppState>>) -> Value {
    let custom = state.custom.lock().unwrap();
    let commands: Vec<Value> = state.builtin.iter().chain(custom.iter()).map(client_shape).collect();
    json!({ "platform": PLATFORM, "commands": commands })
}

/* ---------------- network context ---------------- */

const CONTEXT_SCRIPT: &str = r#"
$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric, InterfaceMetric)
$r = $null; $ip = $null; $dns = @()
foreach ($cand in $routes) {
  $a = @(Get-NetIPAddress -InterfaceIndex $cand.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
         Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.AddressState -eq 'Preferred' })
  if ($a.Count) { $r = $cand; $ip = $a[0].IPAddress; break }
}
if (-not $r -and $routes.Count) { $r = $routes[0] }
if ($r) {
  $dns = @((Get-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
[pscustomobject]@{ gateway = $r.NextHop; adapter = $r.InterfaceAlias; ip = $ip; dns = $dns; admin = $admin } | ConvertTo-Json -Compress
"#;

fn hostname() -> String {
    capture("hostname", &[], Duration::from_secs(5))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default()
}

fn detect_context() -> Value {
    let mut ctx = if cfg!(windows) {
        let (exe, args) = ps_invocation(CONTEXT_SCRIPT);
        capture(&exe, &args, Duration::from_secs(20))
            .and_then(|out| serde_json::from_str::<Value>(out.trim()).ok())
            .unwrap_or_else(|| json!({ "gateway": null, "adapter": null, "ip": null, "dns": [], "admin": false, "partial": true }))
    } else {
        detect_context_unix()
    };
    if !ctx["dns"].is_array() {
        let single = ctx["dns"].as_str().map(|s| json!([s])).unwrap_or(json!([]));
        ctx["dns"] = single;
    }
    ctx["hostname"] = json!(hostname());
    ctx["platform"] = json!(PLATFORM);
    ctx["fetchedAt"] = json!(now_ms());
    ctx
}

fn detect_context_unix() -> Value {
    let (gateway, adapter) = if cfg!(target_os = "macos") {
        let out = capture("route", &["-n".into(), "get".into(), "default".into()], Duration::from_secs(10)).unwrap_or_default();
        (field_after(&out, "gateway:"), field_after(&out, "interface:"))
    } else {
        let out = capture("ip", &["route".into(), "show".into(), "default".into()], Duration::from_secs(10)).unwrap_or_default();
        (word_after(&out, "via"), word_after(&out, "dev"))
    };
    let ip = adapter.as_ref().and_then(|iface| {
        if cfg!(target_os = "macos") {
            capture("ipconfig", &["getifaddr".into(), iface.clone()], Duration::from_secs(5)).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        } else {
            let out = capture("ip", &["-4".into(), "-o".into(), "addr".into(), "show".into(), "dev".into(), iface.clone()], Duration::from_secs(5)).unwrap_or_default();
            word_after(&out, "inet").map(|s| s.split('/').next().unwrap_or("").to_string())
        }
    });
    let dns: Vec<String> = fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("nameserver").map(|rest| rest.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .collect();
    let admin = capture("id", &["-u".into()], Duration::from_secs(5)).map(|s| s.trim() == "0").unwrap_or(false);
    json!({ "gateway": gateway, "adapter": adapter, "ip": ip, "dns": dns, "admin": admin })
}

fn field_after(text: &str, label: &str) -> Option<String> {
    text.lines().find_map(|l| l.trim().strip_prefix(label).map(|v| v.trim().to_string())).filter(|s| !s.is_empty())
}

fn word_after(text: &str, word: &str) -> Option<String> {
    let mut it = text.split_whitespace();
    while let Some(w) = it.next() {
        if w == word {
            return it.next().map(String::from);
        }
    }
    None
}

#[tauri::command]
async fn get_context(state: State<'_, Arc<AppState>>, refresh: bool) -> Result<Value, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if !refresh {
            if let Some(c) = st.context.lock().unwrap().as_ref() {
                return c.clone();
            }
        }
        let ctx = detect_context();
        *st.context.lock().unwrap() = Some(ctx.clone());
        ctx
    })
    .await
    .map_err(|e| e.to_string())
}

/* ---------------- health ---------------- */

fn ping_once(host: &str) -> Option<f64> {
    let args: Vec<String> = if cfg!(windows) {
        vec!["-n".into(), "1".into(), "-w".into(), "1500".into(), host.into()]
    } else if cfg!(target_os = "macos") {
        vec!["-c".into(), "1".into(), "-W".into(), "1500".into(), host.into()]
    } else {
        vec!["-c".into(), "1".into(), "-W".into(), "2".into(), host.into()]
    };
    let out = capture("ping", &args, Duration::from_secs(5))?;
    let lower = out.to_lowercase();
    let idx = lower.find("time=").or_else(|| lower.find("time<"))?;
    let tail = &lower[idx + 5..];
    let num: String = tail.trim_start().chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    num.parse::<f64>().ok().map(|v| v.max(0.5))
}

#[tauri::command]
async fn health(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let gateway_host = {
            let ctx = st.context.lock().unwrap();
            ctx.as_ref().and_then(|c| c["gateway"].as_str().map(String::from))
        };
        let gw = gateway_host.clone();
        let t_gw = thread::spawn(move || gw.as_deref().and_then(ping_once));
        let internet = ping_once("1.1.1.1");
        let gateway = t_gw.join().ok().flatten();
        json!({ "t": now_ms(), "gateway": gateway, "internet": internet, "gatewayHost": gateway_host })
    })
    .await
    .map_err(|e| e.to_string())
}

/* ---------------- custom (reference-only) commands ---------------- */

fn str_field(v: &Value, key: &str, max: usize) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").trim().chars().take(max).collect()
}

fn sanitize_custom(input: &Value) -> Result<Value, String> {
    let name = str_field(input, "name", 80);
    let purpose = str_field(input, "purpose", 240);
    if name.is_empty() || purpose.is_empty() {
        return Err("Name and purpose are required.".into());
    }
    let unix: Vec<String> = match input.get("unix") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
        Some(Value::String(s)) => s.lines().map(String::from).collect(),
        _ => vec![],
    }
    .into_iter()
    .map(|s| s.trim().chars().take(200).collect::<String>())
    .filter(|s| !s.is_empty())
    .take(6)
    .collect();
    let win = str_field(input, "win", 200);
    if win.is_empty() && unix.is_empty() {
        return Err("Give at least one command line (Windows or Linux/macOS).".into());
    }
    let mut platforms = vec![];
    if !win.is_empty() {
        let looks_ps = win.split('-').next().map_or(false, |v| v.len() > 1 && v.chars().next().unwrap().is_ascii_uppercase()) && win.contains('-');
        platforms.push(if looks_ps { "powershell" } else { "windows" });
    }
    if !unix.is_empty() {
        platforms.push("unix");
    }
    let category = str_field(input, "category", 60);
    let note = str_field(input, "note", 240);
    let mut obj = json!({
        "name": name, "purpose": purpose, "unix": unix,
        "category": if category.is_empty() { "Custom".to_string() } else { category },
        "platforms": platforms, "safe": false, "custom": true
    });
    if !win.is_empty() {
        obj["win"] = json!(win);
    }
    if !note.is_empty() {
        obj["note"] = json!(note);
    }
    Ok(obj)
}

fn save_custom(state: &AppState) -> Result<(), String> {
    let list = state.custom.lock().unwrap();
    if let Some(dir) = state.custom_file.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(&state.custom_file, serde_json::to_string_pretty(&*list).unwrap()).map_err(|e| e.to_string())
}

#[tauri::command]
fn add_custom(state: State<'_, Arc<AppState>>, input: Value) -> Result<Value, String> {
    let mut entry = sanitize_custom(&input)?;
    entry["id"] = json!(format!("custom-{:x}", now_ms()));
    state.custom.lock().unwrap().push(entry.clone());
    save_custom(&state)?;
    Ok(client_shape(&entry))
}

#[tauri::command]
fn delete_custom(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    {
        let mut list = state.custom.lock().unwrap();
        let before = list.len();
        list.retain(|c| c["id"] != id);
        if list.len() == before {
            return Err("No such custom command.".into());
        }
    }
    save_custom(&state)
}

#[tauri::command]
fn write_text_file(path: String, content: String) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())
}

/// Native "Save as" dialog, then write the text. Returns false if the user cancelled.
#[tauri::command]
async fn save_text(app: AppHandle, name: String, content: String) -> Result<bool, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog().file().add_filter("Text", &["txt"]).set_file_name(&name).blocking_save_file()
    })
    .await
    .map_err(|e| e.to_string())?;
    match picked {
        Some(file) => {
            let path = file.into_path().map_err(|e| e.to_string())?;
            fs::write(path, content).map_err(|e| e.to_string())?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Open the manual or the cheat sheet in a second window, optionally at an anchor, so the main
/// window keeps its tabs and running commands. The page name is whitelisted and the anchor sanitised.
// Must be async: on Windows, building a window inside a synchronous command stalls the new
// WebView before it loads (the window appears, but stays on about:blank).
#[tauri::command]
async fn open_doc(app: AppHandle, page: String, anchor: Option<String>) -> Result<(), String> {
    if page != "manual.html" && page != "cheatsheet.html" {
        return Err("Unknown page.".into());
    }
    let anchor: String = anchor
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(80)
        .collect();

    if let Some(w) = app.get_webview_window("docs") {
        let target = if anchor.is_empty() { page.clone() } else { format!("{page}#{anchor}") };
        let _ = w.eval(&format!("location.href = '{target}'"));
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
        return Ok(());
    }

    let pending = Arc::new(Mutex::new(Some(anchor)));
    tauri::WebviewWindowBuilder::new(&app, "docs", tauri::WebviewUrl::App(page.into()))
        .title("NetDeck \u{2014} Manual")
        .inner_size(1100.0, 840.0)
        .min_inner_size(560.0, 400.0)
        .on_page_load(move |w, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Finished {
                if let Some(a) = pending.lock().unwrap().take() {
                    if !a.is_empty() {
                        let _ = w.eval(&format!("location.hash = '{a}'"));
                    }
                }
            }
        })
        .build()
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Restart NetDeck elevated. Windows shows its own UAC prompt; nothing is elevated without the user's consent.
/// This instance has to exit first (single-instance lock), so a helper waits, then asks Windows for an
/// elevated copy — and if the prompt is declined, starts a normal copy so the app does not just vanish.
#[tauri::command]
fn restart_elevated(app: AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe = exe.to_string_lossy().replace('\'', "''");
        let script = format!(
            "Start-Sleep -Milliseconds 900; try {{ Start-Process -FilePath '{exe}' -Verb RunAs -ErrorAction Stop }} catch {{ Start-Process -FilePath '{exe}' }}"
        );
        command(
            "powershell.exe",
            &["-NoProfile".into(), "-NonInteractive".into(), "-WindowStyle".into(), "Hidden".into(), "-Command".into(), script],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Could not start the elevation helper: {e}"))?;
        app.exit(0);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Err("On this system, quit NetDeck and start it again with sudo to run elevated.".into())
    }
}

#[tauri::command]
fn notify(app: AppHandle, title: String, body: String) -> Result<(), String> {
    app.notification().builder().title(title).body(body).show().map_err(|e| e.to_string())
}

/* ---------------- app: tray, window, setup ---------------- */

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

pub fn run() {
    let builtin: Vec<Value> = serde_json::from_str(BUILTIN).expect("commands.json is valid JSON");

    tauri::Builder::default()
        // Must be registered first: a second launch hands its arguments to the running copy
        // and exits, so there is only ever one window and one tray icon.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            let data_dir = app.path().app_data_dir().unwrap_or_else(|_| PathBuf::from("."));
            let custom_file = data_dir.join("custom-commands.json");
            // One-time migration from the pre-1.4.1 identifier (com.netdeck.app).
            if !custom_file.exists() {
                if let Some(old) = data_dir.parent().map(|p| p.join("com.netdeck.app").join("custom-commands.json")) {
                    if old.exists() {
                        let _ = fs::create_dir_all(&data_dir);
                        let _ = fs::copy(&old, &custom_file);
                    }
                }
            }
            let custom: Vec<Value> = fs::read_to_string(&custom_file)
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
                .unwrap_or_default()
                .into_iter()
                .filter(|c| c["id"].as_str().map_or(false, |id| id.starts_with("custom-")))
                .collect();
            let state = Arc::new(AppState {
                builtin: builtin.clone(),
                custom: Mutex::new(custom),
                custom_file,
                context: Mutex::new(None),
                runs: Mutex::new(HashMap::new()),
            });
            app.manage(state.clone());

            // Warm the network context so the first paint is instant.
            thread::spawn(move || {
                let ctx = detect_context();
                *state.context.lock().unwrap() = Some(ctx);
            });

            let open = MenuItem::with_id(app, "open", "Open NetDeck", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit NetDeck", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().cloned().expect("app icon"))
                .tooltip("NetDeck")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        // Closing the window keeps NetDeck in the tray (runs in progress keep streaming); Quit is in the tray menu.
        .on_window_event(|window, event| {
            // Only the main window hides to the tray; the manual window just closes.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            list_commands,
            run_command,
            stop_run,
            get_context,
            health,
            add_custom,
            delete_custom,
            write_text_file,
            save_text,
            notify,
            restart_elevated,
            open_doc
        ])
        .run(tauri::generate_context!())
        .expect("error while running NetDeck");
}
