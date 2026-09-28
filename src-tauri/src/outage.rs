//! Connection watcher: pings the router and the internet every few seconds while NetDeck runs — window open or
//! closed to the tray — and feeds three things from the same checks:
//!   - the outage log: every outage, when it started, how long it lasted and which side of the router failed;
//!   - the network sensors: current / minimum / maximum / average of each reading since the last reset, and a
//!     rolling history for the mini monitor's graph;
//!   - the tray icon: a green / amber / red light with the latest readings in its tooltip.
//! Mirrors the watcher in server.js (outage log and sensors; the server has no tray). The page reads both through
//! the same shapes.
//!
//! What counts: an outage is no internet reply for about 10 s or longer (two checks in a row at the usual 5 s, five
//! at the 2 s used while a live view is open); anything shorter is a "blip". Where it failed: router answers but the
//! internet does not → past the router (ISP or modem); neither answers → between this PC and the router; no gateway
//! at all → this PC was disconnected; a router that never answers pings → can't tell. Time NetDeck was not watching
//! (closed, asleep) is kept as gaps in `coverage`, never as outages, and the first minute after the log (re)starts is
//! a grace period, because a PC waking up needs a few seconds to reconnect.
//!
//! Testing: NETDECK_OUTAGE_TEST=<file> makes every tick read that file — "isp" sends the internet pings to
//! unroutable TEST-NET addresses, "lan" does the same to the router ping — and turns off the grace period.

use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{image::Image, AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use super::{detect_context, ping_once, AppState};

fn now_ms() -> u64 {
    super::now_ms() as u64
}

/// Check every 5 s normally, every 2 s while the sensors card or the mini monitor is being watched.
const INTERVAL_MS: u64 = 5_000;
const LIVE_INTERVAL_MS: u64 = 2_000;
/// How long a sensors poll keeps the fast interval going.
const LIVE_HOLD_MS: u64 = 12_000;
/// A tick later than this after the previous one means NetDeck was not watching (asleep, closed, stalled).
const GAP_MS: u64 = 20_000;
/// After the log (re)starts, failures are not counted for this long: a waking PC needs time to reconnect.
const GRACE_MS: u64 = 60_000;
/// No internet reply for this long is an outage; shorter is a blip.
const DOWN_MS: u64 = 10_000;
const KEEP_MS: u64 = 90 * 24 * 3600 * 1000;
const CONTEXT_EVERY_MS: u64 = 10 * 60 * 1000;
const SAVE_EVERY_MS: u64 = 60_000;
const RING: usize = 900;
const INTERNET: [&str; 2] = ["1.1.1.1", "8.8.8.8"];

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct Outage {
    start: u64,
    end: u64,
    /// isp | lan | offline | unknown — the side that failed in most of the outage's checks
    layer: String,
    fails: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adapter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    /// NetDeck stopped watching (sleep, quit) before the connection came back: `end` is the last failed check.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    open: bool,
}

fn five_s() -> u64 {
    INTERVAL_MS
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct Current {
    start: u64,
    last: u64,
    fails: u32,
    counts: [u32; 4],
    adapter: Option<String>,
    gateway: Option<String>,
    /// the interval of the last failed check: an outage has lasted until at least last + tick
    #[serde(default = "five_s")]
    tick: u64,
}

impl Current {
    fn down(&self) -> bool {
        self.last.saturating_sub(self.start) + self.tick >= DOWN_MS
    }
}

const LAYERS: [&str; 4] = ["isp", "lan", "offline", "unknown"];
const RULES: [&str; 4] = ["ping", "router", "loss", "down"];

/// One alert: on or off, its limit (ms or %), and how long it must hold (s).
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", default)]
pub struct Rule {
    on: bool,
    limit: f64,
    secs: u64,
}

impl Default for Rule {
    fn default() -> Self {
        Rule { on: false, limit: 0.0, secs: 30 }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", default)]
pub struct Alerts {
    /// internet ping above limit ms for secs
    ping: Rule,
    /// router ping above limit ms for secs
    router: Rule,
    /// internet loss above limit % over the last minute
    loss: Rule,
    /// no internet reply for secs
    down: Rule,
}

impl Default for Alerts {
    fn default() -> Self {
        Alerts {
            ping: Rule { on: false, limit: 150.0, secs: 30 },
            router: Rule { on: false, limit: 50.0, secs: 30 },
            loss: Rule { on: false, limit: 2.0, secs: 60 },
            down: Rule { on: false, limit: 0.0, secs: 20 },
        }
    }
}

impl Alerts {
    fn any(&self) -> bool {
        self.ping.on || self.router.on || self.loss.on || self.down.on
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Log {
    enabled: bool,
    notify: bool,
    /// the tray icon shows the connection's state (on unless turned off)
    tray: bool,
    /// [start, end] of each stretch the log was watching
    coverage: Vec<[u64; 2]>,
    outages: Vec<Outage>,
    /// single missed checks
    blips: Vec<u64>,
    /// the router has answered a ping at some point, so "no answer" from it means something
    gateway_answers: bool,
    current: Option<Current>,
    alerts: Alerts,
}

impl Default for Log {
    fn default() -> Self {
        Log { enabled: false, notify: false, tray: true, coverage: vec![], outages: vec![], blips: vec![], gateway_answers: false, current: None, alerts: Alerts::default() }
    }
}

/// One sensor since the last reset: latest, lowest, highest, average, and loss — overall and per minute.
#[derive(Default, Clone)]
struct Acc {
    last: Option<f64>,
    min: Option<f64>,
    max: Option<f64>,
    sum: f64,
    n: u64,
    sent: u64,
    lost: u64,
    bucket_start: u64,
    bucket_sent: u64,
    bucket_lost: u64,
    worst_minute: f64,
}

impl Acc {
    fn add(&mut self, v: Option<f64>, now: u64) {
        if now.saturating_sub(self.bucket_start) >= 60_000 {
            self.close_bucket();
            self.bucket_start = now;
        }
        self.sent += 1;
        self.bucket_sent += 1;
        match v {
            Some(x) => {
                self.last = Some(x);
                self.min = Some(self.min.map_or(x, |m| m.min(x)));
                self.max = Some(self.max.map_or(x, |m| m.max(x)));
                self.sum += x;
                self.n += 1;
            }
            None => {
                self.last = None;
                self.lost += 1;
                self.bucket_lost += 1;
            }
        }
    }
    fn close_bucket(&mut self) {
        if self.bucket_sent >= 10 {
            self.worst_minute = self.worst_minute.max(100.0 * self.bucket_lost as f64 / self.bucket_sent as f64);
        }
        self.bucket_sent = 0;
        self.bucket_lost = 0;
    }
    fn json(&self) -> Value {
        let open = if self.bucket_sent >= 10 { 100.0 * self.bucket_lost as f64 / self.bucket_sent as f64 } else { 0.0 };
        json!({
            "last": self.last, "min": self.min, "max": self.max,
            "avg": if self.n > 0 { Some(self.sum / self.n as f64) } else { None },
            "sent": self.sent, "lost": self.lost,
            "lossPct": if self.sent > 0 { 100.0 * self.lost as f64 / self.sent as f64 } else { 0.0 },
            "worstMinutePct": self.worst_minute.max(open),
        })
    }
}

#[derive(Default)]
struct Stats {
    since: u64,
    router: Acc,
    internet: Acc,
    jitter: Acc,
    prev_internet: Option<f64>,
    /// [t, router ms | null (lost) | -1 (no router), internet ms | null]
    ring: VecDeque<(u64, Option<f64>, Option<f64>, bool)>,
    /// when the internet stopped answering, for the tray's "down" state
    fail_start: Option<u64>,
    tick: u64,
    gateway: Option<String>,
    state: &'static str,
    /// alerts: which are tripped now, since when, and the recent alert / all-clear events
    active: [bool; 4],
    active_since: [u64; 4],
    events: VecDeque<Value>,
}

struct TrayIcons {
    base: Image<'static>,
    ok: Image<'static>,
    warn: Image<'static>,
    down: Image<'static>,
}

pub struct Monitor {
    log: Mutex<Log>,
    file: PathBuf,
    running: AtomicBool,
    live_until: AtomicU64,
    stats: Mutex<Stats>,
    icons: Mutex<Option<TrayIcons>>,
}

impl Monitor {
    pub fn load(file: PathBuf) -> Arc<Monitor> {
        let mut log: Log = fs::read_to_string(&file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        // NetDeck quit or crashed during an outage: close it where the checks stopped.
        if let Some(c) = log.current.take() {
            if c.down() {
                log.outages.push(close(&c, c.last, true));
            }
        }
        prune(&mut log, now_ms());
        let stats = Stats { since: now_ms(), state: "unknown", ..Default::default() };
        Arc::new(Monitor {
            log: Mutex::new(log),
            file,
            running: AtomicBool::new(false),
            live_until: AtomicU64::new(0),
            stats: Mutex::new(stats),
            icons: Mutex::new(None),
        })
    }

    fn save(&self, log: &Log) {
        if let Some(dir) = self.file.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let tmp = self.file.with_extension("json.tmp");
        if fs::write(&tmp, serde_json::to_string(log).unwrap_or_default()).is_ok() {
            let _ = fs::rename(&tmp, &self.file);
        }
    }

    pub fn status(&self) -> Value {
        let log = self.log.lock().unwrap();
        json!({
            "enabled": log.enabled,
            "notify": log.notify,
            "running": self.running.load(Ordering::SeqCst),
            "now": now_ms(),
            "intervalMs": INTERVAL_MS,
            "minFails": 2,
            "coverage": log.coverage,
            "outages": log.outages,
            "blips": log.blips,
            "gatewayAnswers": log.gateway_answers,
            "current": log.current.as_ref().map(|c| json!({ "start": c.start, "last": c.last, "fails": c.fails, "down": c.down(), "layer": dominant(c) })),
            "notifyNative": true,
        })
    }

    pub fn set(self: &Arc<Self>, app: &AppHandle, enabled: Option<bool>, notify: Option<bool>) -> Value {
        {
            let mut log = self.log.lock().unwrap();
            if let Some(n) = notify {
                log.notify = n;
            }
            if let Some(e) = enabled {
                log.enabled = e;
                if !e {
                    // Stopping mid-outage keeps what was seen, marked as not seen ending.
                    if let Some(c) = log.current.take() {
                        if c.down() {
                            log.outages.push(close(&c, c.last, true));
                        }
                    }
                }
            }
            self.save(&log);
        }
        self.start(app);
        self.update_tray(app);
        self.status()
    }

    pub fn clear(&self) -> Value {
        {
            let mut log = self.log.lock().unwrap();
            log.outages.clear();
            log.blips.clear();
            log.coverage.clear();
            log.current = None;
            self.save(&log);
        }
        self.status()
    }

    /* ---------------- sensors ---------------- */

    /// The readings since the last reset and the recent history. Being asked keeps the fast (2 s) interval going.
    pub fn sensors(self: &Arc<Self>, app: &AppHandle) -> Value {
        self.live_until.store(now_ms() + LIVE_HOLD_MS, Ordering::SeqCst);
        self.start(app);
        let st = self.stats.lock().unwrap();
        let ring: Vec<Value> = st
            .ring
            .iter()
            .map(|(t, r, i, gw)| json!([t, if *gw { json!(r) } else { json!(-1) }, i]))
            .collect();
        json!({
            "now": now_ms(),
            "since": st.since,
            "intervalMs": st.tick,
            "gateway": st.gateway,
            // a drop can pass the 10 s mark between checks
            "state": if st.state == "warn" && st.fail_start.map_or(false, |s| now_ms().saturating_sub(s) + st.tick >= DOWN_MS) { "down" } else { st.state },
            "router": st.router.json(),
            "internet": st.internet.json(),
            "jitter": st.jitter.json(),
            "downSince": st.fail_start.filter(|s| now_ms().saturating_sub(*s) + st.tick >= DOWN_MS),
            "ring": ring,
            "tray": self.log.lock().unwrap().tray,
            "trayNative": true,
            "alerts": self.log.lock().unwrap().alerts,
            "alertActive": st.active,
            "alertEvents": st.events,
        })
    }

    pub fn sensors_reset(self: &Arc<Self>, app: &AppHandle) -> Value {
        {
            let mut st = self.stats.lock().unwrap();
            st.since = now_ms();
            st.router = Acc::default();
            st.internet = Acc::default();
            st.jitter = Acc::default();
            st.prev_internet = None;
        }
        self.sensors(app)
    }

    /// Merge new alert settings (any subset of rules and fields) and start watching if one is on.
    pub fn set_alerts(self: &Arc<Self>, app: &AppHandle, input: &Value) -> Value {
        {
            let mut log = self.log.lock().unwrap();
            let mut cur = serde_json::to_value(&log.alerts).unwrap_or(json!({}));
            if let (Some(c), Some(i)) = (cur.as_object_mut(), input.as_object()) {
                for (k, v) in i {
                    if let (Some(dst), Some(src)) = (c.get_mut(k).and_then(|x| x.as_object_mut()), v.as_object()) {
                        for (fk, fv) in src {
                            dst.insert(fk.clone(), fv.clone());
                        }
                    }
                }
            }
            if let Ok(a) = serde_json::from_value::<Alerts>(cur) {
                log.alerts = sane(a);
            }
            self.save(&log);
        }
        {
            // a rule switched off or changed starts over
            let mut st = self.stats.lock().unwrap();
            st.active = [false; 4];
        }
        self.start(app);
        json!(self.log.lock().unwrap().alerts)
    }

    fn check_alerts(&self, app: &AppHandle, now: u64) {
        let cfg = self.log.lock().unwrap().alerts.clone();
        if !cfg.any() {
            return;
        }
        let mut notes: Vec<(String, String)> = vec![];
        {
            let mut st = self.stats.lock().unwrap();
            let window = |ring: &VecDeque<(u64, Option<f64>, Option<f64>, bool)>, secs: u64| -> Vec<(u64, Option<f64>, Option<f64>, bool)> {
                ring.iter().filter(|e| now.saturating_sub(e.0) <= secs * 1000).cloned().collect()
            };
            let mean = |v: &[f64]| if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 };
            // (rule index, on, exceeded, cleared, alert title, alert text, clear title, clear text)
            let mut results: Vec<(usize, bool, bool, bool, String, String, String, String)> = vec![];
            for (idx, rule, pick) in [(0usize, &cfg.ping, 2u8), (1, &cfg.router, 1)] {
                let w = window(&st.ring, rule.secs.max(5));
                let ok: Vec<f64> = w.iter().filter(|e| pick == 2 || e.3).filter_map(|e| if pick == 2 { e.2 } else { e.1 }).collect();
                let covered = w.first().map_or(false, |e| now.saturating_sub(e.0) * 10 >= rule.secs * 1000 * 7);
                let exceeded = covered && ok.len() >= 2 && ok.iter().all(|v| *v > rule.limit);
                let tail: Vec<f64> = ok.iter().rev().take(3).cloned().collect();
                let cleared = tail.len() >= 2 && tail.iter().all(|v| *v <= rule.limit);
                let what = if pick == 2 { "Internet ping" } else { "Router ping" };
                results.push((
                    idx, rule.on, exceeded, cleared,
                    format!("NetDeck: {} high", what.to_lowercase()),
                    format!("{} ms on average over the last {} s (your limit: {} ms).", mean(&ok).round(), rule.secs, rule.limit),
                    format!("NetDeck: {} back to normal", what.to_lowercase()),
                    format!("{} ms now.", tail.first().map_or(0.0, |v| v.round())),
                ));
            }
            {
                let rule = &cfg.loss;
                let w = window(&st.ring, 60);
                let pct = if w.len() >= 10 { 100.0 * w.iter().filter(|e| e.2.is_none()).count() as f64 / w.len() as f64 } else { 0.0 };
                results.push((
                    2, rule.on, w.len() >= 10 && pct >= rule.limit.max(0.1), pct < rule.limit / 2.0,
                    "NetDeck: packet loss".to_string(),
                    format!("{}% of internet pings lost in the last minute (your limit: {}%).", pct.round(), rule.limit),
                    "NetDeck: packet loss has stopped".to_string(),
                    format!("{}% lost in the last minute.", pct.round()),
                ));
            }
            {
                let rule = &cfg.down;
                let down_for = st.fail_start.map_or(0, |s| now.saturating_sub(s));
                let side = if st.router.last.is_some() { "past your router" } else { "your router is not answering either" };
                results.push((
                    3, rule.on, down_for >= rule.secs.max(5) * 1000, st.fail_start.is_none(),
                    "NetDeck: internet down".to_string(),
                    format!("No internet reply for {} — {}.", duration_text(down_for), side),
                    "NetDeck: internet is back".to_string(),
                    String::new(),
                ));
            }
            for (idx, on, exceeded, cleared, at, ab, ct, cb) in results {
                if !on {
                    st.active[idx] = false;
                    continue;
                }
                if !st.active[idx] && exceeded {
                    st.active[idx] = true;
                    st.active_since[idx] = now;
                    st.events.push_back(json!({ "t": now, "rule": RULES[idx], "kind": "alert", "title": at, "text": ab }));
                    notes.push((at, ab));
                } else if st.active[idx] && cleared {
                    st.active[idx] = false;
                    let lasted = duration_text(now.saturating_sub(st.active_since[idx]));
                    let body = if cb.is_empty() { format!("It lasted {lasted}.") } else { format!("{cb} It lasted {lasted}.") };
                    st.events.push_back(json!({ "t": now, "rule": RULES[idx], "kind": "clear", "title": ct, "text": body }));
                    notes.push((ct, body));
                }
            }
            while st.events.len() > 30 {
                st.events.pop_front();
            }
        }
        for (title, body) in notes {
            let _ = app.notification().builder().title(title).body(body).show();
        }
        let _ = app.emit("alerts", json!({}));
    }

    pub fn tray_enabled(&self) -> bool {
        self.log.lock().unwrap().tray
    }

    pub fn set_tray(self: &Arc<Self>, app: &AppHandle, on: bool) -> bool {
        {
            let mut log = self.log.lock().unwrap();
            log.tray = on;
            self.save(&log);
        }
        self.start(app);
        self.update_tray(app);
        on
    }

    /* ---------------- the watching thread ---------------- */

    fn should_run(&self) -> bool {
        let log = self.log.lock().unwrap();
        log.enabled || log.tray || log.alerts.any() || now_ms() < self.live_until.load(Ordering::SeqCst)
    }

    /// Starts the watching thread if something needs it (log, tray or a live view) and it is not already running.
    pub fn start(self: &Arc<Self>, app: &AppHandle) {
        if !self.should_run() || self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        let app = app.clone();
        thread::spawn(move || {
            let mut last_ctx = 0u64;
            let mut last_save = 0u64;
            let mut watch_start = 0u64;
            while me.should_run() {
                let t0 = std::time::Instant::now();
                let tick = if now_ms() < me.live_until.load(Ordering::SeqCst) { LIVE_INTERVAL_MS } else { INTERVAL_MS };
                me.tick(&app, tick, &mut last_ctx, &mut last_save, &mut watch_start);
                let spent = t0.elapsed();
                let want = Duration::from_millis(tick);
                if spent < want {
                    thread::sleep(want - spent);
                }
            }
            me.running.store(false, Ordering::SeqCst);
            me.update_tray(&app);
            let _ = app.emit("outage", json!({ "kind": "stopped" }));
        });
    }

    fn tick(&self, app: &AppHandle, tick: u64, last_ctx: &mut u64, last_save: &mut u64, watch_start: &mut u64) {
        let test = std::env::var("NETDECK_OUTAGE_TEST").ok().map(|p| fs::read_to_string(p).unwrap_or_default().trim().to_string());
        let state = app.state::<Arc<AppState>>();
        let now = now_ms();
        let logging = self.log.lock().unwrap().enabled;

        // Watching coverage (outage log only): extend the current stretch, or start a new one after a gap.
        if logging {
            let mut log = self.log.lock().unwrap();
            let fresh = match log.coverage.last_mut() {
                Some(c) if now.saturating_sub(c[1]) <= GAP_MS && *watch_start != 0 => {
                    c[1] = now;
                    false
                }
                _ => {
                    log.coverage.push([now, now]);
                    true
                }
            };
            if fresh {
                *watch_start = now;
                if let Some(c) = log.current.take() {
                    if c.down() {
                        log.outages.push(close(&c, c.last, true));
                    }
                }
                self.save(&log);
            }
        }

        // Where to ping: the router from the network context (refreshed now and then, and whenever checks start failing).
        let failing = self.stats.lock().unwrap().fail_start.is_some();
        if now.saturating_sub(*last_ctx) > CONTEXT_EVERY_MS {
            refresh_context(&state);
            *last_ctx = now;
        }
        let ctx = |st: &AppState| st.context.lock().unwrap().clone().unwrap_or(Value::Null);
        let mut context = ctx(&state);
        let mut gateway = context["gateway"].as_str().map(String::from);

        let test_mode = test.as_deref().unwrap_or("");
        let gw_target = if test_mode == "lan" { Some("203.0.113.252".to_string()) } else { gateway.clone() };
        let t_gw = {
            let g = gw_target.clone();
            thread::spawn(move || g.as_deref().and_then(ping_once))
        };
        let internet = if test_mode == "isp" || test_mode == "lan" {
            ping_once("203.0.113.251").or_else(|| ping_once("198.51.100.251"))
        } else {
            ping_once(INTERNET[0]).or_else(|| ping_once(INTERNET[1]))
        };
        let gw = t_gw.join().ok().flatten();

        if internet.is_none() && !failing {
            // First failed check: look again at the adapter — "no gateway" means this PC is disconnected.
            refresh_context(&state);
            *last_ctx = now;
            context = ctx(&state);
            gateway = context["gateway"].as_str().map(String::from);
        }

        self.record_sensors(now, tick, gateway.clone(), gw, internet);
        self.check_alerts(app, now);

        let mut ended: Option<Outage> = None;
        let mut started = false;
        if logging {
            let grace = if test.is_some() { 0 } else { GRACE_MS };
            let settling = now.saturating_sub(*watch_start) < grace;
            let mut log = self.log.lock().unwrap();
            if gw.is_some() {
                log.gateway_answers = true;
            }
            if internet.is_some() {
                if let Some(c) = log.current.take() {
                    if c.down() {
                        let o = close(&c, now, false);
                        log.outages.push(o.clone());
                        ended = Some(o);
                    } else {
                        log.blips.push(c.start);
                    }
                }
            } else if !settling {
                let layer = if gateway.is_none() || context["ip"].is_null() {
                    2
                } else if gw.is_some() {
                    0
                } else if log.gateway_answers {
                    1
                } else {
                    3
                };
                let c = log.current.get_or_insert_with(|| Current {
                    start: now,
                    adapter: context["adapter"].as_str().map(String::from),
                    gateway: gateway.clone(),
                    tick,
                    ..Default::default()
                });
                let was_down = c.down();
                c.fails += 1;
                c.last = now;
                c.tick = tick;
                c.counts[layer] += 1;
                started = !was_down && c.down();
            }
            if ended.is_some() || started || now.saturating_sub(*last_save) > SAVE_EVERY_MS {
                prune(&mut log, now);
                self.save(&log);
                *last_save = now;
            }
        }

        self.update_tray(app);
        if started {
            let _ = app.emit("outage", json!({ "kind": "started" }));
        }
        if let Some(o) = ended {
            let _ = app.emit("outage", json!({ "kind": "ended" }));
            if self.log.lock().unwrap().notify {
                let _ = app
                    .notification()
                    .builder()
                    .title("NetDeck: connection is back")
                    .body(format!("It was down {} — {}.", duration_text(o.end - o.start), layer_text(&o.layer)))
                    .show();
            }
        }
    }

    fn record_sensors(&self, now: u64, tick: u64, gateway: Option<String>, gw: Option<f64>, internet: Option<f64>) {
        let mut st = self.stats.lock().unwrap();
        st.tick = tick;
        let has_gw = gateway.is_some();
        st.gateway = gateway;
        if has_gw {
            st.router.add(gw, now);
        }
        st.internet.add(internet, now);
        match (st.prev_internet, internet) {
            (Some(a), Some(b)) => st.jitter.add(Some((b - a).abs()), now),
            _ => {}
        }
        st.prev_internet = internet;
        if internet.is_some() {
            st.fail_start = None;
        } else if st.fail_start.is_none() {
            st.fail_start = Some(now);
        }
        st.ring.push_back((now, gw, internet, has_gw));
        while st.ring.len() > RING {
            st.ring.pop_front();
        }
        // the light: red when down (or no network), amber when slow or lossy in the last minute, green otherwise
        let recent_loss = st.ring.iter().filter(|e| now.saturating_sub(e.0) <= 60_000 && e.2.is_none()).count();
        st.state = if !has_gw {
            "offline"
        } else if let Some(s) = st.fail_start {
            if now.saturating_sub(s) + tick >= DOWN_MS { "down" } else { "warn" }
        } else if recent_loss > 0 || internet.map_or(false, |v| v > 150.0) || gw.map_or(false, |v| v > 60.0) {
            "warn"
        } else {
            "ok"
        };
    }

    /* ---------------- tray ---------------- */

    fn update_tray(&self, app: &AppHandle) {
        let Some(tray) = app.tray_by_id("main") else { return };
        let (tray_on, logging) = {
            let log = self.log.lock().unwrap();
            (log.tray, log.enabled)
        };
        let watching = if logging { " · outage log on" } else { "" };
        let running = self.running.load(Ordering::SeqCst);
        let mut icons = self.icons.lock().unwrap();
        if icons.is_none() {
            *icons = app.default_window_icon().map(|i| make_icons(i));
        }
        let Some(icons) = icons.as_ref() else { return };
        if !tray_on || !running {
            let _ = tray.set_icon(Some(icons.base.clone()));
            let _ = tray.set_tooltip(Some(if logging { "NetDeck — watching for outages" } else { "NetDeck" }));
            return;
        }
        let st = self.stats.lock().unwrap();
        let ms = |v: Option<f64>| v.map_or("no reply".to_string(), |x| format!("{} ms", x.round()));
        let (icon, tip) = match st.state {
            "offline" => (&icons.down, "NetDeck — no network connection".to_string()),
            "down" => {
                let secs = st.fail_start.map_or(0, |s| now_ms().saturating_sub(s) / 1000);
                let side = if st.router.last.is_some() { "past your router" } else { "router not answering either" };
                (&icons.down, format!("NetDeck — internet down for {} ({side})", duration_text(secs * 1000)))
            }
            "warn" => (&icons.warn, format!("NetDeck — unsteady · router {} · internet {}", ms(st.router.last), ms(st.internet.last))),
            "ok" => (&icons.ok, format!("NetDeck — connected · router {} · internet {}", ms(st.router.last), ms(st.internet.last))),
            _ => (&icons.base, "NetDeck".to_string()),
        };
        let _ = tray.set_icon(Some(icon.clone()));
        let mut tip = format!("{tip}{watching}");
        tip.truncate(120);
        let _ = tray.set_tooltip(Some(tip));
    }
}

/// Keep alert settings within sensible bounds.
fn sane(mut a: Alerts) -> Alerts {
    a.ping.limit = a.ping.limit.clamp(10.0, 5000.0);
    a.ping.secs = a.ping.secs.clamp(5, 3600);
    a.router.limit = a.router.limit.clamp(2.0, 5000.0);
    a.router.secs = a.router.secs.clamp(5, 3600);
    a.loss.limit = a.loss.limit.clamp(0.5, 100.0);
    a.loss.secs = 60;
    a.down.secs = a.down.secs.clamp(5, 3600);
    a
}

/// The app icon with a colored dot in the lower right corner, for each state.
fn make_icons(base: &Image<'_>) -> TrayIcons {
    let (w, h) = (base.width(), base.height());
    let px = base.rgba().to_vec();
    let dot = |rgb: [u8; 3]| -> Image<'static> {
        let mut p = px.clone();
        let r = (w.min(h) as f64) * 0.30;
        let (cx, cy) = (w as f64 - r - 0.5, h as f64 - r - 0.5);
        let rim = (r * 0.22).max(1.0);
        for y in 0..h {
            for x in 0..w {
                let d = ((x as f64 + 0.5 - cx).powi(2) + (y as f64 + 0.5 - cy).powi(2)).sqrt();
                if d <= r {
                    let i = ((y * w + x) * 4) as usize;
                    let c = if d > r - rim { [24, 24, 24] } else { rgb };
                    p[i] = c[0];
                    p[i + 1] = c[1];
                    p[i + 2] = c[2];
                    p[i + 3] = 255;
                }
            }
        }
        Image::new_owned(p, w, h)
    };
    TrayIcons { base: Image::new_owned(px.clone(), w, h), ok: dot([46, 170, 80]), warn: dot([230, 160, 30]), down: dot([220, 55, 50]) }
}

fn refresh_context(state: &AppState) {
    let fresh = detect_context();
    *state.context.lock().unwrap() = Some(fresh);
}

fn dominant(c: &Current) -> &'static str {
    let mut best = 3;
    for i in 0..4 {
        if c.counts[i] > c.counts[best] || (c.counts[i] == c.counts[best] && i < best) {
            best = i;
        }
    }
    LAYERS[best]
}

fn close(c: &Current, end: u64, open: bool) -> Outage {
    Outage { start: c.start, end, layer: dominant(c).into(), fails: c.fails, adapter: c.adapter.clone(), gateway: c.gateway.clone(), open }
}

fn prune(log: &mut Log, now: u64) {
    let cut = now.saturating_sub(KEEP_MS);
    log.outages.retain(|o| o.end >= cut);
    log.blips.retain(|&b| b >= cut);
    log.coverage.retain(|c| c[1] >= cut);
    if log.blips.len() > 5000 {
        let extra = log.blips.len() - 5000;
        log.blips.drain(0..extra);
    }
}

fn duration_text(ms: u64) -> String {
    let s = (ms + 500) / 1000;
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{} h {} min", s / 3600, (s % 3600) / 60)
    }
}

fn layer_text(layer: &str) -> &'static str {
    match layer {
        "isp" => "past your router (your internet provider or modem)",
        "lan" => "between this PC and the router (Wi-Fi, cable or the router itself)",
        "offline" => "this PC had no network connection",
        _ => "your router does not answer pings, so NetDeck cannot tell which side",
    }
}
