//! Outage log. While NetDeck runs — window open or closed to the tray — ping the router and the internet every
//! few seconds and record every outage: when it started, how long it lasted and which side of the router failed.
//! Mirrors the outage monitor in server.js; the page reads both through the same shape.
//!
//! What counts: an outage is two or more checks in a row with no internet reply (about 10 s or longer); a single
//! missed check is a "blip". Where it failed: router answers but the internet does not → past the router (ISP or
//! modem); neither answers → between this PC and the router; no gateway at all → this PC was disconnected; a
//! router that never answers pings → can't tell. Time NetDeck was not watching (closed, asleep) is kept as gaps in
//! `coverage`, never as outages, and the first minute after watching (re)starts is a grace period, because a PC
//! waking up needs a few seconds to reconnect.
//!
//! Testing: NETDECK_OUTAGE_TEST=<file> makes every tick read that file — "isp" sends the internet pings to
//! unroutable TEST-NET addresses, "lan" does the same to the router ping — and turns off the grace period.

use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use super::{detect_context, ping_once, AppState};

fn now_ms() -> u64 {
    super::now_ms() as u64
}

const INTERVAL: Duration = Duration::from_secs(5);
/// A tick later than this after the previous one means NetDeck was not watching (asleep, closed, stalled).
const GAP_MS: u64 = 20_000;
/// After watching (re)starts, failures are not counted for this long: a waking PC needs time to reconnect.
const GRACE_MS: u64 = 60_000;
const MIN_FAILS: u32 = 2;
const KEEP_MS: u64 = 90 * 24 * 3600 * 1000;
const CONTEXT_EVERY_MS: u64 = 10 * 60 * 1000;
const SAVE_EVERY_MS: u64 = 60_000;
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

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct Current {
    start: u64,
    last: u64,
    fails: u32,
    counts: [u32; 4],
    adapter: Option<String>,
    gateway: Option<String>,
}

const LAYERS: [&str; 4] = ["isp", "lan", "offline", "unknown"];

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Log {
    enabled: bool,
    notify: bool,
    /// [start, end] of each stretch NetDeck was watching
    coverage: Vec<[u64; 2]>,
    outages: Vec<Outage>,
    /// single missed checks
    blips: Vec<u64>,
    /// the router has answered a ping at some point, so "no answer" from it means something
    gateway_answers: bool,
    current: Option<Current>,
}

pub struct Monitor {
    log: Mutex<Log>,
    file: PathBuf,
    running: AtomicBool,
}

impl Monitor {
    pub fn load(file: PathBuf) -> Arc<Monitor> {
        let mut log: Log = fs::read_to_string(&file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        // NetDeck quit or crashed during an outage: close it where the checks stopped.
        if let Some(c) = log.current.take() {
            if c.fails >= MIN_FAILS {
                log.outages.push(close(&c, c.last, true));
            }
        }
        prune(&mut log, now_ms());
        Arc::new(Monitor { log: Mutex::new(log), file, running: AtomicBool::new(false) })
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
            "intervalMs": INTERVAL.as_millis() as u64,
            "minFails": MIN_FAILS,
            "coverage": log.coverage,
            "outages": log.outages,
            "blips": log.blips,
            "gatewayAnswers": log.gateway_answers,
            "current": log.current.as_ref().map(|c| json!({ "start": c.start, "last": c.last, "fails": c.fails, "layer": dominant(c) })),
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
                        if c.fails >= MIN_FAILS {
                            log.outages.push(close(&c, c.last, true));
                        }
                    }
                }
            }
            self.save(&log);
        }
        if enabled == Some(true) {
            self.start(app);
        }
        tray_tooltip(app, self.log.lock().unwrap().enabled);
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

    /// Starts the watching thread if the log is enabled and it is not already running.
    pub fn start(self: &Arc<Self>, app: &AppHandle) {
        if !self.log.lock().unwrap().enabled || self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        tray_tooltip(app, true);
        let me = self.clone();
        let app = app.clone();
        thread::spawn(move || {
            let mut last_ctx = 0u64;
            let mut last_save = 0u64;
            let mut watch_start = 0u64;
            while me.log.lock().unwrap().enabled {
                let t0 = std::time::Instant::now();
                me.tick(&app, &mut last_ctx, &mut last_save, &mut watch_start);
                let spent = t0.elapsed();
                if spent < INTERVAL {
                    thread::sleep(INTERVAL - spent);
                }
            }
            me.running.store(false, Ordering::SeqCst);
            let _ = app.emit("outage", json!({ "kind": "stopped" }));
        });
    }

    fn tick(&self, app: &AppHandle, last_ctx: &mut u64, last_save: &mut u64, watch_start: &mut u64) {
        let test = std::env::var("NETDECK_OUTAGE_TEST").ok().map(|p| fs::read_to_string(p).unwrap_or_default().trim().to_string());
        let state = app.state::<Arc<AppState>>();
        let now = now_ms();

        // Watching coverage: extend the current stretch, or start a new one after a gap.
        {
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
                    if c.fails >= MIN_FAILS {
                        log.outages.push(close(&c, c.last, true));
                    }
                }
                self.save(&log);
            }
        }

        // Where to ping: the router from the network context (refreshed now and then, and whenever checks start failing).
        let failing = self.log.lock().unwrap().current.is_some();
        if now.saturating_sub(*last_ctx) > CONTEXT_EVERY_MS {
            refresh_context(&state);
            *last_ctx = now;
        }
        let ctx = |st: &AppState| st.context.lock().unwrap().clone().unwrap_or(Value::Null);
        let mut context = ctx(&state);
        let mut gateway = context["gateway"].as_str().map(String::from);

        let test_mode = test.as_deref().unwrap_or("");
        let gw_target = if test_mode == "lan" { Some("192.0.2.3".to_string()) } else { gateway.clone() };
        let t_gw = {
            let g = gw_target.clone();
            thread::spawn(move || g.as_deref().and_then(ping_once))
        };
        let internet = if test_mode == "isp" || test_mode == "lan" {
            ping_once("192.0.2.1").or_else(|| ping_once("192.0.2.2"))
        } else {
            ping_once(INTERNET[0]).or_else(|| ping_once(INTERNET[1]))
        };
        let gw = t_gw.join().ok().flatten();

        let grace = if test.is_some() { 0 } else { GRACE_MS };
        let settling = now.saturating_sub(*watch_start) < grace;
        if internet.is_none() && !settling && !failing {
            // First failed check: look again at the adapter — "no gateway" means this PC is disconnected.
            refresh_context(&state);
            *last_ctx = now;
            context = ctx(&state);
            gateway = context["gateway"].as_str().map(String::from);
        }
        let mut ended: Option<Outage> = None;
        let mut started = false;
        {
            let mut log = self.log.lock().unwrap();
            if gw.is_some() {
                log.gateway_answers = true;
            }
            if internet.is_some() {
                if let Some(c) = log.current.take() {
                    if c.fails >= MIN_FAILS {
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
                    ..Default::default()
                });
                c.fails += 1;
                c.last = now;
                c.counts[layer] += 1;
                started = c.fails == MIN_FAILS;
            }
            if ended.is_some() || started || now.saturating_sub(*last_save) > SAVE_EVERY_MS {
                prune(&mut log, now);
                self.save(&log);
                *last_save = now;
            }
        }

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

fn tray_tooltip(app: &AppHandle, watching: bool) {
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(if watching { "NetDeck — watching for outages" } else { "NetDeck" }));
    }
}
