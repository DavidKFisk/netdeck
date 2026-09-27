/* NetDeck backend adapter. The UI calls window.NetDeckAPI; this file picks the implementation:
   - Tauri desktop app: window.__TAURI__ IPC (no HTTP at all)
   - Local Node server, or a hosted page paired with one: HTTP + streaming fetch */
window.NetDeckAPI = (() => {
  const tauri = window.__TAURI__;

  if (tauri?.core?.invoke) {
    const { invoke, Channel } = tauri.core;
    let seq = 0;
    return {
      kind: 'tauri',
      configure() {},
      get base() { return ''; },
      ping: () => Promise.resolve({ ok: true }),
      commands: () => invoke('list_commands'),
      context: (refresh) => invoke('get_context', { refresh: Boolean(refresh) }),
      health: () => invoke('health'),
      // Outage log: watched by the Rust backend, so it carries on while the window is closed to the tray.
      outage: () => invoke('outage_status'),
      outageSet: ({ enabled = null, notify = null } = {}) => invoke('outage_set', { enabled, notify }),
      outageClear: () => invoke('outage_clear'),
      onOutage: (cb) => (tauri.event?.listen ? tauri.event.listen('outage', (e) => cb(e.payload)) : Promise.resolve(null)),
      // Start with Windows: a per-user startup entry that opens NetDeck hidden in the tray (also in the tray menu).
      autostart: () => invoke('autostart_get'),
      autostartSet: (enabled) => invoke('autostart_set', { enabled: Boolean(enabled) }),
      onAutostart: (cb) => (tauri.event?.listen ? tauri.event.listen('autostart', (e) => cb(e.payload)) : Promise.resolve(null)),
      async run({ id, params, preset = null, help = false }, { onChunk, signal } = {}) {
        const runId = ++seq;
        let output = '';
        const onEvent = new Channel();
        onEvent.onmessage = (ev) => {
          if (ev.type === 'chunk') { output += ev.data; onChunk?.(ev.data); }
        };
        const abort = () => { invoke('stop_run', { runId }).catch(() => {}); };
        signal?.addEventListener('abort', abort);
        try {
          const r = await invoke('run_command', { payload: { id, params: params || {}, preset, help, runId }, onEvent });
          if (signal?.aborted) return { output, exitCode: null, aborted: true };
          const tail = `\n[exited with code ${r.exitCode ?? '?'}]\n`;
          output += tail;
          onChunk?.(tail);
          return { output, exitCode: r.exitCode ?? null, error: false };
        } catch (e) {
          if (signal?.aborted) return { output, exitCode: null, aborted: true };
          const msg = `[${String(e)}]\n`;
          output += msg;
          onChunk?.(msg);
          return { output, exitCode: null, refused: true, error: /could not start/.test(String(e)) };
        } finally {
          signal?.removeEventListener('abort', abort);
        }
      },
      addCustom: (data) => invoke('add_custom', { input: data }),
      deleteCustom: (id) => invoke('delete_custom', { id }),
      // Native dialog and toast go through Rust commands (the plugin JS globals aren't injected).
      saveText: (name, content) => invoke('save_text', { name, content }),
      notifyPermission: () => Promise.resolve('granted'),
      async notify(title, body) {
        await invoke('notify', { title, body });
        return true;
      },
      navigate: (href) => { location.href = href; },
      // Restarts the app elevated; Windows' UAC prompt asks for consent.
      elevate: () => invoke('restart_elevated'),
      // Manual / cheat sheet open in their own window so the main one keeps its tabs.
      openDoc: (page, anchor) => invoke('open_doc', { page, anchor: anchor || null }),
      openSite: () => invoke('open_site'),
    };
  }

  let base = '';
  let token = '';
  const headers = (extra) => ({ 'X-NetDeck': '1', ...(token ? { 'X-NetDeck-Token': token } : {}), ...(extra || {}) });
  const request = (path, opts = {}) => fetch(`${base}${path}`, { ...opts, headers: headers(opts.headers) });
  const jsonOrThrow = async (r) => { if (!r.ok) throw new Error(await r.text()); return r.json(); };

  return {
    kind: 'http',
    configure({ base: b = '', token: t = '' } = {}) { base = b.replace(/\/$/, ''); token = t; },
    get base() { return base; },
    ping: () => request('/api/ping').then(jsonOrThrow),
    commands: () => request('/api/commands').then(jsonOrThrow),
    context: (refresh) => request(`/api/context${refresh ? '?refresh=1' : ''}`).then(jsonOrThrow),
    health: () => request('/api/health').then(jsonOrThrow),
    outage: () => request('/api/outage').then(jsonOrThrow),
    outageSet: (opts) => request('/api/outage', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(opts || {}) }).then(jsonOrThrow),
    outageClear: () => request('/api/outage', { method: 'DELETE' }).then(jsonOrThrow),
    onOutage: null,
    autostart: null,
    autostartSet: null,
    onAutostart: null,
    async run({ id, params, preset = null, help = false }, { onChunk, signal } = {}) {
      let output = '';
      try {
        const res = await request('/api/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id, params, preset, help }),
          signal,
        });
        if (!res.ok) {
          output = `[${await res.text()}]\n`;
          onChunk?.(output);
          return { output, exitCode: null, refused: true };
        }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          output += chunk;
          onChunk?.(chunk);
        }
        const m = output.match(/\[exited with code (\d+|\?)\]\s*$/);
        return { output, exitCode: m && m[1] !== '?' ? Number(m[1]) : null, error: /\[could not start:/.test(output) };
      } catch (err) {
        if (err.name === 'AbortError') return { output, exitCode: null, aborted: true };
        const msg = `[connection error: ${err.message}]\n`;
        onChunk?.(msg);
        return { output: output + msg, exitCode: null, error: true };
      }
    },
    addCustom: (data) => request('/api/custom', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }).then(jsonOrThrow),
    deleteCustom: async (id) => { const r = await request(`/api/custom?id=${encodeURIComponent(id)}`, { method: 'DELETE' }); if (!r.ok) throw new Error(await r.text()); },
    saveText: null,
    notifyPermission: async () => (typeof Notification === 'undefined' ? 'denied' : Notification.permission === 'default' ? Notification.requestPermission() : Notification.permission),
    notify: null,
    navigate: null,
    openDoc: (page, anchor) => { window.open(`${page}${anchor ? `#${anchor}` : ''}`, '_blank', 'noopener'); return Promise.resolve(); },
  };
})();
