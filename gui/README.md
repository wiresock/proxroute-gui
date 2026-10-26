# proxroute-gui — Proxroute GUI (GPUI)

A standalone GPUI desktop app (`proxroute-gui.exe`) for the live traffic view + controls.
It talks to the running engine over the management **named pipe** `\\.\pipe\Proxroute`
(`proxroute-ipc`).

This is a **separate cargo workspace** on purpose: GPUI pulls a large dependency tree
(the Zed repo as a git dependency), kept out of the engine workspace so its
build/test/clippy stay fast.

## Build & run (Windows)

```sh
cd gui
cargo run --release
```

- **First build is heavy** — it fetches the Zed repo (for `gpui`) as a git dependency
  and compiles a large tree. Expect several minutes and a few GB of disk.
- The GUI must run **elevated** — the management pipe is restricted to SYSTEM +
  Administrators. Start the engine first (`proxroute run` for foreground dev, or the
  installed `ProxrouteService`); the GUI connects to it over the pipe and shows "engine not
  reachable" until it's up.

## Pinned versions

`gpui`, `gpui_platform` and `gpui-component` are pinned to exact git revisions (see
`Cargo.toml`), never a branch. `gpui` / `gpui_platform` use the Zed revision that
`gpui-component` builds against, so they resolve to a single `gpui`. Bump all three together.

## What it does

**Connections tab** — a live traffic table polled from `ListConnections` (~1×/s):
PID, process, protocol (TCP/UDP), destination (host when known), decision, state, and
sent/received bytes. Columns sort (click headers) and resize. A filter bar offers
decision/state chips (with live counts) + free-text search, **Pause** (freezes the
table while the log keeps moving), and **Clear closed**. Double-click a row for a detail
panel with **Explain** routing, **Create rule**, and copy actions; right-click gives the
same. A drag-resizable **event log** at the bottom shows opens/closes/blocks/failures
with severity filters, search, copy, and **Export**; clicking a line selects its
connection. The status bar shows the running profile · redirect mode · DNS, active/shown
counts, throughput, driver version, and engine state.

**Config tab** — a read-only view plus two editors: a **form editor** (Rules / Proxies /
Chains / Profile sub-tabs) and a raw **JSON editor**. Edits apply live via `SetConfig`
(structural changes prompt a restart); **Revert** confirms before discarding unsaved
work, with an unsaved-changes indicator. Proxy setup is kind-aware (auth schemes,
TCP/UDP support, **Check** to verify a proxy end-to-end). A setting that is modeled but
not yet enforced (per-proxy `dns: local`) is flagged inline.

Chips, tabs, and icon buttons are keyboard-focusable (Tab + Enter/Space). The active
tab, config section, and filters are remembered across restarts
(`%LOCALAPPDATA%\Proxroute\ui.json`).
