//! Proxroute — GUI (GPUI).
//!
//! Two tabs over the engine's management named pipe (`proxroute-ipc`):
//!  - **Connections**: a live traffic table (gpui-component `DataTable`: virtualized,
//!    with resizable + click-to-sort columns), polling `ListConnections` ~1×/s.
//!  - **Config**: view + edit of the LAST-SAVED configuration (fetched via `GetConfig`,
//!    refreshed by Reload), with live save (`SetConfig`), optimistic-concurrency on a
//!    revision digest, and a restart prompt when a saved change isn't yet live.
//!
//! A background tokio thread drives the pipe (off GPUI's executor); results cross a
//! `futures` channel and the GPUI side re-renders. Run **elevated** (the pipe is
//! SYSTEM/Admin-only), against a running engine (`proxroute run …`).
//!
//! Security: `GetConfig` returns the last-saved config with proxy passwords REDACTED to a
//! placeholder — cleartext credentials never cross the pipe or render in the editor; a
//! `SetConfig` that echoes the placeholder is restored to the real secret engine-side.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Local;
use futures::{channel::mpsc, StreamExt};
use gpui::*;
use gpui_component::{
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState},
    menu::PopupMenu,
    popover::Popover,
    resizable::{resizable_panel, v_resizable},
    table::{Column, ColumnSort, DataTable, TableDelegate, TableEvent, TableState},
    tooltip::Tooltip,
    *,
};
use proxroute_config::{
    chain_hops_summary, Action, ActionType, AppMatch, ChainDns, ChainMode, Config, HealthCheck,
    HealthCheckKind, OnFailure, Predicate, Profile, Protocol, ProxyAuth, ProxyChain, ProxyDef,
    ProxyDnsResolution, ProxyKind, Rule, RuleGroup, Secret, DEFAULT_HEALTH_INTERVAL_SECS,
};
use proxroute_ipc::{ConnectionRow, Request, Response, RestartRequired, RestartScope};

// Internationalization. `i18n!` embeds every `gui/locales/*.yml` at compile time and generates the
// `t!` machinery; `en` is the fallback so a missing key/locale degrades to English, never a panic.
// The active locale is a runtime global (`rust_i18n::set_locale`) read by every `t!` call, so a
// language switch just re-renders. User-facing text is being migrated to `t!` in staged slices;
// the goal is that no user-visible string stays a bare literal, but many still are for now.
rust_i18n::i18n!("locales", fallback = "en");
use rust_i18n::t;

mod config_load;
mod profile_select;
mod restart;
mod rules;
use rules::{
    build_match, conn_dest_fields, extract_rule_fields, set_action_kind, split_list,
    unique_group_name, unique_rule_name, RuleFields,
};

// --- palette (dark) --------------------------------------------------------
const BG: u32 = 0x1e1e1e;
const BG_ALT: u32 = 0x252526;
const BG_BAR: u32 = 0x2d2d30;
const BG_PANEL: u32 = 0x232323;
const FG: u32 = 0xd4d4d4;
const FG_DIM: u32 = 0x9aa0a6;
const GREEN: u32 = 0x4ec9b0;
const RED: u32 = 0xf48771;
const YELLOW: u32 = 0xd7ba7d;
/// Keyboard-focus ring — visible against both the dim chip bg and the green active bg.
const FOCUS_RING: u32 = 0x569cd6;

/// Event-log panel height (px) and ring-buffer cap.
const LOG_PANEL_H: f32 = 170.0;
const MAX_LOG: usize = 1000;
/// How long to wait for an in-place `RestartEngine` to take effect (the engine to come back running
/// the saved config) before reporting it didn't complete. An in-place restart reconnects in a
/// second or two; this is a generous ceiling so a refused/failed restart doesn't spin forever.
const RESTART_TIMEOUT: Duration = Duration::from_secs(20);

// Context-menu actions dispatched from a right-clicked connection row (handled by
// `AppView`, which acts on the row stashed in `ctx_row`).
actions!(
    proxroute,
    [CreateRuleFromConn, ShowConnDetails, ExplainConn]
);

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Connections,
    Config,
}

/// Explicit engine connectivity state for the status bar — tracked from each poll's outcome
/// rather than sniffed from the status string, so the dot/label can't drift from reality.
#[derive(PartialEq, Clone, Copy)]
enum EngineState {
    /// Before the first poll result has come back.
    Loading,
    /// Reachable, polls succeeding.
    Running,
    /// A restart is in flight (the pipe drops, then the poller reconnects).
    Reconnecting,
    /// Polls failing — not running, or the caller isn't elevated.
    Unreachable,
}

impl EngineState {
    /// (dot color, short label) for the status bar.
    fn dot(self) -> u32 {
        match self {
            EngineState::Running => GREEN,
            EngineState::Loading | EngineState::Reconnecting => YELLOW,
            EngineState::Unreachable => RED,
        }
    }
}

/// Connections-tab quick filter by routing decision / state.
#[derive(PartialEq, Clone, Copy)]
enum ConnFilter {
    All,
    Proxied,
    Direct,
    Blocked,
    Failed,
}

impl ConnFilter {
    const ALL: [ConnFilter; 5] = [
        ConnFilter::All,
        ConnFilter::Proxied,
        ConnFilter::Direct,
        ConnFilter::Blocked,
        ConnFilter::Failed,
    ];

    /// Stable ENGLISH key — persisted to ui.json and parsed by `from_label`, so it must NOT change
    /// per language. Use [`display`](Self::display) for on-screen text.
    fn label(self) -> &'static str {
        match self {
            ConnFilter::All => "All",
            ConnFilter::Proxied => "Proxied",
            ConnFilter::Direct => "Direct",
            ConnFilter::Blocked => "Blocked",
            ConnFilter::Failed => "Failed",
        }
    }

    /// Localized label for rendering (kept separate from the persisted `label`).
    fn display(self) -> SharedString {
        match self {
            ConnFilter::All => t!("conn_filter.all"),
            ConnFilter::Proxied => t!("conn_filter.proxied"),
            ConnFilter::Direct => t!("conn_filter.direct"),
            ConnFilter::Blocked => t!("conn_filter.blocked"),
            ConnFilter::Failed => t!("conn_filter.failed"),
        }
        .into()
    }

    /// Parse a persisted label back to a filter (for saved UI state).
    fn from_label(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.label() == s)
    }

    /// Whether a row passes this decision/state filter.
    fn matches(self, r: &ConnectionRow) -> bool {
        match self {
            ConnFilter::All => true,
            ConnFilter::Proxied => r.proxy_or_chain.is_some(),
            ConnFilter::Direct => r.decision == "direct",
            ConnFilter::Blocked => r.state == "Blocked" || r.decision == "block",
            ConnFilter::Failed => r.state == "Failed",
        }
    }
}

/// Config-tab mode: read-only view, the per-field form editor, or the raw JSON editor.
#[derive(PartialEq, Clone, Copy)]
enum ConfigMode {
    View,
    Form,
    Json,
}

/// Which section the Config view/form shows — sub-tabs so it isn't one long scroll.
#[derive(PartialEq, Clone, Copy)]
enum ConfigSection {
    Rules,
    Proxies,
    Chains,
    Profile,
}

impl ConfigSection {
    const ALL: [ConfigSection; 4] = [
        ConfigSection::Rules,
        ConfigSection::Proxies,
        ConfigSection::Chains,
        ConfigSection::Profile,
    ];

    /// Stable ENGLISH key (persisted to ui.json / parsed by `from_label`). Use `display` on screen.
    fn label(self) -> &'static str {
        match self {
            ConfigSection::Rules => "Rules",
            ConfigSection::Proxies => "Proxies",
            ConfigSection::Chains => "Chains",
            ConfigSection::Profile => "Profile",
        }
    }

    /// Localized label for rendering (kept separate from the persisted `label`).
    fn display(self) -> SharedString {
        match self {
            ConfigSection::Rules => t!("config_section.rules"),
            ConfigSection::Proxies => t!("config_section.proxies"),
            ConfigSection::Chains => t!("config_section.chains"),
            ConfigSection::Profile => t!("config_section.profile"),
        }
        .into()
    }

    fn from_label(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.label() == s)
    }
}

/// Proxy auth scheme selectable in the form (mirrors `ProxyAuth`'s variants).
#[derive(PartialEq, Clone, Copy)]
enum AuthKind {
    None,
    UserPass,
    Basic,
    Digest,
    Negotiate,
}

impl AuthKind {
    fn label(self) -> &'static str {
        match self {
            AuthKind::None => "none",
            AuthKind::UserPass => "userPass",
            AuthKind::Basic => "basic",
            AuthKind::Digest => "digest",
            AuthKind::Negotiate => "negotiate",
        }
    }

    /// One-line explanation of the auth scheme (shown as a tooltip on the auth chips).
    fn tip(self) -> &'static str {
        match self {
            AuthKind::None => "No authentication — connect to the proxy anonymously.",
            AuthKind::UserPass => {
                "SOCKS5 username/password (RFC 1929). SOCKS4/4a send the username only."
            }
            AuthKind::Basic => {
                "HTTP Basic auth — username/password (base64, so use HTTPS proxies)."
            }
            AuthKind::Digest => {
                "HTTP Digest auth — challenge/response, password not sent in clear."
            }
            AuthKind::Negotiate => {
                "HTTP Negotiate / NTLM via Windows SSPI — authenticates with the engine's Windows \
                 identity (no password stored). Needs an HTTPS proxy with a trusted certificate; \
                 under the service that identity is the computer account, which is refused unless \
                 the proxy config allows it (allowServiceIdentity)."
            }
        }
    }

    fn from_auth(a: &ProxyAuth) -> Self {
        match a {
            ProxyAuth::None => AuthKind::None,
            ProxyAuth::UserPass { .. } => AuthKind::UserPass,
            ProxyAuth::Basic { .. } => AuthKind::Basic,
            ProxyAuth::Digest { .. } => AuthKind::Digest,
            ProxyAuth::Negotiate { .. } => AuthKind::Negotiate,
        }
    }

    /// Whether this scheme uses the username/password fields.
    fn needs_creds(self) -> bool {
        matches!(
            self,
            AuthKind::UserPass | AuthKind::Basic | AuthKind::Digest
        )
    }

    /// The auth schemes that apply to a given proxy kind, so the form only offers valid
    /// choices: SOCKS uses RFC-1929 user/pass (SOCKS4 ignores the password), while HTTP/HTTPS
    /// proxies use the HTTP auth schemes (basic / digest, and negotiate only over HTTPS, which
    /// config validation requires).
    fn allowed_for(kind: ProxyKind) -> &'static [AuthKind] {
        match kind {
            ProxyKind::Socks5 | ProxyKind::Socks5Tls | ProxyKind::Socks4 | ProxyKind::Socks4a => {
                &[AuthKind::None, AuthKind::UserPass]
            }
            ProxyKind::Http => &[AuthKind::None, AuthKind::Basic, AuthKind::Digest],
            ProxyKind::Https => &[
                AuthKind::None,
                AuthKind::Basic,
                AuthKind::Digest,
                AuthKind::Negotiate,
            ],
        }
    }

    fn build(self, user: String, pass: String) -> ProxyAuth {
        match self {
            AuthKind::None => ProxyAuth::None,
            AuthKind::UserPass => ProxyAuth::UserPass {
                username: user,
                password: Secret::new(pass),
            },
            AuthKind::Basic => ProxyAuth::Basic {
                username: user,
                password: Secret::new(pass),
            },
            AuthKind::Digest => ProxyAuth::Digest {
                username: user,
                password: Secret::new(pass),
            },
            AuthKind::Negotiate => ProxyAuth::Negotiate {
                allow_service_identity: false,
            },
        }
    }
}

/// Split a `host:port` endpoint into its parts (host keeps any `[ipv6]` brackets).
fn split_host_port(endpoint: &str) -> (String, String) {
    match endpoint.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => (endpoint.to_string(), String::new()),
    }
}

/// Rejoin host + port into an endpoint (omit the `:` when no port is given).
fn join_host_port(host: &str, port: &str) -> String {
    let (host, port) = (host.trim(), port.trim());
    if port.is_empty() {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// The item being edited in the form's detail panel.
#[derive(PartialEq, Clone, Copy)]
enum FormSel {
    Rule(usize, usize),
    Proxy(usize),
    Chain(usize),
}

/// Outcome of a successful `SetConfig`. `restart` is `Some` when the change was saved but needs a
/// restart to take effect; `config_digest` is the engine's digest of the saved config — the GUI
/// waits for the engine's *running* digest to reach it before declaring the change live (so a fast
/// in-place restart whose pipe drop falls between polls is still detected).
struct SaveOk {
    restart: Option<RestartRequired>,
    config_digest: Option<u64>,
    /// Advisory validation warnings from the engine for the config just saved — best-effort-config
    /// steering (e.g. domain rules under a non-fakeIp dns.mode). Shown in an amber panel; non-blocking.
    warnings: Vec<String>,
}

/// A message from the background IPC thread to the UI.
enum Msg {
    /// A connection-list poll result. `total`/`active` are the registry's true counts, which
    /// can exceed `rows.len()` when the listing is capped — so the status bar reports them
    /// honestly rather than from the capped slice. `reachable` is the poll outcome (the engine
    /// answered), which drives the explicit `EngineState` without sniffing the status string.
    /// `running_config_digest` is the engine's digest of the config it is running (None if the
    /// engine predates the field or the poll failed) — the restart-completion signal.
    Status {
        status: String,
        rows: Vec<ConnectionRow>,
        total: u64,
        active: u64,
        reachable: bool,
        running_config_digest: Option<u64>,
        /// The engine's effective (running) profile, from the same per-tick Status poll — `None` if
        /// the poll failed or the service predates the field. Polled every tick so the status bar
        /// and config tab reflect a profile-changing restart within ~1 s, not up to 5 s late.
        running_profile: Option<String>,
        /// `Some(scope)` when the engine's saved config differs from the running one (a
        /// restart-required save not yet applied), so a fresh session can surface a pending restart.
        /// `None` when in sync or the poll/older-service yields nothing.
        pending_restart_scope: Option<RestartScope>,
        /// Digest of the engine's last-saved config — the restart-completion target while a restart
        /// is pending, refreshed every poll so it tracks the latest save. `None` on a failed poll.
        saved_config_digest: Option<u64>,
        /// The engine's kill-switch is armed but its permit-all heartbeat is missing, so direct/host
        /// traffic is being blocked by the WFP floor — drives a status-bar warning. `false` on a
        /// failed poll or an older service (the wire field defaults).
        killswitch_degraded: bool,
        /// Per-proxy health from the engine's background monitor (only proxies with a probed
        /// `healthCheck` appear). `Some(..)` when the Status leg answered (possibly an empty vec, an
        /// older service, or no health checks); `None` when the Status leg FAILED this tick — the
        /// handler then keeps the last-known badges instead of blanking them (mirrors
        /// `running_profile`). Drives the per-proxy health badges in the config tab.
        proxy_health: Option<Vec<proxroute_ipc::ProxyHealth>>,
        /// True if EITHER poll leg failed this tick (Status or ListConnections) — computed in the
        /// worker, used ONLY for the digest-less restart drop/reconnect fallback
        /// (restart::any_poll_leg_failed). Kept separate from `reachable` (= either leg answered) so a
        /// single-leg failure during a legacy restart is still recorded as a drop.
        any_leg_failed: bool,
        /// True when `rows` came from a SUCCESSFUL ListConnections leg. A failed leg sends an empty
        /// vec that must NOT be ingested as a real snapshot: wiping the poll-diff state (`seen`/
        /// `seen_bytes`) makes the recovery poll re-log every retained connection as freshly opened
        /// and count every row's full cumulative byte totals as one interval's throughput.
        rows_valid: bool,
        /// The GUI's config-operation generation (`EditSession::config_seq`, mirrored to the worker
        /// through an atomic) loaded when this poll was CAPTURED. The poll worker and the save
        /// thread share one channel, but a Status captured before a save can be enqueued after its
        /// `SaveResult` — its digests then describe the PRE-save revision, and acting on them
        /// regresses the restart target (firing a false "restart complete" that discards the save's
        /// warnings) and triggers spurious auto-reloads. The handler skips digest-driven logic when
        /// this doesn't match the current generation; rows/health/status text are still applied.
        config_seq_at_capture: u64,
    },
    /// The config fetch: the parsed config plus the engine's revision token (digest, `None` from an
    /// older engine), echoed back as `SetConfig.base_digest` for optimistic concurrency; or an error.
    /// `reload_gen` is `Some(config_seq-at-issue)` for a user-triggered Reload (so a stale response is
    /// dropped if a save completed OR a newer reload was issued since) and `None` for the startup fetch.
    Config {
        result: Result<(Config, Option<u64>), String>,
        reload_gen: Option<u64>,
    },
    /// The result of a `SetConfig` save (see [`SaveOk`]), or Err(validation/IO error messages).
    /// `session_gen` is the edit-session generation that ISSUED the save: a save can outlive its
    /// session (Revert during a slow save, then a fresh edit), and the late result must then apply
    /// only its config-level effects — force-closing the CURRENT session would silently discard an
    /// unrelated draft, bypassing the two-click discard protection.
    SaveResult {
        session_gen: u64,
        result: Result<SaveOk, Vec<String>>,
    },
    /// The routing explanation for connection `id` (`ExplainConnection`), or an error string.
    /// Tagged with the id so a late reply for a no-longer-selected row is dropped.
    Explanation {
        id: u64,
        result: Result<String, String>,
    },
    /// A proxy check result, tagged with `checked` — the serialized proxy snapshot the check
    /// ran against — so a late reply is dropped if the editor no longer matches it (different
    /// proxy, or any field edited since).
    ProxyCheck {
        checked: String,
        result: Result<String, String>,
    },
    /// Periodic engine info from `Request::Status` (the driver version) — surfaced less often than
    /// the per-tick status since it changes rarely.
    EngineInfo { driver_version: Option<u32> },
    /// The outcome of a triggered `RestartEngine`: `Ok` when accepted (completion is then detected
    /// by the status poll), or `Err` when the engine refused/failed it — distinct from a config
    /// `SaveResult` so a restart error can clear the in-flight deadline without being mistaken for a
    /// validation problem.
    RestartResult(Result<(), Vec<String>>),
}

/// Own a tokio runtime on a background thread: fetch the config once (`GetConfig`), then
/// poll `ListConnections` ~1×/s, pushing each result to the UI over `tx`. Returns when
/// the UI drops the receiver. `config_seq` mirrors `EditSession::config_seq`; each poll loads it
/// at CAPTURE time and stamps its `Msg::Status`, so the handler can tell a poll that predates a
/// since-processed save/reload and skip acting on its stale digests.
fn spawn_worker(tx: mpsc::UnboundedSender<Msg>, config_seq: Arc<AtomicU64>) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.unbounded_send(Msg::Status {
                    status: t!("worker.runtime_error", error = e).into(),
                    rows: Vec::new(),
                    total: 0,
                    active: 0,
                    reachable: false,
                    running_config_digest: None,
                    running_profile: None,
                    pending_restart_scope: None,
                    saved_config_digest: None,
                    killswitch_degraded: false,
                    proxy_health: None,
                    any_leg_failed: true,
                    rows_valid: false,
                    config_seq_at_capture: config_seq.load(AtomicOrdering::Relaxed),
                });
                return;
            }
        };
        rt.block_on(async move {
            // Load the last-saved config (redacted) for the Config tab. If this fails (e.g. the engine is down
            // when the GUI starts), `config_loaded` stays false and the poll loop below retries
            // GetConfig until it succeeds — so the Config tab recovers once the engine comes up,
            // just like the connection poll does.
            let config = match proxroute_ipc::request(&Request::GetConfig).await {
                // STRICT parse via the shared helper (see config_load) — a config from a NEWER engine
                // carrying fields this GUI doesn't know is REJECTED here, not silently down-shaped.
                Ok(Response::Config { json, digest }) => {
                    config_load::parse_get_config(&json, digest)
                }
                Ok(other) => Err(format!("unexpected reply to GetConfig: {other:?}")),
                Err(e) => Err(format!("engine not reachable ({e})")),
            };
            let mut config_loaded = config.is_ok();
            if tx
                .unbounded_send(Msg::Config {
                    result: config,
                    reload_gen: None,
                })
                .is_err()
            {
                return;
            }

            // Then poll connections forever, with a slower Status refresh for engine info.
            let mut tick = 0u32;
            loop {
                // Retry the config fetch until it loads — the engine may have been down at GUI
                // start, so the initial GetConfig failed. Only a success is reported (the error
                // was already shown once); it stops retrying once loaded.
                if !config_loaded {
                    if let Ok(Response::Config { json, digest }) =
                        proxroute_ipc::request(&Request::GetConfig).await
                    {
                        if let Ok(parsed) = config_load::parse_get_config(&json, digest) {
                            config_loaded = true;
                            if tx
                                .unbounded_send(Msg::Config {
                                    result: Ok(parsed),
                                    reload_gen: None,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                // Poll engine status each tick for the running-config digest (the restart-completion
                // signal) AND the RUNNING profile — both travel in the per-tick Msg::Status so a
                // profile-changing restart reflects within ~1 s. The driver version changes rarely,
                // so it rides the slower EngineInfo cadence. The running profile is the engine's
                // EFFECTIVE profile, which differs from the config's activeProfile under `--profile`.
                // Load the generation BEFORE the first digest-bearing request: if a save/reload is
                // processed after this point, the digests below describe the older revision and the
                // handler must not act on them (the generations won't match).
                let config_seq_at_capture = config_seq.load(AtomicOrdering::Relaxed);
                let (
                    driver_version,
                    running_config_digest,
                    running_profile,
                    pending_restart_scope,
                    saved_config_digest,
                    status_ok,
                    killswitch_degraded,
                    proxy_health,
                ) = match proxroute_ipc::request(&Request::Status).await {
                    Ok(Response::Status {
                        driver_version,
                        running_config_digest,
                        active_profile,
                        pending_restart_scope,
                        saved_config_digest,
                        killswitch_degraded,
                        proxy_health,
                        ..
                    }) => (
                        driver_version,
                        running_config_digest,
                        Some(active_profile),
                        pending_restart_scope,
                        saved_config_digest,
                        true,
                        killswitch_degraded,
                        proxy_health,
                    ),
                    _ => (None, None, None, None, None, false, false, Vec::new()),
                };
                // Only carry health when the Status leg actually answered; `None` tells the handler
                // to keep the last-known badges rather than blank them on a transient failed poll.
                let proxy_health = status_ok.then_some(proxy_health);
                if tick.is_multiple_of(5)
                    && tx
                        .unbounded_send(Msg::EngineInfo { driver_version })
                        .is_err()
                {
                    break;
                }
                tick = tick.wrapping_add(1);
                let msg = match proxroute_ipc::request(&Request::ListConnections).await {
                    Ok(Response::Connections {
                        rows,
                        total,
                        active,
                    }) => {
                        // Version skew: an older service may omit total/active (serde defaults
                        // them to 0). If rows came back, fall back to what we can see rather than
                        // reporting a misleading "0 tracked".
                        let counts_missing = total == 0 && !rows.is_empty();
                        let total = if counts_missing {
                            rows.len() as u64
                        } else {
                            total
                        };
                        let active = if counts_missing {
                            rows.iter()
                                .filter(|r| {
                                    matches!(
                                        r.state.as_str(),
                                        "Connecting" | "Established" | "Pending"
                                    )
                                })
                                .count() as u64
                        } else {
                            active
                        };
                        Msg::Status {
                            status: t!("status.live", count = total).into(),
                            rows,
                            total,
                            active,
                            reachable: restart::engine_reachable(status_ok, true),
                            running_config_digest,
                            running_profile,
                            pending_restart_scope,
                            saved_config_digest,
                            killswitch_degraded,
                            proxy_health,
                            any_leg_failed: restart::any_poll_leg_failed(status_ok, true),
                            rows_valid: true,
                            config_seq_at_capture,
                        }
                    }
                    Ok(other) => Msg::Status {
                        status: t!("worker.unexpected_reply", reply = format!("{other:?}")).into(),
                        rows: Vec::new(),
                        total: 0,
                        active: 0,
                        // Status is a separate request; if it answered, the engine is
                        // reachable and its restart-completion digest is valid even though
                        // this ListConnections leg didn't return rows. Forwarding the digest
                        // (not None) stops a flapping list call from stalling restart
                        // completion or manufacturing a spurious engine "drop".
                        reachable: restart::engine_reachable(status_ok, false),
                        running_config_digest,
                        running_profile,
                        pending_restart_scope,
                        saved_config_digest,
                        killswitch_degraded,
                        proxy_health,
                        any_leg_failed: restart::any_poll_leg_failed(status_ok, false),
                        rows_valid: false,
                        config_seq_at_capture,
                    },
                    Err(e) => Msg::Status {
                        status: if status_ok {
                            t!("worker.engine_up_no_list", error = e).into()
                        } else {
                            t!("worker.engine_unreachable", error = e).into()
                        },
                        rows: Vec::new(),
                        total: 0,
                        active: 0,
                        reachable: restart::engine_reachable(status_ok, false),
                        running_config_digest,
                        running_profile,
                        pending_restart_scope,
                        saved_config_digest,
                        killswitch_degraded,
                        proxy_health,
                        any_leg_failed: restart::any_poll_leg_failed(status_ok, false),
                        rows_valid: false,
                        config_seq_at_capture,
                    },
                };
                if tx.unbounded_send(msg).is_err() {
                    break; // UI gone
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    });
}

// =================== Connections table delegate ============================

/// Backs the Connections `DataTable`: owns the rows + column defs + current sort.
struct ConnDelegate {
    rows: Vec<ConnectionRow>,
    columns: Vec<Column>,
    /// Active sort (column index + direction), re-applied after each poll so a sorted
    /// view stays sorted as data refreshes.
    sort: Option<(usize, ColumnSort)>,
}

impl ConnDelegate {
    fn new() -> Self {
        // Headers are localized at construction (after set_locale at startup); a live language
        // switch re-applies them via `ConnDelegate::relocalize` (see `AppView::render`).
        let col = |key: &str, name: SharedString, w: f32| {
            Column::new(key.to_string(), name)
                .width(px(w))
                .resizable(true)
                .sortable()
        };
        Self {
            rows: Vec::new(),
            columns: vec![
                col("pid", t!("table.conn.pid").into(), 60.0),
                col("process", t!("table.conn.process").into(), 170.0),
                col("protocol", t!("table.conn.protocol").into(), 64.0),
                col("destination", t!("table.conn.destination").into(), 290.0),
                col("decision", t!("table.conn.decision").into(), 160.0),
                col("state", t!("table.conn.state").into(), 100.0),
                col("sent", t!("table.conn.sent").into(), 90.0),
                col("recv", t!("table.conn.received").into(), 100.0),
            ],
            sort: None,
        }
    }

    /// Re-localize the column headers in place after a live language switch, preserving each
    /// column's width, sort, and order (only the display `name` changes; the stable `key` matches).
    fn relocalize(&mut self) {
        for col in &mut self.columns {
            col.name = match col.key.as_ref() {
                "pid" => t!("table.conn.pid"),
                "process" => t!("table.conn.process"),
                "protocol" => t!("table.conn.protocol"),
                "destination" => t!("table.conn.destination"),
                "decision" => t!("table.conn.decision"),
                "state" => t!("table.conn.state"),
                "sent" => t!("table.conn.sent"),
                "recv" => t!("table.conn.received"),
                _ => continue,
            }
            .into();
        }
    }

    /// Replace the rows (from a poll), re-applying the active sort.
    fn set_rows(&mut self, rows: Vec<ConnectionRow>) {
        self.rows = rows;
        self.apply_sort();
    }

    fn apply_sort(&mut self) {
        let Some((col_ix, sort)) = self.sort else {
            return;
        };
        let Some(key) = self.columns.get(col_ix).map(|c| c.key.clone()) else {
            return;
        };
        let desc = matches!(sort, ColumnSort::Descending);
        // Compute each row's sort key ONCE. The previous sort_by recomputed it — and, for the
        // process/destination/decision columns, re-allocated a String — on every pairwise comparison
        // (O(n log n) allocations each 1 s poll). sort_by_cached_key computes it n times and is
        // stable; `Reverse` makes descending a stable key reversal, identical to the old
        // `ord.reverse()`.
        macro_rules! sort_rows {
            ($k:expr) => {
                if desc {
                    self.rows.sort_by_cached_key(|r| std::cmp::Reverse($k(r)));
                } else {
                    self.rows.sort_by_cached_key($k);
                }
            };
        }
        match key.as_ref() {
            "pid" => sort_rows!(|r: &ConnectionRow| r.pid),
            "process" => sort_rows!(|r: &ConnectionRow| process_basename(&r.process)),
            "protocol" => sort_rows!(|r: &ConnectionRow| r.protocol.clone()),
            "destination" => sort_rows!(|r: &ConnectionRow| destination(r)),
            "decision" => sort_rows!(|r: &ConnectionRow| decision_label(r)),
            "state" => sort_rows!(|r: &ConnectionRow| r.state.clone()),
            "sent" => sort_rows!(|r: &ConnectionRow| r.bytes_sent),
            "recv" => sort_rows!(|r: &ConnectionRow| r.bytes_recv),
            _ => {}
        }
    }
}

impl TableDelegate for ConnDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        self.columns[col_ix].clone()
    }

    fn perform_sort(
        &mut self,
        col_ix: usize,
        sort: ColumnSort,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        self.sort = Some((col_ix, sort));
        self.apply_sort();
        cx.notify();
    }

    /// Right-click menu for a connection row: create a rule for its app, or show details.
    /// The actions dispatch up to `AppView`, which reads the row from `ctx_row` (set by
    /// the `RightClickedRow` event).
    fn context_menu(
        &mut self,
        row_ix: usize,
        menu: PopupMenu,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> PopupMenu {
        let Some(r) = self.rows.get(row_ix) else {
            return menu;
        };
        let app = process_basename(&r.process);
        menu.menu(
            t!("button.create_rule_for", app = app),
            Box::new(CreateRuleFromConn),
        )
        .menu(t!("button.explain_routing"), Box::new(ExplainConn))
        .menu(t!("button.show_details"), Box::new(ShowConnDetails))
    }

    /// Header cell with an explicit, visible sort indicator: ▲/▼ on the active column,
    /// a dim ↕ on the other (sortable) columns so the affordance is discoverable.
    fn render_th(
        &mut self,
        col_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let col = &self.columns[col_ix];
        let numeric = matches!(col.key.as_ref(), "pid" | "sent" | "recv");
        let (arrow, color) = match self.sort {
            Some((ix, ColumnSort::Descending)) if ix == col_ix => ("▼", FG),
            Some((ix, _)) if ix == col_ix => ("▲", FG),
            _ => ("↕", FG_DIM),
        };
        let mut h = div().h_flex().gap_1().items_center();
        if numeric {
            h = h.w_full().justify_end();
        }
        h.child(col.name.clone())
            .child(div().text_color(rgb(color)).child(arrow))
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(r) = self.rows.get(row_ix) else {
            return div().into_any_element();
        };
        let Some(col) = self.columns.get(col_ix) else {
            return div().into_any_element();
        };
        match col.key.as_ref() {
            "pid" => num_cell(r.pid.to_string()).into_any_element(),
            "process" => {
                let full = full_path_of(r);
                div()
                    .id(("proc", row_ix))
                    .child(process_basename(&r.process))
                    .tooltip(move |window, cx| Tooltip::new(full.clone()).build(window, cx))
                    .into_any_element()
            }
            "protocol" => div().child(r.protocol.clone()).into_any_element(),
            "destination" => div().child(destination(r)).into_any_element(),
            "decision" => div()
                .text_color(rgb(decision_color(&r.decision)))
                .child(decision_label(r))
                .into_any_element(),
            "state" => {
                let mut cell = div()
                    .h_flex()
                    .gap_1()
                    .items_center()
                    .text_color(rgb(state_color(&r.state)))
                    .child(r.state.clone());
                // Surface a failure reason at scan speed: a ⚠ badge with the error tooltip.
                if let Some(err) = r.error.clone() {
                    cell =
                        cell.child(div().id(("err", row_ix)).child("⚠").tooltip(
                            move |window, cx| Tooltip::new(err.clone()).build(window, cx),
                        ));
                }
                cell.into_any_element()
            }
            "sent" => num_cell(fmt_bytes(r.bytes_sent)).into_any_element(),
            "recv" => num_cell(fmt_bytes(r.bytes_recv)).into_any_element(),
            _ => div().into_any_element(),
        }
    }
}

/// A right-aligned cell, for numeric columns (PID / byte counts), Proxifier-style.
fn num_cell(text: String) -> Div {
    div().w_full().h_flex().justify_end().child(text)
}

/// One line in the event-log panel.
struct LogLine {
    text: String,
    color: u32,
    /// The connection this line is about, if any — lets a click jump to that row. `None` for
    /// notes (e.g. "exported log to …") that aren't tied to a connection.
    id: Option<u64>,
}

/// Event-log severity filter (severity derived from a line's color).
#[derive(PartialEq, Clone, Copy)]
enum LogFilter {
    All,
    Info,
    Warn,
    Error,
}

impl LogFilter {
    const ALL: [LogFilter; 4] = [
        LogFilter::All,
        LogFilter::Info,
        LogFilter::Warn,
        LogFilter::Error,
    ];

    /// Stable ENGLISH key (persisted to ui.json / parsed by `from_label`). Use `display` on screen.
    fn label(self) -> &'static str {
        match self {
            LogFilter::All => "All",
            LogFilter::Info => "Info",
            LogFilter::Warn => "Warn",
            LogFilter::Error => "Error",
        }
    }

    /// Localized label for rendering (kept separate from the persisted `label`).
    fn display(self) -> SharedString {
        match self {
            LogFilter::All => t!("log_filter.all"),
            LogFilter::Info => t!("log_filter.info"),
            LogFilter::Warn => t!("log_filter.warn"),
            LogFilter::Error => t!("log_filter.error"),
        }
        .into()
    }

    fn from_label(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.label() == s)
    }

    /// Whether a line of the given color passes: RED = error, YELLOW = warn, else info.
    fn matches(self, color: u32) -> bool {
        match self {
            LogFilter::All => true,
            LogFilter::Error => color == RED,
            LogFilter::Warn => color == YELLOW,
            LogFilter::Info => color != RED && color != YELLOW,
        }
    }
}

struct AppView {
    tab: Tab,
    /// Active UI language code (one of [`LOCALES`]). Drives the switcher's highlight and is
    /// persisted; `rust_i18n::set_locale` (a global) is what actually localizes `t!`.
    locale: &'static str,
    /// Set when the language changes at runtime. The table headers and input placeholders are
    /// localized once at construction (they need a `&mut Window`, which `set_language` lacks), so a
    /// live switch re-applies them on the next `render` (which has the window) via this flag.
    relocalize_pending: bool,
    status: String,
    /// Explicit engine connectivity state (drives the status-bar dot/label).
    engine_state: EngineState,
    /// The kill-switch is armed but its heartbeat is missing (direct/host egress blocked by the WFP
    /// floor), from the latest Status poll — drives a status-bar warning.
    killswitch_degraded: bool,
    /// Per-proxy health (name → verdict) from the latest SUCCESSFUL Status poll, for the proxy/chain
    /// health badges. Only proxies with a probed `healthCheck` appear. Retained (not cleared) when a
    /// Status poll fails, so badges don't flicker off on a transient blip — it can be momentarily
    /// stale while the engine is unreachable.
    proxy_health: std::collections::HashMap<String, proxroute_ipc::ProxyHealth>,
    /// The config the user views/edits (the last-saved document).
    config: Option<Config>,
    /// The config the engine is actually running. Equals `config` except between a
    /// restart-required save and the restart — so the status bar shows what's truly live,
    /// not pending structural changes.
    running_config: Option<Config>,
    config_error: Option<String>,
    /// The engine's revision token for the config currently being edited (from `GetConfig`, refreshed
    /// from `Applied` after each save). Sent as `SetConfig.base_digest` so the engine rejects a save
    /// built on a stale view (another client, a CLI reload, or a pending restart-required save).
    /// `None` before the first fetch or against an older engine (then the check is skipped).
    base_digest: Option<u64>,
    /// Config-tab mode (read-only view / form editor / JSON editor).
    config_mode: ConfigMode,
    /// Which config section (sub-tab) the view/form shows.
    config_section: ConfigSection,
    /// Editable working copy for the form editor (cloned from `config` on entering Form).
    draft: Option<Config>,
    /// The form item whose detail editor is open (its text fields live in the inputs below).
    form_sel: Option<FormSel>,
    /// The detail-panel form inputs + their scalar toggles, grouped (see [`ConfigEditor`]).
    form: ConfigEditor,
    /// JSON config editor (populated from the saved config when entering JSON mode).
    editor: Entity<InputState>,
    /// The config edit/save session workflow — in-flight flags, save feedback, and confirm-dialog
    /// arming (see [`EditSession`]).
    edit: EditSession,
    /// Mirror of `edit.config_seq` shared with the poll worker (kept in sync by
    /// [`Self::bump_config_seq`]): the worker stamps each poll with the generation loaded at
    /// capture time, so the Status handler can ignore digests captured before a since-processed
    /// save/reload (see `Msg::Status::config_seq_at_capture`).
    config_seq_shared: Arc<AtomicU64>,
    /// Sender clone so a Save can report its result back on the same channel.
    tx: mpsc::UnboundedSender<Msg>,
    /// The live traffic monitoring view — connections table, event log, filters, poll-diff
    /// state, and the selected/right-clicked row (see [`TrafficView`]).
    traffic: TrafficView,
    /// Form-input change subscriptions — flush typed text into the draft on every change so the
    /// "unsaved" badge is accurate immediately, not only after a flush-triggering action.
    _form_subs: Vec<Subscription>,
    /// Status-bar traffic metrics, recomputed each poll (see [`Metrics`]).
    metrics: Metrics,
    /// Last proxy reachability-check result, shown under the proxy editor.
    proxy_check: Option<String>,
    /// Whether the proxy editor is entering a NEW password (vs keeping the stored secret, which is
    /// never loaded into the input — avoids accidental exposure / blanking). The typed value lives
    /// ONLY in the input widget: `flush` never writes it into `draft` (which always keeps the
    /// `<unchanged>` placeholder), so an abandoned change can't be persisted — it is merged into a
    /// config only at Save / Check via [`Self::pending_password`].
    pass_changing: bool,
    /// Engine driver version (from `Request::Status`), shown in the status bar.
    driver_version: Option<u32>,
    /// The profile the engine is ACTUALLY running (its effective profile, from `Request::Status`).
    /// Differs from the config's `activeProfile` under a `--profile` override, so the status bar must
    /// show THIS, not `running_config.active_profile`. `None` until the first status poll.
    running_profile_name: Option<String>,
    /// The profile FROZEN for the currently-open form edit, captured when the draft was seeded.
    /// `Some` only while the form editor is open. Form lookups/edits resolve against this so a
    /// mid-edit running-profile change can't retarget the open `form_sel` index onto another
    /// profile. `None` outside the form (the read-only view follows the running profile live).
    form_profile_name: Option<String>,
    /// True when [`Self::form_profile_name`] was frozen BEFORE the first status poll reported the
    /// running profile, so it provisionally used the config's active profile — which can be wrong
    /// under a `--profile` override. When the running profile first arrives, a still-pristine form is
    /// re-aimed at it (see `reconcile_provisional_freeze`); an already-edited form keeps its profile
    /// and the drift banner warns. Cleared once reconciled or the form closes.
    form_profile_provisional: bool,
    /// Pending-restart state machine (grouped so it travels together — see [`RestartTracker`]).
    restart: RestartTracker,
}

/// The config edit/save session: in-flight save/reload flags, the save feedback (status + the
/// error/warning panels), confirm-dialog arming, and the pending save bookkeeping. Grouped out of
/// `AppView`; every field is `Default`-able (built via `EditSession::default()`).
#[derive(Default)]
struct EditSession {
    /// The config sent by the in-flight save, applied to `config` on success.
    pending_config: Option<Config>,
    /// Monotonic generation of the latest config OPERATION: bumped on every successful save AND on
    /// every Reload issuance. A reload captures it when issued; if it has advanced by the time the
    /// reload's GetConfig response arrives — a save completed OR a newer reload was issued — the older
    /// response is dropped rather than moving self.config/base_digest backward to an older snapshot.
    config_seq: u64,
    /// A SetConfig save is in flight (set in `save`, cleared in `SaveResult`). Reload and Save are
    /// disabled while true so a second save / a racing reload can't start.
    saving: bool,
    /// A GetConfig reload is in flight (set in `reload_config`, cleared when its `Msg::Config`
    /// arrives). Gates the auto-refresh so a stale self.config triggers at most one refetch.
    reloading: bool,
    /// Last save outcome shown in the editor toolbar.
    save_status: String,
    /// Structured validation/save errors (one per problem) shown in a panel under the
    /// toolbar — each is a "location: message" the panel splits into a badge + hint.
    save_errors: Vec<String>,
    /// Advisory validation warnings from the last successful save (engine-side; the GUI runs no
    /// validation of its own). Shown in an amber panel under the toolbar; cleared alongside errors.
    save_warnings: Vec<String>,
    /// Revert is armed for a second confirming click (only when there are unsaved changes).
    confirm_revert: bool,
    /// Reload (refetch the saved config from the engine) is armed for a second confirming click when
    /// it would discard unsaved edits — the recovery path after a stale-save rejection.
    confirm_reload: bool,
    /// A section sub-tab the user clicked while editing with unsaved changes. Switching
    /// sections closes edit mode, so rather than silently discard the draft we hold the
    /// target here and show a discard-confirm banner first.
    pending_section: Option<ConfigSection>,
    /// A right-clicked connection whose "Create rule" would DISCARD unsaved JSON-editor edits:
    /// held here (instead of acting immediately) so a discard-confirm banner can gate it, matching
    /// every other dirty-editor exit. `Some` only while that banner is up in the JSON editor.
    /// Grouped with the other confirm/pending state so retire_session/close_to_view clear it in
    /// one place.
    pending_create_rule: Option<ConnectionRow>,
    /// Monotonic generation of the edit SESSION (bumped by enter_form / enter_json / exit_edit).
    /// A save stamps the generation that issued it; a `SaveResult` arriving after that session
    /// ended (Revert during a slow save, then a fresh edit) applies only its config-level effects
    /// and must not force-close the newer, unrelated session.
    session_gen: u64,
}

/// The live traffic-monitoring view: the connections table + its filter/selection, the derived
/// event log + its tools, and the poll-diff bookkeeping that feeds both. Grouped out of `AppView`
/// so the monitoring tab's ~two-dozen fields travel together. Built in [`AppView::new`] (the table
/// and inputs need a `cx`).
struct TrafficView {
    table: Entity<TableState<ConnDelegate>>,
    _sub: Subscription,
    /// Snapshot of the double-clicked connection, shown in the detail panel.
    selected: Option<ConnectionRow>,
    /// Event log (newest first), derived by diffing each poll against `seen`.
    log: VecDeque<LogLine>,
    /// Last-seen lifecycle state per connection id, to detect open/close transitions.
    seen: HashMap<u64, String>,
    /// Last-seen byte totals per connection id, to derive throughput from deltas.
    seen_bytes: HashMap<u64, (u64, u64)>,
    /// Suppress logging / rate spikes for the connections that already existed at first poll.
    first_poll: bool,
    /// Connections quick-filter: the latest unfiltered poll (`all_rows`) is filtered by a
    /// search box (process/destination substring) + a decision/state chip to produce the
    /// table's visible rows. `shown` is the post-filter count, for the status bar.
    all_rows: Vec<ConnectionRow>,
    filter_input: Entity<InputState>,
    filter_kind: ConnFilter,
    shown: usize,
    _filter_sub: Subscription,
    /// Freeze the table (stop applying polls) so a row can be inspected; the log + rates
    /// keep updating.
    paused: bool,
    /// A connection a paused-table log click asked to select; applied once the table resumes
    /// and the row is back in `all_rows`.
    pending_select: Option<u64>,
    /// Terminal rows the user cleared from the view; pruned as the engine ages them out.
    hidden_terminal: HashSet<u64>,
    /// The most recently right-clicked row, acted on by the row context-menu actions.
    ctx_row: Option<ConnectionRow>,
    /// Routing explanation (`ExplainConnection`) for the selected row, shown in the detail
    /// panel; `None` until requested, then "explaining…" / the text / an error.
    explanation: Option<String>,
    /// Event-log tools: severity filter + free-text search over the log lines.
    log_filter: LogFilter,
    log_search: Entity<InputState>,
    _log_sub: Subscription,
}

/// Status-bar traffic metrics, recomputed on each successful poll.
#[derive(Default)]
struct Metrics {
    active: usize,
    total: usize,
    rate_sent: u64,
    rate_recv: u64,
    last_poll: Option<Instant>,
}

/// The Config-tab detail-panel editor state: the reusable text inputs (seeded on selection, flushed
/// to `draft`) plus their scalar toggles. Grouped out of `AppView` so the ~two-dozen form fields
/// travel together. Built once in [`AppView::new`] (the inputs need a `cx`), not `Default`.
struct ConfigEditor {
    /// Rule identity + app-name match.
    name: Entity<InputState>,
    apps: Entity<InputState>,
    /// Rule destination-match fields (comma-separated), plus protocol toggles.
    domains: Entity<InputState>,
    ips: Entity<InputState>,
    ports: Entity<InputState>,
    tcp: bool,
    udp: bool,
    /// Advanced rule-match fields (the "Advanced match" foldout): app path/parent/signer
    /// patterns, IP-family toggles, and a time window (days / hours).
    app_paths: Entity<InputState>,
    app_parent: Entity<InputState>,
    signed_by: Entity<InputState>,
    v4: bool,
    v6: bool,
    days: Entity<InputState>,
    hours: Entity<InputState>,
    /// Whether the rule's "Advanced match" foldout is expanded.
    adv_open: bool,
    /// Proxy host (`endpoint`) is split from its port (`pport`); `auth` is the selected auth scheme
    /// (the username/password inputs apply to it).
    endpoint: Entity<InputState>,
    pport: Entity<InputState>,
    auth: AuthKind,
    user: Entity<InputState>,
    pass: Entity<InputState>,
    /// Proxy health check: `hc_enabled` toggles `ProxyDef.health_check` between `None` and a
    /// `Some(..)` built (on flush) from `hc_target` (ip:port) and `hc_interval` (seconds).
    hc_enabled: bool,
    hc_target: Entity<InputState>,
    hc_interval: Entity<InputState>,
}

/// State for a config change that was saved but needs a restart to take effect — the fragile part
/// of the `Msg::Status` orchestration. Grouped into one struct so the restart machine's fields stay
/// together rather than scattered across the 5.9k-line view.
#[derive(Default)]
struct RestartTracker {
    /// A structural config change was saved but needs a restart to take effect.
    needed: bool,
    /// Which restart the pending change needs — an in-place engine restart, or a full service
    /// restart (logLevel / kill-switch floor changes, which RestartEngine refuses). Drives the action.
    scope: Option<RestartScope>,
    /// The engine's digest of the saved config a pending restart must reach (from `Applied`). The
    /// restart is complete once a status poll reports this as the engine's *running* digest — a
    /// signal keyed off the engine's own state, so a fast in-place restart whose pipe drop falls
    /// between 1 s polls is still detected (the old `saw_drop` drop-observation could miss it).
    /// `None` when no restart is pending, or when the engine predates the digest field.
    target_digest: Option<u64>,
    /// Deadline for an in-place restart we triggered (`RestartEngine`); if the running digest never
    /// reaches the target by then, we surface a "did not complete" status instead of spinning. Only
    /// set for the engine-scope restart the GUI initiates — a service-scope restart is the user's to
    /// perform, so it waits without a timeout.
    deadline: Option<Instant>,
    /// Whether we've seen the engine drop since a triggered in-place restart — used ONLY for the
    /// legacy fallback when talking to a service too old to report a config digest (see
    /// [`restart::restart_completed`]). A digest-aware peer ignores this.
    saw_drop: bool,
}

/// The password string of a proxy auth (empty for schemes without one).
fn password_of(auth: &ProxyAuth) -> String {
    match auth {
        ProxyAuth::UserPass { password, .. }
        | ProxyAuth::Basic { password, .. }
        | ProxyAuth::Digest { password, .. } => password.expose().to_string(),
        _ => String::new(),
    }
}

/// Overwrite a proxy auth's password in place (auth-kind and username unchanged). Used to merge a
/// pending password change into the cloned draft (see [`AppView::effective_draft`]); a no-op for
/// passwordless auth kinds.
fn set_password(auth: &mut ProxyAuth, pw: String) {
    match auth {
        ProxyAuth::UserPass { password, .. }
        | ProxyAuth::Basic { password, .. }
        | ProxyAuth::Digest { password, .. } => *password = Secret::new(pw),
        _ => {}
    }
}

/// Re-match a selected row across polls by its stable registry id.
fn same_connection(a: &ConnectionRow, b: &ConnectionRow) -> bool {
    a.id == b.id
}

fn is_terminal(state: &str) -> bool {
    matches!(state, "Closed" | "Failed" | "Blocked" | "Cancelled")
}

/// Color for the editor save-status line: ✓ applied (green), ✗ error (red), else dim.
fn status_color(s: &str) -> u32 {
    if s.starts_with('✓') {
        GREEN
    } else if s.starts_with('✗') {
        RED
    } else {
        FG_DIM
    }
}

/// Shorten a transient `save_status` into a compact badge word for the Config header (the full
/// string still drives [`status_color`]). Classified STRUCTURALLY — the ✓/✗ glyph prefixes
/// (locale-independent by design: every locale's success/failure statuses carry them) plus the
/// saving/restarting state flags — never by matching localized substrings, which would break under
/// any non-English locale. (A restart-REQUIRED save never reaches here: the caller shows the
/// dedicated "restart needed" badge instead when `restart.needed`, so there is no such branch.)
fn compact_status(s: &str, saving: bool, restarting: bool) -> SharedString {
    if s.starts_with('✗') {
        t!("save.compact_error").into()
    } else if s.starts_with('✓') {
        t!("save.compact_applied").into()
    } else if saving {
        t!("save.compact_saving").into()
    } else if restarting {
        t!("save.compact_restarting").into()
    } else {
        SharedString::from(s.to_string())
    }
}

/// Path to the persisted UI-preferences file (active tab, config section, filters).
fn ui_state_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(
        std::path::PathBuf::from(base)
            .join(proxroute_ipc::DATA_DIR_NAME)
            .join("ui.json"),
    )
}

/// UI languages the switcher offers: `(locale code, native display name)`. English is the source
/// of truth (`locales/en.yml`) and the fallback — a key missing from another locale degrades to it.
/// Adding a language is: drop `locales/<code>.yml`, add a row here.
const LOCALES: &[(&str, &str)] = &[("en", "English"), ("es", "Español"), ("ru", "Русский")];

/// A persisted/requested locale code clamped to one we actually ship (else English), so the
/// switcher's active-state and `set_locale` never point at a language with no catalog.
fn known_locale(code: &str) -> &'static str {
    LOCALES
        .iter()
        .find(|&&(c, _)| c == code)
        .map(|&(c, _)| c)
        .unwrap_or("en")
}

/// Load persisted UI preferences, falling back to defaults on any error — UI state is
/// best-effort and never blocks startup.
fn load_ui_state() -> (Tab, ConfigSection, ConnFilter, LogFilter, &'static str) {
    let defaults = (
        Tab::Connections,
        ConfigSection::Rules,
        ConnFilter::All,
        LogFilter::All,
        "en",
    );
    let Some(v) = ui_state_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    else {
        return defaults;
    };
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    (
        if s("tab") == "config" {
            Tab::Config
        } else {
            Tab::Connections
        },
        ConfigSection::from_label(&s("section")).unwrap_or(ConfigSection::Rules),
        ConnFilter::from_label(&s("filter")).unwrap_or(ConnFilter::All),
        LogFilter::from_label(&s("logFilter")).unwrap_or(LogFilter::All),
        known_locale(&s("locale")),
    )
}

/// A structured panel for config issues: one row per item, each split into a location badge and
/// the message hint (validation messages are "location: message"). `accent` colors the border and
/// heading (red for blocking errors, amber for advisory warnings), `heading` names the group, and
/// `fallback_badge` labels an item that isn't "location: message". `None` when there's nothing to
/// show, so the toolbar layout stays unchanged on success.
fn issue_panel(
    items: &[String],
    accent: u32,
    heading: &str,
    fallback_badge: &str,
) -> Option<AnyElement> {
    if items.is_empty() {
        return None;
    }
    let mut panel = div()
        .v_flex()
        .gap_1()
        .p_2()
        .rounded_md()
        .border_1()
        .border_color(rgb(accent))
        .bg(rgb(BG_PANEL))
        .child(
            div()
                .text_color(rgb(accent))
                .child(format!("{} {heading}", items.len())),
        );
    for e in items {
        // Validation messages are "location: message"; fall back to a generic badge otherwise.
        let (badge, msg) = match e.split_once(": ") {
            Some((loc, m)) if !loc.is_empty() => (loc.to_string(), m.to_string()),
            _ => (fallback_badge.to_string(), e.clone()),
        };
        panel = panel.child(
            div()
                .h_flex()
                .gap_2()
                .items_start()
                .child(
                    div()
                        .flex_none()
                        .px_1()
                        .rounded_sm()
                        .bg(rgb(BG_BAR))
                        .text_color(rgb(YELLOW))
                        .child(badge),
                )
                .child(div().flex_grow(1.0).text_color(rgb(FG)).child(msg)),
        );
    }
    Some(panel.into_any_element())
}

/// Log line for a connection seen for the first time: its terminal verdict if it was
/// blocked/failed at decision time, otherwise an "opened" line.
fn opened_line(now: &str, r: &ConnectionRow) -> LogLine {
    if is_terminal(&r.state) {
        return terminal_line(now, r);
    }
    let via = match &r.proxy_or_chain {
        Some(p) => t!("log.opened_via", target = p),
        None => t!("log.opened_direct"),
    };
    LogLine {
        text: format!(
            "[{now}] {}  {}  {}",
            process_basename(&r.process),
            destination(r),
            via
        ),
        color: GREEN,
        id: Some(r.id),
    }
}

/// Log line for a connection that just reached a terminal state.
fn terminal_line(now: &str, r: &ConnectionRow) -> LogLine {
    let (verb, color): (String, u32) = match r.state.as_str() {
        "Blocked" => (t!("log.blocked").into(), RED),
        "Failed" => (
            t!(
                "log.failed",
                detail = r
                    .error
                    .as_deref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            )
            .into(),
            RED,
        ),
        "Cancelled" => (t!("log.cancelled").into(), YELLOW),
        _ => (
            t!(
                "log.closed",
                sent = fmt_bytes(r.bytes_sent),
                recv = fmt_bytes(r.bytes_recv)
            )
            .into(),
            FG_DIM,
        ),
    };
    LogLine {
        text: format!(
            "[{now}] {}  {}  {}",
            process_basename(&r.process),
            destination(r),
            verb
        ),
        color,
        id: Some(r.id),
    }
}

impl AppView {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (tx, mut rx) = mpsc::unbounded::<Msg>();
        let config_seq_shared = Arc::new(AtomicU64::new(0));
        spawn_worker(tx.clone(), config_seq_shared.clone());
        // Restore the tab / config section / filters / language the user last left (best-effort).
        let (saved_tab, saved_section, saved_filter, saved_log_filter, saved_locale) =
            load_ui_state();
        // Apply the persisted language before the first render so the initial paint is localized.
        rust_i18n::set_locale(saved_locale);
        cx.spawn(async move |this, cx| {
            while let Some(msg) = rx.next().await {
                let pushed = this.update(cx, |view, cx| {
                    view.apply(msg, cx);
                    cx.notify();
                });
                if pushed.is_err() {
                    break;
                }
            }
        })
        .detach();

        let table = cx.new(|cx| TableState::new(ConnDelegate::new(), window, cx));
        let _sub = cx.subscribe_in(&table, window, Self::on_table_event);
        let editor = cx.new(|cx| InputState::new(window, cx).code_editor("json"));
        let f_name = cx.new(|cx| InputState::new(window, cx));
        let f_apps = cx.new(|cx| InputState::new(window, cx));
        let f_domains = cx.new(|cx| InputState::new(window, cx));
        let f_ips = cx.new(|cx| InputState::new(window, cx));
        let f_ports = cx.new(|cx| InputState::new(window, cx));
        let f_app_paths = cx.new(|cx| InputState::new(window, cx));
        let f_app_parent = cx.new(|cx| InputState::new(window, cx));
        let f_signed_by = cx.new(|cx| InputState::new(window, cx));
        let f_days = cx.new(|cx| InputState::new(window, cx).placeholder("Mon-Fri, Sat"));
        let f_hours = cx.new(|cx| InputState::new(window, cx).placeholder("09:00-18:00"));
        let f_endpoint = cx.new(|cx| InputState::new(window, cx));
        let f_pport = cx.new(|cx| InputState::new(window, cx));
        let f_user = cx.new(|cx| InputState::new(window, cx));
        // Proxy secret starts masked; the Input's mask_toggle adds an eye to reveal.
        let f_pass = cx.new(|cx| InputState::new(window, cx).masked(true));
        // Health-check probe target (ip:port) + interval (seconds), shown when a proxy's health
        // check is enabled.
        let f_hc_target = cx.new(|cx| InputState::new(window, cx).placeholder("1.1.1.1:443"));
        let f_hc_interval = cx.new(|cx| {
            InputState::new(window, cx).placeholder(DEFAULT_HEALTH_INTERVAL_SECS.to_string())
        });
        let filter_input = cx.new(|cx| InputState::new(window, cx).placeholder(t!("input.filter")));
        let _filter_sub = cx.subscribe_in(&filter_input, window, Self::on_filter_event);
        let log_search =
            cx.new(|cx| InputState::new(window, cx).placeholder(t!("input.log_search")));
        let _log_sub = cx.subscribe_in(&log_search, window, Self::on_log_search);
        // Flush each form text field into the draft as it changes (see on_form_input), so the
        // "unsaved" badge reflects typing immediately rather than only after another action.
        let form_subs = vec![
            cx.subscribe_in(&f_name, window, Self::on_form_input),
            cx.subscribe_in(&f_apps, window, Self::on_form_input),
            cx.subscribe_in(&f_domains, window, Self::on_form_input),
            cx.subscribe_in(&f_ips, window, Self::on_form_input),
            cx.subscribe_in(&f_ports, window, Self::on_form_input),
            cx.subscribe_in(&f_app_paths, window, Self::on_form_input),
            cx.subscribe_in(&f_app_parent, window, Self::on_form_input),
            cx.subscribe_in(&f_signed_by, window, Self::on_form_input),
            cx.subscribe_in(&f_days, window, Self::on_form_input),
            cx.subscribe_in(&f_hours, window, Self::on_form_input),
            cx.subscribe_in(&f_endpoint, window, Self::on_form_input),
            cx.subscribe_in(&f_pport, window, Self::on_form_input),
            cx.subscribe_in(&f_user, window, Self::on_form_input),
            cx.subscribe_in(&f_pass, window, Self::on_form_input),
            cx.subscribe_in(&f_hc_target, window, Self::on_form_input),
            cx.subscribe_in(&f_hc_interval, window, Self::on_form_input),
        ];

        Self {
            tab: saved_tab,
            locale: saved_locale,
            relocalize_pending: false,
            status: t!("status.connecting").into(),
            engine_state: EngineState::Loading,
            killswitch_degraded: false,
            proxy_health: std::collections::HashMap::new(),
            config: None,
            running_config: None,
            config_error: None,
            base_digest: None,
            config_mode: ConfigMode::View,
            config_section: saved_section,
            draft: None,
            form_sel: None,
            form: ConfigEditor {
                name: f_name,
                apps: f_apps,
                domains: f_domains,
                ips: f_ips,
                ports: f_ports,
                tcp: false,
                udp: false,
                app_paths: f_app_paths,
                app_parent: f_app_parent,
                signed_by: f_signed_by,
                v4: false,
                v6: false,
                days: f_days,
                hours: f_hours,
                adv_open: false,
                endpoint: f_endpoint,
                pport: f_pport,
                auth: AuthKind::None,
                user: f_user,
                pass: f_pass,
                hc_enabled: false,
                hc_target: f_hc_target,
                hc_interval: f_hc_interval,
            },
            editor,
            edit: EditSession::default(),
            config_seq_shared,
            tx,
            traffic: TrafficView {
                table,
                _sub,
                selected: None,
                log: VecDeque::new(),
                seen: HashMap::new(),
                seen_bytes: HashMap::new(),
                first_poll: true,
                all_rows: Vec::new(),
                filter_input,
                filter_kind: saved_filter,
                shown: 0,
                _filter_sub,
                paused: false,
                pending_select: None,
                hidden_terminal: HashSet::new(),
                ctx_row: None,
                explanation: None,
                log_filter: saved_log_filter,
                log_search,
                _log_sub,
            },
            _form_subs: form_subs,
            metrics: Metrics::default(),
            proxy_check: None,
            pass_changing: false,
            driver_version: None,
            running_profile_name: None,
            form_profile_name: None,
            form_profile_provisional: false,
            restart: RestartTracker::default(),
        }
    }

    /// Process one poll: diff lifecycle states into event-log lines, and recompute the
    /// status-bar metrics (↓/↑ throughput from byte deltas). `total`/`active` are the
    /// registry's true counts (authoritative, not derived from the capped `rows` slice).
    fn ingest_poll(&mut self, rows: &[ConnectionRow], total: u64, active: u64) {
        let now = Local::now().format("%H:%M:%S").to_string();
        let mut cur_state = HashMap::with_capacity(rows.len());
        let mut cur_bytes = HashMap::with_capacity(rows.len());
        let mut lines: Vec<LogLine> = Vec::new();
        let (mut d_sent, mut d_recv) = (0u64, 0u64);

        for r in rows {
            cur_state.insert(r.id, r.state.clone());
            let (ps, pr) = self
                .traffic
                .seen_bytes
                .get(&r.id)
                .copied()
                .unwrap_or((0, 0));
            d_sent += r.bytes_sent.saturating_sub(ps);
            d_recv += r.bytes_recv.saturating_sub(pr);
            cur_bytes.insert(r.id, (r.bytes_sent, r.bytes_recv));
            if !self.traffic.first_poll {
                match self.traffic.seen.get(&r.id) {
                    None => lines.push(opened_line(&now, r)),
                    Some(prev) if !is_terminal(prev) && is_terminal(&r.state) => {
                        lines.push(terminal_line(&now, r))
                    }
                    _ => {}
                }
            }
        }

        // Throughput over the actual interval (skip the seeding poll's spurious spike).
        if self.traffic.first_poll {
            self.metrics.rate_sent = 0;
            self.metrics.rate_recv = 0;
        } else {
            let secs = self
                .metrics
                .last_poll
                .map(|t| Instant::now().saturating_duration_since(t).as_secs_f64())
                .unwrap_or(1.0)
                .max(0.001);
            self.metrics.rate_sent = (d_sent as f64 / secs) as u64;
            self.metrics.rate_recv = (d_recv as f64 / secs) as u64;
        }
        self.metrics.last_poll = Some(Instant::now());
        self.metrics.active = active as usize;
        self.metrics.total = total as usize;
        self.traffic.seen = cur_state;
        self.traffic.seen_bytes = cur_bytes;
        self.traffic.first_poll = false;

        for line in lines {
            self.traffic.log.push_front(line); // newest first
        }
        while self.traffic.log.len() > MAX_LOG {
            self.traffic.log.pop_back();
        }
    }

    /// The digest-driven half of a Status poll: pending-restart adoption + completion tracking,
    /// running-config attribution, and the stale-config auto-refresh. Split out of `apply` so the
    /// handler can skip it wholesale for a poll captured at an OLD config generation (see
    /// `Msg::Status::config_seq_at_capture`) — its digests would describe the pre-save revision.
    fn apply_poll_digests(
        &mut self,
        running_config_digest: Option<u64>,
        pending_restart_scope: Option<RestartScope>,
        saved_config_digest: Option<u64>,
        reachable: bool,
        any_leg_failed: bool,
        cx: &mut Context<Self>,
    ) {
        // Keep pending-restart state in sync with the engine BEFORE checking completion.
        // `pending_restart_scope` is Some exactly when the saved config isn't live yet;
        // `saved_config_digest` is the digest the engine will report running once a restart
        // applies it — the completion target. Refresh it EVERY poll so a newer save (another
        // client, or a reload) advances the digest we wait for, not just on first adoption —
        // otherwise the target goes stale and the restart never registers as complete.
        // Adopt a pending restart we aren't tracking yet (a fresh session, or a save that just
        // became pending): the saved config is NOT live, so surface the restart and stop
        // rendering it as running (the status bar shows a pending indicator instead).
        if pending_restart_scope.is_some() && !self.restart.needed {
            self.running_config = None;
            self.edit.save_status = t!("save.adopted_pending_restart").into();
            self.restart.needed = true;
        }
        if let Some(scope) = pending_restart_scope {
            self.restart.scope = Some(scope);
        }
        // While tracking a restart, pin the completion target to the engine's CURRENT saved
        // digest EVERY poll — even when pending_restart_scope is None this poll. If another
        // client saves B and the engine restarts BETWEEN two of our polls, the next Status is
        // already in sync (running == saved == B); without refreshing here we'd keep waiting on
        // a stale target A and never register completion.
        if self.restart.needed {
            self.restart.target_digest = restart::refreshed_restart_target(
                true,
                saved_config_digest,
                self.restart.target_digest,
                // Fallback for an intermediate-version service that omits saved_config_digest:
                // base_digest (from GetConfig) is the last-saved digest the engine will report
                // running once the pending restart applies — keeps completion digest-driven.
                self.base_digest,
            );
        }
        // Advance the drop/reconnect state for this poll. Decide completion against the drop
        // seen on EARLIER polls (`prev_saw_drop`), THEN fold in this poll's leg failure for
        // next time — so the poll that first observes a drop (Status ok before the restart,
        // List fails as it drops) can't also complete it. Computed AFTER the target refresh
        // so the digest-aware completion sees the freshest target. A digest-aware peer
        // completes immediately on a digest match; a digest-less one needs a prior drop + now
        // reachable. `dropped_this_poll` only counts while an in-place restart we triggered is
        // in flight (a deadline is armed) — never a passive blip.
        let prev_saw_drop = self.restart.saw_drop;
        let dropped_this_poll = self.restart.deadline.is_some() && any_leg_failed;
        let step = restart::step_restart(
            self.restart.target_digest,
            running_config_digest,
            prev_saw_drop,
            dropped_this_poll,
            reachable,
        );
        self.restart.saw_drop = step.saw_drop_next; // carried to the next poll (reset on completion)
        if self.restart.needed && step.completed {
            self.edit.save_status = t!("save.restart_complete").into();
            self.restart = RestartTracker::default(); // the saved structural change is live now
                                                      // Only claim self.config as running if it IS the running config (digest match) —
                                                      // after another client advanced the saved config it's stale; the auto-refresh
                                                      // below fetches the current one.
            self.set_running_from_local_config(running_config_digest);
            self.edit.save_errors.clear();
            self.edit.save_warnings.clear(); // a successful restart clears any prior issue panels
        } else if let Some(deadline) = self.restart.deadline {
            if Instant::now() >= deadline {
                if self.restart.target_digest.is_none() && prev_saw_drop && reachable {
                    // Legacy (digest-less) peer: we can't confirm via a digest, but we DID
                    // observe the engine drop and it is reachable again — so the restart
                    // happened. (Require the observed drop: a peer that merely stayed
                    // reachable the whole time never actually restarted, and must NOT be
                    // marked complete / advance running_config to a config it isn't running.)
                    self.edit.save_status = t!("save.restart_unconfirmed").into();
                    // target_digest is already None here (outer guard), so a full reset is
                    // equivalent and robust against future RestartTracker fields.
                    self.restart = RestartTracker::default();
                    self.set_running_from_local_config(running_config_digest);
                    self.edit.save_errors.clear();
                    self.edit.save_warnings.clear();
                } else {
                    // A digest-aware restart that never reached the target, or a peer still
                    // unreachable at the deadline: stop waiting and say so, leaving
                    // restart.needed set so the action stays offered.
                    self.edit.save_status = t!("save.restart_incomplete").into();
                    self.restart.deadline = None;
                    self.restart.saw_drop = false;
                }
            }
        }
        // In sync (no pending change, and not mid-restart): the saved config IS what's running
        // — surface it as running_config when our local copy actually matches the running
        // digest, else leave it unknown (None) until a refresh fetches the current one.
        if !self.restart.needed {
            self.set_running_from_local_config(running_config_digest);
        }
        // Another client (or a CLI reload) advanced the saved config beyond what this GUI
        // holds (base_digest != the engine's saved digest): our self.config is stale. When
        // idle in the read-only view, refresh it automatically so the display and the next
        // save's base track the current config. While editing, the stale-save rejection
        // handles it; while saving/reloading, wait for that to settle. (The `reloading` guard
        // makes this fire at most once per external save.)
        if !self.is_editing()
            && !self.edit.saving
            && !self.edit.reloading
            && self.base_digest.is_some()
            && saved_config_digest.is_some()
            && self.base_digest != saved_config_digest
        {
            self.reload_config(cx);
        }
    }

    /// Advance the config-operation generation (a save completed / a reload was issued) and mirror
    /// it to the poll worker's atomic, so polls captured before this point are recognizably stale.
    fn bump_config_seq(&mut self) {
        self.edit.config_seq = self.edit.config_seq.wrapping_add(1);
        self.config_seq_shared
            .store(self.edit.config_seq, AtomicOrdering::Relaxed);
    }

    /// Whether an edit is open — the form/JSON editor is active, or a form draft is held. Single
    /// source of truth so the reload-drop, the foreign-save guard, and the auto-refresh gate
    /// can't drift into disagreement over what "editing" means.
    fn is_editing(&self) -> bool {
        !matches!(self.config_mode, ConfigMode::View) || self.draft.is_some()
    }

    /// Retire the current edit session: advance `session_gen` (so a still-in-flight save from it
    /// applies only its config-level effects, never force-closing a later session) and drop the
    /// stale confirm state (a leaked `pending_section` would keep rendering the "discard & switch?"
    /// banner in View and arm its danger button against the NEXT session's fresh draft). Every
    /// session boundary — enter_form/enter_json/on_create_rule (open a new one), exit_edit/
    /// reload_config (close one) — routes through here so the invariant lives in one place.
    fn retire_session(&mut self) {
        self.edit.session_gen = self.edit.session_gen.wrapping_add(1);
        self.edit.pending_section = None;
        self.edit.confirm_revert = false;
        self.edit.confirm_reload = false;
        // Drop a queued create-rule discard-confirm too: opening/closing a session supersedes it,
        // so its banner (and its captured connection row) must not survive into the new session.
        self.edit.pending_create_rule = None;
    }

    /// Reset the per-session VIEW state back to the read-only view: no draft, no selection, the
    /// frozen edit-profile released, and the typed cleartext password dropped. Shared by
    /// `exit_edit` and the save-success path so a new per-session field can't be dropped on one
    /// exit but not the other. Does NOT touch `session_gen` (a save-success close keeps its own
    /// generation) or the save-feedback panels (each caller manages those).
    fn close_to_view(&mut self) {
        self.config_mode = ConfigMode::View;
        self.draft = None;
        self.form_sel = None;
        // Stop treating a typed password as live (pending_password ignores it once pass_changing
        // is false). No `window` here to clear the masked input buffer, but it is never rendered
        // or used while hidden and is re-cleared on the next form entry (Change / select_proxy).
        self.pass_changing = false;
        self.form_profile_name = None; // form closed; the view follows the running profile live
        self.form_profile_provisional = false;
        // A save-success close ends the session too, so drop any queued create-rule confirm (and
        // its captured row) — same guarantee retire_session gives on a session open.
        self.edit.pending_create_rule = None;
    }

    fn apply(&mut self, msg: Msg, cx: &mut Context<Self>) {
        match msg {
            Msg::Status {
                status,
                rows,
                total,
                active,
                reachable,
                running_config_digest,
                running_profile,
                pending_restart_scope,
                saved_config_digest,
                killswitch_degraded,
                proxy_health,
                any_leg_failed,
                rows_valid,
                config_seq_at_capture,
            } => {
                // Update the running (effective) profile every tick so the status bar and config tab
                // reflect a profile-changing restart within ~1 s. Keep the last known value if this
                // poll's Status leg failed (None on an unreachable poll) — don't blank a good value.
                if running_profile.is_some() {
                    self.running_profile_name = running_profile;
                }
                // If a form was opened before the first poll, re-aim its provisional freeze now that
                // the running profile is known (no-op unless a provisional freeze is pending).
                self.reconcile_provisional_freeze(cx);
                // (The legacy drop/reconnect tracking is computed below, AFTER the target refresh,
                // via restart::step_restart — so the drop and the completion land on separate polls.)
                // Digest-driven bookkeeping (pending-restart adoption/completion, running-config
                // attribution, stale-config auto-refresh) runs only when this poll was captured at
                // the CURRENT config generation: the poll worker and the save thread share one
                // channel, so a Status captured before a save can be processed after its
                // SaveResult — its digests then describe the PRE-save revision, and acting on them
                // would regress the restart target (firing a false "restart complete" that
                // discards the save's warnings and restart reason) and trigger a spurious reload.
                // Skipping the tick is safe: the next fresh poll re-runs all of it.
                if config_seq_at_capture == self.edit.config_seq {
                    self.apply_poll_digests(
                        running_config_digest,
                        pending_restart_scope,
                        saved_config_digest,
                        reachable,
                        any_leg_failed,
                        cx,
                    );
                }
                // "Reconnecting" only while an in-place restart WE initiated is in flight (a deadline
                // is armed); a passive unreachable poll is just Unreachable. No status-string sniff.
                let restarting = self.restart.deadline.is_some();
                self.engine_state = match (restarting && !reachable, reachable) {
                    (true, _) => EngineState::Reconnecting,
                    (_, true) => EngineState::Running,
                    (_, false) => EngineState::Unreachable,
                };
                self.status = status;
                self.killswitch_degraded = killswitch_degraded;
                // Index health by proxy name for O(1) lookup while rendering proxy/chain cards. Only
                // replace it when the Status leg answered (`Some`); a failed Status poll (`None`)
                // keeps the last-known badges rather than flickering them all off for one tick.
                if let Some(health) = proxy_health {
                    self.proxy_health = health.into_iter().map(|h| (h.name.clone(), h)).collect();
                }
                // Only a SUCCESSFUL list leg is a real snapshot. A failed leg's empty rows must
                // not reach ingest_poll: replacing seen/seen_bytes with empty maps makes the
                // recovery poll re-log every retained connection as freshly opened and count each
                // row's full cumulative byte totals as one interval's throughput — one transient
                // IPC timeout would fabricate log history and a rate spike (and a failed FIRST
                // poll would consume the first_poll seeding suppression). So NEVER ingest a failed
                // leg (preserving seen/seen_bytes/log/rates); but the VISIBLE table must still
                // reflect reachability, handled below.
                if rows_valid {
                    self.ingest_poll(&rows, total, active);
                }
                // Refresh the visible table only when it would be honest to. A successful leg
                // shows its rows. A failed leg keeps the last-known table WHILE THE ENGINE IS
                // STILL REACHABLE (the Status leg answered — the list call merely flaked, so the
                // rows are almost certainly still accurate and shouldn't flicker). But once the
                // engine is UNREACHABLE, clear the table and live counts so a sustained outage
                // doesn't keep rendering dead "Established" connections as live, contradicting the
                // Unreachable status dot. Either way seen/seen_bytes are preserved above, so
                // recovery doesn't re-log. Paused freezes the table regardless (for inspection).
                if !self.traffic.paused {
                    if rows_valid {
                        self.traffic.all_rows = rows;
                        self.refilter(cx);
                    } else if !reachable && !self.traffic.all_rows.is_empty() {
                        self.traffic.all_rows.clear();
                        // Zero the visible counts/rates but KEEP last_poll: ingest_poll divides
                        // byte deltas by the time elapsed since the last successful ingest
                        // (1-second fallback when None), so on recovery the outage-long deltas
                        // are averaged over the true gap. Resetting last_poll here would divide
                        // them by the fallback instead — a huge false rate spike, the very
                        // artifact the failed-leg handling exists to prevent.
                        self.metrics = Metrics {
                            last_poll: self.metrics.last_poll,
                            ..Metrics::default()
                        };
                        self.refilter(cx);
                    }
                    // Apply a selection queued by a log click made while paused — whatever this
                    // tick's list outcome: a flaked leg retains the previous rows (the clicked
                    // row is still present and selectable), so deferring the selection to the
                    // next successful poll would make the click look dead during list flakiness.
                    // On the unreachable-clear path the row set is empty and this is a no-op.
                    if let Some(id) = self.traffic.pending_select.take() {
                        self.select_conn_by_id(id, cx);
                    }
                }
            }
            Msg::Config { result, reload_gen } => {
                // Drop a stale RELOAD response: if config_seq advanced since this reload was issued —
                // a save completed, OR a newer reload was issued (overlapping reloads) — applying its
                // older snapshot would move self.config/base_digest backward. The startup fetch
                // (reload_gen None) is never stale. Clear the transient "reloading…" status either way.
                if reload_gen.is_some() {
                    self.edit.reloading = false; // this reload's response has arrived (applied or dropped)
                }
                let stale = reload_gen.is_some_and(|g| g != self.edit.config_seq);
                // Drop a reload response that lands under an OPEN edit session (the user clicked
                // Edit while the fetch was in flight): rebasing self.config + base_digest under
                // the draft would arm the NEXT save with a fresh digest for stale content — the
                // engine's stale-save check would then PASS and silently clobber the other
                // client's changes, the exact overwrite base_digest exists to reject. Dropped,
                // the draft keeps its original base: a save of stale content is rejected as
                // stale, and the auto-refresh re-fetches once back in View. (The startup fetch,
                // reload_gen None, can't race an edit: no config existed to edit before it.)
                let stale = stale || (reload_gen.is_some() && self.is_editing());
                // Compare against the SAME t! the set site used. (If the user switches language in the

                // sub-second window between issuing the reload and its response, this misses and the

                // transient text merely lingers until the next status change — cosmetic.)

                let reloading = self.edit.save_status == t!("save.reloading");
                if stale {
                    if reloading {
                        self.edit.save_status.clear();
                    }
                } else {
                    match result {
                        Ok((config, digest)) => {
                            // GetConfig returns the LAST-SAVED config, which is NOT necessarily what's
                            // running (a pending restart-required save makes them differ). So set only
                            // the editable config here; whether it is also the running config is decided
                            // by the next Status poll — don't assume saved == running.
                            self.config = Some(config);
                            self.config_error = None;
                            // The revision token this edit is based on — echoed in SetConfig so the
                            // engine can reject a stale save (optimistic concurrency).
                            self.base_digest = digest;
                            if reloading {
                                self.edit.save_status = t!("save.reloaded").into();
                            }
                        }
                        Err(e) => {
                            self.config_error = Some(e);
                            if reloading {
                                self.edit.save_status.clear();
                            }
                        }
                    }
                }
            }
            Msg::SaveResult {
                session_gen,
                result: Ok(save_ok),
            } => {
                self.edit.saving = false;
                self.bump_config_seq(); // a save changed the config — supersede a racing reload / stale polls
                let SaveOk {
                    restart,
                    config_digest,
                    warnings,
                } = save_ok;
                let needs_restart = restart.is_some();
                // Redact the freshly-typed proxy secrets from the optimistic config the instant the
                // save succeeds, regardless of which session it belongs to: the engine now holds the
                // real values and restores `<unchanged>` on the next save, so keeping cleartext here
                // only risks rendering it and lingers credentials longer than necessary.
                let mut saved_cfg = self.edit.pending_config.take();
                if let Some(cfg) = saved_cfg.as_mut() {
                    proxroute_config::redact_secrets(cfg);
                }
                // A save can OUTLIVE the session that issued it: the user can Revert out during a
                // slow save and open a NEW session, so `session_gen` may no longer match.
                // Rebasing self.config/base_digest (and the save-feedback panels) onto this result
                // while a FOREIGN edit is open would arm that draft with a fresh base_digest for
                // stale content — the engine's stale-save check would then PASS and silently clobber
                // the just-saved revision (the same hazard the Msg::Config reload-drop guards). So
                // apply the config-level effects only when this result still owns the view — i.e.
                // its session is current, or nothing is being edited. A foreign open session's
                // pending restart / stale base re-syncs from the next Status poll (auto-refresh once
                // back in View). We always cleared `saving` + redacted secrets above.
                let owns_view = session_gen == self.edit.session_gen || !self.is_editing();
                if !owns_view {
                    return;
                }
                if session_gen == self.edit.session_gen {
                    // The session that issued this save is still current — close it to View. (Keep
                    // its generation: a save-success close doesn't need to supersede itself.)
                    self.close_to_view();
                    self.edit.confirm_revert = false;
                    self.edit.confirm_reload = false;
                    self.edit.pending_section = None;
                }
                self.restart.needed = needs_restart;
                self.restart.scope = restart.as_ref().map(|r| r.scope.clone());
                // A restart-required change isn't live yet: remember the engine's digest of the
                // saved config so a later status poll can tell when the engine is running it. A
                // hot-applied change clears any stale target (nothing to wait for).
                self.restart.target_digest = if needs_restart { config_digest } else { None };
                // The save succeeded, so the saved config is now this revision: base the NEXT save on
                // it (last_saved advanced to it for both hot and restart-required saves).
                self.base_digest = config_digest;
                self.restart.deadline = None; // not triggered yet (engine-scope waits for the click)
                self.restart.saw_drop = false; // fresh pending change — no drop seen for it yet
                self.edit.save_status = match &restart {
                    None => t!("save.applied").into(),
                    Some(r) if r.scope == RestartScope::Service => {
                        t!("save.saved_service_restart", reason = r.reason).into()
                    }
                    Some(r) => t!("save.saved_engine_restart", reason = r.reason).into(),
                };
                self.edit.save_errors.clear();
                self.edit.save_warnings = warnings; // advisory; surfaced in an amber panel, doesn't block
                                                    // Reflect what was saved in the structured view. A hot-applied change is now
                                                    // live too; a restart-required one is only saved — the engine keeps running the
                                                    // previous config, so `running_config` (the status bar) must not advance to it.
                if let Some(cfg) = saved_cfg {
                    if !needs_restart {
                        self.running_config = Some(cfg.clone());
                    }
                    self.config = Some(cfg);
                }
            }
            Msg::SaveResult {
                session_gen: _,
                result: Err(messages),
            } => {
                // Stay in edit mode so the user can fix it; drop the optimistic config. Show a
                // brief count in the toolbar and the per-problem detail in the panel below it. A
                // FAILED save changed nothing, so don't bump config_seq (a racing reload is still
                // valid) and no session is closed (session_gen is irrelevant here — errors are
                // shown regardless, since they describe the config the engine rejected).
                self.edit.saving = false;
                self.edit.pending_config = None;
                self.edit.save_status = t!("save.problems", count = messages.len()).into();
                self.edit.save_errors = messages;
                self.edit.save_warnings.clear();
            }
            Msg::Explanation { id, result } => {
                // Drop a late reply if the user has since selected a different connection.
                if self.traffic.selected.as_ref().map(|r| r.id) == Some(id) {
                    self.traffic.explanation = Some(match result {
                        Ok(text) => text,
                        Err(e) => t!("detail.explain_failed", error = e).to_string(),
                    });
                }
            }
            Msg::ProxyCheck { checked, result } => {
                // Commit the current inputs and compare to the snapshot the check ran against;
                // drop the reply if the user has since edited a field or opened another proxy,
                // so a stale result never renders under different values.
                self.flush(cx);
                if self.selected_proxy_json(cx).as_deref() == Some(checked.as_str()) {
                    self.proxy_check = Some(match result {
                        Ok(s) => format!("✓ {s}"),
                        Err(e) => format!("✗ {e}"),
                    });
                }
            }
            Msg::EngineInfo { driver_version } => {
                self.driver_version = driver_version;
            }
            Msg::RestartResult(Ok(())) => {
                // Restart accepted — completion is detected by the status poll (digest match, or the
                // drop/reconnect fallback). Nothing to do here.
            }
            Msg::RestartResult(Err(messages)) => {
                // A restart error can arrive AFTER a status poll already detected completion (the two
                // run on different threads). If the restart is no longer pending, the restart already
                // succeeded — drop the stale error rather than resurrect a problem panel over a
                // completed restart (which, for a digest-less peer, would otherwise stick forever).
                if !self.restart.needed {
                    return;
                }
                // The engine refused or failed the restart. Disarm the deadline so its later timeout
                // can't overwrite this specific error, but keep restart.needed / target_digest so the user
                // can retry. Surface the reason like a save error (toolbar + problem panel).
                self.restart.deadline = None;
                self.restart.saw_drop = false;
                self.edit.save_status = t!("save.problems", count = messages.len()).into();
                self.edit.save_errors = messages;
                self.edit.save_warnings.clear();
            }
        }
    }

    /// The proxy currently open in the form editor, serialized — a fingerprint used to bind an
    /// async `Msg::ProxyCheck` reply to the exact proxy snapshot it was issued for. Compared
    /// after a `flush`, so editing *any* field (even keeping the name) invalidates a stale
    /// in-flight result.
    fn selected_proxy_json(&self, cx: &App) -> Option<String> {
        let Some(FormSel::Proxy(i)) = self.form_sel else {
            return None;
        };
        // Fingerprint the proxy AS IT WOULD BE SAVED/CHECKED — through effective_draft, so the
        // pending-password merge is the SAME one Save uses (no second, drift-prone copy) and the
        // typed password is tested/compared exactly as it will be persisted.
        let profile = self.editing_profile_name();
        let cfg = self.effective_draft(cx)?;
        proxy_at(&cfg, &profile, i).and_then(|px| serde_json::to_string(px).ok())
    }

    /// Check the proxy currently open in the form editor: send the *live draft* definition
    /// (serialized) to the engine, which connects + runs the real handshake/auth (+ TLS) via
    /// its connectors, on a one-shot thread → `Msg::ProxyCheck`. Sending the draft (not just a
    /// name) means unsaved endpoint/auth edits are checked as typed — no save-first needed.
    fn check_proxy(&mut self, cx: &mut Context<Self>) {
        // Commit the visible inputs into the draft first, so the check tests exactly what's on
        // screen. The new-password input isn't flushed to the draft, so selected_proxy_json
        // merges it into the checked snapshot directly.
        self.flush(cx);
        let Some(proxy) = self.selected_proxy_json(cx) else {
            return;
        };
        // The proxy being checked belongs to the profile being edited (the engine's running profile
        // under a --profile run) — send its name so the engine restores a redacted secret from the
        // SAME profile, not a same-named proxy elsewhere.
        let profile = Some(self.editing_profile_name());
        self.proxy_check = Some(t!("proxy.checking").to_string());
        let tx = self.tx.clone();
        let checked = proxy.clone(); // bind the reply to this exact snapshot
        std::thread::spawn(move || {
            let result = (|| -> Result<String, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                rt.block_on(async {
                    match proxroute_ipc::request(&Request::CheckProxy { proxy, profile }).await {
                        Ok(Response::ProxyCheck { ok: true, detail }) => Ok(detail),
                        Ok(Response::ProxyCheck { ok: false, detail }) => Err(detail),
                        Ok(Response::Error { messages }) => Err(messages.join("; ")),
                        Ok(other) => Err(format!("unexpected reply: {other:?}")),
                        Err(e) => Err(e.to_string()),
                    }
                })
            })();
            let _ = tx.unbounded_send(Msg::ProxyCheck { checked, result });
        });
        cx.notify();
    }

    /// The search box changed — re-apply the quick filter.
    fn on_filter_event(
        &mut self,
        _: &Entity<InputState>,
        ev: &InputEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if matches!(ev, InputEvent::Change) {
            self.refilter(cx);
            cx.notify();
        }
    }

    /// A form text field changed — flush it into the draft so the "unsaved" badge stays accurate
    /// while typing (form inputs otherwise only reach the draft on a flush-triggering action).
    fn on_form_input(
        &mut self,
        _: &Entity<InputState>,
        ev: &InputEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if matches!(ev, InputEvent::Change)
            && matches!(self.config_mode, ConfigMode::Form)
            && self.form_sel.is_some()
        {
            self.flush(cx);
            cx.notify();
        }
    }

    /// The log search box changed — re-render with the new filter (no table to rebuild).
    fn on_log_search(
        &mut self,
        _: &Entity<InputState>,
        ev: &InputEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if matches!(ev, InputEvent::Change) {
            cx.notify();
        }
    }

    /// Lines currently shown in the log (severity filter + search), newest first.
    fn visible_log(&self, cx: &App) -> Vec<&LogLine> {
        let needle = self
            .traffic
            .log_search
            .read(cx)
            .value()
            .trim()
            .to_lowercase();
        let filter = self.traffic.log_filter;
        self.traffic
            .log
            .iter()
            .filter(|l| filter.matches(l.color))
            .filter(|l| needle.is_empty() || l.text.to_lowercase().contains(&needle))
            .collect()
    }

    /// Copy the visible log lines to the clipboard.
    fn copy_log(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        let text = self
            .visible_log(cx)
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        cx.write_to_clipboard(ClipboardItem::new_string(text));
    }

    /// Write the visible log lines to a timestamped file in the OS temp dir, then note the
    /// path in the log itself (so the result is visible without a save dialog).
    fn export_log(&mut self, _: &ClickEvent, _: &mut Window, cx: &mut Context<Self>) {
        let text = self
            .visible_log(cx)
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let path = std::env::temp_dir().join(format!(
            "proxroute-log-{}.txt",
            Local::now().format("%Y%m%d-%H%M%S")
        ));
        match std::fs::write(&path, text) {
            Ok(()) => self.push_log_note(t!("log.exported", path = path.display()).into()),
            Err(e) => self.push_log_note(t!("log.export_failed", error = e).into()),
        }
        cx.notify();
    }

    /// Push a non-connection note (dim) to the front of the event log.
    fn push_log_note(&mut self, msg: String) {
        let now = Local::now().format("%H:%M:%S").to_string();
        self.traffic.log.push_front(LogLine {
            text: format!("[{now}] {msg}"),
            color: FG_DIM,
            id: None,
        });
        while self.traffic.log.len() > MAX_LOG {
            self.traffic.log.pop_back();
        }
    }

    /// Select the connection a clicked log line refers to, if it's still in the current rows
    /// (closed-and-evicted flows simply don't select).
    fn select_conn_by_id(&mut self, id: u64, cx: &mut Context<Self>) {
        if let Some(row) = self.traffic.all_rows.iter().find(|r| r.id == id).cloned() {
            self.traffic.selected = Some(row);
            self.traffic.explanation = None;
            cx.notify();
        } else if self.traffic.paused {
            // The row appeared in the log after the table was frozen — resume and select it
            // once the next poll brings it back, so the click isn't a silent no-op.
            self.traffic.paused = false;
            self.traffic.pending_select = Some(id);
            cx.notify();
        }
    }

    /// Re-apply the quick filter (search text + decision/state chip) to `all_rows`,
    /// refreshing the table's visible rows, the `shown` count, and the live detail
    /// selection. Called on each poll and whenever the filter changes.
    /// Clear every view filter — the decision/state chip, the search box, and any
    /// "Clear closed"-hidden rows — so the full connection list is shown again.
    fn reset_filters(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.traffic.filter_kind = ConnFilter::All;
        self.traffic.hidden_terminal.clear();
        self.traffic
            .filter_input
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.refilter(cx);
        self.save_ui_state();
        cx.notify();
    }

    /// Persist the active tab / config section / filters so they survive a restart
    /// (best-effort; ignores all errors). Pane sizes, sort and column widths are owned by
    /// the gpui-component widgets and aren't persistable here.
    fn save_ui_state(&self) {
        let Some(path) = ui_state_path() else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tab = match self.tab {
            Tab::Connections => "connections",
            Tab::Config => "config",
        };
        let obj = serde_json::json!({
            "tab": tab,
            "section": self.config_section.label(),
            "filter": self.traffic.filter_kind.label(),
            "logFilter": self.traffic.log_filter.label(),
            "locale": self.locale,
        });
        let _ = std::fs::write(path, obj.to_string());
    }

    /// Switch the UI language: persist the choice, flip the runtime locale global (which every
    /// `t!` reads), and re-render so the whole UI repaints in the new language. gpui-component's
    /// built-in strings share this locale, so they follow too.
    fn set_language(&mut self, code: &'static str, cx: &mut Context<Self>) {
        if self.locale == code {
            return;
        }
        self.locale = code;
        rust_i18n::set_locale(code);
        // Table headers and input placeholders are baked at construction; re-apply them on the next
        // render (which has the `&mut Window` they need).
        self.relocalize_pending = true;
        self.save_ui_state();
        cx.notify();
    }

    fn refilter(&mut self, cx: &mut Context<Self>) {
        let needle = self
            .traffic
            .filter_input
            .read(cx)
            .value()
            .trim()
            .to_lowercase();
        let kind = self.traffic.filter_kind;
        // Drop cleared ids the engine has since aged out, so the set stays bounded.
        let present: HashSet<u64> = self.traffic.all_rows.iter().map(|r| r.id).collect();
        self.traffic
            .hidden_terminal
            .retain(|id| present.contains(id));
        let hidden = &self.traffic.hidden_terminal;
        let filtered: Vec<ConnectionRow> = self
            .traffic
            .all_rows
            .iter()
            .filter(|r| !(is_terminal(&r.state) && hidden.contains(&r.id)))
            .filter(|r| kind.matches(r) && row_matches_text(r, &needle))
            .cloned()
            .collect();
        self.traffic.shown = filtered.len();
        self.traffic
            .table
            .update(cx, |t, _| t.delegate_mut().set_rows(filtered));
        // Keep an open detail panel live: re-match the selection against the fresh
        // (filtered) rows, else keep the last-known snapshot.
        let fresh = self.traffic.selected.as_ref().and_then(|sel| {
            self.traffic
                .table
                .read(cx)
                .delegate()
                .rows
                .iter()
                .find(|r| same_connection(r, sel))
                .cloned()
        });
        if let Some(fresh) = fresh {
            self.traffic.selected = Some(fresh);
        }
    }

    /// Hide every currently-terminal row (closed/failed/blocked/cancelled) from the view.
    /// New connections still appear; the cleared ids are dropped once the engine ages
    /// them out. Closes the detail panel if its row was cleared.
    fn clear_closed(&mut self, cx: &mut Context<Self>) {
        for r in &self.traffic.all_rows {
            if is_terminal(&r.state) {
                self.traffic.hidden_terminal.insert(r.id);
            }
        }
        if let Some(sel) = &self.traffic.selected {
            if self.traffic.hidden_terminal.contains(&sel.id) {
                self.traffic.selected = None;
            }
        }
        self.refilter(cx);
        cx.notify();
    }

    /// Context-menu action: open the form editor with a new rule matching the
    /// right-clicked connection's app (Direct by default — pick a proxy from there).
    fn on_create_rule(
        &mut self,
        _: &CreateRuleFromConn,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(row) = self.traffic.ctx_row.clone() else {
            return;
        };
        self.tab = Tab::Config;
        // Refuse while the running profile is still unknown (only before the first successful
        // Status poll — it is set once and never cleared, so this is the startup/`--profile`
        // window), BEFORE offering the discard banner so "Discard & create" always creates. This
        // inserts a rule immediately, but until the first poll we can't tell which profile is
        // routing the connection (known within ~1 s of a reachable engine — the user just retries).
        if self.running_profile_name.is_none() {
            self.edit.save_status = t!("save.waiting_engine_status").into();
            cx.notify();
            return;
        }
        // Guard the ONE silent-discard path: switching from the JSON editor to the form to add the
        // rule would throw away unsaved JSON edits with no warning (every other dirty-editor exit —
        // section switch, Revert, Reload — confirms first). Stash the row and raise a discard-confirm
        // banner instead; the banner's "Discard & create" calls create_rule_from_conn. (Form mode
        // doesn't discard — it appends to the live draft; View has nothing to lose.)
        if matches!(self.config_mode, ConfigMode::Json) && self.config_is_dirty(cx) {
            self.edit.pending_create_rule = Some(row);
            cx.notify();
            return;
        }
        self.create_rule_from_conn(row, window, cx);
    }

    /// Insert a Direct rule prefilled from `row` into the active profile and open it for editing.
    /// Split from [`Self::on_create_rule`] so the JSON-discard confirm path and the direct path
    /// share one implementation.
    fn create_rule_from_conn(
        &mut self,
        row: ConnectionRow,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let app = process_basename(&row.process);
        // Defensive backstop: on_create_rule already refuses an unknown profile up front, and the
        // profile is never cleared once known, so a confirm-banner click can't reach here with it
        // unknown — but never insert into an unknown profile regardless of how this is called.
        if self.running_profile_name.is_none() {
            self.edit.save_status = t!("save.waiting_engine_status").into();
            cx.notify();
            return;
        }
        // Show the Rules section, else the new rule (and its just-opened detail editor) render into
        // whichever section was last viewed — invisible on Proxies/Chains/Profile, and reaching it
        // via the Rules sub-tab trips the dirty-draft discard-confirm, a trap that deletes the rule.
        if self.config_section != ConfigSection::Rules {
            self.config_section = ConfigSection::Rules;
            self.save_ui_state();
        }
        // Seed the draft from the saved config unless we're already mid-edit in the form.
        if self.config_mode != ConfigMode::Form {
            self.config_mode = ConfigMode::Form;
            // A fresh session: retire the previous generation like the other entry points, so a
            // late SaveResult from an earlier in-flight save can't force-close this one and
            // silently drop the just-created rule.
            self.retire_session();
            self.edit.save_status.clear();
            self.edit.save_errors.clear();
            self.edit.save_warnings.clear();
            self.draft = self.config.clone();
            self.form_sel = None;
            // Fresh form session — freeze its profile (the running one, so the rule lands where the
            // connection is actually routed). An already-open form keeps its existing frozen profile.
            self.form_profile_name = Some(self.running_or_active_profile());
            self.form_profile_provisional = self.running_profile_name.is_none();
        }
        self.flush(cx); // commit any open detail edit first
                        // Prefill the destination alongside the process, so a host- or IP-specific rule is just a
                        // delete away (remove the fields you don't want rather than typing them in). The match is
                        // built via `build_match` (the same path the form commits through), so every prefilled
                        // field is form-editable. See `conn_dest_fields` for the fake-IP caveat.
        let (domains, ips, ports) = conn_dest_fields(&row.destination, row.dest_host.as_deref());
        let rule = Rule {
            name: format!("Rule for {app}"),
            enabled: true,
            match_: build_match(RuleFields {
                apps: vec![app.clone()],
                domains,
                ips,
                ports,
                ..Default::default()
            }),
            action: Action {
                kind: ActionType::Direct,
                target: None,
                dns_mode: None,
                on_failure: None,
            },
        };
        if let Some((g, r)) = self.append_rule_to_active_profile(rule) {
            self.select_rule(g, r, window, cx);
        }
        cx.notify();
    }

    /// Append `rule` into the active profile's last ENABLED rule group and return its
    /// `(group, rule)` index (or `None` if there is no active profile). Compiled routing skips
    /// disabled groups entirely, so a rule appended into a disabled trailing group is saved and
    /// "applied" yet never matches — silently inert; this always targets an enabled group,
    /// creating a fresh one (via [`unique_group_name`]) when none qualifies. The rule's `name` is
    /// made unique within the chosen group (the validator rejects duplicate rule names within a
    /// group). Shared by [`Self::add_rule`] and [`Self::create_rule_from_conn`] so neither can
    /// drift back into the disabled-group / duplicate-name traps.
    fn append_rule_to_active_profile(&mut self, mut rule: Rule) -> Option<(usize, usize)> {
        let p = self.active_profile_mut()?;
        let g = match p.rule_groups.iter().rposition(|grp| grp.enabled) {
            Some(i) => i,
            None => {
                let name = unique_group_name(&p.rule_groups, "default");
                p.rule_groups.push(RuleGroup {
                    name,
                    enabled: true,
                    rules: Vec::new(),
                });
                p.rule_groups.len() - 1
            }
        };
        rule.name = unique_rule_name(&p.rule_groups[g].rules, &rule.name);
        let r = p.rule_groups[g].rules.len();
        p.rule_groups[g].rules.push(rule);
        Some((g, r))
    }

    /// Context-menu action: open the detail panel for the right-clicked row.
    fn on_show_details(&mut self, _: &ShowConnDetails, _: &mut Window, cx: &mut Context<Self>) {
        if self.traffic.ctx_row.is_some() {
            self.traffic.selected = self.traffic.ctx_row.clone();
            self.traffic.explanation = None;
            cx.notify();
        }
    }

    /// Context-menu action: open the detail panel and request the routing explanation.
    fn on_explain(&mut self, _: &ExplainConn, _: &mut Window, cx: &mut Context<Self>) {
        if self.traffic.ctx_row.is_some() {
            self.traffic.selected = self.traffic.ctx_row.clone();
            self.traffic.explanation = None;
            self.explain(cx);
        }
    }

    /// Request the routing explanation (`ExplainConnection`) for the selected row on a
    /// one-shot thread; the text comes back as `Msg::Explanation`.
    fn explain(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.traffic.selected.clone() else {
            return;
        };
        let id = row.id;
        self.traffic.explanation = Some(t!("detail.explaining").to_string());
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<String, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                rt.block_on(async {
                    match proxroute_ipc::request(&Request::ExplainConnection { id }).await {
                        Ok(Response::Explanation { text }) => Ok(text),
                        Ok(Response::Error { messages }) => Err(messages.join("; ")),
                        Ok(other) => Err(format!("unexpected reply: {other:?}")),
                        Err(e) => Err(e.to_string()),
                    }
                })
            })();
            let _ = tx.unbounded_send(Msg::Explanation { id, result });
        });
        cx.notify();
    }

    /// Refetch the saved config from the engine and rebase on it: drops any in-progress edit and
    /// updates `base_digest`, so the user can recover after a stale-save rejection ("the
    /// configuration changed since it was loaded") without restarting the GUI. Reuses the
    /// `Msg::Config` path, which sets `config` + `base_digest` and lets the next Status decide
    /// running-vs-saved.
    fn reload_config(&mut self, cx: &mut Context<Self>) {
        // Hard guard against overlap: at most one reload (or save) config-fetch in flight. The button
        // is disabled and the auto-refresh is gated while busy, but this backstops any other caller —
        // without it, a stale reload's response could clear `reloading` while a newer one is still
        // active (its `self.edit.reloading = false` runs before the staleness check).
        if self.edit.saving || self.edit.reloading {
            return;
        }
        self.close_to_view();
        self.retire_session(); // closes any open edit session (bumps session_gen, clears confirm state)
        self.edit.save_errors.clear();
        self.edit.save_warnings.clear();
        self.edit.reloading = true;
        self.edit.save_status = t!("save.reloading").into();
        // Bump the config-operation generation so a LATER reload (or save) supersedes this one, then
        // capture it. If config_seq advances before this reload's GetConfig response arrives — a save
        // completed, or a newer reload was issued — the response is dropped (see the Msg::Config
        // handler), so overlapping reloads can't apply out of order and move self.config backward.
        self.bump_config_seq();
        let reload_gen = Some(self.edit.config_seq);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = (|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("runtime: {e}"))?;
                rt.block_on(async {
                    match proxroute_ipc::request(&Request::GetConfig).await {
                        // Strict parse via the shared helper (see config_load).
                        Ok(Response::Config { json, digest }) => {
                            config_load::parse_get_config(&json, digest)
                        }
                        Ok(other) => Err(format!("unexpected reply to GetConfig: {other:?}")),
                        Err(e) => Err(format!("engine not reachable ({e})")),
                    }
                })
            })();
            let _ = tx.unbounded_send(Msg::Config { result, reload_gen });
        });
        cx.notify();
    }

    /// Reload, arming a confirming second click first when it would discard unsaved edits.
    fn request_reload(&mut self, cx: &mut Context<Self>) {
        self.flush(cx); // count typed-but-unflushed text as a change
        if self.config_is_dirty(cx) && !self.edit.confirm_reload {
            self.edit.confirm_reload = true;
            cx.notify();
        } else {
            self.reload_config(cx);
        }
    }

    /// Enter the form editor, cloning the saved config into an editable draft.
    fn enter_form(&mut self, cx: &mut Context<Self>) {
        self.config_mode = ConfigMode::Form;
        self.retire_session(); // a new session supersedes any prior one's still-in-flight save
        self.edit.save_status.clear();
        self.edit.save_errors.clear();
        self.edit.save_warnings.clear();
        self.draft = self.config.clone();
        self.form_sel = None;
        // Freeze the edited profile for this form session (see editing_profile_name) so a mid-edit
        // running-profile change can't retarget the open selection onto a different profile. If the
        // running profile isn't known yet (pre-first-poll), mark the freeze provisional so it can be
        // re-aimed when the first Status poll arrives (see reconcile_provisional_freeze).
        self.form_profile_name = Some(self.running_or_active_profile());
        self.form_profile_provisional = self.running_profile_name.is_none();
        cx.notify();
    }

    /// Enter the JSON editor, seeding it from the saved config.
    fn enter_json(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.config_mode = ConfigMode::Json;
        self.retire_session(); // a new session supersedes any prior one's still-in-flight save
        self.edit.save_status.clear();
        self.edit.save_errors.clear();
        self.edit.save_warnings.clear();
        self.form_profile_name = None; // not the form editor; release the frozen profile
        self.form_profile_provisional = false;
        if let Some(cfg) = &self.config {
            // Never serialize real proxy secrets into the editable JSON. self.config is already
            // redacted (GetConfig / post-save), but redact again via the shared helper so the editor
            // seed and the dirty-check baseline use the SAME redacted serialization and can't drift.
            // Untouched placeholders round-trip back through the engine's restore on save.
            if let Some(json) = Self::redacted_editor_json(cfg) {
                self.editor
                    .update(cx, |state, cx| state.set_value(json, window, cx));
            }
        }
        cx.notify();
    }

    /// Leave edit mode without saving.
    fn exit_edit(&mut self, cx: &mut Context<Self>) {
        self.close_to_view();
        self.retire_session(); // a save from this session must not close a later one when it lands
        self.edit.save_status.clear();
        self.edit.save_errors.clear();
        self.edit.save_warnings.clear();
        cx.notify();
    }

    /// Handle a section sub-tab click. In read-only view, just switch. While editing,
    /// switching sections closes edit mode (the contextual "Edit <section>" model) — but
    /// unsaved changes aren't discarded silently: if dirty, stash the target and surface a
    /// discard-confirm banner instead of switching.
    fn request_section(&mut self, target: ConfigSection, cx: &mut Context<Self>) {
        if target == self.config_section {
            self.edit.pending_section = None;
            cx.notify();
            return;
        }
        let editing = !matches!(self.config_mode, ConfigMode::View);
        if editing {
            // Commit typed-but-unflushed field text into the draft FIRST, so the dirty check
            // sees it — otherwise typing then switching sections would silently drop the value
            // (form inputs only reach the draft via flush, not on every keystroke). A pending
            // password change needs no handling: it isn't in the draft, and config_is_dirty
            // consults pending_password() directly.
            self.flush(cx);
        }
        if editing && self.config_is_dirty(cx) {
            self.edit.pending_section = Some(target);
            cx.notify();
            return;
        }
        if editing {
            self.exit_edit(cx); // clean — nothing to lose, so close edit mode and switch
        }
        self.config_section = target;
        self.edit.pending_section = None;
        self.save_ui_state();
        cx.notify();
    }

    /// Mutate a rule in the active profile of the draft (form-editor edits).
    fn with_rule_mut(&mut self, g: usize, r: usize, f: impl FnOnce(&mut Rule)) {
        if let Some(p) = self.active_profile_mut() {
            if let Some(rule) = p
                .rule_groups
                .get_mut(g)
                .and_then(|grp| grp.rules.get_mut(r))
            {
                f(rule);
            }
        }
    }

    /// The engine's RUNNING (effective) profile when it has reported one and the config in hand
    /// still defines it, else the config's active profile. Under a `--profile` run the config's
    /// `activeProfile` differs from what the engine recompiles, so the config tab must follow the
    /// profile the engine actually runs — otherwise an operator edits a non-running profile, saves,
    /// sees "configuration applied", and routing is unchanged. Falls back to the active profile for
    /// the normal (non-pinned) case and before the first status poll. This is the DYNAMIC target;
    /// the open form freezes it (see [`Self::editing_profile_name`]). Pure core:
    /// [`resolve_running_or_active`].
    fn running_or_active_profile(&self) -> String {
        let cfg = self.draft.as_ref().or(self.config.as_ref());
        profile_select::resolve_running_or_active(self.running_profile_name.as_deref(), cfg)
    }

    /// The profile the config tab edits and displays. While a form edit is OPEN, this is FROZEN to
    /// `form_profile_name` (captured when the draft was seeded) so that an external profile change
    /// mid-edit — `running_profile_name` now updates every status poll — cannot silently retarget a
    /// stored `form_sel` index onto a different profile's rules/proxies/chains. Outside the form
    /// (read-only view), it follows the running profile dynamically. Pure core:
    /// [`resolve_editing_profile`].
    fn editing_profile_name(&self) -> String {
        let cfg = self.draft.as_ref().or(self.config.as_ref());
        profile_select::resolve_editing_profile(
            self.form_profile_name.as_deref(),
            self.running_profile_name.as_deref(),
            cfg,
        )
    }

    /// The health verdict to badge for proxy `name`, or `None` when no badge should show. Health is
    /// scoped to the engine's RUNNING profile and keyed by name, so callers pass `show` = "the
    /// rendered profile is the running one" (computed once per render in [`Self::render_form`]) —
    /// otherwise a same-named proxy in a different/edited profile would be mislabeled.
    fn proxy_health_for(&self, name: &str, show: bool) -> Option<&proxroute_ipc::ProxyHealth> {
        show.then(|| self.proxy_health.get(name)).flatten()
    }

    /// Set `running_config` from the locally-held `self.config` ONLY when that config actually IS the
    /// running one — its digest (`base_digest`) matches the engine's `running_config_digest`. After
    /// another client advanced the saved config, `self.config` is stale, so leave `running_config`
    /// unknown (None) rather than present stale content as live (the auto-refresh fetches the current
    /// one). A digest-less (legacy) peer reports no running digest; there we can't tell, so fall back
    /// to assuming the locally-held config is what's running (the common single-client case).
    fn set_running_from_local_config(&mut self, running_digest: Option<u64>) {
        match running_digest {
            Some(_) if self.base_digest == running_digest => {
                self.running_config.clone_from(&self.config)
            }
            Some(_) => self.running_config = None,
            None => self.running_config.clone_from(&self.config),
        }
    }

    /// Reconcile a provisional form freeze once the running profile is first known. The form may have
    /// been opened before any status poll, freezing to the config's active profile — which is wrong
    /// under a `--profile` override. If the draft is still pristine, re-aim the freeze at the running
    /// profile so the user edits the right one; if they have already edited, keep the frozen profile
    /// (the drift banner warns). Runs at most once per form session, then clears the provisional flag.
    fn reconcile_provisional_freeze(&mut self, cx: &App) {
        if !self.form_profile_provisional {
            return;
        }
        let Some(running) = self.running_profile_name.clone() else {
            return; // still unknown — stay provisional until a poll reports it
        };
        self.form_profile_provisional = false; // the running profile is known now, either way
                                               // Only silently re-target a PRISTINE form (no edits yet) whose draft defines the running
                                               // profile; an edited form keeps its profile and surfaces the drift banner instead. Compare
                                               // the EFFECTIVE draft so a pending password (kept out of self.draft) counts as an edit
                                               // and doesn't let a started-but-unflushed change be mistaken for pristine.
        let pristine = match (self.effective_draft(cx), self.config.as_ref()) {
            (Some(d), Some(c)) => serde_json::to_string(&d).ok() == serde_json::to_string(c).ok(),
            _ => false,
        };
        let running_in_draft = self
            .draft
            .as_ref()
            .is_some_and(|d| d.profiles.iter().any(|p| p.name == running));
        if let Some(new) = profile_select::reconciled_freeze(
            self.form_profile_name.as_deref(),
            &running,
            pristine,
            running_in_draft,
        ) {
            self.form_profile_name = Some(new);
        }
    }

    /// The profile being edited in the draft (see [`Self::editing_profile_name`]), mutably.
    fn active_profile_mut(&mut self) -> Option<&mut Profile> {
        let name = self.editing_profile_name();
        let draft = self.draft.as_mut()?;
        draft.profiles.iter_mut().find(|p| p.name == name)
    }

    /// Commit the detail-panel text inputs back into the draft for the current selection.
    fn flush(&mut self, cx: &mut Context<Self>) {
        let Some(sel) = self.form_sel else { return };
        let name = self.form.name.read(cx).value().to_string();
        match sel {
            FormSel::Rule(g, r) => {
                let apps = self.form.apps.read(cx).value().to_string();
                let domains = self.form.domains.read(cx).value().to_string();
                let ips = self.form.ips.read(cx).value().to_string();
                let ports = self.form.ports.read(cx).value().to_string();
                let app_paths = self.form.app_paths.read(cx).value().to_string();
                let app_parent = self.form.app_parent.read(cx).value().to_string();
                let signed_by = self.form.signed_by.read(cx).value().to_string();
                let days = self.form.days.read(cx).value().to_string();
                let hours = self.form.hours.read(cx).value().to_string();
                let (tcp, udp, v4, v6) = (self.form.tcp, self.form.udp, self.form.v4, self.form.v6);
                // Only rebuild the predicate for a form-representable match; a complex
                // JSON-only match keeps its structure (only the name updates).
                let profile = self.editing_profile_name();
                let editable = self
                    .draft
                    .as_ref()
                    .and_then(|d| rule_at(d, &profile, g, r))
                    .is_some_and(|ru| extract_rule_fields(&ru.match_).is_some());
                self.with_rule_mut(g, r, |rule| {
                    if !name.trim().is_empty() {
                        rule.name = name;
                    }
                    if editable {
                        rule.match_ = build_match(RuleFields {
                            apps: split_list(&apps),
                            domains: split_list(&domains),
                            ips: split_list(&ips),
                            ports: split_list(&ports),
                            tcp,
                            udp,
                            app_paths: split_list(&app_paths),
                            app_parent: split_list(&app_parent),
                            signed_by,
                            v4,
                            v6,
                            days: split_list(&days),
                            hours: split_list(&hours),
                        });
                    }
                });
            }
            FormSel::Proxy(i) => {
                let host = self.form.endpoint.read(cx).value().to_string();
                let port = self.form.pport.read(cx).value().to_string();
                let user = self.form.user.read(cx).value().to_string();
                let auth = self.form.auth;
                // Health check (read before the &mut self borrow below): build from the inputs when
                // enabled, else clear.
                let hc_enabled = self.form.hc_enabled;
                let hc_target = self.form.hc_target.read(cx).value().trim().to_string();
                // EMPTY interval -> the documented 30s default. An actually-typed invalid/zero/huge
                // value flows through as 0 so the engine's "intervalSec must be greater than 0"
                // validation surfaces it on save (matching how the target field reports errors),
                // rather than being silently rewritten to 30 (which would diverge from the input).
                let hc_interval_raw = self.form.hc_interval.read(cx).value().trim().to_string();
                let hc_interval = if hc_interval_raw.is_empty() {
                    DEFAULT_HEALTH_INTERVAL_SECS
                } else {
                    hc_interval_raw.parse::<u32>().unwrap_or(0)
                };
                // ALWAYS keep the stored secret (the `<unchanged>` placeholder). A pending new
                // password is deliberately NOT written to the draft here — it lives only in the
                // input widget and is merged in at Save / Check (pending_password), so an abandoned
                // change can never be persisted.
                let pass = {
                    let profile = self.editing_profile_name();
                    self.draft
                        .as_ref()
                        .and_then(|d| proxy_at(d, &profile, i))
                        .map(|px| password_of(&px.auth))
                        .unwrap_or_default()
                };
                if let Some(p) = self.active_profile_mut() {
                    if let Some(px) = p.proxies.get_mut(i) {
                        if !name.trim().is_empty() {
                            px.name = name;
                        }
                        px.endpoint = join_host_port(&host, &port);
                        // The form has no control for the service-identity opt-in; keep one the
                        // config already carries instead of silently dropping it on save.
                        let keep_service_identity = matches!(
                            px.auth,
                            ProxyAuth::Negotiate {
                                allow_service_identity: true
                            }
                        );
                        px.auth = auth.build(user, pass);
                        if let ProxyAuth::Negotiate {
                            allow_service_identity,
                        } = &mut px.auth
                        {
                            *allow_service_identity |= keep_service_identity;
                        }
                        px.health_check = hc_enabled.then_some(HealthCheck {
                            kind: HealthCheckKind::Connect,
                            target: hc_target,
                            interval_sec: hc_interval,
                        });
                    }
                }
                // Any committed edit to the selected proxy (endpoint / auth scheme / username /
                // the pending password merged at check time) invalidates a previously displayed
                // reachability result — drop it so the ✓/✗ never lingers under changed
                // credentials. check_proxy and the ProxyCheck reply set proxy_check AFTER their
                // own flush, so they are unaffected.
                self.proxy_check = None;
            }
            FormSel::Chain(i) => {
                if let Some(p) = self.active_profile_mut() {
                    if let Some(ch) = p.chains.get_mut(i) {
                        if !name.trim().is_empty() {
                            ch.name = name;
                        }
                    }
                }
            }
        }
    }

    /// Select a rule and seed the detail inputs from it (committing the previous selection).
    fn select_rule(&mut self, g: usize, r: usize, window: &mut Window, cx: &mut Context<Self>) {
        // Leaving a proxy ends any in-progress password change uniformly (like select_proxy): its
        // typed value was never in the draft, so it is simply dropped — a proxy password change
        // takes effect only via Save while that proxy is selected. Keeps discard-confirm
        // behavior path-independent (pending_password no longer lingers on a non-proxy form_sel).
        self.pass_changing = false;
        self.flush(cx);
        self.form_sel = Some(FormSel::Rule(g, r));
        let profile = self.editing_profile_name();
        let seed = self
            .draft
            .as_ref()
            .and_then(|d| rule_at(d, &profile, g, r))
            .map(|rule| {
                (
                    rule.name.clone(),
                    extract_rule_fields(&rule.match_).unwrap_or_default(),
                )
            });
        if let Some((name, f)) = seed {
            self.form
                .name
                .update(cx, |s, cx| s.set_value(name, window, cx));
            self.form
                .apps
                .update(cx, |s, cx| s.set_value(f.apps.join(", "), window, cx));
            self.form
                .domains
                .update(cx, |s, cx| s.set_value(f.domains.join(", "), window, cx));
            self.form
                .ips
                .update(cx, |s, cx| s.set_value(f.ips.join(", "), window, cx));
            self.form
                .ports
                .update(cx, |s, cx| s.set_value(f.ports.join(", "), window, cx));
            self.form.tcp = f.tcp;
            self.form.udp = f.udp;
            self.form
                .app_paths
                .update(cx, |s, cx| s.set_value(f.app_paths.join(", "), window, cx));
            self.form
                .app_parent
                .update(cx, |s, cx| s.set_value(f.app_parent.join(", "), window, cx));
            self.form
                .signed_by
                .update(cx, |s, cx| s.set_value(f.signed_by.clone(), window, cx));
            self.form
                .days
                .update(cx, |s, cx| s.set_value(f.days.join(", "), window, cx));
            self.form
                .hours
                .update(cx, |s, cx| s.set_value(f.hours.join(", "), window, cx));
            self.form.v4 = f.v4;
            self.form.v6 = f.v6;
            // Auto-expand the advanced foldout when the rule actually uses advanced criteria.
            self.form.adv_open = !f.app_paths.is_empty()
                || !f.app_parent.is_empty()
                || !f.signed_by.is_empty()
                || f.v4
                || f.v6
                || !f.days.is_empty()
                || !f.hours.is_empty();
        }
        cx.notify();
    }

    /// Append a new empty rule to the active profile's last enabled group and select it.
    fn add_rule(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.flush(cx);
        let rule = Rule {
            name: "New rule".into(),
            enabled: true,
            match_: Predicate::App(AppMatch::default()),
            action: Action {
                kind: ActionType::Direct,
                target: None,
                dns_mode: None,
                on_failure: None,
            },
        };
        if let Some((g, r)) = self.append_rule_to_active_profile(rule) {
            self.select_rule(g, r, window, cx);
        }
    }

    fn delete_rule(&mut self, g: usize, r: usize, cx: &mut Context<Self>) {
        // Commit any open detail edit before indices shift (matches move_rule/clone_rule) — otherwise
        // deleting a DIFFERENT rule discards the selected rule's typed-but-unflushed edits. flush()
        // no-ops when nothing is selected.
        self.flush(cx);
        if let Some(p) = self.active_profile_mut() {
            if let Some(group) = p.rule_groups.get_mut(g) {
                if r < group.rules.len() {
                    group.rules.remove(r);
                }
            }
        }
        self.form_sel = None; // indices shifted; drop the selection
        cx.notify();
    }

    fn move_rule(&mut self, g: usize, r: usize, up: bool, cx: &mut Context<Self>) {
        self.flush(cx); // commit any open detail edit before reordering
        let mut swapped = None;
        if let Some(p) = self.active_profile_mut() {
            if let Some(group) = p.rule_groups.get_mut(g) {
                // Guard BOTH ends: r > 0 (not already at the top) AND r < len (not a stale
                // index) — so a stale index is a no-op rather than a swap panic on the UI
                // thread. Symmetric with the down branch below.
                let j = if up {
                    (r > 0 && r < group.rules.len()).then_some(r - 1)
                } else {
                    (r + 1 < group.rules.len()).then_some(r + 1)
                };
                if let Some(j) = j {
                    group.rules.swap(r, j);
                    swapped = Some(j);
                }
            }
        }
        // Keep the selection on whichever rule the user was looking at across the swap,
        // instead of dropping it.
        if let Some(j) = swapped {
            self.form_sel = match self.form_sel {
                Some(FormSel::Rule(sg, sr)) if sg == g && sr == r => Some(FormSel::Rule(g, j)),
                Some(FormSel::Rule(sg, sr)) if sg == g && sr == j => Some(FormSel::Rule(g, r)),
                other => other,
            };
        }
        cx.notify();
    }

    /// Duplicate a rule, inserting the copy just below it and selecting it.
    fn clone_rule(&mut self, g: usize, r: usize, window: &mut Window, cx: &mut Context<Self>) {
        self.flush(cx);
        let added = self.active_profile_mut().and_then(|p| {
            let group = p.rule_groups.get_mut(g)?;
            let mut copy = group.rules.get(r)?.clone();
            copy.name = format!("{} (copy)", copy.name);
            group.rules.insert(r + 1, copy);
            Some((g, r + 1))
        });
        if let Some((g, r)) = added {
            self.select_rule(g, r, window, cx);
        }
    }

    fn with_proxy_mut(&mut self, i: usize, f: impl FnOnce(&mut ProxyDef)) {
        if let Some(p) = self.active_profile_mut() {
            if let Some(px) = p.proxies.get_mut(i) {
                f(px);
            }
        }
    }

    /// The new password the user has typed for the selected proxy but not committed. `Some` only
    /// while a "Change" is in progress for a proxy AND the field is non-empty. The typed secret is
    /// kept OUT of `draft` on purpose, so this is how Save / Check / the dirty check see it;
    /// merge it into a proxy value with [`set_password`]. Returns the proxy index too so the caller
    /// applies it to the right proxy.
    fn pending_password(&self, cx: &App) -> Option<(usize, String)> {
        let Some(FormSel::Proxy(i)) = self.form_sel else {
            return None;
        };
        if !self.pass_changing {
            return None;
        }
        let pw = self.form.pass.read(cx).value().to_string();
        (!pw.is_empty()).then_some((i, pw))
    }

    /// The draft AS IT WOULD BE SAVED: a clone of `self.draft` with the pending new password (if
    /// any) merged into the `i`-th proxy of the editing profile (indexing mirrors `flush`'s proxy
    /// branch). The typed password is deliberately kept out of `self.draft`, so this is the
    /// ONE place that reconstitutes the effective config — every draft-consumer (the
    /// provisional-freeze pristine check, Save, the reachability-check fingerprint) goes through it
    /// so none can forget the pending password and disagree about what a Save would produce.
    fn effective_draft(&self, cx: &App) -> Option<Config> {
        let mut cfg = self.draft.clone()?;
        if let Some((i, pw)) = self.pending_password(cx) {
            let profile = self.editing_profile_name();
            if let Some(p) = cfg.profiles.iter_mut().find(|p| p.name == profile) {
                if let Some(px) = p.proxies.get_mut(i) {
                    set_password(&mut px.auth, pw);
                }
            }
        }
        Some(cfg)
    }

    /// Cancel an in-progress password change: the typed value was never in the draft, so this just
    /// drops it (hide the input, clear the field) and discards a stale reachability result that may
    /// have tested the abandoned password.
    fn cancel_pass_change(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.pass_changing = false;
        self.form
            .pass
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.proxy_check = None;
        cx.notify();
    }

    fn select_proxy(&mut self, i: usize, window: &mut Window, cx: &mut Context<Self>) {
        // Leaving/reselecting a proxy ends any in-progress password change (its typed value was
        // never in the draft, so nothing to revert — just drop it). Scoped to a proxy switch: from
        // a rule/chain/section the input isn't shown and pending_password() ignores it anyway.
        self.pass_changing = false;
        self.flush(cx);
        self.form_sel = Some(FormSel::Proxy(i));
        self.proxy_check = None;
        let profile = self.editing_profile_name();
        let seed = self
            .draft
            .as_ref()
            .and_then(|d| proxy_at(d, &profile, i))
            .map(|px| {
                let user = match &px.auth {
                    ProxyAuth::UserPass { username, .. }
                    | ProxyAuth::Basic { username, .. }
                    | ProxyAuth::Digest { username, .. } => username.clone(),
                    _ => String::new(),
                };
                let (host, port) = split_host_port(&px.endpoint);
                let (hc_enabled, hc_target, hc_interval) = match &px.health_check {
                    Some(hc) => (true, hc.target.clone(), hc.interval_sec.to_string()),
                    None => (false, String::new(), String::new()),
                };
                (
                    px.name.clone(),
                    host,
                    port,
                    user,
                    AuthKind::from_auth(&px.auth),
                    hc_enabled,
                    hc_target,
                    hc_interval,
                )
            });
        if let Some((name, host, port, user, auth, hc_enabled, hc_target, hc_interval)) = seed {
            self.form
                .name
                .update(cx, |s, cx| s.set_value(name, window, cx));
            self.form
                .endpoint
                .update(cx, |s, cx| s.set_value(host, window, cx));
            self.form
                .pport
                .update(cx, |s, cx| s.set_value(port, window, cx));
            self.form
                .user
                .update(cx, |s, cx| s.set_value(user, window, cx));
            // The stored password is never loaded into the input (shown as “set”; the user
            // clicks Change to enter a new one) — avoids accidental exposure / blanking.
            self.form
                .pass
                .update(cx, |s, cx| s.set_value("", window, cx));
            self.form.auth = auth;
            self.form.hc_enabled = hc_enabled;
            self.form
                .hc_target
                .update(cx, |s, cx| s.set_value(hc_target, window, cx));
            self.form
                .hc_interval
                .update(cx, |s, cx| s.set_value(hc_interval, window, cx));
        }
        cx.notify();
    }

    fn add_proxy(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.flush(cx);
        let idx = self.active_profile_mut().map(|p| {
            let i = p.proxies.len();
            p.proxies.push(ProxyDef {
                name: format!("New proxy {}", i + 1),
                kind: ProxyKind::Socks5,
                endpoint: String::new(),
                protocols: vec![Protocol::Tcp, Protocol::Udp],
                auth: ProxyAuth::None,
                dns: Default::default(),
                priority: None,
                health_check: None,
                skip_verify: false,
                udp_use_proxy_host: false,
            });
            i
        });
        if let Some(i) = idx {
            self.select_proxy(i, window, cx);
        }
    }

    fn delete_proxy(&mut self, i: usize, cx: &mut Context<Self>) {
        // Commit any open detail edit first (see delete_rule) so deleting a different proxy doesn't
        // discard an unsaved endpoint/username edit on the selected one.
        self.flush(cx);
        if let Some(p) = self.active_profile_mut() {
            if i < p.proxies.len() {
                p.proxies.remove(i);
            }
        }
        self.form_sel = None;
        cx.notify();
    }

    /// Reorder a chain hop up/down (chain traversal order is significant).
    fn move_hop(&mut self, i: usize, h: usize, up: bool, cx: &mut Context<Self>) {
        self.with_chain_mut(i, |c| {
            // Guard both ends (see move_rule): h > 0 AND h < len, so a stale index is a
            // no-op rather than a swap panic.
            let j = if up {
                (h > 0 && h < c.hops.len()).then_some(h - 1)
            } else {
                (h + 1 < c.hops.len()).then_some(h + 1)
            };
            if let Some(j) = j {
                c.hops.swap(h, j);
            }
        });
        cx.notify();
    }

    fn with_chain_mut(&mut self, i: usize, f: impl FnOnce(&mut ProxyChain)) {
        if let Some(p) = self.active_profile_mut() {
            if let Some(ch) = p.chains.get_mut(i) {
                f(ch);
            }
        }
    }

    fn select_chain(&mut self, i: usize, window: &mut Window, cx: &mut Context<Self>) {
        self.pass_changing = false; // leaving a proxy drops any in-progress password change (see select_rule)
        self.flush(cx);
        self.form_sel = Some(FormSel::Chain(i));
        let profile = self.editing_profile_name();
        let name = self
            .draft
            .as_ref()
            .and_then(|d| chain_at(d, &profile, i))
            .map(|ch| ch.name.clone());
        if let Some(name) = name {
            self.form
                .name
                .update(cx, |s, cx| s.set_value(name, window, cx));
        }
        cx.notify();
    }

    fn add_chain(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.flush(cx);
        let idx = self.active_profile_mut().map(|p| {
            let i = p.chains.len();
            p.chains.push(ProxyChain {
                name: format!("New chain {}", i + 1),
                mode: ChainMode::Static,
                hops: Vec::new(),
                protocols: vec![Protocol::Tcp],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            });
            i
        });
        if let Some(i) = idx {
            self.select_chain(i, window, cx);
        }
    }

    fn delete_chain(&mut self, i: usize, cx: &mut Context<Self>) {
        // Commit any open detail edit first (see delete_rule) so deleting a different chain doesn't
        // discard an unsaved edit on the selected one.
        self.flush(cx);
        if let Some(p) = self.active_profile_mut() {
            if i < p.chains.len() {
                p.chains.remove(i);
            }
        }
        self.form_sel = None;
        cx.notify();
    }

    /// Send the editor's JSON to the engine (`SetConfig`) on a one-shot background thread;
    /// the result comes back as `Msg::SaveResult`.
    fn save(&mut self, cx: &mut Context<Self>) {
        // Hard guard against a second concurrent save: pending_config is a single shared slot, so a
        // second save would overwrite it and a late first response could then apply the wrong draft.
        // The Save button is also disabled while saving; this backstops a click that races that.
        if self.edit.saving {
            return;
        }
        self.edit.save_errors.clear();
        self.edit.save_warnings.clear(); // a fresh attempt clears any prior issue panels
                                         // Commit any open detail-panel inputs into the draft first.
        if matches!(self.config_mode, ConfigMode::Form) {
            self.flush(cx);
        }
        // The JSON to save + an optimistic Config for the structured view. For the JSON editor
        // we send the text *verbatim* so the engine's strict parse sees any unknown/misspelled
        // keys — parsing + reserializing here would silently drop them before the engine ever
        // checks. The Form editor has no unknown keys, so it serializes the typed draft.
        let (json, pending) = match self.config_mode {
            ConfigMode::Form => {
                // effective_draft merges the pending password into a CLONE (never self.draft), so
                // only an explicit Save commits it — an abandoned change stays out.
                let Some(draft) = self.effective_draft(cx) else {
                    return;
                };
                match serde_json::to_string_pretty(&draft) {
                    Ok(j) => (j, Some(draft)),
                    Err(e) => {
                        self.edit.save_status = t!("save.serialize_error", error = e).into();
                        cx.notify();
                        return;
                    }
                }
            }
            ConfigMode::Json => {
                let text = self.editor.read(cx).value().to_string();
                // Best-effort parse only to reflect the save in the structured view; the engine
                // is the authority on validity (it strict-parses this same text).
                let pending = serde_json::from_str::<Config>(&text).ok();
                (text, pending)
            }
            ConfigMode::View => return,
        };
        self.edit.pending_config = pending;
        self.edit.saving = true; // disables Reload + lets a racing reload be dropped on save completion
        self.edit.save_status = t!("save.saving").into();
        let tx = self.tx.clone();
        // The revision this edit is based on — the engine rejects the save if the saved config has
        // advanced since (another client, a reload, a pending restart-required save).
        let base_digest = self.base_digest;
        // The session issuing this save: the result closes the edit session only if it is STILL
        // this one (the user can Revert out and open a new session during a slow save).
        let session_gen = self.edit.session_gen;
        std::thread::spawn(move || {
            let result = (|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| vec![e.to_string()])?;
                rt.block_on(async {
                    match proxroute_ipc::request(&Request::SetConfig { json, base_digest }).await {
                        // Reconstruct the convenience struct from the flat wire fields; an older
                        // service omits the scope, which we treat as an in-place engine restart.
                        Ok(Response::Applied {
                            restart_required,
                            restart_scope,
                            config_digest,
                            warnings,
                        }) => Ok(SaveOk {
                            restart: restart_required.map(|reason| RestartRequired {
                                reason,
                                scope: restart_scope.unwrap_or(RestartScope::Engine),
                            }),
                            config_digest,
                            warnings,
                        }),
                        Ok(Response::Error { messages }) => Err(messages),
                        Ok(other) => Err(vec![format!("unexpected reply: {other:?}")]),
                        Err(e) => Err(vec![e.to_string()]),
                    }
                })
            })();
            let _ = tx.unbounded_send(Msg::SaveResult {
                session_gen,
                result,
            });
        });
        cx.notify();
    }

    /// Ask the engine to restart (foreground only). The management connection drops as it
    /// relaunches and the poller reconnects; completion is detected when a status poll reports the
    /// engine running the saved config (its digest == `restart.target_digest`). Arm a deadline so a
    /// restart that's refused or never takes effect surfaces a "did not complete" status instead of
    /// spinning on "restarting…".
    fn restart(&mut self, cx: &mut Context<Self>) {
        // Ignore duplicate clicks while a restart is already in flight — a second request would
        // reset the deadline/drop state and muddle the feedback.
        if self.restart.deadline.is_some() {
            return;
        }
        self.edit.save_status = t!("save.restarting").into();
        self.edit.save_errors.clear();
        self.edit.save_warnings.clear(); // drop any stale issue panels from a previous attempt
        self.restart.deadline = Some(Instant::now() + RESTART_TIMEOUT);
        self.restart.saw_drop = false; // start of a fresh in-place restart
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result: Result<(), Vec<String>> = (|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| vec![e.to_string()])?;
                rt.block_on(async {
                    match proxroute_ipc::request(&Request::RestartEngine).await {
                        Ok(Response::Ok) => Ok(()),
                        Ok(Response::Error { messages }) => Err(messages),
                        Ok(other) => Err(vec![format!("unexpected reply: {other:?}")]),
                        Err(e) => {
                            use std::io::ErrorKind::*;
                            // After RestartEngine the engine cancels filtering and the pipe drops,
                            // so a broken-pipe / EOF here is the EXPECTED accepted path. Any OTHER
                            // error — couldn't open/connect, server-trust failure, write/read
                            // timeout, decode — means the request didn't take effect; surface it
                            // instead of masquerading as "restarting…" until the deadline times out.
                            if matches!(
                                e.kind(),
                                BrokenPipe | UnexpectedEof | ConnectionReset | ConnectionAborted
                            ) {
                                Ok(())
                            } else {
                                Err(vec![format!("restart request failed: {e}")])
                            }
                        }
                    }
                })
            })();
            let _ = tx.unbounded_send(Msg::RestartResult(result));
        });
        cx.notify();
    }

    /// Open the detail panel when a table row is double-clicked.
    fn on_table_event(
        &mut self,
        table: &Entity<TableState<ConnDelegate>>,
        event: &TableEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            TableEvent::DoubleClickedRow(ix) => {
                if let Some(row) = table.read(cx).delegate().rows.get(*ix).cloned() {
                    self.traffic.selected = Some(row);
                    self.traffic.explanation = None;
                    cx.notify();
                }
            }
            // Stash the right-clicked row so the context-menu actions know their target.
            TableEvent::RightClickedRow(Some(ix)) => {
                self.traffic.ctx_row = table.read(cx).delegate().rows.get(*ix).cloned();
            }
            _ => {}
        }
    }
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // A live language switch flags construction-time strings (table headers, input placeholders)
        // for re-localization here, where the `&mut Window` they need is available.
        if self.relocalize_pending {
            self.relocalize_pending = false;
            self.traffic.table.update(cx, |t, cx| {
                t.delegate_mut().relocalize();
                cx.notify();
            });
            self.traffic.filter_input.update(cx, |s, cx| {
                s.set_placeholder(t!("input.filter"), window, cx)
            });
            self.traffic.log_search.update(cx, |s, cx| {
                s.set_placeholder(t!("input.log_search"), window, cx)
            });
        }
        let entity = cx.entity();
        let body = match self.tab {
            Tab::Connections => self.render_connections(&entity, cx).into_any_element(),
            Tab::Config => self.render_config(cx).into_any_element(),
        };
        let mut tabs = div()
            .w_full()
            .h_flex()
            .gap_1()
            .px_2()
            .pt_1()
            .bg(rgb(BG_BAR))
            .child(tab_btn(
                "tab-connections",
                t!("tab.connections"),
                self.tab == Tab::Connections,
                cx.listener(|this, _ev, _w, cx| {
                    this.tab = Tab::Connections;
                    this.save_ui_state();
                    cx.notify();
                }),
            ))
            .child(tab_btn(
                "tab-config",
                t!("tab.config"),
                self.tab == Tab::Config,
                cx.listener(|this, _ev, _w, cx| {
                    this.tab = Tab::Config;
                    this.save_ui_state();
                    cx.notify();
                }),
            ))
            // Push the language dropdown to the far right of the tab bar.
            .child(div().flex_grow(1.0));
        // Language selector as a dropdown (scales past two languages better than side-by-side
        // chips): the trigger shows the current language; the popover lists all shipped languages,
        // and picking one flips the locale and dismisses. Uncontrolled — the Popover self-manages
        // open state (click-outside closes) keyed by its id.
        let current_lang = LOCALES
            .iter()
            .find(|&&(c, _)| c == self.locale)
            .map(|&(_, n)| n)
            .unwrap_or("English");
        let active_locale = self.locale;
        let lang_entity = cx.entity();
        tabs = tabs.child(
            Popover::new("lang-menu")
                .anchor(Anchor::TopRight)
                .trigger(
                    Button::new("lang-trigger")
                        .ghost()
                        .label(format!("{current_lang} ▾")),
                )
                .content(move |_, _, cx| {
                    let mut list = div().v_flex().gap_1().p_1().min_w(px(140.0));
                    for &(code, name) in LOCALES {
                        let ent = lang_entity.clone();
                        list = list.child(
                            Button::new(SharedString::from(code))
                                .ghost()
                                .label(name)
                                .selected(code == active_locale)
                                .on_click(cx.listener(move |_, _, _, cx| {
                                    ent.update(cx, |view, cx| view.set_language(code, cx));
                                    cx.emit(DismissEvent);
                                })),
                        );
                    }
                    list
                }),
        );
        div()
            .size_full()
            .v_flex()
            .bg(rgb(BG))
            .text_color(rgb(FG))
            .text_sm()
            .on_action(cx.listener(Self::on_create_rule))
            .on_action(cx.listener(Self::on_show_details))
            .on_action(cx.listener(Self::on_explain))
            .child(
                div()
                    .w_full()
                    .px_3()
                    .py_2()
                    .bg(rgb(BG_BAR))
                    .text_color(rgb(FG))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Proxroute"),
            )
            .child(tabs)
            .child(body)
            .child(self.status_bar())
    }
}

impl AppView {
    /// Empty-list state when connections exist but are all filtered/cleared out: names what's
    /// active and offers a one-click reset, so "where did my traffic go?" has an obvious fix.
    fn filtered_empty_state(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let search = self
            .traffic
            .filter_input
            .read(cx)
            .value()
            .trim()
            .to_string();
        let mut parts = Vec::new();
        if self.traffic.filter_kind != ConnFilter::All {
            parts.push(
                t!(
                    "msg.active_filter",
                    name = self.traffic.filter_kind.display()
                )
                .to_string(),
            );
        }
        if !search.is_empty() {
            parts.push(t!("msg.search_filter", term = search).into());
        }
        if !self.traffic.hidden_terminal.is_empty() {
            parts.push(t!("msg.cleared_note").into());
        }
        let summary = if parts.is_empty() {
            t!("msg.no_connections")
        } else {
            t!("msg.nothing_matches", filters = parts.join(" · "))
        };
        div()
            .size_full()
            .v_flex()
            .gap_2()
            .items_center()
            .justify_center()
            .child(div().text_color(rgb(FG_DIM)).child(summary))
            .child(
                Button::new("reset-filters")
                    .label(t!("button.reset_filters"))
                    .on_click(cx.listener(|this, _, window, cx| this.reset_filters(window, cx))),
            )
    }

    fn render_connections(
        &self,
        entity: &Entity<Self>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let detail = self.traffic.selected.clone();
        let reachable = self.engine_state != EngineState::Unreachable;
        // The table, or — when nothing is showing — either the reset-able filtered-empty state
        // (connections exist but are filtered/cleared out) or the plain waiting/unreachable note.
        let table_area = div()
            .flex_grow(1.0)
            .min_h(px(0.0))
            .child(if self.traffic.shown != 0 {
                DataTable::new(&self.traffic.table)
                    .stripe(true)
                    .into_any_element()
            } else if reachable && !self.traffic.all_rows.is_empty() {
                self.filtered_empty_state(cx).into_any_element()
            } else {
                connections_empty(self.traffic.all_rows.is_empty(), reachable).into_any_element()
            });

        // The upper pane (one resizable panel): the table fills it, and the detail panel —
        // when a row is selected — sits below the table at its *content* height (capped +
        // scrollable). Content-sized means it never leaves blank space, so the log below can
        // be dragged up into all the free room above it.
        let upper = div()
            .v_flex()
            .flex_grow(1.0)
            .min_h(px(0.0))
            .child(table_area)
            .children(detail.map(|row| {
                // The fields scroll within a bounded box; the routing explanation sits BELOW that
                // box (not inside it) so it's visible the instant Explain returns, with no need to
                // scroll the details to find it.
                div()
                    .v_flex()
                    .flex_none()
                    .child(
                        div()
                            .id("detail-scroll")
                            .flex_none()
                            .max_h(px(380.0))
                            .overflow_y_scroll()
                            .child(detail_panel(&row, entity)),
                    )
                    .children(self.traffic.explanation.as_deref().map(explanation_block))
            }));

        div()
            .v_flex()
            .flex_grow(1.0)
            .child(self.filter_bar(cx))
            // Make the frozen-table state obvious — the log + rates keep moving, so it's easy
            // to think the table is just idle.
            .children(self.traffic.paused.then(|| {
                div()
                    .h_flex()
                    .items_center()
                    .justify_between()
                    .px_3()
                    .py_1()
                    .bg(rgb(BG_BAR))
                    .text_color(rgb(YELLOW))
                    .child(t!("msg.paused_banner"))
                    .child(
                        Button::new("resume-banner")
                            .label(t!("button.resume"))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.traffic.paused = false;
                                cx.notify();
                            })),
                    )
            }))
            .child(
                // Split: the table+detail pane | the log. Drag the divider above the log to grow
                // or shrink the log; it fills whatever room is free above it.
                div().flex_grow(1.0).min_h(px(0.0)).child(
                    v_resizable("conn-log-split")
                        .child(resizable_panel().child(upper))
                        .child(
                            resizable_panel()
                                .size(px(LOG_PANEL_H))
                                .size_range(px(90.0)..px(800.0))
                                .flex_none()
                                .child(self.render_log(cx)),
                        ),
                ),
            )
    }

    /// The event-log panel: a toolbar (severity chips + search + Copy + Clear) over the
    /// filtered log lines.
    fn render_log(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut chips = div().h_flex().flex_wrap().gap_1().items_center();
        for f in LogFilter::ALL {
            // Per-severity count over the whole log, so the toolbar shows the mix at a glance.
            let count = self
                .traffic
                .log
                .iter()
                .filter(|l| f.matches(l.color))
                .count();
            let label = format!("{} {count}", f.display());
            chips = chips.child(chip(
                SharedString::from(f.label()),
                label,
                t!("chip.log_filter.tip"),
                self.traffic.log_filter == f,
                cx.listener(move |this, _, _, cx| {
                    this.traffic.log_filter = f;
                    this.save_ui_state();
                    cx.notify();
                }),
            ));
        }
        let toolbar = div()
            .h_flex()
            .gap_2()
            .items_center()
            .mb_1()
            .child(
                div()
                    .w(gpui::px(220.0))
                    .child(Input::new(&self.traffic.log_search).cleanable(true)),
            )
            .child(chips)
            .child(div().flex_grow(1.0))
            .child(
                Button::new("log-copy")
                    .label(t!("button.copy"))
                    .on_click(cx.listener(Self::copy_log)),
            )
            .child(
                Button::new("log-export")
                    .label(t!("button.export"))
                    .on_click(cx.listener(Self::export_log)),
            )
            .child(
                Button::new("log-clear")
                    .label(t!("button.clear"))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.traffic.log.clear();
                        cx.notify();
                    })),
            );

        // Own the visible lines (text/color/id) so the borrow of self.traffic.log is dropped before the
        // per-line click listeners are built.
        let visible: Vec<(String, u32, Option<u64>)> = self
            .visible_log(cx)
            .iter()
            .map(|l| (l.text.clone(), l.color, l.id))
            .collect();
        let mut lines = div()
            .id("event-log")
            .flex_grow(1.0)
            .min_h(gpui::px(0.0))
            .v_flex()
            .overflow_y_scroll();
        if visible.is_empty() {
            let msg = if self.traffic.log.is_empty() {
                t!("msg.log_empty")
            } else {
                t!("msg.log_filter_empty")
            };
            lines = lines.child(dim(msg.into()));
        }
        for (idx, (text, color, id)) in visible.into_iter().enumerate() {
            let base = div().whitespace_nowrap().text_color(rgb(color));
            // A line tied to a connection is clickable → selects that row (when still present).
            let el = if let Some(id) = id {
                base.id(SharedString::from(format!("logln-{idx}")))
                    .cursor_pointer()
                    .hover(|s| s.bg(rgb(BG_BAR)))
                    .on_click(cx.listener(move |this, _, _, cx| this.select_conn_by_id(id, cx)))
                    .child(text)
                    .into_any_element()
            } else {
                base.child(text).into_any_element()
            };
            lines = lines.child(el);
        }

        div()
            // Fill the resizable panel (its height is drag-controlled by the split); the
            // `lines` area inside flex-grows and scrolls.
            .size_full()
            .min_h(gpui::px(0.0))
            .v_flex()
            .px_3()
            .py_2()
            .border_t_1()
            .border_color(rgb(BG_BAR))
            .bg(rgb(BG_PANEL))
            .child(toolbar)
            .child(lines)
    }

    /// The connections filter bar: a free-text search box + decision/state chips on the
    /// left, pause / clear-closed controls on the right.
    fn filter_bar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut chips = div()
            .h_flex()
            .flex_wrap() // wrap the chips below the search box on narrow windows instead of overflowing
            .gap_2()
            .items_center()
            .child(
                div()
                    .w(px(300.0))
                    .child(Input::new(&self.traffic.filter_input).cleanable(true)),
            );
        for f in ConnFilter::ALL {
            let active = self.traffic.filter_kind == f;
            // Count the same rows the table shows: skip terminal rows the user has cleared via
            // "Clear closed" (hidden from the table), so the tab numbers match the visible list
            // instead of counting dismissed/closed connections the registry still retains.
            let count = self
                .traffic
                .all_rows
                .iter()
                .filter(|r| {
                    !(is_terminal(&r.state) && self.traffic.hidden_terminal.contains(&r.id))
                })
                .filter(|r| f.matches(r))
                .count();
            let label = format!("{} {count}", f.display());
            chips = chips.child(chip(
                SharedString::from(f.label()),
                label,
                t!("chip.conn_filter.tip"),
                active,
                cx.listener(move |this, _, _, cx| {
                    this.traffic.filter_kind = f;
                    this.refilter(cx);
                    this.save_ui_state();
                    cx.notify();
                }),
            ));
        }
        let controls = div()
            .h_flex()
            .gap_2()
            .items_center()
            .child(
                Button::new("pause")
                    .label(if self.traffic.paused {
                        t!("button.resume")
                    } else {
                        t!("button.pause")
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.traffic.paused = !this.traffic.paused;
                        cx.notify();
                    })),
            )
            .child(
                Button::new("clear-closed")
                    .label(t!("button.clear_closed"))
                    .on_click(cx.listener(|this, _, _, cx| this.clear_closed(cx))),
            );
        div()
            .w_full()
            .flex_none()
            .h_flex()
            .items_center()
            .justify_between()
            .px_2()
            .py_1()
            .bg(rgb(BG_BAR))
            .child(chips)
            .child(controls)
    }

    /// Serialize a config for the JSON editor with proxy secrets redacted. Single source for BOTH
    /// the editor seed (`enter_json`) and the dirty-check baseline (`config_is_dirty`), so the two
    /// can never drift — a drift would show a spurious "unsaved" state, or surface a cleartext
    /// password if `self.config` were ever left non-redacted.
    fn redacted_editor_json(config: &proxroute_config::Config) -> Option<String> {
        let mut shown = config.clone();
        proxroute_config::redact_secrets(&mut shown);
        serde_json::to_string_pretty(&shown).ok()
    }

    /// Whether the edit in progress differs from the saved config (drives the unsaved-changes
    /// indicator and the Revert confirmation). Compared via serialization since `Config` isn't
    /// `PartialEq`; form edits register once flushed into the draft (chip/add/delete are
    /// immediate, text on the next flush).
    fn config_is_dirty(&self, cx: &App) -> bool {
        match self.config_mode {
            ConfigMode::Form => {
                // A pending password is a change BY DEFINITION: the typed secret is kept out of
                // self.draft and can't be compared to the real stored secret (a redacted
                // placeholder), so treat it as dirty. Short-circuiting here also avoids
                // effective_draft's full-Config clone on this per-render hot path in the common
                // (no-pending) case — then a plain draft-vs-config compare suffices.
                if self.pending_password(cx).is_some() {
                    return true;
                }
                match (self.draft.as_ref(), self.config.as_ref()) {
                    (Some(d), Some(c)) => {
                        serde_json::to_string(d).ok() != serde_json::to_string(c).ok()
                    }
                    _ => false,
                }
            }
            // Same redacted serialization the editor was seeded with (redacted_editor_json), so an
            // untouched editor reads as clean rather than spuriously dirty.
            ConfigMode::Json => match self.config.as_ref().and_then(Self::redacted_editor_json) {
                Some(saved) => self.editor.read(cx).value().as_ref() != saved.as_str(),
                None => false,
            },
            ConfigMode::View => false,
        }
    }

    fn render_config(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let dirty = self.config_is_dirty(cx);
        let editing = !matches!(self.config_mode, ConfigMode::View);

        // Reload refetches the saved config from the engine (recovery after a stale-save rejection,
        // or a manual refresh). It arms a confirming second click when it would discard unsaved edits.
        // Disabled while a save or another reload is in flight, so a second reload can't overlap
        // (the config_seq check backstops any that slips through, applying only the newest response).
        let reload_busy = self.edit.saving || self.edit.reloading;
        let reload_btn = if self.edit.confirm_reload {
            Button::new("reload-config")
                .danger()
                .label(t!("button.discard_reload"))
                .disabled(reload_busy)
                .on_click(cx.listener(|this, _, _, cx| this.reload_config(cx)))
        } else {
            Button::new("reload-config")
                .label(if self.edit.reloading {
                    t!("button.reloading")
                } else {
                    t!("button.reload")
                })
                .tooltip(t!("button.reload_tip"))
                .disabled(reload_busy)
                .on_click(cx.listener(|this, _, _, cx| this.request_reload(cx)))
        };

        // Page-level action buttons, kept in the same top-right spot in both modes so the eye
        // doesn't have to hunt — Save & apply takes Edit config's place when editing.
        let actions = if editing {
            // Revert discards unsaved work, so when there are changes it arms a second
            // confirming click; with nothing to lose it reverts immediately.
            let revert_btn = if self.edit.confirm_revert {
                Button::new("revert-config")
                    .danger()
                    .label(t!("button.discard_changes"))
                    .on_click(cx.listener(|this, _, _, cx| this.exit_edit(cx)))
            } else {
                Button::new("revert-config")
                    .label(t!("button.revert"))
                    .tooltip(t!("button.revert_tip"))
                    .on_click(cx.listener(|this, _, _, cx| {
                        // Flush first so typed-but-unflushed text counts as a change and arms the
                        // discard confirm, instead of being dropped by an immediate revert.
                        this.flush(cx);
                        if this.config_is_dirty(cx) {
                            this.edit.confirm_revert = true;
                            cx.notify();
                        } else {
                            this.exit_edit(cx);
                        }
                    }))
            };
            div()
                .h_flex()
                .gap_2()
                .items_center()
                .child(
                    Button::new("save-config")
                        .primary()
                        .label(if self.edit.saving {
                            t!("button.saving")
                        } else {
                            t!("button.save_apply")
                        })
                        .tooltip(t!("button.save_apply_tip"))
                        .disabled(self.edit.saving) // one save at a time — no concurrent pending_config
                        .on_click(cx.listener(|this, _, _, cx| this.save(cx))),
                )
                .child(revert_btn)
                .child(reload_btn)
        } else {
            let mut row = div().h_flex().gap_2().items_center();
            // The Profile section has no per-field form (DNS / redirect mode / IPv6 / bypass are
            // structural), so its only edit affordance is the raw JSON — "Edit Profile" would
            // imply a form that doesn't exist. Every other section gets a form ("Edit Rules" etc.)
            // plus a secondary "Edit JSON". The label tracks the active section; since switching
            // sections closes edit mode, editing is effectively scoped to that section.
            if matches!(self.config_section, ConfigSection::Profile) {
                row = row.child(
                    Button::new("edit-json")
                        .primary()
                        .label(t!("button.edit_json"))
                        .on_click(cx.listener(|this, _, window, cx| this.enter_json(window, cx))),
                );
            } else {
                row = row
                    .child(
                        Button::new("edit-form")
                            .primary()
                            .label(t!(
                                "button.edit_section",
                                section = self.config_section.display()
                            ))
                            .on_click(cx.listener(|this, _, _, cx| this.enter_form(cx))),
                    )
                    .child(
                        Button::new("edit-json")
                            .label(t!("button.edit_json"))
                            .on_click(
                                cx.listener(|this, _, window, cx| this.enter_json(window, cx)),
                            ),
                    );
            }
            row = row.child(reload_btn);
            // A restart control appears only when a saved structural change is waiting for it, and
            // it offers the RIGHT action: an in-place "Restart engine" for engine-scope changes, or
            // a plain "service restart required" note for Service-scoped changes (logLevel /
            // kill-switch floor), which RestartEngine refuses — so don't lead the user into a failing click.
            if self.restart.needed {
                if matches!(self.restart.scope, Some(RestartScope::Service)) {
                    row = row.child(
                        div()
                            .text_color(rgb(YELLOW))
                            .child(t!("save.service_restart_hint")),
                    );
                } else {
                    // Disable + relabel while a restart is in flight so repeated clicks can't spawn
                    // duplicate requests (restart() also early-returns as a hard guard).
                    let restarting = self.restart.deadline.is_some();
                    row = row.child(
                        Button::new("restart-engine")
                            .primary()
                            .label(if restarting {
                                t!("save.compact_restarting")
                            } else {
                                t!("button.restart_engine")
                            })
                            .disabled(restarting)
                            .on_click(cx.listener(|this, _, _, cx| this.restart(cx))),
                    );
                }
            }
            row
        };

        // Compact mode badge: "<mode> · <state>" — mode dim, an unsaved marker in yellow, then a
        // compact save/restart state. The state is derived STRUCTURALLY from restart.needed /
        // restart.scope (not by parsing the save message), so a restart-required save shows
        // "restart needed" — never the green "Applied", which would imply it's already live.
        let mode = if editing {
            t!("config.editing")
        } else {
            t!("config.readonly")
        };
        let status_badge: Option<(SharedString, u32)> = if self.restart.needed {
            let text: SharedString = if matches!(self.restart.scope, Some(RestartScope::Service)) {
                t!("save.badge_service_restart").into()
            } else {
                t!("save.badge_restart").into()
            };
            Some((text, YELLOW))
        } else if !self.edit.save_status.is_empty() {
            Some((
                compact_status(
                    &self.edit.save_status,
                    self.edit.saving,
                    self.restart.deadline.is_some(),
                ),
                status_color(&self.edit.save_status),
            ))
        } else {
            None
        };
        let has_status = status_badge.is_some();
        let indicator = div()
            .h_flex()
            .gap_2()
            .items_center()
            .child(div().text_color(rgb(FG_DIM)).child(mode))
            .children((editing && dirty).then(|| div().text_color(rgb(FG_DIM)).child("·")))
            .children(
                (editing && dirty)
                    .then(|| div().text_color(rgb(YELLOW)).child(t!("config.unsaved"))),
            )
            .children(has_status.then(|| div().text_color(rgb(FG_DIM)).child("·")))
            .children(status_badge.map(|(text, color)| div().text_color(rgb(color)).child(text)));

        // Header: page title on the left; mode indicator + page actions on the right.
        let header = div()
            .h_flex()
            .items_center()
            .gap_3()
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(FG))
                    .child(t!("config.title")),
            )
            .child(div().flex_grow(1.0))
            .child(indicator)
            .child(actions);

        // The profile the config tab acts on: name · redirect mode · DNS mode — context that
        // otherwise lives only in the bottom status bar. Labelled "Editing profile" while a form is
        // open (it's the frozen target) and "Running profile" in the read-only view, since under a
        // `--profile` override this is NOT necessarily the config's activeProfile.
        // Pick the SOURCE config + label by mode so the header is honest: the form renders the config
        // being edited; the read-only view renders the RUNNING config (so "Running profile" + its
        // DNS/redirect modes are genuinely live); and when a saved change isn't live yet (a pending
        // restart left running_config None) it renders the SAVED config, clearly labelled "Saved
        // profile … not yet live" so saved modes aren't presented as running.
        let editing = self.editing_profile_name();
        let (src_cfg, name, profile_label, pending) = if self.form_profile_name.is_some() {
            (
                self.config.as_ref(),
                editing.clone(),
                t!("profile.editing"),
                false,
            )
        } else if let Some(rc) = self.running_config.as_ref() {
            let name = self
                .running_profile_name
                .clone()
                .unwrap_or_else(|| rc.active_profile.clone());
            (Some(rc), name, t!("profile.running"), false)
        } else if self.restart.needed {
            (
                self.config.as_ref(),
                editing.clone(),
                t!("profile.saved"),
                true,
            )
        } else {
            // Pre-first-poll: nothing better than the saved config; treat as running (self-corrects).
            (
                self.config.as_ref(),
                editing.clone(),
                t!("profile.running"),
                false,
            )
        };
        let profile_line = src_cfg.and_then(|cfg| {
            cfg.profiles.iter().find(|p| p.name == name).map(|p| {
                // Redirect mode and DNS mode stay as their technical enum spellings (they are the
                // same tokens shown in the status bar and in JSON) — see the i18n deferral note.
                let redirect = if cfg.redirect_mode == proxroute_config::RedirectMode::IpLayer {
                    "IP layer"
                } else {
                    "ALE"
                };
                // All three arms are `Cow<'static, str>` so they unify without allocating: `t!`
                // returns Cow (Borrowed for the static note, Owned once interpolated), and the
                // empty arm is a borrowed "". `format!` below consumes it via Display.
                let note = if pending {
                    t!("profile.note_pending")
                } else if name != cfg.active_profile {
                    // `--profile` run: the labelled profile isn't the config's stored activeProfile.
                    t!("profile.note_config_default", name = cfg.active_profile)
                } else {
                    std::borrow::Cow::Borrowed("")
                };
                let color = if pending { YELLOW } else { FG_DIM };
                div().text_color(rgb(color)).child(format!(
                    "{profile_label}: {} · {} · DNS {:?}{}",
                    name, redirect, p.dns.mode, note
                ))
            })
        });
        // While the form is open the edited profile is frozen. If the engine's running profile has
        // since drifted (an external restart / profile switch), warn that edits stay aimed at the
        // frozen profile — they won't affect the now-running one until it is active.
        let form_drift = match (
            &self.config_mode,
            &self.form_profile_name,
            &self.running_profile_name,
        ) {
            (ConfigMode::Form, Some(frozen), Some(running)) if running != frozen => {
                Some(div().text_color(rgb(YELLOW)).child(t!(
                    "profile.drift_warning",
                    running = running,
                    frozen = frozen
                )))
            }
            _ => None,
        };
        let content = match self.config_mode {
            ConfigMode::View => {
                let inner = match (&self.config, &self.config_error) {
                    (_, Some(err)) => {
                        simple_msg(t!("msg.config_load_failed", error = err).into(), RED)
                    }
                    (Some(cfg), _) => config_body(cfg, &editing, self.config_section, cx),
                    (None, None) => simple_msg(t!("msg.loading_config").into(), FG_DIM),
                };
                // min_h(0) lets the scroll area shrink below its content so overflow_y_scroll
                // actually engages (a flex child's min-height defaults to its content size).
                div()
                    .id("config-scroll")
                    .flex_grow(1.0)
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .child(inner)
                    .into_any_element()
            }
            ConfigMode::Form => div()
                .id("form-scroll")
                .flex_grow(1.0)
                .min_h(px(0.0))
                .overflow_y_scroll()
                .child(self.render_form(cx))
                .into_any_element(),
            ConfigMode::Json => div()
                .flex_grow(1.0)
                .min_h(px(0.0))
                .child(Input::new(&self.editor).h_full())
                .into_any_element(),
        };
        // Section sub-tabs (Rules / Proxies / Chains / Profile) — not in the raw JSON editor.
        let subtabs = (!matches!(self.config_mode, ConfigMode::Json)).then(|| {
            let mut row = div().h_flex().gap_2().items_center();
            for s in ConfigSection::ALL {
                row = row.child(chip(
                    SharedString::from(s.label()),
                    s.display(),
                    t!("chip.config_section.tip"),
                    self.config_section == s,
                    cx.listener(move |this, _, _, cx| this.request_section(s, cx)),
                ));
            }
            row
        });
        // Discard-confirm banner: shown when a section switch was requested mid-edit with
        // unsaved changes (see request_section). Confirm discards the draft and switches;
        // cancel keeps editing the current section.
        let switch_confirm = self.edit.pending_section.map(|target| {
            div()
                .h_flex()
                .gap_2()
                .items_center()
                .child(div().text_color(rgb(YELLOW)).child(SharedString::from(t!(
                    "config.switch_confirm",
                    section = target.display()
                ))))
                .child(
                    Button::new("switch-discard")
                        .danger()
                        .label(t!("button.discard_switch"))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.exit_edit(cx); // clears the draft + pending_section
                            this.config_section = target;
                            this.save_ui_state();
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("switch-cancel")
                        .label(t!("button.keep_editing"))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.edit.pending_section = None;
                            cx.notify();
                        })),
                )
        });
        // Discard-confirm for "Create rule from connection" while the JSON editor has unsaved
        // edits (see on_create_rule). Only meaningful in the JSON editor with edits still pending:
        // hidden once the mode changes OR the editor is made clean again (undo/save/reload), so it
        // never promises to discard edits that no longer exist. The captured row it holds is
        // cleared on the next session boundary (retire_session / close_to_view). Confirm discards
        // the JSON edits and creates the rule.
        let create_rule_confirm = (self.edit.pending_create_rule.is_some()
            && matches!(self.config_mode, ConfigMode::Json)
            && dirty)
            .then(|| {
                div()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .child(
                        div()
                            .text_color(rgb(YELLOW))
                            .child(SharedString::from(t!("config.create_rule_confirm"))),
                    )
                    .child(
                        Button::new("create-rule-discard")
                            .danger()
                            .label(t!("button.discard_create"))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                if let Some(row) = this.edit.pending_create_rule.take() {
                                    this.create_rule_from_conn(row, window, cx);
                                }
                            })),
                    )
                    .child(
                        Button::new("create-rule-cancel")
                            .label(t!("button.keep_editing"))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.edit.pending_create_rule = None;
                                cx.notify();
                            })),
                    )
            });
        div()
            .v_flex()
            .flex_grow(1.0)
            // Allow this pane to shrink to its slot so the inner scroll container (which also
            // sets min_h(0)) gets a bounded height — without it the whole chain grows to content
            // and `overflow_y_scroll` never engages.
            .min_h(px(0.0))
            .p_3()
            .gap_2()
            .child(header)
            .children(profile_line)
            .children(form_drift)
            .children(issue_panel(
                &self.edit.save_errors,
                RED,
                &t!("panel.problems_heading"),
                "error",
            ))
            .children(issue_panel(
                &self.edit.save_warnings,
                YELLOW,
                &t!("panel.warnings_heading"),
                "warn",
            ))
            .children(subtabs)
            .children(switch_confirm)
            .children(create_rule_confirm)
            .child(content)
    }

    /// The per-field form editor: shows the selected config section (Rules / Proxies /
    /// Chains / Profile). Each rule/proxy/chain is a clickable card with an inline editor.
    fn render_form(&self, cx: &mut Context<Self>) -> AnyElement {
        let editing = self.editing_profile_name();
        // Health badges only make sense for the RUNNING profile (health is scoped to it and keyed by
        // name). Decide ONCE per render and thread it down — proxy_health_for would otherwise
        // re-resolve (and allocate) the editing-profile name for every card and hop.
        let show_health = self.running_profile_name.as_deref() == Some(editing.as_str());
        let Some(draft) = &self.draft else {
            return simple_msg(t!("msg.no_config").into(), FG_DIM);
        };
        let Some(profile) = draft.profiles.iter().find(|p| p.name == editing) else {
            return simple_msg(t!("msg.profile_not_found", name = editing).into(), RED);
        };
        let proxies: Vec<String> = profile.proxies.iter().map(|p| p.name.clone()).collect();
        let chains: Vec<String> = profile.chains.iter().map(|c| c.name.clone()).collect();

        let mut root = div().v_flex().gap_2();
        match self.config_section {
            ConfigSection::Rules => {
                root = root.child(section_header(
                    &t!("config_section.rules"),
                    "add-rule",
                    &t!("config.add_rule"),
                    cx.listener(|this, _, window, cx| this.add_rule(window, cx)),
                ));
                // A header per group keeps the flat list of rule cards in its group/priority
                // context (groups apply in order; rules within a group apply in order).
                for (g, group) in profile.rule_groups.iter().enumerate() {
                    let count = group.rules.len();
                    root = root.child(rule_group_header(g, group));
                    if count == 0 {
                        root = root.child(dim("(no rules in this group)".into()));
                    }
                    for (r, rule) in group.rules.iter().enumerate() {
                        root = root
                            .child(self.render_rule_card(g, r, count, rule, &proxies, &chains, cx));
                    }
                }
                if profile.rule_groups.is_empty() {
                    root = root.child(dim("No rules yet — click “+ Add rule”.".into()));
                }
            }
            ConfigSection::Proxies => {
                root = root.child(section_header(
                    &t!("config_section.proxies"),
                    "add-proxy",
                    &t!("config.add_proxy"),
                    cx.listener(|this, _, window, cx| this.add_proxy(window, cx)),
                ));
                if profile.proxies.is_empty() {
                    root = root.child(dim("No proxies yet — click “+ Add proxy”.".into()));
                }
                for (i, px) in profile.proxies.iter().enumerate() {
                    root = root.child(self.render_proxy_card(i, px, show_health, cx));
                }
            }
            ConfigSection::Chains => {
                root = root.child(section_header(
                    &t!("config_section.chains"),
                    "add-chain",
                    &t!("config.add_chain"),
                    cx.listener(|this, _, window, cx| this.add_chain(window, cx)),
                ));
                if profile.chains.is_empty() {
                    root = root.child(dim("No chains yet — click “+ Add chain”.".into()));
                }
                for (i, ch) in profile.chains.iter().enumerate() {
                    root = root.child(self.render_chain_card(
                        i,
                        ch,
                        &profile.proxies,
                        show_health,
                        cx,
                    ));
                }
            }
            ConfigSection::Profile => {
                // `redirectAuth` is editable here, unlike its structural neighbours: it is a
                // driver-level toggle the engine hot-applies, and its whole purpose is to be
                // flipped on a live machine to isolate a suspected conflict with third-party
                // security software — which sending the operator to "Edit JSON" would undermine.
                let auth_on = draft.redirect_auth;
                root = root
                    .child(profile_summary(draft, profile))
                    .child(labeled(
                        t!("form.redirect_auth"),
                        chip(
                            "redirect-auth".into(),
                            if auth_on {
                                SharedString::from(t!("badge.on"))
                            } else {
                                SharedString::from(t!("badge.off"))
                            },
                            t!("form.redirect_auth_tip"),
                            auth_on,
                            cx.listener(move |this, _, _, cx| {
                                if let Some(d) = this.draft.as_mut() {
                                    d.redirect_auth = !d.redirect_auth;
                                }
                                cx.notify();
                            }),
                        ),
                    ))
                    .child(dim(t!("config.structural_note").into()));
            }
        }
        root.into_any_element()
    }

    #[allow(clippy::too_many_arguments)] // indices + data + cx for one rule row
    fn render_rule_card(
        &self,
        g: usize,
        r: usize,
        count: usize,
        rule: &Rule,
        proxies: &[String],
        chains: &[String],
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let selected = self.form_sel == Some(FormSel::Rule(g, r));
        let header = div()
            .h_flex()
            .gap_2()
            .items_center()
            .child(
                div()
                    .id(SharedString::from(format!("rule-{g}-{r}")))
                    .flex_grow(1.0)
                    .cursor_pointer()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.select_rule(g, r, window, cx)),
                    )
                    // Position number makes top-to-bottom precedence obvious.
                    .child(
                        div()
                            .min_w(px(22.0))
                            .text_color(rgb(FG_DIM))
                            .child(format!("{}.", r + 1)),
                    )
                    .child(div().text_color(rgb(FG)).child(rule.name.clone()))
                    .child(
                        div()
                            .text_color(rgb(if rule.enabled { GREEN } else { FG_DIM }))
                            .child(if rule.enabled {
                                t!("badge.on")
                            } else {
                                t!("badge.off")
                            }),
                    )
                    .child(
                        div()
                            .text_color(rgb(action_color(rule.action.kind)))
                            .child(summarize_action(&rule.action)),
                    ),
            )
            .child(icon_btn(
                format!("up-{g}-{r}").into(),
                "↑",
                r > 0,
                cx.listener(move |this, _, _, cx| this.move_rule(g, r, true, cx)),
            ))
            .child(icon_btn(
                format!("dn-{g}-{r}").into(),
                "↓",
                r + 1 < count,
                cx.listener(move |this, _, _, cx| this.move_rule(g, r, false, cx)),
            ))
            .child(icon_btn(
                format!("clone-{g}-{r}").into(),
                "⧉",
                true,
                cx.listener(move |this, _, window, cx| this.clone_rule(g, r, window, cx)),
            ))
            .child(icon_btn(
                format!("del-{g}-{r}").into(),
                "✕",
                true,
                cx.listener(move |this, _, _, cx| this.delete_rule(g, r, cx)),
            ));

        let body = if selected {
            self.render_rule_detail(g, r, rule, proxies, chains, cx)
        } else {
            dim(t!(
                "rule.match_summary",
                summary = summarize_predicate(&rule.match_)
            )
            .to_string())
            .into_any_element()
        };
        card().gap_2().child(header).child(body).into_any_element()
    }

    fn render_rule_detail(
        &self,
        g: usize,
        r: usize,
        rule: &Rule,
        proxies: &[String],
        chains: &[String],
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let kind = rule.action.kind;
        let target = rule.action.target.clone();
        let on_failure = rule.action.on_failure;

        // A form-representable match (apps + dest domains/IPs/ports/protocol) gets full
        // fields; anything richer (nested any/not, net/time) keeps the JSON fallback.
        let match_row: AnyElement = if extract_rule_fields(&rule.match_).is_some() {
            div()
                .v_flex()
                .gap_1()
                .child(labeled_tip(
                    "apps",
                    t!("form.apps"),
                    "Process-name patterns, e.g. chrome.exe, *update*. Comma separated (spaces are kept — a name like 'Adobe Desktop Service.exe' is one item); matched case-insensitively.",
                    Input::new(&self.form.apps),
                ))
                .child(labeled_tip(
                    "hosts",
                    t!("form.hosts"),
                    "Destination host/domain patterns, e.g. *.example.com. Prefix ! to negate. Comma separated.",
                    Input::new(&self.form.domains),
                ))
                .child(labeled_tip(
                    "ips",
                    t!("form.ips"),
                    "Destination IPs or CIDR ranges, e.g. 10.0.0.0/8, 1.2.3.4. Comma separated.",
                    Input::new(&self.form.ips),
                ))
                .child(labeled_tip(
                    "ports",
                    t!("form.ports"),
                    "Destination ports or ranges, e.g. 443, 8000-8100. Comma separated.",
                    Input::new(&self.form.ports),
                ))
                .child(labeled(
                    t!("form.protocol"),
                    div()
                        .h_flex()
                        .gap_1()
                        .child(chip(
                            format!("ptcp-{g}-{r}").into(),
                            "TCP",
                            "Match TCP connections. Leave both off to match any protocol.",
                            self.form.tcp,
                            cx.listener(move |this, _, _, cx| {
                                this.form.tcp = !this.form.tcp;
                                cx.notify();
                            }),
                        ))
                        .child(chip(
                            format!("pudp-{g}-{r}").into(),
                            "UDP",
                            "Match UDP flows (includes QUIC / HTTP3). Leave both off to match any.",
                            self.form.udp,
                            cx.listener(move |this, _, _, cx| {
                                this.form.udp = !this.form.udp;
                                cx.notify();
                            }),
                        )),
                ))
                // Advanced match foldout — app path/parent/signer, IP family, time window.
                .child(
                    div()
                        .id(SharedString::from(format!("adv-{g}-{r}")))
                        .cursor_pointer()
                        .pt_1()
                        .text_color(rgb(FG_DIM))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.form.adv_open = !this.form.adv_open;
                            cx.notify();
                        }))
                        .child(if self.form.adv_open {
                            SharedString::from(format!("▾ {}", t!("form.advanced_match")))
                        } else {
                            SharedString::from(format!("▸ {}", t!("form.advanced_match")))
                        }),
                )
                .children(self.form.adv_open.then(|| {
                    div()
                        .v_flex()
                        .gap_1()
                        .pl_2()
                        .child(labeled_tip(
                            "app-path",
                            "app path",
                            "Full executable-path patterns, e.g. C:\\Program Files\\**. Comma separated (spaces are kept — put each path on its own comma-separated item).",
                            Input::new(&self.form.app_paths),
                        ))
                        .child(labeled_tip(
                            "parent",
                            "parent",
                            "Parent-process name patterns. Comma separated (spaces are kept). Not matched yet.",
                            Input::new(&self.form.app_parent),
                        ))
                        .child(labeled_tip(
                            "signed-by",
                            "signed by",
                            "Code-signing subject pattern, e.g. CN=Corp (not matched yet).",
                            Input::new(&self.form.signed_by),
                        ))
                        .child(labeled(
                            t!("form.ip_family"),
                            div()
                                .h_flex()
                                .gap_1()
                                .child(chip(
                                    format!("fv4-{g}-{r}").into(),
                                    "IPv4",
                                    "Match IPv4 destinations. Leave both off to match either family.",
                                    self.form.v4,
                                    cx.listener(|this, _, _, cx| {
                                        this.form.v4 = !this.form.v4;
                                        cx.notify();
                                    }),
                                ))
                                .child(chip(
                                    format!("fv6-{g}-{r}").into(),
                                    "IPv6",
                                    "Match IPv6 destinations. Leave both off to match either family.",
                                    self.form.v6,
                                    cx.listener(|this, _, _, cx| {
                                        this.form.v6 = !this.form.v6;
                                        cx.notify();
                                    }),
                                )),
                        ))
                        .child(labeled_tip(
                            "days",
                            "days",
                            "Days the rule applies, e.g. Mon-Fri, Sat. Comma separated.",
                            Input::new(&self.form.days),
                        ))
                        .child(labeled_tip(
                            "hours",
                            "hours",
                            "Hours the rule applies, e.g. 09:00-18:00. Comma separated.",
                            Input::new(&self.form.hours),
                        ))
                }))
                .into_any_element()
        } else {
            // Boolean (any/not) or otherwise non-form-representable matches: a clear JSON-only
            // badge + a summary, so it's obvious the form can't edit this one.
            labeled(
                t!("form.match"),
                div()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .child(
                        div()
                            .flex_none()
                            .px_1()
                            .rounded_sm()
                            .bg(rgb(BG_BAR))
                            .text_color(rgb(YELLOW))
                            .child(t!("badge.json_only")),
                    )
                    .child(dim(format!(
                        "{} — edit in the JSON editor",
                        summarize_predicate(&rule.match_)
                    ))),
            )
            .into_any_element()
        };

        let type_chips = labeled(
            t!("form.action"),
            div()
                .h_flex()
                .gap_1()
                .child(action_chip(g, r, "proxy", ActionType::Proxy, kind, cx))
                .child(action_chip(g, r, "chain", ActionType::Chain, kind, cx))
                .child(action_chip(g, r, "direct", ActionType::Direct, kind, cx))
                .child(action_chip(g, r, "block", ActionType::Block, kind, cx)),
        );

        let targets = matches!(kind, ActionType::Proxy | ActionType::Chain).then(|| {
            let proxy_kind = kind == ActionType::Proxy;
            let (names, what, section) = if proxy_kind {
                (proxies, "proxy", ConfigSection::Proxies)
            } else {
                (chains, "chain", ConfigSection::Chains)
            };
            // No target to pick: guide the user to add one rather than leaving an empty
            // (invalid) target that only surfaces as a save-time error.
            if names.is_empty() {
                return labeled(
                    t!("form.target"),
                    div()
                        .h_flex()
                        .gap_2()
                        .items_center()
                        .child(
                            div()
                                .text_color(rgb(YELLOW))
                                .child(t!("rule.no_target", what = what)),
                        )
                        .child(
                            Button::new(SharedString::from(format!("addtgt-{g}-{r}")))
                                .label(t!("rule.add_target", what = what))
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.config_section = section;
                                    if proxy_kind {
                                        this.add_proxy(window, cx);
                                    } else {
                                        this.add_chain(window, cx);
                                    }
                                })),
                        ),
                )
                .into_any_element();
            }
            let mut row = div().h_flex().gap_1();
            for name in names {
                let n = name.clone();
                let active = target.as_deref() == Some(name.as_str());
                row = row.child(chip(
                    format!("tg-{g}-{r}-{name}").into(),
                    name,
                    t!("chip.rule_target.tip"),
                    active,
                    cx.listener(move |this, _, _, cx| {
                        let n = n.clone();
                        this.with_rule_mut(g, r, |ru| ru.action.target = Some(n));
                        cx.notify();
                    }),
                ));
            }
            labeled(t!("form.target"), row).into_any_element()
        });

        let onfail = matches!(kind, ActionType::Proxy | ActionType::Chain).then(|| {
            labeled(
                t!("form.on_failure"),
                div()
                    .h_flex()
                    .gap_1()
                    .child(fail_chip(g, r, "block", OnFailure::Block, on_failure, cx))
                    .child(fail_chip(g, r, "direct", OnFailure::Direct, on_failure, cx))
                    .child(fail_chip(g, r, "next", OnFailure::Next, on_failure, cx)),
            )
            .into_any_element()
        });

        let enabled = rule.enabled;
        div()
            .v_flex()
            .gap_1()
            .pt_1()
            .child(labeled(t!("form.name"), Input::new(&self.form.name)))
            .child(match_row)
            .child(type_chips)
            .children(targets)
            .children(onfail)
            .child(
                div()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .child(div().w(px(64.0)).flex_none())
                    .child(chip(
                        format!("en-{g}-{r}").into(),
                        if enabled {
                            t!("badge.enabled")
                        } else {
                            t!("badge.disabled")
                        },
                        t!("chip.rule_enabled.tip"),
                        enabled,
                        cx.listener(move |this, _, _, cx| {
                            this.with_rule_mut(g, r, |ru| ru.enabled = !ru.enabled);
                            cx.notify();
                        }),
                    )),
            )
            .into_any_element()
    }

    fn render_proxy_card(
        &self,
        i: usize,
        px: &ProxyDef,
        show_health: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let selected = self.form_sel == Some(FormSel::Proxy(i));
        let endpoint = if px.endpoint.is_empty() {
            "(no endpoint)".to_string()
        } else {
            px.endpoint.clone()
        };
        let header = div()
            .h_flex()
            .gap_2()
            .items_center()
            .child(
                div()
                    .id(SharedString::from(format!("px-{i}")))
                    .flex_grow(1.0)
                    .cursor_pointer()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.select_proxy(i, window, cx)),
                    )
                    .child(div().text_color(rgb(GREEN)).child(px.name.clone()))
                    .child(dim(format!("{:?} @ {endpoint}", px.kind)))
                    .children(
                        self.proxy_health_for(&px.name, show_health)
                            .map(health_badge),
                    ),
            )
            .child(icon_btn(
                format!("pxdel-{i}").into(),
                "✕",
                true,
                cx.listener(move |this, _, _, cx| this.delete_proxy(i, cx)),
            ));
        card()
            .gap_2()
            .child(header)
            .children(selected.then(|| self.render_proxy_detail(i, px, cx)))
            .into_any_element()
    }

    fn render_proxy_detail(&self, i: usize, px: &ProxyDef, cx: &mut Context<Self>) -> AnyElement {
        let kind = px.kind;
        let kind_chips = labeled(
            "kind",
            div()
                .h_flex()
                .gap_1()
                .child(kind_chip(i, "SOCKS5", ProxyKind::Socks5, kind, cx))
                .child(kind_chip(i, "SOCKS5 TLS", ProxyKind::Socks5Tls, kind, cx))
                .child(kind_chip(i, "SOCKS4", ProxyKind::Socks4, kind, cx))
                .child(kind_chip(i, "SOCKS4a", ProxyKind::Socks4a, kind, cx))
                .child(kind_chip(i, "HTTP", ProxyKind::Http, kind, cx))
                .child(kind_chip(i, "HTTPS", ProxyKind::Https, kind, cx)),
        );
        // TLS kinds (https / socks5Tls) get a cert-verification toggle. skipVerify
        // is insecure (accepts any proxy cert) — for testing a self-signed proxy.
        let skip = px.skip_verify;
        let tls_row = kind.is_tls().then(|| {
            labeled(
                t!("form.tls_cert"),
                chip(
                    format!("skipverify-{i}").into(),
                    if skip {
                        SharedString::from(t!("form.skip_cert"))
                    } else {
                        SharedString::from(t!("form.verify_cert"))
                    },
                    t!("form.skip_cert_tip"),
                    skip,
                    cx.listener(move |this, _, _, cx| {
                        this.with_proxy_mut(i, |px| px.skip_verify = !px.skip_verify);
                        cx.notify();
                    }),
                ),
            )
        });
        let host_port = labeled(
            "host : port",
            div()
                .h_flex()
                .gap_1()
                .child(div().flex_grow(1.0).child(Input::new(&self.form.endpoint)))
                .child(div().w(gpui::px(90.0)).child(Input::new(&self.form.pport))),
        );

        // Make the transport support explicit before traffic fails validation: every kind
        // carries TCP; only SOCKS5 / SOCKS5 TLS also carry UDP (QUIC).
        let carries = labeled(
            t!("form.carries"),
            if kind.supports_udp() {
                div()
                    .text_color(rgb(GREEN))
                    .child(t!("form.carries_tcp_udp"))
            } else {
                div()
                    .text_color(rgb(YELLOW))
                    .child(t!("form.carries_tcp_only"))
            },
        );

        // SOCKS5 UDP behind NAT: ignore the internal BND.ADDR from UDP ASSOCIATE and relay via
        // the proxy's own host instead (SOCKS5 / SOCKS5-TLS only).
        let udp_nat = px.udp_use_proxy_host;
        let udp_nat_row = kind.supports_udp().then(|| {
            labeled(
                "udp relay",
                chip(
                    format!("udpnat-{i}").into(),
                    if udp_nat {
                        "use proxy host (behind NAT)"
                    } else {
                        "use server bind address"
                    },
                    "For SOCKS5 UDP: ignore the (possibly internal) BND.ADDR the proxy returns \
                         and relay datagrams to the proxy's own host:port instead. Use when the \
                         proxy is behind NAT.",
                    udp_nat,
                    cx.listener(move |this, _, _, cx| {
                        this.with_proxy_mut(i, |px| px.udp_use_proxy_host = !px.udp_use_proxy_host);
                        cx.notify();
                    }),
                ),
            )
        });

        // Auth scheme chips — only the schemes valid for this proxy kind, so setup is guided
        // and a SOCKS proxy can't be saved with an HTTP-only scheme. username/password show
        // only for schemes that use them.
        let mut auth_row = div().h_flex().gap_1();
        for &a in AuthKind::allowed_for(kind) {
            auth_row = auth_row.child(chip(
                format!("auth-{i}-{}", a.label()).into(),
                a.label(),
                a.tip(),
                self.form.auth == a,
                cx.listener(move |this, _, _, cx| {
                    this.form.auth = a;
                    // A scheme without credentials hides the password field + Cancel button, so
                    // end any in-progress password change here too (else pass_changing lingers with
                    // no way to cancel and a spurious dirty flag), mirroring kind_chip's reclamp.
                    if !a.needs_creds() {
                        this.pass_changing = false;
                    }
                    // Flush so the auth change reaches the draft immediately and the "unsaved" badge
                    // is accurate (chips don't flush via the input subscriptions) — same as kind_chip.
                    this.flush(cx);
                    cx.notify();
                }),
            ));
        }
        // SOCKS4/4a carry only a USERID — the password is ignored by the protocol.
        let socks4_note = (matches!(kind, ProxyKind::Socks4 | ProxyKind::Socks4a)
            && self.form.auth == AuthKind::UserPass)
            .then(|| {
                labeled(
                    "",
                    dim("SOCKS4 sends the username only — the password is ignored".into()),
                )
            });
        let has_pass = !password_of(&px.auth).is_empty();
        let creds = self.form.auth.needs_creds().then(|| {
            // Keep the stored secret out of the input: show "set" + a Change button until
            // the user opts in to entering a new password.
            let pass_field: AnyElement = if self.pass_changing {
                // The typed value stays out of the draft, so Cancel just drops it — no
                // revert needed. Navigating away / re-selecting drops it the same way.
                labeled(
                    t!("form.new_password"),
                    div()
                        .h_flex()
                        .gap_2()
                        .items_center()
                        .child(Input::new(&self.form.pass).mask_toggle())
                        .child(
                            Button::new(SharedString::from(format!("cancelpass-{i}")))
                                .label(t!("button.cancel"))
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.cancel_pass_change(window, cx)
                                })),
                        ),
                )
                .into_any_element()
            } else {
                labeled(
                    t!("form.password"),
                    div()
                        .h_flex()
                        .gap_2()
                        .items_center()
                        .child(div().text_color(rgb(FG_DIM)).child(if has_pass {
                            "••••• (set)"
                        } else {
                            "(none)"
                        }))
                        .child(
                            Button::new(SharedString::from(format!("changepass-{i}")))
                                .label(t!("button.change"))
                                .on_click(cx.listener(|this, _, window, cx| {
                                    // Always start from an empty field, never a value left
                                    // in the widget by a prior (already-saved) edit.
                                    this.form
                                        .pass
                                        .update(cx, |s, cx| s.set_value("", window, cx));
                                    this.pass_changing = true;
                                    cx.notify();
                                })),
                        ),
                )
                .into_any_element()
            };
            div()
                .v_flex()
                .gap_1()
                .child(labeled(t!("form.username"), Input::new(&self.form.user)))
                .child(pass_field)
        });

        let dns = px.dns;
        let dns_chips = labeled(
            t!("form.dns"),
            div()
                .h_flex()
                .gap_1()
                .child(dns_chip(i, "remote", ProxyDnsResolution::Remote, dns, cx))
                .child(dns_chip(i, "local", ProxyDnsResolution::Local, dns, cx)),
        );
        // Per-proxy DNS is modeled but not honored yet (the profile's dns.mode governs).
        let dns_note = (dns == ProxyDnsResolution::Local).then(|| {
            labeled(
                "",
                div().text_color(rgb(YELLOW)).child(
                    "'local' isn't enforced yet — the profile's DNS mode governs name resolution",
                ),
            )
        });

        // Health check: enable + (when on) the probe target and interval. Drives the background
        // monitor → latency mode, failover/roundRobin skip, and the up/down + RTT badges.
        let hc_enabled = self.form.hc_enabled;
        let hc_toggle = labeled(
            "health check",
            chip(
                format!("hc-en-{i}").into(),
                if hc_enabled { t!("badge.enabled") } else { t!("badge.off") },
                "Periodically probe this proxy (connect THROUGH it to the target) so chains can \
                     prefer healthy / lowest-RTT members and the proxy shows an up/down + RTT badge.",
                hc_enabled,
                cx.listener(move |this, _, _, cx| {
                    this.form.hc_enabled = !this.form.hc_enabled;
                    // Persist the toggle into the draft now (build/clear health_check from the
                    // current inputs), so the unsaved state reflects it immediately.
                    this.flush(cx);
                    cx.notify();
                }),
            ),
        );
        let hc_fields =
            hc_enabled.then(|| {
                div()
                .v_flex()
                .gap_1()
                .child(labeled(t!("form.hc_target"), Input::new(&self.form.hc_target)))
                .child(labeled(t!("form.hc_interval"), Input::new(&self.form.hc_interval)))
                .child(labeled(
                    "",
                    dim(
                        "target is an ip:port reached THROUGH the proxy (e.g. 1.1.1.1:443, or a \
                         bracketed [2606:4700:4700::1111]:443 for IPv6); SOCKS4/4a can't use an \
                         IPv6 target. Interval defaults to 30s."
                            .into(),
                    ),
                ))
            });

        // Reachability check (TCP connect to host:port) with its last result.
        let check_row = div()
            .h_flex()
            .gap_2()
            .items_center()
            .child(
                Button::new(SharedString::from(format!("check-{i}")))
                    .label(t!("button.check"))
                    .on_click(cx.listener(|this, _, _, cx| this.check_proxy(cx))),
            )
            .children(
                self.proxy_check
                    .as_ref()
                    .map(|s| div().text_color(rgb(status_color(s))).child(s.clone())),
            );

        div()
            .v_flex()
            .gap_1()
            .pt_1()
            .child(labeled(t!("form.name"), Input::new(&self.form.name)))
            .child(host_port)
            .child(kind_chips)
            .child(carries)
            .children(udp_nat_row)
            .child(labeled(t!("form.auth"), auth_row))
            .children(socks4_note)
            .children(creds)
            .child(dns_chips)
            .children(dns_note)
            .child(hc_toggle)
            .children(hc_fields)
            .children(tls_row)
            .child(check_row)
            .into_any_element()
    }

    fn render_chain_card(
        &self,
        i: usize,
        ch: &ProxyChain,
        proxies: &[ProxyDef],
        show_health: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let selected = self.form_sel == Some(FormSel::Chain(i));
        let hops = chain_hops_summary(&ch.hops, proxies);
        let header = div()
            .h_flex()
            .gap_2()
            .items_center()
            .child(
                div()
                    .id(SharedString::from(format!("ch-{i}")))
                    .flex_grow(1.0)
                    .cursor_pointer()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .on_click(
                        cx.listener(move |this, _, window, cx| this.select_chain(i, window, cx)),
                    )
                    .child(div().text_color(rgb(GREEN)).child(ch.name.clone()))
                    .child(dim(format!("{:?}: {hops}", ch.mode))),
            )
            .child(icon_btn(
                format!("chdel-{i}").into(),
                "✕",
                true,
                cx.listener(move |this, _, _, cx| this.delete_chain(i, cx)),
            ));
        card()
            .gap_2()
            .child(header)
            .children(selected.then(|| self.render_chain_detail(i, ch, proxies, show_health, cx)))
            .into_any_element()
    }

    fn render_chain_detail(
        &self,
        i: usize,
        ch: &ProxyChain,
        proxies: &[ProxyDef],
        show_health: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mode = ch.mode;
        let mode_chips = labeled(
            t!("form.mode"),
            div()
                .h_flex()
                .gap_1()
                .child(mode_chip(i, "static", ChainMode::Static, mode, cx))
                .child(mode_chip(i, "failover", ChainMode::Failover, mode, cx))
                .child(mode_chip(i, "roundRobin", ChainMode::RoundRobin, mode, cx))
                .child(mode_chip(i, "latency", ChainMode::Latency, mode, cx)),
        );
        // All four modes are enforced. failover / roundRobin / latency use the hops as a pool of
        // alternatives (one proxy per flow, not a chain) — note that so the meaning is clear;
        // latency ranks them by health-check RTT, so it needs a healthCheck on each hop to sort.
        let mode_note: Option<AnyElement> = match mode {
            ChainMode::Static => None,
            ChainMode::Latency => Some(
                labeled(
                    "",
                    dim(
                        "hops are used as alternatives — the lowest-latency hop per flow (those \
                         that a health check reports as down are tried last, not excluded); set a \
                         healthCheck on each hop so latency can rank them"
                            .into(),
                    ),
                )
                .into_any_element(),
            ),
            ChainMode::Failover | ChainMode::RoundRobin => Some(
                labeled(
                    "",
                    dim("hops are used as alternatives — one proxy per flow, not chained".into()),
                )
                .into_any_element(),
            ),
        };
        // DNS placement: where the destination name resolves. firstHop (entry, send IP) /
        // lastHop (exit, default) are enforced; perRule currently behaves as lastHop.
        let dns = ch.dns;
        let dns_chips = labeled(
            t!("form.dns"),
            div()
                .h_flex()
                .gap_1()
                .child(chain_dns_chip(i, "firstHop", ChainDns::FirstHop, dns, cx))
                .child(chain_dns_chip(i, "lastHop", ChainDns::LastHop, dns, cx))
                .child(chain_dns_chip(i, "perRule", ChainDns::PerRule, dns, cx)),
        );
        let dns_note: Option<AnyElement> = match dns {
            ChainDns::LastHop => None,
            ChainDns::FirstHop => Some(
                labeled(
                    "",
                    dim(
                        "resolved at the chain entry (client-side); the resulting IP must be \
                         reachable from the exit"
                            .into(),
                    ),
                )
                .into_any_element(),
            ),
            ChainDns::PerRule => Some(
                labeled(
                    "",
                    dim("not yet distinct — currently resolves at the exit, like lastHop".into()),
                )
                .into_any_element(),
            ),
        };
        // Hops in traversal order, each with reorder (↑/↓) and remove (✕).
        let hop_count = ch.hops.len();
        let mut hops_row = div().v_flex().gap_1();
        for (h, hop) in ch.hops.iter().enumerate() {
            hops_row = hops_row.child(
                div()
                    .h_flex()
                    .gap_1()
                    .items_center()
                    .child(
                        div()
                            .min_w(gpui::px(28.0))
                            .text_color(rgb(FG_DIM))
                            .child(format!("{}.", h + 1)),
                    )
                    .child(
                        div()
                            .flex_grow(1.0)
                            .h_flex()
                            .gap_2()
                            .items_center()
                            .child(div().text_color(rgb(GREEN)).child(hop.clone()))
                            .child(div().text_color(rgb(FG_DIM)).child(
                                match proxies.iter().find(|p| &p.name == hop) {
                                    Some(p) => format!("({})", p.kind.short_label()),
                                    None => "(?)".to_string(),
                                },
                            ))
                            .children(self.proxy_health_for(hop, show_health).map(health_badge)),
                    )
                    .child(icon_btn(
                        format!("hopup-{i}-{h}").into(),
                        "↑",
                        h > 0,
                        cx.listener(move |this, _, _, cx| this.move_hop(i, h, true, cx)),
                    ))
                    .child(icon_btn(
                        format!("hopdn-{i}-{h}").into(),
                        "↓",
                        h + 1 < hop_count,
                        cx.listener(move |this, _, _, cx| this.move_hop(i, h, false, cx)),
                    ))
                    .child(icon_btn(
                        format!("hopdel-{i}-{h}").into(),
                        "✕",
                        true,
                        cx.listener(move |this, _, _, cx| {
                            this.with_chain_mut(i, |c| {
                                if h < c.hops.len() {
                                    c.hops.remove(h);
                                }
                            });
                            cx.notify();
                        }),
                    )),
            );
        }
        let mut add_row = div().h_flex().gap_1().flex_wrap();
        for px in proxies {
            let name = px.name.clone();
            let n = name.clone();
            add_row = add_row.child(chip(
                format!("addhop-{i}-{name}").into(),
                format!("+ {name} ({})", px.kind.short_label()),
                t!("chip.chain_add_hop.tip"),
                false,
                cx.listener(move |this, _, _, cx| {
                    let n = n.clone();
                    this.with_chain_mut(i, |c| c.hops.push(n));
                    cx.notify();
                }),
            ));
        }
        div()
            .v_flex()
            .gap_1()
            .pt_1()
            .child(labeled(t!("form.name"), Input::new(&self.form.name)))
            .child(mode_chips)
            .children(mode_note)
            .child(dns_chips)
            .children(dns_note)
            .child(labeled(t!("form.hops"), hops_row))
            .child(labeled(t!("form.add_hop"), add_row))
            .into_any_element()
    }

    /// Proxifier-style bottom status bar: connection counts, throughput, engine state.
    fn status_bar(&self) -> impl IntoElement {
        let dot = self.engine_state.dot();
        let engine = match self.engine_state {
            EngineState::Loading => t!("status.connecting").into(),
            EngineState::Running => t!("status.running").into(),
            EngineState::Reconnecting => t!("status.reconnecting").into(),
            // Show the detailed reason ("engine not reachable …") when it's actually down.
            EngineState::Unreachable => self.status.clone(),
        };
        div()
            .w_full()
            .flex_none()
            .h_flex()
            .items_center()
            .justify_between()
            .px_3()
            .py_1()
            .border_t_1()
            .border_color(rgb(BG_BAR))
            .bg(rgb(BG_BAR))
            .text_color(rgb(FG_DIM))
            .child(
                div()
                    .h_flex()
                    .gap_4()
                    .items_center()
                    // Active profile · redirect mode · DNS mode of the *running* engine —
                    // "is it routing as expected" — not pending, restart-required changes.
                    // Bounded + ellipsized with a tooltip so a long profile name can't crowd
                    // the rest of the bar on a narrow window.
                    .children(self.running_config.as_ref().and_then(|cfg| {
                        // The profile the engine is ACTUALLY running (its effective profile, from the
                        // status poll) — NOT cfg.active_profile, which differs under a --profile
                        // override. Fall back to active_profile before the first poll / on an older
                        // engine that doesn't report it.
                        let running = self
                            .running_profile_name
                            .as_deref()
                            .unwrap_or(cfg.active_profile.as_str());
                        cfg.profiles
                            .iter()
                            .find(|p| p.name.as_str() == running)
                            .map(|p| {
                                let full = format!(
                                    "{} · {:?} · DNS {:?}",
                                    running, cfg.redirect_mode, p.dns.mode
                                );
                                let tip = full.clone();
                                div()
                                    .id("status-profile")
                                    .max_w(gpui::px(320.0))
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .whitespace_nowrap()
                                    .text_color(rgb(FG))
                                    .child(full)
                                    .tooltip(move |w, cx| Tooltip::new(tip.clone()).build(w, cx))
                            })
                    }))
                    // Saved-but-not-live: we don't have the running config's modes (only its profile,
                    // from the status poll), so instead of the modes show that a restart is pending.
                    .children(
                        (self.running_config.is_none() && self.restart.needed).then(|| {
                            let running = self.running_profile_name.as_deref();
                            div().text_color(rgb(YELLOW)).child(match running {
                                Some(p) => format!("{p} · {}", t!("status.pending_restart")),
                                None => t!("status.pending_restart").into(),
                            })
                        }),
                    )
                    .child({
                        let shown = if self.traffic.shown == self.metrics.total {
                            t!("status.shown", count = self.metrics.total)
                        } else {
                            t!(
                                "status.shown_of",
                                shown = self.traffic.shown,
                                total = self.metrics.total
                            )
                        };
                        let paused = if self.traffic.paused {
                            t!("status.paused_suffix")
                        } else {
                            std::borrow::Cow::Borrowed("")
                        };
                        t!(
                            "status.active_line",
                            active = self.metrics.active,
                            shown = shown,
                            paused = paused
                        )
                        .to_string()
                    })
                    .child(format!(
                        "↓ {}/s   ↑ {}/s",
                        fmt_bytes(self.metrics.rate_recv),
                        fmt_bytes(self.metrics.rate_sent)
                    )),
            )
            .child(
                div()
                    .h_flex()
                    .gap_3()
                    .items_center()
                    // The kill-switch is armed but its heartbeat is missing — direct/host egress is
                    // being blocked by the WFP floor. More severe than a pending restart, so red.
                    .children(self.killswitch_degraded.then(|| {
                        div()
                            .text_color(rgb(RED))
                            .child(t!("status.killswitch_degraded"))
                    }))
                    // A saved structural change waiting for a restart.
                    .children(self.restart.needed.then(|| {
                        div()
                            .text_color(rgb(YELLOW))
                            .child(t!("status.restart_needed"))
                    }))
                    // Driver version (high 16 bits = major, low 16 = minor).
                    .children(self.driver_version.map(|v| {
                        div().child(
                            t!(
                                "status.driver_version",
                                major = (v >> 16),
                                minor = (v & 0xFFFF)
                            )
                            .to_string(),
                        )
                    }))
                    .child(
                        div()
                            .h_flex()
                            .gap_2()
                            .items_center()
                            .child(div().text_color(rgb(dot)).child("●"))
                            .child(t!("status.engine", state = engine)),
                    ),
            )
    }
}

// =================== Config rendering (read-only) ==========================

/// The rule at `(group, rule)` indices in the named profile, if any.
fn rule_at<'a>(cfg: &'a Config, profile: &str, g: usize, r: usize) -> Option<&'a Rule> {
    let p = cfg.profiles.iter().find(|p| p.name == profile)?;
    p.rule_groups.get(g)?.rules.get(r)
}

fn proxy_at<'a>(cfg: &'a Config, profile: &str, i: usize) -> Option<&'a ProxyDef> {
    cfg.profiles
        .iter()
        .find(|p| p.name == profile)?
        .proxies
        .get(i)
}

fn chain_at<'a>(cfg: &'a Config, profile: &str, i: usize) -> Option<&'a ProxyChain> {
    cfg.profiles
        .iter()
        .find(|p| p.name == profile)?
        .chains
        .get(i)
}

/// A proxy-kind chip that sets `proxy.kind`.
fn kind_chip(
    i: usize,
    label: &str,
    kind: ProxyKind,
    current: ProxyKind,
    cx: &mut Context<AppView>,
) -> AnyElement {
    chip(
        format!("pk-{i}-{label}").into(),
        label,
        proxy_kind_tip(kind),
        current == kind,
        cx.listener(move |this, _, _, cx| {
            this.with_proxy_mut(i, |px| px.kind = kind);
            // Reclamp the selected auth scheme to one valid for the new kind. The auth chip row
            // renders only `allowed_for(kind)`, so an out-of-set scheme (e.g. Basic left over from
            // an HTTP proxy after switching to SOCKS5) would be INVISIBLE in the form yet still
            // committed on save via flush and then rejected by validation — an error the user can't
            // map to any control on screen. Reset it to None (valid for every kind) and drop any
            // pending password entry, mirroring how the auth chips assign `form.auth`.
            if !AuthKind::allowed_for(kind).contains(&this.form.auth) {
                this.form.auth = AuthKind::None;
                this.pass_changing = false;
            }
            // Flush the form into the draft NOW so dirty tracking sees the auth reclamp
            // immediately. Without this, switching the kind back to the original would leave the
            // draft equal to the saved config (no "unsaved" badge) while form.auth stays reset —
            // and a later save would then silently commit auth=None.
            this.flush(cx);
            cx.notify();
        }),
    )
    .into_any_element()
}

/// One-line explanation of each proxy kind (shown as a tooltip on the kind chips).
fn proxy_kind_tip(kind: ProxyKind) -> SharedString {
    match kind {
        ProxyKind::Socks5 => t!("proxy.kind.socks5"),
        ProxyKind::Socks5Tls => t!("proxy.kind.socks5_tls"),
        ProxyKind::Socks4 => t!("proxy.kind.socks4"),
        ProxyKind::Socks4a => t!("proxy.kind.socks4a"),
        ProxyKind::Http => t!("proxy.kind.http"),
        ProxyKind::Https => t!("proxy.kind.https"),
    }
    .into()
}

/// A proxy DNS-resolution chip that sets `proxy.dns` (remote / local).
fn dns_chip(
    i: usize,
    label: &str,
    dns: ProxyDnsResolution,
    current: ProxyDnsResolution,
    cx: &mut Context<AppView>,
) -> AnyElement {
    chip(
        format!("dns-{i}-{label}").into(),
        label,
        dns_resolution_tip(dns),
        current == dns,
        cx.listener(move |this, _, _, cx| {
            this.with_proxy_mut(i, |px| px.dns = dns);
            cx.notify();
        }),
    )
    .into_any_element()
}

/// One-line explanation of each per-proxy DNS-resolution mode (tooltip on the dns chips).
fn dns_resolution_tip(dns: ProxyDnsResolution) -> SharedString {
    match dns {
        ProxyDnsResolution::Remote => t!("proxy.dns.remote"),
        ProxyDnsResolution::Local => t!("proxy.dns.local"),
    }
    .into()
}

/// A chain-mode chip that sets `chain.mode`.
fn mode_chip(
    i: usize,
    label: &str,
    mode: ChainMode,
    current: ChainMode,
    cx: &mut Context<AppView>,
) -> AnyElement {
    chip(
        format!("cm-{i}-{label}").into(),
        label,
        chain_mode_tip(mode),
        current == mode,
        cx.listener(move |this, _, _, cx| {
            this.with_chain_mut(i, |c| c.mode = mode);
            cx.notify();
        }),
    )
    .into_any_element()
}

/// A chain DNS-placement chip — highlighted when it's the chain's current `dns`. Parallels
/// [`mode_chip`]. (Distinct from [`dns_chip`], which sets a *proxy's* remote/local resolution.)
fn chain_dns_chip(
    i: usize,
    label: &str,
    dns: ChainDns,
    current: ChainDns,
    cx: &mut Context<AppView>,
) -> AnyElement {
    chip(
        format!("cdns-{i}-{label}").into(),
        label,
        chain_dns_tip(dns),
        current == dns,
        cx.listener(move |this, _, _, cx| {
            this.with_chain_mut(i, |c| c.dns = dns);
            cx.notify();
        }),
    )
    .into_any_element()
}

/// One-line explanation of each chain DNS-placement option (tooltip). `firstHop` / `lastHop` are
/// enforced; `perRule` currently behaves as `lastHop`.
fn chain_dns_tip(dns: ChainDns) -> SharedString {
    match dns {
        ChainDns::FirstHop => t!("chain.dns.first_hop"),
        ChainDns::LastHop => t!("chain.dns.last_hop"),
        ChainDns::PerRule => t!("chain.dns.per_rule"),
    }
    .into()
}

/// One-line explanation of each chain mode (shown as a tooltip). All four are enforced; `latency`
/// ranks hops by health-check RTT, so it needs a `healthCheck` on each hop to sort them.
fn chain_mode_tip(mode: ChainMode) -> SharedString {
    match mode {
        ChainMode::Static => t!("chain.mode.static"),
        ChainMode::Failover => t!("chain.mode.failover"),
        ChainMode::RoundRobin => t!("chain.mode.round_robin"),
        ChainMode::Latency => t!("chain.mode.latency"),
    }
    .into()
}

/// A small icon button (reorder / delete) — dimmer when `active` is false.
fn icon_btn(
    id: SharedString,
    label: &str,
    active: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let fg = if active { FG_DIM } else { 0x55585a };
    // An accessible label for the symbol-only buttons, shown on hover.
    let title: SharedString = match label {
        "↑" => "Move up",
        "↓" => "Move down",
        "⧉" => "Clone",
        "✕" => "Remove",
        other => other,
    }
    .into();
    div()
        .id(id)
        // Focusable: a tab stop, and gpui fires on_click on Enter/Space when focused.
        .focusable()
        .px_2()
        .py_1()
        .rounded_md()
        // Reserve the ring so focus doesn't shift layout; color it only when focused.
        .border_1()
        .border_color(rgba(0x00000000))
        .bg(rgb(BG_BAR))
        .text_color(rgb(fg))
        .cursor_pointer()
        .hover(|s| s.text_color(rgb(FG)))
        .focus(|s| s.border_color(rgb(FOCUS_RING)))
        .tooltip(move |window, cx| Tooltip::new(title.clone()).build(window, cx))
        .on_click(on_click)
        .child(label.to_string())
}

/// A label + content row for the form detail panel (fixed-width label).
fn labeled(label: impl Into<SharedString>, content: impl IntoElement) -> impl IntoElement {
    div()
        .h_flex()
        .gap_2()
        .items_start()
        .child(
            div()
                .w(px(64.0))
                .flex_none()
                .text_color(rgb(FG_DIM))
                .child(label.into()),
        )
        .child(div().flex_grow(1.0).child(content))
}

/// Like [`labeled`], but the field label carries a hover tooltip explaining the field (and a
/// dashed underline to hint it's hoverable). `id` is a stable, NON-localized key for the stateful
/// tooltip element — the label text changes per locale (and two locales could even translate two
/// different fields to the same word), so it can't double as the identifier.
fn labeled_tip(
    id: &'static str,
    label: impl Into<SharedString>,
    tip: impl Into<SharedString>,
    content: impl IntoElement,
) -> impl IntoElement {
    let label = label.into();
    let tip = tip.into();
    div()
        .h_flex()
        .gap_2()
        .items_start()
        .child(
            div()
                // `.tooltip()` needs a stateful element, so an id is required.
                .id(SharedString::from(format!("lbl-{id}")))
                .w(px(64.0))
                .flex_none()
                .text_color(rgb(FG_DIM))
                // Dashed underline hints the label is hoverable for an explanation.
                .border_b_1()
                .border_dashed()
                .border_color(rgb(FG_DIM))
                .tooltip(move |w, cx| Tooltip::new(tip.clone()).build(w, cx))
                .child(label),
        )
        .child(div().flex_grow(1.0).child(content))
}

fn config_body(
    cfg: &Config,
    profile: &str,
    section: ConfigSection,
    cx: &mut Context<AppView>,
) -> AnyElement {
    let Some(p) = cfg.profiles.iter().find(|p| p.name == profile) else {
        return simple_msg(format!("Profile '{profile}' not found in config."), RED)
            .into_any_element();
    };
    // No per-section heading — the highlighted sub-tab already names the section.
    let mut root = div().v_flex().gap_3();
    match section {
        ConfigSection::Profile => root = root.child(profile_summary(cfg, p)),
        ConfigSection::Proxies => {
            if p.proxies.is_empty() {
                root = root.child(empty_state(
                    "No proxies configured.",
                    "Add a proxy to route matching traffic through it.",
                    ConfigSection::Proxies,
                    cx,
                ));
            }
            for px in &p.proxies {
                root = root.child(proxy_row(px));
            }
        }
        ConfigSection::Chains => {
            if p.chains.is_empty() {
                root = root.child(empty_state(
                    "No chains configured.",
                    "Create a chain to route traffic through several proxies in sequence.",
                    ConfigSection::Chains,
                    cx,
                ));
            }
            for ch in &p.chains {
                let hops = chain_hops_summary(&ch.hops, &p.proxies);
                root = root.child(
                    card().child(
                        div()
                            .h_flex()
                            .gap_2()
                            .child(div().text_color(rgb(GREEN)).child(ch.name.clone()))
                            .child(dim(format!("{:?}: {hops}", ch.mode))),
                    ),
                );
            }
        }
        ConfigSection::Rules => {
            if p.rule_groups.is_empty() {
                root = root.child(empty_state(
                    "No rules configured.",
                    "Add a rule to send matching apps or hosts through a proxy.",
                    ConfigSection::Rules,
                    cx,
                ));
            }
            for g in &p.rule_groups {
                root = root.child(group_card(g));
            }
        }
    }
    root.into_any_element()
}

/// A self-explaining empty state for a config section: a title line, a one-line hint, and a
/// button straight into that section's editor — replaces the bare "(none)".
fn empty_state(
    title: &str,
    hint: &str,
    section: ConfigSection,
    cx: &mut Context<AppView>,
) -> impl IntoElement {
    div()
        .v_flex()
        .gap_2()
        .items_start()
        .py_2()
        .child(div().text_color(rgb(FG)).child(title.to_string()))
        .child(dim(hint.to_string()))
        .child(
            Button::new(SharedString::from(format!(
                "empty-edit-{}",
                section.label()
            )))
            .label(t!("button.edit_section", section = section.display()))
            .on_click(cx.listener(|this, _, _, cx| this.enter_form(cx))),
        )
}

fn profile_summary(cfg: &Config, p: &Profile) -> impl IntoElement {
    card()
        .gap_1()
        .child(
            div()
                .text_color(rgb(FG))
                .child(t!("profile.title", name = p.name)),
        )
        .child(kv(
            &t!("profile.redirect_mode"),
            format!("{:?}", cfg.redirect_mode),
        ))
        .child(kv(&t!("profile.dns"), format!("{:?}", p.dns.mode)))
        .child(kv(&t!("profile.ipv6"), format!("{:?}", p.ipv6)))
        .child(kv(
            &t!("profile.bypass"),
            format!(
                "lan={} loopback={} customCidrs={}",
                p.bypass.lan,
                p.bypass.loopback,
                p.bypass.custom_cidrs.len()
            ),
        ))
}

/// Render a protocol set as uppercase TCP/UDP (Debug gives "Tcp"/"Udp").
fn protocols_label(ps: &[Protocol]) -> String {
    ps.iter()
        .map(|p| match p {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Proxy summary — name, kind, endpoint, protocols. Never renders auth.
fn proxy_row(px: &ProxyDef) -> impl IntoElement {
    card().child(
        div()
            .h_flex()
            .gap_3()
            .items_center()
            .child(div().text_color(rgb(GREEN)).child(px.name.clone()))
            .child(dim(format!("{:?} @ {}", px.kind, px.endpoint)))
            .child(dim(protocols_label(&px.protocols))),
    )
}

/// A group header for the rule *form*: order (group N), name, enabled state, and rule count —
/// so the flat list of editable rule cards keeps its group and precedence context.
fn rule_group_header(g: usize, group: &RuleGroup) -> impl IntoElement {
    div()
        .h_flex()
        .gap_2()
        .items_center()
        .mt_2()
        .pb_1()
        .border_b_1()
        .border_color(rgb(BG_BAR))
        .child(
            div()
                .flex_none()
                .px_1()
                .rounded_sm()
                .bg(rgb(BG_BAR))
                .text_color(rgb(FG_DIM))
                .child(t!("rule.group", n = (g + 1))),
        )
        .child(div().text_color(rgb(FG)).child(group.name.clone()))
        .child(enabled_badge(group.enabled))
        .child(div().flex_grow(1.0))
        .child(
            div()
                .text_color(rgb(FG_DIM))
                .child(t!("rule.count", count = group.rules.len())),
        )
}

fn group_card(g: &RuleGroup) -> impl IntoElement {
    let mut c = card().gap_2().child(
        div()
            .h_flex()
            .gap_2()
            .items_center()
            .child(div().text_color(rgb(FG)).child(g.name.clone()))
            .child(enabled_badge(g.enabled)),
    );
    if g.rules.is_empty() {
        c = c.child(dim("(no rules)".into()));
    }
    for r in &g.rules {
        c = c.child(rule_row(r));
    }
    c
}

fn rule_row(r: &Rule) -> impl IntoElement {
    div()
        .v_flex()
        .gap_1()
        .px_3()
        .py_2()
        .bg(rgb(BG))
        .rounded_md()
        .child(
            div()
                .h_flex()
                .gap_2()
                .items_center()
                .child(div().text_color(rgb(FG)).child(r.name.clone()))
                .child(enabled_badge(r.enabled))
                .child(div().flex_grow(1.0))
                .child(
                    div()
                        .text_color(rgb(action_color(r.action.kind)))
                        .child(summarize_action(&r.action)),
                ),
        )
        .child(dim(t!(
            "rule.match_summary",
            summary = summarize_predicate(&r.match_)
        )
        .to_string()))
}

/// Compact one-line description of a match predicate (recursive).
fn summarize_predicate(p: &Predicate) -> String {
    match p {
        Predicate::All(v) if v.is_empty() => "any traffic".into(),
        Predicate::All(v) => v
            .iter()
            .map(summarize_predicate)
            .collect::<Vec<_>>()
            .join(" AND "),
        Predicate::Any(v) => format!(
            "({})",
            v.iter()
                .map(summarize_predicate)
                .collect::<Vec<_>>()
                .join(" OR ")
        ),
        Predicate::Not(b) => format!("NOT {}", summarize_predicate(b)),
        Predicate::App(a) => {
            let mut parts = Vec::new();
            if !a.names.is_empty() {
                parts.push(format!("app {}", a.names.join("/")));
            }
            if !a.paths.is_empty() {
                parts.push(format!("path {}", a.paths.join("/")));
            }
            if let Some(s) = &a.signed_by {
                parts.push(format!("signedBy {s}"));
            }
            if !a.parent.is_empty() {
                parts.push(format!("parent {}", a.parent.join("/")));
            }
            opt(parts, "app(any)")
        }
        Predicate::Dest(d) => {
            let mut parts = Vec::new();
            if !d.domains.is_empty() {
                parts.push(format!("domains {}", d.domains.join("/")));
            }
            if !d.ips.is_empty() {
                parts.push(format!("ips {}", d.ips.join("/")));
            }
            if !d.ports.is_empty() {
                parts.push(format!("ports {}", d.ports.join("/")));
            }
            if !d.protocol.is_empty() {
                parts.push(format!("proto {}", protocols_label(&d.protocol)));
            }
            opt(parts, "dest(any)")
        }
        Predicate::Net(n) => {
            let mut parts = Vec::new();
            if !n.interfaces.is_empty() {
                parts.push(format!("iface {}", n.interfaces.join("/")));
            }
            if !n.family.is_empty() {
                parts.push(format!("family {:?}", n.family));
            }
            opt(parts, "net(any)")
        }
        Predicate::When(t) => {
            let mut parts = Vec::new();
            if !t.days.is_empty() {
                parts.push(format!("days {}", t.days.join("/")));
            }
            if !t.hours.is_empty() {
                parts.push(format!("hours {}", t.hours.join("/")));
            }
            opt(parts, "when(any)")
        }
    }
}

fn opt(parts: Vec<String>, empty: &str) -> String {
    if parts.is_empty() {
        empty.to_string()
    } else {
        parts.join(" ")
    }
}

fn summarize_action(a: &Action) -> String {
    let base = match a.kind {
        ActionType::Proxy => format!("proxy → {}", a.target.as_deref().unwrap_or("?")),
        ActionType::Chain => format!("chain → {}", a.target.as_deref().unwrap_or("?")),
        ActionType::Direct => "direct".into(),
        ActionType::Block => "block".into(),
    };
    let mut extra = Vec::new();
    if let Some(of) = a.on_failure {
        extra.push(format!("onFailure {of:?}"));
    }
    if let Some(dm) = a.dns_mode {
        extra.push(format!("dns {dm:?}"));
    }
    if extra.is_empty() {
        base
    } else {
        format!("{base} ({})", extra.join(", "))
    }
}

fn action_color(k: ActionType) -> u32 {
    match k {
        ActionType::Proxy | ActionType::Chain => GREEN,
        ActionType::Block => RED,
        ActionType::Direct => FG_DIM,
    }
}

// -- small config-view building blocks --
fn card() -> Div {
    div().v_flex().p_3().bg(rgb(BG_ALT)).rounded_md()
}

fn section_title(t: &str) -> impl IntoElement {
    div().text_color(rgb(FG_DIM)).child(t.to_string())
}

/// A form section header: a title plus an `+ Add …` button.
fn section_header(
    title: &str,
    btn: &'static str,
    label: &str,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .h_flex()
        .gap_2()
        .items_center()
        .child(section_title(title))
        .child(Button::new(btn).label(label.to_string()).on_click(on_click))
}

fn kv(k: &str, v: String) -> impl IntoElement {
    div()
        .h_flex()
        .gap_2()
        .child(
            div()
                .w(px(110.0))
                .flex_none()
                .text_color(rgb(FG_DIM))
                .child(k.to_string()),
        )
        .child(div().text_color(rgb(FG)).child(v))
}

fn dim(t: String) -> impl IntoElement {
    div().text_color(rgb(FG_DIM)).child(t)
}

/// A compact per-proxy health badge from the latest Status poll: a green ● with the last RTT when
/// up, a red ● down when the monitor reports it down. Shown only for proxies with a probed
/// `healthCheck` (callers pass `None` otherwise, so nothing renders).
fn health_badge(h: &proxroute_ipc::ProxyHealth) -> impl IntoElement {
    let (color, text) = match (h.healthy, h.rtt_ms) {
        (true, Some(ms)) => (GREEN, format!("● {ms} ms")),
        (true, None) => (GREEN, "● up".to_string()),
        (false, _) => (RED, "● down".to_string()),
    };
    div().text_color(rgb(color)).child(text)
}

/// A clickable form chip — highlighted (green) when it's the selected value. A hover tooltip
/// explaining the setting is REQUIRED (not optional): every chip must be self-describing, both for
/// discoverability and for screen-reader users. There is deliberately no tooltip-less variant.
fn chip(
    id: SharedString,
    label: impl Into<SharedString>,
    tip: impl Into<SharedString>,
    active: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let (bg, fg) = if active {
        (GREEN, BG)
    } else {
        (BG_BAR, FG_DIM)
    };
    let label = label.into();
    let tip = tip.into();
    div()
        .id(id)
        // Focusable: a tab stop, and gpui fires on_click on Enter/Space when focused.
        .focusable()
        .px_2()
        .py_1()
        .rounded_md()
        // Reserve the ring so focus doesn't shift layout; color it only when focused.
        .border_1()
        .border_color(rgba(0x00000000))
        .bg(rgb(bg))
        .text_color(rgb(fg))
        .cursor_pointer()
        .hover(|s| s.text_color(rgb(FG)))
        .focus(|s| s.border_color(rgb(FOCUS_RING)))
        .on_click(on_click)
        .tooltip(move |w, cx| Tooltip::new(tip.clone()).build(w, cx))
        .child(label)
}

/// An action-type chip that sets `rule.action.kind`, clearing the now-invalid target on any
/// kind change (and onFailure only when moving to a terminal direct/block kind) — see
/// [`set_action_kind`].
fn action_chip(
    g: usize,
    r: usize,
    label: &str,
    kind: ActionType,
    current: ActionType,
    cx: &mut Context<AppView>,
) -> AnyElement {
    chip(
        format!("ty-{g}-{r}-{label}").into(),
        label,
        action_tip(kind),
        current == kind,
        cx.listener(move |this, _, _, cx| {
            this.with_rule_mut(g, r, |ru| set_action_kind(&mut ru.action, kind));
            cx.notify();
        }),
    )
    .into_any_element()
}

/// One-line explanation of each rule action (tooltip on the action chips).
fn action_tip(kind: ActionType) -> SharedString {
    match kind {
        ActionType::Proxy => t!("action.proxy"),
        ActionType::Chain => t!("action.chain"),
        ActionType::Direct => t!("action.direct"),
        ActionType::Block => t!("action.block"),
    }
    .into()
}

/// An onFailure chip that sets `rule.action.on_failure`.
fn fail_chip(
    g: usize,
    r: usize,
    label: &str,
    val: OnFailure,
    current: Option<OnFailure>,
    cx: &mut Context<AppView>,
) -> AnyElement {
    chip(
        format!("of-{g}-{r}-{label}").into(),
        label,
        onfailure_tip(val),
        current == Some(val),
        cx.listener(move |this, _, _, cx| {
            this.with_rule_mut(g, r, |ru| ru.action.on_failure = Some(val));
            cx.notify();
        }),
    )
    .into_any_element()
}

/// One-line explanation of each on-failure policy (tooltip on the on-failure chips).
fn onfailure_tip(val: OnFailure) -> SharedString {
    match val {
        OnFailure::Block => t!("on_failure.block"),
        OnFailure::Direct => t!("on_failure.direct"),
        OnFailure::Next => t!("on_failure.next"),
    }
    .into()
}

fn enabled_badge(on: bool) -> impl IntoElement {
    let (t, c) = if on {
        (t!("badge.enabled"), GREEN)
    } else {
        (t!("badge.disabled"), FG_DIM)
    };
    div().text_color(rgb(c)).child(t)
}

fn simple_msg(text: String, color: u32) -> AnyElement {
    div()
        .p_4()
        .text_color(rgb(color))
        .child(text)
        .into_any_element()
}

/// Centered placeholder shown when the connections table has no visible rows: engine
/// unreachable, nothing yet, or the active filter matches none.
fn connections_empty(no_connections: bool, reachable: bool) -> impl IntoElement {
    let msg = if !reachable {
        t!("msg.engine_unreachable")
    } else if no_connections {
        t!("msg.waiting_connections")
    } else {
        t!("msg.no_filter_match")
    };
    div()
        .size_full()
        .h_flex()
        .items_center()
        .justify_center()
        .text_color(rgb(FG_DIM))
        .child(msg)
}

fn tab_btn(
    id: &'static str,
    label: impl Into<SharedString>,
    active: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let (bg, fg) = if active { (BG, FG) } else { (BG_BAR, FG_DIM) };
    let label = label.into();
    div()
        .id(id)
        // Focusable: a tab stop, and gpui fires on_click on Enter/Space when focused.
        .focusable()
        .px_3()
        .py_1()
        // Reserve the ring so focus doesn't shift layout; color it only when focused.
        .border_1()
        .border_color(rgba(0x00000000))
        .cursor_pointer()
        .bg(rgb(bg))
        .text_color(rgb(fg))
        .hover(|s| s.text_color(rgb(FG)))
        .focus(|s| s.border_color(rgb(FOCUS_RING)))
        .on_click(on_click)
        .child(label)
}

// =================== Connection detail panel ===============================

/// Bottom panel with every field of the selected connection (full image path included).
fn detail_panel(r: &ConnectionRow, entity: &Entity<AppView>) -> impl IntoElement {
    let close_ent = entity.clone();
    let explain_ent = entity.clone();
    let rule_ent = entity.clone();
    div()
        .w_full()
        .flex_none()
        .v_flex()
        .gap_1()
        .px_3()
        .py_2()
        .border_t_1()
        .border_color(rgb(BG_BAR))
        .bg(rgb(BG_PANEL))
        .child(
            div()
                .w_full()
                .h_flex()
                .justify_between()
                .items_center()
                .mb_1()
                .child(div().text_color(rgb(FG)).child(t!("detail.title")))
                .child(
                    // Visible row actions (also in the right-click menu). Per-field Copy buttons
                    // live on the detail rows below.
                    div()
                        .h_flex()
                        .gap_2()
                        .child(
                            Button::new("explain-conn")
                                .label(t!("button.explain"))
                                .on_click(move |_, _, app| {
                                    explain_ent.update(app, |this, cx| this.explain(cx));
                                }),
                        )
                        .child(
                            Button::new("create-rule-conn")
                                .label(t!("button.create_rule"))
                                .on_click(move |_, window, app| {
                                    rule_ent.update(app, |this, cx| {
                                        this.traffic.ctx_row = this.traffic.selected.clone();
                                        this.on_create_rule(&CreateRuleFromConn, window, cx);
                                    });
                                }),
                        )
                        .child(
                            Button::new("close-detail")
                                .label(t!("button.close"))
                                .on_click(move |_, _, app| {
                                    close_ent.update(app, |this, cx| {
                                        this.traffic.selected = None;
                                        this.traffic.explanation = None;
                                        cx.notify();
                                    });
                                }),
                        ),
                ),
        )
        .child(copyable_detail_line(
            t!("detail.process"),
            &r.process,
            "copy-process",
            t!("detail.copy_process"),
        ))
        .child(copyable_detail_line(
            t!("detail.path"),
            &full_path_of(r),
            "copy-path",
            t!("detail.copy_path"),
        ))
        .child(detail_line(t!("detail.pid"), &r.pid.to_string()))
        .child(detail_line(t!("detail.protocol"), &r.protocol))
        .child(copyable_detail_line(
            t!("detail.destination"),
            &r.destination,
            "copy-dest",
            t!("detail.copy_destination"),
        ))
        .child(copyable_detail_line(
            t!("detail.host"),
            r.dest_host.as_deref().unwrap_or("—"),
            "copy-host",
            t!("detail.copy_host"),
        ))
        .child(detail_line(t!("detail.decision"), &decision_label(r)))
        .child(detail_line(
            t!("detail.matched_rule"),
            r.matched_rule.as_deref().unwrap_or("—"),
        ))
        .child(detail_line(t!("detail.state"), &r.state))
        .child(detail_line(
            t!("detail.error"),
            r.error.as_deref().unwrap_or("—"),
        ))
        .child(detail_line(
            t!("detail.sent"),
            &format!("{} ({} bytes)", fmt_bytes(r.bytes_sent), r.bytes_sent),
        ))
        .child(detail_line(
            t!("detail.received"),
            &format!("{} ({} bytes)", fmt_bytes(r.bytes_recv), r.bytes_recv),
        ))
}

/// The routing explanation, rendered as a sibling *below* the scrollable detail fields so it's
/// always on screen (see the detail layout). Bounded with its own scroll in case an explanation
/// is unusually long.
fn explanation_block(text: &str) -> impl IntoElement {
    let mut block = div()
        .id("explanation-block")
        .w_full()
        .flex_none()
        .v_flex()
        .gap_1()
        .px_3()
        .py_2()
        .max_h(px(160.0))
        .overflow_y_scroll()
        .border_t_1()
        .border_color(rgb(BG_BAR))
        .bg(rgb(BG_PANEL))
        .child(
            div()
                .text_color(rgb(FG_DIM))
                .child(t!("detail.explanation_title")),
        );
    for line in text.lines() {
        block = block.child(div().text_color(rgb(FG)).child(line.to_string()));
    }
    block
}

fn detail_line(label: impl Into<SharedString>, value: &str) -> impl IntoElement {
    div()
        .w_full()
        .h_flex()
        .gap_2()
        .items_start()
        .child(
            div()
                .w(px(110.0))
                .flex_none()
                .text_color(rgb(FG_DIM))
                .child(label.into()),
        )
        .child(
            div()
                .flex_grow(1.0)
                .text_color(rgb(FG))
                .child(value.to_string()),
        )
}

/// Like [`detail_line`], but the value is followed *immediately* by a small dim copy glyph that
/// brightens on hover and copies the value on click (tooltip "Copy <what>") — so each meaningful
/// field (process, path, destination, host) is copyable right next to its string instead of via a
/// button at the row's edge. No glyph for an empty/placeholder ("—") value. `copy_id` must be
/// unique within the panel.
fn copyable_detail_line(
    label: impl Into<SharedString>,
    value: &str,
    copy_id: &'static str,
    copy_tip: impl Into<SharedString>,
) -> impl IntoElement {
    let copy_tip = copy_tip.into();
    let copy_glyph = (!value.is_empty() && value != "—").then(|| {
        let owned = value.to_string();
        let tip = copy_tip.clone();
        div()
            .id(copy_id)
            .flex_none()
            .text_color(rgb(FG_DIM)) // dim by default, so it doesn't clutter the row
            .cursor_pointer()
            .hover(|s| s.text_color(rgb(FG))) // brighten when hovered
            .child("\u{29c9}") // ⧉ copy glyph
            .tooltip(move |w, cx| Tooltip::new(tip.clone()).build(w, cx))
            .on_click(move |_, _, app| {
                app.write_to_clipboard(ClipboardItem::new_string(owned.clone()));
            })
    });
    div()
        .w_full()
        .h_flex()
        .gap_2()
        .items_start()
        .child(
            div()
                .w(px(110.0))
                .flex_none()
                .text_color(rgb(FG_DIM))
                .child(label.into()),
        )
        .child(
            // Value + its glyph, left-aligned. The value is content-sized (no flex-grow) with
            // min-width 0 so it wraps for a long path, and the glyph sits right after the string
            // rather than being pushed to the row's right edge.
            div()
                .flex_grow(1.0)
                .h_flex()
                .gap_1()
                .items_center()
                .child(
                    div()
                        .min_w(px(0.0))
                        .text_color(rgb(FG))
                        .child(value.to_string()),
                )
                .children(copy_glyph),
        )
}

// =================== Shared row formatting =================================

/// `decision` plus the proxy/chain name when present (mirrors the CLI's column).
fn decision_label(r: &ConnectionRow) -> String {
    match &r.proxy_or_chain {
        Some(target) => format!("{}: {target}", r.decision),
        None => r.decision.clone(),
    }
}

/// Whether a row matches the free-text filter — a case-insensitive substring of any of
/// the process (name + path), destination/host, decision, proxy/chain, matched rule,
/// state, protocol, or error. An empty needle matches everything.
fn row_matches_text(r: &ConnectionRow, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let fields = [
        r.process.as_str(),
        r.process_path.as_str(),
        r.decision.as_str(),
        r.state.as_str(),
        r.protocol.as_str(),
        r.proxy_or_chain.as_deref().unwrap_or(""),
        r.matched_rule.as_deref().unwrap_or(""),
        r.error.as_deref().unwrap_or(""),
    ];
    fields.iter().any(|f| f.to_lowercase().contains(needle))
        || destination(r).to_lowercase().contains(needle)
}

/// Prefer the real hostname over a (possibly synthetic) destination IP.
fn destination(r: &ConnectionRow) -> String {
    match &r.dest_host {
        Some(host) => {
            let port = r.destination.rsplit_once(':').map(|(_, p)| p).unwrap_or("");
            format!("{host}:{port}")
        }
        None => r.destination.clone(),
    }
}

/// Last path component of a process image path — turns a full NT device path
/// (`\device\harddiskvolume3\…\claude.exe`) into just `claude.exe`.
fn process_basename(s: &str) -> String {
    s.rsplit(['\\', '/']).next().unwrap_or(s).to_string()
}

/// Full image path for tooltips / detail, falling back to the basename when the engine
/// supplied no path.
fn full_path_of(r: &ConnectionRow) -> String {
    if r.process_path.is_empty() {
        r.process.clone()
    } else {
        r.process_path.clone()
    }
}

fn decision_color(decision: &str) -> u32 {
    if decision.starts_with("proxy") || decision.starts_with("chain") {
        GREEN
    } else if decision.starts_with("block") {
        RED
    } else {
        FG_DIM // direct
    }
}

fn state_color(state: &str) -> u32 {
    match state {
        "Established" => GREEN,
        "Connecting" | "Cancelled" => YELLOW,
        "Blocked" | "Failed" => RED,
        _ => FG_DIM, // Closed / Pending
    }
}

fn fmt_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let n = n as f64;
    if n < KIB {
        format!("{n:.0}")
    } else if n < MIB {
        format!("{:.1}K", n / KIB)
    } else if n < GIB {
        format!("{:.1}M", n / MIB)
    } else {
        format!("{:.1}G", n / GIB)
    }
}

fn main() {
    // Select the UI language before the first render. English is the fallback; a persisted or
    // OS-derived choice will drive this once the language switcher lands (later slice).
    rust_i18n::set_locale("en");
    gpui_platform::application().run(|cx| {
        gpui_component::init(cx);
        gpui_component::Theme::change(gpui_component::ThemeMode::Dark, None, cx);
        // Explicit centered bounds within the display's work area, so the title bar
        // isn't placed above the monitor edge (the default unset bounds can do that).
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(1200.0), px(800.0)), cx)),
            ..Default::default()
        };
        cx.spawn(async move |cx| {
            cx.open_window(options, |window, cx| {
                let view = cx.new(|cx| AppView::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            })
            .expect("failed to open window");
        })
        .detach();
    });
}
