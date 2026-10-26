//! Request / response / event types for the local management API.

use serde::{Deserialize, Serialize};

/// A command sent by the CLI or UI to the running service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    /// Service / driver / connection summary.
    Status,
    /// Snapshot of active and recent connections.
    ListConnections,
    /// Full routing explanation for one connection id.
    ExplainConnection { id: u64 },
    /// Test a proxy definition through the real connectors: every kind runs its actual CONNECT
    /// handshake to a benign target, so reachability *and* credentials are verified — SOCKS5 /
    /// SOCKS5-over-TLS (method/auth + CONNECT), SOCKS4 (CONNECT grant), and HTTP / HTTPS CONNECT
    /// (incl. the `https` TLS handshake and any proxy auth). The [`Response::ProxyCheck`] detail
    /// says what was verified. Carries the candidate `ProxyDef` serialized as JSON (not just a
    /// name) so the editor checks the *unsaved* draft the user is editing, not the last-applied
    /// config. Sent over the admin-only pipe, same as [`Request::SetConfig`].
    ///
    /// `profile` names the profile the draft proxy belongs to, so the engine restores a redacted
    /// ("unchanged") secret from the SAME profile in the last-saved config — proxy names are unique only
    /// per profile, so a global name match could restore a same-named proxy's password from the
    /// wrong profile. `#[serde(default)]` for skew: an older GUI omits it and the engine falls back
    /// to the live active profile.
    CheckProxy {
        proxy: String,
        #[serde(default)]
        profile: Option<String>,
    },
    /// The LAST-SAVED configuration (proxy secrets redacted), serialized as JSON — what the GUI
    /// editor loads. Not necessarily the *running* config: a pending restart-required save makes
    /// them differ (the GUI compares digests / `Status.pending_restart_scope` to tell).
    GetConfig,
    /// Replace the configuration (full JSON document): validate, persist, and hot-reload
    /// the routing policy. Structural changes (redirect mode / DNS / active profile —
    /// in-place engine restart; logLevel / kill-switch floor — full service restart) are saved but
    /// need a restart to take effect. (IPv6 policy is a flag and hot-applies — no restart.)
    SetConfig {
        json: String,
        /// Optimistic-concurrency base: the digest the editing client last saw (from
        /// [`Response::Config`] or [`Response::Applied`]). The engine REJECTS the save if the
        /// saved config has advanced since (another client, a CLI reload, or a pending
        /// restart-required save), so a stale document can't silently clobber newer changes.
        /// `None` (an older client, or a deliberately-forced save) skips the check.
        #[serde(default)]
        base_digest: Option<u64>,
    },
    /// Re-read the config file from disk and hot-reload it.
    ReloadConfig,
    /// Restart the engine in place after a clean teardown: the host reloads the saved config and
    /// re-runs the engine loop (no process / SCM restart). The guarded hosts CONSUME the config the
    /// restart preflight already validated + staged (so an external disk edit between preflight and
    /// reload can't change it), falling back to re-reading the file only if nothing was staged.
    /// REFUSED with an error
    /// (no teardown) for ANY [`RestartScope::Service`] change — currently a logLevel change (logging
    /// is initialized once per process and isn't re-run in place) or a kill-switch floor change
    /// (failClosed.killSwitch / allowLan / allowDns — no leak-free in-place re-arm); both need a full
    /// service/process restart. Supported by both the foreground `run` host and the Windows service host.
    RestartEngine,
    // switch-profile / export-diagnostics will be added here with their handlers, not
    // before. validate-config runs locally in the CLI.
}

/// Whether a restart-required change can be applied by an in-place engine restart (`RestartEngine`)
/// or needs a full service stop/start. A SERVICE-scoped change — currently a logLevel change (logging
/// is initialized once per process and isn't re-run in place) or a kill-switch floor change (no
/// leak-free in-place re-arm) — is refused by `RestartEngine`, so the UI must offer the matching
/// full-service-restart action instead.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestartScope {
    /// An in-place engine restart (`RestartEngine`) applies it.
    Engine,
    /// A full service stop/start is required (cannot be applied in place).
    Service,
}

/// A change that was persisted but isn't live yet: `reason` is human-readable, and `scope` says
/// which restart applies so the UI offers the right action instead of a generic "restart".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestartRequired {
    pub scope: RestartScope,
    pub reason: String,
}

/// A reply from the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Response {
    /// Generic success with no payload.
    Ok,
    /// Answer to [`Request::Status`].
    Status {
        running: bool,
        /// The profile the engine is RUNNING — its *effective* profile, i.e. the `--profile`
        /// override when pinned, otherwise the config's `activeProfile`. This is NOT necessarily
        /// `Config::active_profile`: a `--profile` run reports its pinned profile here. The field is
        /// named `active_profile` for wire compatibility; treat the value as the running profile.
        active_profile: String,
        active_connections: u64,
        driver_version: Option<u32>,
        /// Content digest ([`proxroute_config::digest`], computed engine-side) of the config the engine is
        /// currently running. The GUI clears "restart needed" once this matches the digest a
        /// restart-required save returned (see `Applied::config_digest`) — a signal that survives a
        /// fast in-place restart whose pipe drop falls between polls. `#[serde(default)]` for skew:
        /// an older service omits it (returns `None`), and the GUI falls back to drop/reconnect
        /// observation for that restart (see `gui::restart::restart_completed`).
        #[serde(default)]
        running_config_digest: Option<u64>,
        /// Set when the LAST-SAVED config differs from the running one (a restart-required save not
        /// yet applied) — the scope of the restart needed to make it live. `None` when the running
        /// config already equals the saved one. Lets a freshly-opened GUI surface a pending restart
        /// from a PRIOR session instead of mistaking the saved config for the live one.
        /// `#[serde(default)]` for skew (an older service omits it ⇒ `None`).
        #[serde(default)]
        pending_restart_scope: Option<RestartScope>,
        /// Digest of the LAST-SAVED config (what `GetConfig` serves). When a restart is pending this
        /// is the digest the engine will report as `running_config_digest` once a restart applies it,
        /// so the GUI uses it as the restart-completion target — and because it comes from the engine
        /// every poll, the target tracks the LATEST save even if another client advanced it, instead
        /// of waiting on a digest the GUI captured earlier. `#[serde(default)]` for skew.
        #[serde(default)]
        saved_config_digest: Option<u64>,
        /// True when the engine-down kill-switch is ARMED but its permit-all heartbeat could not be
        /// added — a degraded fail-closed state: the service runs and proxied flows still egress (via
        /// the own-app permit), but DIRECT-routed and host-own traffic stay BLOCKED. Surfaced so the
        /// CLI/GUI can show a degraded health state instead of a misleading healthy "running".
        /// `#[serde(default)]` for skew (an older service omits it ⇒ `false`).
        #[serde(default)]
        killswitch_degraded: bool,
        /// True when the driver refused to re-register recv-auth because a crashed instance still
        /// holds it. DNS is redirected over UDP, so in this state name resolution fails
        /// machine-wide and BOTH proxied and direct traffic break — while everything else about
        /// the service looks healthy. Surfaced so `status` cannot report a bare "running: true"
        /// for a machine that cannot resolve a name. `#[serde(default)]` for skew.
        #[serde(default)]
        recv_auth_degraded: bool,
        /// Per-proxy health from the background monitor: only proxies with a `healthCheck` that have
        /// been probed appear. Empty from an older engine that predates health reporting.
        /// `#[serde(default)]` for skew.
        #[serde(default)]
        proxy_health: Vec<ProxyHealth>,
    },
    /// Answer to [`Request::ListConnections`]. `rows` is capped so the response always fits
    /// one IPC frame; `total` is the true number of records the registry held and `active`
    /// the true active count — both taken from the registry, not the capped slice, so the
    /// status bar stays honest when a spike truncates the listing. Both default on decode so a
    /// newer client tolerates an older service that predates the fields (version skew during
    /// an upgrade); the count just reads 0 until the service catches up.
    Connections {
        rows: Vec<ConnectionRow>,
        #[serde(default)]
        total: u64,
        #[serde(default)]
        active: u64,
    },
    /// Answer to [`Request::ExplainConnection`].
    Explanation { text: String },
    /// Answer to [`Request::CheckProxy`]: whether the proxy passed, plus a human-readable
    /// detail (what was verified + latency, or the failure reason).
    ProxyCheck { ok: bool, detail: String },
    /// Answer to [`Request::GetConfig`] — the last-saved config (proxy secrets redacted) as JSON.
    Config {
        json: String,
        /// Opaque revision token = digest of the (real, pre-redaction) config served. The client
        /// echoes it as [`Request::SetConfig`]`::base_digest` for optimistic-concurrency. `None`
        /// from an older engine that doesn't supply it.
        #[serde(default)]
        digest: Option<u64>,
    },
    /// Answer to [`Request::SetConfig`] / [`Request::ReloadConfig`] on a successful save.
    /// `restart_required` carries the human-readable reason when the change was persisted but needs
    /// a restart to take effect (`None` when hot-applied). `restart_scope` says which restart —
    /// in-place engine vs full service (logLevel / kill-switch floor changes); it is `#[serde(default)]` so the
    /// wire shape stays backward-compatible: an older peer that predates it omits the field and a
    /// newer peer reads `None` (treated as an engine restart), and the legacy string-shaped
    /// `restart_required` is unchanged. Keep these two flat fields — do NOT fold them into a nested
    /// object (that breaks decoding against an older service/GUI during an upgrade).
    Applied {
        restart_required: Option<String>,
        #[serde(default)]
        restart_scope: Option<RestartScope>,
        /// Content digest ([`proxroute_config::digest`]) of the config just saved, computed engine-side so
        /// it is directly comparable to `Status::running_config_digest`. The GUI stores it as the
        /// target a pending restart must reach. `#[serde(default)]` for skew: an older service omits
        /// it (returns `None`), and the GUI falls back to drop/reconnect observation for that
        /// restart instead of digest matching (see `gui::restart::restart_completed`).
        #[serde(default)]
        config_digest: Option<u64>,
        /// Advisory validation warnings for the config that was just applied (e.g. domain-matching
        /// rules under a non-`fakeIp` `dns.mode`, whose reverse IP→name attribution is best-effort).
        /// Non-blocking — the config still applied. Surfaced by the callers that do NO client-side
        /// validation of their own (the GUI's `SetConfig` and the `reload-config` verb), so the same
        /// steering guidance the CLI/service already log reaches those live-editing surfaces too.
        /// `#[serde(default)]` for skew: an older service omits it and the client shows none.
        #[serde(default)]
        warnings: Vec<String>,
    },
    /// Validation / operation failure with a list of human-readable messages.
    Error { messages: Vec<String> },
}

/// One connection row for the live traffic view.
///
/// Strings (not core enums) so the protocol crate stays free of `proxroute-core` and
/// the UI can render rows without extra dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRow {
    /// Stable per-connection id from the registry (constant across polls for one
    /// connection; lets a client track open/close events). Resets per engine run.
    #[serde(default)]
    pub id: u64,
    pub pid: u32,
    /// Image file name (e.g. `firefox.exe`) — the scannable table column.
    pub process: String,
    /// Full image path (e.g. `\device\harddiskvolume3\…\firefox.exe`) for detail views
    /// and hover tooltips. Defaulted so an older service without the field still
    /// deserializes against a newer client.
    #[serde(default)]
    pub process_path: String,
    pub protocol: String,
    pub destination: String,
    /// Hostname behind the destination, when known (e.g. recovered from a fake IP).
    pub dest_host: Option<String>,
    pub decision: String,
    pub proxy_or_chain: Option<String>,
    pub matched_rule: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// Health verdict for one proxy, from the background health monitor (`proxroute-engine::health`).
/// Carried in [`Response::Status`]; only proxies that declare a `healthCheck` and have been probed
/// appear, so an absent proxy means "no health check / not yet probed", not "down".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyHealth {
    /// The proxy's configured name (matches `ProxyDef::name`).
    pub name: String,
    /// Whether the last probe succeeded.
    pub healthy: bool,
    /// Last successful round-trip in milliseconds; absent when currently down / never succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
}

/// An asynchronous event the service can push to subscribed clients
/// (live updates for the traffic view).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    ConnectionOpened { row: Box<ConnectionRow> },
    ConnectionClosed { pid: u32, destination: String },
    ConfigReloaded { active_profile: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applied_response_wire_is_backward_compatible() {
        // Legacy frame (no restart_scope) from an older service still decodes — restart_scope
        // defaults to None (the UI treats that as an in-place engine restart).
        let old: Response = serde_json::from_str(
            r#"{"status":"applied","restart_required":"DNS settings changed"}"#,
        )
        .expect("legacy Applied frame must decode");
        assert!(matches!(
            old,
            Response::Applied { restart_required: Some(ref r), restart_scope: None, config_digest: None, ref warnings }
                if r == "DNS settings changed" && warnings.is_empty()
        ));

        // New frame carries the scope.
        let new: Response = serde_json::from_str(
            r#"{"status":"applied","restart_required":"kill-switch floor changed","restart_scope":"service"}"#,
        )
        .expect("new Applied frame must decode");
        assert!(matches!(
            new,
            Response::Applied {
                restart_scope: Some(RestartScope::Service),
                ..
            }
        ));

        // Hot-applied (no restart) decodes too. (A new frame against an OLDER decoder also works:
        // the Response enum doesn't deny unknown fields, so an old GUI ignores restart_scope.)
        let hot: Response = serde_json::from_str(r#"{"status":"applied","restart_required":null}"#)
            .expect("hot-applied frame must decode");
        assert!(matches!(
            hot,
            Response::Applied {
                restart_required: None,
                restart_scope: None,
                config_digest: None,
                warnings,
            } if warnings.is_empty()
        ));

        // A frame carrying the config digest decodes it (the restart-completion target).
        let digested: Response = serde_json::from_str(
            r#"{"status":"applied","restart_required":"redirect mode changed","restart_scope":"engine","config_digest":12345}"#,
        )
        .expect("digest-bearing Applied frame must decode");
        assert!(matches!(
            digested,
            Response::Applied {
                config_digest: Some(12345),
                ..
            }
        ));
    }

    #[test]
    fn status_response_wire_is_backward_compatible() {
        // Legacy frame from an older service: omits running_config_digest, pending_restart_scope, and
        // saved_config_digest. All three default to None — the GUI then falls back to drop/reconnect
        // restart detection and treats "no pending scope" as in-sync. (driver_version is original.)
        let old: Response = serde_json::from_str(
            r#"{"status":"status","running":true,"active_profile":"p","active_connections":3,"driver_version":65537}"#,
        )
        .expect("legacy Status frame must decode");
        assert!(matches!(
            old,
            Response::Status {
                running: true,
                driver_version: Some(65537),
                running_config_digest: None,
                pending_restart_scope: None,
                saved_config_digest: None,
                killswitch_degraded: false,
                ..
            }
        ));

        // New frame carries the running digest, a pending restart scope, and the saved digest.
        let new: Response = serde_json::from_str(
            r#"{"status":"status","running":true,"active_profile":"p","active_connections":3,
                "driver_version":65537,"running_config_digest":111,"pending_restart_scope":"engine",
                "saved_config_digest":222}"#,
        )
        .expect("new Status frame must decode");
        assert!(matches!(
            new,
            Response::Status {
                running_config_digest: Some(111),
                pending_restart_scope: Some(RestartScope::Engine),
                saved_config_digest: Some(222),
                ..
            }
        ));

        // Intermediate-version frame: reports running_config_digest + pending_restart_scope (added
        // earlier) but NOT saved_config_digest (added later). It decodes with saved_config_digest
        // None; the GUI then seeds the restart target from base_digest (GetConfig) instead of
        // dropping to the legacy drop/reconnect path.
        let partial: Response = serde_json::from_str(
            r#"{"status":"status","running":true,"active_profile":"p","active_connections":1,
                "driver_version":65537,"running_config_digest":111,"pending_restart_scope":"service"}"#,
        )
        .expect("intermediate Status frame must decode");
        assert!(matches!(
            partial,
            Response::Status {
                running_config_digest: Some(111),
                pending_restart_scope: Some(RestartScope::Service),
                saved_config_digest: None,
                ..
            }
        ));

        // A frame from a newer service carrying the kill-switch degraded flag: it decodes true, while
        // the legacy/new/partial frames above (which omit it) default it to false.
        let degraded: Response = serde_json::from_str(
            r#"{"status":"status","running":true,"active_profile":"p","active_connections":0,
                "driver_version":65537,"killswitch_degraded":true}"#,
        )
        .expect("degraded Status frame must decode");
        assert!(matches!(
            degraded,
            Response::Status {
                killswitch_degraded: true,
                running_config_digest: None,
                ..
            }
        ));

        // recv_auth_degraded gets the same two-sided guarantee. It is the flag that says DNS is
        // dead machine-wide after a crashed instance left recv-auth registered, so a skew bug that
        // silently defaulted it the wrong way would hide exactly the state it exists to report.
        // (a) An older service omits it entirely -> false, not a spurious DEGRADED on every status.
        assert!(matches!(
            old,
            Response::Status {
                recv_auth_degraded: false,
                ..
            }
        ));
        // ...including a frame that carries the OTHER degraded flag, so the two cannot be confused.
        assert!(matches!(
            degraded,
            Response::Status {
                killswitch_degraded: true,
                recv_auth_degraded: false,
                ..
            }
        ));
        // (b) A newer service sets it -> decodes true, and independently of killswitch_degraded.
        let recv_degraded: Response = serde_json::from_str(
            r#"{"status":"status","running":true,"active_profile":"p","active_connections":0,
                "driver_version":65537,"recv_auth_degraded":true}"#,
        )
        .expect("recv-auth degraded Status frame must decode");
        assert!(matches!(
            recv_degraded,
            Response::Status {
                recv_auth_degraded: true,
                killswitch_degraded: false,
                ..
            }
        ));
        // (c) Both at once, since a crash can leave the machine in both states.
        let both: Response = serde_json::from_str(
            r#"{"status":"status","running":true,"active_profile":"p","active_connections":0,
                "driver_version":65537,"killswitch_degraded":true,"recv_auth_degraded":true}"#,
        )
        .expect("both-degraded Status frame must decode");
        assert!(matches!(
            both,
            Response::Status {
                killswitch_degraded: true,
                recv_auth_degraded: true,
                ..
            }
        ));

        // A new frame against an OLDER decoder also works: the enum doesn't deny unknown fields, so an
        // old GUI ignores the digest fields it doesn't know. (Mirrors the Applied compat guarantee.)
    }

    #[test]
    fn status_proxy_health_round_trips_and_defaults() {
        // Absent proxyHealth (older engine) ⇒ empty.
        let without: Response = serde_json::from_str(
            r#"{"status":"status","running":true,"active_profile":"p","active_connections":0,"driver_version":65537}"#,
        )
        .expect("Status without proxyHealth must decode");
        assert!(matches!(
            without,
            Response::Status { ref proxy_health, .. } if proxy_health.is_empty()
        ));

        // Present: the variant field is snake_case (`proxy_health`, like its siblings); each entry's
        // own fields are camelCase (`rttMs`), and rttMs is optional (absent ⇒ None for a down proxy).
        let with: Response = serde_json::from_str(
            r#"{"status":"status","running":true,"active_profile":"p","active_connections":0,
                "driver_version":65537,
                "proxy_health":[{"name":"A","healthy":true,"rttMs":42},{"name":"B","healthy":false}]}"#,
        )
        .expect("Status with proxy_health must decode");
        // True round-trip: re-encode and pin the EMIT shape too — snake_case variant key
        // `proxy_health`, camelCase nested `rttMs`, and rttMs OMITTED (not null) for the down proxy
        // via skip_serializing_if. (Other Option fields without skip still emit `null`, so we check
        // the rttMs key specifically.)
        let reencoded = serde_json::to_string(&with).expect("Status re-serializes");
        assert!(
            reencoded.contains(r#""proxy_health":["#),
            "snake_case variant key: {reencoded}"
        );
        assert!(
            reencoded.contains(r#""rttMs":42"#),
            "camelCase nested key: {reencoded}"
        );
        assert!(
            !reencoded.contains(r#""rttMs":null"#),
            "down proxy omits rttMs (skip_serializing_if): {reencoded}"
        );
        match with {
            Response::Status { proxy_health, .. } => assert_eq!(
                proxy_health,
                vec![
                    ProxyHealth {
                        name: "A".into(),
                        healthy: true,
                        rtt_ms: Some(42),
                    },
                    ProxyHealth {
                        name: "B".into(),
                        healthy: false,
                        rtt_ms: None,
                    },
                ]
            ),
            other => panic!("expected Status, got {other:?}"),
        }
    }
}
