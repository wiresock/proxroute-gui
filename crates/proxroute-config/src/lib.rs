//! Proxroute configuration model (schema v2).
//!
//! A [`Config`] is a versioned document holding one or more named [`Profile`]s.
//! Each profile carries its proxies, proxy chains, rule groups, DNS policy and
//! bypass settings, so users can switch whole routing setups at once
//!. Credentials are wrapped in [`Secret`] so they never leak
//! into logs.
//!
//! See `docs/config-schema.md` for the schema reference.

pub mod migrate;
pub mod schema;
pub mod secret;
pub mod timespec;
pub mod validate;

pub use schema::{
    chain_hops_summary, Action, ActionType, AddrFamily, AppMatch, Bypass, ChainDns, ChainMode,
    Config, DestMatch, DnsConfig, DnsMode, DnsSplit, FailClosed, HealthCheck, HealthCheckKind,
    Ipv6Policy, LogLevel, NetMatch, OnFailure, OnHopFailure, Predicate, Profile, Protocol,
    ProxyAuth, ProxyChain, ProxyDef, ProxyDnsResolution, ProxyKind, RedirectMode, Rule, RuleGroup,
    TimeMatch, DEFAULT_HEALTH_INTERVAL_SECS,
};
pub use secret::{Secret, SecretBytes};
pub use validate::{enforce_strict, validate, ConfigIssue, IssueKind, Severity};

use std::path::Path;

/// The configuration schema version this build understands.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// Errors returned while loading a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("unsupported config version: {0}")]
    Migrate(#[from] migrate::MigrateError),
    #[error("config has unknown or misspelled key(s) — a typo here silently weakens policy: {}", .0.join(", "))]
    UnknownKeys(Vec<String>),
}

/// Load, deserialize and version-migrate a configuration file.
///
/// The `schemaVersion` is **enforced**: a document from a newer build, or a
/// pre-v2 document we cannot migrate, is rejected here rather than silently
/// accepted with ignored fields. Semantic validation is separate — call
/// [`validate`] on the result to surface dangling references, invalid CIDRs etc.
pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    from_json_str(&text)
}

/// Parse + version-migrate a config from JSON text (the file-less core of [`load`]).
///
/// Unknown / misspelled keys are a **hard error**: a typo like `killSwtich` or
/// `ruleGrops` would otherwise be silently dropped to a default that weakens policy
/// before [`validate`] ever runs. Use this — never a bare `serde_json::from_str` — for any
/// caller-supplied config JSON (live `SetConfig`, the GUI editor), so the same strict gate
/// applies as on file load.
pub fn from_json_str(text: &str) -> Result<Config, ConfigError> {
    let mut unknown = Vec::new();
    let mut de = serde_json::Deserializer::from_str(text);
    let mut cfg: Config =
        serde_ignored::deserialize(&mut de, |path| unknown.push(path.to_string()))?;
    // Reject anything but whitespace after the document. Driving the Deserializer by hand (for
    // serde_ignored) skips the end-of-input check `serde_json::from_str` performs, so without this
    // `{...} {...}` or `{...} junk` loaded just the first value and silently ignored the rest.
    de.end()?;
    // Run the version gate first: a v1 / too-new document should report its precise
    // migration error, not "unknown keys" (its keys look unknown against the v2 schema).
    migrate::migrate(&mut cfg)?;
    if !unknown.is_empty() {
        return Err(ConfigError::UnknownKeys(unknown));
    }
    Ok(cfg)
}

/// Serialize a configuration back to pretty JSON (for `export` / round-tripping).
///
/// Note that [`Secret`] fields serialize their real value, so callers must only
/// write the output to access-controlled locations — never to logs.
pub fn to_json(cfg: &Config) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(cfg)
}

/// A stable content digest of a config, used to tell whether the engine is yet running a given
/// configuration — e.g. so the GUI can clear "restart needed" once a restart-required change is
/// actually live, robust to a fast in-place restart whose pipe drop falls between status polls.
///
/// This is FNV-1a over the canonical JSON, NOT a cryptographic hash — it is only a change-detection
/// token, never a trust boundary. Determinism relies on `Config` serializing in a fixed order: it
/// holds only structs / `Vec`s / `Option`s / scalars (no `HashMap`/`HashSet`), so serde's field
/// order is stable. To stay comparable across producers, the digest must be computed by ONE party
/// (the engine, over the config it parsed and runs) and merely echoed by others — a peer that
/// parsed the same JSON differently (looser serde vs. `from_json_str` migration) could serialize to
/// different bytes.
pub fn digest(cfg: &Config) -> u64 {
    // `Config` is plain data (structs / Vec / Option / scalars), so serialization never fails in
    // practice. If it ever did, hash a fixed sentinel rather than an empty slice: this token gates
    // the optimistic-concurrency check, and a silent collapse to the digest of `[]` could let a
    // stale save's base digest alias a real one.
    let bytes = serde_json::to_vec(cfg)
        .unwrap_or_else(|_| b"\0proxroute:digest-serialize-error\0".to_vec());
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 64-bit offset basis
    for b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
    }
    h
}

/// Placeholder substituted for a proxy secret when a config is serialized for a less-trusted reader
/// (the GUI, over the management pipe), so plaintext passwords never leave the engine. A config
/// saved back carrying this placeholder for a secret means "unchanged": [`restore_redacted_secrets`]
/// swaps the real value back in (matched by profile + proxy name, and only while the proxy's
/// credential identity is unchanged — see [`secret_binding_changes`]) before the config is
/// validated, applied, or persisted. NOTE: a real secret equal to this exact string would be treated as
/// unchanged, so it must not be used as an actual password.
pub const REDACTED_SECRET: &str = "<unchanged>";

/// Replace every proxy password with [`REDACTED_SECRET`] in place — for `GetConfig`
/// display/transport, so cleartext credentials never leave the engine.
pub fn redact_secrets(cfg: &mut Config) {
    for profile in &mut cfg.profiles {
        for proxy in &mut profile.proxies {
            redact_proxy_auth(&mut proxy.auth);
        }
    }
}

fn redact_proxy_auth(auth: &mut ProxyAuth) {
    if let ProxyAuth::UserPass { password, .. }
    | ProxyAuth::Basic { password, .. }
    | ProxyAuth::Digest { password, .. } = auth
    {
        if !password.is_empty() {
            *password = Secret::new(REDACTED_SECRET);
        }
    }
}

/// Restore real proxy secrets that a redacted round-trip left as [`REDACTED_SECRET`], taking the
/// value from `live` (matched by profile name + proxy name). A non-placeholder password is a
/// deliberately-changed secret and is left as-is. Call before validating / persisting / applying a
/// config received over the management API.
///
/// **Secret binding policy.** A stored secret is restored only to the same *credential identity*
/// it was saved for: the same profile and proxy name **and** the same proxy kind, endpoint host and
/// port, auth type, username and `skipVerify` (see [`secret_binding_changes`]). If any of those
/// changed, the placeholder is left in place and the caller rejects the config, so the user must
/// re-enter the password. Otherwise editing a proxy's endpoint (or downgrading it from `https` to
/// `http`, or from `digest` to `basic`) would silently send the old password to a different server
/// or over a weaker scheme. Every other edit — or none — restores as before.
pub fn restore_redacted_secrets(cfg: &mut Config, live: &Config) {
    for profile in &mut cfg.profiles {
        let Some(live_profile) = live.profiles.iter().find(|p| p.name == profile.name) else {
            continue;
        };
        for proxy in &mut profile.proxies {
            if let Some(live_proxy) = live_profile.proxies.iter().find(|p| p.name == proxy.name) {
                restore_proxy_secret(proxy, live_proxy);
            }
        }
    }
}

/// Restore one proxy's redacted secret from the live config, matched by name within the ACTIVE
/// profile only. Used by `CheckProxy`, where the GUI sends a single proxy def (from the active
/// profile it edits) with a possibly-redacted secret. Matching only the active profile avoids
/// restoring a same-named proxy's secret from the WRONG profile — proxy names are unique per profile,
/// not globally. A new/renamed proxy won't match, and neither will one whose credential identity
/// changed ([`restore_redacted_secrets`] explains the binding), leaving the placeholder for the
/// caller to reject — the same rule a save applies, so Check and Save agree.
pub fn restore_redacted_proxy(proxy: &mut ProxyDef, live: &Config, active_profile: &str) {
    let Some(profile) = live.profiles.iter().find(|p| p.name == active_profile) else {
        return;
    };
    if let Some(live_proxy) = profile.proxies.iter().find(|p| p.name == proxy.name) {
        restore_proxy_secret(proxy, live_proxy);
    }
}

/// Whether a proxy's auth secret is still the redaction placeholder — i.e. restore could not resolve
/// it (a new or renamed proxy, or one whose credential identity changed). The caller should refuse
/// to use it rather than treat the literal placeholder as a password.
pub fn proxy_secret_is_redacted(proxy: &ProxyDef) -> bool {
    password_of(&proxy.auth).is_some_and(|pw| pw.expose() == REDACTED_SECRET)
}

/// The password of a credential-carrying auth variant.
fn password_of(auth: &ProxyAuth) -> Option<&Secret> {
    match auth {
        ProxyAuth::UserPass { password, .. }
        | ProxyAuth::Basic { password, .. }
        | ProxyAuth::Digest { password, .. } => Some(password),
        ProxyAuth::None | ProxyAuth::Negotiate { .. } => None,
    }
}

/// The username of a credential-carrying auth variant.
fn username_of(auth: &ProxyAuth) -> Option<&str> {
    match auth {
        ProxyAuth::UserPass { username, .. }
        | ProxyAuth::Basic { username, .. }
        | ProxyAuth::Digest { username, .. } => Some(username),
        ProxyAuth::None | ProxyAuth::Negotiate { .. } => None,
    }
}

/// Which parts of a proxy's credential identity differ between an edited `draft` and the `live`
/// definition its `<unchanged>` secret would be restored from — empty when the stored secret may be
/// reused. The identity is: proxy kind (this also covers the TLS wrapping), endpoint host
/// (ASCII case-insensitive) and port, auth type, username, and `skipVerify`. Fields that do not
/// change where or how the secret is sent (protocols, DNS, priority, health check, UDP options) are
/// not part of it.
pub fn secret_binding_changes(draft: &ProxyDef, live: &ProxyDef) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if draft.kind != live.kind {
        changed.push("proxy kind");
    }
    match (
        validate::parse_host_port(&draft.endpoint),
        validate::parse_host_port(&live.endpoint),
    ) {
        (Some((dh, dp)), Some((lh, lp))) => {
            if !dh.eq_ignore_ascii_case(lh) {
                changed.push("endpoint host");
            }
            if dp != lp {
                changed.push("endpoint port");
            }
        }
        // An unparseable endpoint (validation rejects it anyway): only an identical string counts
        // as the same endpoint.
        _ => {
            if draft.endpoint != live.endpoint {
                changed.push("endpoint");
            }
        }
    }
    if std::mem::discriminant(&draft.auth) != std::mem::discriminant(&live.auth) {
        changed.push("auth type");
    } else if username_of(&draft.auth) != username_of(&live.auth) {
        changed.push("username");
    }
    if draft.skip_verify != live.skip_verify {
        changed.push("skipVerify");
    }
    changed
}

fn restore_proxy_secret(draft: &mut ProxyDef, live: &ProxyDef) {
    if !proxy_secret_is_redacted(draft) {
        return; // a deliberately-changed (or empty) secret, or no secret at all — keep it
    }
    if !secret_binding_changes(draft, live).is_empty() {
        return; // bound to a different credential identity — the user must re-enter it
    }
    let Some(live_pw) = password_of(&live.auth).cloned() else {
        return;
    };
    if let ProxyAuth::UserPass { password, .. }
    | ProxyAuth::Basic { password, .. }
    | ProxyAuth::Digest { password, .. } = &mut draft.auth
    {
        *password = live_pw;
    }
}

/// The name of the first proxy whose secret is still [`REDACTED_SECRET`] after a restore — i.e. the
/// GUI sent the "unchanged" placeholder but no matching live secret was found (a new or renamed
/// proxy, or one whose credential identity changed). `None` means every placeholder resolved.
/// Callers should reject such a config so a literal placeholder never becomes an actual password;
/// [`unresolved_redacted_secret_message`] words that rejection.
pub fn first_unresolved_redacted_secret(cfg: &Config) -> Option<&str> {
    cfg.profiles
        .iter()
        .flat_map(|p| &p.proxies)
        .find(|proxy| proxy_secret_is_redacted(proxy))
        .map(|proxy| proxy.name.as_str())
}

/// An actionable rejection for the first `<unchanged>` placeholder that survived
/// [`restore_redacted_secrets`]`(cfg, live)`, or `None` if every placeholder resolved. It says
/// whether the proxy had no saved secret to reuse (new or renamed) or its credential identity
/// changed, and which parts changed. Never contains a secret.
pub fn unresolved_redacted_secret_message(cfg: &Config, live: &Config) -> Option<String> {
    for profile in &cfg.profiles {
        for proxy in &profile.proxies {
            if proxy_secret_is_redacted(proxy) {
                return Some(redacted_proxy_message(proxy, live, &profile.name));
            }
        }
    }
    None
}

/// [`unresolved_redacted_secret_message`] for a single proxy draft of `profile` (`CheckProxy`).
/// Call only when [`proxy_secret_is_redacted`] is still true after [`restore_redacted_proxy`].
pub fn redacted_proxy_message(proxy: &ProxyDef, live: &Config, profile: &str) -> String {
    let live_proxy = live
        .profiles
        .iter()
        .find(|p| p.name == profile)
        .and_then(|p| p.proxies.iter().find(|p| p.name == proxy.name));
    match live_proxy {
        Some(live_proxy) => {
            let changed = secret_binding_changes(proxy, live_proxy);
            if changed.is_empty() {
                // Same identity but the saved definition has no password to reuse (e.g. it was
                // `none` auth before).
                format!(
                    "proxy '{}': the password is the 'unchanged' placeholder but the saved \
                     definition has no password to keep. Enter the password.",
                    proxy.name
                )
            } else {
                format!(
                    "proxy '{}': the saved password is bound to the proxy's kind, endpoint, auth \
                     type, username and skipVerify, and the {} changed, so it is not reused. \
                     Re-enter the password to use it with the new settings.",
                    proxy.name,
                    changed.join(", ")
                )
            }
        }
        None => format!(
            "proxy '{}': the password is the 'unchanged' placeholder but no saved secret exists \
             for this proxy in profile '{profile}' (is it new or renamed?). Enter the password.",
            proxy.name
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{"schemaVersion":2,"logLevel":"Info","redirectMode":"ale","activeProfile":"default","profiles":[]}"#;

    #[test]
    fn valid_config_loads_with_no_unknown_keys() {
        let cfg = from_json_str(MINIMAL).expect("minimal v2 config loads");
        assert_eq!(cfg.schema_version, 2);
        assert_eq!(cfg.active_profile, "default");
    }

    #[test]
    fn unknown_key_is_a_hard_error() {
        // A typo'd / stray key must NOT be silently ignored — it could weaken policy.
        let json = r#"{"schemaVersion":2,"logLevel":"Info","redirectMode":"ale","activeProfile":"default","profiles":[],"kilSwitch":true}"#;
        match from_json_str(json) {
            Err(ConfigError::UnknownKeys(keys)) => {
                assert!(keys.iter().any(|k| k.contains("kilSwitch")), "got {keys:?}");
            }
            other => panic!("expected UnknownKeys, got {other:?}"),
        }
    }

    #[test]
    fn trailing_data_after_the_document_is_rejected() {
        // A second value or stray text after the config object must not be silently ignored: an
        // editor merge or a concatenated file would otherwise load only its first document.
        for tail in [" {}", " garbage", "\n{\"schemaVersion\":2}", " ]"] {
            let text = format!("{MINIMAL}{tail}");
            assert!(
                matches!(from_json_str(&text), Err(ConfigError::Parse(_))),
                "trailing {tail:?} must be a parse error"
            );
        }
        // Trailing whitespace (an editor's final newline) is still fine.
        assert!(from_json_str(&format!("{MINIMAL}\r\n\t ")).is_ok());
    }

    #[test]
    fn version_gate_wins_over_unknown_keys() {
        // A v1 doc's keys look unknown against the v2 schema, but the migration error
        // must take precedence so the user gets the precise reason.
        let json = r#"{"schemaVersion":1,"logLevel":"Info","redirectMode":"ale","activeProfile":"x","profiles":[],"legacyOnlyKey":true}"#;
        assert!(matches!(from_json_str(json), Err(ConfigError::Migrate(_))));
    }

    #[test]
    fn redirect_auth_defaults_on_and_round_trips_when_disabled() {
        // Absent key ⇒ ON. Every config written before this option existed must keep authorizing
        // redirected flows; silently defaulting to off would break proxied UDP/QUIC and proxy-mode
        // DNS on machines with a restrictive inbound firewall policy, with nothing in the config
        // to explain why.
        assert!(
            from_json_str(MINIMAL).unwrap().redirect_auth,
            "an absent redirectAuth must default to enabled"
        );

        // ...and an explicit `false` is honoured and survives a save/load round-trip, since it is
        // the escape hatch for isolating a conflict with third-party security software.
        let off = MINIMAL.replace(
            r#""activeProfile""#,
            r#""redirectAuth":false,"activeProfile""#,
        );
        let cfg = from_json_str(&off).unwrap();
        assert!(!cfg.redirect_auth, "an explicit false must be honoured");
        let reloaded = from_json_str(&to_json(&cfg).unwrap()).unwrap();
        assert!(
            !reloaded.redirect_auth,
            "redirectAuth: false must survive a serialize/parse round-trip"
        );
    }

    #[test]
    fn doh_guard_defaults_on_and_round_trips_when_disabled() {
        // Same contract as `redirectAuth` above: a config written before the option existed must
        // get the guard, and the hand-written `Default for DnsConfig` must agree with serde's
        // `default = "default_true"`. A derived `Default` would say `false` while a parsed config
        // says `true`, so anything reasoning from the type (diagnostics, the GUI toggle) would
        // disagree with the running engine.
        let with_profile = MINIMAL.replace(
            r#""profiles":[]"#,
            r#""profiles":[{"name":"default","dns":{"mode":"fakeIp"}}]"#,
        );
        assert!(
            from_json_str(&with_profile).unwrap().profiles[0]
                .dns
                .doh_guard,
            "an absent dohGuard must default to enabled"
        );
        assert!(
            schema::DnsConfig::default().doh_guard,
            "Default must match the serde default, or the type lies about the product"
        );

        // An explicit `false` is honoured and survives save/load — it is the only escape for a
        // client that requires DoH, since the guard returns before the routing engine and no rule
        // can exempt a listed address.
        let off = MINIMAL.replace(
            r#""profiles":[]"#,
            r#""profiles":[{"name":"default","dns":{"mode":"fakeIp","dohGuard":false}}]"#,
        );
        let cfg = from_json_str(&off).unwrap();
        assert!(
            !cfg.profiles[0].dns.doh_guard,
            "explicit false must be honoured"
        );
        let reloaded = from_json_str(&to_json(&cfg).unwrap()).unwrap();
        assert!(
            !reloaded.profiles[0].dns.doh_guard,
            "dohGuard: false must survive a serialize/parse round-trip"
        );
    }

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        let a = from_json_str(MINIMAL).unwrap();
        // Same content, parsed twice → identical digest (the restart-completion invariant).
        let a2 = from_json_str(MINIMAL).unwrap();
        assert_eq!(digest(&a), digest(&a2));
        // A different active profile → different digest, so a real change is observable.
        let other = MINIMAL.replace("\"default\"", "\"other\"");
        let b = from_json_str(&other).unwrap();
        assert_ne!(digest(&a), digest(&b));
    }

    fn cfg_with_secret(pw: &str) -> Config {
        use schema::{Profile, ProxyAuth, ProxyDef, ProxyKind};
        let proxy = ProxyDef {
            name: "px".into(),
            kind: ProxyKind::Socks5,
            endpoint: "h:1080".into(),
            protocols: vec![],
            auth: ProxyAuth::UserPass {
                username: "u".into(),
                password: Secret::new(pw),
            },
            dns: Default::default(),
            priority: None,
            health_check: None,
            skip_verify: false,
            udp_use_proxy_host: false,
        };
        Config {
            schema_version: CURRENT_SCHEMA_VERSION,
            log_level: Default::default(),
            redirect_mode: Default::default(),
            redirect_auth: true,
            active_profile: "p".into(),
            profiles: vec![Profile {
                name: "p".into(),
                proxies: vec![proxy],
                ..Default::default()
            }],
        }
    }

    fn proxy_secret(cfg: &Config) -> String {
        match &cfg.profiles[0].proxies[0].auth {
            ProxyAuth::UserPass { password, .. } => password.expose().to_string(),
            other => panic!("expected UserPass, got {other:?}"),
        }
    }

    #[test]
    fn redact_hides_then_restore_recovers_unchanged_secret() {
        let live = cfg_with_secret("realsecret");
        let mut shown = live.clone();
        redact_secrets(&mut shown);
        // The displayed/transported config must not contain the real secret.
        assert!(!to_json(&shown).unwrap().contains("realsecret"));
        assert_eq!(proxy_secret(&shown), REDACTED_SECRET);
        // Saving the redacted config back restores the real secret (unchanged → placeholder).
        let mut saved = shown.clone();
        restore_redacted_secrets(&mut saved, &live);
        assert_eq!(proxy_secret(&saved), "realsecret");
    }

    #[test]
    fn restore_keeps_a_deliberately_changed_secret() {
        let live = cfg_with_secret("realsecret");
        // The user typed a new secret over the placeholder — restore must NOT clobber it.
        let mut changed = cfg_with_secret("newsecret");
        restore_redacted_secrets(&mut changed, &live);
        assert_eq!(proxy_secret(&changed), "newsecret");
    }

    /// `cfg_with_secret`'s proxy, redacted and then edited by `edit` — a GUI save of an edited draft.
    fn redacted_draft(edit: impl FnOnce(&mut ProxyDef)) -> Config {
        let mut draft = cfg_with_secret("realsecret");
        redact_secrets(&mut draft);
        edit(&mut draft.profiles[0].proxies[0]);
        draft
    }

    #[test]
    fn unchanged_secret_is_not_restored_when_its_credential_identity_changes() {
        // Before the binding policy the placeholder was restored by profile + proxy name alone, so
        // pointing a saved proxy at another server (or a weaker scheme) silently sent it the old
        // password. Each of these edits must now leave the placeholder for the caller to reject.
        let live = cfg_with_secret("realsecret");
        type Edit = Box<dyn Fn(&mut ProxyDef)>;
        let cases: Vec<(&str, Edit)> = vec![
            (
                "endpoint host",
                Box::new(|p| p.endpoint = "other.example:1080".into()),
            ),
            ("endpoint port", Box::new(|p| p.endpoint = "h:1081".into())),
            ("proxy kind", Box::new(|p| p.kind = ProxyKind::Socks5Tls)),
            ("skipVerify", Box::new(|p| p.skip_verify = true)),
            (
                "username",
                Box::new(|p| {
                    p.auth = ProxyAuth::UserPass {
                        username: "someone-else".into(),
                        password: Secret::new(REDACTED_SECRET),
                    }
                }),
            ),
            (
                "auth type",
                Box::new(|p| {
                    p.kind = ProxyKind::Https;
                    p.auth = ProxyAuth::Basic {
                        username: "u".into(),
                        password: Secret::new(REDACTED_SECRET),
                    }
                }),
            ),
        ];
        for (what, edit) in cases {
            let mut saved = redacted_draft(|p| edit(p));
            restore_redacted_secrets(&mut saved, &live);
            assert_eq!(
                first_unresolved_redacted_secret(&saved),
                Some("px"),
                "a changed {what} must not restore the old secret"
            );
            let msg = unresolved_redacted_secret_message(&saved, &live).unwrap();
            assert!(
                msg.contains(what) && msg.contains("Re-enter"),
                "{what}: {msg}"
            );
            assert!(
                !msg.contains("realsecret"),
                "the message must not carry the secret"
            );
            // CheckProxy applies the same rule to a single draft.
            let mut one = redacted_draft(|p| edit(p)).profiles[0].proxies[0].clone();
            restore_redacted_proxy(&mut one, &live, "p");
            assert!(proxy_secret_is_redacted(&one), "CheckProxy: changed {what}");
        }
    }

    #[test]
    fn unchanged_secret_is_restored_across_edits_outside_its_identity() {
        // Ordinary saves keep working: no edit, a host differing only in letter case, or edits to
        // fields that do not change where/how the secret is sent.
        let live = cfg_with_secret("realsecret");
        for edit in [
            Box::new(|_: &mut ProxyDef| {}) as Box<dyn Fn(&mut ProxyDef)>,
            Box::new(|p| p.endpoint = "H:1080".into()),
            Box::new(|p| p.priority = Some(3)),
            Box::new(|p| p.udp_use_proxy_host = true),
            Box::new(|p| p.protocols = vec![schema::Protocol::Tcp]),
        ] {
            let mut saved = redacted_draft(|p| edit(p));
            restore_redacted_secrets(&mut saved, &live);
            assert_eq!(proxy_secret(&saved), "realsecret");
            assert!(unresolved_redacted_secret_message(&saved, &live).is_none());
        }
        // A new endpoint WITH a freshly typed password is simply that new password.
        let mut retyped = redacted_draft(|p| {
            p.endpoint = "other.example:1080".into();
            p.auth = ProxyAuth::UserPass {
                username: "u".into(),
                password: Secret::new("typed-anew"),
            };
        });
        restore_redacted_secrets(&mut retyped, &live);
        assert_eq!(proxy_secret(&retyped), "typed-anew");
    }

    #[test]
    fn unresolved_placeholder_message_names_a_new_or_renamed_proxy() {
        let live = cfg_with_secret("realsecret");
        let mut saved = redacted_draft(|p| p.name = "renamed".into());
        restore_redacted_secrets(&mut saved, &live);
        let msg = unresolved_redacted_secret_message(&saved, &live).unwrap();
        assert!(
            msg.contains("'renamed'") && msg.contains("new or renamed"),
            "{msg}"
        );
    }

    #[test]
    fn restore_redacted_proxy_uses_the_named_profile_not_a_global_match() {
        use schema::{Profile, ProxyAuth, ProxyDef, ProxyKind};
        // Proxy names are unique only PER profile, so a same-named proxy can carry different secrets
        // in different profiles. CheckProxy must restore from the profile the draft belongs to.
        let corp = |pw: &str| ProxyDef {
            name: "corp".into(),
            kind: ProxyKind::Socks5,
            endpoint: "h:1080".into(),
            protocols: vec![],
            auth: ProxyAuth::UserPass {
                username: "u".into(),
                password: Secret::new(pw),
            },
            dns: Default::default(),
            priority: None,
            health_check: None,
            skip_verify: false,
            udp_use_proxy_host: false,
        };
        let live = Config {
            schema_version: CURRENT_SCHEMA_VERSION,
            log_level: Default::default(),
            redirect_mode: Default::default(),
            redirect_auth: true,
            active_profile: "A".into(),
            profiles: vec![
                Profile {
                    name: "A".into(),
                    proxies: vec![corp("A-secret")],
                    ..Default::default()
                },
                Profile {
                    name: "B".into(),
                    proxies: vec![corp("B-secret")],
                    ..Default::default()
                },
            ],
        };
        // A redacted draft of B's "corp": restoring against profile B must yield B's secret —
        // NOT profile A's (which a global name match would wrongly pick, since A comes first).
        let mut draft = corp(REDACTED_SECRET);
        restore_redacted_proxy(&mut draft, &live, "B");
        match &draft.auth {
            ProxyAuth::UserPass { password, .. } => assert_eq!(password.expose(), "B-secret"),
            other => panic!("expected UserPass, got {other:?}"),
        }
    }
}
