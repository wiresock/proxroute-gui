//! Pure helpers for the rule form editor: mapping a rule's match [`Predicate`] to/from
//! the flat set of fields the form edits (apps + destination + advanced app/net/time
//! criteria). Kept out of `main.rs` so the unit tests use the standard `#[test]` (the
//! `gpui::*` glob there shadows it).

use proxroute_config::{
    Action, ActionType, AddrFamily, AppMatch, DestMatch, NetMatch, Predicate, Protocol, Rule,
    RuleGroup, TimeMatch,
};

/// The form-editable fields of a rule's match. Covers the common app/destination shape plus
/// the advanced criteria (app path/parent/signer, IP family, time window). Anything richer
/// (Any/Not boolean logic, network interfaces, nested groups) keeps the JSON-only fallback.
#[derive(Default)]
pub struct RuleFields {
    pub apps: Vec<String>,
    pub app_paths: Vec<String>,
    pub app_parent: Vec<String>,
    pub signed_by: String,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
    pub ports: Vec<String>,
    pub tcp: bool,
    pub udp: bool,
    pub v4: bool,
    pub v6: bool,
    pub days: Vec<String>,
    pub hours: Vec<String>,
}

/// Which sub-matches have been absorbed, so each appears at most once.
#[derive(Default)]
struct Seen {
    app: bool,
    dest: bool,
    net: bool,
    when: bool,
}

/// Extract the form fields from a match **iff** it's a shape the form can fully represent —
/// a single `App`/`Dest`/`Net`/`When`, or an `All` of at most one of each. Returns `None`
/// for anything richer (Any/Not, nested All, a network-interface match, or two of the same
/// kind) so those keep the JSON-only fallback and the form never silently drops them.
pub fn extract_rule_fields(pred: &Predicate) -> Option<RuleFields> {
    fn absorb(p: &Predicate, f: &mut RuleFields, seen: &mut Seen) -> bool {
        match p {
            Predicate::App(a) => {
                if seen.app {
                    return false;
                }
                seen.app = true;
                f.apps = a.names.clone();
                f.app_paths = a.paths.clone();
                f.app_parent = a.parent.clone();
                f.signed_by = a.signed_by.clone().unwrap_or_default();
                true
            }
            Predicate::Dest(d) => {
                if seen.dest {
                    return false;
                }
                seen.dest = true;
                f.domains = d.domains.clone();
                f.ips = d.ips.clone();
                f.ports = d.ports.clone();
                f.tcp = d.protocol.contains(&Protocol::Tcp);
                f.udp = d.protocol.contains(&Protocol::Udp);
                true
            }
            Predicate::Net(n) => {
                // Interface matching isn't form-representable (and isn't implemented) — keep
                // such rules JSON-only rather than silently dropping the interfaces.
                if seen.net || !n.interfaces.is_empty() {
                    return false;
                }
                seen.net = true;
                f.v4 = n.family.contains(&AddrFamily::Ipv4);
                f.v6 = n.family.contains(&AddrFamily::Ipv6);
                true
            }
            Predicate::When(t) => {
                if seen.when {
                    return false;
                }
                seen.when = true;
                f.days = t.days.clone();
                f.hours = t.hours.clone();
                true
            }
            _ => false,
        }
    }
    let mut f = RuleFields::default();
    let mut seen = Seen::default();
    match pred {
        Predicate::All(children) => {
            for c in children {
                if !absorb(c, &mut f, &mut seen) {
                    return None;
                }
            }
            Some(f)
        }
        single => absorb(single, &mut f, &mut seen).then_some(f),
    }
}

/// Rebuild a match Predicate from form fields: an `App` / `Dest` / `Net` / `When` for each
/// non-empty group, combined with `All` when more than one is present (empty → `All([])`,
/// match-all).
pub fn build_match(f: RuleFields) -> Predicate {
    let mut parts = Vec::new();

    let signed_by = {
        let s = f.signed_by.trim();
        (!s.is_empty()).then(|| s.to_string())
    };
    if !f.apps.is_empty()
        || !f.app_paths.is_empty()
        || !f.app_parent.is_empty()
        || signed_by.is_some()
    {
        parts.push(Predicate::App(AppMatch {
            names: f.apps,
            paths: f.app_paths,
            signed_by,
            parent: f.app_parent,
        }));
    }

    let mut protocol = Vec::new();
    if f.tcp {
        protocol.push(Protocol::Tcp);
    }
    if f.udp {
        protocol.push(Protocol::Udp);
    }
    if !f.domains.is_empty() || !f.ips.is_empty() || !f.ports.is_empty() || !protocol.is_empty() {
        parts.push(Predicate::Dest(DestMatch {
            domains: f.domains,
            ips: f.ips,
            ports: f.ports,
            protocol,
        }));
    }

    let mut family = Vec::new();
    if f.v4 {
        family.push(AddrFamily::Ipv4);
    }
    if f.v6 {
        family.push(AddrFamily::Ipv6);
    }
    if !family.is_empty() {
        parts.push(Predicate::Net(NetMatch {
            interfaces: Vec::new(),
            family,
        }));
    }

    if !f.days.is_empty() || !f.hours.is_empty() {
        parts.push(Predicate::When(TimeMatch {
            days: f.days,
            hours: f.hours,
        }));
    }

    match parts.len() {
        0 => Predicate::All(Vec::new()),
        1 => parts.into_iter().next().expect("len checked"),
        _ => Predicate::All(parts),
    }
}

/// Split a free-text match field into tokens on comma / semicolon / newline (CR and LF) / tab —
/// **not** space. Item patterns legitimately contain spaces (Windows paths like `C:\Program Files\**`,
/// process names like `Adobe Desktop Service.exe`, day specs like `Mon - Fri`), so splitting on
/// space would shred them on the seed→flush round-trip. Each token is trimmed, so surrounding
/// whitespace after a comma is dropped while internal spaces are preserved.
pub fn split_list(s: &str) -> Vec<String> {
    s.split([',', ';', '\n', '\t', '\r'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

/// Map a connection's destination + resolved host onto the rule form's `(domains, ips, ports)`,
/// for prefilling "Create rule from connection". A non-empty `dest_host` becomes the host pattern;
/// a parseable `destination` socket becomes its IP and port (IPv6 brackets handled by
/// [`std::net::SocketAddr`]). An unparseable destination yields no IP/port — the host (if any)
/// still prefills. Both are intentionally seeded so the user deletes what they don't want rather
/// than typing it; note a fake-IP destination is ephemeral, so the host is the stable matcher.
pub fn conn_dest_fields(
    destination: &str,
    dest_host: Option<&str>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let domains = dest_host
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(|h| vec![h.to_string()])
        .unwrap_or_default();
    let (ips, ports) = match destination.parse::<std::net::SocketAddr>() {
        Ok(sa) => (vec![sa.ip().to_string()], vec![sa.port().to_string()]),
        Err(_) => (Vec::new(), Vec::new()),
    };
    (domains, ips, ports)
}

/// A name based on `base` not present in `taken` (the existing names). Returns `base` when free,
/// else `base 2`, `base 3`, … — the config validator rejects duplicate group names and duplicate
/// rule names within a group. Collects `taken` into a set once, so each candidate is an O(1)
/// lookup rather than a rescan.
fn unique_name<'a>(base: &str, taken: impl Iterator<Item = &'a str>) -> String {
    let taken: std::collections::HashSet<&str> = taken.collect();
    if !taken.contains(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base} {n}"))
        .find(|cand| !taken.contains(cand.as_str()))
        .expect("an unused name exists in an unbounded sequence")
}

/// A rule-group name based on `base` that doesn't collide with any existing group — used when
/// create-rule must append a fresh enabled group (all existing groups disabled).
pub fn unique_group_name(groups: &[RuleGroup], base: &str) -> String {
    unique_name(base, groups.iter().map(|g| g.name.as_str()))
}

/// A rule name based on `base` that doesn't collide within `rules` — so a second "Create rule"
/// (or "+ Add rule") for the same app doesn't build a config the validator rejects for a
/// duplicate rule name within the group.
pub fn unique_rule_name(rules: &[Rule], base: &str) -> String {
    unique_name(base, rules.iter().map(|r| r.name.as_str()))
}

/// Change a rule action's `kind`, clearing fields that become invalid. A `target` is a
/// proxy name for `Proxy`, a chain name for `Chain`, and unused for `Direct`/`Block`, so it
/// is cleared on ANY kind change — keeping it would silently reinterpret it as the wrong
/// kind (saving an invalid config, or, on a proxy/chain name collision, mis-routing).
/// `on_failure` (the failure policy) applies equally to `Proxy` and `Chain`, so it is
/// preserved across a Proxy<->Chain switch and cleared only when moving to a terminal
/// `Direct`/`Block` kind (where "failed to establish" has no meaning). Fields are left
/// untouched when the kind is unchanged (e.g. re-clicking the current chip keeps the target).
pub fn set_action_kind(action: &mut Action, new_kind: ActionType) {
    if action.kind != new_kind {
        action.target = None;
        if matches!(new_kind, ActionType::Direct | ActionType::Block) {
            action.on_failure = None;
        }
    }
    action.kind = new_kind;
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxroute_config::OnFailure;
    use rust_i18n::t;

    /// The i18n catalog must actually LOAD and RESOLVE — `t!` returns the key verbatim when it
    /// finds no translation, which shipped once (the split `en.yml`/`ru.yml` were mis-tagged
    /// `_version: 2`, the merged-format marker, so nothing resolved and the UI rendered raw keys
    /// like "tab.connections"). Assert a known key yields its VALUE (not the key) in every shipped locale.
    #[test]
    fn i18n_catalog_resolves_keys_in_each_locale() {
        // rust-i18n's active locale is a PROCESS-GLOBAL, and tests run in parallel — so hold the
        // shared lock (serializing any locale-mutating test) and restore the prior locale via the
        // guard's Drop, which runs even if an assertion below panics.
        let _g = LocaleGuard::acquire();
        rust_i18n::set_locale("en");
        assert_eq!(t!("tab.connections"), "Connections");
        assert_eq!(t!("button.copy"), "Copy");
        // Cover the comprehensive tranche too — one key per area (detail panel, enum displays,
        // table headers, form labels) so a missing/typoed key in any area fails here.
        assert_eq!(t!("detail.title"), "Connection details");
        assert_eq!(t!("conn_filter.blocked"), "Blocked");
        assert_eq!(t!("table.conn.destination"), "Destination");
        assert_eq!(t!("form.apps"), "apps");
        // Slice 4 areas: status bar, save feedback, badges, messages, log lines.
        assert_eq!(t!("status.running"), "running");
        assert_eq!(t!("save.applied"), "✓ configuration applied");
        assert_eq!(t!("badge.on"), "on");
        assert_eq!(t!("msg.no_connections"), "No connections to show.");
        assert_eq!(t!("log.blocked"), "BLOCKED");
        // Straggler tranche: config-header buttons + the running-profile line (construction-time
        // strings that a live language switch re-applies).
        assert_eq!(t!("button.save_apply"), "Save & apply");
        assert_eq!(t!("profile.running"), "Running profile");
        rust_i18n::set_locale("es");
        assert_eq!(t!("tab.connections"), "Conexiones");
        assert_eq!(t!("button.copy"), "Copiar");
        assert_eq!(t!("detail.title"), "Detalles de la conexión");
        assert_eq!(t!("conn_filter.blocked"), "Bloqueadas");
        assert_eq!(t!("table.conn.destination"), "Destino");
        assert_eq!(t!("form.apps"), "aplicaciones");
        assert_eq!(t!("status.running"), "en ejecución");
        assert_eq!(t!("save.applied"), "✓ configuración aplicada");
        assert_eq!(t!("badge.on"), "activo");
        assert_eq!(t!("msg.no_connections"), "No hay conexiones que mostrar.");
        assert_eq!(t!("log.blocked"), "BLOQUEADA");
        assert_eq!(t!("button.save_apply"), "Guardar y aplicar");
        assert_eq!(t!("profile.running"), "Perfil en ejecución");
        rust_i18n::set_locale("ru");
        assert_eq!(t!("tab.connections"), "Соединения");
        assert_eq!(t!("button.copy"), "Копировать");
        assert_eq!(t!("detail.title"), "Сведения о соединении");
        assert_eq!(t!("conn_filter.blocked"), "Заблокировано");
        assert_eq!(t!("table.conn.destination"), "Назначение");
        assert_eq!(t!("form.apps"), "приложения");
        assert_eq!(t!("status.running"), "работает");
        assert_eq!(t!("save.applied"), "✓ конфигурация применена");
        assert_eq!(t!("badge.on"), "вкл");
        assert_eq!(t!("msg.no_connections"), "Нет соединений для показа.");
        assert_eq!(t!("log.blocked"), "ЗАБЛОКИРОВАНО");
        assert_eq!(t!("button.save_apply"), "Сохранить и применить");
        assert_eq!(t!("profile.running"), "Запущенный профиль");
        // Fallback: under a locale with no catalog, `fallback = "en"` resolves keys to the English
        // value — never the raw key. This is what keeps a trailing `ru.yml` (keys not yet migrated
        // during the staged rollout) showing English instead of "tab.connections".
        rust_i18n::set_locale("xx-no-catalog");
        assert_eq!(t!("tab.connections"), "Connections");
    }

    /// Serializes locale-mutating tests and restores rust-i18n's process-global locale on drop
    /// (including a panicking assertion), so a test can never leak the global to a parallel or
    /// later test. Any future test that calls `set_locale` should take one first.
    struct LocaleGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: String,
    }
    impl LocaleGuard {
        fn acquire() -> Self {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
            Self {
                _lock: lock,
                prev: rust_i18n::locale().to_string(),
            }
        }
    }
    impl Drop for LocaleGuard {
        fn drop(&mut self) {
            rust_i18n::set_locale(&self.prev);
        }
    }

    /// The connections-view strings the i18n campaign missed: the row context menu +
    /// transient explain/check states. Assert each resolves (not the raw key) in every shipped locale,
    /// including the two interpolated ones.
    #[test]
    fn connections_view_strings_are_localized() {
        let _g = LocaleGuard::acquire();
        rust_i18n::set_locale("en");
        assert_eq!(
            t!("button.create_rule_for", app = "chrome.exe"),
            "Create rule for chrome.exe"
        );
        assert_eq!(t!("button.explain_routing"), "Explain routing");
        assert_eq!(t!("button.show_details"), "Show details");
        assert_eq!(t!("detail.explaining"), "explaining…");
        assert_eq!(
            t!("detail.explain_failed", error = "boom"),
            "explain failed: boom"
        );
        assert_eq!(t!("proxy.checking"), "checking…");
        rust_i18n::set_locale("es");
        assert_eq!(
            t!("button.create_rule_for", app = "chrome.exe"),
            "Crear regla para chrome.exe"
        );
        assert_eq!(t!("button.explain_routing"), "Explicar enrutamiento");
        assert_eq!(t!("button.show_details"), "Mostrar detalles");
        assert_eq!(t!("detail.explaining"), "explicando…");
        assert_eq!(
            t!("detail.explain_failed", error = "boom"),
            "la explicación falló: boom"
        );
        assert_eq!(t!("proxy.checking"), "comprobando…");
        rust_i18n::set_locale("ru");
        assert_eq!(
            t!("button.create_rule_for", app = "chrome.exe"),
            "Создать правило для chrome.exe"
        );
        assert_eq!(t!("button.explain_routing"), "Пояснить маршрутизацию");
        assert_eq!(t!("button.show_details"), "Показать сведения");
        assert_eq!(t!("detail.explaining"), "поясняю…");
        assert_eq!(
            t!("detail.explain_failed", error = "boom"),
            "не удалось пояснить: boom"
        );
        assert_eq!(t!("proxy.checking"), "проверяю…");
    }

    #[test]
    fn set_action_kind_clears_stale_target_across_kinds() {
        let mut a = Action {
            kind: ActionType::Proxy,
            target: Some("p1".into()),
            dns_mode: None,
            on_failure: Some(OnFailure::default()),
        };
        // Proxy -> Chain: the target (a proxy name) is cross-kind and cleared, but the
        // failure policy applies to both kinds and is preserved.
        set_action_kind(&mut a, ActionType::Chain);
        assert_eq!(a.kind, ActionType::Chain);
        assert!(
            a.target.is_none(),
            "a proxy target must not carry over to Chain"
        );
        assert_eq!(
            a.on_failure,
            Some(OnFailure::default()),
            "on_failure applies to both Proxy and Chain"
        );
        // Re-selecting the SAME kind keeps a freshly-picked target.
        a.target = Some("c1".into());
        set_action_kind(&mut a, ActionType::Chain);
        assert_eq!(a.target.as_deref(), Some("c1"));
        // Switching to a terminal kind clears both the target and the (now-inapplicable)
        // failure policy.
        set_action_kind(&mut a, ActionType::Direct);
        assert_eq!(a.kind, ActionType::Direct);
        assert!(a.target.is_none());
        assert!(a.on_failure.is_none());
    }

    #[test]
    fn round_trip_app_and_dest() {
        let pred = Predicate::All(vec![
            Predicate::App(AppMatch {
                names: vec!["chrome.exe".into()],
                ..Default::default()
            }),
            Predicate::Dest(DestMatch {
                domains: vec!["*.example.com".into()],
                ips: vec!["10.0.0.0/8".into()],
                ports: vec!["443".into()],
                protocol: vec![Protocol::Tcp],
            }),
        ]);
        let f = extract_rule_fields(&pred).expect("simple shape extracts");
        assert_eq!(f.apps, ["chrome.exe"]);
        assert_eq!(f.domains, ["*.example.com"]);
        assert_eq!(f.ports, ["443"]);
        assert!(f.tcp && !f.udp);

        let f2 = extract_rule_fields(&build_match(extract_rule_fields(&pred).unwrap()))
            .expect("rebuilt is still form-editable");
        assert_eq!(f2.apps, f.apps);
        assert_eq!(f2.domains, f.domains);
        assert_eq!(f2.ips, f.ips);
        assert_eq!(f2.ports, f.ports);
        assert_eq!((f2.tcp, f2.udp), (f.tcp, f.udp));
    }

    #[test]
    fn round_trip_advanced_app_net_time() {
        let pred = Predicate::All(vec![
            Predicate::App(AppMatch {
                names: vec!["app.exe".into()],
                paths: vec!["C:\\Corp\\**".into()],
                signed_by: Some("CN=Corp".into()),
                parent: vec!["launcher.exe".into()],
            }),
            Predicate::Net(NetMatch {
                interfaces: vec![],
                family: vec![AddrFamily::Ipv6],
            }),
            Predicate::When(TimeMatch {
                days: vec!["Mon-Fri".into()],
                hours: vec!["09:00-18:00".into()],
            }),
        ]);
        let f = extract_rule_fields(&pred).expect("advanced shape extracts");
        assert_eq!(f.app_paths, ["C:\\Corp\\**"]);
        assert_eq!(f.app_parent, ["launcher.exe"]);
        assert_eq!(f.signed_by, "CN=Corp");
        assert!(!f.v4 && f.v6);
        assert_eq!(f.days, ["Mon-Fri"]);
        assert_eq!(f.hours, ["09:00-18:00"]);

        // Round-trips cleanly through build_match.
        let f2 = extract_rule_fields(&build_match(extract_rule_fields(&pred).unwrap()))
            .expect("rebuilt advanced shape is still form-editable");
        assert_eq!(f2.app_paths, f.app_paths);
        assert_eq!(f2.signed_by, f.signed_by);
        assert_eq!((f2.v4, f2.v6), (f.v4, f.v6));
        assert_eq!(f2.days, f.days);
        assert_eq!(f2.hours, f.hours);
    }

    #[test]
    fn complex_match_stays_json_only() {
        // Any / Not, a network-interface match, or two of the same kind → not form-representable.
        assert!(extract_rule_fields(&Predicate::Any(vec![])).is_none());
        assert!(extract_rule_fields(&Predicate::Not(Box::new(Predicate::All(vec![])))).is_none());
        let net_ifaces = Predicate::Net(NetMatch {
            interfaces: vec!["Ethernet".into()],
            family: vec![],
        });
        assert!(extract_rule_fields(&net_ifaces).is_none());
        let two_apps = Predicate::All(vec![
            Predicate::App(AppMatch::default()),
            Predicate::App(AppMatch::default()),
        ]);
        assert!(extract_rule_fields(&two_apps).is_none());
    }

    #[test]
    fn app_with_paths_is_now_form_editable() {
        // Previously JSON-only; the advanced foldout now represents it.
        let app_paths = Predicate::App(AppMatch {
            paths: vec!["C:\\x\\**".into()],
            ..Default::default()
        });
        let f = extract_rule_fields(&app_paths).expect("app paths now extract");
        assert_eq!(f.app_paths, ["C:\\x\\**"]);
    }

    #[test]
    fn empty_is_match_all() {
        assert!(matches!(build_match(RuleFields::default()), Predicate::All(v) if v.is_empty()));
    }

    #[test]
    fn split_list_handles_separators() {
        assert_eq!(
            split_list("a.exe, b.exe;  c.exe\nd.exe"),
            ["a.exe", "b.exe", "c.exe", "d.exe"]
        );
        assert!(split_list("   ").is_empty());
    }

    #[test]
    fn split_list_preserves_internal_spaces() {
        // Regression for the F1 corruption: patterns that legitimately contain spaces (Windows
        // paths, process names, `Mon - Fri` day specs) must survive as ONE item, not be shredded.
        assert_eq!(
            split_list("C:\\Program Files\\**"),
            ["C:\\Program Files\\**"]
        );
        assert_eq!(
            split_list("C:\\Program Files\\**, D:\\Games\\*"),
            ["C:\\Program Files\\**", "D:\\Games\\*"]
        );
        assert_eq!(
            split_list("Adobe Desktop Service.exe"),
            ["Adobe Desktop Service.exe"]
        );
        assert_eq!(split_list("Mon - Fri, Sat"), ["Mon - Fri", "Sat"]);
        // The timespec parser also accepts whitespace around an HOUR range, so an
        // `09:00 - 18:00` window must round-trip through the form tokenizer as one item too.
        assert_eq!(split_list("09:00 - 18:00"), ["09:00 - 18:00"]);
    }

    #[test]
    fn form_round_trip_preserves_space_containing_patterns() {
        // Mirrors the GUI seed (`join(", ")`) → flush (`split_list`) round-trip on a rule whose
        // app name and path contain spaces — the exact F1 path that silently corrupted matches.
        let pred = Predicate::App(AppMatch {
            names: vec!["Adobe Desktop Service.exe".into()],
            paths: vec!["C:\\Program Files\\**".into()],
            ..Default::default()
        });
        let f = extract_rule_fields(&pred).expect("single App is form-representable");
        let apps = split_list(&f.apps.join(", "));
        let paths = split_list(&f.app_paths.join(", "));
        assert_eq!(apps, ["Adobe Desktop Service.exe"]);
        assert_eq!(paths, ["C:\\Program Files\\**"]);
        let rebuilt = build_match(RuleFields {
            apps,
            app_paths: paths,
            ..Default::default()
        });
        // Predicate isn't PartialEq, so re-extract and compare the fields.
        let re = extract_rule_fields(&rebuilt).expect("rebuilt is form-representable");
        assert_eq!(re.apps, ["Adobe Desktop Service.exe"]);
        assert_eq!(re.app_paths, ["C:\\Program Files\\**"]);
    }

    #[test]
    fn conn_dest_fields_splits_ipv4_socket() {
        let (domains, ips, ports) = conn_dest_fields("198.18.0.51:443", Some("cp.example.net"));
        assert_eq!(domains, ["cp.example.net"]);
        assert_eq!(ips, ["198.18.0.51"]);
        assert_eq!(ports, ["443"]);
    }

    #[test]
    fn conn_dest_fields_handles_ipv6_and_missing_host() {
        let (domains, ips, ports) = conn_dest_fields("[2001:db8::1]:8080", None);
        assert!(domains.is_empty());
        assert_eq!(ips, ["2001:db8::1"]);
        assert_eq!(ports, ["8080"]);
    }

    #[test]
    fn conn_dest_fields_unparseable_destination_keeps_host_only() {
        // A not-yet-resolved / malformed destination: no IP or port, but the host still prefills
        // (and is trimmed). The prefilled match stays form-editable.
        let (domains, ips, ports) = conn_dest_fields("pending", Some("  host.test  "));
        assert_eq!(domains, ["host.test"]);
        assert!(ips.is_empty() && ports.is_empty());

        let pred = build_match(RuleFields {
            apps: vec!["app.exe".into()],
            domains,
            ips,
            ports,
            ..Default::default()
        });
        assert!(extract_rule_fields(&pred).is_some());
    }

    fn group(name: &str) -> RuleGroup {
        RuleGroup {
            name: name.into(),
            enabled: true,
            rules: Vec::new(),
        }
    }

    #[test]
    fn unique_group_name_avoids_collisions() {
        assert_eq!(unique_group_name(&[], "default"), "default");
        assert_eq!(unique_group_name(&[group("main")], "default"), "default");
        assert_eq!(
            unique_group_name(&[group("default")], "default"),
            "default 2"
        );
        assert_eq!(
            unique_group_name(&[group("default"), group("default 2")], "default"),
            "default 3"
        );
        // A gap in the numbered sequence is reused rather than skipped.
        assert_eq!(
            unique_group_name(&[group("default"), group("default 3")], "default"),
            "default 2"
        );
    }

    fn rule(name: &str) -> Rule {
        Rule {
            name: name.into(),
            enabled: true,
            match_: Predicate::All(Vec::new()),
            action: Action {
                kind: ActionType::Direct,
                target: None,
                dns_mode: None,
                on_failure: None,
            },
        }
    }

    #[test]
    fn unique_rule_name_avoids_within_group_collisions() {
        assert_eq!(
            unique_rule_name(&[], "Rule for chrome.exe"),
            "Rule for chrome.exe"
        );
        assert_eq!(
            unique_rule_name(&[rule("Rule for chrome.exe")], "Rule for chrome.exe"),
            "Rule for chrome.exe 2"
        );
        // A name that only collides with another app's rule is left as-is.
        assert_eq!(
            unique_rule_name(&[rule("Rule for firefox.exe")], "Rule for chrome.exe"),
            "Rule for chrome.exe"
        );
    }
}
