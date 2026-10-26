//! Semantic configuration validation (schema v2).
//!
//! [`validate`] returns *every* problem it finds rather than failing on the
//! first, so the CLI and UI can present a complete list before applying a change
//!.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net};

use crate::schema::{
    Action, ActionType, ChainDns, ChainMode, Config, DestMatch, DnsMode, Ipv6Policy, OnFailure,
    OnHopFailure, Predicate, Profile, Protocol, ProxyAuth, ProxyDef, ProxyDnsResolution, ProxyKind,
    RedirectMode,
};

/// Severity of a [`ConfigIssue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Blocks applying the configuration.
    Error,
    /// Allowed, but worth surfacing.
    Warning,
}

/// Category of a [`ConfigIssue`], used by strict validation ([`enforce_strict`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    /// A general configuration problem or advisory.
    General,
    /// A schema feature that is modeled but not yet enforced by this build (e.g. proxy
    /// `priority`, chain `dns` placement / `onHopFailure`, split DNS, `signedBy`/`parent`
    /// matching, per-rule `dnsMode`). Under strict validation these warnings are upgraded to
    /// errors so a config can't silently rely on weaker-than-declared semantics.
    NotYetEnforced,
}

/// A single problem discovered during validation.
#[derive(Debug, Clone)]
pub struct ConfigIssue {
    pub severity: Severity,
    pub kind: IssueKind,
    /// Dotted path to the offending element, e.g. `profiles.work.chains`.
    pub location: String,
    pub message: String,
}

impl ConfigIssue {
    fn error(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            kind: IssueKind::General,
            location: location.into(),
            message: message.into(),
        }
    }

    fn warning(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            kind: IssueKind::General,
            location: location.into(),
            message: message.into(),
        }
    }

    /// A warning for a schema feature that is modeled but not yet enforced by this
    /// build. Identical to [`warning`](Self::warning) except it is tagged
    /// [`IssueKind::NotYetEnforced`], so strict validation upgrades it to an error.
    fn not_yet_enforced(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            kind: IssueKind::NotYetEnforced,
            location: location.into(),
            message: message.into(),
        }
    }
}

/// Upgrade every "modeled but not yet enforced" warning ([`IssueKind::NotYetEnforced`])
/// to an error — the `validate-config --strict` mode — so a config can't validate
/// while relying on schema features this build doesn't actually enforce. Leaves
/// general advisories (e.g. risky-but-allowed combinations) as warnings.
pub fn enforce_strict(issues: &mut [ConfigIssue]) {
    for issue in issues.iter_mut() {
        if issue.kind == IssueKind::NotYetEnforced {
            issue.severity = Severity::Error;
        }
    }
}

/// Validate a fully-deserialized configuration.
pub fn validate(cfg: &Config) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();

    if cfg.schema_version != crate::CURRENT_SCHEMA_VERSION {
        issues.push(ConfigIssue::error(
            "schemaVersion",
            format!(
                "config schemaVersion {} is not the supported {} (load() migrates/rejects, \
                 so this indicates a programmatically-built config)",
                cfg.schema_version,
                crate::CURRENT_SCHEMA_VERSION
            ),
        ));
    }

    if !cfg.profiles.iter().any(|p| p.name == cfg.active_profile) {
        issues.push(ConfigIssue::error(
            "activeProfile",
            format!(
                "activeProfile '{}' does not match any defined profile",
                cfg.active_profile
            ),
        ));
    }

    // Turning this off is legitimate — it is the switch for isolating a conflict with third-party
    // security software — but it is easy to set once while debugging and then forget, and the
    // symptom (proxied UDP/QUIC and proxy-mode DNS failing, but only on machines with a restrictive
    // inbound firewall policy) looks nothing like its cause. Surface it once, at config level, so
    // the setting is visible in `validate-config` rather than only in a running engine's log.
    if !cfg.redirect_auth {
        issues.push(ConfigIssue::warning(
            "redirectAuth",
            "redirectAuth is disabled, so the driver will not authorize our own redirected flows \
             at the ALE receive layer. On a machine with a restrictive inbound firewall policy \
             this blocks proxied UDP (QUIC) and proxy-mode DNS — in BOTH redirect modes, since UDP \
             is redirected at the IP layer even under 'ale'. Leave it enabled unless you are \
             deliberately ruling it out as the cause of a problem.",
        ));
    }

    validate_names_nonempty(cfg, &mut issues);

    let mut seen_profiles = HashSet::new();
    for p in &cfg.profiles {
        if !seen_profiles.insert(p.name.as_str()) {
            issues.push(ConfigIssue::error(
                format!("profiles.{}", p.name),
                "duplicate profile name",
            ));
        }
        validate_profile(cfg, p, &mut issues);
    }

    issues
}

fn validate_profile(cfg: &Config, p: &Profile, issues: &mut Vec<ConfigIssue>) {
    let loc = |field: &str| format!("profiles.{}.{}", p.name, field);

    // The redirect-mode knob interacts with loopback bypass: IP-layer redirect
    // cannot redirect loopback connections at all.
    if cfg.redirect_mode == RedirectMode::IpLayer && !p.bypass.loopback {
        issues.push(ConfigIssue::warning(
            loc("bypass.loopback"),
            "redirectMode 'ipLayer' cannot redirect loopback connections; \
             localhost will not be proxied even though bypass.loopback is false",
        ));
    }

    // Proxies: unique names, parseable endpoint, runtime-supportable features.
    let mut proxies_by_name: HashMap<&str, &ProxyDef> = HashMap::new();
    for proxy in &p.proxies {
        // Keep the FIRST definition authoritative: the downstream chain-hop checks
        // resolve hop names against this map, so overwriting on a duplicate would
        // silently let the LAST def drive those diagnostics. Still flag the duplicate
        // (validate() rejects the config regardless). The entry API does this in a
        // single lookup.
        match proxies_by_name.entry(proxy.name.as_str()) {
            std::collections::hash_map::Entry::Occupied(_) => issues.push(ConfigIssue::error(
                loc("proxies"),
                format!("duplicate proxy name '{}'", proxy.name),
            )),
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(proxy);
            }
        }
        if !endpoint_host_is_valid(&proxy.endpoint) {
            issues.push(ConfigIssue::error(
                loc("proxies"),
                format!(
                    "proxy '{}' endpoint '{}' is not a valid host:port (host must be an IP literal \
                     or a valid DNS name — not the unspecified 0.0.0.0/:: address — and the port \
                     must be non-zero)",
                    proxy.name, proxy.endpoint
                ),
            ));
        }
        validate_proxy_support(proxy, &loc("proxies"), issues);
        // `priority` is still modeled-but-unused (selection is name-based); warn so a config does
        // not look smarter than the engine. `healthCheck` IS consulted now (the monitor probes it
        // and the chain relay orders alternatives by it) — validate its shape instead of warning.
        if proxy.priority.is_some() {
            issues.push(ConfigIssue::not_yet_enforced(
                loc("proxies"),
                format!(
                    "proxy '{}' sets 'priority' but selection is not priority-based yet \
                     (ignored at runtime)",
                    proxy.name
                ),
            ));
        }
        if let Some(hc) = &proxy.health_check {
            // The monitor connects THROUGH the proxy to this target by IP (no remote DNS), so the
            // target must be an ip:port literal.
            match hc.target.parse::<std::net::SocketAddr>() {
                Err(_) => issues.push(ConfigIssue::error(
                    loc("proxies"),
                    format!(
                        "proxy '{}' healthCheck.target '{}' is not an ip:port literal",
                        proxy.name, hc.target
                    ),
                )),
                // SOCKS4/4a CONNECT carries a 4-byte IPv4 destination only, so an IPv6 target can
                // never be reached through them — the probe would report down forever. Reject it.
                Ok(addr)
                    if addr.is_ipv6()
                        && matches!(proxy.kind, ProxyKind::Socks4 | ProxyKind::Socks4a) =>
                {
                    issues.push(ConfigIssue::error(
                        loc("proxies"),
                        format!(
                            "proxy '{}' is {} (IPv4-only) but its healthCheck.target '{}' is IPv6 — \
                             the probe can never connect",
                            proxy.name,
                            proxy.kind.short_label(),
                            hc.target
                        ),
                    ));
                }
                // Port 0 / the unspecified address (0.0.0.0 / ::) parse fine but can
                // never be connected, so the probe would report the proxy down forever.
                Ok(addr) if is_unusable_endpoint_addr(&addr) => {
                    issues.push(ConfigIssue::error(
                        loc("proxies"),
                        format!(
                            "proxy '{}' healthCheck.target '{}' uses port 0 or the unspecified \
                             address (0.0.0.0 / ::), which the probe can never connect to",
                            proxy.name, hc.target
                        ),
                    ));
                }
                Ok(_) => {}
            }
            if hc.interval_sec == 0 {
                issues.push(ConfigIssue::error(
                    loc("proxies"),
                    format!(
                        "proxy '{}' healthCheck.intervalSec must be greater than 0",
                        proxy.name
                    ),
                ));
            }
        }
    }
    let proxy_names: HashSet<&str> = proxies_by_name.keys().copied().collect();

    // Chains: unique names, non-empty, hops reference known proxies.
    let mut chain_names = HashSet::new();
    let mut disabled_chains: HashSet<&str> = HashSet::new();
    for chain in &p.chains {
        if !chain_names.insert(chain.name.as_str()) {
            issues.push(ConfigIssue::error(
                loc("chains"),
                format!("duplicate chain name '{}'", chain.name),
            ));
        }
        if chain.enabled == Some(false) {
            disabled_chains.insert(chain.name.as_str());
        }
        if chain.hops.is_empty() {
            issues.push(ConfigIssue::error(
                loc("chains"),
                format!("chain '{}' has no hops", chain.name),
            ));
        }
        // All four modes are enforced now — `static` (sequential chain), `failover` / `roundRobin` /
        // `latency` (alternatives pool). `latency` orders by health-check RTT, so it can only sort
        // hops that HAVE a health check; warn about any that don't (no RTT → config-order fallback).
        if chain.mode == ChainMode::Latency {
            let unprobed: Vec<&str> = chain
                .hops
                .iter()
                .filter(|h| {
                    proxies_by_name
                        .get(h.as_str())
                        .is_some_and(|p| p.health_check.is_none())
                })
                .map(|h| h.as_str())
                .collect();
            if !unprobed.is_empty() {
                issues.push(ConfigIssue::warning(
                    loc("chains"),
                    format!(
                        "chain '{}' mode latency orders hops by health-check RTT, but these hops \
                         have no healthCheck and fall back to config order: {}",
                        chain.name,
                        unprobed.join(", ")
                    ),
                ));
            }
        }
        // `dns` placement: `firstHop` (resolve at the entry) and `lastHop` (default, resolve at the
        // exit) are enforced, so they don't warn. `perRule` is *modeled* to defer to the per-rule /
        // profile DNS, but per-rule DNS isn't honored yet, so it currently behaves as `lastHop` —
        // flag it as not-yet-enforced (so it doesn't pass `--strict` as if it were distinct).
        if chain.dns == ChainDns::PerRule {
            issues.push(ConfigIssue::not_yet_enforced(
                loc("chains"),
                format!(
                    "chain '{}' sets dns perRule but per-rule chain DNS is not enforced yet \
                     (it currently resolves at the exit, i.e. lastHop)",
                    chain.name
                ),
            ));
        }
        // `onHopFailure` is still modeled but not consulted by the chain relay — warn on a
        // non-default so the config does not over-promise.
        if chain.on_hop_failure != OnHopFailure::Report {
            issues.push(ConfigIssue::not_yet_enforced(
                loc("chains"),
                format!(
                    "chain '{}' sets onHopFailure {:?} but hop-failure handling is not enforced \
                     yet (a hop failure is reported)",
                    chain.name, chain.on_hop_failure
                ),
            ));
        }
        // UDP through a chain is nested SOCKS5 UDP encapsulation, so it works only for a `static`
        // chain whose every hop can speak SOCKS5 UDP. Routing fails such a flow CLOSED
        // (`CompiledPolicy::resolve_route`), so the cost of a mis-declared chain is dropped
        // datagrams rather than a leak — but silently dropped, which is worth warning about at
        // config time where the reason can be named precisely.
        //
        // Match routing's predicate exactly: an EMPTY `protocols` list means "unrestricted", so
        // such a chain carries UDP at runtime. Testing `contains(&Udp)` alone would let precisely
        // the mis-declared chains that drop datagrams escape every warning below — and the hop
        // check further down already spells the rule correctly, so the two disagreed.
        let declares_udp = chain.protocols.is_empty() || chain.protocols.contains(&Protocol::Udp);
        if declares_udp {
            if chain.mode != ChainMode::Static {
                issues.push(ConfigIssue::warning(
                    loc("chains"),
                    format!(
                        "chain '{}' declares UDP with mode '{:?}', but only 'static' chains carry \
                         UDP: the other modes are proxy pools, and a UDP flow routed here is \
                         dropped. Use mode 'static' for UDP, or scope this chain to TCP with \
                         protocols: [\"TCP\"] — an empty protocols list is unrestricted and still \
                         declares UDP (pooled proxies that can carry UDP still do so individually)",
                        chain.name, chain.mode
                    ),
                ));
            } else {
                let bad: Vec<&str> = chain
                    .hops
                    .iter()
                    .filter_map(|hn| p.proxies.iter().find(|px| &px.name == hn))
                    .filter(|px| {
                        !px.kind.supports_udp()
                            || !(px.protocols.is_empty() || px.protocols.contains(&Protocol::Udp))
                    })
                    .map(|px| px.name.as_str())
                    .collect();
                if !bad.is_empty() {
                    issues.push(ConfigIssue::warning(
                        loc("chains"),
                        format!(
                            "chain '{}' declares UDP, but these hops cannot carry it: {}. UDP \
                             needs SOCKS5 UDP ASSOCIATE at every hop, so a UDP flow routed here \
                             is dropped. Use socks5/socks5Tls hops that permit UDP in their \
                             protocols, or scope this chain to TCP with protocols: [\"TCP\"] — \
                             an empty protocols list is unrestricted and still declares UDP",
                            chain.name,
                            bad.join(", ")
                        ),
                    ));
                }
            }
        }
        for (i, hop) in chain.hops.iter().enumerate() {
            // Any proxy kind can be a chain hop: the relay speaks each hop's protocol
            // (SOCKS5/SOCKS4/4a/HTTP) over the prior hop's tunnel, TLS-wrapping a socks5Tls/https
            // hop first. An unknown reference is rejected here.
            let Some(def) = proxies_by_name.get(hop.as_str()) else {
                issues.push(ConfigIssue::error(
                    loc("chains"),
                    format!("chain '{}' references unknown proxy '{}'", chain.name, hop),
                ));
                continue;
            };
            // SOCKS4/4a CONNECT encodes a 4-byte IPv4 address only, so such a hop can't carry IPv6.
            // Only a `static` chain traverses hops in order (hop i CONNECTs to hop i+1); the other
            // modes treat hops as independent alternatives that each CONNECT straight to the
            // destination. So the "next hop" check applies ONLY to a non-last static hop; in every
            // other case the SOCKS4/4a hop reaches the destination itself (an IPv4-only exit).
            if matches!(def.kind, ProxyKind::Socks4 | ProxyKind::Socks4a) {
                let next_static_hop = (chain.mode == ChainMode::Static)
                    .then(|| chain.hops.get(i + 1))
                    .flatten();
                match next_static_hop {
                    // Static, non-last: the inter-hop CONNECT targets the next hop's endpoint.
                    Some(next_name) => {
                        let next_is_v6 = proxies_by_name.get(next_name.as_str()).is_some_and(|n| {
                            n.endpoint
                                .parse::<std::net::SocketAddr>()
                                .is_ok_and(|a| a.is_ipv6())
                        });
                        if next_is_v6 {
                            issues.push(ConfigIssue::error(
                                loc("chains"),
                                format!(
                                    "chain '{}': hop '{}' is {} (IPv4-only) but the next hop '{}' \
                                     has an IPv6 endpoint — SOCKS4 CONNECT cannot reach it",
                                    chain.name,
                                    hop,
                                    def.kind.short_label(),
                                    next_name
                                ),
                            ));
                        }
                    }
                    // Reaches the destination itself (static last hop, or any alternative): it can't
                    // carry IPv6 destinations. Advisory, since the destination family is runtime.
                    None => issues.push(ConfigIssue::warning(
                        loc("chains"),
                        format!(
                            "chain '{}': hop '{}' is {} (IPv4-only), so it cannot carry IPv6 \
                             destinations (they fail at connect time)",
                            chain.name,
                            hop,
                            def.kind.short_label()
                        ),
                    )),
                }
            }
        }
    }

    // DNS fake-IP pool: valid CIDR, usable capacity, reserved/non-overlapping.
    if let Some(pool) = &p.dns.fake_ip_pool {
        validate_fake_ip_pool(pool, &loc("dns.fakeIpPool"), issues);
    }

    // Custom bypass ranges.
    for cidr in &p.bypass.custom_cidrs {
        if cidr.parse::<IpNet>().is_err() {
            issues.push(ConfigIssue::error(
                loc("bypass.customCidrs"),
                format!("invalid CIDR '{cidr}'"),
            ));
        }
    }

    // Rule groups: unique group names, and within each group unique rule names, valid
    // predicates, resolvable actions. Duplicate group names make routing explanations and
    // the GUI ambiguous (both render a "group/rule" label), so reject them.
    let mut rule_names = HashSet::new();
    let mut group_names = HashSet::new();
    for group in &p.rule_groups {
        if !group_names.insert(group.name.as_str()) {
            issues.push(ConfigIssue::error(
                loc(&format!("ruleGroups.{}", group.name)),
                "duplicate rule group name",
            ));
        }
        for rule in &group.rules {
            let rloc = loc(&format!("ruleGroups.{}.rules.{}", group.name, rule.name));
            if !rule_names.insert(format!("{}/{}", group.name, rule.name)) {
                issues.push(ConfigIssue::error(
                    &rloc,
                    "duplicate rule name within group",
                ));
            }
            validate_predicate(&rule.match_, &rloc, issues);
            validate_action(
                &rule.action,
                &proxy_names,
                &chain_names,
                &disabled_chains,
                &rloc,
                issues,
            );
        }
    }

    // --- Honest validation -------------------------------------------------
    // Surface policy that is modeled in the schema but not enforced by this
    // build, so the config never appears stronger or more capable than the
    // engine behaves (configuration must be trustworthy).
    if p.fail_closed.default && !p.fail_closed.kill_switch {
        issues.push(ConfigIssue::warning(
            loc("failClosed.default"),
            "failClosed.default does not survive the engine/driver stopping; for a durable \
             engine-down block set failClosed.killSwitch. While the engine runs, failClosed.apps \
             and per-connection proxy failures already fail closed.",
        ));
    }
    if p.fail_closed.kill_switch {
        issues.push(ConfigIssue::warning(
            loc("failClosed.killSwitch"),
            "failClosed.killSwitch installs a persistent WFP block that survives the engine exiting \
             and reboots — remove it with 'proxroute killswitch clear'. It needs a build with \
             the 'killswitch' feature (otherwise startup reports it unsupported).",
        ));
        // The kill-switch WFP filters are validated only with ALE redirect; their
        // coexistence with IP-layer redirect is not yet verified, so the engine-down
        // egress block may not behave as expected under 'ipLayer'. Warn loudly rather
        // than reject, so this combination can still be validated on a throwaway VM.
        if cfg.redirect_mode == RedirectMode::IpLayer {
            issues.push(ConfigIssue::warning(
                loc("failClosed.killSwitch"),
                "failClosed.killSwitch has only been validated with redirectMode 'ale'; its \
                 coexistence with 'ipLayer' redirect is NOT yet verified and engine-down egress \
                 protection may not behave as expected. Validate on a throwaway VM before relying \
                 on it, or use redirectMode 'ale'.",
            ));
        }
    }
    if p.dns.mode == DnsMode::Proxy && !p.proxies.iter().any(|x| x.kind == ProxyKind::Socks5) {
        issues.push(ConfigIssue::error(
            loc("dns.mode"),
            "dns.mode 'proxy' forwards DNS through a SOCKS5 proxy, but the profile defines none",
        ));
    }
    // Proxy-mode DNS forwarding target + upstream: make the choice explicit and
    // validated rather than implicitly "the first SOCKS5 proxy to 1.1.1.1:53".
    if let Some(name) = &p.dns.forward_proxy {
        match p.proxies.iter().find(|x| &x.name == name) {
            None => issues.push(ConfigIssue::error(
                loc("dns.forwardProxy"),
                format!("dns.forwardProxy '{name}' is not a defined proxy"),
            )),
            Some(x) if x.kind != ProxyKind::Socks5 => issues.push(ConfigIssue::error(
                loc("dns.forwardProxy"),
                format!(
                    "dns.forwardProxy '{name}' is {:?}; DNS is forwarded over SOCKS5 only",
                    x.kind
                ),
            )),
            Some(_) => {}
        }
    }
    if let Some(up) = &p.dns.upstream {
        match up.parse::<std::net::SocketAddr>() {
            Err(_) => issues.push(ConfigIssue::error(
                loc("dns.upstream"),
                format!(
                    "dns.upstream '{up}' is not a valid ip:port (the resolver queried through the \
                     proxy must be an IP literal)"
                ),
            )),
            Ok(a) if is_unusable_endpoint_addr(&a) => issues.push(ConfigIssue::error(
                loc("dns.upstream"),
                format!(
                    "dns.upstream '{up}' is not a usable resolver address (port 0 or the \
                     unspecified 0.0.0.0/:: address)"
                ),
            )),
            Ok(_) => {}
        }
    }
    for up in &p.dns.direct_upstreams {
        match up.parse::<std::net::SocketAddr>() {
            Err(_) => issues.push(ConfigIssue::error(
                loc("dns.directUpstreams"),
                format!("dns.directUpstreams entry '{up}' is not a valid ip:port resolver address"),
            )),
            Ok(a) if is_unusable_endpoint_addr(&a) => issues.push(ConfigIssue::error(
                loc("dns.directUpstreams"),
                format!(
                    "dns.directUpstreams entry '{up}' is not a usable resolver address (port 0 or \
                     the unspecified 0.0.0.0/:: address)"
                ),
            )),
            Ok(_) => {}
        }
    }
    // Under fake-IP / leak-prevention the OS resolver is disabled, so the proxy
    // endpoint (and direct-mode destination names) resolve via the *direct*
    // resolver's upstreams. With none configured those default to the host's system
    // DNS (or public DNS only if none can be enumerated) — nudge the user to pin an
    // internal resolver if they don't fully trust the host's DNS configuration.
    if (p.dns.mode == DnsMode::FakeIp || p.dns.leak_prevention) && p.dns.direct_upstreams.is_empty()
    {
        issues.push(ConfigIssue::warning(
            loc("dns.directUpstreams"),
            "under fake-IP / leak-prevention the OS resolver is disabled, so endpoint and \
             direct-mode names resolve via the host's system DNS servers — set \
             dns.directUpstreams to pin an internal resolver (startup fails closed if neither \
             pinned upstreams nor system DNS servers are available, rather than leaking to \
             public DNS)",
        ));
    }
    if p.dns.mode != DnsMode::Proxy && (p.dns.forward_proxy.is_some() || p.dns.upstream.is_some()) {
        issues.push(ConfigIssue::warning(
            loc("dns"),
            format!(
                "dns.forwardProxy/upstream apply only to dns.mode 'proxy' (current mode is \
                 '{:?}'); they are ignored",
                p.dns.mode
            ),
        ));
    }
    if p.dns.leak_prevention && !matches!(p.dns.mode, DnsMode::FakeIp | DnsMode::Proxy) {
        issues.push(ConfigIssue::warning(
            loc("dns.leakPrevention"),
            format!(
                "leakPrevention has no effect with dns.mode '{:?}'; leak-free remote resolution \
                 requires fakeIp or proxy",
                p.dns.mode
            ),
        ));
    }
    // Turning the DoH guard off while asking for leak prevention re-opens the one encrypted-DNS
    // path that reaches the wire unseen: a client pointed at an IP-literal DoH template performs
    // no lookup, so fake-IP capture and hostname rules never see the name. Reproduced on hardware
    // (a residual confirmed on hardware), which is why this warns rather than passing
    // quietly.
    if !p.dns.doh_guard && p.dns.mode == DnsMode::FakeIp {
        issues.push(ConfigIssue::warning(
            loc("dns.dohGuard"),
            concat!(
                "dohGuard is off while DNS mode is fakeIp: a client ",
                "configured with an IP-literal DoH template (e.g. https://1.1.1.1/dns-query) ",
                "resolves outside this engine's view, and unless an app or IP rule catches that ",
                "connection its lookups leave the machine. Leave it on unless a known resolver ",
                "endpoint must stay reachable on :443"
            )
            .to_string(),
        ));
    }
    if !p.dns.split.is_empty() {
        issues.push(ConfigIssue::not_yet_enforced(
            loc("dns.split"),
            "split DNS is not yet enforced; all names use the profile dns.mode",
        ));
    }

    // Domain-matching rules depend on recovering the destination hostname from a
    // prior DNS answer (reverse IP->name). That is reliable only under fakeIp
    // (one synthetic IP per name); other modes are best-effort or unavailable.
    let uses_domain_rules = p
        .rule_groups
        .iter()
        .flat_map(|g| &g.rules)
        .any(|r| predicate_uses_domains(&r.match_));
    if uses_domain_rules {
        match p.dns.mode {
            DnsMode::FakeIp => {}
            DnsMode::System => issues.push(ConfigIssue::warning(
                loc("dns.mode"),
                "domain-matching rules need DNS interception to recover hostnames, but dns.mode is \
                 'system' (DNS is not intercepted), so these rules can never match. Use 'fakeIp' \
                 (reliable) — or 'local'/'proxy' for best-effort matching",
            )),
            other => issues.push(ConfigIssue::warning(
                loc("dns.mode"),
                format!(
                    "domain-matching rules are best-effort with dns.mode '{other:?}': the hostname \
                     is recovered by reverse-mapping the destination IP, so on shared/CDN IPs the \
                     most recent lookup wins and a rule can match the wrong domain. Use 'fakeIp' \
                     for reliable domain rules (one synthetic IP per name)"
                ),
            )),
        }
    }

    if p.ipv6 == Ipv6Policy::BlockWhenProxied {
        issues.push(ConfigIssue::warning(
            loc("ipv6"),
            "ipv6 'blockWhenProxied' blocks internet-direct IPv6 while proxying is configured, so \
             an app's IPv6 can't leak around an IPv4 proxy via Happy-Eyeballs; loopback/LAN IPv6 \
             and IPv6 that is itself proxied are unaffected. Remove it to let IPv6 flow directly",
        ));
    }
}

/// Whether any node in a predicate tree constrains on destination domains.
fn predicate_uses_domains(p: &Predicate) -> bool {
    match p {
        Predicate::All(children) | Predicate::Any(children) => {
            children.iter().any(predicate_uses_domains)
        }
        Predicate::Not(child) => predicate_uses_domains(child),
        Predicate::Dest(dest) => !dest.domains.is_empty(),
        _ => false,
    }
}

fn validate_predicate(p: &Predicate, loc: &str, issues: &mut Vec<ConfigIssue>) {
    match p {
        Predicate::All(children) | Predicate::Any(children) => {
            for c in children {
                validate_predicate(c, loc, issues);
            }
        }
        Predicate::Not(child) => validate_predicate(child, loc, issues),
        Predicate::Dest(dest) => validate_dest(dest, loc, issues),
        Predicate::Net(net) => {
            if !net.interfaces.is_empty() {
                issues.push(ConfigIssue::error(
                    loc,
                    "'net.interfaces' matching is not implemented; a rule relying on it \
                     cannot be evaluated correctly (it would match every interface). \
                     Remove the 'interfaces' constraint until interface matching is supported",
                ));
            }
        }
        Predicate::When(when) => {
            // `when` is enforced against the local clock — validate the syntax so
            // a malformed spec is caught here rather than silently never matching.
            for d in &when.days {
                if crate::timespec::parse_day_spec(d).is_none() {
                    issues.push(ConfigIssue::error(
                        loc,
                        format!(
                            "invalid 'when' day '{d}' — use a weekday (Mon..Sun) or a range like \
                             Mon-Fri"
                        ),
                    ));
                }
            }
            for h in &when.hours {
                match crate::timespec::parse_hour_window(h) {
                    None => issues.push(ConfigIssue::error(
                        loc,
                        format!("invalid 'when' hours '{h}' - use a 24h window like 09:00-18:00"),
                    )),
                    // A zero-length window (start == end, e.g. 09:00-09:00) parses but the
                    // matcher never matches it (start > end is required to wrap), so the
                    // rule is silently dead. Reject it so the mistake surfaces.
                    Some((start, end)) if start == end => issues.push(ConfigIssue::error(
                        loc,
                        format!(
                            "'when' hours '{h}' is a zero-length window (start == end) that never \
                             matches; omit 'hours' for an all-day match, or use a non-empty window"
                        ),
                    )),
                    Some(_) => {}
                }
            }
        }
        Predicate::App(app) => {
            // signer / parent-process attributes are not collected at match time, so a rule that
            // requires either cannot be evaluated correctly: its semantics are unsound — bare or
            // under All/Any it never fires, but under Not it inverts to match EVERY flow. The
            // compiler forces such a rule to fail CLOSED (match-all + Block) regardless, so REJECT
            // it here (like net.interfaces above) rather than let a config that turns into a
            // block-everything rule load with only an advisory warning.
            if app.signed_by.is_some() {
                issues.push(ConfigIssue::error(
                    loc,
                    "app 'signedBy' matching is not implemented (code-signing data is not \
                     collected), so a rule that requires it cannot be evaluated correctly and is \
                     forced to block every flow that reaches it (fail closed). Remove the 'signedBy' constraint \
                     until signer matching is supported",
                ));
            }
            if !app.parent.is_empty() {
                issues.push(ConfigIssue::error(
                    loc,
                    "app 'parent' matching is not implemented (parent-process data is not \
                     collected), so a rule that requires it cannot be evaluated correctly and is \
                     forced to block every flow that reaches it (fail closed). Remove the 'parent' constraint \
                     until parent-process matching is supported",
                ));
            }
        }
    }
}

fn validate_dest(dest: &DestMatch, loc: &str, issues: &mut Vec<ConfigIssue>) {
    for ip in &dest.ips {
        if !is_ip_or_cidr(ip) {
            issues.push(ConfigIssue::error(
                loc,
                format!("invalid dest IP/CIDR '{ip}'"),
            ));
        }
    }
    for port in &dest.ports {
        match parse_port_spec(port) {
            None => issues.push(ConfigIssue::error(
                loc,
                format!("invalid dest port spec '{port}'"),
            )),
            // Port 0 is the wildcard/unspecified port, never a real destination: a rule naming it is
            // dead, and as a range start (`0-1024`) it is silently over-broad. Reject it so the typo
            // surfaces instead of compiling into a confusing rule.
            Some((0, _)) => issues.push(ConfigIssue::error(
                loc,
                format!("dest port spec '{port}' includes port 0, which is not a valid destination port"),
            )),
            Some(_) => {}
        }
    }
}

fn validate_action(
    action: &Action,
    proxy_names: &HashSet<&str>,
    chain_names: &HashSet<&str>,
    disabled_chains: &HashSet<&str>,
    loc: &str,
    issues: &mut Vec<ConfigIssue>,
) {
    match action.kind {
        ActionType::Proxy => match &action.target {
            Some(t) if proxy_names.contains(t.as_str()) => {}
            Some(t) => issues.push(ConfigIssue::error(
                loc,
                format!("action references unknown proxy '{t}'"),
            )),
            None => issues.push(ConfigIssue::error(loc, "proxy action is missing 'target'")),
        },
        ActionType::Chain => match &action.target {
            // A disabled chain is dropped at compile time, so a rule targeting it
            // fails closed at runtime — surface that rather than let it look valid.
            Some(t) if chain_names.contains(t.as_str()) => {
                if disabled_chains.contains(t.as_str()) {
                    issues.push(ConfigIssue::warning(
                        loc,
                        format!(
                            "action targets chain '{t}', which is disabled; matching traffic fails \
                             closed (blocked) until the chain is enabled"
                        ),
                    ));
                }
            }
            Some(t) => issues.push(ConfigIssue::error(
                loc,
                format!("action references unknown chain '{t}'"),
            )),
            None => issues.push(ConfigIssue::error(loc, "chain action is missing 'target'")),
        },
        ActionType::Direct | ActionType::Block => {}
    }

    // The relay always fails closed on a proxy/chain error; the fall-back modes
    // are not honored, so warn rather than silently behave differently.
    if matches!(
        action.on_failure,
        Some(OnFailure::Direct) | Some(OnFailure::Next)
    ) {
        issues.push(ConfigIssue::not_yet_enforced(
            loc,
            "onFailure 'direct'/'next' is not honored; the engine blocks (never falls back to \
             direct) when the proxy or chain fails",
        ));
    }

    // DNS is resolved at :53 interception, before a flow is matched to a rule, so
    // a per-action DNS override can't be applied — warn rather than ignore it.
    if action.dns_mode.is_some() {
        issues.push(ConfigIssue::not_yet_enforced(
            loc,
            "action 'dnsMode' is not honored: DNS is resolved before a flow is matched to a rule, \
             so the profile-wide dns.mode applies (per-rule DNS override is not yet supported)",
        ));
    }
}

/// Reject or flag proxy features this build cannot honor at runtime, so a
/// config never validates clean and then fails per-connection.
/// Reject empty/whitespace-only identifiers anywhere (profiles, proxies, chains, rule groups,
/// rules). An empty name is almost always a serialization/editor bug and yields ambiguous routing
/// explanations and GUI labels (the same class duplicate names are rejected for). The location uses
/// the parent's name, since the entity's own is blank.
fn validate_names_nonempty(cfg: &Config, issues: &mut Vec<ConfigIssue>) {
    let mut blank = |loc: String| {
        issues.push(ConfigIssue::error(
            loc,
            "name must not be empty".to_string(),
        ));
    };
    for p in &cfg.profiles {
        if p.name.trim().is_empty() {
            blank("profiles[].name".to_string());
        }
        for px in &p.proxies {
            if px.name.trim().is_empty() {
                blank(format!("profiles.{}.proxies[].name", p.name));
            }
        }
        for c in &p.chains {
            if c.name.trim().is_empty() {
                blank(format!("profiles.{}.chains[].name", p.name));
            }
        }
        for g in &p.rule_groups {
            if g.name.trim().is_empty() {
                blank(format!("profiles.{}.ruleGroups[].name", p.name));
            }
            for r in &g.rules {
                if r.name.trim().is_empty() {
                    blank(format!(
                        "profiles.{}.ruleGroups.{}.rules[].name",
                        p.name, g.name
                    ));
                }
            }
        }
    }
}

fn validate_proxy_support(proxy: &ProxyDef, loc: &str, issues: &mut Vec<ConfigIssue>) {
    // A TCP-only proxy kind (HTTP/HTTPS/SOCKS4/4a) carrying the default `[TCP, UDP]` is NOT an
    // error: routing blocks UDP to a non-UDP-capable proxy at runtime (fail closed — see
    // CompiledPolicy::resolve_route / kind_carries), so both TCP-only and TCP+UDP proxies are
    // first class and a rule may target either. UDP to a TCP-only proxy is blocked, not leaked.
    //
    // What IS an error: a proxy scoped to carry only the protocol its kind can't. A TCP-only kind
    // whose explicit `protocols` excludes TCP (leaving UDP only — `Protocol` is just TCP/UDP)
    // carries nothing: TCP is scoped out and UDP is blocked by the kind. Flag that unroutable proxy
    // rather than silently accept one no flow can ever use.
    if !proxy.protocols.is_empty()
        && !proxy.protocols.contains(&Protocol::Tcp)
        && !proxy.kind.supports_udp()
    {
        issues.push(ConfigIssue::error(
            loc,
            format!(
                "proxy '{}' is unroutable: scoped to UDP only, but its kind ({:?}) cannot carry UDP",
                proxy.name, proxy.kind
            ),
        ));
    }

    // Auth must be one this build implements for the proxy's kind.
    match (proxy.kind, &proxy.auth) {
        (_, ProxyAuth::None)
        | (ProxyKind::Socks5 | ProxyKind::Socks5Tls, ProxyAuth::UserPass { .. })
        | (
            ProxyKind::Http | ProxyKind::Https,
            ProxyAuth::Basic { .. } | ProxyAuth::Digest { .. },
        )
        | (ProxyKind::Https, ProxyAuth::Negotiate { .. }) => {}
        // Integrated auth over plaintext HTTP: the SSPI handshake would travel unprotected to an
        // unauthenticated peer, so anyone on the path could answer as the proxy and relay it. The
        // integrated-auth policy requires a verified TLS proxy (checked again at connect time).
        (ProxyKind::Http, ProxyAuth::Negotiate { .. }) => {
            issues.push(ConfigIssue::error(
                loc,
                format!(
                    "proxy '{}': 'negotiate' auth sends an integrated Windows sign-in and requires \
                     kind 'https' with certificate verification; over plaintext 'http' any host on \
                     the path can impersonate the proxy and capture or relay the handshake. Use the \
                     proxy's TLS (https) endpoint, or basic/digest auth",
                    proxy.name
                ),
            ));
        }
        (ProxyKind::Socks4 | ProxyKind::Socks4a, ProxyAuth::UserPass { .. }) => {
            issues.push(ConfigIssue::warning(
                loc,
                format!(
                    "proxy '{}': SOCKS4 has no password; only the username (USERID) is sent",
                    proxy.name
                ),
            ));
        }
        (kind, auth) => {
            issues.push(ConfigIssue::error(
                loc,
                format!(
                    "proxy '{}': '{}' auth is not supported for a {:?} proxy in this build",
                    proxy.name,
                    auth_name(auth),
                    kind
                ),
            ));
        }
    }

    // Catch a dropped/misspelled credential field. ProxyAuth is internally tagged, so the strict
    // unknown-key gate (serde_ignored) can't see a typo *inside* an auth block — e.g. "passwrod"
    // silently leaves `password` at its empty default, which would then fail auth at runtime with
    // an opaque error. Treat an empty username (any credential variant), or an empty password where
    // the scheme uses one, as an error so the typo surfaces here instead.
    let cred = match &proxy.auth {
        ProxyAuth::UserPass { username, password }
        | ProxyAuth::Basic { username, password }
        | ProxyAuth::Digest { username, password } => Some((username, password)),
        ProxyAuth::None | ProxyAuth::Negotiate { .. } => None,
    };
    if let Some((username, password)) = cred {
        if username.is_empty() {
            issues.push(ConfigIssue::error(
                loc,
                format!(
                    "proxy '{}': {} auth has an empty username (a missing or misspelled 'username'?)",
                    proxy.name,
                    auth_name(&proxy.auth)
                ),
            ));
        }
        // SOCKS4/4a sends only the username (USERID); every other credential scheme needs a password.
        let needs_password = !matches!(proxy.kind, ProxyKind::Socks4 | ProxyKind::Socks4a);
        if needs_password && password.is_empty() {
            issues.push(ConfigIssue::error(
                loc,
                format!(
                    "proxy '{}': {} auth has an empty password (a missing or misspelled 'password'?)",
                    proxy.name,
                    auth_name(&proxy.auth)
                ),
            ));
        }
        // A literal `<unchanged>` password collides with the redaction placeholder
        // (REDACTED_SECRET): on a GUI round-trip it is read as "keep the existing secret",
        // so the real value would be silently dropped. Reject it as an actual credential.
        if password.expose() == crate::REDACTED_SECRET {
            issues.push(ConfigIssue::error(
                loc,
                format!(
                    "proxy '{}': password must not be the literal '{}' — it collides with the \
                     redaction placeholder and would be treated as 'unchanged'",
                    proxy.name,
                    crate::REDACTED_SECRET
                ),
            ));
        }
    }

    // RFC 1929 (SOCKS5 username/password) caps each field at 255 bytes; the runtime
    // rejects longer credentials per-connection — for SOCKS5 *and* SOCKS5-over-TLS, which
    // share the same auth handshake — so fail the config up front instead of validating
    // clean and then failing every connection. (Lengths only — never the values.)
    if matches!(proxy.kind, ProxyKind::Socks5 | ProxyKind::Socks5Tls) {
        if let ProxyAuth::UserPass { username, password } = &proxy.auth {
            if username.len() > 255 {
                issues.push(ConfigIssue::error(
                    loc,
                    format!(
                        "proxy '{}': SOCKS5 username is {} bytes (max 255 per RFC 1929)",
                        proxy.name,
                        username.len()
                    ),
                ));
            }
            if password.expose().len() > 255 {
                issues.push(ConfigIssue::error(
                    loc,
                    format!(
                        "proxy '{}': SOCKS5 password is {} bytes (max 255 per RFC 1929)",
                        proxy.name,
                        password.expose().len()
                    ),
                ));
            }
        }
    }

    // Negotiate (NTLM/Kerberos) authenticates as the *process* identity with its ambient
    // credentials. Under the installed Windows service (LocalSystem) that is the computer account
    // (`HOST$`), not the logged-in user. The integrated-auth policy refuses a machine/service
    // identity at connect time unless this proxy opts in, so say which case the config is in.
    if let ProxyAuth::Negotiate {
        allow_service_identity,
    } = proxy.auth
    {
        if proxy.skip_verify {
            // Checked here rather than as a skipVerify warning below: for integrated auth an
            // unverified proxy certificate is not merely weaker, it hands the handshake to whoever
            // answers. The runtime refuses it as well.
            issues.push(ConfigIssue::error(
                loc,
                format!(
                    "proxy '{}': 'negotiate' auth cannot be combined with skipVerify — an integrated \
                     Windows sign-in is only sent to a proxy whose TLS certificate is verified. \
                     Remove skipVerify (trust the proxy's certificate in the Windows store instead)",
                    proxy.name
                ),
            ));
        }
        if allow_service_identity {
            issues.push(ConfigIssue::warning(
                loc,
                format!(
                    "proxy '{}' sets allowServiceIdentity: under the installed service (LocalSystem) \
                     'negotiate' authenticates to this proxy with the COMPUTER account. Channel \
                     binding and the proxy SPN limit, but do not rule out, relay of that \
                     authentication by a malicious or compromised proxy — enable it only for a \
                     proxy you trust",
                    proxy.name
                ),
            ));
        } else {
            issues.push(ConfigIssue::warning(
                loc,
                format!(
                    "proxy '{}' uses 'negotiate' auth, which authenticates as the process identity \
                     (the logged-in user for a foreground run). A machine or service identity — the \
                     installed LocalSystem service authenticates as the computer account — is \
                     refused unless auth.allowServiceIdentity is set for this proxy",
                    proxy.name
                ),
            ));
        }
    }

    // Per-proxy DNS resolution (remote/local) is not honored — DNS is governed
    // globally by the profile dns.mode. Surface the explicit `local` setting,
    // which is silently ignored (the default `remote` aligns with leak-free
    // resolution and isn't flagged).
    if proxy.dns == ProxyDnsResolution::Local {
        issues.push(ConfigIssue::not_yet_enforced(
            loc,
            format!(
                "proxy '{}' sets dns 'local', but per-proxy DNS is not honored; the profile \
                 dns.mode governs how destination names are resolved",
                proxy.name
            ),
        ));
    }

    // skipVerify is the single most security-weakening proxy knob, so — like every lesser one
    // above (negotiate, dns 'local', SOCKS4 no-password) — it must be surfaced, not pass silently.
    // For a TLS proxy kind it fully disables certificate validation at runtime (skip_verify=true ->
    // tls_client_config(skip_verify) -> insecure_tls_config, which accepts ANY certificate), removing the
    // only defense against an on-path attacker MITMing the tunnel and capturing the proxy
    // credentials plus all tunneled traffic. For a non-TLS kind it does nothing and is ignored, so
    // say that rather than let the operator believe it grants some protection.
    // (A negotiate proxy's skipVerify is already an error above.)
    if proxy.skip_verify && !matches!(proxy.auth, ProxyAuth::Negotiate { .. }) {
        if proxy.kind.is_tls() {
            issues.push(ConfigIssue::warning(
                loc,
                format!(
                    "proxy '{}' sets skipVerify, which disables TLS certificate validation for the \
                     proxy connection — an on-path attacker can silently MITM the tunnel and capture \
                     the proxy credentials and all tunneled traffic. Insecure; testing only (e.g. a \
                     self-signed proxy cert)",
                    proxy.name
                ),
            ));
        } else {
            issues.push(ConfigIssue::warning(
                loc,
                format!(
                    "proxy '{}' sets skipVerify, but its kind ({}) is not TLS-wrapped, so the \
                     setting has no effect and is ignored",
                    proxy.name,
                    proxy.kind.short_label()
                ),
            ));
        }
    }
}

/// Name of an auth variant for messages (never prints the secret).
fn auth_name(a: &ProxyAuth) -> &'static str {
    match a {
        ProxyAuth::None => "none",
        ProxyAuth::UserPass { .. } => "userPass",
        ProxyAuth::Basic { .. } => "basic",
        ProxyAuth::Digest { .. } => "digest",
        ProxyAuth::Negotiate { .. } => "negotiate",
    }
}

/// Parse a `host:port` or `[v6]:port` endpoint into its host and port. Rejects
/// **unbracketed** IPv6 (`2001:db8::1:1080`), which the runtime resolver can't
/// parse — shared with the engine's endpoint resolver so both agree on the form.
/// (Full DNS resolution still happens at runtime.)
pub fn parse_host_port(endpoint: &str) -> Option<(&str, u16)> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        // [v6]:port — the bracketed host must be a valid IPv6 literal.
        let (host, after) = rest.split_once(']')?;
        let port: u16 = after.strip_prefix(':')?.parse().ok()?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        Some((host, port))
    } else {
        let (host, port) = endpoint.rsplit_once(':')?;
        // A bare host containing ':' is an unbracketed IPv6 literal — reject it.
        if host.is_empty() || host.contains(':') {
            return None;
        }
        Some((host, port.parse().ok()?))
    }
}

/// Whether `host` is a syntactically valid DNS hostname: 1..=253 chars total,
/// dot-separated labels each 1..=63 chars of letters/digits/hyphen/underscore
/// (LDH + `_`), with no empty labels. Rejects spaces, slashes, control bytes, CRLF,
/// leading/trailing/double dots, and over-long labels — inputs that pass the bare
/// host:port shape check but then fail at resolution/TLS for every proxied flow.
fn is_valid_dns_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Whether a proxy endpoint is usable: a `host:port` whose host is an IP literal (v4,
/// or bracketed v6 as accepted by [`parse_host_port`]) or a valid DNS hostname, with a
/// non-zero port and a non-unspecified IP (0.0.0.0 / :: are rejected). Catches endpoints
/// that pass the shape check but fail every connection at runtime.
fn endpoint_host_is_valid(endpoint: &str) -> bool {
    match parse_host_port(endpoint) {
        // Port 0 (the wildcard port) and an unspecified IP literal (0.0.0.0 / ::) are
        // never a real proxy endpoint — an outbound connect to either fails — so reject
        // them here, mirroring the port-0 rejection validate_dest applies to destinations.
        Some((host, port)) => {
            port != 0
                && match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => !ip.is_unspecified(),
                    Err(_) => is_valid_dns_hostname(host),
                }
        }
        None => false,
    }
}

/// Whether a parsed `ip:port` is unusable as a resolver upstream or health-probe
/// target: port 0 (the wildcard port) or the unspecified address (0.0.0.0 / ::). Both
/// parse fine but can never be connected. Mirrors validate_dest's port-0 rejection.
fn is_unusable_endpoint_addr(addr: &std::net::SocketAddr) -> bool {
    addr.port() == 0 || addr.ip().is_unspecified()
}

fn is_ip_or_cidr(s: &str) -> bool {
    s.parse::<IpNet>().is_ok() || s.parse::<IpAddr>().is_ok()
}

/// Validate a fake-IP pool beyond syntax: it must be an IPv4 CIDR with usable
/// capacity, ideally in reserved space, and must not overlap ranges that have to
/// stay real (the handler classifies any destination inside the pool as
/// synthetic).
fn validate_fake_ip_pool(pool: &str, loc: &str, issues: &mut Vec<ConfigIssue>) {
    let net: IpNet = match pool.parse() {
        Ok(n) => n,
        Err(_) => {
            issues.push(ConfigIssue::error(
                loc,
                format!("invalid fake-IP pool CIDR '{pool}'"),
            ));
            return;
        }
    };
    let v4 = match net {
        IpNet::V4(v4) => v4,
        IpNet::V6(_) => {
            issues.push(ConfigIssue::warning(
                loc,
                format!(
                    "fake-IP pool '{pool}' is IPv6, but fake-IP is IPv4-only - it has no effect"
                ),
            ));
            return;
        }
    };
    // The allocator hands out network+1 .. broadcast-1, so /31 and /32 are empty.
    if v4.prefix_len() >= 31 {
        issues.push(ConfigIssue::error(
            loc,
            format!("fake-IP pool '{pool}' has no usable addresses (use at least a /30; default is /15)"),
        ));
    }
    if !is_reserved_fake_range(v4) {
        if let Some(what) = lan_like_overlap(v4) {
            issues.push(ConfigIssue::error(
                loc,
                format!("fake-IP pool '{pool}' overlaps {what}; real traffic there would be misclassified as synthetic"),
            ));
        } else {
            issues.push(ConfigIssue::warning(
                loc,
                format!("fake-IP pool '{pool}' is not a reserved range; synthetic IPs may shadow real destinations - prefer 198.18.0.0/15"),
            ));
        }
    }
}

/// Whether `net` is fully inside a range conventionally reserved for fake-IP use
/// (benchmarking, CGNAT, Class-E reserved, documentation).
fn is_reserved_fake_range(net: Ipv4Net) -> bool {
    const RESERVED: &[&str] = &[
        "198.18.0.0/15",   // RFC 2544 benchmarking (the default)
        "100.64.0.0/10",   // RFC 6598 CGNAT
        "240.0.0.0/4",     // reserved (Class E)
        "192.0.2.0/24",    // TEST-NET-1
        "198.51.100.0/24", // TEST-NET-2
        "203.0.113.0/24",  // TEST-NET-3
    ];
    RESERVED
        .iter()
        .filter_map(|s| s.parse::<Ipv4Net>().ok())
        .any(|r| r.contains(&net.network()) && r.contains(&net.broadcast()))
}

/// If `net` overlaps loopback / multicast / a LAN-private range, name it.
fn lan_like_overlap(net: Ipv4Net) -> Option<&'static str> {
    const RANGES: &[(&str, &str)] = &[
        ("127.0.0.0/8", "loopback"),
        ("224.0.0.0/4", "multicast"),
        ("10.0.0.0/8", "a private LAN range"),
        ("172.16.0.0/12", "a private LAN range"),
        ("192.168.0.0/16", "a private LAN range"),
        ("169.254.0.0/16", "link-local"),
    ];
    RANGES.iter().find_map(|(cidr, what)| {
        let r: Ipv4Net = cidr.parse().ok()?;
        (r.contains(&net.network()) || net.contains(&r.network())).then_some(*what)
    })
}

/// Parse `"443"` or `"8000-8100"` into an inclusive `(lo, hi)` range.
pub fn parse_port_spec(s: &str) -> Option<(u16, u16)> {
    match s.split_once('-') {
        Some((lo, hi)) => {
            let lo: u16 = lo.trim().parse().ok()?;
            let hi: u16 = hi.trim().parse().ok()?;
            if lo <= hi {
                Some((lo, hi))
            } else {
                None
            }
        }
        None => {
            let p: u16 = s.trim().parse().ok()?;
            Some((p, p))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        AppMatch, ChainDns, DestMatch, FailClosed, HealthCheck, HealthCheckKind, ProxyChain,
        ProxyDef, ProxyKind, Rule, RuleGroup, TimeMatch,
    };

    fn proxy(name: &str, endpoint: &str) -> ProxyDef {
        ProxyDef {
            name: name.into(),
            kind: ProxyKind::Socks5,
            endpoint: endpoint.into(),
            protocols: vec![],
            auth: Default::default(),
            dns: Default::default(),
            priority: None,
            health_check: None,
            skip_verify: false,
            udp_use_proxy_host: false,
        }
    }

    fn kill_switch_cfg(redirect_mode: RedirectMode) -> Config {
        let profile = Profile {
            name: "default".into(),
            fail_closed: FailClosed {
                kill_switch: true,
                ..Default::default()
            },
            ..Default::default()
        };
        Config {
            schema_version: crate::CURRENT_SCHEMA_VERSION,
            log_level: Default::default(),
            redirect_mode,
            redirect_auth: true,
            active_profile: "default".into(),
            profiles: vec![profile],
        }
    }

    #[test]
    fn warns_when_redirect_auth_is_disabled_but_not_when_enabled() {
        // Disabling is legitimate (it is the isolate-a-conflict switch), so this must WARN, never
        // reject — and it must be silent in the default/enabled case, or every config would carry a
        // permanent warning and operators would learn to ignore the whole list.
        // Match issues by the structured `location`, not by message substring: the message is free
        // to be reworded, and a substring match would also miss a redirectAuth error whose text
        // happens not to contain the key.
        let mut cfg = kill_switch_cfg(RedirectMode::default());
        cfg.redirect_auth = false;
        let issues = validate(&cfg);
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Warning && i.location == "redirectAuth"),
            "a disabled redirectAuth must warn: {issues:?}"
        );
        assert!(
            issues
                .iter()
                .all(|i| !(i.severity == Severity::Error && i.location == "redirectAuth")),
            "it must warn, not reject: {issues:?}"
        );

        cfg.redirect_auth = true;
        assert!(
            !validate(&cfg).iter().any(|i| i.location == "redirectAuth"),
            "the default (enabled) must produce no redirectAuth issue"
        );
    }

    #[test]
    fn warns_when_doh_guard_is_off_under_fake_ip_but_not_in_other_dns_modes() {
        // The guard only runs under fakeIp (redirect.rs scopes it to the fake pool), so warning in
        // `local`/`proxy` would be advice about a setting that has no effect there — the fastest
        // way to teach an operator to skim past the whole list. Match on `location`, not message
        // text, for the reason the redirectAuth test above gives.
        let mut cfg = kill_switch_cfg(RedirectMode::default());
        cfg.profiles[0].dns.mode = DnsMode::FakeIp;
        cfg.profiles[0].dns.doh_guard = false;
        assert!(
            validate(&cfg)
                .iter()
                .any(|i| i.severity == Severity::Warning
                    && i.location == "profiles.default.dns.dohGuard"),
            "dohGuard off under fakeIp must warn"
        );

        cfg.profiles[0].dns.doh_guard = true;
        assert!(
            !validate(&cfg)
                .iter()
                .any(|i| i.location == "profiles.default.dns.dohGuard"),
            "the default (on) must be silent, or every config carries a permanent warning"
        );

        cfg.profiles[0].dns.doh_guard = false;
        for mode in [DnsMode::System, DnsMode::Local, DnsMode::Proxy] {
            cfg.profiles[0].dns.mode = mode;
            assert!(
                !validate(&cfg)
                    .iter()
                    .any(|i| i.location == "profiles.default.dns.dohGuard"),
                "{mode:?} never runs the guard, so there is nothing to warn about"
            );
        }
    }

    #[test]
    fn warns_on_ip_layer_with_kill_switch() {
        let needle = "only been validated with redirectMode 'ale'";
        // ipLayer + killSwitch is unverified -> must warn (but not error: validation
        // still passes so the combo can be tested on a VM).
        let issues = validate(&kill_switch_cfg(RedirectMode::IpLayer));
        assert!(
            issues.iter().any(|i| i.message.contains(needle)),
            "ipLayer + killSwitch must warn about the unverified combination"
        );
        assert!(
            issues.iter().all(|i| i.severity != Severity::Error),
            "the combination must warn, not reject"
        );
        // The default (ALE) redirect mode is the validated combination — no such warning.
        let ale = validate(&kill_switch_cfg(RedirectMode::default()));
        assert!(
            !ale.iter().any(|i| i.message.contains(needle)),
            "ALE mode must not raise the ipLayer-combination warning"
        );
    }

    fn cfg_with_profile(profile: Profile) -> Config {
        Config {
            schema_version: crate::CURRENT_SCHEMA_VERSION,
            log_level: Default::default(),
            redirect_mode: RedirectMode::default(),
            redirect_auth: true,
            active_profile: profile.name.clone(),
            profiles: vec![profile],
        }
    }

    #[test]
    fn socks5_tls_oversized_credentials_are_rejected() {
        // The 255-byte RFC 1929 credential cap must cover SOCKS5-over-TLS too (same auth
        // handshake) — otherwise a long-credential socks5Tls proxy validates clean, then fails
        // every connection.
        let mut px = proxy("P", "proxy.example.com:443");
        px.kind = ProxyKind::Socks5Tls;
        px.auth = ProxyAuth::UserPass {
            username: "u".repeat(300),
            password: "p".into(),
        };
        let issues = validate(&cfg_with_profile(Profile {
            name: "default".into(),
            proxies: vec![px],
            ..Default::default()
        }));
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains("255")),
            "socks5Tls username over 255 bytes must error: {issues:?}"
        );
    }

    #[test]
    fn skip_verify_on_a_tls_proxy_warns_but_does_not_reject() {
        // skipVerify disables TLS certificate validation — the single most security-weakening proxy
        // knob. It must be surfaced (like every lesser one), but NOT rejected: it is an intentional,
        // documented testing option (a self-signed proxy cert), so validation still passes.
        let mut px = proxy("P", "proxy.example.com:443");
        px.kind = ProxyKind::Socks5Tls;
        px.skip_verify = true;
        let issues = validate(&cfg_with_profile(Profile {
            name: "default".into(),
            proxies: vec![px],
            ..Default::default()
        }));
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Warning && i.message.contains("skipVerify")),
            "skipVerify on a TLS proxy must warn: {issues:?}"
        );
        assert!(
            issues.iter().all(|i| i.severity != Severity::Error),
            "skipVerify must warn, not reject: {issues:?}"
        );
    }

    fn negotiate_issues(kind: ProxyKind, skip_verify: bool, allow: bool) -> Vec<ConfigIssue> {
        let mut px = proxy("P", "proxy.example.com:443");
        px.kind = kind;
        px.skip_verify = skip_verify;
        px.auth = ProxyAuth::Negotiate {
            allow_service_identity: allow,
        };
        validate(&cfg_with_profile(Profile {
            name: "default".into(),
            proxies: vec![px],
            ..Default::default()
        }))
    }

    #[test]
    fn negotiate_over_plain_http_is_rejected() {
        // Integrated credentials over plaintext HTTP go to whoever answers on the path. Before the
        // integrated-auth policy this validated with a mere warning.
        let issues = negotiate_issues(ProxyKind::Http, false, false);
        assert!(
            issues.iter().any(|i| i.severity == Severity::Error
                && i.message.contains("'negotiate'")
                && i.message.contains("https")),
            "negotiate over http must be an error: {issues:?}"
        );
    }

    #[test]
    fn negotiate_with_skip_verify_is_rejected() {
        let issues = negotiate_issues(ProxyKind::Https, true, false);
        assert!(
            issues.iter().any(|i| i.severity == Severity::Error
                && i.message.contains("skipVerify")
                && i.message.contains("'negotiate'")),
            "negotiate + skipVerify must be an error: {issues:?}"
        );
    }

    #[test]
    fn negotiate_over_verified_https_is_allowed_with_a_policy_warning() {
        // The secure default: allowed, but the operator is told a service identity is refused.
        let issues = negotiate_issues(ProxyKind::Https, false, false);
        assert!(
            issues.iter().all(|i| i.severity != Severity::Error),
            "verified-https negotiate must validate: {issues:?}"
        );
        assert!(
            issues.iter().any(|i| i.severity == Severity::Warning
                && i.message
                    .contains("refused unless auth.allowServiceIdentity")),
            "the default policy must be explained: {issues:?}"
        );
        // Opting in is allowed too, with a warning that names the computer account and relay.
        let opted = negotiate_issues(ProxyKind::Https, false, true);
        assert!(
            opted.iter().all(|i| i.severity != Severity::Error),
            "{opted:?}"
        );
        assert!(
            opted.iter().any(|i| i.severity == Severity::Warning
                && i.message.contains("COMPUTER account")
                && i.message.contains("relay")),
            "allowServiceIdentity must warn about the computer account: {opted:?}"
        );
    }

    #[test]
    fn negotiate_policy_round_trips_and_defaults_off() {
        // `{"type":"negotiate"}` (every config written before the policy existed) means the secure
        // default; an explicit opt-in survives a save/load round-trip, and the default is not
        // serialized (so the document an older build wrote is unchanged).
        let def: ProxyAuth = serde_json::from_str(r#"{"type":"negotiate"}"#).unwrap();
        assert!(matches!(
            def,
            ProxyAuth::Negotiate {
                allow_service_identity: false
            }
        ));
        assert_eq!(
            serde_json::to_string(&def).unwrap(),
            r#"{"type":"negotiate"}"#
        );
        let on: ProxyAuth =
            serde_json::from_str(r#"{"type":"negotiate","allowServiceIdentity":true}"#).unwrap();
        let back: ProxyAuth = serde_json::from_str(&serde_json::to_string(&on).unwrap()).unwrap();
        assert!(matches!(
            back,
            ProxyAuth::Negotiate {
                allow_service_identity: true
            }
        ));
    }

    #[test]
    fn skip_verify_on_a_non_tls_proxy_warns_it_is_ignored() {
        // On a non-TLS kind skipVerify does nothing; warn that it is ignored rather than let the
        // operator believe it granted some protection.
        let mut px = proxy("P", "proxy.example.com:1080"); // SOCKS5 (non-TLS)
        px.skip_verify = true;
        let issues = validate(&cfg_with_profile(Profile {
            name: "default".into(),
            proxies: vec![px],
            ..Default::default()
        }));
        assert!(
            issues.iter().any(|i| i.severity == Severity::Warning
                && i.message.contains("skipVerify")
                && i.message.contains("ignored")),
            "skipVerify on a non-TLS proxy must warn it is ignored: {issues:?}"
        );
        // ...and it must stay a WARNING — an ignored setting is not a config error, so a future
        // change must not start rejecting this config (the same no-Error contract the TLS test pins).
        assert!(
            issues.iter().all(|i| i.severity != Severity::Error),
            "an ignored skipVerify must warn, not reject: {issues:?}"
        );
    }

    #[test]
    fn empty_credential_field_is_rejected() {
        // A misspelled credential key (e.g. "passwrod") deserializes to an empty Secret, which the
        // internally-tagged ProxyAuth hides from the strict unknown-key gate — so validation must
        // catch the resulting empty credential rather than letting it fail auth at runtime.
        let mut px = proxy("P", "proxy.example.com:1080"); // SOCKS5
        px.auth = ProxyAuth::UserPass {
            username: "u".into(),
            password: crate::Secret::new(""),
        };
        let issues = validate(&cfg_with_profile(Profile {
            name: "default".into(),
            proxies: vec![px],
            ..Default::default()
        }));
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains("empty password")),
            "an empty password must be a hard error: {issues:?}"
        );
    }

    #[test]
    fn empty_name_is_rejected() {
        // An empty/blank identifier (here a proxy name) is almost always a serialization bug.
        let mut px = proxy("", "proxy.example:1080");
        px.auth = ProxyAuth::None;
        let issues = validate(&cfg_with_profile(Profile {
            name: "default".into(),
            proxies: vec![px],
            ..Default::default()
        }));
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains("must not be empty")),
            "an empty proxy name must error: {issues:?}"
        );
    }

    #[test]
    fn duplicate_rule_group_names_are_rejected() {
        let group = |name: &str| RuleGroup {
            name: name.into(),
            enabled: true,
            rules: vec![],
        };
        let issues = validate(&cfg_with_profile(Profile {
            name: "default".into(),
            rule_groups: vec![group("default"), group("default")],
            ..Default::default()
        }));
        assert!(
            issues.iter().any(|i| i.severity == Severity::Error
                && i.message.contains("duplicate rule group name")),
            "two rule groups with the same name must error: {issues:?}"
        );
    }

    #[test]
    fn endpoint_host_validation_accepts_ip_and_dns_rejects_junk() {
        // Valid: IPv4 / bracketed IPv6 literals and well-formed DNS names.
        assert!(endpoint_host_is_valid("10.0.0.1:1080"));
        assert!(endpoint_host_is_valid("[2001:db8::1]:1080"));
        assert!(endpoint_host_is_valid("proxy.corp:8080"));
        assert!(endpoint_host_is_valid("a-b_c.example.com:443"));
        // Invalid: space, slash, CRLF, empty/over-long labels, missing port.
        assert!(!endpoint_host_is_valid("bad host:1080"));
        assert!(!endpoint_host_is_valid("host/name:1080"));
        assert!(!endpoint_host_is_valid("ho\r\nst:1080"));
        assert!(!endpoint_host_is_valid("a..b:1080"));
        assert!(!endpoint_host_is_valid(".lead:1080"));
        assert!(!endpoint_host_is_valid("trail.:1080"));
        assert!(!endpoint_host_is_valid(&format!(
            "{}.com:1080",
            "a".repeat(64)
        )));
        assert!(!endpoint_host_is_valid("noport"));
    }

    #[test]
    fn flags_oversized_socks5_credentials() {
        // RFC 1929 caps user/pass at 255 bytes; a longer cred must fail validation
        // (not just at connect time) — and the message must not leak the value.
        let mut p = proxy("big", "127.0.0.1:1080");
        p.auth = ProxyAuth::UserPass {
            username: "u".repeat(256),
            password: crate::Secret::new("x"),
        };
        let profile = Profile {
            name: "d".into(),
            proxies: vec![p],
            ..Default::default()
        };
        let msgs = messages(profile);
        assert!(
            msgs.iter().any(|m| m.contains("username is 256 bytes")),
            "expected an oversize-username error: {msgs:?}"
        );
    }

    #[test]
    fn flags_dangling_references_and_bad_specs() {
        let group = RuleGroup {
            name: "g".into(),
            enabled: true,
            rules: vec![Rule {
                name: "r".into(),
                enabled: true,
                match_: Predicate::All(vec![
                    Predicate::App(AppMatch::default()),
                    Predicate::Dest(DestMatch {
                        ips: vec!["nope".into()],
                        ports: vec!["8000-1".into(), "0".into()],
                        ..Default::default()
                    }),
                ]),
                action: Action {
                    kind: ActionType::Chain,
                    target: Some("Missing".into()),
                    dns_mode: None,
                    on_failure: None,
                },
            }],
        };
        let profile = Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080")],
            chains: vec![ProxyChain {
                name: "Bad".into(),
                mode: Default::default(),
                hops: vec!["A".into(), "Ghost".into()],
                protocols: vec![],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            rule_groups: vec![group],
            ..Default::default()
        };
        let cfg = Config {
            schema_version: crate::CURRENT_SCHEMA_VERSION,
            log_level: Default::default(),
            redirect_mode: Default::default(),
            redirect_auth: true,
            active_profile: "default".into(),
            profiles: vec![profile],
        };

        let issues = validate(&cfg);
        let msgs: Vec<&str> = issues.iter().map(|i| i.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("unknown proxy 'Ghost'")));
        assert!(msgs.iter().any(|m| m.contains("unknown chain 'Missing'")));
        assert!(msgs
            .iter()
            .any(|m| m.contains("invalid dest IP/CIDR 'nope'")));
        assert!(msgs
            .iter()
            .any(|m| m.contains("invalid dest port spec '8000-1'")));
        assert!(
            msgs.iter().any(|m| m.contains("includes port 0")),
            "port 0 must be rejected: {msgs:?}"
        );
    }

    #[test]
    fn port_spec_parsing() {
        assert_eq!(parse_port_spec("443"), Some((443, 443)));
        assert_eq!(parse_port_spec("8000-8100"), Some((8000, 8100)));
        assert_eq!(parse_port_spec("8100-8000"), None);
        assert_eq!(parse_port_spec("x"), None);
    }

    #[test]
    fn parse_host_port_handles_v6_bracketing() {
        assert_eq!(
            parse_host_port("example.com:1080"),
            Some(("example.com", 1080))
        );
        assert_eq!(parse_host_port("1.2.3.4:53"), Some(("1.2.3.4", 53)));
        assert_eq!(
            parse_host_port("[2001:db8::1]:1080"),
            Some(("2001:db8::1", 1080))
        );
        assert_eq!(parse_host_port("[::1]:53"), Some(("::1", 53)));
        // Unbracketed IPv6 is rejected (the runtime resolver can't parse it).
        assert_eq!(parse_host_port("2001:db8::1:1080"), None);
        assert_eq!(parse_host_port("noport"), None);
        assert_eq!(parse_host_port("host:bad"), None);
        assert_eq!(parse_host_port("[bad]:53"), None); // bracketed but not IPv6
        assert_eq!(parse_host_port(":53"), None); // empty host
    }

    #[test]
    fn fake_ip_pool_capacity_and_overlap() {
        let pool_profile = |pool: &str| {
            let mut p = Profile {
                name: "default".into(),
                ..Default::default()
            };
            p.dns.fake_ip_pool = Some(pool.into());
            p
        };
        let has = |pool: &str, s: &str| messages(pool_profile(pool)).iter().any(|m| m.contains(s));

        // The reserved default is clean.
        assert!(!has("198.18.0.0/15", "fake-IP pool"));
        // /32 has no usable addresses (error).
        assert!(has("198.18.0.0/32", "no usable addresses"));
        // Overlaps a private LAN range (error).
        assert!(has("10.10.0.0/16", "private LAN"));
        // Publicly routable (warning).
        assert!(has("8.8.0.0/16", "not a reserved range"));
        // IPv6 pool (warning — fake-IP is IPv4-only).
        assert!(has("fd00::/64", "IPv4-only"));
    }

    #[test]
    fn flags_kill_switch_persistence() {
        let mut profile = Profile {
            name: "default".into(),
            ..Default::default()
        };
        profile.fail_closed.kill_switch = true;
        let msgs = messages(profile);
        assert!(
            msgs.iter().any(|m| m.contains("persistent WFP block")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("killswitch clear")),
            "{msgs:?}"
        );
    }

    #[test]
    fn flags_unsupported_and_unenforced_features() {
        // HTTP with userPass is a kind/auth mismatch (HTTP uses basic/digest/
        // negotiate). Keep the profile SOCKS5-free so the proxy-DNS check fires.
        let mut bad_auth = proxy("d", "proxy.example:8080");
        bad_auth.kind = ProxyKind::Http;
        bad_auth.auth = ProxyAuth::UserPass {
            username: "u".into(),
            password: crate::Secret::new("x"),
        };
        let mut http_hop = proxy("hc", "proxy.example:8080");
        http_hop.kind = ProxyKind::Http;

        let rule = Rule {
            name: "r".into(),
            enabled: true,
            match_: Predicate::App(AppMatch::default()),
            action: Action {
                kind: ActionType::Proxy,
                target: Some("d".into()),
                dns_mode: None,
                on_failure: Some(OnFailure::Direct),
            },
        };
        let mut profile = Profile {
            name: "default".into(),
            proxies: vec![bad_auth, http_hop],
            chains: vec![ProxyChain {
                name: "c".into(),
                mode: Default::default(),
                hops: vec!["hc".into()],
                protocols: vec![],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            rule_groups: vec![RuleGroup {
                name: "g".into(),
                enabled: true,
                rules: vec![rule],
            }],
            ..Default::default()
        };
        profile.fail_closed.default = true;
        profile.dns.mode = DnsMode::Proxy;

        let cfg = Config {
            schema_version: crate::CURRENT_SCHEMA_VERSION,
            log_level: Default::default(),
            redirect_mode: Default::default(),
            redirect_auth: true,
            active_profile: "default".into(),
            profiles: vec![profile],
        };
        let msgs: Vec<String> = validate(&cfg).into_iter().map(|i| i.message).collect();
        let has = |s: &str| msgs.iter().any(|m| m.contains(s));
        assert!(has("'userPass' auth is not supported"), "{msgs:?}");
        // An HTTP chain hop is no longer rejected — assert the exact removed error is absent.
        assert!(!has("only SOCKS5 chain hops"), "{msgs:?}");
        assert!(has("failClosed.default does not survive"), "{msgs:?}");
        assert!(
            has("dns.mode 'proxy' forwards DNS through a SOCKS5 proxy"),
            "{msgs:?}"
        );
        assert!(has("onFailure"), "{msgs:?}");
    }

    #[test]
    fn mixed_kind_chain_hops_are_allowed() {
        // A chain may mix proxy kinds — the relay speaks each hop's protocol over the prior
        // tunnel, TLS-wrapping a socks5Tls/https hop. SOCKS5 + HTTP + HTTPS here: no hop error.
        let mut http = proxy("http", "proxy.example:8080");
        http.kind = ProxyKind::Http;
        let mut https = proxy("https", "proxy.example:443");
        https.kind = ProxyKind::Https;
        let profile = Profile {
            name: "default".into(),
            proxies: vec![proxy("s5", "127.0.0.1:1080"), http, https],
            chains: vec![ProxyChain {
                name: "c".into(),
                mode: Default::default(),
                hops: vec!["s5".into(), "http".into(), "https".into()],
                protocols: vec![],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            ..Default::default()
        };
        assert!(
            errors(profile).is_empty(),
            "a mixed-kind chain must validate without errors"
        );
    }

    fn with_kind(name: &str, endpoint: &str, kind: ProxyKind) -> ProxyDef {
        ProxyDef {
            kind,
            ..proxy(name, endpoint)
        }
    }

    /// A `mode` chain over `hops` with the given proxy defs.
    fn chain_profile_with_mode(proxies: Vec<ProxyDef>, hops: &[&str], mode: ChainMode) -> Profile {
        Profile {
            name: "default".into(),
            proxies,
            chains: vec![ProxyChain {
                name: "c".into(),
                mode,
                hops: hops.iter().map(|h| h.to_string()).collect(),
                protocols: vec![],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            ..Default::default()
        }
    }

    /// A static chain over `hops` with the given proxy defs.
    fn chain_profile(proxies: Vec<ProxyDef>, hops: &[&str]) -> Profile {
        chain_profile_with_mode(proxies, hops, ChainMode::Static)
    }

    #[test]
    fn socks4_hop_before_an_ipv6_endpoint_hop_is_rejected() {
        // SOCKS4 hop -> next hop with an IPv6 *literal* endpoint: the inter-hop CONNECT can't
        // express it, so this is a hard error.
        let errs = errors(chain_profile(
            vec![
                with_kind("s4", "1.2.3.4:1080", ProxyKind::Socks4),
                with_kind("exit", "[2001:db8::1]:1080", ProxyKind::Socks5),
            ],
            &["s4", "exit"],
        ));
        assert!(
            errs.iter()
                .any(|m| m.contains("SOCKS4 CONNECT cannot reach")),
            "{errs:?}"
        );
    }

    #[test]
    fn socks4_exit_hop_warns_the_chain_is_ipv4_only() {
        let msgs = messages(chain_profile(
            vec![
                with_kind("entry", "1.2.3.4:1080", ProxyKind::Socks5),
                with_kind("exit", "5.6.7.8:1080", ProxyKind::Socks4a),
            ],
            &["entry", "exit"],
        ));
        assert!(
            msgs.iter()
                .any(|m| m.contains("cannot carry IPv6 destinations")),
            "{msgs:?}"
        );
    }

    #[test]
    fn socks4_hop_before_a_hostname_endpoint_is_allowed() {
        // A hostname next-hop endpoint resolves at runtime (could be IPv4), so it is NOT statically
        // rejected — only an IPv6 *literal* endpoint is.
        let errs = errors(chain_profile(
            vec![
                with_kind("s4", "1.2.3.4:1080", ProxyKind::Socks4),
                with_kind("exit", "proxy.example:1080", ProxyKind::Socks5),
            ],
            &["s4", "exit"],
        ));
        assert!(
            !errs
                .iter()
                .any(|m| m.contains("SOCKS4 CONNECT cannot reach")),
            "a hostname next-hop must not be statically rejected: {errs:?}"
        );
    }

    #[test]
    fn socks4_in_a_non_static_chain_is_not_checked_against_the_next_hop() {
        // failover/roundRobin/latency treat hops as independent alternatives, NOT a sequential
        // path, so a SOCKS4 member must NOT be validated against the next member's endpoint (that
        // would be a false error). It IS flagged as an IPv4-only exit, since each alternative
        // reaches the destination directly.
        let msgs = messages(chain_profile_with_mode(
            vec![
                with_kind("s4", "1.2.3.4:1080", ProxyKind::Socks4),
                with_kind("alt", "[2001:db8::1]:1080", ProxyKind::Socks5),
            ],
            &["s4", "alt"],
            ChainMode::Failover,
        ));
        assert!(
            !msgs
                .iter()
                .any(|m| m.contains("SOCKS4 CONNECT cannot reach")),
            "alternatives must not be checked as a sequential path: {msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.contains("cannot carry IPv6 destinations")),
            "an alternative SOCKS4 hop reaches the destination directly (IPv4-only exit): {msgs:?}"
        );
    }

    #[test]
    fn all_socks5_chain_has_no_ipv4_only_warning() {
        let msgs = messages(chain_profile(
            vec![
                with_kind("a", "1.2.3.4:1080", ProxyKind::Socks5),
                with_kind("b", "5.6.7.8:1080", ProxyKind::Socks5),
            ],
            &["a", "b"],
        ));
        assert!(!msgs.iter().any(|m| m.contains("IPv4-only")), "{msgs:?}");
    }

    #[test]
    fn perrule_chain_dns_warns_but_firsthop_and_lasthop_do_not() {
        let warns = |dns: ChainDns| {
            let mut p = chain_profile(vec![proxy("A", "127.0.0.1:1080")], &["A"]);
            p.chains[0].dns = dns;
            messages(p).into_iter().any(|m| m.contains("perRule"))
        };
        assert!(
            warns(ChainDns::PerRule),
            "perRule warns it is not yet enforced"
        );
        assert!(
            !warns(ChainDns::FirstHop),
            "firstHop is enforced — no warning"
        );
        assert!(
            !warns(ChainDns::LastHop),
            "lastHop is the default — no warning"
        );
    }

    #[test]
    fn chain_hops_summary_annotates_kinds() {
        let mut https = proxy("Exit", "proxy.example:443");
        https.kind = ProxyKind::Https;
        let proxies = vec![proxy("Corp", "127.0.0.1:1080"), https];
        assert_eq!(
            crate::chain_hops_summary(&["Corp".to_string(), "Exit".to_string()], &proxies),
            "Corp (socks5) → Exit (https)"
        );
        // Unknown hop, and the empty case.
        assert_eq!(
            crate::chain_hops_summary(&["Ghost".to_string()], &proxies),
            "Ghost (?)"
        );
        assert_eq!(crate::chain_hops_summary(&[], &proxies), "(no hops)");
    }

    /// Validate a single profile and return just the issue messages.
    fn messages(profile: Profile) -> Vec<String> {
        let cfg = Config {
            schema_version: crate::CURRENT_SCHEMA_VERSION,
            log_level: Default::default(),
            redirect_mode: Default::default(),
            redirect_auth: true,
            active_profile: profile.name.clone(),
            profiles: vec![profile],
        };
        validate(&cfg).into_iter().map(|i| i.message).collect()
    }

    /// Error-severity messages only — what would actually block a save (warnings are advisory).
    fn errors(profile: Profile) -> Vec<String> {
        let cfg = Config {
            schema_version: crate::CURRENT_SCHEMA_VERSION,
            log_level: Default::default(),
            redirect_mode: Default::default(),
            redirect_auth: true,
            active_profile: profile.name.clone(),
            profiles: vec![profile],
        };
        validate(&cfg)
            .into_iter()
            .filter(|i| i.severity == Severity::Error)
            .map(|i| i.message)
            .collect()
    }

    #[test]
    fn zero_length_when_hour_window_is_rejected() {
        // start == end (e.g. 09:00-09:00) parses but the matcher never matches it, so the
        // rule would be silently dead — validation must reject it.
        for spec in ["09:00-09:00", "00:00-00:00"] {
            let mut issues = Vec::new();
            validate_predicate(
                &Predicate::When(TimeMatch {
                    days: vec![],
                    hours: vec![spec.to_string()],
                }),
                "rule",
                &mut issues,
            );
            assert!(
                issues
                    .iter()
                    .any(|i| i.severity == Severity::Error && i.message.contains("zero-length")),
                "{spec}: {issues:?}"
            );
        }
        // A normal window is still accepted.
        let mut ok = Vec::new();
        validate_predicate(
            &Predicate::When(TimeMatch {
                days: vec![],
                hours: vec!["09:00-18:00".into()],
            }),
            "rule",
            &mut ok,
        );
        assert!(ok.is_empty(), "{ok:?}");
    }

    #[test]
    fn resolver_upstreams_reject_port_zero_and_unspecified() {
        // Upstreams that parse but can never resolve (port 0 or 0.0.0.0/::) must be
        // rejected rather than validating clean and failing at runtime.
        for bad in ["1.1.1.1:0", "0.0.0.0:53", "[::]:53"] {
            let mut prof = Profile {
                name: "default".into(),
                proxies: vec![proxy("A", "127.0.0.1:1080")],
                ..Default::default()
            };
            prof.dns.upstream = Some(bad.to_string());
            prof.dns.direct_upstreams = vec![bad.to_string()];
            let errs = errors(prof);
            assert!(
                errs.iter()
                    .any(|m| m.contains("dns.upstream") && m.contains("usable")),
                "upstream {bad}: {errs:?}"
            );
            assert!(
                errs.iter()
                    .any(|m| m.contains("dns.directUpstreams") && m.contains("usable")),
                "directUpstreams {bad}: {errs:?}"
            );
        }
    }

    #[test]
    fn health_check_target_rejects_port_zero_and_unspecified() {
        // Both halves of the check: port 0 and the unspecified address (v4 here so the
        // result is independent of the proxy kind's IPv6 support).
        for bad in ["1.2.3.4:0", "0.0.0.0:80"] {
            let px = ProxyDef {
                health_check: Some(HealthCheck {
                    kind: HealthCheckKind::Connect,
                    target: bad.into(),
                    interval_sec: 30,
                }),
                ..proxy("A", "127.0.0.1:1080")
            };
            let errs = errors(Profile {
                name: "default".into(),
                proxies: vec![px],
                ..Default::default()
            });
            assert!(
                errs.iter()
                    .any(|m| m.contains("healthCheck.target") && m.contains("unspecified")),
                "{bad}: {errs:?}"
            );
        }
    }

    #[test]
    fn proxy_endpoint_with_port_zero_or_unspecified_is_rejected() {
        // host:0 (port 0) and the unspecified 0.0.0.0 / :: address parse as a shape but
        // can never be connected, so the endpoint must be rejected at config time.
        for bad in ["proxy.example.com:0", "0.0.0.0:1080", "[::]:1080"] {
            let errs = errors(Profile {
                name: "default".into(),
                proxies: vec![proxy("A", bad)],
                ..Default::default()
            });
            assert!(
                errs.iter()
                    .any(|m| m.contains("endpoint") && m.contains(bad)),
                "{bad}: {errs:?}"
            );
        }
    }

    #[test]
    fn duplicate_proxy_name_still_errors() {
        // Regression for the first-wins change: a duplicate name must still be reported.
        let errs = errors(Profile {
            name: "default".into(),
            proxies: vec![
                proxy("dup", "127.0.0.1:1080"),
                proxy("dup", "127.0.0.1:1081"),
            ],
            ..Default::default()
        });
        assert!(
            errs.iter()
                .any(|m| m.contains("duplicate proxy name 'dup'")),
            "{errs:?}"
        );
    }

    #[test]
    fn no_chain_mode_is_flagged_as_unimplemented() {
        // All four modes are enforced now — none should warn that it "is not implemented".
        for mode in [
            ChainMode::Static,
            ChainMode::Failover,
            ChainMode::RoundRobin,
            ChainMode::Latency,
        ] {
            let profile = Profile {
                name: "default".into(),
                proxies: vec![proxy("A", "127.0.0.1:1080")],
                chains: vec![ProxyChain {
                    name: "c".into(),
                    mode,
                    hops: vec!["A".into()],
                    protocols: vec![],
                    dns: Default::default(),
                    on_hop_failure: Default::default(),
                    enabled: None,
                }],
                ..Default::default()
            };
            assert!(
                !messages(profile)
                    .iter()
                    .any(|m| m.contains("is not implemented")),
                "{mode:?} should not warn as unimplemented"
            );
        }
    }

    #[test]
    fn latency_warns_only_about_hops_without_a_health_check() {
        let probed = ProxyDef {
            health_check: Some(HealthCheck {
                kind: HealthCheckKind::Connect,
                target: "1.1.1.1:443".into(),
                interval_sec: 30,
            }),
            ..proxy("probed", "127.0.0.1:1080")
        };
        let latency = |hops: Vec<&str>, proxies: Vec<ProxyDef>| {
            let profile = Profile {
                name: "default".into(),
                proxies,
                chains: vec![ProxyChain {
                    name: "c".into(),
                    mode: ChainMode::Latency,
                    hops: hops.into_iter().map(String::from).collect(),
                    protocols: vec![],
                    dns: Default::default(),
                    on_hop_failure: Default::default(),
                    enabled: None,
                }],
                ..Default::default()
            };
            messages(profile)
                .into_iter()
                .any(|m| m.contains("fall back to config order"))
        };
        // A hop without a health check → latency can't sort it → warn.
        assert!(
            latency(vec!["A"], vec![proxy("A", "127.0.0.1:1080")]),
            "unprobed hop warns"
        );
        // Every hop has a health check → no warning.
        assert!(
            !latency(vec!["probed"], vec![probed.clone()]),
            "fully-probed latency chain is clean"
        );
        // failover with an unprobed hop must NOT emit the latency-specific warning.
        let failover_profile = Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080")],
            chains: vec![ProxyChain {
                name: "c".into(),
                mode: ChainMode::Failover,
                hops: vec!["A".into()],
                protocols: vec![],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            ..Default::default()
        };
        assert!(
            !messages(failover_profile)
                .iter()
                .any(|m| m.contains("fall back to config order")),
            "failover does not emit the latency warning"
        );
    }

    #[test]
    fn strict_upgrades_only_not_yet_enforced_warnings() {
        // enforce_strict upgrades NotYetEnforced warnings to errors, but leaves a
        // general advisory warning and an existing error unchanged.
        let mut issues = vec![
            ConfigIssue::warning("a", "general advisory"),
            ConfigIssue::not_yet_enforced("b", "feature modeled but not enforced"),
            ConfigIssue::error("c", "hard error"),
        ];
        enforce_strict(&mut issues);
        assert_eq!(
            issues[0].severity,
            Severity::Warning,
            "general stays a warning"
        );
        assert_eq!(
            issues[1].severity,
            Severity::Error,
            "not-yet-enforced is upgraded"
        );
        assert_eq!(issues[2].severity, Severity::Error, "errors stay errors");
    }

    #[test]
    fn health_check_target_must_be_an_ip_port_literal() {
        let bad = ProxyDef {
            health_check: Some(HealthCheck {
                kind: HealthCheckKind::Connect,
                target: "example.com:443".into(), // a name, not an ip:port literal
                interval_sec: 30,
            }),
            ..proxy("A", "127.0.0.1:1080")
        };
        let errs = errors(Profile {
            name: "default".into(),
            proxies: vec![bad],
            ..Default::default()
        });
        assert!(
            errs.iter()
                .any(|m| m.contains("healthCheck.target") && m.contains("ip:port")),
            "{errs:?}"
        );
    }

    #[test]
    fn socks4_health_check_with_ipv6_target_is_rejected() {
        let bad = ProxyDef {
            kind: ProxyKind::Socks4,
            health_check: Some(HealthCheck {
                kind: HealthCheckKind::Connect,
                target: "[2001:db8::1]:443".into(), // IPv6 — unreachable via SOCKS4
                interval_sec: 30,
            }),
            ..proxy("A", "127.0.0.1:1080")
        };
        let errs = errors(Profile {
            name: "default".into(),
            proxies: vec![bad],
            ..Default::default()
        });
        assert!(
            errs.iter()
                .any(|m| m.contains("IPv4-only") && m.contains("IPv6")),
            "{errs:?}"
        );
    }

    #[test]
    fn health_check_interval_zero_is_an_error() {
        let bad = ProxyDef {
            health_check: Some(HealthCheck {
                kind: HealthCheckKind::Connect,
                target: "1.1.1.1:443".into(),
                interval_sec: 0,
            }),
            ..proxy("A", "127.0.0.1:1080")
        };
        let errs = errors(Profile {
            name: "default".into(),
            proxies: vec![bad],
            ..Default::default()
        });
        assert!(
            errs.iter().any(|m| m.contains("intervalSec must be")),
            "{errs:?}"
        );
    }

    #[test]
    fn valid_health_check_produces_no_issue() {
        let good = ProxyDef {
            health_check: Some(HealthCheck {
                kind: HealthCheckKind::Connect,
                target: "1.1.1.1:443".into(),
                interval_sec: 30,
            }),
            ..proxy("A", "127.0.0.1:1080")
        };
        let msgs = messages(Profile {
            name: "default".into(),
            proxies: vec![good],
            ..Default::default()
        });
        assert!(
            !msgs.iter().any(|m| m.contains("healthCheck")),
            "a valid health check is neither rejected nor warned: {msgs:?}"
        );
    }

    #[test]
    fn flags_ignored_action_dns_mode() {
        let profile = Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080")],
            rule_groups: vec![RuleGroup {
                name: "g".into(),
                enabled: true,
                rules: vec![Rule {
                    name: "r".into(),
                    enabled: true,
                    match_: Predicate::App(AppMatch::default()),
                    action: Action {
                        kind: ActionType::Proxy,
                        target: Some("A".into()),
                        dns_mode: Some(DnsMode::FakeIp),
                        on_failure: None,
                    },
                }],
            }],
            ..Default::default()
        };
        let msgs = messages(profile);
        assert!(
            msgs.iter()
                .any(|m| m.contains("action 'dnsMode' is not honored")),
            "{msgs:?}"
        );
    }

    #[test]
    fn flags_ipv6_block_when_proxied_behavior() {
        let profile = Profile {
            name: "default".into(),
            ipv6: Ipv6Policy::BlockWhenProxied,
            ..Default::default()
        };
        let msgs = messages(profile);
        assert!(
            msgs.iter()
                .any(|m| m.contains("blocks internet-direct IPv6 while proxying is configured")),
            "{msgs:?}"
        );
    }

    #[test]
    fn flags_domain_rules_outside_fake_ip() {
        let domain_rule = || RuleGroup {
            name: "g".into(),
            enabled: true,
            rules: vec![Rule {
                name: "r".into(),
                enabled: true,
                match_: Predicate::Dest(DestMatch {
                    domains: vec!["*.example.com".into()],
                    ..Default::default()
                }),
                action: Action {
                    kind: ActionType::Direct,
                    target: None,
                    dns_mode: None,
                    on_failure: None,
                },
            }],
        };

        // Default dns.mode = system -> domain rules can never match.
        let mut profile = Profile {
            name: "default".into(),
            rule_groups: vec![domain_rule()],
            ..Default::default()
        };
        assert!(
            messages(profile.clone())
                .iter()
                .any(|m| m.contains("can never match")),
            "system mode should warn that domain rules can't match"
        );

        // local mode -> best-effort (shared-IP ambiguity).
        profile.dns.mode = DnsMode::Local;
        assert!(
            messages(profile.clone())
                .iter()
                .any(|m| m.contains("best-effort")),
            "local mode should warn that domain rules are best-effort"
        );

        // fakeIp -> reliable, no warning.
        profile.dns.mode = DnsMode::FakeIp;
        assert!(
            !messages(profile)
                .iter()
                .any(|m| m.contains("domain-matching rules")),
            "fakeIp mode should not warn about domain rules"
        );
    }

    #[test]
    fn flags_dns_forward_proxy_and_upstream() {
        use crate::schema::DnsConfig;

        // forwardProxy must name a SOCKS5 proxy; upstream must be an ip:port.
        let mut http = proxy("H", "proxy.example:8080");
        http.kind = ProxyKind::Http;
        let profile = Profile {
            name: "default".into(),
            proxies: vec![http, proxy("S", "127.0.0.1:1080")],
            dns: DnsConfig {
                mode: DnsMode::Proxy,
                forward_proxy: Some("H".into()), // non-SOCKS5 -> error
                upstream: Some("not-an-addr".into()), // bad literal -> error
                ..Default::default()
            },
            ..Default::default()
        };
        let msgs = messages(profile);
        assert!(
            msgs.iter()
                .any(|m| m.contains("is Http; DNS is forwarded over SOCKS5 only")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.contains("dns.upstream 'not-an-addr' is not a valid ip:port")),
            "{msgs:?}"
        );

        // Unknown forwardProxy name -> error.
        let profile2 = Profile {
            name: "default".into(),
            proxies: vec![proxy("S", "127.0.0.1:1080")],
            dns: DnsConfig {
                mode: DnsMode::Proxy,
                forward_proxy: Some("ghost".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(messages(profile2)
            .iter()
            .any(|m| m.contains("dns.forwardProxy 'ghost' is not a defined proxy")));

        // forwardProxy with a non-proxy dns.mode -> warning (ignored).
        let profile3 = Profile {
            name: "default".into(),
            proxies: vec![proxy("S", "127.0.0.1:1080")],
            dns: DnsConfig {
                mode: DnsMode::FakeIp,
                forward_proxy: Some("S".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(messages(profile3)
            .iter()
            .any(|m| m.contains("apply only to dns.mode 'proxy'")));
    }

    #[test]
    fn flags_unhonored_proxy_dns_local() {
        let mut p = proxy("A", "127.0.0.1:1080");
        p.dns = crate::schema::ProxyDnsResolution::Local;
        let profile = Profile {
            name: "default".into(),
            proxies: vec![p],
            ..Default::default()
        };
        assert!(
            messages(profile)
                .iter()
                .any(|m| m.contains("sets dns 'local'")),
            "proxy dns:local should warn that per-proxy DNS isn't honored"
        );

        // The default `remote` must NOT warn (low noise).
        let remote = Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080")],
            ..Default::default()
        };
        assert!(
            !messages(remote)
                .iter()
                .any(|m| m.contains("per-proxy DNS is not honored")),
            "default dns:remote should not warn"
        );
    }

    #[test]
    fn a_static_all_socks5_chain_declaring_udp_is_silent() {
        // UDP through a static all-SOCKS5 chain is supported (nested SOCKS5 UDP encapsulation), so
        // declaring it must NOT warn. This replaced a test asserting the opposite, from when UDP
        // was never carried through chains.
        let profile = Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080"), proxy("B", "127.0.0.1:1081")],
            chains: vec![ProxyChain {
                name: "c".into(),
                mode: ChainMode::Static,
                hops: vec!["A".into(), "B".into()],
                protocols: vec![Protocol::Tcp, Protocol::Udp],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            ..Default::default()
        };
        let msgs = messages(profile);
        assert!(
            !msgs.iter().any(|m| m.contains("declares UDP")),
            "a supported UDP chain must not warn; got {msgs:?}"
        );
    }

    /// An EMPTY `protocols` list means "unrestricted", so such a chain carries UDP at runtime and
    /// must be warned about on exactly the same terms as one that names UDP explicitly.
    ///
    /// This is the predicate routing uses (`carries`: empty or contains). Testing
    /// `contains(&Udp)` alone let precisely the mis-declared chains that silently drop datagrams
    /// escape every warning — while the hop check a few lines below already spelled the rule
    /// correctly, so the two disagreed with each other.
    #[test]
    fn an_unrestricted_chain_is_warned_about_like_one_that_names_udp() {
        let mut http_hop = proxy("H", "127.0.0.1:8080");
        http_hop.kind = ProxyKind::Http;
        let unrestricted = |mode, hops: Vec<String>| Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080"), http_hop.clone()],
            chains: vec![ProxyChain {
                name: "c".into(),
                mode,
                hops,
                // Empty = unrestricted = carries UDP, without naming it.
                protocols: vec![],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            ..Default::default()
        };

        // Both remediations must name a fix that WORKS for an empty list: "drop UDP" resolves
        // nothing here — there is no `UDP` item to drop, and leaving the list empty keeps the
        // chain unrestricted, so the warning would persist forever. Scoping to TCP explicitly
        // (`protocols: ["TCP"]`) is the remediation that resolves it in every case — and the
        // pinned casing is deliberate: `Protocol` deserializes only the UPPERCASE spellings, so
        // the message must show the exact string a user can paste into their config.
        let pooled = unrestricted(ChainMode::Failover, vec!["A".into()]);
        assert!(
            messages(pooled)
                .iter()
                .any(|m| m.contains("only 'static' chains carry UDP")
                    && m.contains("protocols: [\"TCP\"]")),
            "an unrestricted pool-mode chain carries UDP at runtime, so it must warn — and the \
             remediation must be one an EMPTY protocols list can follow"
        );

        let bad_hop = unrestricted(ChainMode::Static, vec!["A".into(), "H".into()]);
        assert!(
            messages(bad_hop)
                .iter()
                .any(|m| m.contains("these hops cannot carry it")
                    && m.contains("protocols: [\"TCP\"]")),
            "an unrestricted chain with a UDP-incapable hop must warn and name the hop — and the \
             remediation must be one an EMPTY protocols list can follow"
        );
    }

    #[test]
    fn warns_when_a_udp_chain_cannot_actually_carry_udp() {
        // A non-static mode: the pool modes are not tunnels.
        let pooled = Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080")],
            chains: vec![ProxyChain {
                name: "c".into(),
                mode: ChainMode::Failover,
                hops: vec!["A".into()],
                protocols: vec![Protocol::Tcp, Protocol::Udp],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            ..Default::default()
        };
        assert!(
            messages(pooled)
                .iter()
                .any(|m| m.contains("only 'static' chains carry UDP")),
            "a pooled chain declaring UDP should say why"
        );

        // A hop kind with no UDP ASSOCIATE to nest — and the message must name the hop.
        let mut http_hop = proxy("H", "127.0.0.1:8080");
        http_hop.kind = ProxyKind::Http;
        let mixed = Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080"), http_hop],
            chains: vec![ProxyChain {
                name: "c".into(),
                mode: ChainMode::Static,
                hops: vec!["A".into(), "H".into()],
                protocols: vec![Protocol::Tcp, Protocol::Udp],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: None,
            }],
            ..Default::default()
        };
        let msgs = messages(mixed);
        assert!(
            msgs.iter()
                .any(|m| m.contains("cannot carry it") && m.contains('H')),
            "the warning must name the offending hop; got {msgs:?}"
        );
    }

    #[test]
    fn tcp_only_proxy_kind_with_default_protocols_is_valid() {
        // A TCP-only proxy KIND (HTTPS) carrying the default [TCP, UDP] is no longer a config
        // error: UDP routed to it is blocked at runtime (CompiledPolicy::resolve_route), so both
        // TCP-only and TCP+UDP proxies are first class and a rule may target either.
        let mut https = proxy("web", "127.0.0.1:443");
        https.kind = ProxyKind::Https;
        https.protocols = vec![Protocol::Tcp, Protocol::Udp];
        let profile = Profile {
            name: "default".into(),
            proxies: vec![https],
            ..Default::default()
        };
        assert!(
            errors(profile).is_empty(),
            "a TCP-only proxy kind with the default [TCP, UDP] must validate without errors"
        );
    }

    #[test]
    fn flags_udp_only_scope_on_tcp_only_kind_as_unroutable() {
        // protocols ["UDP"] on an HTTPS kind: TCP is scoped out and UDP is blocked by the kind, so
        // the proxy carries nothing — a hard error (unlike the default [TCP, UDP], which is fine).
        let mut https = proxy("web", "127.0.0.1:443");
        https.kind = ProxyKind::Https;
        https.protocols = vec![Protocol::Udp];
        let profile = Profile {
            name: "default".into(),
            proxies: vec![https],
            ..Default::default()
        };
        assert!(
            messages(profile).iter().any(|m| m.contains("unroutable")),
            "a UDP-only scope on a TCP-only kind should be flagged unroutable"
        );
    }

    #[test]
    fn flags_inert_signedby_and_parent() {
        let group = |match_: Predicate| RuleGroup {
            name: "g".into(),
            enabled: true,
            rules: vec![Rule {
                name: "r".into(),
                enabled: true,
                match_,
                action: Action {
                    kind: ActionType::Direct,
                    target: None,
                    dns_mode: None,
                    on_failure: None,
                },
            }],
        };

        let signed = Profile {
            name: "default".into(),
            rule_groups: vec![group(Predicate::App(AppMatch {
                signed_by: Some("CN=Acme".into()),
                ..Default::default()
            }))],
            ..Default::default()
        };
        assert!(
            errors(signed)
                .iter()
                .any(|m| m.contains("'signedBy' matching is not implemented")),
            "signedBy must be rejected: it can never match and is forced to block"
        );

        let parented = Profile {
            name: "default".into(),
            rule_groups: vec![group(Predicate::App(AppMatch {
                parent: vec!["explorer.exe".into()],
                ..Default::default()
            }))],
            ..Default::default()
        };
        assert!(
            errors(parented)
                .iter()
                .any(|m| m.contains("'parent' matching is not implemented")),
            "parent must be rejected: it can never match and is forced to block"
        );
    }

    #[test]
    fn flags_rule_targeting_disabled_chain() {
        let profile = Profile {
            name: "default".into(),
            proxies: vec![proxy("A", "127.0.0.1:1080")],
            chains: vec![ProxyChain {
                name: "off".into(),
                mode: Default::default(),
                hops: vec!["A".into()],
                protocols: vec![],
                dns: Default::default(),
                on_hop_failure: Default::default(),
                enabled: Some(false), // disabled
            }],
            rule_groups: vec![RuleGroup {
                name: "g".into(),
                enabled: true,
                rules: vec![Rule {
                    name: "r".into(),
                    enabled: true,
                    match_: Predicate::App(AppMatch::default()),
                    action: Action {
                        kind: ActionType::Chain,
                        target: Some("off".into()),
                        dns_mode: None,
                        on_failure: None,
                    },
                }],
            }],
            ..Default::default()
        };
        let msgs = messages(profile);
        assert!(
            msgs.iter().any(|m| m.contains("which is disabled")),
            "{msgs:?}"
        );
        // A disabled chain is still a *known* name — not an "unknown chain" error.
        assert!(
            !msgs.iter().any(|m| m.contains("unknown chain")),
            "{msgs:?}"
        );
    }
}
