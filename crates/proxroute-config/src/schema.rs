//! Serde types mirroring the Proxroute configuration JSON (schema v2).
//!
//! Field names use `camelCase` on the wire. See `docs/config-schema.md` for
//! the reference for the rationale behind
//! the v2 rule engine, proxy-protocol and DNS additions.

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

/// Top-level versioned configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub log_level: LogLevel,
    /// Driver TCP redirect mode (global). See [`RedirectMode`].
    #[serde(default)]
    pub redirect_mode: RedirectMode,
    /// Authorize our own redirected flows at the ALE receive layer (global; **on by default**;
    /// needs driver v1.2+).
    ///
    /// A redirected flow is reinjected on the RECEIVE path, so Windows classifies it as an
    /// unsolicited inbound connection to our listener and a restrictive inbound firewall policy —
    /// the default on many domain-joined machines — drops it. With this on, the driver permits
    /// exactly those flows: only ones whose tuple matches a live redirect mapping, never anything
    /// else, and it never touches Windows Firewall itself.
    ///
    /// This applies in **both** redirect modes, because the driver rewrites UDP through the
    /// IP-layer path even in `ale` — so turning it off can break proxied UDP (QUIC) and
    /// `dns.mode: proxy` on a machine with a restrictive inbound policy. TCP in `ale` mode is
    /// unaffected either way.
    ///
    /// Set to `false` only to rule this out as the cause of a problem: the driver installs a
    /// condition-less filter in a sub-layer above Windows Firewall, so if it ever conflicts with a
    /// third-party security product this is the switch that isolates it, without stopping the
    /// service. A pre-v1.2 driver ignores the setting (it warns and continues) either way.
    #[serde(default = "default_true")]
    pub redirect_auth: bool,
    pub active_profile: String,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

/// Log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warning,
    #[default]
    Info,
    Debug,
    Trace,
}

/// TCP redirect mode exposed by the proxroute driver.
///
/// `Ale` redirects at the ALE connect-redirect layer and **can redirect loopback
/// (localhost) connections**. `IpLayer` rewrites at the IP layer; it is useful
/// for some scenarios but **cannot redirect loopback connections** — choose
/// `Ale` if you need to proxy localhost traffic. Default is `Ale`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RedirectMode {
    #[default]
    Ale,
    IpLayer,
}

/// A self-contained, switchable routing setup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub bypass: Bypass,
    #[serde(default)]
    pub ipv6: Ipv6Policy,
    #[serde(default)]
    pub fail_closed: FailClosed,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub proxies: Vec<ProxyDef>,
    #[serde(default)]
    pub chains: Vec<ProxyChain>,
    #[serde(default)]
    pub rule_groups: Vec<RuleGroup>,
}

/// Traffic that always bypasses the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bypass {
    /// Bypass the built-in RFC1918 / link-local / multicast LAN ranges.
    #[serde(default = "default_true")]
    pub lan: bool,
    /// Bypass loopback (`127.0.0.0/8`, `::1`).
    #[serde(default = "default_true")]
    pub loopback: bool,
    /// Extra CIDR ranges to bypass.
    #[serde(default)]
    pub custom_cidrs: Vec<String>,
}

impl Default for Bypass {
    fn default() -> Self {
        Self {
            lan: true,
            loopback: true,
            custom_cidrs: Vec::new(),
        }
    }
}

/// IPv6 leak policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Ipv6Policy {
    /// Allow IPv6 to flow (proxied or direct) normally.
    #[default]
    Allow,
    /// Block internet-direct IPv6 whenever proxying is configured, so an app's IPv6
    /// can't leak around an IPv4 proxy via Happy-Eyeballs. Loopback/LAN IPv6 and
    /// IPv6 that is itself proxied (or fail-closed) are unaffected.
    BlockWhenProxied,
}

/// Fail-closed ("kill-switch") policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailClosed {
    /// Default behaviour when the engine/driver is unavailable: `false` =
    /// fail-open (passthrough), `true` = fail-closed. (Runtime hint; the durable
    /// engine-down guarantee is `killSwitch`.)
    #[serde(default)]
    pub default: bool,
    /// Apps that must always fail closed (blocked rather than leaked) while the
    /// engine runs (enforced at routing).
    #[serde(default)]
    pub apps: Vec<String>,
    /// Arm the persistent WFP kill-switch: a default-deny outbound block that
    /// survives the engine/service exiting, so traffic can't leak direct while
    /// the engine is down. **Opt-in** (off by default); removable with
    /// `proxroute killswitch clear`. Needs a build with the `killswitch`
    /// feature.
    #[serde(default)]
    pub kill_switch: bool,
    /// While the kill-switch is armed, also permit LAN (RFC1918) egress (DHCP and
    /// loopback are always permitted). Default `true`.
    #[serde(default = "default_true")]
    pub allow_lan: bool,
    /// While the kill-switch is armed, also permit DNS (`:53`) so the host can
    /// still resolve names (a metadata leak; set `false` for strict). Default
    /// `true`.
    #[serde(default = "default_true")]
    pub allow_dns: bool,
}

impl Default for FailClosed {
    fn default() -> Self {
        Self {
            default: false,
            apps: Vec::new(),
            kill_switch: false,
            allow_lan: true,
            allow_dns: true,
        }
    }
}

/// DNS handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfig {
    #[serde(default)]
    pub mode: DnsMode,
    /// Fake-IP pool (CIDR) used when `mode = fakeIp`. Defaults to `198.18.0.0/15`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fake_ip_pool: Option<String>,
    #[serde(default)]
    pub leak_prevention: bool,
    /// Sink connections to **known DoH resolver endpoints on :443** while **fake-IP** DNS is
    /// active,
    /// so a client configured with an IP-literal DoH template cannot resolve outside our view.
    /// Defaults to **true**.
    ///
    /// Unlike the `:853` DoT/DoQ guard this is a toggle, because `:443` is shared with the web.
    /// The guard is limited to addresses a provider publishes AS a DoH resolver (see
    /// `proxroute-engine::doh`) — but those are not DNS-*only*: `1.1.1.1` also serves `one.one.one.one`,
    /// and the guard sees a destination and a port, never a URL path, so a direct IP-literal
    /// request to one of them is sunk too. That accepted false positive, plus the blast radius
    /// `:853` does not have, is why this stays switchable.
    /// A *hostname* DoH template is visible under fake-IP mode — it resolves through our resolver
    /// and the connect carries the hostname — but visible is not stopped: without a rule matching
    /// that hostname the flow is relayed direct to the provider. It needs a rule; this guard covers
    /// only the IP-literal form — which no *domain* rule can match, since it carries no hostname,
    /// though `app` and `dest.ips` rules still do.
    ///
    /// Note what this does to a client that **requires** DoH (`curl --doh-url`, a browser set to
    /// strict secure-DNS): its lookups fail rather than falling back. Measured on hardware. That
    /// is the intended trade for leak prevention, and the reason this is switchable.
    #[serde(default = "default_true")]
    pub doh_guard: bool,
    /// Domains resolved by a different mode (e.g. LAN/private via `system`).
    #[serde(default)]
    pub split: Vec<DnsSplit>,
    /// In `proxy` mode, the name of the SOCKS5 [`ProxyDef`] to forward DNS
    /// through. Defaults to the first SOCKS5 proxy in the profile — set this when
    /// several proxies exist and DNS must take a specific account/region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_proxy: Option<String>,
    /// In `proxy` mode, the upstream resolver (`ip:port` literal) queried through
    /// the proxy. Defaults to `1.1.1.1:53`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// Resolvers (`ip:port` literals) the direct resolver uses for `local` /
    /// `fakeIp` resolution and proxy-endpoint resolution, bypassing the OS
    /// resolver. Defaults to the host's own system DNS servers (public resolvers
    /// 1.1.1.1 / 8.8.8.8 only if none can be enumerated); set internal resolvers to
    /// pin corporate/split-horizon resolution and avoid any public-DNS leak.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_upstreams: Vec<String>,
}

/// Hand-written so `Default` matches what the engine actually does: `dohGuard` is ON unless a
/// config turns it off. A derived `Default` would say `false` while the running engine says
/// `true`, and anything reasoning from the type (diagnostics, a future GUI toggle) would disagree
/// with the product.
impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: DnsMode::default(),
            fake_ip_pool: None,
            leak_prevention: false,
            doh_guard: true,
            split: Vec::new(),
            forward_proxy: None,
            upstream: None,
            direct_upstreams: Vec::new(),
        }
    }
}

/// DNS resolution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsMode {
    /// Don't touch DNS; route by IP only.
    #[default]
    System,
    /// Resolve locally, proxy by IP.
    Local,
    /// Forward queries through a SOCKS5 proxy (DNS-over-TCP) to an upstream
    /// resolver and return the real addresses — leak-free, proxied by IP.
    Proxy,
    /// Hand out synthetic IPs and resolve remotely at connect time.
    FakeIp,
}

/// Per-domain DNS mode override (split DNS).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsSplit {
    pub domains: Vec<String>,
    pub mode: DnsMode,
}

/// L4 protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Upstream proxy protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyKind {
    Socks5,
    /// SOCKS5 spoken inside a TLS tunnel to the proxy (`socks5Tls`). The
    /// control/CONNECT channel is TLS-wrapped; relayed UDP datagrams remain
    /// plain, as the SOCKS5 UDP relay (RFC 1928) is not itself encrypted.
    ///
    /// **UDP data plane is NOT protected by the TLS**, and this matters most in a chain: a chained
    /// UDP datagram carries every downstream hop's relay address as nested plaintext SOCKS5 UDP
    /// headers, sent over ordinary UDP to the first hop's relay. Making a hop `socks5Tls` encrypts
    /// only its control channel — an on-path observer of the UDP leg still sees the addresses and
    /// the payload. Use it for control-channel confidentiality and credential protection, not to
    /// hide the UDP relay path.
    Socks5Tls,
    Socks4,
    Socks4a,
    /// HTTP CONNECT.
    Http,
    /// HTTP CONNECT inside TLS to the proxy.
    Https,
}

impl ProxyKind {
    /// SOCKS5 — plain or over TLS — carries UDP (ASSOCIATE); the rest are TCP-only.
    pub fn supports_udp(self) -> bool {
        matches!(self, ProxyKind::Socks5 | ProxyKind::Socks5Tls)
    }

    /// Whether the proxy connection is wrapped in TLS (`https` / `socks5Tls`).
    pub fn is_tls(self) -> bool {
        matches!(self, ProxyKind::Https | ProxyKind::Socks5Tls)
    }

    /// Short label matching the config's JSON spelling — for compact display (chain hop paths,
    /// explanations).
    pub fn short_label(self) -> &'static str {
        match self {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Socks5Tls => "socks5Tls",
            ProxyKind::Socks4 => "socks4",
            ProxyKind::Socks4a => "socks4a",
            ProxyKind::Http => "http",
            ProxyKind::Https => "https",
        }
    }
}

/// A chain's hops rendered as `name (kind) → name (kind)` for compact display, resolving each
/// hop's proxy kind from `proxies`. An empty list → `(no hops)`; a hop whose proxy is missing →
/// `name (?)`. Used by the GUI chain cards and the engine's connection explanation.
pub fn chain_hops_summary(hops: &[String], proxies: &[ProxyDef]) -> String {
    if hops.is_empty() {
        return "(no hops)".to_string();
    }
    hops.iter()
        .map(|h| match proxies.iter().find(|p| &p.name == h) {
            Some(p) => format!("{h} ({})", p.kind.short_label()),
            None => format!("{h} (?)"),
        })
        .collect::<Vec<_>>()
        .join(" → ")
}

/// A single upstream proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyDef {
    pub name: String,
    pub kind: ProxyKind,
    /// `host:port` of the proxy server.
    pub endpoint: String,
    #[serde(default = "default_protocols")]
    pub protocols: Vec<Protocol>,
    #[serde(default)]
    pub auth: ProxyAuth,
    /// Where hostnames resolve for this proxy.
    #[serde(default)]
    pub dns: ProxyDnsResolution,
    /// Lower = preferred (future smart routing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheck>,
    /// TLS proxy kinds (`https` / `socks5Tls`) only: skip certificate
    /// validation. **Insecure — testing only** (e.g. a self-signed proxy cert);
    /// ignored for non-TLS kinds.
    #[serde(default, skip_serializing_if = "is_false")]
    pub skip_verify: bool,
    /// SOCKS5 UDP behind NAT: ignore the BND.ADDR the proxy returns from UDP ASSOCIATE
    /// (which can be the server's unreachable *internal* address) and send relay datagrams
    /// to the proxy's own host:BND.PORT instead. SOCKS5 / SOCKS5-TLS UDP only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_use_proxy_host: bool,
}

/// serde helper: omit a `false` bool from serialized config (absent = default `false`).
fn is_false(b: &bool) -> bool {
    !*b
}

/// Proxy authentication. Secrets use [`Secret`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ProxyAuth {
    #[default]
    None,
    /// SOCKS5 username/password.
    UserPass { username: String, password: Secret },
    /// HTTP Basic.
    Basic { username: String, password: Secret },
    /// HTTP Digest.
    Digest { username: String, password: Secret },
    /// Windows integrated (NTLM / Negotiate) via SSPI with the process's ambient credentials.
    ///
    /// Integrated-auth policy (enforced by validation and again at connect time):
    /// - the proxy must be `https` with certificate verification (`skipVerify` is rejected), and
    ///   the handshake is bound to that TLS session (channel binding) and to the proxy's own
    ///   SPN (`HTTP/<proxy host>`);
    /// - a machine or service identity (the installed LocalSystem service authenticates as the
    ///   computer account `HOST$`; also virtual/managed service accounts) is **refused** unless
    ///   `allowServiceIdentity` is set for this proxy. A user identity (a foreground run) is
    ///   allowed without it.
    Negotiate {
        /// Explicit opt-in to send a machine/service identity's integrated credentials to this
        /// proxy. Off by default: a configured proxy then never silently receives the computer
        /// account's authentication.
        #[serde(
            default,
            rename = "allowServiceIdentity",
            skip_serializing_if = "is_false"
        )]
        allow_service_identity: bool,
    },
}

/// Where a proxy resolves destination hostnames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyDnsResolution {
    /// Resolve at the proxy (remote DNS) — preferred for leak prevention.
    #[default]
    Remote,
    /// Resolve locally and send an IP to the proxy.
    Local,
}

/// Active proxy/chain health probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheck {
    #[serde(rename = "type", default)]
    pub kind: HealthCheckKind,
    /// `host:port` to probe.
    pub target: String,
    #[serde(default = "default_health_interval")]
    pub interval_sec: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HealthCheckKind {
    #[default]
    Connect,
}

/// An ordered chain of proxy hops.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyChain {
    pub name: String,
    #[serde(default)]
    pub mode: ChainMode,
    /// Names of [`ProxyDef`]s to traverse (first hop first).
    pub hops: Vec<String>,
    /// Defaults to TCP only. Add `UDP` to carry UDP, which requires a `static` chain whose every
    /// hop is `socks5`/`socks5Tls` and itself carries UDP — anything else fails CLOSED at routing.
    /// The default stays TCP-only so a chain never silently promises more than its hops can do.
    #[serde(default = "default_chain_protocols")]
    pub protocols: Vec<Protocol>,
    #[serde(default)]
    pub dns: ChainDns,
    #[serde(default)]
    pub on_hop_failure: OnHopFailure,
    /// Chain-level enable/disable; defaults to enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChainMode {
    /// Traverse every hop in order.
    #[default]
    Static,
    /// Try hops/sub-chains in order; advance on failure.
    Failover,
    /// Round-robin across the pool.
    RoundRobin,
    /// Pick the lowest-RTT healthy member.
    Latency,
}

/// Where names resolve within a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChainDns {
    FirstHop,
    #[default]
    LastHop,
    PerRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnHopFailure {
    #[default]
    Report,
    Failover,
}

/// A named, ordered group of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleGroup {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// A routing rule: a match predicate plus an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(rename = "match")]
    pub match_: Predicate,
    pub action: Action,
}

/// A composable match predicate.
///
/// Serialized externally tagged, so each node is a one-key object:
/// `{ "all": [ … ] }`, `{ "app": { … } }`, `{ "not": { … } }`, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Predicate {
    /// All children must match (AND).
    All(Vec<Predicate>),
    /// Any child must match (OR).
    Any(Vec<Predicate>),
    /// Negate the child.
    Not(Box<Predicate>),
    App(AppMatch),
    Dest(DestMatch),
    Net(NetMatch),
    When(TimeMatch),
}

impl Default for Predicate {
    /// An empty `all` matches everything.
    fn default() -> Self {
        Predicate::All(Vec::new())
    }
}

/// Process match criteria. All fields are wildcard-matched
/// case-insensitively; specified fields are ANDed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppMatch {
    /// Executable name patterns (`chrome.exe`, `*chrome*`).
    #[serde(default)]
    pub names: Vec<String>,
    /// Full image-path patterns (`C:\\Corp\\**`).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Code-signing subject pattern (not matched yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// Parent-process name patterns (not matched yet).
    #[serde(default)]
    pub parent: Vec<String>,
}

/// Destination match criteria. Specified fields are ANDed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DestMatch {
    /// Domain patterns; `!` prefix negates (`*.corp`, `!public.corp`).
    #[serde(default)]
    pub domains: Vec<String>,
    /// IPs or CIDRs (`10.0.0.0/8`, `1.2.3.4`).
    #[serde(default)]
    pub ips: Vec<String>,
    /// Ports or ranges (`443`, `8000-8100`).
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<Protocol>,
}

/// Network match criteria.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetMatch {
    /// Interface name patterns. **Not implemented** — `validate-config` rejects a
    /// non-empty list, since it can't be evaluated and matching every interface
    /// would silently over-apply the rule.
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub family: Vec<AddrFamily>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddrFamily {
    Ipv4,
    Ipv6,
}

/// Time-window match: `days` (e.g. `Mon-Fri`, `Sat`) plus `hours`
/// (`HH:MM-HH:MM`, 24h, end-exclusive, wraps past midnight), evaluated against
/// the local clock by the `proxroute-core` matcher.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeMatch {
    /// Day specs (`Mon-Fri`, `Sat`).
    #[serde(default)]
    pub days: Vec<String>,
    /// Hour windows (`09:00-18:00`).
    #[serde(default)]
    pub hours: Vec<String>,
}

/// What to do with a matched flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    #[serde(rename = "type")]
    pub kind: ActionType,
    /// Proxy or chain name (required for `proxy`/`chain`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Override DNS resolution for this action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_mode: Option<DnsMode>,
    /// What to do if the proxy/chain cannot be established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_failure: Option<OnFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActionType {
    Proxy,
    Chain,
    Direct,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnFailure {
    #[default]
    Block,
    Direct,
    Next,
}

fn default_true() -> bool {
    true
}

fn default_protocols() -> Vec<Protocol> {
    vec![Protocol::Tcp, Protocol::Udp]
}

fn default_chain_protocols() -> Vec<Protocol> {
    // TCP-only by default even though UDP chaining exists: opting a chain into UDP requires every
    // hop to speak SOCKS5 UDP, which the config cannot assume. Defaulting to TCP means a chain
    // never declares a capability its hops may not have.
    vec![Protocol::Tcp]
}

/// Default health-check probe interval (seconds), used when `intervalSec` is omitted. The single
/// source of truth for both the config default and the GUI's blank-field default / placeholder.
pub const DEFAULT_HEALTH_INTERVAL_SECS: u32 = 30;

fn default_health_interval() -> u32 {
    DEFAULT_HEALTH_INTERVAL_SECS
}
