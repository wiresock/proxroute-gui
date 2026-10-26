//! Pure profile-selection logic for the config tab, split out of `main.rs` so the unit tests use
//! the standard `#[test]` (the `gpui::*` glob in `main.rs` shadows it — see `rules.rs`). These
//! decide WHICH profile the config tab edits/displays under a `--profile` run, where the engine's
//! effective (running) profile differs from the config's `activeProfile`.

use proxroute_config::Config;

/// The running profile when the engine has reported one and `cfg` still defines it, else the
/// config's active profile (empty when there is no config at all). The DYNAMIC target the read-only
/// view follows; the open form freezes it (see [`resolve_editing_profile`]).
pub(crate) fn resolve_running_or_active(running: Option<&str>, cfg: Option<&Config>) -> String {
    if let (Some(running), Some(cfg)) = (running, cfg) {
        if cfg.profiles.iter().any(|p| p.name == running) {
            return running.to_string();
        }
    }
    cfg.map(|c| c.active_profile.clone()).unwrap_or_default()
}

/// The profile the config tab edits: the FROZEN form profile while a form edit is open (so a
/// mid-edit running-profile change can't retarget the open selection onto a different profile),
/// else the dynamic running-or-active target.
pub(crate) fn resolve_editing_profile(
    frozen: Option<&str>,
    running: Option<&str>,
    cfg: Option<&Config>,
) -> String {
    match frozen {
        Some(frozen) => frozen.to_string(),
        None => resolve_running_or_active(running, cfg),
    }
}

/// Decide whether to re-aim a PROVISIONAL form freeze once the running profile first becomes known.
/// Returns `Some(running)` to re-target the form at the running profile — done only when the form is
/// still PRISTINE (no edits) and the draft actually defines that profile — else `None` to keep the
/// current (provisional) freeze, in which case the drift banner warns if they differ.
pub(crate) fn reconciled_freeze(
    frozen: Option<&str>,
    running: &str,
    pristine: bool,
    running_in_draft: bool,
) -> Option<String> {
    if frozen == Some(running) || !pristine || !running_in_draft {
        return None;
    }
    Some(running.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Config with profiles `A` and `B` (active `B`), each carrying one distinctly-named proxy and
    /// rule, so a lookup that resolves the wrong profile is visible in the assertion.
    fn two_profile_cfg() -> Config {
        serde_json::from_str(
            r#"{"schemaVersion":2,"activeProfile":"B","profiles":[
                {"name":"A","ipv6":"allow",
                 "proxies":[{"name":"proxyA","kind":"socks5","endpoint":"127.0.0.1:1080"}],
                 "ruleGroups":[{"name":"g","enabled":true,"rules":[
                     {"name":"ruleA","enabled":true,"match":{"app":{"names":["a.exe"]}},"action":{"type":"direct"}}]}]},
                {"name":"B","ipv6":"allow",
                 "proxies":[{"name":"proxyB","kind":"socks5","endpoint":"127.0.0.1:1081"}],
                 "ruleGroups":[{"name":"g","enabled":true,"rules":[
                     {"name":"ruleB","enabled":true,"match":{"app":{"names":["b.exe"]}},"action":{"type":"direct"}}]}]}]}"#,
        )
        .expect("test config parses")
    }

    #[test]
    fn running_or_active_prefers_the_running_profile_when_present() {
        let cfg = two_profile_cfg();
        // A `--profile A` run reports running "A" — it overrides the config's activeProfile "B".
        assert_eq!(resolve_running_or_active(Some("A"), Some(&cfg)), "A");
    }

    #[test]
    fn running_or_active_falls_back_to_active_when_running_absent_or_unknown() {
        let cfg = two_profile_cfg();
        // A running profile the config no longer defines (e.g. just renamed) → activeProfile.
        assert_eq!(resolve_running_or_active(Some("ghost"), Some(&cfg)), "B");
        // No running profile reported yet (before the first status poll) → activeProfile.
        assert_eq!(resolve_running_or_active(None, Some(&cfg)), "B");
        // No config loaded at all → empty (caller treats as "nothing to edit").
        assert_eq!(resolve_running_or_active(Some("A"), None), "");
    }

    #[test]
    fn editing_profile_freezes_to_the_form_profile_despite_running_drift() {
        let cfg = two_profile_cfg();
        // Form frozen to A; the engine's running profile drifts to B mid-edit → edits STAY on A.
        // Regression guard for "form edits retarget to a different profile while the editor is open".
        assert_eq!(
            resolve_editing_profile(Some("A"), Some("B"), Some(&cfg)),
            "A"
        );
        // The frozen profile wins even once the running profile is no longer reported.
        assert_eq!(resolve_editing_profile(Some("A"), None, Some(&cfg)), "A");
    }

    #[test]
    fn editing_profile_is_dynamic_when_no_form_is_open() {
        let cfg = two_profile_cfg();
        // No frozen form profile (read-only view) → follow the running profile, else activeProfile.
        assert_eq!(resolve_editing_profile(None, Some("A"), Some(&cfg)), "A");
        assert_eq!(resolve_editing_profile(None, None, Some(&cfg)), "B");
    }

    #[test]
    fn reconciled_freeze_reaims_a_pristine_form_to_the_running_profile() {
        // Provisional freeze guessed "B" (config active) before the first poll; running is "A".
        // Pristine form whose draft defines A → re-aim to A so the user edits the running profile.
        assert_eq!(
            reconciled_freeze(Some("B"), "A", true, true),
            Some("A".to_string())
        );
    }

    #[test]
    fn reconciled_freeze_keeps_an_edited_or_mismatched_freeze() {
        // Already edited (not pristine) → keep the frozen profile; the drift banner warns instead.
        assert_eq!(reconciled_freeze(Some("B"), "A", false, true), None);
        // Running profile isn't in the draft (e.g. just removed) → don't re-aim to a missing profile.
        assert_eq!(reconciled_freeze(Some("B"), "A", true, false), None);
        // Provisional guess already matched the running profile → nothing to do.
        assert_eq!(reconciled_freeze(Some("A"), "A", true, true), None);
    }

    #[test]
    fn lookups_target_the_named_profile_not_the_config_active() {
        let cfg = two_profile_cfg();
        // crate::proxy_at / crate::rule_at resolve within the PROFILE they are handed, not
        // cfg.activeProfile (B): targeting A must see A's proxy/rule even though B is active.
        assert_eq!(
            crate::proxy_at(&cfg, "A", 0).map(|p| p.name.as_str()),
            Some("proxyA")
        );
        assert_eq!(
            crate::proxy_at(&cfg, "B", 0).map(|p| p.name.as_str()),
            Some("proxyB")
        );
        assert_eq!(
            crate::rule_at(&cfg, "A", 0, 0).map(|r| r.name.as_str()),
            Some("ruleA")
        );
        assert_eq!(
            crate::rule_at(&cfg, "B", 0, 0).map(|r| r.name.as_str()),
            Some("ruleB")
        );
        // An unknown profile yields nothing rather than falling through to another profile.
        assert!(crate::proxy_at(&cfg, "ghost", 0).is_none());
    }
}
