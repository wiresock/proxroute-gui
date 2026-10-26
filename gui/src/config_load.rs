//! Parsing `GetConfig` responses — kept out of `main.rs` so the unit test uses the standard
//! `#[test]` (the `gpui::*` glob there shadows it; see `rules.rs`), and so the STRICT-parse choice is
//! pinned by a test that fails if a call site is reverted to a lenient parser.

use proxroute_config::Config;

/// Parse a `GetConfig` response with the STRICT parser (`proxroute_config::from_json_str`: rejects unknown
/// keys + migrates), matching the engine — so a config from a NEWER engine carrying fields this GUI
/// doesn't know is REJECTED, never silently down-shaped and later re-saved (which would erase the
/// newer settings). Pairs the parsed config with the engine's revision `digest`. Used by the startup
/// fetch, the retry fetch, and Reload.
pub(crate) fn parse_get_config(
    json: &str,
    digest: Option<u64>,
) -> Result<(Config, Option<u64>), String> {
    proxroute_config::from_json_str(json)
        .map(|cfg| (cfg, digest))
        .map_err(|e| format!("parse config: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_instead_of_dropping_them() {
        // A config from a NEWER engine carries a field this GUI's Config struct doesn't know. The
        // parse must REJECT it — never drop the unknown field and risk a later save erasing it.
        let top = r#"{"schemaVersion":2,"activeProfile":"p","futureGlobalSetting":true,
            "profiles":[{"name":"p","ipv6":"allow","ruleGroups":[]}]}"#;
        assert!(
            parse_get_config(top, Some(1)).is_err(),
            "an unknown top-level field must be rejected, not dropped"
        );

        // …as is one nested inside a profile.
        let nested = r#"{"schemaVersion":2,"activeProfile":"p",
            "profiles":[{"name":"p","ipv6":"allow","ruleGroups":[],"futureProfileSetting":42}]}"#;
        assert!(
            parse_get_config(nested, Some(1)).is_err(),
            "an unknown nested field must be rejected, not dropped"
        );

        // A clean config parses, and the digest is paired through unchanged.
        let ok = r#"{"schemaVersion":2,"activeProfile":"p",
            "profiles":[{"name":"p","ipv6":"allow","ruleGroups":[]}]}"#;
        let (cfg, digest) = parse_get_config(ok, Some(0xABC)).expect("clean config parses");
        assert_eq!(cfg.active_profile, "p");
        assert_eq!(digest, Some(0xABC));
    }
}
