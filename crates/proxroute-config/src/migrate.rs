//! Schema migration scaffold.
//!
//! Configuration carries a `schemaVersion`. As the schema evolves, each version
//! bump adds one migration step here so older configs continue to load
//! (backward-compatible migration where practical).

use crate::schema::Config;
use crate::CURRENT_SCHEMA_VERSION;

#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("config schemaVersion {found} is newer than supported {supported}; upgrade Proxroute")]
    TooNew { found: u32, supported: u32 },
    #[error("config schemaVersion {found} predates the oldest supported schema — a legacy (v0/v1) config has no automatic migration yet; re-create it with the current schema")]
    LegacyV1 { found: u32 },
}

/// Migrate a config in place from its declared `schemaVersion` up to
/// [`CURRENT_SCHEMA_VERSION`].
///
/// The v1 → v2 rewrite (flat rules/exclusions → composable rule groups, single
/// SOCKS5 → multi-protocol proxies) is not yet automated; v1 documents are
/// rejected with a clear error. Future in-range bumps add stepwise migrations
/// before this point.
pub fn migrate(cfg: &mut Config) -> Result<(), MigrateError> {
    if cfg.schema_version > CURRENT_SCHEMA_VERSION {
        return Err(MigrateError::TooNew {
            found: cfg.schema_version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if cfg.schema_version < 2 {
        return Err(MigrateError::LegacyV1 {
            found: cfg.schema_version,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Config;

    fn cfg(version: u32) -> Config {
        Config {
            schema_version: version,
            log_level: Default::default(),
            redirect_mode: Default::default(),
            redirect_auth: true,
            active_profile: "default".into(),
            profiles: vec![],
        }
    }

    #[test]
    fn accepts_current_version() {
        assert!(migrate(&mut cfg(CURRENT_SCHEMA_VERSION)).is_ok());
    }

    #[test]
    fn rejects_legacy_v1() {
        assert!(matches!(
            migrate(&mut cfg(1)),
            Err(MigrateError::LegacyV1 { found: 1 })
        ));
    }

    #[test]
    fn rejects_too_new() {
        assert!(matches!(
            migrate(&mut cfg(CURRENT_SCHEMA_VERSION + 1)),
            Err(MigrateError::TooNew { .. })
        ));
    }
}
