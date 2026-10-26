//! Local management API shared by the service, CLI and UI.
//!
//! The transport is a Windows named pipe (`\\.\pipe\Proxroute`) whose DACL is
//! restricted to authorized users. Messages are
//! newline-delimited JSON ([`protocol`]). The same crate is used by the service
//! (server) and by every client (CLI today, GUI later), so the wire contract has
//! a single source of truth.
//!
//! See `docs/architecture.md`.

pub mod protocol;
pub mod transport;

#[cfg(windows)]
mod secure_pipe;

pub use protocol::{
    ConnectionRow, Event, ProxyHealth, Request, Response, RestartRequired, RestartScope,
};
pub use transport::{decode_frame, encode_frame, PIPE_NAME};

/// Windows service name of the application (the engine host). The kernel driver is a separate
/// service (`proxroute`, see `proxroute_driver_client::common::DRIVER_SERVICE_NAME`); the two are
/// stopped and started independently, the application first.
pub const APP_SERVICE_NAME: &str = "ProxrouteService";

/// Display name of [`APP_SERVICE_NAME`] in the Services snap-in.
pub const APP_SERVICE_DISPLAY_NAME: &str = "Proxroute Service";

/// Folder name used under `%ProgramData%` (service config, logs) and `%LOCALAPPDATA%` (GUI state).
pub const DATA_DIR_NAME: &str = "Proxroute";

#[cfg(windows)]
pub use transport::{request, serve, PipeOwnership};
