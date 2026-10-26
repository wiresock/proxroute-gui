//! Security-hardened named-pipe server creation.
//!
//! tokio's `ServerOptions` creates the pipe with the process's default DACL,
//! which typically lets any authenticated local user connect. The management
//! API exposes connection metadata and control commands, so the pipe is created
//! here with an explicit DACL granting full access only to **Local System** and
//! **Builtin Administrators** — born with that descriptor, so there is no window
//! during which a weaker DACL is in effect. Remote clients are rejected too.
//!
//! The pipe's DACL is fixed by its FIRST instance, which is the host's ownership anchor
//! ([`create_reservation`]); every serving instance ([`create_secured_server`]) joins that pipe.

use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

use tokio::net::windows::named_pipe::NamedPipeServer;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// DACL (SDDL): protected, full access for Local System (SY) and Builtin
/// Administrators (BA) only.
///
/// TRUST BOUNDARY (deliberate): this DACL *is* the management API's entire authorization model —
/// the server does not separately authenticate or authorize the connecting client. Every local
/// Administrator is therefore fully trusted: any admin can read connection metadata, rewrite the
/// routing policy, toggle the kill-switch floor, and use `CheckProxy` as a credential-confirmation
/// oracle. That is acceptable because an admin already holds the secured config file (real secrets)
/// plus driver/debug access, so the pipe grants nothing beyond what being admin already implies. If
/// a non-elevated GUI is ever added, do NOT simply widen this DACL to a user SID — add server-side
/// `ImpersonateNamedPipeClient` + an explicit allow-list, and gate the secret-bearing verbs
/// (`SetConfig` / `CheckProxy`) behind it.
pub(crate) const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// In/out buffer size hint for the pipe.
const PIPE_BUF: u32 = 64 * 1024;

/// Create one serving instance of the management pipe and adopt it into the current Tokio runtime.
///
/// Never the FIRST instance: the name is already held by the caller's
/// [`crate::transport::PipeOwnership`] anchor, which was created with
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`. Adding an instance to an existing pipe requires
/// `FILE_CREATE_PIPE_INSTANCE` under the pipe's DACL (`sddl`, fixed by the anchor), so it only
/// succeeds for a principal the anchor's DACL admits — which is also why an unprivileged process
/// cannot add a rogue instance to our pipe.
pub(crate) fn create_secured_server(name: &str, sddl: &str) -> io::Result<NamedPipeServer> {
    let handle = create_instance(name, sddl, false)?;
    // SAFETY: a freshly created overlapped server pipe end, owned solely here.
    // tokio's inherent `from_raw_handle` registers it with the current runtime
    // (hence the `io::Result`), so this must run inside the tokio context.
    unsafe { NamedPipeServer::from_raw_handle(handle.0 as _) }
}

/// Create the FIRST instance of `name` (`FILE_FLAG_FIRST_PIPE_INSTANCE`, so the call fails rather
/// than joining a pipe someone else created) and immediately put it in the DISCONNECTED state, so it
/// holds the name without ever accepting a client. Not registered with any runtime: it can be created
/// before the engine's runtime exists and outlive it across in-place restarts.
///
/// A freshly created instance is in the LISTENING state, and a client's `CreateFile` binds to any
/// listening instance — an anchor left listening would swallow clients nobody serves. A listening
/// instance accepts `DisconnectNamedPipe`, which moves it to DISCONNECTED; clients only bind to
/// instances that are listening, so they reach the serving instances instead (or get
/// `ERROR_PIPE_BUSY` while none exists, which [`crate::transport::request`] already retries).
pub(crate) fn create_reservation(name: &str, sddl: &str) -> io::Result<OwnedHandle> {
    let handle = create_instance(name, sddl, true)?;
    // SAFETY: a freshly created pipe handle owned solely here; closed on drop.
    let owned = unsafe { OwnedHandle::from_raw_handle(handle.0 as _) };
    // SAFETY: `handle` is the live server end created above.
    unsafe { DisconnectNamedPipe(handle) }
        .map_err(|e| io::Error::other(format!("park the management pipe anchor: {e}")))?;
    Ok(owned)
}

/// `CreateNamedPipeW` with the hardened descriptor `sddl`. `first` sets
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`.
fn create_instance(name: &str, sddl: &str, first: bool) -> io::Result<HANDLE> {
    let sddl_w: Vec<u16> = name_wide(sddl);
    let name_w: Vec<u16> = name_wide(name);

    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl_w is a valid NUL-terminated UTF-16 string; psd is written by
    // the call and freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .map_err(|e| io::Error::other(format!("build pipe security descriptor: {e}")))?;
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };

    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

    // SAFETY: name_w is NUL-terminated; sa references a live descriptor.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUF,
            PIPE_BUF,
            0,
            Some(&sa),
        )
    };
    // Capture the error BEFORE the free below, which may reset the thread's last-error value: the
    // caller classifies it (access denied = the name is held by someone else).
    let create_err = (handle == INVALID_HANDLE_VALUE).then(io::Error::last_os_error);

    // Free the security descriptor regardless of outcome.
    // SAFETY: psd.0 was allocated by ConvertStringSecurityDescriptor... above.
    unsafe {
        let _ = LocalFree(HLOCAL(psd.0));
    }

    match create_err {
        Some(e) => Err(e),
        None => Ok(handle),
    }
}

/// UTF-16, NUL-terminated.
fn name_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
