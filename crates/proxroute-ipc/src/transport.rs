//! Named-pipe transport for the local management API.
//!
//! Framing is one JSON document per line (newline-delimited JSON), which keeps
//! the client/server loop trivial and is easy to inspect during debugging.
//!
//! The pipe's DACL is restricted to Local System and Administrators (Requirements
//! §9: "Restrict local management API to authorized users") — see
//! [`crate::secure_pipe`], which builds the security descriptor. Concurrent
//! callers retry on `ERROR_PIPE_BUSY` (see [`request`]).

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Well-known pipe name for the local management API.
pub const PIPE_NAME: &str = r"\\.\pipe\Proxroute";

/// Maximum bytes read for a single newline-delimited frame. Bounds memory if a
/// peer sends an oversized/never-terminated line. The pipe is restricted to
/// Administrators + SYSTEM, so this is defense-in-depth; the cap is generous
/// enough for a full connection-list response.
const MAX_FRAME: u64 = 4 * 1024 * 1024;

/// Per-operation timeout for a pipe read/write, so a stalled peer can't hold a
/// CLI call or a service handler task forever.
#[cfg(windows)]
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Cap on concurrently-served management connections. The accept loop spawns a task per
/// client; without a bound, an admin-context client that connects in a tight loop could pile
/// up unbounded tasks (each holding a pipe handle for up to [`IO_TIMEOUT`]). The pipe DACL
/// already restricts callers to SYSTEM/Administrators, so this is defense-in-depth against a
/// buggy/hostile same-privilege client; the accept loop applies backpressure past the cap.
#[cfg(windows)]
const MAX_INFLIGHT_CONNS: usize = 16;

/// Upper bound on a single request handler, so a stalled handler can't pin its connection and one
/// of [`MAX_INFLIGHT_CONNS`] permits forever — 16 stuck handlers would otherwise exhaust the pool
/// and wedge the whole management API (`status`/`list`/`config` all unavailable). Set well above the
/// slowest legitimate verb — CheckProxy bounds itself at 8s (`dispatch::CHECK_TIMEOUT`) — so a real
/// call completes (or errors) first and only a genuinely wedged handler hits this, becoming a
/// per-connection error rather than a pool-exhausting hang.
#[cfg(windows)]
const HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Run a pipe I/O future under [`IO_TIMEOUT`], mapping a timeout to a TimedOut error.
#[cfg(windows)]
async fn with_timeout<F, T>(fut: F) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    match tokio::time::timeout(IO_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "IPC operation timed out",
        )),
    }
}

/// Read one newline-delimited frame, bounded to [`MAX_FRAME`] (the caller wraps the
/// reader in `.take(MAX_FRAME)`). A frame that reaches the cap without a terminating
/// newline is reported as an explicit "too large" error, rather than handed on as a
/// truncated line that fails downstream as an opaque JSON parse error. Returns
/// `Ok(None)` on a clean EOF before any bytes (peer connected then closed, no frame).
#[cfg(windows)]
async fn read_framed_line<R>(reader: &mut R) -> std::io::Result<Option<String>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let mut line = String::new();
    if with_timeout(reader.read_line(&mut line)).await? == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "management API frame exceeded the {MAX_FRAME}-byte cap or ended without a newline"
            ),
        ));
    }
    Ok(Some(line))
}

/// Encode a value as a single newline-terminated JSON frame.
pub fn encode_frame<T: Serialize>(value: &T) -> serde_json::Result<String> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    Ok(s)
}

/// Decode one newline-delimited JSON frame.
pub fn decode_frame<T: DeserializeOwned>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim_end())
}

/// Exclusive ownership of the management pipe's name, held by an engine HOST.
///
/// The management pipe is also the engine's single-instance lock: the driver session (filter mask,
/// redirect mode, PID exclusion list, recv-auth) is shared by every handle to `\\.\PROXROUTE`, so a
/// second engine that reached its baseline IOCTLs would silently reset a live engine's interception.
/// Acquiring this first — before the driver is opened or any shared state is touched — makes "I own
/// the management endpoint" the precondition for "I may program the driver". A second engine, or a
/// process squatting the well-known name, makes acquisition FAIL (it is never retried in the
/// background, never connected to, and never ignored) and the host stops before changing anything.
///
/// It is the pipe's FIRST instance (`FILE_FLAG_FIRST_PIPE_INSTANCE`, created with the SYSTEM/
/// Administrators-only DACL), parked in the disconnected state so it never accepts a client (see
/// [`crate::secure_pipe`]). While it lives the name cannot be taken, and an unprivileged process
/// cannot add an instance of its own (that needs `FILE_CREATE_PIPE_INSTANCE` under our DACL). The
/// serving instances [`serve`] creates join this pipe. A host keeps one across in-place engine
/// restarts, so the endpoint is never released between two engine runs.
#[cfg(windows)]
pub struct PipeOwnership {
    _anchor: std::os::windows::io::OwnedHandle,
    name: String,
    sddl: &'static str,
}

#[cfg(windows)]
impl std::fmt::Debug for PipeOwnership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeOwnership")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl PipeOwnership {
    /// Take ownership of [`PIPE_NAME`] with the hardened DACL, retrying briefly.
    ///
    /// The retry absorbs only the transient case: our OWN previous process (an SCM recovery restart,
    /// or a foreground run that just exited) still closing its handles. A name that stays held —
    /// another live engine, or a squatter — fails after the last attempt with an error that says so.
    /// Needs no Tokio runtime.
    pub fn acquire() -> std::io::Result<std::sync::Arc<Self>> {
        Self::acquire_named(PIPE_NAME, crate::secure_pipe::PIPE_SDDL, ACQUIRE_ATTEMPTS)
    }

    /// [`Self::acquire`] for another pipe name, with the production DACL and a single attempt. For
    /// tests that must not touch the real management pipe (they use private names).
    pub fn acquire_at(name: &str) -> std::io::Result<std::sync::Arc<Self>> {
        Self::acquire_named(name, crate::secure_pipe::PIPE_SDDL, 1)
    }

    /// [`Self::acquire`] for an explicit pipe name and DACL (tests use private names).
    pub(crate) fn acquire_named(
        name: &str,
        sddl: &'static str,
        attempts: u32,
    ) -> std::io::Result<std::sync::Arc<Self>> {
        let mut last = None;
        for attempt in 0..attempts.max(1) {
            match crate::secure_pipe::create_reservation(name, sddl) {
                Ok(anchor) => {
                    return Ok(std::sync::Arc::new(Self {
                        _anchor: anchor,
                        name: name.to_string(),
                        sddl,
                    }))
                }
                Err(e) => {
                    if attempt + 1 < attempts {
                        std::thread::sleep(ACQUIRE_DELAY);
                    }
                    last = Some(e);
                }
            }
        }
        Err(describe_acquire_error(
            name,
            last.expect("at least one attempt failed"),
        ))
    }

    /// The pipe name this ownership holds.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Attempts (and spacing) for [`PipeOwnership::acquire`]: long enough to ride out our own previous
/// process closing, short enough that a held name fails startup promptly.
#[cfg(windows)]
const ACQUIRE_ATTEMPTS: u32 = 5;
#[cfg(windows)]
const ACQUIRE_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// Turn a failed first-instance creation into an actionable error, keeping the OS error kind and code
/// (callers and tests classify on them). `ERROR_ACCESS_DENIED` is what `FILE_FLAG_FIRST_PIPE_INSTANCE`
/// reports when the name already exists; `ERROR_PIPE_BUSY` when it exists with its instance limit
/// reached.
#[cfg(windows)]
fn describe_acquire_error(name: &str, e: std::io::Error) -> std::io::Error {
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_PIPE_BUSY: i32 = 231;
    match e.raw_os_error() {
        Some(ERROR_ACCESS_DENIED) | Some(ERROR_PIPE_BUSY) => std::io::Error::new(
            e.kind(),
            format!(
                "the management pipe {name} is already held by another process — another \
                 Proxroute engine (the service or a foreground `proxroute run`) is running, or a \
                 process is squatting the name. Nothing was changed: the driver and the kill-switch \
                 were not touched. Stop the other instance (or the process holding the name) and \
                 start again ({e})"
            ),
        ),
        _ => std::io::Error::new(
            e.kind(),
            format!("create the management pipe {name}: {e}"),
        ),
    }
}

/// Bind the local management API pipe and return its accept loop.
///
/// `owner` is the proof that this process holds the pipe name (see [`PipeOwnership`]); the loop keeps
/// a clone, so the name cannot be released while it runs even if every serving instance is closed.
/// The first serving instance is created here (synchronously) so a failure is surfaced to the
/// caller instead of being lost in a spawned task; only then is the returned future spawned.
///
/// Must be called from within a Tokio runtime context (it adopts an overlapped
/// pipe handle into a `NamedPipeServer`).
#[cfg(windows)]
pub fn serve<H, Fut>(
    owner: std::sync::Arc<PipeOwnership>,
    handler: H,
    cancel: tokio_util::sync::CancellationToken,
) -> std::io::Result<impl std::future::Future<Output = std::io::Result<()>>>
where
    H: Fn(&crate::protocol::Request) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = crate::protocol::Response> + Send,
{
    let first = crate::secure_pipe::create_secured_server(&owner.name, owner.sddl)
        .map_err(|e| std::io::Error::new(e.kind(), format!("arm {}: {e}", owner.name)))?;
    Ok(serve_loop(
        owner,
        first,
        std::sync::Arc::new(handler),
        cancel,
    ))
}

/// Accept clients, recreating an instance per connection, until cancelled.
///
/// Both fallible steps here — accepting a client and minting the *next* instance —
/// are recoverable and must NOT propagate out of this future. The engine supervises
/// the `serve` task and treats *any* exit as a reason to tear the whole engine down
/// (filtering off, all proxying stops), so a transient `CreateNamedPipeW` hiccup
/// (handle/memory pressure, a momentary name collision) or a one-off accept error
/// must not end the loop. We re-arm a fresh instance and keep serving; only
/// cancellation ends the loop. The management API degrades, never the data plane.
#[cfg(windows)]
async fn serve_loop<H, Fut>(
    owner: std::sync::Arc<PipeOwnership>,
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    handler: std::sync::Arc<H>,
    cancel: tokio_util::sync::CancellationToken,
) -> std::io::Result<()>
where
    H: Fn(&crate::protocol::Request) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = crate::protocol::Response> + Send,
{
    // Bound concurrently-served connections; a permit is held for each in-flight
    // handle_conn task and released when it finishes. `acquire_owned` awaits when at the
    // cap, applying backpressure to the accept loop rather than dropping the client.
    let conns = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_CONNS));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            res = server.connect() => {
                if let Err(e) = res {
                    // A failed accept is per-connection and recoverable: drop this
                    // instance, re-arm a fresh one, and keep serving.
                    tracing::warn!(%e, "IPC accept failed; re-creating pipe instance");
                    match next_instance(&owner, &cancel).await {
                        Some(next) => server = next,
                        None => break, // cancelled while retrying
                    }
                    continue;
                }
                let connected = server;
                // Acquire a slot before handing off (backpressure if MAX_INFLIGHT_CONNS are
                // already busy) — but race it against cancellation, so a full cap can't
                // block shutdown until some client releases a permit. The semaphore is
                // never closed, so acquire itself can't fail.
                let permit = tokio::select! {
                    _ = cancel.cancelled() => break,
                    p = std::sync::Arc::clone(&conns).acquire_owned() => {
                        p.expect("IPC connection semaphore is never closed")
                    }
                };
                // Hand the accepted client off immediately, BEFORE re-arming the next
                // listener. Serving the connection is independent of minting the next
                // instance, so if create_secured_server is transiently failing (and
                // next_instance is backing off) the already-connected client must still
                // be served promptly rather than left idle until we can re-arm.
                let conn_handler = std::sync::Arc::clone(&handler);
                tokio::spawn(async move {
                    let _permit = permit; // released when this task ends, freeing the slot
                    if let Err(e) = handle_conn(connected, conn_handler.as_ref()).await {
                        tracing::debug!(%e, "IPC connection error");
                    }
                });
                // Re-arm the next instance so the next client can connect. Retry
                // transient failures instead of propagating (which would tear the
                // whole engine down via the supervisor).
                match next_instance(&owner, &cancel).await {
                    Some(next) => server = next,
                    None => break, // cancelled while retrying
                }
            }
        }
    }
    Ok(())
}

/// Mint the next pipe instance for the accept loop, retrying transient failures with
/// capped backoff until it succeeds or `cancel` fires (returns `None` only if cancelled).
///
/// This deliberately never gives up with an error: a propagated failure would exit
/// [`serve_loop`], which the engine supervisor turns into a full engine teardown. A
/// *persistent* failure therefore degrades the management API (it stops accepting new
/// clients) while the proxy data plane keeps running — the correct trade-off for a
/// non-essential control pipe. `create_secured_server` is a quick set of syscalls, so
/// it is fine to call inline here (as the original loop did); the backoff sleep is the
/// only await between attempts and it races cancellation.
#[cfg(windows)]
async fn next_instance(
    owner: &PipeOwnership,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<tokio::net::windows::named_pipe::NamedPipeServer> {
    const BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(50);
    const MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
    // Re-warn every Nth attempt so a persistent failure stays visible without flooding:
    // once the backoff caps at MAX_DELAY this is roughly one WARN per minute.
    const WARN_EVERY: u32 = 12;
    let mut delay = BASE_DELAY;
    let mut attempt: u32 = 0;
    loop {
        // Always joins OUR pipe: `owner`'s anchor holds the name for as long as this loop runs, so
        // there is no gap (e.g. the last connection closing first) in which another process could
        // create the name and have this non-first instance join ITS pipe instead.
        match crate::secure_pipe::create_secured_server(&owner.name, owner.sddl) {
            Ok(pipe) => return Some(pipe),
            Err(e) => {
                attempt += 1;
                // Surface the first failure immediately and then periodically; a
                // persistent failure would otherwise emit a WARN every backoff interval
                // (up to every 5s) indefinitely and flood the log. DEBUG the rest.
                if attempt == 1 || attempt % WARN_EVERY == 0 {
                    tracing::warn!(%e, attempt, "failed to re-arm management pipe; retrying");
                } else {
                    tracing::debug!(%e, attempt, "failed to re-arm management pipe; retrying");
                }
                tokio::select! {
                    _ = cancel.cancelled() => return None,
                    _ = tokio::time::sleep(delay) => {}
                }
                delay = (delay * 2).min(MAX_DELAY);
            }
        }
    }
}

#[cfg(windows)]
async fn handle_conn<H, Fut>(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    handler: &H,
) -> std::io::Result<()>
where
    H: Fn(&crate::protocol::Request) -> Fut,
    Fut: std::future::Future<Output = crate::protocol::Response>,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    // Cap the request frame so a malformed/oversized line can't grow memory.
    let mut reader = BufReader::new(pipe.take(MAX_FRAME));
    let Some(line) = read_framed_line(&mut reader).await? else {
        return Ok(()); // peer connected then closed without sending a request
    };
    let response = match decode_frame::<crate::protocol::Request>(&line) {
        // Bound the handler (unlike the surrounding I/O, which is already under IO_TIMEOUT): a
        // handler that never returns would otherwise hold this pipe instance and its inflight permit
        // forever. On timeout the handler future is dropped (cancelled) and the client gets an error
        // rather than hanging until its own deadline; the permit is freed when this task returns.
        Ok(req) => match tokio::time::timeout(HANDLER_TIMEOUT, handler(&req)).await {
            Ok(resp) => resp,
            Err(_) => crate::protocol::Response::Error {
                messages: vec![format!(
                    "request handler exceeded {}s and was abandoned",
                    HANDLER_TIMEOUT.as_secs()
                )],
            },
        },
        Err(e) => crate::protocol::Response::Error {
            messages: vec![format!("bad request: {e}")],
        },
    };
    let frame = encode_frame(&response).map_err(to_io)?;
    let mut pipe = reader.into_inner().into_inner();
    with_timeout(pipe.write_all(frame.as_bytes())).await?;
    with_timeout(pipe.flush()).await?;
    Ok(())
}

/// Send a single request to the running service and read its response.
#[cfg(windows)]
pub async fn request(req: &crate::protocol::Request) -> std::io::Result<crate::protocol::Response> {
    use std::os::windows::io::AsRawHandle;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    // SECURITY_IDENTIFICATION (+ SQOS_PRESENT): if we ever connect to an impostor pipe server it
    // can only IDENTIFY us — never impersonate this (possibly elevated admin) client to act on its
    // behalf, which would otherwise be a privilege-escalation vector.
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

    // The service serves one pipe instance at a time, so concurrent callers can
    // hit ERROR_PIPE_BUSY. Retry briefly (a WaitNamedPipe-style backoff) rather
    // than failing a routine status/list call.
    const ERROR_PIPE_BUSY: i32 = 231;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut client = loop {
        match ClientOptions::new()
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
            .open(PIPE_NAME)
        {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    };
    // Authenticate the SERVER before sending anything. The pipe is created with
    // FILE_FLAG_FIRST_PIPE_INSTANCE, but if the host is down a local process can squat the
    // well-known name and harvest admin requests — including SetConfig, which carries proxy
    // credentials. Require a trusted host: the LocalSystem service OR an elevated process (the
    // foreground `proxroute run` host) — see verify_server_trusted.
    verify_server_trusted(client.as_raw_handle())?;

    let frame = encode_frame(req).map_err(to_io)?;
    with_timeout(client.write_all(frame.as_bytes())).await?;
    with_timeout(client.flush()).await?;

    // Cap the response frame to bound memory; an oversize/truncated frame surfaces as
    // an explicit error rather than a truncated line that fails as opaque JSON.
    let mut reader = BufReader::new(client.take(MAX_FRAME));
    let line = read_framed_line(&mut reader).await?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "management API closed without sending a response",
        )
    })?;
    decode_frame::<crate::protocol::Response>(&line).map_err(to_io)
}

#[cfg(windows)]
fn to_io(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

/// Whether a connected pipe server is a trusted management host: the LocalSystem **service**, or
/// any **elevated** process — the documented foreground `proxroute run` host serves the same
/// pipe as an elevated admin *user*, not LocalSystem. A non-elevated process (the realistic squatter
/// that grabs the pipe name while the service is down) is rejected. An elevated impostor is out of
/// this threat model: it implies the attacker already holds admin, and the pipe's SY+BA DACL already
/// requires elevation to connect at all.
#[cfg(windows)]
fn server_is_trusted(is_local_system: bool, is_elevated: bool) -> bool {
    is_local_system || is_elevated
}

/// Verify the connected pipe SERVER is a trusted host (see [`server_is_trusted`]) before sending
/// any request, so admin commands and secrets never go to a squatter that grabbed the well-known
/// pipe name while the service was down. Errors (incl. "untrusted") fail the call.
#[cfg(windows)]
fn verify_server_trusted(handle: std::os::windows::io::RawHandle) -> std::io::Result<()> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TokenElevation, TokenUser, WinLocalSystemSid,
        TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let pipe = HANDLE(handle as _);
    let mut pid = 0u32;
    // SAFETY: `pipe` is a valid connected pipe-client handle for the duration of the call.
    unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) }
        .map_err(|e| std::io::Error::other(format!("identify pipe server: {e}")))?;

    // SAFETY: `pid` is from the call above; the returned handle is closed below.
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| std::io::Error::other(format!("open pipe-server process {pid}: {e}")))?;

    let verdict = (|| -> std::io::Result<bool> {
        let mut token = HANDLE::default();
        // SAFETY: `proc` is a live process handle; `token` is an out-param, closed below.
        unsafe { OpenProcessToken(proc, TOKEN_QUERY, &mut token) }
            .map_err(|e| std::io::Error::other(format!("open server token: {e}")))?;

        // (1) Is the server LocalSystem? TokenUser is variable-length (TOKEN_USER + the trailing
        // SID); size it, then fill an 8-byte-aligned buffer (TOKEN_USER holds a pointer, so a byte
        // Vec would be misaligned).
        let mut size = 0u32;
        // SAFETY: a sizing call — it returns ERROR_INSUFFICIENT_BUFFER and sets `size`.
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        }
        let mut buf = vec![0u64; (size as usize).div_ceil(std::mem::size_of::<u64>()).max(1)];
        // SAFETY: `buf` is 8-byte aligned and sized per the first call.
        let got_user = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                size,
                &mut size,
            )
        };

        // (2) Is the server elevated? (the foreground `run` host — an elevated admin user process.)
        let mut elevation = TOKEN_ELEVATION::default();
        let mut elen = 0u32;
        // SAFETY: TOKEN_ELEVATION is fixed-size; the out-buffer is exactly one of them.
        let got_elev = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(std::ptr::addr_of_mut!(elevation).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut elen,
            )
        };
        // SAFETY: `token` handle is owned here and no longer needed after the reads.
        unsafe {
            let _ = CloseHandle(token);
        }
        got_user.map_err(|e| std::io::Error::other(format!("read server token user: {e}")))?;
        got_elev.map_err(|e| std::io::Error::other(format!("read server token elevation: {e}")))?;

        // SAFETY: `buf` now holds a TOKEN_USER whose `User.Sid` points within the buffer.
        let is_local_system = unsafe {
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            IsWellKnownSid(tu.User.Sid, WinLocalSystemSid).as_bool()
        };
        Ok(server_is_trusted(
            is_local_system,
            elevation.TokenIsElevated != 0,
        ))
    })();

    // SAFETY: `proc` handle is owned here.
    unsafe {
        let _ = CloseHandle(proc);
    }

    if verdict? {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "management pipe server is neither LocalSystem nor an elevated host — refusing to send \
             (a non-elevated process may have squatted the pipe name while the service is down)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    #[cfg(windows)]
    #[test]
    fn server_trust_accepts_service_or_elevated_host_only() {
        // The LocalSystem service is trusted.
        assert!(server_is_trusted(true, false));
        assert!(server_is_trusted(true, true));
        // The foreground `proxroute run` host is an elevated admin-user process — also trusted,
        // so foreground IPC keeps working (regression: a LocalSystem-only check broke it).
        assert!(server_is_trusted(false, true));
        // A non-elevated process (the realistic pipe squatter) is rejected.
        assert!(!server_is_trusted(false, false));
    }

    #[test]
    fn frames_round_trip() {
        let req = Request::ExplainConnection { id: 42 };
        let frame = encode_frame(&req).unwrap();
        assert!(frame.ends_with('\n'));
        let back: Request = decode_frame(&frame).unwrap();
        assert!(matches!(back, Request::ExplainConnection { id } if id == 42));

        let resp = Response::Ok;
        let back: Response = decode_frame(&encode_frame(&resp).unwrap()).unwrap();
        assert!(matches!(back, Response::Ok));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn framed_line_reads_a_terminated_frame() {
        use tokio::io::BufReader;
        let data = b"{\"status\":\"ok\"}\n";
        let mut reader = BufReader::new(&data[..]);
        let line = read_framed_line(&mut reader).await.unwrap().unwrap();
        assert!(line.ends_with('\n'));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn framed_line_rejects_a_frame_without_a_terminator() {
        use tokio::io::BufReader;
        // No trailing newline simulates a frame truncated at the MAX_FRAME cap: it must
        // be an explicit InvalidData error, not a silently-truncated line.
        let data = b"{\"status\":\"ok\"}";
        let mut reader = BufReader::new(&data[..]);
        let err = read_framed_line(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn framed_line_returns_none_on_clean_eof() {
        use tokio::io::BufReader;
        let data: &[u8] = b"";
        let mut reader = BufReader::new(data);
        assert!(read_framed_line(&mut reader).await.unwrap().is_none());
    }

    // --- Pipe ownership (single-engine lock) ---------------------------------------------------
    //
    // These use private pipe names, never PIPE_NAME, and a DACL that also admits Authenticated
    // Users so a non-elevated test process may add serving instances. The production DACL's
    // exclusion of unprivileged principals is checked separately below.

    #[cfg(windows)]
    const TEST_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)";
    #[cfg(windows)]
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    #[cfg(windows)]
    const ERROR_PIPE_BUSY: i32 = 231;

    #[cfg(windows)]
    fn test_pipe_name(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\proxroute-test-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Send one framed request on a raw client (no trusted-server check: the test server is this
    /// non-elevated process) and return the decoded response. Retries the transient
    /// `ERROR_PIPE_BUSY` while no serving instance is listening yet.
    #[cfg(windows)]
    async fn raw_round_trip(name: &str, req: &Request) -> Response {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::windows::named_pipe::ClientOptions;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut client = loop {
            match ClientOptions::new().open(name) {
                Ok(c) => break c,
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("open {name}: {e}"),
            }
        };
        client
            .write_all(encode_frame(req).unwrap().as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new((&mut client).take(MAX_FRAME));
        let line = read_framed_line(&mut reader).await.unwrap().unwrap();
        decode_frame(&line).unwrap()
    }

    /// A second engine (or anything else) asking for the name while it is owned is refused — and the
    /// refusal says what to do, rather than leaving the caller to guess from "access denied".
    #[cfg(windows)]
    #[test]
    fn ownership_is_exclusive() {
        let name = test_pipe_name("exclusive");
        let first = PipeOwnership::acquire_named(&name, TEST_SDDL, 1).expect("first owner");
        let err = PipeOwnership::acquire_named(&name, TEST_SDDL, 2).expect_err("second owner");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("already held"), "{err}");
        assert!(err.to_string().contains("Nothing was changed"), "{err}");
        // Once the owner is gone the name is free again (a later engine run can take it).
        drop(first);
        PipeOwnership::acquire_named(&name, TEST_SDDL, 1).expect("reacquire after release");
    }

    /// A squatter that created the name first (with its own, permissive DACL) makes acquisition fail;
    /// we never join or connect to its pipe.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_squatted_name_is_refused() {
        use tokio::net::windows::named_pipe::ServerOptions;
        let name = test_pipe_name("squat");
        let _squatter = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .expect("squatter creates the name");
        let err = PipeOwnership::acquire_named(&name, TEST_SDDL, 2).expect_err("squatted");
        assert!(err.to_string().contains("already held"), "{err}");
    }

    /// The anchor never accepts a client: with no serving instance a client is told the pipe is busy
    /// (and retries), instead of binding to an instance nobody serves.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_anchor_never_accepts_a_client() {
        use tokio::net::windows::named_pipe::ClientOptions;
        let name = test_pipe_name("anchor");
        let _owner = PipeOwnership::acquire_named(&name, TEST_SDDL, 1).unwrap();
        let err = ClientOptions::new()
            .open(&name)
            .expect_err("the anchor must not accept a client");
        assert_eq!(err.raw_os_error(), Some(ERROR_PIPE_BUSY), "{err}");
    }

    /// Serving instances join the owned pipe, and the name stays reserved across an in-place restart
    /// (one serve loop ending, the next starting): in the gap it cannot be squatted and clients see
    /// "busy", not "absent".
    #[cfg(windows)]
    #[tokio::test]
    async fn the_endpoint_is_retained_across_serve_runs() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        let name = test_pipe_name("restart");
        let owner = PipeOwnership::acquire_named(&name, TEST_SDDL, 1).unwrap();

        for run in 0..2 {
            let cancel = tokio_util::sync::CancellationToken::new();
            let serving = serve(
                std::sync::Arc::clone(&owner),
                |_req: &Request| async { Response::Ok },
                cancel.clone(),
            )
            .expect("arm a serving instance");
            let task = tokio::spawn(serving);
            let resp = raw_round_trip(&name, &Request::Status).await;
            assert!(matches!(resp, Response::Ok), "run {run}: {resp:?}");
            cancel.cancel();
            task.await.unwrap().unwrap();
            // Let the runtime drop the last serving instance.
            tokio::task::yield_now().await;

            // Between runs: still ours.
            let squat = ServerOptions::new().first_pipe_instance(true).create(&name);
            assert!(squat.is_err(), "run {run}: the name must stay reserved");
            let open = ClientOptions::new().open(&name);
            let code = open.as_ref().err().and_then(std::io::Error::raw_os_error);
            assert_ne!(
                code,
                Some(ERROR_FILE_NOT_FOUND),
                "run {run}: must not read as absent"
            );
        }
    }

    /// With the PRODUCTION DACL (SYSTEM + Administrators only) a non-elevated process cannot add an
    /// instance to an owned pipe, so it cannot interpose on the endpoint while the anchor is held.
    /// Only meaningful when the test itself runs non-elevated; skipped (with a note) otherwise.
    #[cfg(windows)]
    #[tokio::test]
    async fn an_unprivileged_process_cannot_add_an_instance_under_the_production_dacl() {
        if current_process_is_elevated() {
            eprintln!("skipped: the test process is elevated, so the DACL admits it");
            return;
        }
        let name = test_pipe_name("dacl");
        let _owner = PipeOwnership::acquire_named(&name, crate::secure_pipe::PIPE_SDDL, 1).unwrap();
        let err = crate::secure_pipe::create_secured_server(&name, crate::secure_pipe::PIPE_SDDL)
            .expect_err("a non-admin must not add an instance");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }

    #[cfg(windows)]
    fn current_process_is_elevated() -> bool {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        // SAFETY: pseudo-handle; correctly sized out-params; the token is closed before return.
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return true; // unknown: treat as elevated, i.e. skip
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(std::ptr::addr_of_mut!(elevation).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            let _ = CloseHandle(token);
            ok.is_err() || elevation.TokenIsElevated != 0
        }
    }
}
