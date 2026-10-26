//! A string newtype that refuses to print itself.
//!
//! SOCKS5 credentials and license tokens are stored as [`Secret`] so that the
//! type system — not careful logging discipline — keeps them out of traces and
//! diagnostic bundles. `Debug` and `Display` render `***`;
//! serde is transparent so the real value still round-trips through config
//! files. The only way to read the value is the explicit [`Secret::expose`].
//!
//! At rest the value is therefore **plaintext JSON, protected by the file ACL** (a
//! SYSTEM/Admins-only `%ProgramData%` config), not encrypted — there is no DPAPI/machine-scope
//! encryption today. `Secret` is purely an in-memory/redaction guard, not at-rest encryption.
//!
//! In memory the buffer is **zeroized on drop** (`zeroize`), so a password does not linger in
//! freed heap after a `Config` is replaced (e.g. each `SetConfig` hot-reload drops the prior
//! config). This does not cover transient `expose().to_string()` clones at call sites, nor a
//! `String` reallocation made while the value was being built — it is a best-effort scrub of the
//! stored value's final buffer, not a guarantee against a determined memory-forensics adversary.
//! Call sites that must encode a secret (an auth header, a SOCKS5 auth message) build the encoded
//! form in a [`Secret`] / [`SecretBytes`] sized up front, so those temporaries are scrubbed too;
//! copies made by the OS, SSPI, TLS or the allocator are outside this crate's reach.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A secret string that redacts itself in `Debug`/`Display` output and zeroizes on drop.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying secret value.
    ///
    /// Call sites are responsible for never logging or otherwise exposing the
    /// returned string.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// A byte buffer that holds secret material while a credential is being encoded onto the wire
/// (e.g. an RFC 1929 sub-negotiation message carrying a password). Redacted in `Debug` and
/// zeroized on drop, like [`Secret`]. Build it at its final size ([`SecretBytes::with_capacity`])
/// so growth never leaves an unscrubbed reallocated copy behind.
#[derive(Default)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Append bytes (stays within the reserved capacity if it was sized correctly).
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    pub fn push(&mut self, byte: u8) {
        self.0.push(byte);
    }

    /// Borrow the bytes. Call sites must never log them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes({} bytes, ***)", self.0.len())
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn redacts_in_debug_and_display() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s}"), "***");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        // The real value is still reachable when explicitly requested.
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn secret_bytes_redact_in_debug() {
        let mut b = super::SecretBytes::with_capacity(8);
        b.extend_from_slice(b"hunter2");
        b.push(b'!');
        assert_eq!(format!("{b:?}"), "SecretBytes(8 bytes, ***)");
        assert_eq!(b.expose(), b"hunter2!");
    }

    #[test]
    fn serializes_transparently() {
        let s = Secret::new("hunter2");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"hunter2\"");
        let back: Secret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), "hunter2");
    }
}
