# Proxroute GUI

A Windows desktop interface for Proxroute, built with GPUI. It displays connections and
events, explains routing decisions, and edits configuration through the local management API.
See [the GUI guide](gui/README.md) for the interface and runtime setup.

This source snapshot contains the GUI and its two shared libraries. The Proxroute service,
engine, command-line program, and kernel driver are separate products and are not included.
The GUI can be built from this directory without access to their source repositories. It
needs a compatible, separately installed Proxroute service and driver to manage traffic.
Until the service is available, the GUI reports that the engine is not reachable.

## Licences

| Component | Licence |
| --- | --- |
| GUI (`gui/`) | [GPL-3.0-or-later](gui/LICENSE), with the full text in [COPYING](COPYING) |
| `proxroute-ipc` | [MIT](crates/proxroute-ipc/LICENSE-MIT) **OR** [Apache-2.0](crates/proxroute-ipc/LICENSE-APACHE), at your choice |
| `proxroute-config` | [MIT](crates/proxroute-config/LICENSE-MIT) **OR** [Apache-2.0](crates/proxroute-config/LICENSE-APACHE), at your choice |
| Third-party dependencies | Their own licences; see [the notices](gui/THIRD-PARTY-NOTICES.txt) |

The root [LICENSE](LICENSE) explains the scope. Sharing this source does not grant a licence
to the separately supplied service or driver.

## Build on Windows

Install Rust with the MSVC toolchain and Visual Studio Build Tools with the C++ build tools
and Windows SDK. Build from `gui/` so Cargo uses its checked-in MSVC linker configuration:

```powershell
cd gui
cargo build --release --locked
```

The executable is `gui/target/release/proxroute-gui.exe` when `CARGO_TARGET_DIR` is unset.
Compiling does not need administrator privileges, an installed driver, or a certificate.
Running the GUI against the service currently requires elevation because the management
pipe is restricted to SYSTEM and Administrators.

The first build fetches dependencies from public crates.io and GitHub sources and can take
several minutes and multiple GB. `gui/Cargo.lock` fixes their resolved versions and Git
revisions. There are no dependencies on a private repository or the private engine source.
`rust-toolchain.toml` selects the floating `stable` channel; the snapshot's local validation
uses Rust 1.98.1 on Windows x64. The lockfile does not make executable bytes reproducible
across compiler versions or build environments. This package contains no executable release.

## Test the exported code

From `gui/`:

```powershell
cargo test --release --locked -p proxroute-gui -p proxroute-config -p proxroute-ipc
```

Add `--offline` to build or test when the pinned dependencies are already cached.
The shared libraries inherit a few values from the root workspace; the GUI has its own
workspace and lockfile. Keep the directory structure intact.

## Source identity and scope

The GUI and shared-library source files are exported unchanged from revision
`d2ae57a9a0b19383b9c0c15918ff8bfbda524949`, version `0.1.0`. The root Cargo workspace is
generated with only the inheritance values these libraries need. Public-facing root
documentation, licence copies and dependency notices accompany the export.
[SOURCE-MANIFEST.json](SOURCE-MANIFEST.json) records the provenance and the SHA-256 of every
other file in the package.

The private product's driver remediation is ongoing. Publishing or building this GUI
source does not certify the driver's R03/RW-139 fixes or enable production record
reclamation. The current per-proxy `dns: local` setting is modeled but not yet enforced;
the GUI flags that limitation. This export makes no claim of a validated production bundle.
