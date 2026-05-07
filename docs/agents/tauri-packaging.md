# Tauri packaging — `justrdp-tauri`

How to produce a production binary of the Tauri reference client and
verify its security posture.

## TL;DR

```bash
cd justrdp-tauri
pnpm install
pnpm tauri build      # produces MSI on Windows / DMG on macOS / AppImage on Linux
```

The MSI lands in `src-tauri/target/release/bundle/msi/*.msi`.

## Requirements

- Rust toolchain (stable)
- pnpm (the project's chosen JS package manager — see `tauri.conf.json`'s `beforeDevCommand`)
- Tauri CLI: `pnpm add -D @tauri-apps/cli` (already in `devDependencies`)
- **Windows**: WebView2 Runtime (pre-installed on Windows 11; bundled by the Tauri MSI for Windows 10)
- **macOS**: Xcode Command Line Tools
- **Linux**: GTK / WebKit dev headers (`libwebkit2gtk-4.1-dev`, etc.)

## Security configuration (Slice F)

Three files lock down what the Tauri webview can reach:

- `src-tauri/tauri.conf.json` — `app.security.csp` defines the
  Content Security Policy. Slice F set this to a strict
  `default-src 'self'` policy with explicit `connect-src` /
  `img-src` / `style-src` / `script-src` / `font-src` directives.
  Dev mode (Vite HMR) bypasses CSP automatically.
- `src-tauri/capabilities/default.json` — Tauri 2 capability
  allow-list. Reduced to `core:default` only. No `dialog:*`,
  `fs:*`, `shell:*`, `notification:*`, `opener:*`, or HTTP plugin
  permissions.
- `src-tauri/Cargo.toml` — production builds **must not** pass
  `--features dev-no-verify`. With the feature off, the
  `dangerous_no_verify` TLS path in `lib.rs::rdp_connect` is gated
  behind `#[cfg(feature = "dev-no-verify")]` and is not compiled
  into the binary at all (verifiable with `nm` / `strings`).

## Build commands

### Development

```bash
pnpm tauri dev
# or, to enable the dangerous TLS bypass for local iteration:
pnpm tauri dev -- -- --features dev-no-verify
```

### Production (Windows MSI)

```bash
pnpm tauri build
# artifacts:
#   src-tauri/target/release/bundle/msi/justrdp-tauri_<version>_x64_en-US.msi
#   src-tauri/target/release/justrdp-tauri.exe
```

To tighten further, override the bundle target:

```bash
pnpm tauri build -- --bundles msi
```

### Production (macOS DMG / Linux AppImage)

Same `pnpm tauri build`; the Tauri CLI picks the appropriate
bundler from the host OS. Cross-bundling is out of scope for
Slice F — track as follow-up.

## Verification checklist

After `pnpm tauri build` finishes:

- [ ] Artifact exists at `src-tauri/target/release/bundle/msi/*.msi`
      (Windows) or equivalent on other OSes
- [ ] The MSI installs and the installed binary launches
- [ ] Connecting to a real RDP server (e.g. 192.168.136.136)
      reproduces dev-mode behavior — same Slice C/D1/D2/E
      checks pass
- [ ] `strings src-tauri/target/release/justrdp-tauri.exe |
      grep dangerous_no_verify` returns no matches (the cargo
      feature gate elides the symbol)
- [ ] No `tauri::api::*` import appears in `src-tauri/src/`
      that the capability set does not authorise

## Outstanding follow-ups

- macOS DMG and Linux AppImage builds verified on their host OSes.
- Code signing / notarisation (Apple Developer ID, Windows EV
  cert).
- Tauri auto-updater integration.
- CI workflow that runs `pnpm tauri build` on each push and
  uploads artifacts.
