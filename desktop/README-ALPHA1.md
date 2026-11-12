# NODEX Windows Alpha 1 — сборка и runtime

## Реализовано в feature/alpha1-build-preparation

- Electron main/preload shell with `contextIsolation`, `sandbox`, `nodeIntegration: false`.
- Local frontend HTTP origin on `127.0.0.1:4173`; backend remains loopback-only on `127.0.0.1:3001`.
- Windows DPAPI-backed encrypted storage for generated PostgreSQL password and sync-room encryption key via Electron `safeStorage`.
- PostgreSQL first-run cluster initialization under `%APPDATA%/NODEX`, private loopback listener, database creation and existing SQL migrations.
- Kubo repo initialization; API and Gateway are forced to `127.0.0.1`. Kubo is never exposed to LAN.
- Backend health check and ordered shutdown: backend receives SIGTERM, Kubo is asked to shut down through its loopback API with process fallback, and the NODEX PostgreSQL cluster is stopped with `pg_ctl -m fast`. User data is retained on uninstall.
- A Windows runtime staging script downloads exact pinned Node.js 24.22.3, PostgreSQL 17.11-5 portable ZIP and Kubo 0.43.1. It verifies Node.js release signature and pinned archive SHA-256, EDB's vendor-published PostgreSQL archive SHA-256, Kubo's official SHA-512 sidecar, executable hashes and exact runtime versions; it preserves upstream license files and generates the runtime manifest.
- Runtime integrity validation is shared by build preflight and desktop startup. It rejects missing archives/hashes, altered executables, path traversal, version drift and invalid/untrusted PostgreSQL Authenticode signatures.
- A dedicated Windows 2022 GitHub Actions workflow installs production backend dependencies and Electron build dependencies from lockfiles, stages and verifies runtime, runs preflight, builds NSIS installer and portable executable, then uploads both as a workflow artifact.
- Electron 45.3.0 and electron-builder 26.18.0 are pinned. NSIS is configured not to remove NODEX app data on uninstall.

## Closed Alpha signing policy

The user explicitly approved unsigned Alpha 1 packaging. The installer and portable EXE are unsigned. EDB's PostgreSQL 17.11-5 portable archive may also contain unsigned EXE/DLL files. The staging script retains only PostgreSQL `bin/`, `lib/`, and `share/` runtime trees (excluding debug symbols and manuals); invalid or untrusted signatures stop the build. If files are merely unsigned, the manifest records `NOT_SIGNED_INTERNAL_ALPHA`, and build preflight requires the explicit `NODEX_ALPHA_ALLOW_UNSIGNED_POSTGRES=1` opt-in plus `releaseChannel=closed-alpha`.

**Important:** Windows Smart App Control may block unsigned PostgreSQL binaries. This package is for closed Alpha testing only and is not public-release ready. Do not disable Windows security protections merely to make the installer run; report any block so we can select a properly signed PostgreSQL distribution or revise the packaging plan. Commercial Authenticode signing is deferred until public release as agreed.

## Build

The build is reproducible from the feature branch on a Windows x64 runner. In GitHub Actions, run workflow:

`NODEX Alpha 1 Windows build`

The workflow stages runtime automatically, installs backend production dependencies with `npm ci --omit=dev`, verifies native Argon2 under the pinned Node.js runtime, installs Electron dependencies with `npm ci`, and executes `npm run dist:win`. It uploads:
- `NODEX-Alpha-1-Windows-x64` — NSIS installer and portable executable (plus blockmaps and generated runtime manifest).

Workflow artifact retention is 30 days. The build must not be considered complete until the workflow succeeds and both executable artifacts are present.

For a local Windows x64 build:

```powershell
pwsh -File .\\scripts\\prepare-runtime.ps1
cd ..\\secure-disk-backend
npm ci --omit=dev
cd ..\\desktop
npm ci
$env:NODEX_ALPHA_ALLOW_UNSIGNED_POSTGRES = '1'
npm run dist:win
```

## Current Alpha 1 scope and remaining test gates

1. Android LAN is still intentionally disabled. The backend binds only to loopback. Safe HTTPS, Android certificate trust and WebView cookie/CSRF behavior require a native Android project and device tests; do not bind to `0.0.0.0`.
2. SMTP is not configured by default. Backend Alpha uses development-mode `DEV_RETURN_VERIFICATION_TOKEN=true` for test registration; it is not a public production server.
3. Frontend still has ESM/CDN dependencies (Trystero, JSZip, qrcode-generator, html5-qrcode); internet access is required until these are localized and their licenses reviewed.
4. Kubo 0.43.1 is pinned for closed Alpha compatibility only. Beta must reassess maintenance and choose a supported fork or migration to Helia.
5. Real Windows 10/11 install, upgrade, first-run DB initialization/migrations, Kubo lifecycle, uninstall/data retention and Smart App Control behavior require the user's device testing after artifact creation.
6. CI previously passed 71 backend tests and 4 runtime-integrity tests; backend audit reported zero vulnerabilities. Desktop dependency audit reports six moderate `minimatch` advisory items in the Electron Builder dependency tree, no high/critical findings. Do not run `npm audit fix --force` because it proposes a major-version change.

## Safety boundaries

- No changes to existing cryptography, VMK, AES-GCM, Ed25519/X25519, pairing or P2P handshake/trustedPeers.
- No Kubo API/Gateway LAN exposure; no Android direct Kubo access; Android IPFS operations must use the restricted authenticated/CSRF-protected backend proxy.
- Existing database migrations and data formats are not rewritten.
- All implementation work remains on `feature/alpha1-build-preparation`; do not merge this draft PR without review and explicit approval.
