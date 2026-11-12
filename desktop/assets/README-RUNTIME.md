# NODEX Alpha 1 — Windows runtime assets

Runtime binaries are downloaded during the dedicated Windows build workflow. Never download a moving `latest` version and never execute a binary before its source archive has been verified.

## Pinned Windows x64 components

| Component | Version | Source artifact | Verification |
|---|---:|---|---|
| Node.js | 24.22.3 | Official `node-v24.22.3-win-x64.zip` | Verify detached signature of `SHASUMS256.txt` using the official Node.js active releaser keyring, then check archive SHA-256 |
| PostgreSQL | 17.11 | EDB `postgresql-17.11-4-windows-x64-binaries.zip` | Verify exact vendor-published SHA-256 before extraction |
| Kubo | 0.43.1 | Official `kubo_v0.43.1_windows-amd64.zip` | Verify official `.sha512` sidecar before extraction |

The staging script is `desktop/scripts/prepare-runtime.ps1`. It downloads the exact pinned artifacts, verifies them, extracts the complete PostgreSQL `bin/`, `lib/`, and `share/` layout, preserves upstream license files, computes executable hashes, validates exact runtime versions, and writes `RUNTIME-MANIFEST.json`.

## PostgreSQL signature status — closed Alpha limitation

EDB's published SHA-256 for the exact 17.11-4 ZIP is `b9424ee7bc60b52450ff910a3630225df32e633f3cb29c1d126d9299d59aea28`. EDB has stated that expanded Authenticode signing coverage is in progress, but its public issue still documents unsigned PostgreSQL EXE/DLL files and does not yet confirm that the portable ZIP is fully signed. The staging script inspects every EXE/DLL under `bin/` and `lib/`; invalid or untrusted signatures fail the build.

For the user's explicitly approved **closed Alpha 1**, unsigned PostgreSQL binaries are recorded as `NOT_SIGNED_INTERNAL_ALPHA`. Packaging requires both this manifest state and the explicit `NODEX_ALPHA_ALLOW_UNSIGNED_POSTGRES=1` opt-in. This is not acceptable for public distribution. Windows Smart App Control may block unsigned PostgreSQL binaries even though the downloaded archive and executable hashes match; the Alpha test machine may need Smart App Control compatibility verified before testing. Do not represent this as a signed or public-ready distribution.

## Runtime manifest contract

The generated manifest records:
- exact version, source URL, archive filename and staged executable path for each component;
- SHA-256 of each source archive and staged executable;
- Node.js detached-signature verification;
- EDB archive digest verification and actual Authenticode state;
- Kubo official sidecar verification;
- closed-Alpha/unsigned distribution status and included license files.

The build preflight verifies the manifest, executable hashes, exact versions, PostgreSQL PE signature state, backend production dependencies and lockfiles. Desktop startup repeats manifest, path containment, executable hash and exact-version checks. A missing or mismatched value fails closed.

## PostgreSQL runtime layout and lifecycle

Alpha 1 uses the portable EDB Windows x64 binary ZIP, not embedded-postgres and not a machine-wide installer/service. The full extracted distribution lives under `desktop/assets/postgres/`. Electron's service manager initializes the cluster on first launch, binds PostgreSQL to `127.0.0.1:5432`, creates the NODEX database, runs existing migrations, and stops only the NODEX data directory on application shutdown. Data remains under `%APPDATA%\\NODEX` and is not deleted by uninstall.

## Kubo runtime layout and lifecycle

Kubo 0.43.1 runs as a child process managed by Electron. Its API and Gateway are forced to `127.0.0.1`; they are never exposed to LAN. Shutdown is requested through the loopback API before a process-termination fallback. Kubo 0.43.1 is a closed-Alpha compatibility pin only; Beta must reassess active maintenance and the Helia/fork migration path.

## Build commands

On Windows x64, after the runtime staging script and locked backend dependencies have completed:

```powershell
pwsh -File .\\scripts\\prepare-runtime.ps1
cd ..\\secure-disk-backend
npm ci --omit=dev
cd ..\\desktop
npm ci
$env:NODEX_ALPHA_ALLOW_UNSIGNED_POSTGRES = '1'
npm run dist:win
```

The reproducible GitHub Actions workflow `.github/workflows/alpha1-windows-build.yml` performs staging, verification, dependency installation, preflight, NSIS installer creation and portable EXE creation, then uploads both artifacts for 30 days.

## Licensing

Upstream license/notice files are retained for Node.js, PostgreSQL and Kubo. Review all transitive notices before public redistribution. Successful archive verification does not replace license review.
