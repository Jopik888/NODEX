# NODEX Alpha 1 — Windows runtime assets

Runtime binaries are downloaded during the dedicated Windows build workflow. Never download a moving `latest` version and never execute a binary before its source archive has been verified.

## Pinned Windows x64 components

| Component | Version | Source artifact | Verification |
|---|---:|---|---|
| Node.js | 24.22.3 | Official `node-v24.22.3-win-x64.zip` | Verify official clear-signed `SHASUMS256.txt.asc` with the pinned Node release keyring and approved signer fingerprint, then check archive SHA-256 |
| PostgreSQL | 17.11 (EDB revision 17.11-5) | `postgresql-17.11-5-windows-x64-binaries.zip` | Verify EDB's official `.sha256` sidecar and pinned archive SHA-256 |
| Kubo | 0.43.1 | Official `kubo_v0.43.1_windows-amd64.zip` | Verify official `.sha512` sidecar before extraction |

The staging script is `desktop/scripts/prepare-runtime.ps1`. It downloads the exact pinned artifacts, verifies them, extracts the complete PostgreSQL `bin/`, `lib/`, and `share/` layout, preserves upstream license files, computes executable hashes, validates exact runtime versions, and writes `RUNTIME-MANIFEST.json`. Node.js release ZIP SHA-256 is pinned to `e612af99f626ab415ea225af6bce5c971feb448cb5cae250bb1c3fa50c5f7d9f`; the staged `node.exe` SHA-256 is pinned to `86fc4785327db5f5c7558dc6156c543b433c313e813a222e088086222ab4afa6`. Kubo Windows ZIP SHA-256 is pinned to the official GitHub release asset digest `c25871516dec4d97ce1d160a26c1e3fdad294cb0eea065c0c0343bcfca86c524`; the official `.sha512` sidecar's SHA-256 is pinned to `99ded6a03faa39a92417f15781da332b8ed014840e089cca354cea347ce40717`.

## PostgreSQL archive identity and Authenticode

The selected archive is EDB PostgreSQL 17.11-5:
- ZIP: `https://get.enterprisedb.com/postgresql/postgresql-17.11-5-windows-x64-binaries.zip`
- Official checksum sidecar: `https://get.enterprisedb.com/postgresql/postgresql-17.11-5-windows-x64-binaries.zip.sha256`
- Pinned SHA-256: `80379b2c04d51c30225532e0ae04509899141e9957ed096fe749d7fd9df8f82f`

EDB confirmed this SHA-256 in its issue tracker and linked the official checksum sidecar. A public report for this archive identified `postgres.exe`, `initdb.exe`, and `pg_ctl.exe` as `NotSigned`; EDB has not yet confirmed that all portable EXE/DLL files are Authenticode-signed. The staging script therefore inspects every EXE/DLL under `bin/` and `lib/`; invalid or untrusted signatures fail the build.

For the user's explicitly approved **closed Alpha 1**, unsigned PostgreSQL PE files are recorded as `NOT_SIGNED_INTERNAL_ALPHA`. Packaging requires both this manifest state and the explicit `NODEX_ALPHA_ALLOW_UNSIGNED_POSTGRES=1` opt-in. This is not acceptable for public distribution. Windows Smart App Control may block unsigned PostgreSQL binaries even though the downloaded archive and executable hashes match; do not disable Windows security protections to work around a block.

## Runtime manifest contract

The generated manifest records:
- exact version, source URL, archive filename and staged executable path for each component;
- SHA-256 of each source archive and staged executable;
- Node.js detached/clear-signature verification and expected signing-key fingerprint;
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
