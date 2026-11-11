# NODEX Alpha 1 — Windows runtime assets

This directory intentionally contains no executable third-party binaries in the source archive. Do not download `latest` builds at install time and do not run unverified binaries.

## Pinned candidate set for Windows x64

| Component | Candidate version | Required staged file(s) | Official source |
|---|---:|---|---|
| Node.js | 24.22.3 LTS | `runtime/node.exe` | https://nodejs.org/dist/v24.22.3/win-x64/node.exe |
| PostgreSQL | 17.11 (EDB Windows ZIP revision must be selected and verified) | Full EDB binaries distribution under `postgres/` with `bin/`, `lib/`, `share/` | https://www.enterprisedb.com/download-postgresql-binaries |
| Kubo | 0.43.1 | `ipfs/ipfs.exe` | https://dist.ipfs.tech/kubo/v0.43.1/kubo_v0.43.1_windows-amd64.zip |

Node.js 24.22.3 is the current pinned LTS security release (2026-11-11), superseding 24.22.2; see https://github.com/nodejs/node/releases/tag/v24.22.3. The signed upstream SHASUMS publish `86fc4785327db5f5c7558dc6156c543b433c313e813a222e088086222ab4afa6` for `win-x64/node.exe` and `e612af99f626ab415ea225af6bce5c971feb448cb5cae250bb1c3fa50c5f7d9f` for `node-v24.22.3-win-x64.zip`. These are expected upstream hashes, not a claim that a local binary has already been downloaded and independently verified. The PGP signature still must be checked by the staging workflow.

For PostgreSQL, do not reuse the EDB `17.11-4` checksum for a later ZIP revision. EDB has a more recent `17.11-5` Windows x64 archive listed by current package metadata, but a vendor-confirmed digest and full Authenticode signing coverage for every EXE/DLL are not yet verified. EDB's signing coverage remains an explicit blocker: its public issue documents unsigned server executables and libraries and contains no confirmation yet that the portable ZIP is fully signed. Do not stage/package PostgreSQL until the exact archive digest and binary signing are checked. See https://github.com/EnterpriseDB/edb-installers/issues/713 and https://github.com/EnterpriseDB/edb-installers/issues/706. Do not use the EDB installer executable as a substitute for the portable binary ZIP.

For Kubo, retain the release archive, official `.sha512` sidecar and license files alongside the extracted `ipfs.exe`. Verify the downloaded archive against the sidecar, then compute the SHA-256 of the staged `ipfs.exe` for the runtime manifest. Verify the release using the official Kubo release page and official `dist.ipfs.tech` distribution.

## PostgreSQL packaging decision\n\nAlpha 1 uses the official EDB Windows x64 portable binary ZIP, not embedded-postgres and not a machine-wide PostgreSQL installer/service. Stage the complete extracted distribution under `desktop/assets/postgres/` preserving `bin/`, `lib/`, and `share/`. Electron's service manager runs `initdb.exe` on first launch, starts the private cluster with `pg_ctl.exe` bound only to 127.0.0.1, creates the NODEX database, runs existing migrations, and stops the cluster on exit. The data directory remains in the user's NODEX app-data folder and is not removed by uninstall. No PostgreSQL service registration or administrator-level installation is required.\n\n## Staging rules

1. Preserve the vendor's complete PostgreSQL binary layout. Keep all DLLs in `bin/` and the full `lib/` and `share/` trees; do not copy only `postgres.exe`/`initdb.exe`. Before acceptance, verify all `.exe`/`.dll` files in `bin/` and `lib/` with `Get-AuthenticodeSignature`; require `Status -eq Valid` and confirm publisher identity. A passing archive hash alone is not enough for Windows Smart App Control.
2. Stage the Node runtime at `runtime/node.exe`.
3. Stage Kubo at `ipfs/ipfs.exe`.
4. Fill `RUNTIME-MANIFEST.json` with the exact downloaded filename, source URL, SHA-256 for each staged executable and source archive, integrity verification results (`VERIFIED` only after actual SHA/signature verification), and license details before building. Required status keys are `nodeShasumsSignature`, `postgresArchiveSha256`, `postgresAuthenticode`, and `kuboArchiveSha256`. Windows preflight checks executable hashes and PostgreSQL Authenticode signatures; the desktop service manager repeats runtime manifest, version, and executable hash checks at every startup.
5. Build the backend dependencies on Windows x64 using the staged Node 24.22.3 runtime and a committed `package-lock.json`; verify the native `argon2` module loads under that exact runtime.
6. Build on Windows 10/11 x64 and run the installer/integration checklist. Linux syntax checks are not a substitute.

## Kubo maintenance risk

NODEX Alpha 1 decision: retain Kubo 0.43.1 for closed Alpha only. The exact version is enforced by `service-manager.cjs` and `preflight.cjs`; the executable SHA-256 must be verified in `RUNTIME-MANIFEST.json`. Docker is not used: Kubo runs as a separate Windows process under the Electron service manager. See `../IPFS-ALPHA-DECISION.md` for the decision, constraints, and migration gate.


Kubo 0.43.1 is the latest release shown by the official Kubo release page as of 2026-11-11. The release page also states that Shipyard's IPFS work ended on 2026-09-30 and that 0.43 is its last Kubo release. Treat 0.43.1 as an Alpha compatibility candidate, not as a long-term maintenance guarantee. Before a public release, reassess the active Kubo maintenance/fork situation and security update path.

## Licensing and redistribution

Keep all upstream LICENSE/NOTICE files. Verify each component's redistribution terms and third-party notices before publishing the installer. Do not assume that downloading a binary automatically grants permission to redistribute it in every packaging context.
