const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { validateRuntimeManifest } = require('./runtime-integrity.cjs');

const root = path.resolve(__dirname, '..');
const checks = [
  ['Node.js runtime', path.join(__dirname, 'assets', 'runtime', 'node.exe')],
  ['PostgreSQL postgres.exe', path.join(__dirname, 'assets', 'postgres', 'bin', 'postgres.exe')],
  ['PostgreSQL runtime libraries', path.join(__dirname, 'assets', 'postgres', 'lib')],
  ['PostgreSQL initdb.exe', path.join(__dirname, 'assets', 'postgres', 'bin', 'initdb.exe')],
  ['PostgreSQL pg_ctl.exe', path.join(__dirname, 'assets', 'postgres', 'bin', 'pg_ctl.exe')],
  ['PostgreSQL createdb.exe', path.join(__dirname, 'assets', 'postgres', 'bin', 'createdb.exe')],
  ['PostgreSQL extension support files', path.join(__dirname, 'assets', 'postgres', 'share', 'extension')],
  ['Kubo ipfs.exe', path.join(__dirname, 'assets', 'ipfs', 'ipfs.exe')],
  ['Backend production dependencies', path.join(root, 'secure-disk-backend', 'node_modules', 'argon2')],
  ['Backend package-lock.json', path.join(root, 'secure-disk-backend', 'package-lock.json')],
  ['Desktop package-lock.json', path.join(__dirname, 'package-lock.json')],
  ['Runtime provenance manifest', path.join(__dirname, 'assets', 'RUNTIME-MANIFEST.json')],
];

if (process.platform !== 'win32' || process.arch !== 'x64') {
  console.error('Windows packaging must run on Windows x64.');
  process.exit(1);
}

const missing = checks.filter(([, target]) => !fs.existsSync(target));
if (missing.length) {
  console.error('NODEX Alpha 1 packaging blocked. Missing audited assets:');
  for (const [label, target] of missing) console.error(`- ${label}: ${target}`);
  process.exit(1);
}

const manifestPath = path.join(__dirname, 'assets', 'RUNTIME-MANIFEST.json');
let manifest;
try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); }
catch (error) { console.error(`Invalid runtime manifest: ${error.message}`); process.exit(1); }

const runtimeErrors = validateRuntimeManifest({
  manifest,
  assetsRoot: path.join(__dirname, 'assets'),
});
if (runtimeErrors.length) {
  console.error('Runtime manifest validation failed:');
  for (const error of runtimeErrors) console.error(`- ${error}`);
  process.exit(1);
}

const nodeExe = path.join(__dirname, 'assets', 'runtime', 'node.exe');
const version = spawnSync(nodeExe, ['--version'], { encoding: 'utf8', windowsHide: true });
if (version.status !== 0 || version.stdout.trim() !== 'v24.22.3') {
  console.error(`Expected bundled Node.js v24.22.3, got: ${(version.stdout || version.stderr || '').trim()}`);
  process.exit(1);
}

const versionChecks = [
  [path.join(__dirname, 'assets', 'postgres', 'bin', 'postgres.exe'), ['--version'], 'postgres (PostgreSQL) 17.11'],
  [path.join(__dirname, 'assets', 'ipfs', 'ipfs.exe'), ['--version'], 'ipfs version 0.43.1'],
];
for (const [executable, args, expected] of versionChecks) {
  const result = spawnSync(executable, args, { encoding: 'utf8', windowsHide: true });
  if (result.status !== 0 || result.stdout.trim() !== expected) {
    console.error(`Expected ${expected}, got: ${(result.stdout || result.stderr || '').trim()}`);
    process.exit(1);
  }
}

const postgresBin = path.join(__dirname, 'assets', 'postgres', 'bin');
const postgresLib = path.join(__dirname, 'assets', 'postgres', 'lib');
const signatureScript = [
  "$ErrorActionPreference = 'Stop'",
  "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop",
  "$roots = @($env:NODEX_PG_BIN, $env:NODEX_PG_LIB)",
  "$files = @(Get-ChildItem -LiteralPath $roots -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' })",
  "if ($files.Count -eq 0) { Write-Error 'No PostgreSQL executable or DLL files were found.'; exit 1 }",
  "$statuses = @($files | ForEach-Object { [string](Get-AuthenticodeSignature -LiteralPath $_.FullName).Status })",
  "if (@($statuses | Where-Object { $_ -notin @('Valid', 'NotSigned') }).Count -gt 0) { Write-Error 'PostgreSQL binaries contain an invalid or untrusted Authenticode signature.'; exit 1 }",
  "if (@($statuses | Where-Object { $_ -eq 'NotSigned' }).Count -gt 0) { Write-Output 'NOT_SIGNED_INTERNAL_ALPHA' } else { Write-Output 'VERIFIED' }",
].join('; ');
const signatures = spawnSync('pwsh.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', signatureScript], {
  encoding: 'utf8',
  windowsHide: true,
  maxBuffer: 4 * 1024 * 1024,
  env: { ...process.env, NODEX_PG_BIN: postgresBin, NODEX_PG_LIB: postgresLib },
});
if (signatures.error || signatures.status !== 0) {
  console.error('PostgreSQL Authenticode inspection failed.');
  console.error((signatures.stdout || signatures.stderr || signatures.error?.message || '').trim());
  process.exit(1);
}
const actualSignatureState = (signatures.stdout || '').trim().split(/\r?\n/).pop();
if (actualSignatureState !== manifest.integrityVerification.postgresAuthenticode) {
  console.error(`PostgreSQL signature state mismatch: manifest=${manifest.integrityVerification.postgresAuthenticode}, actual=${actualSignatureState}`);
  process.exit(1);
}
if (actualSignatureState === 'NOT_SIGNED_INTERNAL_ALPHA'
  && (manifest.releaseChannel !== 'closed-alpha'
    || manifest.installerSigning !== 'unsigned'
    || process.env.NODEX_ALPHA_ALLOW_UNSIGNED_POSTGRES !== '1')) {
  console.error('Unsigned PostgreSQL files are permitted only for an explicitly opted-in, unsigned closed Alpha build.');
  process.exit(1);
}
console.log(`PostgreSQL Authenticode state: ${actualSignatureState}`);

console.log('NODEX Alpha 1 Windows x64 packaging preflight: PASS');
