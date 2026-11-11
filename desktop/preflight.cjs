const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '..');
const checks = [
  ['Node.js runtime', path.join(__dirname, 'assets', 'runtime', 'node.exe')],
  ['PostgreSQL postgres.exe', path.join(__dirname, 'assets', 'postgres', 'bin', 'postgres.exe')],
  ['PostgreSQL runtime libraries', path.join(__dirname, 'assets', 'postgres', 'lib')],
  ['PostgreSQL initdb.exe', path.join(__dirname, 'assets', 'postgres', 'bin', 'initdb.exe')],
  ['PostgreSQL pg_ctl.exe', path.join(__dirname, 'assets', 'postgres', 'bin', 'pg_ctl.exe')],
  ['PostgreSQL createdb.exe', path.join(__dirname, 'assets', 'postgres', 'bin', 'createdb.exe')],
  ['PostgreSQL share/server', path.join(__dirname, 'assets', 'postgres', 'share', 'server')],
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

const expectedVersions = { node: '24.22.3', postgres: '17.11', kubo: '0.43.1' };
for (const [name, expectedVersion] of Object.entries(expectedVersions)) {
  const component = manifest.components?.[name];
  if (!component || component.version !== expectedVersion || !/^[a-f0-9]{64}$/i.test(component.sha256 || '')) {
    console.error(`Runtime manifest entry '${name}' must declare version ${expectedVersion} and a verified SHA-256.`);
    process.exit(1);
  }
  const filePath = path.join(__dirname, 'assets', component.file || '');
  const digest = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
  if (digest.toLowerCase() !== component.sha256.toLowerCase()) {
    console.error(`Runtime hash mismatch for ${name}: expected ${component.sha256}, got ${digest}`);
    process.exit(1);
  }
}
if (Object.values(manifest.integrityVerification || {}).some((value) => value !== 'VERIFIED')) {
  console.error('Runtime manifest integrityVerification entries must all be VERIFIED.');
  process.exit(1);
}
for (const [name, digest] of Object.entries(manifest.archiveSha256 || {})) {
  if (!/^[a-f0-9]{64}$/i.test(digest || '')) {
    console.error(`Runtime manifest archiveSha256.${name} must contain a verified SHA-256.`);
    process.exit(1);
  }
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
  "$roots = @($env:NODEX_PG_BIN, $env:NODEX_PG_LIB)",
  "$files = @(Get-ChildItem -LiteralPath $roots -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' })",
  "if ($files.Count -eq 0) { Write-Error 'No PostgreSQL executable or DLL files were found.'; exit 1 }",
  "$invalid = @($files | ForEach-Object { $signature = Get-AuthenticodeSignature -LiteralPath $_.FullName; if ($signature.Status -ne 'Valid') { [PSCustomObject]@{ Path = $_.FullName; Status = [string]$signature.Status; Signer = $signature.SignerCertificate.Subject } } })",
  "if ($invalid.Count -gt 0) { $invalid | ConvertTo-Json -Compress | Write-Output; exit 1 }",
  "Write-Output ('Verified Authenticode signatures for ' + $files.Count + ' PostgreSQL EXE/DLL files.')",
].join('; ');
const signatures = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', signatureScript], {
  encoding: 'utf8',
  windowsHide: true,
  maxBuffer: 4 * 1024 * 1024,
  env: { ...process.env, NODEX_PG_BIN: postgresBin, NODEX_PG_LIB: postgresLib },
});
if (signatures.error || signatures.status !== 0) {
  console.error('PostgreSQL Authenticode verification failed. Every EXE/DLL in bin/ and lib/ must have a valid trusted signature.');
  console.error((signatures.stdout || signatures.stderr || signatures.error?.message || '').trim());
  process.exit(1);
}
console.log((signatures.stdout || '').trim());

console.log('NODEX Alpha 1 Windows x64 packaging preflight: PASS');
