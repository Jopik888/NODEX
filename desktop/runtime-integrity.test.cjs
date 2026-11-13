const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { validateRuntimeManifest } = require('./runtime-integrity.cjs');

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nodex-runtime-integrity-'));
  const files = {
    node: ['runtime/node.exe', Buffer.from('node-runtime')],
    postgres: ['postgres/bin/postgres.exe', Buffer.from('postgres-runtime')],
    kubo: ['ipfs/ipfs.exe', Buffer.from('kubo-runtime')],
  };
  const components = {};
  for (const [name, [relative, bytes]] of Object.entries(files)) {
    const target = path.join(root, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, bytes);
    const version = { node: '24.22.3', postgres: '17.11', kubo: '0.43.1' }[name];
    components[name] = { version, file: relative, sha256: sha256(bytes) };
  }
  const manifest = {
    schemaVersion: 1,
    platform: 'win32-x64',
    components,
    archiveSha256: {
      nodeWindowsZip: 'a'.repeat(64),
      postgresBinariesZip: 'b'.repeat(64),
      kuboWindowsZip: 'c'.repeat(64),
    },
    integrityVerification: {
      nodeShasumsSignature: 'VERIFIED',
      postgresArchiveSha256: 'VERIFIED',
      postgresAuthenticode: 'VERIFIED',
      kuboArchiveSha256: 'VERIFIED',
    },
  };
  return { root, manifest, files };
}

test('accepts a fully verified manifest whose staged runtime hashes match', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  assert.deepEqual(validateRuntimeManifest({ manifest: f.manifest, assetsRoot: f.root }), []);
});

test('rejects an executable whose bytes do not match its manifest hash', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  fs.appendFileSync(path.join(f.root, f.files.node[0]), '-tampered');
  assert.ok(validateRuntimeManifest({ manifest: f.manifest, assetsRoot: f.root })
    .some((error) => error.includes('Runtime hash mismatch for node')));
});

test('rejects runtime components without verified source/signature states', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  f.manifest.integrityVerification.postgresAuthenticode = 'PENDING';
  assert.ok(validateRuntimeManifest({ manifest: f.manifest, assetsRoot: f.root })
    .some((error) => error.includes('postgresAuthenticode must be VERIFIED')));
});

test('allows unsigned PostgreSQL only in an explicitly marked closed Alpha build', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  f.manifest.releaseChannel = 'closed-alpha';
  f.manifest.installerSigning = 'unsigned';
  f.manifest.integrityVerification.postgresAuthenticode = 'NOT_SIGNED_INTERNAL_ALPHA';
  assert.deepEqual(validateRuntimeManifest({ manifest: f.manifest, assetsRoot: f.root }), []);
  f.manifest.releaseChannel = 'public';
  assert.ok(validateRuntimeManifest({ manifest: f.manifest, assetsRoot: f.root })
    .some((error) => error.includes('postgresAuthenticode')));
});

test('rejects a missing archive digest and path traversal outside the assets root', (t) => {
  const f = fixture();
  t.after(() => fs.rmSync(f.root, { recursive: true, force: true }));
  f.manifest.archiveSha256.kuboWindowsZip = '';
  f.manifest.components.node.file = '../node.exe';
  const errors = validateRuntimeManifest({ manifest: f.manifest, assetsRoot: f.root });
  assert.ok(errors.some((error) => error.includes('archiveSha256.kuboWindowsZip')));
  assert.ok(errors.some((error) => error.includes('components.node.file escapes')));
});
