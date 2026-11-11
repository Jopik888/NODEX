const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const EXPECTED_COMPONENTS = Object.freeze({
  node: { version: '24.22.3', file: 'runtime/node.exe' },
  postgres: { version: '17.11', file: 'postgres/bin/postgres.exe' },
  kubo: { version: '0.43.1', file: 'ipfs/ipfs.exe' },
});
const REQUIRED_INTEGRITY = Object.freeze([
  'nodeShasumsSignature',
  'postgresArchiveSha256',
  'postgresAuthenticode',
  'kuboArchiveSha256',
]);
const REQUIRED_ARCHIVES = Object.freeze([
  'nodeWindowsZip',
  'postgresBinariesZip',
  'kuboWindowsZip',
]);

/**
 * Validate manifest provenance and the exact staged runtime bytes.
 * Returns a list of actionable errors; it never modifies files.
 */
function validateRuntimeManifest({ manifest, assetsRoot }) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object') {
    return ['Runtime manifest is missing or is not an object.'];
  }
  if (!assetsRoot || typeof assetsRoot !== 'string') {
    return ['Runtime assets directory is not configured.'];
  }
  if (manifest.schemaVersion !== 1 || manifest.platform !== 'win32-x64') {
    errors.push('Runtime manifest schemaVersion/platform is invalid for NODEX Windows x64.');
  }

  for (const name of REQUIRED_INTEGRITY) {
    if (manifest.integrityVerification?.[name] !== 'VERIFIED') {
      errors.push(`integrityVerification.${name} must be VERIFIED.`);
    }
  }

  for (const name of REQUIRED_ARCHIVES) {
    if (!/^[a-f0-9]{64}$/i.test(manifest.archiveSha256?.[name] || '')) {
      errors.push(`archiveSha256.${name} must contain a verified SHA-256.`);
    }
  }

  let realAssetsRoot;
  try {
    realAssetsRoot = fs.realpathSync(assetsRoot);
  } catch (error) {
    return [...errors, `Runtime assets directory cannot be resolved: ${error.message}`];
  }

  for (const [name, expected] of Object.entries(EXPECTED_COMPONENTS)) {
    const component = manifest.components?.[name];
    if (!component || component.version !== expected.version
      || !/^[a-f0-9]{64}$/i.test(component.sha256 || '') || typeof component.file !== 'string') {
      errors.push(`components.${name} must declare version ${expected.version}, a runtime file path, and a verified SHA-256.`);
      continue;
    }

    const filePath = path.resolve(realAssetsRoot, component.file);
    const relative = path.relative(realAssetsRoot, filePath);
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
      errors.push(`components.${name}.file escapes the runtime assets directory.`);
      continue;
    }
    if (component.file !== expected.file) {
      errors.push(`components.${name}.file must use the approved path ${expected.file}.`);
      continue;
    }

    let realFile;
    try {
      realFile = fs.realpathSync(filePath);
    } catch (error) {
      errors.push(`Runtime file for ${name} is missing or cannot be resolved: ${error.message}`);
      continue;
    }

    const realRelative = path.relative(realAssetsRoot, realFile);
    if (!realRelative || realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
      errors.push(`Runtime file for ${name} resolves outside the runtime assets directory.`);
      continue;
    }

    const digest = crypto.createHash('sha256').update(fs.readFileSync(realFile)).digest('hex');
    if (digest.toLowerCase() !== component.sha256.toLowerCase()) {
      errors.push(`Runtime hash mismatch for ${name}: expected ${component.sha256}, got ${digest}.`);
    }
  }

  return errors;
}

module.exports = { validateRuntimeManifest };
