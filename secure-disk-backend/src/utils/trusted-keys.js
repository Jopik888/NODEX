const DEVICE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Build a no-store map of active device IDs to canonical Ed25519 public keys. */
export function createTrustedKeysMap(rows, currentDeviceId) {
  if (!Array.isArray(rows) || typeof currentDeviceId !== 'string' || !DEVICE_ID_RE.test(currentDeviceId)) return null;
  const trustedKeys = Object.create(null);
  for (const row of rows) {
    if (row?.status !== 'active' || typeof row.id !== 'string' || !DEVICE_ID_RE.test(row.id) || typeof row.public_key !== 'string') continue;
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(row.public_key)) continue;
    const raw = Buffer.from(row.public_key, 'base64');
    if (raw.length !== 32 || raw.toString('base64') !== row.public_key) continue;
    trustedKeys[row.id] = row.public_key;
  }
  return Object.hasOwn(trustedKeys, currentDeviceId) ? trustedKeys : null;
}
