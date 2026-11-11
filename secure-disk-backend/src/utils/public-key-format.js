/** Decode canonical RFC 4648 Base64 containing exactly one raw 32-byte public key. */
export function decodeRawPublicKey(value) {
  if (typeof value !== 'string') return null;
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== value) return null;
  return decoded;
}
