import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { decodeRawPublicKey } from '../src/utils/public-key-format.js';

test('decodes canonical Base64 public keys of exactly 32 bytes', () => {
  const raw = randomBytes(32);
  const encoded = raw.toString('base64');
  assert.deepEqual(decodeRawPublicKey(encoded), raw);
});

test('rejects malformed, non-canonical and wrong-length public keys', () => {
  assert.equal(decodeRawPublicKey('not-base64!!!'), null);
  assert.equal(decodeRawPublicKey(randomBytes(31).toString('base64')), null);
  assert.equal(decodeRawPublicKey(randomBytes(33).toString('base64')), null);
  assert.equal(decodeRawPublicKey(''), null);
  assert.equal(decodeRawPublicKey(null), null);
});
