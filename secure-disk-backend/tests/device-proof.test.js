import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

test('Ed25519 raw public key reconstructed by backend verifies signed challenge', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const raw = spki.subarray(-32);
  assert.equal(raw.length, 32);
  const reconstructed = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki',
  });
  const message = Buffer.from('SecureDisk-Device-Proof-v1\nchallenge_id=test\nnonce=unique');
  const signature = sign(null, message, privateKey);
  assert.equal(verify(null, message, reconstructed, signature), true);
  assert.equal(verify(null, Buffer.from('different challenge'), reconstructed, signature), false);
});

test('Ed25519 signatures are 64 bytes', () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  assert.equal(sign(null, Buffer.from('test'), privateKey).length, 64);
});
