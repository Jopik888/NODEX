import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

const subtle = webcrypto.subtle;

test('Ed25519 keys are 32-byte raw public keys and private keys can sign without being extractable', async () => {
  const pair = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  assert.equal(pair.privateKey.extractable, false);
  const publicRaw = await subtle.exportKey('raw', pair.publicKey);
  assert.equal(publicRaw.byteLength, 32);

  const message = new TextEncoder().encode('secure-disk-ed25519-test');
  const signature = await subtle.sign('Ed25519', pair.privateKey, message);
  assert.equal(signature.byteLength, 64);
  assert.equal(await subtle.verify('Ed25519', pair.publicKey, signature, message), true);
});

test('X25519 keys are 32-byte raw public keys and derive matching shared secrets', async () => {
  const alice = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const bob = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  assert.equal(alice.privateKey.extractable, false);
  const aliceRaw = await subtle.exportKey('raw', alice.publicKey);
  const bobRaw = await subtle.exportKey('raw', bob.publicKey);
  assert.equal(aliceRaw.byteLength, 32);
  assert.equal(bobRaw.byteLength, 32);
  const fromAlice = await subtle.deriveBits({ name: 'X25519', public: bob.publicKey }, alice.privateKey, 256);
  const fromBob = await subtle.deriveBits({ name: 'X25519', public: alice.publicKey }, bob.privateKey, 256);
  assert.deepEqual(new Uint8Array(fromAlice), new Uint8Array(fromBob));
});
