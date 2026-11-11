import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) globalThis.btoa = value => Buffer.from(value, 'binary').toString('base64');
if (!globalThis.atob) globalThis.atob = value => Buffer.from(value, 'base64').toString('binary');

const { verifyP2PHandshakeSignature } = await import('../../secure-disk/crypto.js');

test('frontend P2P verifier accepts the matching Ed25519 signature', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, new TextEncoder().encode('NODEX P2P test transcript bound to both endpoint identities')));
  const b64 = bytes => Buffer.from(bytes).toString('base64');
  assert.equal(await verifyP2PHandshakeSignature(b64(raw), 'NODEX P2P test transcript bound to both endpoint identities', b64(signature)), true);
  assert.equal(await verifyP2PHandshakeSignature(b64(raw), 'NODEX P2P different transcript bound to both endpoint identities', b64(signature)), false);
});

test('frontend P2P verifier rejects malformed key and signature encodings', async () => {
  await assert.rejects(() => verifyP2PHandshakeSignature('bad', 'NODEX P2P test transcript bound to both endpoint identities', 'bad'));
});
