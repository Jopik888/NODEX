import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;

const vaultCrypto = await import('../../secure-disk/vault-crypto.js');
const deviceCrypto = await import('../../secure-disk/crypto.js');

function b64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

test('VMK envelope seals and opens only for the intended X25519 key and AAD context', async () => {
  const recipient = await webcrypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const publicBytes = new Uint8Array(await webcrypto.subtle.exportKey('raw', recipient.publicKey));
  const vmk = webcrypto.getRandomValues(new Uint8Array(32));
  const context = {
    userId: 'user-1',
    vaultId: 'vault-1',
    deviceId: 'device-2',
    purpose: 'pairing',
    requestId: 'request-3',
  };
  const envelope = await vaultCrypto.sealVmkForDevice(vmk, b64(publicBytes), context);
  const opened = await vaultCrypto.openVmkEnvelopeWithPrivateKey(recipient.privateKey, envelope, context);
  assert.deepEqual(opened, vmk);
  await assert.rejects(
    vaultCrypto.openVmkEnvelopeWithPrivateKey(recipient.privateKey, envelope, { ...context, deviceId: 'device-other' }),
  );
  await assert.rejects(
    vaultCrypto.openVmkEnvelopeWithPrivateKey(recipient.privateKey, envelope, { ...context, requestId: 'request-other' }),
  );
});

test('file-key envelope round-trip is bound to user, vault, and CID', async () => {
  const vmk = webcrypto.getRandomValues(new Uint8Array(32));
  const keyString = 'v2:3mJr7AoUXx2Wqd:1111111111111111';
  const context = { userId: 'user-1', vaultId: 'vault-1', cid: 'bafy-test-cid' };
  const envelope = await vaultCrypto.wrapFileKey(vmk, context, keyString);
  assert.equal(await vaultCrypto.unwrapFileKey(vmk, context, envelope), keyString);
  await assert.rejects(vaultCrypto.unwrapFileKey(vmk, { ...context, cid: 'bafy-other-cid' }, envelope));
  await assert.rejects(vaultCrypto.unwrapFileKey(webcrypto.getRandomValues(new Uint8Array(32)), context, envelope));
});

test('VMK and file-key envelope lengths match AES-256-GCM format', async () => {
  const recipient = await webcrypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const publicBytes = new Uint8Array(await webcrypto.subtle.exportKey('raw', recipient.publicKey));
  const vmk = webcrypto.getRandomValues(new Uint8Array(32));
  const context = { userId: 'u', vaultId: 'v', deviceId: 'd', purpose: 'device-envelope' };
  const envelope = await vaultCrypto.sealVmkForDevice(vmk, b64(publicBytes), context);
  assert.equal(Buffer.from(envelope.ephemeral_public_key, 'base64').length, 32);
  assert.equal(Buffer.from(envelope.salt, 'base64').length, 16);
  assert.equal(Buffer.from(envelope.nonce, 'base64').length, 12);
  assert.equal(Buffer.from(envelope.ciphertext, 'base64').length, 48);
});

test('pairing QR signature binds request token, device ID and both public keys', async () => {
  const signing = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const signingPublic = new Uint8Array(await webcrypto.subtle.exportKey('raw', signing.publicKey));
  const encryption = await webcrypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const encryptionPublic = new Uint8Array(await webcrypto.subtle.exportKey('raw', encryption.publicKey));
  const request = {
    requestId: '11111111-1111-4111-8111-111111111111',
    pairingToken: 'A'.repeat(43),
    deviceId: '22222222-2222-4222-8222-222222222222',
    signingPublicKey: b64(signingPublic),
    encryptionPublicKey: b64(encryptionPublic),
    expiresAt: '2030-01-01T00:00:00.000Z',
  };
  const message = vaultCrypto.buildPairingRequestMessage(request);
  const signature = b64(await webcrypto.subtle.sign('Ed25519', signing.privateKey, new TextEncoder().encode(message)));
  assert.equal(await deviceCrypto.verifyPublicSignature(request.signingPublicKey, message, signature), true);
  assert.equal(await deviceCrypto.verifyPublicSignature(request.signingPublicKey, message.replace('A'.repeat(43), 'B'.repeat(43)), signature), false);
});

test('legacy migration never keeps a plaintext key beside a valid envelope', async () => {
  const vmk = webcrypto.getRandomValues(new Uint8Array(32));
  const context = { userId: 'user-1', vaultId: 'vault-1', cid: 'bafy-existing' };
  const envelope = await vaultCrypto.wrapFileKey(vmk, context, 'v2:legacy-key-material');
  const result = await vaultCrypto.migrateLegacyVaultFileKeys(vmk, context.userId, context.vaultId, [
    { cid: context.cid, name: 'already-wrapped.bin', key: 'must-not-survive', vaultKeyEnvelope: envelope },
    { cid: null, name: 'malformed.bin', key: 'must-also-be-removed' },
  ]);
  assert.equal(result.changed, true);
  assert.equal(Object.hasOwn(result.files[0], 'key'), false);
  assert.equal(Object.hasOwn(result.files[1], 'key'), false);
  assert.equal(await vaultCrypto.unwrapFileKey(vmk, context, result.files[0].vaultKeyEnvelope), 'v2:legacy-key-material');
});
