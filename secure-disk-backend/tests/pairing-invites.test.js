import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const route = await readFile(new URL('../src/routes/pairing.routes.js', import.meta.url), 'utf8');
const devices = await readFile(new URL('../src/routes/devices.routes.js', import.meta.url), 'utf8');
const migration = await readFile(new URL('../migrations/004_device_pairing_invites.sql', import.meta.url), 'utf8');
const app = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
const auth = await readFile(new URL('../../secure-disk/auth.js', import.meta.url), 'utf8');

 test('migration creates one-time invite storage with constrained states and token hash', () => {
  assert.match(migration, /CREATE TABLE IF NOT EXISTS device_pairing_invites/);
  for (const column of ['invite_token_hash', 'initiator_device_id', 'claimed_by_device_public_key', 'claimed_by_encryption_public_key', 'encrypted_vmk_blob', 'expires_at', 'completed_at']) {
    assert.match(migration, new RegExp(`\\b${column}\\b`));
  }
  assert.match(migration, /octet_length\(invite_token_hash\)=32/);
  assert.match(migration, /status IN \('pending','claimed','approved','completed','cancelled','expired'\)/);
  assert.match(migration, /device_pairing_invites_one_live_per_user_idx/);
});

test('invite endpoints are mounted under /devices/pairing', () => {
  assert.match(app, /api\.use\('\/devices\/pairing', pairingRoutes\)/);
  for (const routePath of ["router.post('/invite'", "router.post('/claim'", "router.get('/invite/:inviteId/status'", "router.post('/:inviteId/approve'", "router.get('/:inviteId/result'", "router.post('/:inviteId/complete'", "router.post('/invite/:inviteId/cancel'"]) {
    assert.ok(route.includes(routePath), `Missing route: ${routePath}`);
  }
  for (const apiMethod of ['createPairingInvite', 'getPairingInviteStatus', 'claimPairingInvite', 'approvePairingInvite', 'getPairingInviteResult', 'completePairingInvite', 'cancelPairingInvite']) {
    assert.match(auth, new RegExp(`export async function ${apiMethod}\\(`));
  }
});

test('QR token is hashed at rest and claim is bound to registered device public keys', () => {
  assert.match(route, /randomBytes\(32\)\.toString\('base64url'\)/);
  assert.match(route, /invite_token_hash/);
  assert.match(route, /hashToken\(parsed\.data\.invite_token\)/);
  assert.match(route, /safeEqual\(target\.public_key, claimedSigningKey\)/);
  assert.match(route, /safeEqual\(target\.encryption_public_key, claimedEncryptionKey\)/);
  assert.match(route, /claimed_by_device_id/);
});

test('server accepts and stores only an encrypted envelope, with device signatures for approval and completion', () => {
  assert.match(route, /approvalMessage\(/);
  assert.match(route, /completionMessage\(/);
  assert.match(route, /verifySignature\(/);
  assert.match(route, /encrypted_vmk_blob/);
  assert.match(route, /INSERT INTO key_envelopes/);
  assert.doesNotMatch(route, /req\.body\.vmk\b|plaintext_vmk/i);
});

test('device revocation cancels related live invites and clears the encrypted envelope', () => {
  assert.match(devices, /UPDATE device_pairing_invites SET status='cancelled'/);
  assert.match(devices, /encrypted_vmk_blob=NULL/);
  assert.match(devices, /pairing_invite_cancelled/);
});
