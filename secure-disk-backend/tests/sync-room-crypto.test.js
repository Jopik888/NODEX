import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/test';
process.env.SYNC_ROOM_ENCRYPTION_KEY_BASE64 ||= randomBytes(32).toString('base64');
process.env.SYNC_ROOM_ENCRYPTION_KEY_VERSION ||= 'test-v1';

const { encryptSyncRoomId, decryptSyncRoomId, createSyncRoomId } = await import('../src/services/sync-room-crypto.js');

test('sync room identity encrypts and decrypts with user-bound AAD', () => {
  const userId = '6d7eaaae-4bcd-47a0-8f69-f33f1f96b8a2';
  const roomId = createSyncRoomId();
  const encrypted = encryptSyncRoomId(userId, roomId);
  assert.notEqual(encrypted.toString('utf8'), roomId);
  assert.equal(decryptSyncRoomId(userId, encrypted, 'test-v1'), roomId);
  assert.throws(() => decryptSyncRoomId('another-user-id', encrypted, 'test-v1'));
  assert.throws(() => decryptSyncRoomId(userId, encrypted, 'older-key-v0'));
});
