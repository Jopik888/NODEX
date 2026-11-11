import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { config } from '../config/index.js';

const AAD_VERSION = 'account-sync-room-v1';

export function encryptSyncRoomId(userId, roomId) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', config.syncRoomEncryptionKey, nonce);
  cipher.setAAD(Buffer.from(`${AAD_VERSION}:${config.syncRoomEncryptionKeyVersion}:${userId}`, 'utf8'));
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(roomId, 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  // Stored as nonce (12 bytes) || auth tag (16 bytes) || ciphertext.
  return Buffer.concat([nonce, tag, encrypted]);
}

export function decryptSyncRoomId(userId, storedValue, keyVersion) {
  if (keyVersion !== config.syncRoomEncryptionKeyVersion) {
    throw new Error(`Unsupported sync identity encryption key version: ${keyVersion}`);
  }
  if (!Buffer.isBuffer(storedValue) || storedValue.length < 29) {
    throw new Error('Stored account sync identity is malformed.');
  }
  const nonce = storedValue.subarray(0, 12);
  const tag = storedValue.subarray(12, 28);
  const ciphertext = storedValue.subarray(28);
  const decipher = createDecipheriv('aes-256-gcm', config.syncRoomEncryptionKey, nonce);
  decipher.setAAD(Buffer.from(`${AAD_VERSION}:${config.syncRoomEncryptionKeyVersion}:${userId}`, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

export function createSyncRoomId() {
  return randomBytes(32).toString('base64url');
}
