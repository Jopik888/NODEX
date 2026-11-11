import { Router } from 'express';
import { createHash, randomBytes, randomUUID, timingSafeEqual, createPublicKey, verify as verifySignature } from 'node:crypto';
import { z } from 'zod';
import { pool, withTransaction, lockUserSecurityState } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { requireCsrf, requireSessionCsrf } from '../middleware/csrf.js';
import { deviceRegisterLimiter } from '../middleware/rate-limit.js';

const router = Router();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const envelopeSchema = z.object({
  ephemeral_public_key: z.string().min(40).max(48),
  salt: z.string().min(20).max(24),
  nonce: z.string().min(16).max(20),
  ciphertext: z.string().min(60).max(72),
}).strict();

router.use(requireAuth);

// v0.4.3 Invite-based flow. The new device must first sign in to the same
// account and complete the existing Ed25519 proof-of-possession challenge.
// QR contains only { invite_id, invite_token, expiry }; no public/private key,
// VMK, session cookie or user secret is embedded in it.
const inviteClaimSchema = z.object({
  invite_id: z.string().uuid(),
  invite_token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  public_key: z.string().min(40).max(48),
  encryption_public_key: z.string().min(40).max(48),
}).strict();

function invitePublicDevice(row) {
  return {
    id: row.claimed_by_device_id,
    device_name: row.device_name,
    device_type: row.device_type,
    platform: row.platform,
    signing_public_key: Buffer.from(row.claimed_by_device_public_key).toString('base64'),
    encryption_public_key: Buffer.from(row.claimed_by_encryption_public_key).toString('base64'),
    fingerprint: createHash('sha256').update(row.claimed_by_device_public_key).update(row.claimed_by_encryption_public_key).digest('hex').slice(0, 16),
  };
}

router.post('/invite', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    const source = await currentTrustedDevice(req, res);
    if (!source) return;
    const inviteId = randomUUID();
    const inviteToken = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    const outcome = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      const session = await client.query(
        `SELECT d.id FROM devices d JOIN sessions s ON s.device_id=d.id AND s.user_id=d.user_id
          WHERE d.id=$1 AND d.user_id=$2 AND d.status='active' AND s.id=$3
            AND s.revoked_at IS NULL AND s.access_expires_at>now() AND s.expires_at>now()
          FOR UPDATE OF d,s`,
        [source.id, req.auth.userId, req.auth.sessionId],
      );
      if (!session.rowCount) return { error: 'DEVICE_OR_SESSION_NOT_ACTIVE' };
      const vault = await client.query('SELECT id FROM vaults WHERE user_id=$1 FOR UPDATE', [req.auth.userId]);
      if (!vault.rowCount) return { error: 'VAULT_NOT_INITIALIZED' };
      const sourceEnvelope = await client.query(
        `SELECT 1 FROM key_envelopes WHERE vault_id=$1 AND user_id=$2 AND device_id=$3 AND envelope_type='device'`,
        [vault.rows[0].id, req.auth.userId, source.id],
      );
      if (!sourceEnvelope.rowCount) return { error: 'SOURCE_VAULT_ACCESS_MISSING' };
      await client.query(
        `UPDATE device_pairing_invites SET status='expired',encrypted_vmk_blob=NULL,approved_at=NULL,approved_by_session_id=NULL
          WHERE user_id=$1 AND status IN ('pending','claimed','approved') AND expires_at<=now()`,
        [req.auth.userId],
      );
      const pending = await client.query(
        `SELECT id FROM device_pairing_invites WHERE user_id=$1 AND status IN ('pending','claimed','approved') LIMIT 1`,
        [req.auth.userId],
      );
      if (pending.rowCount) return { error: 'PAIRING_INVITE_ALREADY_ACTIVE' };
      await client.query(
        `INSERT INTO device_pairing_invites(id,user_id,initiator_device_id,initiator_session_id,
          invite_token_hash,vault_id,expires_at)
         VALUES($1,$2,$3,$4,$5,$6,$7)`,
        [inviteId, req.auth.userId, source.id, req.auth.sessionId, hashToken(inviteToken), vault.rows[0].id, expiresAt],
      );
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
         VALUES($1,$2,$3,'pairing_invite_created',$4::jsonb)`,
        [req.auth.userId, source.id, req.auth.sessionId, JSON.stringify({ invite_id: inviteId, expires_at: expiresAt.toISOString() })],
      );
      return { created: true };
    });
    if (outcome.error === 'DEVICE_OR_SESSION_NOT_ACTIVE') return error(res, 409, outcome.error, 'Доверенное устройство или сессия больше не активны.');
    if (outcome.error === 'VAULT_NOT_INITIALIZED') return error(res, 409, outcome.error, 'Сначала инициализируйте Сейф на доверенном устройстве.');
    if (outcome.error === 'SOURCE_VAULT_ACCESS_MISSING') return error(res, 409, outcome.error, 'На этом устройстве нет действующего конверта ключа Сейфа.');
    if (outcome.error === 'PAIRING_INVITE_ALREADY_ACTIVE') return error(res, 409, outcome.error, 'У аккаунта уже есть активное приглашение. Отмените его или дождитесь истечения срока.');
    res.set('Cache-Control', 'no-store');
    return res.status(201).json({ invite_id: inviteId, invite_token: inviteToken, expires_at: expiresAt.toISOString() });
  } catch (e) { return next(e); }
});

router.post('/claim', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    const parsed = inviteClaimSchema.safeParse(req.body);
    if (!parsed.success) return error(res, 422, 'VALIDATION_ERROR', 'Данные приглашения или ключи устройства имеют неверный формат.');
    const token = tokenBytes(parsed.data.invite_token);
    const claimedSigningKey = decodeCanonical(parsed.data.public_key, 32);
    const claimedEncryptionKey = decodeCanonical(parsed.data.encryption_public_key, 32);
    if (!token || !claimedSigningKey || !claimedEncryptionKey) return error(res, 422, 'INVALID_CLAIM_KEYS', 'Токен или публичные ключи устройства некорректны.');
    const target = await currentTrustedDevice(req, res);
    if (!target) return;
    if (!safeEqual(target.public_key, claimedSigningKey) || !safeEqual(target.encryption_public_key, claimedEncryptionKey)) {
      return error(res, 409, 'CLAIM_KEY_MISMATCH', 'Публичные ключи не совпадают с проверенной идентичностью текущего устройства.');
    }
    const inviteId = req.body?.invite_id;
    if (!UUID_RE.test(inviteId || '')) return error(res, 422, 'INVALID_INVITE_ID', 'invite_id должен быть UUID.');
    const outcome = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      const selected = await client.query(
        `SELECT i.*, d.status AS initiator_status
           FROM device_pairing_invites i
           JOIN devices d ON d.id=i.initiator_device_id AND d.user_id=i.user_id
          WHERE i.id=$1 AND i.user_id=$2 FOR UPDATE OF i,d`,
        [inviteId, req.auth.userId],
      );
      if (!selected.rowCount) return { error: 'PAIRING_INVITE_NOT_FOUND' };
      const invite = selected.rows[0];
      if (!safeEqual(hashToken(parsed.data.invite_token), invite.invite_token_hash)) return { error: 'PAIRING_INVITE_NOT_FOUND' };
      if (invite.status !== 'pending' || invite.expires_at <= new Date()) {
        if (invite.status === 'pending') await client.query(`UPDATE device_pairing_invites SET status='expired' WHERE id=$1`, [inviteId]);
        return { error: 'PAIRING_INVITE_EXPIRED' };
      }
      if (invite.initiator_device_id === req.auth.deviceId) return { error: 'PAIRING_INVITE_SELF_CLAIM' };
      if (invite.initiator_status !== 'active') return { error: 'PAIRING_INITIATOR_REVOKED' };
      const activeSession = await client.query(
        `SELECT d.id FROM devices d JOIN sessions s ON s.device_id=d.id AND s.user_id=d.user_id
          WHERE d.id=$1 AND d.user_id=$2 AND d.status='active' AND s.id=$3
            AND s.revoked_at IS NULL AND s.access_expires_at>now() AND s.expires_at>now()
          FOR UPDATE OF d,s`,
        [req.auth.deviceId, req.auth.userId, req.auth.sessionId],
      );
      if (!activeSession.rowCount) return { error: 'CLAIM_DEVICE_NOT_ACTIVE' };
      const existingEnvelope = await client.query(
        `SELECT 1 FROM key_envelopes WHERE vault_id=$1 AND user_id=$2 AND device_id=$3 AND envelope_type='device'`,
        [invite.vault_id, req.auth.userId, req.auth.deviceId],
      );
      if (existingEnvelope.rowCount) return { error: 'DEVICE_ALREADY_PAIRED' };
      await client.query(
        `UPDATE device_pairing_invites SET status='claimed',claimed_by_device_id=$2,
          claimed_by_device_public_key=$3,claimed_by_encryption_public_key=$4,claimed_at=now()
         WHERE id=$1`,
        [inviteId, req.auth.deviceId, claimedSigningKey, claimedEncryptionKey],
      );
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
         VALUES($1,$2,$3,'pairing_invite_claimed',$4::jsonb)`,
        [req.auth.userId, req.auth.deviceId, req.auth.sessionId, JSON.stringify({ invite_id: inviteId, initiator_device_id: invite.initiator_device_id })],
      );
      return { claimed: true };
    });
    if (outcome.error === 'PAIRING_INVITE_NOT_FOUND') return error(res, 404, outcome.error, 'Приглашение не найдено. Проверьте QR-код и аккаунт.');
    if (outcome.error === 'PAIRING_INVITE_EXPIRED') return error(res, 410, outcome.error, 'Приглашение истекло или уже использовано. Создайте новый QR-код.');
    if (outcome.error === 'PAIRING_INVITE_SELF_CLAIM') return error(res, 409, outcome.error, 'Нельзя подключить то же устройство, которое создало приглашение.');
    if (outcome.error === 'PAIRING_INITIATOR_REVOKED') return error(res, 409, outcome.error, 'Доверенное устройство-инициатор отозвано.');
    if (outcome.error === 'CLAIM_DEVICE_NOT_ACTIVE') return error(res, 409, outcome.error, 'Новое устройство ещё не прошло проверку ключа. Перезагрузите приложение и повторите попытку.');
    if (outcome.error === 'DEVICE_ALREADY_PAIRED') return error(res, 409, outcome.error, 'Это устройство уже подключено к Сейфу.');
    res.set('Cache-Control', 'no-store');
    return res.json({ claimed: true, status: 'claimed' });
  } catch (e) { return next(e); }
});

router.get('/invite/:inviteId/status', async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.inviteId)) return error(res, 400, 'INVALID_INVITE_ID', 'Идентификатор приглашения некорректен.');
    const result = await pool.query(
      `SELECT i.*, d.device_name,d.device_type,d.platform
         FROM device_pairing_invites i
         LEFT JOIN devices d ON d.id=i.claimed_by_device_id AND d.user_id=i.user_id
        WHERE i.id=$1 AND i.user_id=$2 AND i.initiator_device_id=$3`,
      [req.params.inviteId, req.auth.userId, req.auth.deviceId],
    );
    if (!result.rowCount) return error(res, 404, 'PAIRING_INVITE_NOT_FOUND', 'Приглашение не найдено.');
    const row = result.rows[0];
    if (row.status !== 'completed' && row.expires_at <= new Date() && ['pending','claimed','approved'].includes(row.status)) {
      await pool.query(`UPDATE device_pairing_invites SET status='expired',encrypted_vmk_blob=NULL,approved_at=NULL,approved_by_session_id=NULL WHERE id=$1 AND status IN ('pending','claimed','approved')`, [row.id]);
      row.status = 'expired';
    }
    res.set('Cache-Control', 'no-store');
    return res.json({
      invite_id: row.id,
      status: row.status,
      expires_at: row.expires_at,
      claimed_device: row.claimed_by_device_id ? invitePublicDevice(row) : null,
    });
  } catch (e) { return next(e); }
});

router.get('/:inviteId/result', async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.inviteId)) return error(res, 400, 'INVALID_INVITE_ID', 'Идентификатор приглашения некорректен.');
    const result = await pool.query(
      `SELECT i.*, v.id AS confirmed_vault_id
         FROM device_pairing_invites i
         LEFT JOIN vaults v ON v.id=i.vault_id AND v.user_id=i.user_id
        WHERE i.id=$1 AND i.user_id=$2 AND i.claimed_by_device_id=$3`,
      [req.params.inviteId, req.auth.userId, req.auth.deviceId],
    );
    if (!result.rowCount) return error(res, 404, 'PAIRING_INVITE_NOT_FOUND', 'Приглашение не найдено для этого устройства.');
    const row = result.rows[0];
    if (row.status !== 'completed' && row.expires_at <= new Date() && ['pending','claimed','approved'].includes(row.status)) {
      await pool.query(`UPDATE device_pairing_invites SET status='expired',encrypted_vmk_blob=NULL,approved_at=NULL,approved_by_session_id=NULL WHERE id=$1 AND status IN ('pending','claimed','approved')`, [row.id]);
      row.status = 'expired';
    }
    res.set('Cache-Control', 'no-store');
    return res.json({
      invite_id: row.id,
      status: row.status,
      expires_at: row.expires_at,
      vault_id: row.confirmed_vault_id,
      envelope: row.status === 'approved' ? row.encrypted_vmk_blob : null,
    });
  } catch (e) { return next(e); }
});

// The same /:id/approve path is used by the legacy request flow. If this UUID
// belongs to a new invitation, process it here; otherwise fall through.
router.post('/:inviteId/approve', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.inviteId)) return next();
    const exists = await pool.query(`SELECT id FROM device_pairing_invites WHERE id=$1 AND user_id=$2`, [req.params.inviteId, req.auth.userId]);
    if (!exists.rowCount) return next();
    const source = await currentTrustedDevice(req, res);
    if (!source) return;
    const envelope = decodeEnvelope(req.body?.envelope);
    const signature = decodeSignature(req.body?.signature);
    if (!envelope || !signature) return error(res, 422, 'INVALID_PAIRING_PROOF', 'Конверт VMK или подпись имеет неверный формат.');
    const outcome = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      const selected = await client.query(
        `SELECT i.*, t.public_key AS target_signing_key,t.encryption_public_key AS target_encryption_key,t.status AS target_status
           FROM device_pairing_invites i
           JOIN devices t ON t.id=i.claimed_by_device_id AND t.user_id=i.user_id
          WHERE i.id=$1 AND i.user_id=$2 FOR UPDATE OF i,t`,
        [req.params.inviteId, req.auth.userId],
      );
      if (!selected.rowCount) return { error: 'PAIRING_INVITE_NOT_FOUND' };
      const row = selected.rows[0];
      if (row.initiator_device_id !== source.id) return { error: 'NOT_INVITE_INITIATOR' };
      if (row.status !== 'claimed' || row.expires_at <= new Date()) {
        if (row.status === 'claimed') await client.query(`UPDATE device_pairing_invites SET status='expired' WHERE id=$1`, [row.id]);
        return { error: 'PAIRING_INVITE_EXPIRED' };
      }
      if (row.target_status !== 'active') return { error: 'TARGET_DEVICE_NOT_ACTIVE' };
      if (!safeEqual(row.claimed_by_device_public_key, row.target_signing_key) || !safeEqual(row.claimed_by_encryption_public_key, row.target_encryption_key)) return { error: 'CLAIMED_DEVICE_KEY_CHANGED' };
      const sourceCheck = await client.query(
        `SELECT d.public_key FROM devices d JOIN sessions s ON s.device_id=d.id AND s.user_id=d.user_id
          WHERE d.id=$1 AND d.user_id=$2 AND d.status='active' AND s.id=$3
            AND s.revoked_at IS NULL AND s.access_expires_at>now() AND s.expires_at>now()
          FOR UPDATE OF d,s`,
        [source.id, req.auth.userId, req.auth.sessionId],
      );
      if (!sourceCheck.rowCount) return { error: 'SOURCE_DEVICE_NOT_ACTIVE' };
      if (!row.vault_id) return { error: 'VAULT_NOT_INITIALIZED' };
      const digest = envelopeDigest(envelope);
      const message = approvalMessage({ requestId: row.id, sourceDeviceId: source.id, targetDeviceId: row.claimed_by_device_id, vaultId: row.vault_id, digest });
      if (!verifySignature(null, Buffer.from(message, 'utf8'), ed25519PublicKey(sourceCheck.rows[0].public_key), signature)) return { error: 'INVALID_SOURCE_SIGNATURE' };
      const blob = {
        ephemeral_public_key: envelope.ephemeral.toString('base64'),
        salt: envelope.saltBytes.toString('base64'),
        nonce: envelope.nonceBytes.toString('base64'),
        ciphertext: envelope.ciphertextBytes.toString('base64'),
      };
      await client.query(
        `UPDATE device_pairing_invites SET status='approved',approved_at=now(),approved_by_session_id=$2,
          encrypted_vmk_blob=$3::jsonb WHERE id=$1`,
        [row.id, req.auth.sessionId, JSON.stringify(blob)],
      );
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
         VALUES($1,$2,$3,'pairing_invite_approved',$4::jsonb)`,
        [req.auth.userId, source.id, req.auth.sessionId, JSON.stringify({ invite_id: row.id, target_device_id: row.claimed_by_device_id })],
      );
      return { approved: true };
    });
    if (outcome.error === 'PAIRING_INVITE_NOT_FOUND') return error(res, 404, outcome.error, 'Приглашение не найдено.');
    if (outcome.error === 'NOT_INVITE_INITIATOR') return error(res, 403, outcome.error, 'Одобрить приглашение может только устройство, которое его создало.');
    if (outcome.error === 'PAIRING_INVITE_EXPIRED') return error(res, 410, outcome.error, 'Приглашение истекло или уже обработано.');
    if (outcome.error === 'TARGET_DEVICE_NOT_ACTIVE') return error(res, 409, outcome.error, 'Новое устройство больше не активно.');
    if (outcome.error === 'CLAIMED_DEVICE_KEY_CHANGED') return error(res, 409, outcome.error, 'Ключи устройства изменились после claim.');
    if (outcome.error === 'SOURCE_DEVICE_NOT_ACTIVE') return error(res, 409, outcome.error, 'Доверенное устройство или сессия больше не активны.');
    if (outcome.error === 'VAULT_NOT_INITIALIZED') return error(res, 409, outcome.error, 'Сейф не инициализирован.');
    if (outcome.error === 'INVALID_SOURCE_SIGNATURE') return error(res, 401, outcome.error, 'Подпись доверенного устройства недействительна.');
    res.set('Cache-Control', 'no-store');
    return res.json({ approved: true, status: 'approved' });
  } catch (e) { return next(e); }
});

router.post('/:inviteId/complete', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.inviteId)) return next();
    const exists = await pool.query(`SELECT id FROM device_pairing_invites WHERE id=$1 AND user_id=$2`, [req.params.inviteId, req.auth.userId]);
    if (!exists.rowCount) return next();
    const signature = decodeSignature(req.body?.signature);
    if (!signature) return error(res, 422, 'INVALID_SIGNATURE', 'Подпись завершения подключения должна быть Ed25519 Base64.');
    const outcome = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      const selected = await client.query(
        `SELECT i.*, t.public_key AS target_signing_key,t.status AS target_status,
                a.status AS initiator_status
           FROM device_pairing_invites i
           JOIN devices t ON t.id=i.claimed_by_device_id AND t.user_id=i.user_id
           JOIN devices a ON a.id=i.initiator_device_id AND a.user_id=i.user_id
          WHERE i.id=$1 AND i.user_id=$2 FOR UPDATE OF i,t,a`,
        [req.params.inviteId, req.auth.userId],
      );
      if (!selected.rowCount) return { error: 'PAIRING_INVITE_NOT_FOUND' };
      const row = selected.rows[0];
      if (req.auth.deviceId !== row.claimed_by_device_id) return { error: 'NOT_TARGET_DEVICE' };
      if (row.status !== 'approved' || row.expires_at <= new Date()) return { error: 'PAIRING_INVITE_NOT_APPROVED' };
      if (row.target_status !== 'active' || row.initiator_status !== 'active') return { error: 'PAIRING_DEVICE_REVOKED' };
      const blob = row.encrypted_vmk_blob;
      if (!blob?.ephemeral_public_key || !blob?.salt || !blob?.nonce || !blob?.ciphertext) return { error: 'PAIRING_ENVELOPE_MISSING' };
      const decoded = decodeEnvelope(blob);
      if (!decoded) return { error: 'PAIRING_ENVELOPE_INVALID' };
      const digest = envelopeDigest(decoded);
      const message = completionMessage({ requestId: row.id, targetDeviceId: row.claimed_by_device_id, vaultId: row.vault_id, digest });
      if (!verifySignature(null, Buffer.from(message, 'utf8'), ed25519PublicKey(row.target_signing_key), signature)) return { error: 'INVALID_TARGET_SIGNATURE' };
      const session = await client.query(
        `SELECT 1 FROM sessions WHERE id=$1 AND user_id=$2 AND device_id=$3
          AND revoked_at IS NULL AND access_expires_at>now() AND expires_at>now() FOR UPDATE`,
        [req.auth.sessionId, req.auth.userId, req.auth.deviceId],
      );
      if (!session.rowCount) return { error: 'TARGET_SESSION_NOT_ACTIVE' };
      await client.query(
        `INSERT INTO key_envelopes(vault_id,user_id,envelope_type,device_id,format_id,format_version,
          key_derivation_algorithm,key_derivation_params,cipher_algorithm,salt,nonce,ciphertext,aad_version)
         VALUES($1,$2,'device',$3,'vault-device-envelope-v1',1,'X25519+HKDF-SHA256',$4::jsonb,
          'AES-256-GCM',$5,$6,$7,1)`,
        [row.vault_id, req.auth.userId, row.claimed_by_device_id,
          JSON.stringify({ ephemeral_public_key: blob.ephemeral_public_key, hkdf_info: 'SecureDisk-VMK-Envelope-v1', purpose: 'pairing', request_id: row.id }),
          decoded.saltBytes, decoded.nonceBytes, decoded.ciphertextBytes],
      );
      await client.query(`UPDATE device_pairing_invites SET status='completed',completed_at=now() WHERE id=$1`, [row.id]);
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
         VALUES($1,$2,$3,'pairing_invite_completed',$4::jsonb)`,
        [req.auth.userId, row.claimed_by_device_id, req.auth.sessionId, JSON.stringify({ invite_id: row.id, initiator_device_id: row.initiator_device_id })],
      );
      return { completed: true, vaultId: row.vault_id };
    });
    if (outcome.error === 'PAIRING_INVITE_NOT_FOUND') return error(res, 404, outcome.error, 'Приглашение или конверт не найдены.');
    if (outcome.error === 'NOT_TARGET_DEVICE') return error(res, 403, outcome.error, 'Завершить подключение может только устройство, которое отправило claim.');
    if (outcome.error === 'PAIRING_INVITE_NOT_APPROVED') return error(res, 409, outcome.error, 'Приглашение ещё не одобрено или истекло.');
    if (outcome.error === 'PAIRING_DEVICE_REVOKED') return error(res, 409, outcome.error, 'Одно из устройств было отозвано.');
    if (outcome.error === 'PAIRING_ENVELOPE_MISSING' || outcome.error === 'PAIRING_ENVELOPE_INVALID') return error(res, 409, outcome.error, 'Зашифрованный конверт VMK повреждён.');
    if (outcome.error === 'INVALID_TARGET_SIGNATURE') return error(res, 401, outcome.error, 'Новое устройство не подтвердило успешную расшифровку VMK.');
    if (outcome.error === 'TARGET_SESSION_NOT_ACTIVE') return error(res, 409, outcome.error, 'Сессия нового устройства больше не активна.');
    res.set('Cache-Control', 'no-store');
    return res.json({ completed: true, vault_id: outcome.vaultId });
  } catch (e) { return next(e); }
});

router.post('/invite/:inviteId/cancel', requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.inviteId)) return error(res, 400, 'INVALID_INVITE_ID', 'Идентификатор приглашения некорректен.');
    const cancelled = await pool.query(
      `UPDATE device_pairing_invites SET status='cancelled',encrypted_vmk_blob=NULL,approved_at=NULL,approved_by_session_id=NULL
        WHERE id=$1 AND user_id=$2 AND initiator_device_id=$3 AND status IN ('pending','claimed','approved')
        RETURNING id`,
      [req.params.inviteId, req.auth.userId, req.auth.deviceId],
    );
    if (!cancelled.rowCount) return error(res, 404, 'PAIRING_INVITE_NOT_FOUND', 'Активное приглашение не найдено.');
    return res.json({ cancelled: true });
  } catch (e) { return next(e); }
});

function error(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}
function decodeCanonical(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === length && decoded.toString('base64') === value ? decoded : null;
}
function decodeSignature(value) { return decodeCanonical(value, 64); }
function tokenBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === 32 && bytes.toString('base64url') === value ? bytes : null;
}
function safeEqual(a, b) { return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && timingSafeEqual(a, b); }
function hashToken(token) { return createHash('sha256').update(token).digest(); }
function decodeEnvelope(input) {
  const parsed = envelopeSchema.safeParse(input);
  if (!parsed.success) return null;
  const ephemeral = decodeCanonical(parsed.data.ephemeral_public_key, 32);
  const salt = decodeCanonical(parsed.data.salt, 16);
  const nonce = decodeCanonical(parsed.data.nonce, 12);
  const ciphertext = decodeCanonical(parsed.data.ciphertext, 48);
  if (!ephemeral || !salt || !nonce || !ciphertext) return null;
  return { ...parsed.data, ephemeral, saltBytes: salt, nonceBytes: nonce, ciphertextBytes: ciphertext };
}
function ed25519PublicKey(raw) {
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });
}
function envelopeDigest(envelope) {
  return createHash('sha256')
    .update(envelope.ephemeral)
    .update(envelope.saltBytes)
    .update(envelope.nonceBytes)
    .update(envelope.ciphertextBytes)
    .digest('hex');
}
function approvalMessage({ requestId, sourceDeviceId, targetDeviceId, vaultId, digest }) {
  return [
    'SecureDisk-Pairing-Approval-v1',
    `request_id=${requestId}`,
    `source_device_id=${sourceDeviceId}`,
    `target_device_id=${targetDeviceId}`,
    `vault_id=${vaultId}`,
    `envelope_sha256=${digest}`,
  ].join('\n');
}
function completionMessage({ requestId, targetDeviceId, vaultId, digest }) {
  return [
    'SecureDisk-Pairing-Complete-v1',
    `request_id=${requestId}`,
    `target_device_id=${targetDeviceId}`,
    `vault_id=${vaultId}`,
    `envelope_sha256=${digest}`,
  ].join('\n');
}
async function currentTrustedDevice(req, res) {
  if (!req.auth.deviceId) {
    error(res, 409, 'DEVICE_NOT_BOUND', 'Current session is not bound to a trusted device.');
    return null;
  }
  const result = await pool.query(
    `SELECT id,public_key,encryption_public_key,device_name,device_type,platform,status
       FROM devices WHERE id=$1 AND user_id=$2`,
    [req.auth.deviceId, req.auth.userId],
  );
  if (!result.rowCount || result.rows[0].status !== 'active') {
    error(res, 409, 'DEVICE_NOT_TRUSTED', 'Current device is not active and trusted.');
    return null;
  }
  return result.rows[0];
}

// New device creates a one-time request capability. The QR also carries a
// signature-bound copy of the device's public keys; the approving client compares
// those values with this authenticated backend record before it can approve.
router.post('/start', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    const device = await currentTrustedDevice(req, res);
    if (!device) return;
    const vault = await pool.query('SELECT id FROM vaults WHERE user_id=$1', [req.auth.userId]);
    if (!vault.rowCount) return error(res, 409, 'VAULT_NOT_INITIALIZED', 'Initialize the Vault on the first trusted device before pairing another device.');
    const alreadyPaired = await pool.query(
      `SELECT 1 FROM key_envelopes WHERE vault_id=$1 AND user_id=$2 AND device_id=$3 AND envelope_type='device'`,
      [vault.rows[0].id, req.auth.userId, device.id],
    );
    if (alreadyPaired.rowCount) return error(res, 409, 'DEVICE_ALREADY_PAIRED', 'This device already has a Vault key envelope.');

    const requestId = randomUUID();
    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    const created = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      // Lock device then session and re-check the session binding inside the
      // transaction. Revocation also locks the device before changing its sessions.
      const guard = await client.query(
        `SELECT d.id FROM devices d
          JOIN sessions s ON s.device_id=d.id AND s.user_id=d.user_id
         WHERE d.id=$1 AND d.user_id=$2 AND d.status='active'
           AND s.id=$3 AND s.revoked_at IS NULL
           AND s.access_expires_at>now() AND s.expires_at>now()
         FOR UPDATE OF d,s`,
        [device.id, req.auth.userId, req.auth.sessionId],
      );
      if (!guard.rowCount) return { error: 'DEVICE_OR_SESSION_NOT_ACTIVE' };
      const vault = await client.query('SELECT id FROM vaults WHERE user_id=$1 FOR UPDATE', [req.auth.userId]);
      if (!vault.rowCount) return { error: 'VAULT_NOT_INITIALIZED' };
      const alreadyPaired = await client.query(
        `SELECT 1 FROM key_envelopes WHERE vault_id=$1 AND user_id=$2 AND device_id=$3 AND envelope_type='device'`,
        [vault.rows[0].id, req.auth.userId, device.id],
      );
      if (alreadyPaired.rowCount) return { error: 'DEVICE_ALREADY_PAIRED' };
      // Do not silently supersede another live request. This avoids racing
      // with an approval/revocation transaction; the user can cancel it or wait
      // for its short expiry before creating another request.
      const pending = await client.query(
        `SELECT 1 FROM device_pairing_requests
          WHERE target_device_id=$1 AND user_id=$2
            AND status IN ('pending','approved') AND expires_at>now()
          LIMIT 1`,
        [device.id, req.auth.userId],
      );
      if (pending.rowCount) return { error: 'PAIRING_ALREADY_PENDING' };
      await client.query(
        `INSERT INTO device_pairing_requests(request_id,user_id,target_device_id,target_session_id,token_hash,expires_at)
         VALUES($1,$2,$3,$4,$5,$6)`,
        [requestId, req.auth.userId, device.id, req.auth.sessionId, hashToken(token), expiresAt],
      );
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
         VALUES($1,$2,$3,'pairing_requested',$4::jsonb)`,
        [req.auth.userId, device.id, req.auth.sessionId, JSON.stringify({ request_id: requestId, expires_at: expiresAt.toISOString() })],
      );
      return { created: true };
    });
    if (created.error === 'DEVICE_OR_SESSION_NOT_ACTIVE') return error(res, 409, created.error, 'The current device or session is no longer active.');
    if (created.error === 'VAULT_NOT_INITIALIZED') return error(res, 409, created.error, 'Initialize the Vault on the first trusted device before pairing another device.');
    if (created.error === 'DEVICE_ALREADY_PAIRED') return error(res, 409, created.error, 'This device already has a Vault key envelope.');
    if (created.error === 'PAIRING_ALREADY_PENDING') return error(res, 409, created.error, 'A live pairing request already exists for this device. Cancel it or wait until it expires.');
    res.set('Cache-Control', 'no-store');
    return res.status(201).json({ request_id: requestId, pairing_token: token, expires_at: expiresAt.toISOString() });
  } catch (e) { return next(e); }
});

// Old trusted device fetches target details with the one-time token from the QR.
// New target device polls the same endpoint using its bound session instead.
router.get('/:requestId', async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.requestId)) return error(res, 400, 'INVALID_REQUEST_ID', 'Pairing request ID is invalid.');
    const result = await pool.query(
      `SELECT r.*, t.device_name AS target_device_name,t.device_type AS target_device_type,
              t.platform AS target_platform,t.encryption_public_key AS target_encryption_public_key,
              t.public_key AS target_signing_public_key,
              s.device_id AS session_device_id,
              v.id AS vault_id,
              pe.ephemeral_public_key,pe.salt,pe.nonce,pe.ciphertext
         FROM device_pairing_requests r
         JOIN devices t ON t.id=r.target_device_id AND t.user_id=r.user_id
         JOIN sessions s ON s.id=$2 AND s.user_id=r.user_id
         LEFT JOIN vaults v ON v.user_id=r.user_id
         LEFT JOIN pairing_envelopes pe ON pe.request_id=r.request_id
        WHERE r.request_id=$1 AND r.user_id=$3`,
      [req.params.requestId, req.auth.sessionId, req.auth.userId],
    );
    if (!result.rowCount) return error(res, 404, 'PAIRING_NOT_FOUND', 'Pairing request not found.');
    const row = result.rows[0];
    if (row.status !== 'completed' && new Date(row.expires_at) <= new Date()) {
      await withTransaction(async client => {
        await lockUserSecurityState(client, req.auth.userId);
        const expired = await client.query(
          `UPDATE device_pairing_requests SET status='expired'
            WHERE request_id=$1 AND user_id=$2 AND status IN ('pending','approved')
            RETURNING target_device_id`,
          [row.request_id, req.auth.userId],
        );
        if (expired.rowCount) {
          await client.query('DELETE FROM pairing_envelopes WHERE request_id=$1', [row.request_id]);
          await client.query(
            `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
             VALUES($1,$2,$3,'pairing_expired',$4::jsonb)`,
            [req.auth.userId, expired.rows[0].target_device_id, req.auth.sessionId, JSON.stringify({ request_id: row.request_id })],
          );
        }
      });
      row.status = 'expired';
    }
    const isTarget = req.auth.deviceId === row.target_device_id && req.auth.sessionId === row.target_session_id;
    if (isTarget) {
      res.set('Cache-Control', 'no-store');
      // An envelope is returned only while the request is still approved.
      // Cancelled/expired requests must not leak a previously uploaded envelope.
      const envelope = row.status === 'approved' && row.ephemeral_public_key ? {
        ephemeral_public_key: Buffer.from(row.ephemeral_public_key).toString('base64'),
        salt: Buffer.from(row.salt).toString('base64'),
        nonce: Buffer.from(row.nonce).toString('base64'),
        ciphertext: Buffer.from(row.ciphertext).toString('base64'),
      } : null;
      return res.json({ request_id: row.request_id, status: row.status, expires_at: row.expires_at, vault_id: row.vault_id, envelope });
    }

    const suppliedToken = tokenBytes(req.get('X-Pairing-Token'));
    const suppliedHash = suppliedToken ? hashToken(suppliedToken) : null;
    if (!suppliedHash || !safeEqual(suppliedHash, row.token_hash)) return error(res, 404, 'PAIRING_NOT_FOUND', 'Pairing request not found.');
    const source = await currentTrustedDevice(req, res);
    if (!source) return;
    if (source.id === row.target_device_id) return error(res, 409, 'PAIRING_SOURCE_EQUALS_TARGET', 'Pairing must be approved from a different trusted device.');
    res.set('Cache-Control', 'no-store');
    return res.json({
      request_id: row.request_id,
      status: row.status,
      expires_at: row.expires_at,
      vault_id: row.vault_id,
      target_device: {
        id: row.target_device_id,
        device_name: row.target_device_name,
        device_type: row.target_device_type,
        platform: row.target_platform,
        encryption_algorithm: 'X25519',
        signing_public_key: Buffer.from(row.target_signing_public_key).toString('base64'),
        encryption_public_key: Buffer.from(row.target_encryption_public_key).toString('base64'),
        fingerprint: createHash('sha256').update(row.target_signing_public_key).update(row.target_encryption_public_key).digest('hex').slice(0, 16),
      },
    });
  } catch (e) { return next(e); }
});

router.post('/:requestId/approve', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.requestId)) return error(res, 400, 'INVALID_REQUEST_ID', 'Pairing request ID is invalid.');
    const source = await currentTrustedDevice(req, res);
    if (!source) return;
    const token = tokenBytes(req.get('X-Pairing-Token'));
    if (!token) return error(res, 404, 'PAIRING_NOT_FOUND', 'Pairing request not found.');
    const envelope = decodeEnvelope(req.body?.envelope);
    const signature = decodeSignature(req.body?.signature);
    if (!envelope || !signature) return error(res, 422, 'INVALID_PAIRING_PROOF', 'Envelope or Ed25519 signature has an invalid format.');

    const outcome = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      const selected = await client.query(
        `SELECT r.*, t.encryption_public_key AS target_encryption_public_key,
                t.status AS target_status
           FROM device_pairing_requests r
           JOIN devices t ON t.id=r.target_device_id AND t.user_id=r.user_id
           JOIN sessions ts ON ts.id=r.target_session_id AND ts.user_id=r.user_id
                AND ts.device_id=t.id AND ts.revoked_at IS NULL
                AND ts.access_expires_at>now() AND ts.expires_at>now()
          WHERE r.request_id=$1 AND r.user_id=$2 FOR UPDATE OF r,t,ts`,
        [req.params.requestId, req.auth.userId],
      );
      if (!selected.rowCount) return { error: 'PAIRING_NOT_FOUND' };
      const row = selected.rows[0];
      if (!safeEqual(hashToken(token), row.token_hash)) return { error: 'PAIRING_NOT_FOUND' };
      if (row.status !== 'pending' || new Date(row.expires_at) <= new Date()) {
        if (row.status === 'pending') await client.query(`UPDATE device_pairing_requests SET status='expired' WHERE request_id=$1`, [row.request_id]);
        return { error: 'PAIRING_EXPIRED' };
      }
      if (row.target_status !== 'active') return { error: 'TARGET_DEVICE_NOT_ACTIVE' };
      if (row.target_device_id === source.id) return { error: 'PAIRING_SOURCE_EQUALS_TARGET' };
      const sourceCheck = await client.query(
        `SELECT d.public_key FROM devices d
          JOIN sessions s ON s.device_id=d.id AND s.user_id=d.user_id
         WHERE d.id=$1 AND d.user_id=$2 AND d.status='active'
           AND s.id=$3 AND s.revoked_at IS NULL
           AND s.access_expires_at>now() AND s.expires_at>now()
         FOR UPDATE OF d,s`,
        [req.auth.deviceId, req.auth.userId, req.auth.sessionId],
      );
      if (!sourceCheck.rowCount) return { error: 'SOURCE_DEVICE_NOT_ACTIVE' };
      if (!row.target_encryption_public_key || row.target_encryption_public_key.length !== 32) return { error: 'TARGET_KEY_INVALID' };
      const vault = await client.query('SELECT id FROM vaults WHERE user_id=$1 FOR UPDATE', [req.auth.userId]);
      if (!vault.rowCount) return { error: 'VAULT_NOT_INITIALIZED' };
      const digest = envelopeDigest(envelope);
      const message = approvalMessage({
        requestId: row.request_id, sourceDeviceId: source.id,
        targetDeviceId: row.target_device_id, vaultId: vault.rows[0].id, digest,
      });
      const valid = verifySignature(null, Buffer.from(message, 'utf8'), ed25519PublicKey(sourceCheck.rows[0].public_key), signature);
      if (!valid) return { error: 'INVALID_SOURCE_SIGNATURE' };

      await client.query(
        `INSERT INTO pairing_envelopes(request_id,source_device_id,user_id,format_id,format_version,
          ephemeral_public_key,salt,nonce,ciphertext,envelope_sha256)
         VALUES($1,$2,$3,'vault-device-envelope-v1',1,$4,$5,$6,$7,$8)`,
        [row.request_id, source.id, req.auth.userId, envelope.ephemeral, envelope.saltBytes,
          envelope.nonceBytes, envelope.ciphertextBytes, Buffer.from(digest, 'hex')],
      );
      await client.query(
        `UPDATE device_pairing_requests SET status='approved',approved_at=now(),approved_by_device_id=$2,approved_by_session_id=$3
          WHERE request_id=$1`,
        [row.request_id, source.id, req.auth.sessionId],
      );
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
         VALUES($1,$2,$3,'pairing_approved',$4::jsonb)`,
        [req.auth.userId, source.id, req.auth.sessionId, JSON.stringify({ request_id: row.request_id, target_device_id: row.target_device_id })],
      );
      return { approved: true };
    });
    if (outcome.error === 'PAIRING_NOT_FOUND') return error(res, 404, outcome.error, 'Pairing request not found.');
    if (outcome.error === 'PAIRING_EXPIRED') return error(res, 410, outcome.error, 'Pairing request expired, was already used, or is no longer pending.');
    if (outcome.error === 'TARGET_DEVICE_NOT_ACTIVE') return error(res, 409, outcome.error, 'Target device is no longer active.');
    if (outcome.error === 'SOURCE_DEVICE_NOT_ACTIVE') return error(res, 409, outcome.error, 'The approving device or session is no longer active.');
    if (outcome.error === 'PAIRING_SOURCE_EQUALS_TARGET') return error(res, 409, outcome.error, 'The target device cannot approve its own pairing request.');
    if (outcome.error === 'TARGET_KEY_INVALID') return error(res, 409, outcome.error, 'Target device encryption key is invalid.');
    if (outcome.error === 'VAULT_NOT_INITIALIZED') return error(res, 409, outcome.error, 'Vault is not initialized.');
    if (outcome.error === 'INVALID_SOURCE_SIGNATURE') return error(res, 401, outcome.error, 'Approval signature from the trusted device is invalid.');
    res.set('Cache-Control', 'no-store');
    return res.json({ approved: true, status: 'approved' });
  } catch (e) { return next(e); }
});

router.post('/:requestId/complete', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.requestId)) return error(res, 400, 'INVALID_REQUEST_ID', 'Pairing request ID is invalid.');
    const signature = decodeSignature(req.body?.signature);
    if (!signature) return error(res, 422, 'INVALID_SIGNATURE', 'Completion signature must be a canonical Base64 Ed25519 signature.');

    const outcome = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      const selected = await client.query(
        `SELECT r.*, t.public_key AS target_signing_public_key, t.status AS target_status,
                pe.ephemeral_public_key,pe.salt,pe.nonce,pe.ciphertext,pe.envelope_sha256,
                v.id AS vault_id
           FROM device_pairing_requests r
           JOIN devices t ON t.id=r.target_device_id AND t.user_id=r.user_id
           JOIN sessions ts ON ts.id=r.target_session_id AND ts.user_id=r.user_id
                AND ts.device_id=t.id AND ts.revoked_at IS NULL
                AND ts.access_expires_at>now() AND ts.expires_at>now()
           JOIN devices ad ON ad.id=r.approved_by_device_id AND ad.user_id=r.user_id AND ad.status='active'
           JOIN sessions aps ON aps.id=r.approved_by_session_id AND aps.user_id=r.user_id
                AND aps.device_id=ad.id AND aps.revoked_at IS NULL
                AND aps.access_expires_at>now() AND aps.expires_at>now()
           JOIN pairing_envelopes pe ON pe.request_id=r.request_id
           JOIN vaults v ON v.user_id=r.user_id
          WHERE r.request_id=$1 AND r.user_id=$2
          FOR UPDATE OF r,t,ts,ad,aps,pe,v`,
        [req.params.requestId, req.auth.userId],
      );
      if (!selected.rowCount) return { error: 'PAIRING_NOT_FOUND' };
      const row = selected.rows[0];
      if (req.auth.deviceId !== row.target_device_id || req.auth.sessionId !== row.target_session_id) return { error: 'NOT_TARGET_DEVICE' };
      if (row.status !== 'approved' || new Date(row.expires_at) <= new Date()) return { error: 'PAIRING_NOT_APPROVED' };
      if (row.target_status !== 'active') return { error: 'TARGET_DEVICE_REVOKED' };
      const digest = Buffer.from(row.envelope_sha256).toString('hex');
      const message = completionMessage({ requestId: row.request_id, targetDeviceId: row.target_device_id, vaultId: row.vault_id, digest });
      const valid = verifySignature(null, Buffer.from(message, 'utf8'), ed25519PublicKey(row.target_signing_public_key), signature);
      if (!valid) return { error: 'INVALID_TARGET_SIGNATURE' };

      await client.query(
        `INSERT INTO key_envelopes(vault_id,user_id,envelope_type,device_id,format_id,format_version,
          key_derivation_algorithm,key_derivation_params,cipher_algorithm,salt,nonce,ciphertext,aad_version)
         VALUES($1,$2,'device',$3,'vault-device-envelope-v1',1,'X25519+HKDF-SHA256',$4::jsonb,
          'AES-256-GCM',$5,$6,$7,1)`,
        [row.vault_id, req.auth.userId, row.target_device_id,
          JSON.stringify({ ephemeral_public_key: Buffer.from(row.ephemeral_public_key).toString('base64'), hkdf_info: 'SecureDisk-VMK-Envelope-v1', purpose: 'pairing', request_id: row.request_id }),
          row.salt, row.nonce, row.ciphertext],
      );
      await client.query(
        `UPDATE device_pairing_requests SET status='completed',completed_at=now() WHERE request_id=$1`,
        [row.request_id],
      );
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
         VALUES($1,$2,$3,'pairing_completed',$4::jsonb)`,
        [req.auth.userId, row.target_device_id, req.auth.sessionId, JSON.stringify({ request_id: row.request_id, source_device_id: row.approved_by_device_id })],
      );
      return { completed: true, vaultId: row.vault_id };
    });
    if (outcome.error === 'PAIRING_NOT_FOUND') return error(res, 404, outcome.error, 'Pairing envelope or request not found.');
    if (outcome.error === 'NOT_TARGET_DEVICE') return error(res, 403, outcome.error, 'Only the target device session can complete pairing.');
    if (outcome.error === 'PAIRING_NOT_APPROVED') return error(res, 409, outcome.error, 'Pairing has not been approved or has expired.');
    if (outcome.error === 'TARGET_DEVICE_REVOKED') return error(res, 409, outcome.error, 'Target device has been revoked.');
    if (outcome.error === 'INVALID_TARGET_SIGNATURE') return error(res, 401, outcome.error, 'Target device did not prove successful envelope decryption.');
    res.set('Cache-Control', 'no-store');
    return res.json({ completed: true, vault_id: outcome.vaultId });
  } catch (e) { return next(e); }
});

router.post('/:requestId/cancel', requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    if (!UUID_RE.test(req.params.requestId)) return error(res, 400, 'INVALID_REQUEST_ID', 'Pairing request ID is invalid.');
    const result = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      const cancelled = await client.query(
        `UPDATE device_pairing_requests SET status='cancelled'
          WHERE request_id=$1 AND user_id=$2 AND target_device_id=$3 AND target_session_id=$4
            AND status IN ('pending','approved') AND expires_at>now()
          RETURNING request_id,target_device_id`,
        [req.params.requestId, req.auth.userId, req.auth.deviceId, req.auth.sessionId],
      );
      if (cancelled.rowCount) {
        await client.query('DELETE FROM pairing_envelopes WHERE request_id=$1', [cancelled.rows[0].request_id]);
        await client.query(
          `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
           VALUES($1,$2,$3,'pairing_cancelled',$4::jsonb)`,
          [req.auth.userId, req.auth.deviceId, req.auth.sessionId, JSON.stringify({ request_id: cancelled.rows[0].request_id })],
        );
      }
      return { cancelled: Boolean(cancelled.rowCount) };
    });
    if (!result.cancelled) return error(res, 404, 'PAIRING_NOT_FOUND', 'Active pairing request not found.');
    return res.json({ cancelled: true });
  } catch (e) { return next(e); }
});

export default router;
