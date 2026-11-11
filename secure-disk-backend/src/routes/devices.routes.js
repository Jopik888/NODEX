import { Router } from 'express';
import { createHash, randomBytes, createPublicKey, verify as verifySignature } from 'node:crypto';
import { z } from 'zod';
import { pool, withTransaction, lockUserSecurityState } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { requireCsrf, requireSessionCsrf } from '../middleware/csrf.js';
import { decodeRawPublicKey } from '../utils/public-key-format.js';
import { deviceRegisterLimiter } from '../middleware/rate-limit.js';
import { createTrustedKeysMap } from '../utils/trusted-keys.js';

const router = Router();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const registerDeviceSchema = z.object({
  device_name: z.string().trim().min(1).max(80),
  device_type: z.enum(['browser', 'desktop', 'mobile', 'nas', 'server', 'other']),
  platform: z.string().trim().max(100).optional(),
  app_version: z.string().trim().max(50).optional(),
  signing_algorithm: z.literal('Ed25519'),
  encryption_algorithm: z.literal('X25519'),
  public_key: z.string().min(40).max(48),
  encryption_public_key: z.string().min(40).max(48),
}).strict();
const verifySchema = z.object({ challenge_id: z.string().uuid(), signature: z.string().min(80).max(100) }).strict();

function error(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}
function publicDevice(row) {
  return {
    id: row.id, device_name: row.device_name, device_type: row.device_type,
    platform: row.platform, app_version: row.app_version,
    signing_algorithm: row.signing_algorithm, encryption_algorithm: row.encryption_algorithm,
    signing_key_version: row.signing_key_version, encryption_key_version: row.encryption_key_version,
    status: row.status, created_at: row.created_at, last_seen_at: row.last_seen_at,
    revoked_at: row.revoked_at || null, fingerprint: row.fingerprint || null,
    is_current: Boolean(row.is_current),
    has_vault_access: Boolean(row.has_vault_access),
  };
}
function decodeSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) return null;
  return bytes;
}
function ed25519PublicKey(raw) {
  // RFC 8410 SubjectPublicKeyInfo prefix for a raw Ed25519 public key.
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });
}

router.use(requireAuth);

// Only a session that has completed device proof and is still bound to an
// active device may obtain the current account trust set.
router.get('/trusted-keys', async (req, res, next) => {
  try {
    if (!req.auth.deviceId) {
      return error(res, 403, 'DEVICE_NOT_VERIFIED', 'This session is not bound to a verified device.');
    }
    const result = await pool.query(
      `SELECT id, status, encode(public_key, 'base64') AS public_key
         FROM devices
        WHERE user_id = $1 AND status = 'active'
        ORDER BY id`,
      [req.auth.userId],
    );
    const trustedKeys = createTrustedKeysMap(result.rows, req.auth.deviceId);
    if (!trustedKeys) {
      return error(res, 403, 'DEVICE_NOT_ACTIVE', 'The current device is not active. P2P access is disabled.');
    }
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
    return res.json({ trusted_keys: trustedKeys, algorithm: 'Ed25519', version: 1 });
  } catch (e) { return next(e); }
});

router.get('/', async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT d.id, d.device_name, d.device_type, d.platform, d.app_version,
              d.signing_algorithm, d.encryption_algorithm, d.signing_key_version,
              d.encryption_key_version, d.status, d.created_at, d.last_seen_at, d.revoked_at,
              d.public_key, d.encryption_public_key,
              EXISTS (SELECT 1 FROM key_envelopes ke WHERE ke.user_id=d.user_id AND ke.device_id=d.id AND ke.envelope_type='device') AS has_vault_access,
              (s.device_id = d.id) AS is_current
         FROM devices d
         LEFT JOIN sessions s ON s.id = $2
        WHERE d.user_id = $1
        ORDER BY CASE d.status WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
                 d.last_seen_at DESC NULLS LAST, d.created_at DESC`,
      [req.auth.userId, req.auth.sessionId],
    );
    res.set('Cache-Control', 'no-store');
    return res.json({ devices: result.rows.map(row => publicDevice({ ...row, fingerprint: createHash('sha256').update(row.public_key).update(row.encryption_public_key).digest('hex').slice(0, 16) })) });
  } catch (e) { return next(e); }
});

router.post('/register', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    const parsed = registerDeviceSchema.safeParse(req.body);
    if (!parsed.success) return res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Request body is invalid.', details: parsed.error.issues.map(i => ({ path: i.path.join('.'), message: i.message })) } });
    const signingPublicKey = decodeRawPublicKey(parsed.data.public_key);
    const encryptionPublicKey = decodeRawPublicKey(parsed.data.encryption_public_key);
    if (!signingPublicKey || !encryptionPublicKey) return error(res, 422, 'INVALID_PUBLIC_KEY', 'Ed25519 and X25519 public keys must be canonical Base64 encodings of exactly 32 raw bytes.');

    const outcome = await withTransaction(async client => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))', [req.auth.userId]);
      const matching = await client.query(
        `SELECT * FROM devices WHERE user_id = $1 AND (public_key = $2 OR encryption_public_key = $3) FOR UPDATE`,
        [req.auth.userId, signingPublicKey, encryptionPublicKey],
      );
      if (matching.rowCount) {
        const exact = matching.rows.find(r => r.public_key.equals(signingPublicKey) && r.encryption_public_key.equals(encryptionPublicKey));
        if (!exact || matching.rowCount !== 1) return { conflict: 'DEVICE_KEY_CONFLICT' };
        if (exact.status === 'revoked' || exact.status === 'blocked') return { conflict: 'DEVICE_REVOKED' };
        const updated = await client.query(
          `UPDATE devices SET device_name=$1, device_type=$2, platform=$3, app_version=$4
            WHERE id=$5 AND user_id=$6 RETURNING id, status, created_at`,
          [parsed.data.device_name, parsed.data.device_type, parsed.data.platform || null, parsed.data.app_version || null, exact.id, req.auth.userId],
        );
        return { created: false, device: updated.rows[0] };
      }
      const inserted = await client.query(
        `INSERT INTO devices (user_id, device_name, device_type, platform, app_version,
          public_key, signing_algorithm, encryption_public_key, encryption_algorithm,
          signing_key_version, encryption_key_version, status)
         VALUES ($1,$2,$3,$4,$5,$6,'Ed25519',$7,'X25519',1,1,'pending')
         RETURNING id, status, created_at`,
        [req.auth.userId, parsed.data.device_name, parsed.data.device_type, parsed.data.platform || null,
          parsed.data.app_version || null, signingPublicKey, encryptionPublicKey],
      );
      const d = inserted.rows[0];
      await client.query(
        `INSERT INTO device_key_history (device_id,user_id,key_purpose,algorithm,key_version,public_key)
         VALUES ($1,$2,'signing','Ed25519',1,$3),($1,$2,'encryption','X25519',1,$4)`,
        [d.id, req.auth.userId, signingPublicKey, encryptionPublicKey],
      );
      await client.query(`INSERT INTO device_events(user_id,device_id,actor_session_id,event_type) VALUES($1,$2,$3,'registered_pending')`, [req.auth.userId,d.id,req.auth.sessionId]);
      return { created: true, device: d };
    });
    if (outcome.conflict === 'DEVICE_REVOKED') return error(res,409,'DEVICE_REVOKED','This device was revoked. A new device identity and explicit recovery are required.');
    if (outcome.conflict) return error(res,409,'DEVICE_KEY_CONFLICT','A submitted public key is already associated with a different device identity.');
    res.set('Cache-Control','no-store');
    return res.status(outcome.created ? 201 : 200).json({ created: outcome.created, device: outcome.device });
  } catch (e) { return next(e); }
});

router.post('/:deviceId/challenge', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req,res,next) => {
  try {
    if (!UUID_RE.test(req.params.deviceId)) return error(res,400,'INVALID_DEVICE_ID','Device ID is invalid.');
    const device = await pool.query(`SELECT id,status FROM devices WHERE id=$1 AND user_id=$2`,[req.params.deviceId,req.auth.userId]);
    if (!device.rowCount) return error(res,404,'DEVICE_NOT_FOUND','Device not found.');
    if (['revoked','blocked'].includes(device.rows[0].status)) return error(res,409,'DEVICE_REVOKED','This device cannot be authenticated.');
    const nonce = randomBytes(32);
    const nonceB64 = nonce.toString('base64');
    const challengeId = cryptoRandomUuid();
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now()+5*60*1000).toISOString();
    const signedMessage = [
      'SecureDisk-Device-Proof-v1',
      `challenge_id=${challengeId}`,
      `user_id=${req.auth.userId}`,
      `device_id=${req.params.deviceId}`,
      `session_id=${req.auth.sessionId}`,
      `nonce=${nonceB64}`,
      `issued_at=${issuedAt}`,
      `expires_at=${expiresAt}`,
    ].join('\n');
    await pool.query(
      `INSERT INTO device_auth_challenges(id,user_id,device_id,session_id,signed_message,expires_at)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [challengeId,req.auth.userId,req.params.deviceId,req.auth.sessionId,signedMessage,expiresAt],
    );
    res.set('Cache-Control','no-store');
    return res.status(201).json({ challenge_id:challengeId, message:signedMessage, expires_at:expiresAt });
  } catch(e) { return next(e); }
});

router.post('/:deviceId/verify', deviceRegisterLimiter, requireCsrf, requireSessionCsrf, async (req,res,next) => {
  try {
    if (!UUID_RE.test(req.params.deviceId)) return error(res,400,'INVALID_DEVICE_ID','Device ID is invalid.');
    const parsed = verifySchema.safeParse(req.body);
    if (!parsed.success) return error(res,422,'VALIDATION_ERROR','Challenge verification request is invalid.');
    const signature = decodeSignature(parsed.data.signature);
    if (!signature) return error(res,422,'INVALID_SIGNATURE_FORMAT','Ed25519 signature must be canonical Base64 encoding of 64 bytes.');

    const outcome = await withTransaction(async client => {
      const challengeResult = await client.query(
        `SELECT c.*, d.public_key, d.status AS device_status
           FROM device_auth_challenges c JOIN devices d ON d.id=c.device_id AND d.user_id=c.user_id
          WHERE c.id=$1 AND c.user_id=$2 AND c.device_id=$3 AND c.session_id=$4
          FOR UPDATE OF c, d`,
        [parsed.data.challenge_id,req.auth.userId,req.params.deviceId,req.auth.sessionId],
      );
      if (!challengeResult.rowCount) return { error:'CHALLENGE_NOT_FOUND' };
      const c=challengeResult.rows[0];
      if (c.consumed_at || c.expires_at <= new Date()) return { error:'CHALLENGE_EXPIRED' };
      if (['revoked','blocked'].includes(c.device_status)) return { error:'DEVICE_REVOKED' };
      let valid=false;
      try { valid=verifySignature(null,Buffer.from(c.signed_message,'utf8'),ed25519PublicKey(c.public_key),signature); } catch (_) { valid=false; }
      if (!valid) {
        const attempts=c.failed_attempts+1;
        await client.query(`UPDATE device_auth_challenges SET failed_attempts=$1, consumed_at=CASE WHEN $1>=5 THEN now() ELSE consumed_at END WHERE id=$2`,[attempts,c.id]);
        return { error:'INVALID_DEVICE_PROOF' };
      }
      const bound = await client.query(
        `UPDATE sessions SET device_id=$1,last_seen_at=now()
          WHERE id=$2 AND user_id=$3 AND revoked_at IS NULL AND (device_id IS NULL OR device_id=$1)
          RETURNING id`,[req.params.deviceId,req.auth.sessionId,req.auth.userId],
      );
      if (!bound.rowCount) return { error:'SESSION_DEVICE_CONFLICT' };
      await client.query(`UPDATE device_auth_challenges SET consumed_at=now() WHERE id=$1`,[c.id]);
      const activated = await client.query(
        `UPDATE devices SET status='active',last_seen_at=now()
          WHERE id=$1 AND user_id=$2 AND status IN ('pending','active')
          RETURNING id,status,created_at`,[req.params.deviceId,req.auth.userId],
      );
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type)
         VALUES($1,$2,$3,$4)`,
        [req.auth.userId,req.params.deviceId,req.auth.sessionId,c.device_status==='pending'?'proof_verified':'login_proof_verified'],
      );
      return { device:activated.rows[0] };
    });
    if (outcome.error==='CHALLENGE_NOT_FOUND') return error(res,404,outcome.error,'Challenge not found.');
    if (outcome.error==='CHALLENGE_EXPIRED') return error(res,410,outcome.error,'Challenge expired or already consumed.');
    if (outcome.error==='DEVICE_REVOKED') return error(res,409,outcome.error,'Device is revoked.');
    if (outcome.error==='INVALID_DEVICE_PROOF') return error(res,401,outcome.error,'Private-key possession could not be verified.');
    if (outcome.error==='SESSION_DEVICE_CONFLICT') return error(res,409,outcome.error,'This session is already bound to another device. Sign out and authenticate again.');
    res.set('Cache-Control','no-store');
    return res.json({ verified:true, device:outcome.device });
  } catch(e) { return next(e); }
});

router.get('/:deviceId/history', async (req,res,next) => {
  try {
    if (!UUID_RE.test(req.params.deviceId)) return error(res,400,'INVALID_DEVICE_ID','Device ID is invalid.');
    const owned=await pool.query(`SELECT 1 FROM devices WHERE id=$1 AND user_id=$2`,[req.params.deviceId,req.auth.userId]);
    if (!owned.rowCount) return error(res,404,'DEVICE_NOT_FOUND','Device not found.');
    const [events,keys]=await Promise.all([
      pool.query(`SELECT event_type,metadata,created_at FROM device_events WHERE device_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 100`,[req.params.deviceId,req.auth.userId]),
      pool.query(`SELECT key_purpose,algorithm,key_version,encode(public_key,'base64') AS public_key,created_at,superseded_at FROM device_key_history WHERE device_id=$1 AND user_id=$2 ORDER BY key_purpose,key_version`,[req.params.deviceId,req.auth.userId]),
    ]);
    res.set('Cache-Control','no-store');
    return res.json({ events:events.rows, key_history:keys.rows });
  } catch(e) { return next(e); }
});

router.post('/:deviceId/revoke', requireCsrf, requireSessionCsrf, async (req,res,next) => {
  try {
    if (!UUID_RE.test(req.params.deviceId)) return error(res,400,'INVALID_DEVICE_ID','Device ID is invalid.');
    const result=await withTransaction(async client=>{
      await lockUserSecurityState(client, req.auth.userId);
      // Use the same lock order as pairing approval/completion: pairing rows
      // first, then the device and its sessions. This avoids a cycle where a
      // revocation holds the device while an approval holds the pairing row.
      await client.query(
        `SELECT request_id FROM device_pairing_requests
          WHERE user_id=$2 AND status IN ('pending','approved')
            AND (target_device_id=$1 OR approved_by_device_id=$1)
          ORDER BY request_id FOR UPDATE`,
        [req.params.deviceId, req.auth.userId],
      );
      await client.query(
        `SELECT id FROM device_pairing_invites
          WHERE user_id=$2 AND status IN ('pending','claimed','approved')
            AND (initiator_device_id=$1 OR claimed_by_device_id=$1)
          ORDER BY id FOR UPDATE`,
        [req.params.deviceId, req.auth.userId],
      );
      const found=await client.query(`SELECT id,status FROM devices WHERE id=$1 AND user_id=$2 FOR UPDATE`,[req.params.deviceId,req.auth.userId]);
      if (!found.rowCount) return { error:'DEVICE_NOT_FOUND' };
      if (found.rows[0].status==='revoked') return { already:true };
      const vaultAccess = await client.query(
        `SELECT v.id AS vault_id,
                EXISTS(SELECT 1 FROM key_envelopes re WHERE re.vault_id=v.id AND re.envelope_type='recovery') AS has_recovery,
                EXISTS(
                  SELECT 1 FROM key_envelopes oe JOIN devices od ON od.id=oe.device_id AND od.user_id=oe.user_id
                   WHERE oe.vault_id=v.id AND oe.envelope_type='device' AND oe.device_id<>$2 AND od.status='active'
                ) AS has_other_active_device_envelope,
                EXISTS(SELECT 1 FROM key_envelopes te WHERE te.vault_id=v.id AND te.device_id=$2 AND te.envelope_type='device') AS target_has_envelope
           FROM vaults v WHERE v.user_id=$1 FOR UPDATE`,
        [req.auth.userId, req.params.deviceId],
      );
      if (vaultAccess.rowCount && vaultAccess.rows[0].target_has_envelope
          && !vaultAccess.rows[0].has_recovery && !vaultAccess.rows[0].has_other_active_device_envelope) {
        return { error:'LAST_VAULT_ACCESS_DEVICE' };
      }
      await client.query(`UPDATE devices SET status='revoked',revoked_at=now() WHERE id=$1 AND user_id=$2`,[req.params.deviceId,req.auth.userId]);
      const sessions=await client.query(
        `UPDATE sessions SET revoked_at=now(),revoke_reason='device_revoked'
          WHERE device_id=$1 AND user_id=$2 AND revoked_at IS NULL RETURNING id`,[req.params.deviceId,req.auth.userId]);
      await client.query(`UPDATE device_auth_challenges SET consumed_at=now() WHERE device_id=$1 AND consumed_at IS NULL`,[req.params.deviceId]);
      const cancelledPairings = await client.query(
        `UPDATE device_pairing_requests SET status='cancelled'
          WHERE user_id=$2 AND status IN ('pending','approved')
            AND (target_device_id=$1 OR approved_by_device_id=$1)
          RETURNING request_id,target_device_id`,
        [req.params.deviceId, req.auth.userId],
      );
      for (const pairing of cancelledPairings.rows) {
        await client.query('DELETE FROM pairing_envelopes WHERE request_id=$1', [pairing.request_id]);
        await client.query(
          `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
           VALUES($1,$2,$3,'pairing_cancelled',$4::jsonb)`,
          [req.auth.userId, pairing.target_device_id, req.auth.sessionId, JSON.stringify({ request_id: pairing.request_id, reason: 'device_revoked' })],
        );
      }
      const cancelledInvites = await client.query(
        `UPDATE device_pairing_invites SET status='cancelled',encrypted_vmk_blob=NULL,
            approved_at=NULL,approved_by_session_id=NULL
          WHERE user_id=$2 AND status IN ('pending','claimed','approved')
            AND (initiator_device_id=$1 OR claimed_by_device_id=$1)
          RETURNING id,initiator_device_id,claimed_by_device_id`,
        [req.params.deviceId, req.auth.userId],
      );
      for (const invite of cancelledInvites.rows) {
        const affectedDevice = invite.claimed_by_device_id || invite.initiator_device_id;
        await client.query(
          `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
           VALUES($1,$2,$3,'pairing_invite_cancelled',$4::jsonb)`,
          [req.auth.userId, affectedDevice, req.auth.sessionId, JSON.stringify({ invite_id: invite.id, reason: 'device_revoked' })],
        );
      }
      await client.query(`DELETE FROM key_envelopes WHERE device_id=$1 AND user_id=$2`,[req.params.deviceId,req.auth.userId]);
      await client.query(`INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
        VALUES($1,$2,$3,'revoked',$4::jsonb)`,[req.auth.userId,req.params.deviceId,req.auth.sessionId,JSON.stringify({revoked_sessions:sessions.rowCount})]);
      return { revoked:true,revoked_sessions:sessions.rowCount,current_device:sessions.rows.some(s=>s.id===req.auth.sessionId) };
    });
    if (result.error === 'LAST_VAULT_ACCESS_DEVICE') return error(res,409,result.error,'Нельзя отозвать последнее устройство с доступом к Сейфу. Сначала подключите другое доверенное устройство или настройте Recovery Phrase.');
    if (result.error) return error(res,404,result.error,'Device not found.');
    return res.json(result);
  } catch(e) { return next(e); }
});

function cryptoRandomUuid() {
  // UUID generation from the platform CSPRNG; no Math.random fallback.
  const b=randomBytes(16); b[6]=(b[6]&0x0f)|0x40; b[8]=(b[8]&0x3f)|0x80;
  const h=b.toString('hex'); return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

export default router;
