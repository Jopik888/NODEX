import { Router } from 'express';
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { z } from 'zod';
import { pool, withTransaction, lockUserSecurityState } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';
import { requireCsrf, requireSessionCsrf } from '../middleware/csrf.js';

const router = Router();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const b64 = (length) => z.string().min(Math.ceil(length * 4 / 3) - 2).max(Math.ceil(length * 4 / 3) + 4);
const envelopeSchema = z.object({
  ephemeral_public_key: b64(32),
  salt: b64(16),
  nonce: b64(12),
  ciphertext: b64(48),
}).strict();

function err(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}
function decodeCanonical(value, expectedLength) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === expectedLength && decoded.toString('base64') === value ? decoded : null;
}
function ed25519PublicKey(raw) {
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100','hex'), raw]), format: 'der', type: 'spki' });
}
function parseSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 64 && bytes.toString('base64') === value ? bytes : null;
}
function envelopeDigest(envelope) {
  return createHash('sha256').update(envelope.ephemeral).update(envelope.salt).update(envelope.nonce).update(envelope.ciphertext).digest('hex');
}
function parseEnvelope(input) {
  const parsed = envelopeSchema.safeParse(input);
  if (!parsed.success) return null;
  const ephemeral = decodeCanonical(parsed.data.ephemeral_public_key, 32);
  const salt = decodeCanonical(parsed.data.salt, 16);
  const nonce = decodeCanonical(parsed.data.nonce, 12);
  const ciphertext = decodeCanonical(parsed.data.ciphertext, 48);
  if (!ephemeral || !salt || !nonce || !ciphertext) return null;
  return { ephemeral, salt, nonce, ciphertext, json: parsed.data };
}

router.use(requireAuth);

async function requireCurrentActiveDevice(req, res) {
  if (!req.auth.deviceId) {
    err(res, 409, 'DEVICE_NOT_BOUND', 'Current session is not cryptographically bound to a device. Refresh authentication and register the device.');
    return false;
  }
  const result = await pool.query(
    `SELECT id FROM devices WHERE id=$1 AND user_id=$2 AND status='active'`,
    [req.auth.deviceId, req.auth.userId],
  );
  if (!result.rowCount) {
    err(res, 409, 'DEVICE_NOT_TRUSTED', 'Current device is not active and trusted.');
    return false;
  }
  return true;
}

router.get('/envelope', async (req, res, next) => {
  try {
    if (!await requireCurrentActiveDevice(req, res)) return;
    const result = await pool.query(
      `SELECT v.id AS vault_id, v.crypto_version,
              e.format_id,e.format_version,e.key_derivation_algorithm,e.key_derivation_params,
              encode(e.salt,'base64') AS salt,encode(e.nonce,'base64') AS nonce,
              encode(e.ciphertext,'base64') AS ciphertext,e.aad_version
         FROM vaults v
         LEFT JOIN key_envelopes e
           ON e.vault_id=v.id AND e.user_id=v.user_id AND e.device_id=$2 AND e.envelope_type='device'
        WHERE v.user_id=$1`,
      [req.auth.userId, req.auth.deviceId],
    );
    res.set('Cache-Control', 'no-store');
    if (!result.rowCount) return res.json({ initialized: false, envelope: null });
    const row = result.rows[0];
    if (!row.format_id) return res.json({ initialized: true, vault_id: row.vault_id, crypto_version: row.crypto_version, envelope: null });
    return res.json({
      initialized: true,
      vault_id: row.vault_id,
      crypto_version: row.crypto_version,
      envelope: {
        format_id: row.format_id,
        format_version: row.format_version,
        key_derivation_algorithm: row.key_derivation_algorithm,
        key_derivation_params: row.key_derivation_params,
        salt: row.salt, nonce: row.nonce, ciphertext: row.ciphertext,
        aad_version: row.aad_version,
      },
    });
  } catch (e) { return next(e); }
});

router.post('/initialize', requireCsrf, requireSessionCsrf, async (req, res, next) => {
  try {
    if (!await requireCurrentActiveDevice(req, res)) return;
    const vaultId = req.body?.vault_id;
    if (!UUID_RE.test(vaultId || '')) return err(res, 422, 'INVALID_VAULT_ID', 'vault_id must be a UUID.');
    const envelope = parseEnvelope(req.body?.envelope);
    const signature = parseSignature(req.body?.signature);
    if (!envelope || !signature) return err(res, 422, 'INVALID_ENVELOPE', 'VMK envelope or Ed25519 signature has an invalid format.');
    const digest = envelopeDigest(envelope);
    const initMessage = ['SecureDisk-Vault-Initialize-v1', `user_id=${req.auth.userId}`, `device_id=${req.auth.deviceId}`, `vault_id=${vaultId}`, `envelope_sha256=${digest}`].join('\n');
    const deviceKey = await pool.query(`SELECT public_key FROM devices WHERE id=$1 AND user_id=$2 AND status='active'`, [req.auth.deviceId, req.auth.userId]);
    if (!deviceKey.rowCount || !verifySignature(null, Buffer.from(initMessage,'utf8'), ed25519PublicKey(deviceKey.rows[0].public_key), signature)) {
      return err(res, 401, 'INVALID_VAULT_INITIALIZATION_SIGNATURE', 'The active device did not sign the Vault initialization envelope.');
    }

    const outcome = await withTransaction(async client => {
      await lockUserSecurityState(client, req.auth.userId);
      // Serialize initialization with the v0.3 device-revocation flow.
      const activeBinding = await client.query(
        `SELECT d.id FROM devices d
          JOIN sessions s ON s.device_id=d.id AND s.user_id=d.user_id
         WHERE d.id=$1 AND d.user_id=$2 AND d.status='active'
           AND s.id=$3 AND s.revoked_at IS NULL
           AND s.access_expires_at>now() AND s.expires_at>now()
         FOR UPDATE OF d,s`,
        [req.auth.deviceId, req.auth.userId, req.auth.sessionId],
      );
      if (!activeBinding.rowCount) return { inactive: true };
      const existing = await client.query('SELECT id FROM vaults WHERE user_id=$1 FOR UPDATE', [req.auth.userId]);
      if (existing.rowCount) return { conflict: true, vaultId: existing.rows[0].id };
      await client.query(
        `INSERT INTO vaults(id,user_id,crypto_version) VALUES($1,$2,1)`,
        [vaultId, req.auth.userId],
      );
      await client.query(
        `INSERT INTO key_envelopes(
          vault_id,user_id,envelope_type,device_id,format_id,format_version,
          key_derivation_algorithm,key_derivation_params,cipher_algorithm,salt,nonce,ciphertext,aad_version
        ) VALUES($1,$2,'device',$3,'vault-device-envelope-v1',1,'X25519+HKDF-SHA256',$4::jsonb,'AES-256-GCM',$5,$6,$7,1)`,
        [vaultId, req.auth.userId, req.auth.deviceId,
          JSON.stringify({ ephemeral_public_key: envelope.json.ephemeral_public_key, hkdf_info: 'SecureDisk-VMK-Envelope-v1', purpose: 'device-envelope', request_id: '' }),
          envelope.salt, envelope.nonce, envelope.ciphertext],
      );
      await client.query(
        `INSERT INTO device_events(user_id,device_id,actor_session_id,event_type,metadata)
         VALUES($1,$2,$3,'vault_initialized',$4::jsonb)`,
        [req.auth.userId, req.auth.deviceId, req.auth.sessionId, JSON.stringify({ action: 'vault_initialized', vault_id: vaultId })],
      );
      return { created: true, vaultId };
    });
    if (outcome.inactive) return err(res, 409, 'DEVICE_OR_SESSION_NOT_ACTIVE', 'The current device or session is no longer active.');
    if (outcome.conflict) return err(res, 409, 'VAULT_ALREADY_INITIALIZED', 'Vault already exists. This device must be paired by an existing trusted device.');
    res.set('Cache-Control', 'no-store');
    return res.status(201).json({ initialized: true, vault_id: outcome.vaultId });
  } catch (e) { return next(e); }
});

export default router;
