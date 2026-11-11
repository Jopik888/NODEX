import { Router } from 'express';
import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { pool, withTransaction } from '../db/pool.js';
import { config } from '../config/index.js';
import { createOpaqueToken, hashToken } from '../utils/tokens.js';
import { createSyncRoomId, decryptSyncRoomId, encryptSyncRoomId } from '../services/sync-room-crypto.js';
import { sendVerificationEmail } from '../services/email.service.js';
import { issueCsrfToken, requireCsrf, requireSessionCsrf, setCsrfCookie } from '../middleware/csrf.js';
import { requireAuth } from '../middleware/auth.js';
import {
  loginLimiter,
  logoutLimiter,
  refreshLimiter,
  registerLimiter,
  resendLimiter,
  verifyLimiter,
} from '../middleware/rate-limit.js';

const router = Router();

const PASSWORD_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65_536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
};

const registerSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(12).max(128),
  display_name: z.string().trim().min(1).max(80).optional(),
}).strict();

const loginSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(128),
}).strict();

const verifySchema = z.object({
  token: z.string().min(30).max(128),
}).strict();

const resendSchema = z.object({
  email: z.string().trim().email().max(254),
}).strict();

// Perform a costly Argon2 check even when an email is unknown, reducing account-enumeration timing differences.
const dummyPasswordHashPromise = argon2.hash(randomBytes(32).toString('hex'), PASSWORD_OPTIONS);

function validationError(res, issues) {
  return res.status(422).json({
    error: {
      code: 'VALIDATION_ERROR',
      message: 'Request body is invalid.',
      details: issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })),
    },
  });
}

function tokenCookieOptions(httpOnly, maxAge) {
  return {
    httpOnly,
    secure: config.cookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge,
  };
}

function setSessionCookies(res, accessToken, refreshToken, accessExpiresInSeconds, refreshExpiresAt) {
  res.cookie(
    config.cookieNames.access,
    accessToken,
    tokenCookieOptions(true, accessExpiresInSeconds * 1000),
  );
  const refreshRemainingMs = Math.max(0, new Date(refreshExpiresAt).getTime() - Date.now());
  res.cookie(config.cookieNames.refresh, refreshToken, tokenCookieOptions(true, refreshRemainingMs));
}

function clearSessionCookies(res) {
  const options = {
    secure: config.cookieSecure,
    sameSite: 'lax',
    path: '/',
  };
  res.clearCookie(config.cookieNames.access, { ...options, httpOnly: true });
  res.clearCookie(config.cookieNames.refresh, { ...options, httpOnly: true });
  res.clearCookie(config.cookieNames.csrf, { ...options, httpOnly: false });
}

function genericAuthFailure(res) {
  return res.status(401).json({
    error: { code: 'INVALID_CREDENTIALS', message: 'Email or password is incorrect.' },
  });
}

async function createSessionForUser(client, user, req) {
  const accessToken = createOpaqueToken(32);
  const refreshToken = createOpaqueToken(48);
  const csrfToken = createOpaqueToken(32);
  const accessExpiresAt = new Date(Date.now() + config.accessTokenTtlSeconds * 1000);
  const refreshExpiresAt = new Date(Date.now() + config.refreshTokenTtlDays * 24 * 60 * 60 * 1000);

  const sessionResult = await client.query(
    `INSERT INTO sessions
       (user_id, access_token_hash, access_expires_at, expires_at, last_seen_at,
        user_agent, ip_address, csrf_token_hash)
     VALUES ($1, $2, $3, $4, now(), $5, $6, $7)
     RETURNING id`,
    [
      user.id,
      hashToken(accessToken),
      accessExpiresAt,
      refreshExpiresAt,
      (req.get('User-Agent') || '').slice(0, 512) || null,
      req.ip || null,
      hashToken(csrfToken),
    ],
  );
  const sessionId = sessionResult.rows[0].id;

  await client.query(
    `INSERT INTO session_refresh_tokens (session_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [sessionId, hashToken(refreshToken), refreshExpiresAt],
  );

  return {
    accessToken,
    refreshToken,
    csrfToken,
    accessExpiresInSeconds: config.accessTokenTtlSeconds,
    refreshExpiresAt,
    sessionId,
  };
}

async function deliverVerification(email, token) {
  try {
    const sent = await sendVerificationEmail(email, token);
    if (!sent && !config.devReturnVerificationToken) {
      console.warn(JSON.stringify({ level: 'warn', event: 'verification_email_not_sent', reason: 'smtp_not_configured' }));
    }
    return sent;
  } catch (error) {
    console.error(JSON.stringify({ level: 'error', event: 'verification_email_send_failed', message: error.message }));
    return false;
  }
}

router.post('/register', registerLimiter, requireCsrf, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return validationError(res, parsed.error.issues);

  const email = parsed.data.email.toLowerCase();
  const passwordHash = await argon2.hash(parsed.data.password, PASSWORD_OPTIONS);
  const verificationToken = createOpaqueToken(32);
  const syncRoomId = createSyncRoomId();

  let user;
  try {
    user = await withTransaction(async (client) => {
      const userResult = await client.query(
        `INSERT INTO users (email, email_normalized, password_hash, display_name)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, status, created_at`,
        [parsed.data.email, email, passwordHash, parsed.data.display_name || null],
      );
      const createdUser = userResult.rows[0];

      await client.query(
        `INSERT INTO account_sync_identities (user_id, room_id_ciphertext, encryption_key_version)
         VALUES ($1, $2, $3)`,
        [createdUser.id, encryptSyncRoomId(createdUser.id, syncRoomId), config.syncRoomEncryptionKeyVersion],
      );
      await client.query('INSERT INTO storage_usage_accounts (user_id) VALUES ($1)', [createdUser.id]);
      await client.query(
        `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, now() + interval '24 hours')`,
        [createdUser.id, hashToken(verificationToken)],
      );
      return createdUser;
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: { code: 'EMAIL_ALREADY_REGISTERED', message: 'An account with this email already exists.' } });
    }
    throw error;
  }

  const emailSent = await deliverVerification(email, verificationToken);
  const response = {
    user_id: user.id,
    email: user.email,
    status: user.status,
    email_verification_required: true,
    message: emailSent
      ? 'Account created. Check your email for the verification token.'
      : (config.devReturnVerificationToken
          ? 'Account created. Use the development verification token from this response.'
          : 'Account created, but email delivery failed. Retry email verification later.'),
  };

  if (config.devReturnVerificationToken) response.dev_verification_token = verificationToken;
  return res.status(201).json(response);
});

router.post('/verify-email', verifyLimiter, requireCsrf, async (req, res) => {
  const parsed = verifySchema.safeParse(req.body);
  if (!parsed.success) return validationError(res, parsed.error.issues);

  const result = await withTransaction(async (client) => {
    const tokenResult = await client.query(
      `SELECT id, user_id
         FROM email_verification_tokens
        WHERE token_hash = $1
          AND consumed_at IS NULL
          AND expires_at > now()
        FOR UPDATE`,
      [hashToken(parsed.data.token)],
    );
    if (tokenResult.rowCount !== 1) return null;

    const tokenRow = tokenResult.rows[0];
    await client.query('UPDATE email_verification_tokens SET consumed_at = now() WHERE id = $1', [tokenRow.id]);
    const userResult = await client.query(
      `UPDATE users
          SET email_verified_at = now(), status = 'active', updated_at = now()
        WHERE id = $1 AND status = 'pending_verification'
        RETURNING id, email, status, email_verified_at`,
      [tokenRow.user_id],
    );
    return userResult.rows[0] || null;
  });

  if (!result) {
    return res.status(410).json({ error: { code: 'VERIFICATION_TOKEN_INVALID', message: 'Verification token is expired, invalid or already used.' } });
  }

  return res.status(200).json({
    email_verified: true,
    user_id: result.id,
    email: result.email,
    status: result.status,
    verified_at: result.email_verified_at,
  });
});

router.post('/resend-verification', resendLimiter, requireCsrf, async (req, res) => {
  const parsed = resendSchema.safeParse(req.body);
  if (!parsed.success) return validationError(res, parsed.error.issues);

  const email = parsed.data.email.toLowerCase();
  const token = createOpaqueToken(32);
  const user = await withTransaction(async (client) => {
    const userResult = await client.query(
      `SELECT id, email FROM users
        WHERE email_normalized = $1 AND status = 'pending_verification'
        LIMIT 1`,
      [email],
    );
    if (userResult.rowCount !== 1) return null;

    const found = userResult.rows[0];
    await client.query(
      `UPDATE email_verification_tokens
          SET consumed_at = now()
        WHERE user_id = $1 AND consumed_at IS NULL`,
      [found.id],
    );
    await client.query(
      `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + interval '24 hours')`,
      [found.id, hashToken(token)],
    );
    return found;
  });

  if (user) await deliverVerification(user.email, token);
  const response = { message: 'If the account exists and requires verification, a new email will be sent.' };
  if (user && config.devReturnVerificationToken) response.dev_verification_token = token;
  return res.status(202).json(response);
});

router.post('/login', loginLimiter, requireCsrf, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return validationError(res, parsed.error.issues);

  const email = parsed.data.email.toLowerCase();
  const userResult = await pool.query(
    `SELECT id, email, display_name, password_hash, status, email_verified_at
       FROM users
      WHERE email_normalized = $1
      LIMIT 1`,
    [email],
  );
  const user = userResult.rows[0];
  const passwordHash = user?.password_hash || await dummyPasswordHashPromise;
  const passwordMatches = await argon2.verify(passwordHash, parsed.data.password).catch(() => false);

  if (!user || !passwordMatches) return genericAuthFailure(res);
  if (user.status === 'pending_verification' || !user.email_verified_at) {
    return res.status(403).json({ error: { code: 'EMAIL_NOT_VERIFIED', message: 'Verify your email address before signing in.' } });
  }
  if (user.status !== 'active') {
    return res.status(403).json({ error: { code: 'ACCOUNT_NOT_ACTIVE', message: 'This account is not permitted to sign in.' } });
  }

  const totpResult = await pool.query(
    `SELECT 1 FROM totp_credentials
      WHERE user_id = $1 AND confirmed_at IS NOT NULL AND disabled_at IS NULL
      LIMIT 1`,
    [user.id],
  );
  if (totpResult.rowCount > 0) {
    return res.status(501).json({ error: { code: 'TOTP_LOGIN_NOT_IMPLEMENTED', message: 'TOTP is enabled for this account, but the TOTP login flow is not part of backend v0.1.' } });
  }

  const syncResult = await pool.query(
    `SELECT room_id_ciphertext, encryption_key_version
       FROM account_sync_identities
      WHERE user_id = $1
      LIMIT 1`,
    [user.id],
  );
  if (syncResult.rowCount !== 1) {
    return res.status(500).json({ error: { code: 'SYNC_IDENTITY_MISSING', message: 'Account sync identity is not configured.' } });
  }
  const syncRoomId = decryptSyncRoomId(user.id, syncResult.rows[0].room_id_ciphertext, syncResult.rows[0].encryption_key_version);

  const session = await withTransaction(async (client) => {
    const created = await createSessionForUser(client, user, req);
    await client.query('UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1', [user.id]);
    return created;
  });

  setSessionCookies(res, session.accessToken, session.refreshToken, session.accessExpiresInSeconds, session.refreshExpiresAt);
  setCsrfCookie(res, session.csrfToken);

  return res.status(200).json({
    user: {
      id: user.id,
      email: user.email,
      display_name: user.display_name,
      status: user.status,
    },
    sync_room_id: syncRoomId,
    csrf_token: session.csrfToken,
    session: {
      access_expires_in_seconds: config.accessTokenTtlSeconds,
      refresh_expires_at: session.refreshExpiresAt.toISOString(),
    },
  });
});

router.get('/me', requireAuth, async (req, res) => {
  const syncResult = await pool.query(
    `SELECT room_id_ciphertext, encryption_key_version
       FROM account_sync_identities
      WHERE user_id = $1
      LIMIT 1`,
    [req.auth.userId],
  );
  if (syncResult.rowCount !== 1) {
    return res.status(500).json({ error: { code: 'SYNC_IDENTITY_MISSING', message: 'Account sync identity is not configured.' } });
  }

  const syncRoomId = decryptSyncRoomId(
    req.auth.userId,
    syncResult.rows[0].room_id_ciphertext,
    syncResult.rows[0].encryption_key_version,
  );
  res.set('Cache-Control', 'no-store');
  return res.status(200).json({
    user: {
      id: req.auth.userId,
      email: req.auth.email,
      display_name: req.auth.displayName,
      status: 'active',
    },
    sync_room_id: syncRoomId,
  });
});

router.post('/refresh', refreshLimiter, requireCsrf, async (req, res) => {
  const rawRefreshToken = req.cookies?.[config.cookieNames.refresh];
  if (typeof rawRefreshToken !== 'string' || rawRefreshToken.length < 30 || rawRefreshToken.length > 200) {
    return res.status(401).json({ error: { code: 'REFRESH_TOKEN_INVALID', message: 'Refresh token is missing or invalid.' } });
  }

  const tokenHash = hashToken(rawRefreshToken);
  const outcome = await withTransaction(async (client) => {
    const result = await client.query(
      `SELECT rt.id AS refresh_id, rt.session_id, rt.expires_at AS refresh_expires_at,
              rt.used_at, rt.revoked_at AS refresh_revoked_at,
              s.user_id, s.expires_at AS session_expires_at, s.revoked_at AS session_revoked_at,
              s.csrf_token_hash, u.email, u.display_name, u.status
         FROM session_refresh_tokens rt
         JOIN sessions s ON s.id = rt.session_id
         JOIN users u ON u.id = s.user_id
        WHERE rt.token_hash = $1
        FOR UPDATE OF rt, s`,
      [tokenHash],
    );
    if (result.rowCount !== 1) return { kind: 'invalid' };
    const row = result.rows[0];

    if (row.used_at) {
      await client.query(
        `UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'refresh_token_reuse'
          WHERE id = $1`,
        [row.session_id],
      );
      await client.query(
        `UPDATE session_refresh_tokens SET revoked_at = COALESCE(revoked_at, now())
          WHERE session_id = $1`,
        [row.session_id],
      );
      return { kind: 'reused' };
    }

    const now = Date.now();
    if (row.refresh_revoked_at || row.session_revoked_at || row.status !== 'active'
      || new Date(row.refresh_expires_at).getTime() <= now
      || new Date(row.session_expires_at).getTime() <= now) {
      return { kind: 'invalid' };
    }

    const csrfCookie = req.cookies?.[config.cookieNames.csrf];
    if (typeof csrfCookie !== 'string' || !row.csrf_token_hash
      || !row.csrf_token_hash.equals(hashToken(csrfCookie))) {
      return { kind: 'csrf' };
    }

    const newAccessToken = createOpaqueToken(32);
    const newRefreshToken = createOpaqueToken(48);
    const newCsrfToken = createOpaqueToken(32);
    const newAccessExpiresAt = new Date(now + config.accessTokenTtlSeconds * 1000);

    await client.query('UPDATE session_refresh_tokens SET used_at = now() WHERE id = $1', [row.refresh_id]);
    const newRefreshResult = await client.query(
      `INSERT INTO session_refresh_tokens (session_id, token_hash, expires_at)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [row.session_id, hashToken(newRefreshToken), row.session_expires_at],
    );
    await client.query(
      'UPDATE session_refresh_tokens SET replaced_by_id = $1 WHERE id = $2',
      [newRefreshResult.rows[0].id, row.refresh_id],
    );
    await client.query(
      `UPDATE sessions
          SET access_token_hash = $1,
              access_expires_at = $2,
              csrf_token_hash = $3,
              last_seen_at = now()
        WHERE id = $4`,
      [hashToken(newAccessToken), newAccessExpiresAt, hashToken(newCsrfToken), row.session_id],
    );

    return {
      kind: 'ok',
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      csrfToken: newCsrfToken,
      refreshExpiresAt: row.session_expires_at,
      user: { id: row.user_id, email: row.email, display_name: row.display_name, status: row.status },
    };
  });

  if (outcome.kind === 'csrf') {
    return res.status(403).json({ error: { code: 'CSRF_SESSION_VALIDATION_FAILED', message: 'CSRF token is not bound to this session.' } });
  }
  if (outcome.kind !== 'ok') {
    clearSessionCookies(res);
    return res.status(401).json({ error: { code: 'REFRESH_TOKEN_INVALID', message: outcome.kind === 'reused' ? 'Refresh token reuse detected. Session revoked.' : 'Refresh token is invalid or expired.' } });
  }

  setSessionCookies(res, outcome.accessToken, outcome.refreshToken, config.accessTokenTtlSeconds, outcome.refreshExpiresAt);
  setCsrfCookie(res, outcome.csrfToken);
  return res.status(200).json({
    user: outcome.user,
    csrf_token: outcome.csrfToken,
    session: { access_expires_in_seconds: config.accessTokenTtlSeconds, refresh_expires_at: new Date(outcome.refreshExpiresAt).toISOString() },
  });
});

router.post('/logout', logoutLimiter, requireCsrf, requireAuth, requireSessionCsrf, async (req, res) => {
  await withTransaction(async (client) => {
    await client.query(
      `UPDATE sessions
          SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'user_logout'
        WHERE id = $1`,
      [req.auth.sessionId],
    );
    await client.query(
      `UPDATE session_refresh_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE session_id = $1`,
      [req.auth.sessionId],
    );
  });
  clearSessionCookies(res);
  return res.status(200).json({ logged_out: true });
});

export default router;

// Used by GET /csrf-token in the API app.
export { issueCsrfToken };
