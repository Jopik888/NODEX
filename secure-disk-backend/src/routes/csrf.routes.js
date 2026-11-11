import { Router } from 'express';
import { pool } from '../db/pool.js';
import { config } from '../config/index.js';
import { issueCsrfToken, setCsrfCookie } from '../middleware/csrf.js';
import { createOpaqueToken, hashToken, constantTimeBufferEqual } from '../utils/tokens.js';

const router = Router();

function validCsrfCookie(value) {
  return typeof value === 'string' && value.length >= 30 && value.length <= 200;
}

async function rebindSessionCsrf(sessionId, existingToken, res) {
  if (validCsrfCookie(existingToken)) {
    const current = await pool.query('SELECT csrf_token_hash FROM sessions WHERE id = $1', [sessionId]);
    if (current.rowCount === 1 && current.rows[0].csrf_token_hash
      && constantTimeBufferEqual(current.rows[0].csrf_token_hash, hashToken(existingToken))) {
      return existingToken;
    }
  }

  const replacement = createOpaqueToken(32);
  await pool.query('UPDATE sessions SET csrf_token_hash = $1 WHERE id = $2', [hashToken(replacement), sessionId]);
  setCsrfCookie(res, replacement);
  return replacement;
}

router.get('/csrf-token', async (req, res, next) => {
  try {
    const existing = req.cookies?.[config.cookieNames.csrf];
    const accessToken = req.cookies?.[config.cookieNames.access];

    if (typeof accessToken === 'string' && accessToken.length >= 30 && accessToken.length <= 200) {
      const sessionResult = await pool.query(
        `SELECT s.id
           FROM sessions s
           JOIN users u ON u.id = s.user_id
          WHERE s.access_token_hash = $1
            AND s.revoked_at IS NULL
            AND s.access_expires_at > now()
            AND s.expires_at > now()
            AND u.status = 'active'
            AND u.email_verified_at IS NOT NULL
          LIMIT 1`,
        [hashToken(accessToken)],
      );
      if (sessionResult.rowCount === 1) {
        const token = await rebindSessionCsrf(sessionResult.rows[0].id, existing, res);
        res.set('Cache-Control', 'no-store');
        return res.status(200).json({ csrf_token: token });
      }
    }

    // A still-valid refresh cookie can restore the readable CSRF cookie after the
    // short-lived access cookie has expired, without exposing the refresh token.
    const refreshToken = req.cookies?.[config.cookieNames.refresh];
    if (typeof refreshToken === 'string' && refreshToken.length >= 30 && refreshToken.length <= 200) {
      const sessionResult = await pool.query(
        `SELECT s.id
           FROM session_refresh_tokens rt
           JOIN sessions s ON s.id = rt.session_id
           JOIN users u ON u.id = s.user_id
          WHERE rt.token_hash = $1
            AND rt.used_at IS NULL
            AND rt.revoked_at IS NULL
            AND rt.expires_at > now()
            AND s.revoked_at IS NULL
            AND s.expires_at > now()
            AND u.status = 'active'
          LIMIT 1`,
        [hashToken(refreshToken)],
      );
      if (sessionResult.rowCount === 1) {
        const token = await rebindSessionCsrf(sessionResult.rows[0].id, existing, res);
        res.set('Cache-Control', 'no-store');
        return res.status(200).json({ csrf_token: token });
      }
    }

    if (validCsrfCookie(existing)) {
      res.set('Cache-Control', 'no-store');
      return res.status(200).json({ csrf_token: existing });
    }

    const token = issueCsrfToken(res);
    res.set('Cache-Control', 'no-store');
    return res.status(200).json({ csrf_token: token });
  } catch (error) {
    return next(error);
  }
});

export default router;
