import { pool } from '../db/pool.js';
import { config } from '../config/index.js';
import { hashToken } from '../utils/tokens.js';

export async function requireAuth(req, res, next) {
  try {
    const accessToken = req.cookies?.[config.cookieNames.access];
    if (typeof accessToken !== 'string' || accessToken.length < 30 || accessToken.length > 200) {
      return res.status(401).json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication is required.' } });
    }

    const tokenHash = hashToken(accessToken);
    const result = await pool.query(
      `SELECT s.id AS session_id,
              s.user_id,
              s.csrf_token_hash,
              s.device_id,
              u.email,
              u.display_name,
              u.status
         FROM sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.access_token_hash = $1
          AND s.revoked_at IS NULL
          AND s.access_expires_at > now()
          AND s.expires_at > now()
          AND u.status = 'active'
          AND u.email_verified_at IS NOT NULL
        LIMIT 1`,
      [tokenHash],
    );

    if (result.rowCount !== 1) {
      return res.status(401).json({ error: { code: 'SESSION_EXPIRED', message: 'Session is invalid or expired.' } });
    }

    req.auth = {
      sessionId: result.rows[0].session_id,
      userId: result.rows[0].user_id,
      email: result.rows[0].email,
      displayName: result.rows[0].display_name,
      csrfTokenHash: result.rows[0].csrf_token_hash,
      deviceId: result.rows[0].device_id || null,
    };
    return next();
  } catch (error) {
    return next(error);
  }
}
