import { createOpaqueToken, constantTimeBufferEqual, constantTimeStringEqual, hashToken } from '../utils/tokens.js';
import { config } from '../config/index.js';

export function setCsrfCookie(res, token) {
  res.cookie(config.cookieNames.csrf, token, {
    httpOnly: false,
    secure: config.cookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

export function issueCsrfToken(res) {
  const token = createOpaqueToken(32);
  setCsrfCookie(res, token);
  return token;
}

export function requireCsrf(req, res, next) {
  const cookieToken = req.cookies?.[config.cookieNames.csrf];
  const headerToken = req.get('X-CSRF-Token');
  const origin = req.get('Origin');

  if (!constantTimeStringEqual(cookieToken, headerToken)) {
    return res.status(403).json({ error: { code: 'CSRF_VALIDATION_FAILED', message: 'CSRF token is missing or invalid.' } });
  }

  if (origin && !config.frontendOrigins.includes(origin)) {
    return res.status(403).json({ error: { code: 'ORIGIN_NOT_ALLOWED', message: 'Request origin is not allowed.' } });
  }

  if (config.isProduction && !origin) {
    return res.status(403).json({ error: { code: 'ORIGIN_REQUIRED', message: 'Origin header is required for cookie-authenticated requests.' } });
  }

  return next();
}

export function requireSessionCsrf(req, res, next) {
  const cookieToken = req.cookies?.[config.cookieNames.csrf];
  const receivedHash = typeof cookieToken === 'string' ? hashToken(cookieToken) : null;
  if (!receivedHash || !constantTimeBufferEqual(req.auth?.csrfTokenHash, receivedHash)) {
    return res.status(403).json({ error: { code: 'CSRF_SESSION_VALIDATION_FAILED', message: 'CSRF token is not bound to this session.' } });
  }
  return next();
}
