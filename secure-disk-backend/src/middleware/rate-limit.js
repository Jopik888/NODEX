import { rateLimit } from 'express-rate-limit';

function makeLimiter(windowMs, limit, code = 'RATE_LIMITED') {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({ error: { code, message: 'Too many requests. Please try again later.' } });
    },
  });
}

export const apiLimiter = makeLimiter(15 * 60 * 1000, 300);
export const registerLimiter = makeLimiter(60 * 60 * 1000, 5, 'REGISTER_RATE_LIMITED');
export const verifyLimiter = makeLimiter(15 * 60 * 1000, 10, 'VERIFY_RATE_LIMITED');
export const resendLimiter = makeLimiter(60 * 60 * 1000, 3, 'RESEND_RATE_LIMITED');
export const loginLimiter = makeLimiter(15 * 60 * 1000, 10, 'LOGIN_RATE_LIMITED');
export const refreshLimiter = makeLimiter(60 * 1000, 30, 'REFRESH_RATE_LIMITED');
export const logoutLimiter = makeLimiter(60 * 1000, 30, 'LOGOUT_RATE_LIMITED');

export const deviceRegisterLimiter = makeLimiter(60 * 60 * 1000, 20, 'DEVICE_REGISTER_RATE_LIMITED');
