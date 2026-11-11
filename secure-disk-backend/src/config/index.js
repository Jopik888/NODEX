import dotenv from 'dotenv';

dotenv.config();

function asBoolean(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function parseTrustProxy(value) {
  if (!value || value === 'false' || value === '0') return false;
  if (value === 'true') {
    throw new Error('TRUST_PROXY=true is unsafe. Set an explicit trusted proxy hop count, e.g. TRUST_PROXY=1.');
  }
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

const nodeEnv = process.env.NODE_ENV || 'development';
const isProduction = nodeEnv === 'production';
const syncKeyText = process.env.SYNC_ROOM_ENCRYPTION_KEY_BASE64 || '';
const syncKey = Buffer.from(syncKeyText, 'base64');
const frontendOrigins = (process.env.FRONTEND_ORIGINS || 'http://localhost:5500,http://127.0.0.1:5500')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const smtpHost = process.env.SMTP_HOST?.trim() || '';
const smtpUser = process.env.SMTP_USER?.trim() || '';
const smtpPass = process.env.SMTP_PASS || '';
const smtpFrom = process.env.SMTP_FROM?.trim() || '';
const smtpConfigured = Boolean(smtpHost && smtpUser && smtpPass && smtpFrom);
const smtpPartiallyConfigured = Boolean(smtpHost || smtpUser || smtpPass || smtpFrom);

if (syncKey.length !== 32 || syncKey.toString('base64') !== syncKeyText) {
  throw new Error('SYNC_ROOM_ENCRYPTION_KEY_BASE64 must be canonical Base64 of exactly 32 random bytes.');
}
if (isProduction && !asBoolean(process.env.COOKIE_SECURE, true)) {
  throw new Error('COOKIE_SECURE must be true in production.');
}
if (isProduction && !smtpConfigured) {
  throw new Error('SMTP_HOST, SMTP_USER, SMTP_PASS and SMTP_FROM must be configured in production.');
}
if (!smtpConfigured && smtpPartiallyConfigured) {
  throw new Error('SMTP configuration is incomplete. Set SMTP_HOST, SMTP_USER, SMTP_PASS and SMTP_FROM, or leave all SMTP values empty in development.');
}

const accessTokenTtlSeconds = Number(process.env.ACCESS_TOKEN_TTL_SECONDS || 600);
const refreshTokenTtlDays = Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30);
if (!Number.isInteger(accessTokenTtlSeconds) || accessTokenTtlSeconds < 60 || accessTokenTtlSeconds > 3600) {
  throw new Error('ACCESS_TOKEN_TTL_SECONDS must be an integer from 60 to 3600.');
}
if (!Number.isInteger(refreshTokenTtlDays) || refreshTokenTtlDays < 1 || refreshTokenTtlDays > 90) {
  throw new Error('REFRESH_TOKEN_TTL_DAYS must be an integer from 1 to 90.');
}

export const config = Object.freeze({
  nodeEnv,
  isProduction,
  host: process.env.HOST || 'localhost',
  port: Number(process.env.PORT || 3001),
  databaseUrl: process.env.DATABASE_URL || '',
  databaseSsl: asBoolean(process.env.DATABASE_SSL, false),
  frontendOrigins,
  syncRoomEncryptionKey: syncKey,
  syncRoomEncryptionKeyVersion: process.env.SYNC_ROOM_ENCRYPTION_KEY_VERSION || 'local-v1',
  devReturnVerificationToken: nodeEnv === 'development' && !smtpConfigured && asBoolean(process.env.DEV_RETURN_VERIFICATION_TOKEN, false),
  smtp: smtpConfigured ? {
    host: smtpHost,
    port: Number(process.env.SMTP_PORT || 587),
    secure: asBoolean(process.env.SMTP_SECURE, false),
    auth: smtpUser ? { user: smtpUser, pass: smtpPass } : undefined,
    from: smtpFrom,
  } : null,
  cookieSecure: isProduction || asBoolean(process.env.COOKIE_SECURE, false),
  cookieNames: isProduction
    ? { access: '__Host-access', refresh: '__Host-refresh', csrf: '__Host-csrf' }
    : { access: 'access_token', refresh: 'refresh_token', csrf: 'csrf_token' },
  accessTokenTtlSeconds,
  refreshTokenTtlDays,
  trustProxy: parseTrustProxy(process.env.TRUST_PROXY),
});

if (!config.databaseUrl) {
  throw new Error('DATABASE_URL is required. Copy .env.example to .env and configure PostgreSQL.');
}
if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535.');
}
