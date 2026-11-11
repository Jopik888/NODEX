import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { config } from './config/index.js';
import authRoutes from './routes/auth.routes.js';
import csrfRoutes from './routes/csrf.routes.js';
import devicesRoutes from './routes/devices.routes.js';
import pairingRoutes from './routes/pairing.routes.js';
import vaultRoutes from './routes/vault.routes.js';
import ipfsProxyRoutes from './routes/ipfs-proxy.routes.js';
import { apiLimiter } from './middleware/rate-limit.js';

export const app = express();

app.disable('x-powered-by');
if (config.trustProxy !== false) app.set('trust proxy', config.trustProxy);

app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || config.frontendOrigins.includes(origin)) return callback(null, true);
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-Pairing-Token'],
  maxAge: 600,
}));
app.use(express.json({ limit: '32kb', strict: true }));
app.use(cookieParser());

app.get('/healthz', async (_req, res, next) => {
  try {
    // A shallow liveness/readiness check. Does not expose DB details.
    const { pool } = await import('./db/pool.js');
    await pool.query('SELECT 1');
    return res.status(200).json({ status: 'ok', service: 'secure-disk-backend', version: '0.4.6' });
  } catch (error) {
    return next(error);
  }
});

const api = express.Router();
api.use(apiLimiter);
api.use(csrfRoutes);
api.use('/auth', authRoutes);
api.use('/devices/pairing', pairingRoutes);
api.use('/devices', devicesRoutes);
api.use('/vault', vaultRoutes);
app.use('/api/v1', api);
app.use('/ipfs/api/v0', ipfsProxyRoutes);

app.use((_req, res) => {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Route not found.' } });
});

app.use((error, _req, res, _next) => {
  if (res.headersSent) return;

  if (error?.type === 'entity.parse.failed') {
    return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'Request body contains invalid JSON.' } });
  }
  if (error?.type === 'entity.too.large') {
    return res.status(413).json({ error: { code: 'REQUEST_TOO_LARGE', message: 'Request body is too large.' } });
  }

  console.error(JSON.stringify({
    level: 'error',
    event: 'unhandled_request_error',
    message: error?.message || 'Unknown error',
    code: error?.code,
  }));
  return res.status(500).json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'An unexpected server error occurred.' } });
});
