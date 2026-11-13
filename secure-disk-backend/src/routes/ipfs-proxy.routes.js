import { Router } from 'express';
import multer from 'multer';
import { randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { requireAuth } from '../middleware/auth.js';
import { requireCsrf, requireSessionCsrf } from '../middleware/csrf.js';
import { makeLimiter } from '../middleware/rate-limit.js';
import { isPlausibleIpfsCid } from '../utils/ipfs-cid.js';
import { parseKuboAddResponse } from '../utils/ipfs-proxy-response.js';

const router = Router();
const KUBO_API = 'http://127.0.0.1:5001/api/v0';
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;
const ipfsUploadLimiter = makeLimiter(60 * 1000, 10, 'IPFS_UPLOAD_RATE_LIMITED');
const TEMP_DIR = path.join(os.tmpdir(), 'nodex-ipfs-proxy');

await mkdir(TEMP_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, TEMP_DIR),
    filename: (_req, _file, callback) => callback(null, `${randomUUID()}.upload`),
  }),
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1, fields: 0, parts: 1 },
});

const validCid = isPlausibleIpfsCid;
function badRequest(res, code, message, status = 400) {
  return res.status(status).json({ error: { code, message } });
}
function kuboUrl(command, arg) {
  const url = new URL(`${KUBO_API}/${command}`);
  if (arg !== undefined) url.searchParams.set('arg', arg);
  return url;
}

async function fetchKubo(url, options) {
  try {
    return await fetch(url, options);
  } catch (error) {
    const code = error?.cause?.code;
    if (error?.name === 'TimeoutError' || error?.name === 'AbortError'
      || ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT'].includes(code)) {
      const unavailable = new Error('The local IPFS service is unavailable.');
      unavailable.code = 'IPFS_UNAVAILABLE';
      unavailable.cause = error;
      throw unavailable;
    }
    throw error;
  }
}

function handleKuboError(error, res, next) {
  if (error?.code === 'IPFS_UNAVAILABLE') {
    return badRequest(res, 'IPFS_UNAVAILABLE', 'Local IPFS service is unavailable.', 503);
  }
  return next(error);
}

router.use(requireAuth);
router.use(makeLimiter(60 * 1000, 120, 'IPFS_RATE_LIMITED'));
router.use(requireCsrf, requireSessionCsrf);

// This is a narrow RPC allowlist, not a general-purpose Kubo proxy.
router.post('/add', ipfsUploadLimiter, upload.single('file'), async (req, res, next) => {
  const filePath = req.file?.path;
  if (!filePath) return badRequest(res, 'IPFS_FILE_REQUIRED', 'A single file field is required.');
  try {
    const boundary = `nodex-${randomUUID()}`;
    const safeName = 'payload.enc';
    const prefix = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${safeName}"\r\nContent-Type: application/octet-stream\r\n\r\n`);
    const suffix = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Readable.toWeb(Readable.from((async function* () {
      yield prefix;
      for await (const chunk of createReadStream(filePath)) yield chunk;
      yield suffix;
    })()));
    const addUrl = kuboUrl('add');
    if (req.query.pin === 'true') addUrl.searchParams.set('pin', 'true');
    const upstream = await fetchKubo(addUrl, {
      method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      body,
      duplex: 'half',
      signal: AbortSignal.timeout(150000),
    });
    const text = await upstream.text();
    if (!upstream.ok) return badRequest(res, 'IPFS_UPSTREAM_ERROR', 'Local IPFS upload failed.', 502);
    let result;
    try {
      result = parseKuboAddResponse(text);
    } catch {
      return badRequest(res, 'IPFS_INVALID_RESPONSE', 'Local IPFS returned an invalid upload response.', 502);
    }
    res.set('Cache-Control', 'no-store');
    return res.json(result);
  } catch (error) {
    return handleKuboError(error, res, next);
  } finally {
    await rm(filePath, { force: true }).catch(() => {});
  }
});

router.post('/cat', async (req, res, next) => {
  try {
    const cid = req.query.arg;
    if (!validCid(cid)) return badRequest(res, 'IPFS_INVALID_CID', 'Content identifier is invalid.');
    const upstream = await fetchKubo(kuboUrl('cat', cid), { method: 'POST', signal: AbortSignal.timeout(150000) });
    if (!upstream.ok || !upstream.body) return badRequest(res, 'IPFS_NOT_FOUND', 'Encrypted object was not found on this node.', upstream.status === 404 ? 404 : 502);
    res.set('Content-Type', 'application/octet-stream');
    res.set('Cache-Control', 'no-store');
    res.set('X-Content-Type-Options', 'nosniff');
    await pipeline(Readable.fromWeb(upstream.body), res);
    return undefined;
  } catch (error) {
    return handleKuboError(error, res, next);
  }
});

for (const operation of ['add', 'rm']) {
  router.post(`/pin/${operation}`, async (req, res, next) => {
    try {
      const cid = req.query.arg;
      if (!validCid(cid)) return badRequest(res, 'IPFS_INVALID_CID', 'Content identifier is invalid.');
      const upstream = await fetchKubo(kuboUrl(`pin/${operation}`, cid), { method: 'POST', signal: AbortSignal.timeout(30000) });
      if (!upstream.ok) return badRequest(res, 'IPFS_PIN_FAILED', 'Local IPFS pin operation failed.', 502);
      let payload;
      try {
        payload = await upstream.json();
      } catch {
        return badRequest(res, 'IPFS_INVALID_RESPONSE', 'Local IPFS returned an invalid pin response.', 502);
      }
      if (!payload || typeof payload !== 'object') {
        return badRequest(res, 'IPFS_INVALID_RESPONSE', 'Local IPFS returned an invalid pin response.', 502);
      }
      res.set('Cache-Control', 'no-store');
      return res.json(payload);
    } catch (error) {
      return handleKuboError(error, res, next);
    }
  });
}

export default router;
