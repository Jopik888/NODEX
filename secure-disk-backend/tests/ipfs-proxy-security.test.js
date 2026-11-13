import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const routeSource = await readFile(
  new URL('../src/routes/ipfs-proxy.routes.js', import.meta.url),
  'utf8',
);

test('Kubo RPC target is fixed to IPv4 loopback', () => {
  assert.match(routeSource, /const KUBO_API = 'http:\/\/127\.0\.0\.1:5001\/api\/v0';/);
  assert.doesNotMatch(routeSource, /0\.0\.0\.0|process\.env\.KUBO|req\.query\.url/);
});

test('authentication and both CSRF checks execute before Multer reads uploads', () => {
  const authIndex = routeSource.indexOf('router.use(requireAuth)');
  const rateLimitIndex = routeSource.indexOf("router.use(makeLimiter(60 * 1000, 120");
  const csrfIndex = routeSource.indexOf('router.use(requireCsrf, requireSessionCsrf)');
  const multerIndex = routeSource.indexOf("upload.single('file')");

  assert.ok(authIndex >= 0, 'requireAuth middleware must be mounted');
  assert.ok(rateLimitIndex > authIndex, 'global IPFS rate limiter must follow authentication');
  assert.ok(csrfIndex > rateLimitIndex, 'CSRF and session CSRF must run before route handlers');
  assert.ok(multerIndex > csrfIndex, 'Multer must not write request bodies before auth and CSRF');
});

test('uploads are disk-backed, size-limited, and independently rate-limited', () => {
  assert.match(routeSource, /const MAX_UPLOAD_BYTES = 100 \* 1024 \* 1024;/);
  assert.match(routeSource, /storage: multer\.diskStorage\(/);
  assert.match(routeSource, /limits: \{ fileSize: MAX_UPLOAD_BYTES, files: 1, fields: 0, parts: 1 \}/);
  assert.match(routeSource, /makeLimiter\(60 \* 1000, 10, 'IPFS_UPLOAD_RATE_LIMITED'\)/);
  assert.match(routeSource, /finally \{\s*await rm\(filePath, \{ force: true \}\)/);
});

test('proxy exposes only content add/cat and pin add/rm; no admin or catch-all RPC', () => {
  const postRoutes = [...routeSource.matchAll(/router\.post\('([^']+)'/g)].map((match) => match[1]);
  assert.deepEqual(postRoutes, ['/add', '/cat']);
  assert.match(routeSource, /for \(const operation of \['add', 'rm'\]\)/);
  assert.doesNotMatch(routeSource, /repo\/gc|router\.all\(|router\.use\(['"]\/\*/);
});

test('all content identifiers are validated before Kubo cat and pin requests', () => {
  assert.match(routeSource, /if \(!validCid\(cid\)\)/);
  assert.equal((routeSource.match(/if \(!validCid\(cid\)\)/g) || []).length, 2);
});
