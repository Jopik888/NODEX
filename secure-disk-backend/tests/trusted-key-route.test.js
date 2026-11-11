import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const routeSource = await readFile(new URL('../src/routes/devices.routes.js', import.meta.url), 'utf8');
const appSource = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');

test('trusted-keys endpoint is mounted under the authenticated devices API', () => {
  assert.match(routeSource, /router\.use\(requireAuth\)/);
  assert.match(routeSource, /router\.get\('\/trusted-keys'/);
  assert.match(appSource, /api\.use\(['"]\/devices['"],\s*devicesRoutes\)/);
  assert.match(appSource, /app\.use\(['"]\/api\/v1['"],\s*api\)/);
});

test('trusted-keys query is account-scoped and returns active devices only', () => {
  const match = routeSource.match(/router\.get\('\/trusted-keys',[\s\S]*?\n\}\);/);
  assert.ok(match, 'trusted-keys route exists');
  const body = match[0];
  assert.match(body, /if\s*\(!req\.auth\.deviceId\)/);
  assert.match(body, /WHERE user_id = \$1 AND status = 'active'/);
  assert.match(body, /\[req\.auth\.userId\]/);
  assert.match(body, /createTrustedKeysMap\(result\.rows,\s*req\.auth\.deviceId\)/);
  assert.match(body, /Cache-Control',\s*'no-store'/);
  assert.match(body, /Pragma',\s*'no-cache'/);
});
