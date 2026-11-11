import test from 'node:test';
import assert from 'node:assert/strict';
import { createTrustedKeysMap } from '../src/utils/trusted-keys.js';

const currentId = '11111111-1111-4111-8111-111111111111';
const activeId = '22222222-2222-4222-8222-222222222222';
const revokedId = '33333333-3333-4333-8333-333333333333';
const validKey = Buffer.alloc(32, 7).toString('base64');

test('trusted key map contains only active canonical Ed25519 keys', () => {
  const result = createTrustedKeysMap([
    { id: currentId, status: 'active', public_key: validKey },
    { id: activeId, status: 'active', public_key: validKey },
    { id: revokedId, status: 'revoked', public_key: validKey },
    { id: 'bad-key', status: 'active', public_key: 'not-base64' },
  ], currentId);
  assert.deepEqual(Object.keys(result).sort(), [currentId, activeId].sort());
  assert.equal(result[revokedId], undefined);
});

test('trusted key map rejects malformed device identifiers', () => {
  assert.equal(createTrustedKeysMap([{ id: 'not-a-uuid', status: 'active', public_key: validKey }], currentId), null);
  assert.equal(createTrustedKeysMap([{ id: currentId, status: 'active', public_key: validKey }], 'not-a-uuid'), null);
});

test('trusted key endpoint cannot authorize a missing or inactive current device', () => {
  assert.equal(createTrustedKeysMap([{ id: activeId, status: 'active', public_key: validKey }], currentId), null);
  assert.equal(createTrustedKeysMap([{ id: currentId, status: 'revoked', public_key: validKey }], currentId), null);
});
