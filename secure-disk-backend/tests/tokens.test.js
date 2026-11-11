import test from 'node:test';
import assert from 'node:assert/strict';
import { createOpaqueToken, hashToken, constantTimeStringEqual, constantTimeBufferEqual } from '../src/utils/tokens.js';

test('opaque tokens use URL-safe encoding and requested entropy size', () => {
  const token = createOpaqueToken(32);
  assert.match(token, /^[A-Za-z0-9_-]+$/);
  assert.equal(Buffer.from(token, 'base64url').length, 32);
});

test('token hashes are stable SHA-256 digests and do not expose source token', () => {
  const token = createOpaqueToken(32);
  const first = hashToken(token);
  const second = hashToken(token);
  assert.equal(first.length, 32);
  assert.deepEqual(first, second);
  assert.notEqual(first.toString('base64'), token);
});

test('constant-time comparison helpers reject mismatches and malformed values', () => {
  assert.equal(constantTimeStringEqual('abc', 'abc'), true);
  assert.equal(constantTimeStringEqual('abc', 'abd'), false);
  assert.equal(constantTimeStringEqual(undefined, 'abc'), false);
  assert.equal(constantTimeBufferEqual(Buffer.from('x'), Buffer.from('x')), true);
  assert.equal(constantTimeBufferEqual(Buffer.from('x'), Buffer.from('y')), false);
});
