import test from 'node:test';
import assert from 'node:assert/strict';
import { isPlausibleIpfsCid } from '../src/utils/ipfs-cid.js';

test('accepts CIDv0 base58btc identifiers', () => {
  assert.equal(isPlausibleIpfsCid(`Qm${'a'.repeat(44)}`), true);
});

test('accepts lowercase CIDv1 base32 identifiers', () => {
  assert.equal(isPlausibleIpfsCid(`b${'a'.repeat(20)}`), true);
});

test('rejects empty, malformed, and unsupported CID text', () => {
  for (const value of ['', null, 42, 'Qm-short', `Qm${'0'.repeat(44)}`, 'B' + 'a'.repeat(20), `b${'a'.repeat(121)}`]) {
    assert.equal(isPlausibleIpfsCid(value), false, `expected rejection for ${String(value)}`);
  }
});
