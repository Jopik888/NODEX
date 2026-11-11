import test from 'node:test';
import assert from 'node:assert/strict';
import { parseKuboAddResponse } from '../src/utils/ipfs-proxy-response.js';

const cid = `Qm${'a'.repeat(44)}`;

test('parses the final JSON row from Kubo NDJSON upload output', () => {
  assert.deepEqual(parseKuboAddResponse(
    `{"Name":"payload.enc","Bytes":"10"}\r\n{"Hash":"${cid}","Size":"10"}\r\n`
  ), { Hash: cid, Size: '10' });
});

test('normalizes a missing Kubo upload size to an empty string', () => {
  assert.deepEqual(parseKuboAddResponse(JSON.stringify({ Hash: cid })), { Hash: cid, Size: '' });
});

test('rejects empty, malformed, and invalid-CID upload output', () => {
  for (const value of ['', 'not-json', '{"Hash":"bad"}', '{"Hash":null}']) {
    assert.throws(() => parseKuboAddResponse(value));
  }
});

test('rejects non-text Kubo output', () => {
  assert.throws(() => parseKuboAddResponse(null), TypeError);
});
