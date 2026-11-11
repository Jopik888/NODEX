import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const appSource = await readFile(new URL('../../secure-disk/app.js', import.meta.url), 'utf8');

function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  const asyncStart = source.indexOf(`async function ${name}(`);
  const index = start >= 0 ? start : asyncStart;
  assert.ok(index >= 0, `${name} function exists`);
  const brace = source.indexOf('{', index);
  let depth = 0;
  for (let i = brace; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) return source.slice(brace + 1, i);
  }
  throw new Error(`Could not extract ${name}`);
}

test('showApp renders the UI but does not start Trystero', () => {
  const body = extractFunction(appSource, 'showApp');
  assert.doesNotMatch(body, /initWebRTC\s*\(/);
});

test('device proof and active trusted-key fetch precede P2P startup', () => {
  const body = extractFunction(appSource, 'initializeDeviceCryptography');
  const proof = body.indexOf('ensureDeviceRegistered');
  const localIdentity = body.indexOf('getDeviceCryptoIdentity');
  const keys = body.indexOf('refreshTrustedDeviceKeys');
  const enable = body.indexOf('p2pDeviceVerified = true');
  const startup = body.indexOf('initWebRTC(syncRoomId)');
  assert.ok(proof >= 0 && localIdentity > proof && keys > localIdentity && enable > keys && startup > enable);
});

test('Trystero uses pre-admission handshake callback with a finite timeout', () => {
  assert.match(appSource, /joinRoom\([\s\S]*?roomIdentity,[\s\S]*?onPeerHandshake:\s*authenticateTrysteroPeer,[\s\S]*?handshakeTimeoutMs:\s*P2P_HANDSHAKE_TIMEOUT_MS/);
  assert.match(appSource, /onPeerHandshake:\s*authenticateTrysteroPeer/);
  assert.match(appSource, /performP2PHandshake\(/);
  const authStart = appSource.indexOf('await refreshTrustedDeviceKeys();', appSource.indexOf('async function authenticateTrysteroPeer'));
  const handshakeDone = appSource.indexOf('const peerIdentity = await performP2PHandshake', authStart);
  const authRecheck = appSource.indexOf('await refreshTrustedDeviceKeys();', handshakeDone);
  const admission = appSource.indexOf('trustedPeers.set(peerId, peerIdentity)', authRecheck);
  assert.ok(authStart >= 0 && handshakeDone > authStart && authRecheck > handshakeDone && admission > authRecheck,
    'trust keys must be checked before and after the peer handshake');
});

test('sync snapshots are only sent to peers already in trustedPeers and always targeted', () => {
  const body = extractFunction(appSource, 'sendSyncSnapshot');
  assert.match(body, /trustedPeers\.has\(peerId\)/);
  assert.match(body, /\{\s*target:\s*peerId\s*\}/);
  assert.doesNotMatch(body, /send\(createSyncSnapshot\(\)\s*\)/);
});

test('incoming sync request, snapshot and new-file handlers enforce trusted peer membership', () => {
  assert.match(appSource, /sendRequestSync\.onMessage\s*=\s*\(_data,\s*\{\s*peerId\s*\}\)\s*=>\s*\{\s*if\s*\(!p2pDeviceVerified\s*\|\|\s*!trustedPeers\.has\(peerId\)/);
  assert.match(appSource, /sendSyncData\.onMessage\s*=\s*async\s*\(data,\s*\{\s*peerId\s*\}\)\s*=>\s*\{\s*if\s*\(!p2pDeviceVerified\s*\|\|\s*!trustedPeers\.has\(peerId\)/);
  assert.match(appSource, /sendNewFile\.onMessage\s*=\s*\(data,\s*\{\s*peerId\s*\}\)\s*=>\s*\{\s*if\s*\(!p2pDeviceVerified\s*\|\|\s*!trustedPeers\.has\(peerId\)/);
});

test('all manual sync requests are addressed only to trusted peers', () => {
  assert.match(appSource, /sendRequestSync\.send\(\{ profile: currentProfile, version: 1 \}, \{ target: peerId \}\)/);
  assert.doesNotMatch(appSource, /sendRequestSync\.send\(\{\s*profile:\s*currentProfile\s*\}\)/);
  const syncSends = appSource.match(/sendSyncData\.send\([^\n]+/g) || [];
  const requestSends = appSource.match(/sendRequestSync\.send\([^\n]+/g) || [];
  const fileSends = appSource.match(/sendNewFile\.send\([^\n]+/g) || [];
  for (const line of [...syncSends, ...requestSends, ...fileSends]) {
    assert.match(line, /\{\s*target:\s*peerId\s*\}/, line);
  }
  assert.ok(syncSends.length >= 1 && requestSends.length >= 2 && fileSends.length >= 1);
});

test('revocation polling uses 60-second interval and fails closed', () => {
  assert.match(appSource, /const P2P_TRUST_REFRESH_MS\s*=\s*60_000/);
  assert.match(appSource, /setInterval\(async\s*\(\)\s*=>\s*\{[\s\S]*?disableP2P\(/);
  assert.match(appSource, /quarantinePeer\(peerId/);
  assert.match(appSource, /closePeerTransport\(peerId\)/);
  assert.match(appSource, /trustedDeviceKeys\.get\(peerIdentity\.deviceId\) !== peerIdentity\.publicKey/);
});
