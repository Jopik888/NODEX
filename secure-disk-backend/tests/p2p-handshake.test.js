import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import {
  createP2PHandshakeNonce,
  isValidP2PHandshakeNonce,
  buildP2PHandshakeTranscript,
  performP2PHandshake,
} from '../../secure-disk/p2p-handshake.js';

const userId = '11111111-1111-4111-8111-111111111111';
const initiatorDeviceId = '22222222-2222-4222-8222-222222222222';
const responderDeviceId = '33333333-3333-4333-8333-333333333333';
const initiatorPeerId = 'peerInitiator001';
const responderPeerId = 'peerResponder02';
const roomContext = 'a'.repeat(64);

function publicKeyBase64(key) {
  const der = key.export({ format: 'der', type: 'spki' });
  return der.subarray(-32).toString('base64');
}

function createInbox() {
  const queue = [];
  const waiters = [];
  return {
    push(data) {
      const waiter = waiters.shift();
      if (waiter) waiter({ data });
      else queue.push({ data });
    },
    receive() {
      if (queue.length) return Promise.resolve(queue.shift());
      return new Promise(resolve => waiters.push(resolve));
    },
  };
}

function createDuplex() {
  const inboxA = createInbox();
  const inboxB = createInbox();
  return {
    a: { send: async data => inboxB.push(data), receive: () => inboxA.receive() },
    b: { send: async data => inboxA.push(data), receive: () => inboxB.receive() },
  };
}

function makeCrypto(identity, keyPair, knownKeys) {
  return {
    getTrustedPublicKey: async deviceId => knownKeys.get(deviceId) || null,
    sign: async transcript => sign(null, Buffer.from(transcript), keyPair.privateKey).toString('base64'),
    verify: async (publicKey, transcript, signature) => {
      const trusted = [...knownKeys.entries()].find(([, candidate]) => candidate === publicKey);
      if (!trusted) return false;
      const peerId = trusted[0];
      const publicKeyObject = knownKeys.publicObjects.get(peerId);
      try {
        const bytes = Buffer.from(signature, 'base64');
        return bytes.length === 64 && verify(null, Buffer.from(transcript), publicKeyObject, bytes);
      } catch {
        return false;
      }
    },
  };
}

function makeKeyStore(entries) {
  const keys = new Map();
  keys.publicObjects = new Map();
  for (const [deviceId, pair] of entries) {
    keys.set(deviceId, publicKeyBase64(pair.publicKey));
    keys.publicObjects.set(deviceId, pair.publicKey);
  }
  return keys;
}

test('P2P handshake nonce is 256-bit canonical base64url and unique', () => {
  const a = createP2PHandshakeNonce();
  const b = createP2PHandshakeNonce();
  assert.equal(a.length, 43);
  assert.match(a, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(isValidP2PHandshakeNonce(a), true);
  assert.equal(isValidP2PHandshakeNonce(b), true);
  assert.notEqual(a, b);
  assert.equal(isValidP2PHandshakeNonce(`${a}=`), false);
  assert.equal(isValidP2PHandshakeNonce(`${'A'.repeat(42)}B`), false);
});

test('canonical transcript binds phase, both device IDs, peer IDs and both nonces', () => {
  const n1 = createP2PHandshakeNonce();
  const n2 = createP2PHandshakeNonce();
  const base = {
    userId, initiatorDeviceId, responderDeviceId,
    initiatorPeerId, responderPeerId, roomContext,
    initiatorNonce: n1, responderNonce: n2,
  };
  const ack = buildP2PHandshakeTranscript('ACK', base);
  const finish = buildP2PHandshakeTranscript('FINISH', base);
  const changedPeer = buildP2PHandshakeTranscript('ACK', { ...base, responderPeerId: 'differentPeer003' });
  const changedRoom = buildP2PHandshakeTranscript('ACK', { ...base, roomContext: 'b'.repeat(64) });
  assert.notEqual(ack, finish);
  assert.notEqual(ack, changedPeer);
  assert.notEqual(ack, changedRoom);
  assert.match(ack, /NODEX-P2P-HANDSHAKE-v1/);
  assert.throws(() => buildP2PHandshakeTranscript('ACK', { ...base, initiatorNonce: 'replay' }), /Invalid/);
  assert.throws(() => buildP2PHandshakeTranscript('ACK', { ...base, responderDeviceId: initiatorDeviceId }), /Invalid/);
});

test('signature over a handshake transcript cannot be replayed against another nonce or phase', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const n1 = createP2PHandshakeNonce();
  const n2 = createP2PHandshakeNonce();
  const common = { userId, initiatorDeviceId, responderDeviceId, initiatorPeerId, responderPeerId, roomContext, initiatorNonce: n1, responderNonce: n2 };
  const message = buildP2PHandshakeTranscript('ACK', common);
  const signature = sign(null, Buffer.from(message), privateKey);
  assert.equal(verify(null, Buffer.from(message), publicKey, signature), true);
  const changed = buildP2PHandshakeTranscript('ACK', { ...common, initiatorNonce: createP2PHandshakeNonce() });
  assert.equal(verify(null, Buffer.from(changed), publicKey, signature), false);
});

test('two active devices complete mutual admission handshake and obtain each other identity', async () => {
  const initiatorKeys = generateKeyPairSync('ed25519');
  const responderKeys = generateKeyPairSync('ed25519');
  const initiatorStore = makeKeyStore([[responderDeviceId, responderKeys]]);
  const responderStore = makeKeyStore([[initiatorDeviceId, initiatorKeys]]);
  const channel = createDuplex();

  const [initiatorPeer, responderPeer] = await Promise.all([
    performP2PHandshake({
      peerId: responderPeerId, selfId: initiatorPeerId, deviceId: initiatorDeviceId, userId,
      roomContext, isInitiator: true, ...channel.a, ...makeCrypto(initiatorDeviceId, initiatorKeys, initiatorStore),
    }),
    performP2PHandshake({
      peerId: initiatorPeerId, selfId: responderPeerId, deviceId: responderDeviceId, userId,
      roomContext, isInitiator: false, ...channel.b, ...makeCrypto(responderDeviceId, responderKeys, responderStore),
    }),
  ]);

  assert.equal(initiatorPeer.deviceId, responderDeviceId);
  assert.equal(initiatorPeer.publicKey, initiatorStore.get(responderDeviceId));
  assert.equal(responderPeer.deviceId, initiatorDeviceId);
  assert.equal(responderPeer.publicKey, responderStore.get(initiatorDeviceId));
  assert.ok(initiatorPeer.verifiedAt > 0);
  assert.ok(responderPeer.verifiedAt > 0);
});

test('unknown or inactive device is denied before peer admission', async () => {
  const n = createP2PHandshakeNonce();
  await assert.rejects(() => performP2PHandshake({
    peerId: initiatorPeerId,
    selfId: responderPeerId,
    deviceId: responderDeviceId,
    userId,
    roomContext,
    isInitiator: false,
    send: async () => assert.fail('must not send ACK to unknown device'),
    receive: async () => ({ data: { type: 'HELLO', version: 1, deviceId: initiatorDeviceId, peerId: initiatorPeerId, nonce: n } }),
    getTrustedPublicKey: async () => null,
    sign: async () => assert.fail('must not sign for unknown device'),
    verify: async () => false,
  }), /not active/);
});

test('invalid Ed25519 signature is rejected even when the device ID is active', async () => {
  const trustedPair = generateKeyPairSync('ed25519');
  const attackerPair = generateKeyPairSync('ed25519');
  const trustedStore = makeKeyStore([[responderDeviceId, trustedPair]]);
  const responderNonce = createP2PHandshakeNonce();
  let helloPacket = null;
  await assert.rejects(() => performP2PHandshake({
    peerId: responderPeerId,
    selfId: initiatorPeerId,
    deviceId: initiatorDeviceId,
    userId,
    roomContext,
    isInitiator: true,
    send: async packet => { helloPacket = packet; },
    receive: async () => {
      const common = {
        initiatorDeviceId, responderDeviceId, initiatorPeerId, responderPeerId, roomContext,
        initiatorNonce: helloPacket.nonce, responderNonce,
      };
      const forgedSignature = sign(null, Buffer.from(buildP2PHandshakeTranscript('ACK', { userId, ...common })), attackerPair.privateKey).toString('base64');
      return { data: {
        type: 'HELLO_ACK', version: 1, deviceId: responderDeviceId,
        peerId: responderPeerId, initiatorNonce: helloPacket.nonce, responderNonce, signature: forgedSignature,
      } };
    },
    getTrustedPublicKey: async id => trustedStore.get(id),
    sign: async () => 'A'.repeat(88),
    verify: async (publicKey, transcript, signature) => {
      const id = [...trustedStore.entries()].find(([, key]) => key === publicKey)?.[0];
      return Boolean(id && verify(null, Buffer.from(transcript), trustedStore.publicObjects.get(id), Buffer.from(signature, 'base64')));
    },
  }), /responder signature is invalid/);
});

test('invalid initiator peer binding is rejected', async () => {
  const n = createP2PHandshakeNonce();
  await assert.rejects(() => performP2PHandshake({
    peerId: responderPeerId,
    selfId: initiatorPeerId,
    deviceId: initiatorDeviceId,
    userId,
    roomContext,
    isInitiator: true,
    send: async () => {},
    receive: async () => ({ data: {
      type: 'HELLO_ACK', version: 1, deviceId: responderDeviceId,
      peerId: 'anotherPeer', initiatorNonce: n, responderNonce: createP2PHandshakeNonce(),
      signature: 'A'.repeat(88),
    } }),
    getTrustedPublicKey: async () => 'A'.repeat(44),
    sign: async () => 'A'.repeat(88),
    verify: async () => true,
  }), /invalid HELLO_ACK/);
});
