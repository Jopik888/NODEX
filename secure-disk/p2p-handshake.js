const HANDSHAKE_DOMAIN = 'NODEX-P2P-HANDSHAKE-v1';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PEER_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const PHASES = new Set(['ACK', 'FINISH', 'READY']);

function toBase64Url(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function createP2PHandshakeNonce() {
    if (!globalThis.crypto?.getRandomValues) throw new Error('Secure random generator is unavailable.');
    return toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

export function isValidP2PHandshakeNonce(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
    try {
        const standard = value.replace(/-/g, '+').replace(/_/g, '/') + '=';
        const binary = atob(standard);
        if (binary.length !== 32) return false;
        const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
        return toBase64Url(bytes) === value;
    } catch (_) {
        return false;
    }
}

/**
 * Canonical, domain-separated transcript. Both Trystero peer IDs are included
 * to bind a device signature to the transport connection being authenticated.
 */
export function buildP2PHandshakeTranscript(phase, {
    userId,
    initiatorDeviceId,
    responderDeviceId,
    initiatorPeerId,
    responderPeerId,
    roomContext,
    initiatorNonce,
    responderNonce,
} = {}) {
    if (!PHASES.has(phase)) throw new TypeError('Unsupported P2P handshake phase.');
    if (!UUID_PATTERN.test(String(userId || '')) ||
        !UUID_PATTERN.test(String(initiatorDeviceId || '')) ||
        !UUID_PATTERN.test(String(responderDeviceId || '')) ||
        initiatorDeviceId === responderDeviceId ||
        !PEER_ID_PATTERN.test(String(initiatorPeerId || '')) ||
        !PEER_ID_PATTERN.test(String(responderPeerId || '')) ||
        initiatorPeerId === responderPeerId ||
        !/^[a-f0-9]{64}$/.test(String(roomContext || '')) ||
        !isValidP2PHandshakeNonce(initiatorNonce) ||
        !isValidP2PHandshakeNonce(responderNonce) ||
        initiatorNonce === responderNonce) {
        throw new TypeError('Invalid P2P handshake transcript fields.');
    }
    return JSON.stringify([
        HANDSHAKE_DOMAIN,
        phase,
        userId,
        initiatorDeviceId,
        responderDeviceId,
        initiatorPeerId,
        responderPeerId,
        roomContext,
        initiatorNonce,
        responderNonce,
    ]);
}

function assertPeerId(value, label) {
    if (typeof value !== 'string' || !PEER_ID_PATTERN.test(value)) throw new Error(`P2P handshake: invalid ${label}.`);
}

function assertDeviceId(value, label) {
    if (typeof value !== 'string' || !UUID_PATTERN.test(value)) throw new Error(`P2P handshake: invalid ${label}.`);
}

function assertSignedPacket(packet, type, expectedDeviceId, expectedPeerId, initiatorNonce, responderNonce) {
    if (!packet || typeof packet !== 'object' || Array.isArray(packet) ||
        packet.type !== type || packet.version !== 1 ||
        packet.deviceId !== expectedDeviceId || packet.peerId !== expectedPeerId ||
        packet.initiatorNonce !== initiatorNonce || packet.responderNonce !== responderNonce ||
        typeof packet.signature !== 'string' || packet.signature.length < 80 || packet.signature.length > 100) {
        throw new Error(`Некорректный пакет ${type} в P2P handshake.`);
    }
}

/**
 * Mutual Ed25519 device authentication for Trystero's pre-admission callback.
 * The returned peer record must only be added to the trusted peer set after
 * this function resolves successfully.
 */
export async function performP2PHandshake({
    peerId,
    selfId,
    deviceId,
    userId,
    roomContext,
    isInitiator,
    send,
    receive,
    getTrustedPublicKey,
    sign,
    verify,
}) {
    assertPeerId(peerId, 'remote peer ID');
    assertPeerId(selfId, 'local peer ID');
    assertDeviceId(deviceId, 'local device ID');
    assertDeviceId(userId, 'user ID');
    if (peerId === selfId || typeof send !== 'function' || typeof receive !== 'function' ||
        typeof getTrustedPublicKey !== 'function' || typeof sign !== 'function' || typeof verify !== 'function' ||
        typeof isInitiator !== 'boolean') {
        throw new Error('P2P handshake: invalid callback context.');
    }

    const transcript = (phase, values) => buildP2PHandshakeTranscript(phase, { userId, roomContext, ...values });
    const receivePacket = async () => {
        const result = await receive();
        const data = result?.data;
        if (!data || typeof data !== 'object' || Array.isArray(data)) {
            throw new Error('P2P handshake: packet must be an object.');
        }
        let serialized;
        try { serialized = JSON.stringify(data); } catch (_) {
            throw new Error('P2P handshake: packet is not serializable.');
        }
        if (typeof serialized !== 'string' || serialized.length > 4096) {
            throw new Error('P2P handshake: packet exceeds the size limit.');
        }
        return data;
    };

    if (isInitiator) {
        const initiatorNonce = createP2PHandshakeNonce();
        await send({ type: 'HELLO', version: 1, deviceId, peerId: selfId, nonce: initiatorNonce });

        const ack = await receivePacket();
        if (!ack || ack.type !== 'HELLO_ACK' || ack.version !== 1 ||
            typeof ack.deviceId !== 'string' || ack.peerId !== peerId ||
            ack.initiatorNonce !== initiatorNonce || !isValidP2PHandshakeNonce(ack.responderNonce) ||
            typeof ack.signature !== 'string') {
            throw new Error('P2P admission denied: invalid HELLO_ACK.');
        }
        const responderDeviceId = ack.deviceId;
        assertDeviceId(responderDeviceId, 'responder device ID');
        if (responderDeviceId === deviceId) throw new Error('P2P admission denied: duplicate device identity.');
        const responderPublicKey = await getTrustedPublicKey(responderDeviceId);
        if (!responderPublicKey) throw new Error('P2P admission denied: responder device is not active.');

        const common = {
            initiatorDeviceId: deviceId,
            responderDeviceId,
            initiatorPeerId: selfId,
            responderPeerId: peerId,
            initiatorNonce,
            responderNonce: ack.responderNonce,
        };
        if (!await verify(responderPublicKey, transcript('ACK', common), ack.signature)) {
            throw new Error('P2P admission denied: responder signature is invalid.');
        }

        const finishSignature = await sign(transcript('FINISH', common));
        await send({
            type: 'HELLO_FINISH', version: 1, deviceId, peerId: selfId,
            initiatorNonce, responderNonce: ack.responderNonce, signature: finishSignature,
        });

        const ready = await receivePacket();
        assertSignedPacket(ready, 'HELLO_READY', responderDeviceId, peerId, initiatorNonce, ack.responderNonce);
        if (!await verify(responderPublicKey, transcript('READY', common), ready.signature)) {
            throw new Error('P2P admission denied: responder completion signature is invalid.');
        }
        return { deviceId: responderDeviceId, publicKey: responderPublicKey, verifiedAt: Date.now() };
    }

    const hello = await receivePacket();
    if (!hello || hello.type !== 'HELLO' || hello.version !== 1 ||
        typeof hello.deviceId !== 'string' || hello.peerId !== peerId ||
        !isValidP2PHandshakeNonce(hello.nonce)) {
        throw new Error('P2P admission denied: invalid HELLO.');
    }
    const initiatorDeviceId = hello.deviceId;
    assertDeviceId(initiatorDeviceId, 'initiator device ID');
    if (initiatorDeviceId === deviceId) throw new Error('P2P admission denied: duplicate device identity.');
    const initiatorPublicKey = await getTrustedPublicKey(initiatorDeviceId);
    if (!initiatorPublicKey) throw new Error('P2P admission denied: initiator device is not active.');

    const responderNonce = createP2PHandshakeNonce();
    const common = {
        initiatorDeviceId,
        responderDeviceId: deviceId,
        initiatorPeerId: peerId,
        responderPeerId: selfId,
        initiatorNonce: hello.nonce,
        responderNonce,
    };
    const ackSignature = await sign(transcript('ACK', common));
    await send({
        type: 'HELLO_ACK', version: 1, deviceId, peerId: selfId,
        initiatorNonce: hello.nonce, responderNonce, signature: ackSignature,
    });

    const finish = await receivePacket();
    assertSignedPacket(finish, 'HELLO_FINISH', initiatorDeviceId, peerId, hello.nonce, responderNonce);
    if (!await verify(initiatorPublicKey, transcript('FINISH', common), finish.signature)) {
        throw new Error('P2P admission denied: initiator signature is invalid.');
    }

    const readySignature = await sign(transcript('READY', common));
    await send({
        type: 'HELLO_READY', version: 1, deviceId, peerId: selfId,
        initiatorNonce: hello.nonce, responderNonce, signature: readySignature,
    });
    return { deviceId: initiatorDeviceId, publicKey: initiatorPublicKey, verifiedAt: Date.now() };
}
