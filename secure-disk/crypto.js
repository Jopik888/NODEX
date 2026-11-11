import { registerDevice, createDeviceChallenge, verifyDevice } from './auth.js';

const DATABASE_NAME = 'secureDiskDeviceIdentity';
const DATABASE_VERSION = 1;
const STORE_NAME = 'identities';

function idbRequest(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('IndexedDB request failed.'));
    });
}

function idbTransaction(transaction) {
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(transaction.error || new Error('IndexedDB transaction aborted.'));
        transaction.onerror = () => reject(transaction.error || new Error('IndexedDB transaction failed.'));
    });
}

function openIdentityDatabase() {
    return new Promise((resolve, reject) => {
        if (!('indexedDB' in globalThis)) {
            reject(new Error('Этот браузер не предоставляет IndexedDB для безопасного хранения ключей.'));
            return;
        }

        const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
        request.onupgradeneeded = () => {
            const database = request.result;
            if (!database.objectStoreNames.contains(STORE_NAME)) {
                database.createObjectStore(STORE_NAME);
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('Не удалось открыть IndexedDB.'));
        request.onblocked = () => reject(new Error('Обновление хранилища ключей заблокировано другой вкладкой. Закройте другие вкладки Secure Disk и повторите попытку.'));
    });
}

async function readIdentity(userId) {
    const database = await openIdentityDatabase();
    try {
        const transaction = database.transaction(STORE_NAME, 'readonly');
        const done = idbTransaction(transaction);
        const result = await idbRequest(transaction.objectStore(STORE_NAME).get(userId));
        await done;
        return result || null;
    } finally {
        database.close();
    }
}

async function writeIdentity(userId, record) {
    const database = await openIdentityDatabase();
    try {
        const transaction = database.transaction(STORE_NAME, 'readwrite');
        const done = idbTransaction(transaction);
        transaction.objectStore(STORE_NAME).put(record, userId);
        await done;
    } finally {
        database.close();
    }
}

function toBase64(bytes) {
    let binary = '';
    for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function assertCryptoEnvironment() {
    if (!globalThis.isSecureContext) {
        throw new Error('Web Crypto API доступен только в защищённом контексте. Откройте приложение через HTTPS или localhost.');
    }
    if (!globalThis.crypto?.subtle) {
        throw new Error('Web Crypto API недоступен в этом браузере.');
    }
}

function isValidStoredIdentity(record) {
    return Boolean(
        record &&
        record.version === 1 &&
        record.signingKeyPair?.privateKey?.algorithm?.name === 'Ed25519' &&
        record.signingKeyPair?.privateKey?.extractable === false &&
        record.signingKeyPair?.publicKey?.algorithm?.name === 'Ed25519' &&
        record.encryptionKeyPair?.privateKey?.algorithm?.name === 'X25519' &&
        record.encryptionKeyPair?.privateKey?.extractable === false &&
        record.encryptionKeyPair?.publicKey?.algorithm?.name === 'X25519' &&
        typeof record.publicKeyBase64 === 'string' &&
        typeof record.encryptionPublicKeyBase64 === 'string'
    );
}

async function createIdentity() {
    assertCryptoEnvironment();

    try {
        // Public keys remain exportable; private keys are explicitly non-extractable.
        const signingKeyPair = await crypto.subtle.generateKey(
            { name: 'Ed25519' },
            false,
            ['sign', 'verify'],
        );
        const encryptionKeyPair = await crypto.subtle.generateKey(
            { name: 'X25519' },
            false,
            ['deriveBits'],
        );

        const [publicKeyRaw, encryptionPublicKeyRaw] = await Promise.all([
            crypto.subtle.exportKey('raw', signingKeyPair.publicKey),
            crypto.subtle.exportKey('raw', encryptionKeyPair.publicKey),
        ]);

        return {
            version: 1,
            signingKeyPair,
            encryptionKeyPair,
            publicKeyBase64: toBase64(publicKeyRaw),
            encryptionPublicKeyBase64: toBase64(encryptionPublicKeyRaw),
            deviceId: null,
            createdAt: new Date().toISOString(),
        };
    } catch (error) {
        if (error?.name === 'NotSupportedError' || error?.name === 'OperationError') {
            throw new Error('Браузер не поддерживает генерацию Ed25519/X25519 через Web Crypto API. Нужен современный браузер; резервный вариант на libsodium будет отдельным модулем.');
        }
        throw error;
    }
}

function getDeviceDescription() {
    const platform = String(navigator.userAgentData?.platform || navigator.platform || 'unknown')
        .replace(/[\r\n]/g, ' ')
        .slice(0, 100);

    return {
        device_name: `Secure Disk Browser (${platform || 'unknown'})`.slice(0, 80),
        device_type: 'browser',
        platform,
        app_version: '0.4.6',
        signing_algorithm: 'Ed25519',
        encryption_algorithm: 'X25519',
    };
}

/**
 * Creates one stable key identity per account in this browser and registers its
 * public keys with the authenticated backend. Private CryptoKey objects never
 * leave IndexedDB and are never included in an API request.
 */
export async function ensureDeviceRegistered(userId) {
    if (typeof userId !== 'string' || !userId) {
        throw new Error('Невозможно зарегистрировать устройство: отсутствует user_id.');
    }
    assertCryptoEnvironment();

    let identity = await readIdentity(userId);
    if (identity && !isValidStoredIdentity(identity)) {
        throw new Error('Локальная запись криптографического устройства повреждена или имеет неизвестный формат. Она не была перезаписана.');
    }

    if (!identity) {
        identity = await createIdentity();
        // Save before the network request. If the request times out, retrying uses
        // exactly the same key pair and the backend can return the same device.
        await writeIdentity(userId, identity);
    }

    const response = await registerDevice({
        ...getDeviceDescription(),
        public_key: identity.publicKeyBase64,
        encryption_public_key: identity.encryptionPublicKeyBase64,
        signing_algorithm: 'Ed25519',
        encryption_algorithm: 'X25519',
    });

    if (!response?.device?.id || !['pending', 'active'].includes(response.device.status)) {
        throw new Error('Backend не подтвердил регистрацию устройства.');
    }

    identity.deviceId = response.device.id;
    identity.registeredAt = response.device.created_at || identity.registeredAt || new Date().toISOString();
    await writeIdentity(userId, identity);

    // Registration only stores public keys as pending. The device becomes
    // trusted after signing a short-lived, session-bound server challenge.
    const challenge = await createDeviceChallenge(identity.deviceId);
    if (!challenge?.challenge_id || typeof challenge.message !== 'string') {
        throw new Error('Backend не выдал challenge для подтверждения устройства.');
    }
    const signatureBytes = await crypto.subtle.sign(
        'Ed25519', identity.signingKeyPair.privateKey, new TextEncoder().encode(challenge.message),
    );
    const signature = toBase64(signatureBytes);
    const proof = await verifyDevice(identity.deviceId, {
        challenge_id: challenge.challenge_id,
        signature,
    });
    if (!proof?.verified || proof.device?.status !== 'active') {
        throw new Error('Сервер не подтвердил владение приватным ключом устройства.');
    }

    return {
        deviceId: identity.deviceId,
        created: Boolean(response.created),
        signingAlgorithm: 'Ed25519',
        encryptionAlgorithm: 'X25519',
        verified: true,
    };
}

/** Sign bytes with the non-extractable Ed25519 private key for this account. */
export async function signDeviceData(userId, data) {
    const identity = await readIdentity(userId);
    if (!isValidStoredIdentity(identity)) {
        throw new Error('Ключ подписи устройства ещё не создан.');
    }
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError('signDeviceData ожидает строку или Uint8Array.');
    }
    const signature = await crypto.subtle.sign('Ed25519', identity.signingKeyPair.privateKey, bytes);
    return toBase64(signature);
}

/** Verify a canonical Base64 Ed25519 signature using a supplied raw public key. */
export async function verifyPublicSignature(publicKeyBase64, data, signatureBase64) {
    const decode = (value, expectedLength, label) => {
        if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
            throw new Error(`${label}: неверный Base64.`);
        }
        const binary = atob(value);
        const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
        if (bytes.length !== expectedLength || toBase64(bytes) !== value) throw new Error(`${label}: неверная длина.`);
        return bytes;
    };
    const publicBytes = decode(publicKeyBase64, 32, 'Ed25519 public key');
    const signatureBytes = decode(signatureBase64, 64, 'Ed25519 signature');
    const publicKey = await crypto.subtle.importKey('raw', publicBytes, { name: 'Ed25519' }, false, ['verify']);
    const message = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    return crypto.subtle.verify('Ed25519', publicKey, signatureBytes, message);
}


/** Sign a canonical NODEX P2P handshake transcript with the device's non-exportable Ed25519 key. */
export async function signP2PHandshake(userId, transcript) {
    if (typeof transcript !== 'string' || transcript.length < 32 || transcript.length > 2048) {
        throw new TypeError('Некорректный transcript P2P handshake.');
    }
    return signDeviceData(userId, transcript);
}

/** Verify a canonical NODEX P2P handshake signature against an active device key. */
export async function verifyP2PHandshakeSignature(publicKeyBase64, transcript, signatureBase64) {
    if (typeof transcript !== 'string' || transcript.length < 32 || transcript.length > 2048) return false;
    return verifyPublicSignature(publicKeyBase64, transcript, signatureBase64);
}

/** Returns non-secret device metadata only; private keys are not returned. */
export async function getDeviceIdentityInfo(userId) {
    const identity = await readIdentity(userId);
    if (!isValidStoredIdentity(identity)) return null;
    return {
        deviceId: identity.deviceId || null,
        createdAt: identity.createdAt,
        registeredAt: identity.registeredAt || null,
        signingAlgorithm: 'Ed25519',
        encryptionAlgorithm: 'X25519',
    };
}


/**
 * Internal cryptographic identity handle for the Vault and device-pairing modules.
 * This returns non-extractable CryptoKey objects, never raw private key bytes.
 */
export async function getDeviceCryptoIdentity(userId) {
    const identity = await readIdentity(userId);
    if (!isValidStoredIdentity(identity) || !identity.deviceId) {
        throw new Error('Криптографическая идентичность устройства ещё не зарегистрирована.');
    }
    return {
        deviceId: identity.deviceId,
        publicKeyBase64: identity.publicKeyBase64,
        encryptionPublicKeyBase64: identity.encryptionPublicKeyBase64,
        signingKeyPair: identity.signingKeyPair,
        encryptionKeyPair: identity.encryptionKeyPair,
    };
}
