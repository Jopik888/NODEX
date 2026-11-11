import * as deviceCrypto from './crypto.js';
import * as authApi from './auth.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const VMK_BYTES = 32;

function toBase64(bytes) {
    let binary = '';
    for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
    return btoa(binary);
}
function fromBase64(value, expectedLength, fieldName) {
    if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
        throw new Error(`${fieldName}: некорректный Base64.`);
    }
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
    if (bytes.length !== expectedLength || toBase64(bytes) !== value) throw new Error(`${fieldName}: неверная длина.`);
    return bytes;
}
function toHex(bytes) {
    return [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join('');
}
function vmkAad(context) {
    const { userId, vaultId, deviceId, purpose, requestId = '' } = context;
    return textEncoder.encode([
        'SecureDisk-VMK-Envelope-v1',
        `user_id=${userId}`,
        `vault_id=${vaultId}`,
        `device_id=${deviceId}`,
        `purpose=${purpose}`,
        `request_id=${requestId}`,
    ].join('\n'));
}
function fileKeyAad(context) {
    return textEncoder.encode([
        'SecureDisk-Vault-File-Key-v1',
        `user_id=${context.userId}`,
        `vault_id=${context.vaultId}`,
        `cid=${context.cid}`,
    ].join('\n'));
}
async function deriveAesKey(sharedSecret, salt, info, usages) {
    const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info: textEncoder.encode(info) },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        usages,
    );
}
async function deriveSharedSecret(privateKey, peerPublicKeyBytes) {
    const publicKey = await crypto.subtle.importKey('raw', peerPublicKeyBytes, { name: 'X25519' }, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256));
}

export async function sealVmkForDevice(vmkInput, recipientPublicKeyBase64, context) {
    const vmk = new Uint8Array(vmkInput);
    if (vmk.length !== VMK_BYTES) throw new Error('VMK должен содержать ровно 32 байта.');
    const recipientPublic = fromBase64(recipientPublicKeyBase64, 32, 'X25519 public key');
    const ephemeral = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const shared = await deriveSharedSecret(ephemeral.privateKey, recipientPublic);
    try {
        const aesKey = await deriveAesKey(shared, salt, 'SecureDisk-VMK-Envelope-v1', ['encrypt']);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: vmkAad(context), tagLength: 128 },
            aesKey,
            vmk,
        ));
        return {
            ephemeral_public_key: toBase64(ephemeralPublic),
            salt: toBase64(salt),
            nonce: toBase64(nonce),
            ciphertext: toBase64(ciphertext),
        };
    } finally {
        shared.fill(0);
        vmk.fill(0);
    }
}

export async function openVmkEnvelopeWithPrivateKey(privateKey, envelope, context) {
    if (!envelope || (envelope.format_id && envelope.format_id !== 'vault-device-envelope-v1')) {
        throw new Error('Неизвестный формат конверта VMK.');
    }
    const ephemeral = fromBase64(envelope.ephemeral_public_key || envelope.key_derivation_params?.ephemeral_public_key, 32, 'ephemeral_public_key');
    const salt = fromBase64(envelope.salt, 16, 'salt');
    const nonce = fromBase64(envelope.nonce, 12, 'nonce');
    const ciphertext = fromBase64(envelope.ciphertext, 48, 'ciphertext');
    const shared = await deriveSharedSecret(privateKey, ephemeral);
    try {
        const aesKey = await deriveAesKey(shared, salt, 'SecureDisk-VMK-Envelope-v1', ['decrypt']);
        const raw = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: vmkAad(context), tagLength: 128 },
            aesKey,
            ciphertext,
        );
        const vmk = new Uint8Array(raw);
        if (vmk.length !== VMK_BYTES) throw new Error('Расшифрованный VMK имеет неверную длину.');
        return vmk;
    } finally {
        shared.fill(0);
    }
}

export async function openVmkEnvelope(userId, envelope, context) {
    const identity = await deviceCrypto.getDeviceCryptoIdentity(userId);
    if (identity.deviceId !== context.deviceId) throw new Error('Конверт предназначен для другого устройства.');
    return openVmkEnvelopeWithPrivateKey(identity.encryptionKeyPair.privateKey, envelope, context);
}

export async function wrapFileKey(vmkInput, context, keyString) {
    const vmk = new Uint8Array(vmkInput);
    if (vmk.length !== VMK_BYTES || typeof keyString !== 'string' || keyString.length > 512) {
        throw new Error('Некорректный VMK или ключ файла.');
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    try {
        const vmkKey = await crypto.subtle.importKey('raw', vmk, 'HKDF', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: textEncoder.encode('SecureDisk-Vault-File-Key-v1') },
            vmkKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt'],
        );
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: fileKeyAad(context), tagLength: 128 },
            key,
            textEncoder.encode(keyString),
        ));
        return {
            format_id: 'vault-file-key-v1',
            salt: toBase64(salt),
            nonce: toBase64(nonce),
            ciphertext: toBase64(ciphertext),
        };
    } finally {
        vmk.fill(0);
    }
}

export async function unwrapFileKey(vmkInput, context, envelope) {
    if (!envelope || envelope.format_id !== 'vault-file-key-v1') throw new Error('Неизвестный формат ключа Vault-файла.');
    const vmk = new Uint8Array(vmkInput);
    const salt = fromBase64(envelope.salt, 16, 'file salt');
    const nonce = fromBase64(envelope.nonce, 12, 'file nonce');
    if (typeof envelope.ciphertext !== 'string' || envelope.ciphertext.length > 1024) throw new Error('Некорректный file-key envelope.');
    const ciphertext = fromBase64(envelope.ciphertext, Math.floor(envelope.ciphertext.length * 3 / 4) - (envelope.ciphertext.endsWith('==') ? 2 : envelope.ciphertext.endsWith('=') ? 1 : 0), 'file ciphertext');
    try {
        const vmkKey = await crypto.subtle.importKey('raw', vmk, 'HKDF', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: textEncoder.encode('SecureDisk-Vault-File-Key-v1') },
            vmkKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt'],
        );
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: fileKeyAad(context), tagLength: 128 },
            key,
            ciphertext,
        );
        return textDecoder.decode(plaintext);
    } finally {
        vmk.fill(0);
    }
}

export async function pairingEnvelopeDigest(envelope) {
    const chunks = [
        fromBase64(envelope.ephemeral_public_key, 32, 'ephemeral_public_key'),
        fromBase64(envelope.salt, 16, 'salt'),
        fromBase64(envelope.nonce, 12, 'nonce'),
        fromBase64(envelope.ciphertext, 48, 'ciphertext'),
    ];
    const merged = new Uint8Array(chunks.reduce((sum, item) => sum + item.length, 0));
    let offset = 0;
    for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.length; }
    return toHex(await crypto.subtle.digest('SHA-256', merged));
}


export function buildVaultInitializationMessage(userId, deviceId, vaultId, digest) {
    return [
        'SecureDisk-Vault-Initialize-v1',
        `user_id=${userId}`,
        `device_id=${deviceId}`,
        `vault_id=${vaultId}`,
        `envelope_sha256=${digest}`,
    ].join('\n');
}
export function buildPairingRequestMessage({ requestId, pairingToken, deviceId, signingPublicKey, encryptionPublicKey, expiresAt }) {
    return [
        'SecureDisk-Pairing-Request-v1',
        `request_id=${requestId}`,
        `pairing_token=${pairingToken}`,
        `device_id=${deviceId}`,
        `signing_public_key=${signingPublicKey}`,
        `encryption_public_key=${encryptionPublicKey}`,
        `expires_at=${expiresAt}`,
    ].join('\n');
}

export function buildPairingApprovalMessage(requestId, sourceDeviceId, targetDeviceId, vaultId, digest) {
    return [
        'SecureDisk-Pairing-Approval-v1',
        `request_id=${requestId}`,
        `source_device_id=${sourceDeviceId}`,
        `target_device_id=${targetDeviceId}`,
        `vault_id=${vaultId}`,
        `envelope_sha256=${digest}`,
    ].join('\n');
}
export function buildPairingCompletionMessage(requestId, targetDeviceId, vaultId, digest) {
    return [
        'SecureDisk-Pairing-Complete-v1',
        `request_id=${requestId}`,
        `target_device_id=${targetDeviceId}`,
        `vault_id=${vaultId}`,
        `envelope_sha256=${digest}`,
    ].join('\n');
}

export async function unlockVaultForCurrentDevice(userId) {
    const identity = await deviceCrypto.getDeviceCryptoIdentity(userId);
    const status = await authApi.getVaultEnvelope();
    if (!status.initialized) {
        const vmk = crypto.getRandomValues(new Uint8Array(VMK_BYTES));
        const vaultId = crypto.randomUUID();
        try {
            const context = { userId, vaultId, deviceId: identity.deviceId, purpose: 'device-envelope' };
            const envelope = await sealVmkForDevice(vmk, identity.encryptionPublicKeyBase64, context);
            const digest = await pairingEnvelopeDigest(envelope);
            const initMessage = buildVaultInitializationMessage(userId, identity.deviceId, vaultId, digest);
            const signature = await deviceCrypto.signDeviceData(userId, initMessage);
            await authApi.initializeVault({ vault_id: vaultId, envelope, signature });
            return { vaultId, vmk, initialized: true };
        } catch (error) {
            vmk.fill(0);
            if (error.code !== 'VAULT_ALREADY_INITIALIZED') throw error;
            return unlockVaultForCurrentDevice(userId);
        }
    }
    if (!status.envelope) {
        const error = new Error('На этом устройстве ещё нет ключа Сейфа. Подключите его через QR-код с другого доверенного устройства.');
        error.code = 'VAULT_PAIRING_REQUIRED';
        error.vaultId = status.vault_id;
        throw error;
    }
    const params = status.envelope.key_derivation_params || {};
    if (params.hkdf_info !== 'SecureDisk-VMK-Envelope-v1') throw new Error('Неверные параметры конверта VMK.');
    const context = {
        userId, vaultId: status.vault_id, deviceId: identity.deviceId,
        purpose: params.purpose || 'device-envelope', requestId: params.request_id || '',
    };
    const vmk = await openVmkEnvelope(userId, {
        ...status.envelope,
        ephemeral_public_key: params.ephemeral_public_key,
    }, context);
    return { vaultId: status.vault_id, vmk, initialized: false };
}

export async function migrateLegacyVaultFileKeys(vmk, userId, vaultId, files) {
    let changed = false;
    const migrated = [];
    for (const file of files) {
        if (file?.vaultKeyEnvelope?.format_id === 'vault-file-key-v1') {
            if (Object.prototype.hasOwnProperty.call(file, 'key')) {
                const { key: _discardedLegacyKey, ...safeFile } = file;
                migrated.push(safeFile);
                changed = true;
            } else {
                migrated.push(file);
            }
            continue;
        }
        if (typeof file?.key !== 'string' || typeof file?.cid !== 'string') {
            if (file && Object.prototype.hasOwnProperty.call(file, 'key')) {
                const { key: _discardedUnusableKey, ...safeFile } = file;
                migrated.push(safeFile);
                changed = true;
            } else {
                migrated.push(file);
            }
            continue;
        }
        const envelope = await wrapFileKey(vmk, { userId, vaultId, cid: file.cid }, file.key);
        const { key, ...safeFile } = file;
        migrated.push({ ...safeFile, vaultCryptoVersion: 1, vaultKeyEnvelope: envelope });
        changed = true;
    }
    return { files: migrated, changed };
}

export async function unwrapVaultFileKey(vmk, userId, vaultId, file) {
    if (file?.vaultKeyEnvelope?.format_id === 'vault-file-key-v1') {
        return unwrapFileKey(vmk, { userId, vaultId, cid: file.cid }, file.vaultKeyEnvelope);
    }
    // During first migration pass old v0.3 files remain decryptable.
    if (typeof file?.key === 'string') return file.key;
    throw new Error('Для этого файла не найден защищённый ключ.');
}
