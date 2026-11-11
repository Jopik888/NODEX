import {
    IPFS_API, isNativeClient, isServerConfigured, getSavedServerUrl,
    normalizeServerOrigin, setServerConfig,
} from './config.js';
import { joinRoom } from 'https://esm.sh/@trystero-p2p/mqtt@0.26.0';
import { selfId } from 'https://esm.sh/@trystero-p2p/core@0.26.0';
import { performP2PHandshake } from './p2p-handshake.js';
import * as authApi from './auth.js';
import * as deviceCrypto from './crypto.js';
import * as vaultCrypto from './vault-crypto.js';
import JSZip from 'https://esm.sh/jszip@3.10.2';
import {
    isFolderRecord, normalizeDriveName, driveItemKey, getDriveChildren, getDriveFolderPath,
    getDescendantFolderIds, collectFolderContents, canMoveFolder, getRelativePath, getRelativeFolderPath,
    isSafeArchivePath, listArchiveChildren, buildFolderUploadPlan, buildIncomingFolderMergePlan,
} from './file-manager-core.js';

const CHUNK_SIZE = 5 * 1024 * 1024;
const LARGE_FILE_THRESHOLD = 50 * 1024 * 1024;
const MAX_ZIP_SIZE = 100 * 1024 * 1024;

async function ipfsRequestHeaders() {
    if (!isNativeClient()) return {};
    const token = await authApi.getCsrfToken({ force: true });
    return { 'X-CSRF-Token': token };
}


let myFiles = [], vaultFiles = [], currentProfile = '', syncRoomId = '', authenticatedUser = null, isVaultUnlocked = false, currentDeviceHasVaultAccess = false;
let vaultMasterKey = null, vaultId = null, activePairingInvite = null, claimedPairingInvite = null, pairingScanner = null, pairingPollCancelled = false;
// Legacy v0.3 Vault keys received from peers are held only in memory until wrapped by VMK.
const pendingLegacyVaultKeys = new Map();
let selectedMyFiles = new Set(), selectedVaultFiles = new Set();
let myDriveCurrentFolderId = null, driveViewMode = 'grid', zipViewerState = null;
let localPinsCache = null;
let room = null;
let p2pRoomIdentity = null;
let deviceCryptoInitPromise = null;
let deviceCryptoGeneration = 0;
let handlingSessionDeviceConflict = false;
let sendSyncData, sendRequestSync, sendNewFile;
let p2pDeviceVerified = false, localDeviceId = null, localDeviceCryptoIdentity = null;
let trustRefreshTimer = null, trustedKeysRefreshPromise = null, trustedKeysLastRefreshedAt = 0;
const trustedDeviceKeys = new Map();
const trustedPeers = new Map();
const quarantinedPeerIds = new Set();
const P2P_TRUST_REFRESH_MS = 60_000;
const P2P_HANDSHAKE_TIMEOUT_MS = 20_000;
const DEVICE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ALPHABET_MAP = {}; for (let i = 0; i < ALPHABET.length; i++) ALPHABET_MAP[ALPHABET.charAt(i)] = i;
function encodeBase58(buffer) { let digits = [0]; for (let i = 0; i < buffer.length; i++) { let carry = buffer[i]; for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; } while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; } } let string = ''; for (let i = 0; i < buffer.length && buffer[i] === 0; i++) string += ALPHABET[0]; for (let i = digits.length - 1; i >= 0; i--) string += ALPHABET[digits[i]]; return string; }
function decodeBase58(string) { if (string.length === 0) return new Uint8Array(0); let leadingZeros = 0; while (string.charAt(leadingZeros) === ALPHABET[0]) leadingZeros++; const clean = string.slice(leadingZeros), bytes = []; for (let i = 0; i < clean.length; i++) { let value = ALPHABET_MAP[clean.charAt(i)]; if (value === undefined) throw new Error('Invalid Base58'); let carry = value; for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; } while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; } } const result = new Uint8Array(leadingZeros + bytes.length), reversed = bytes.slice().reverse(); for (let i = 0; i < reversed.length; i++) result[leadingZeros + i] = reversed[i]; return result; }

async function deriveAesKeyAndIv(masterKeyBytes, saltBytes, infoStr, usage) { const hkdfKey = await crypto.subtle.importKey('raw', masterKeyBytes, { name: 'HKDF' }, false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: new TextEncoder().encode(infoStr) }, hkdfKey, 44 * 8); const material = new Uint8Array(bits); const key = await crypto.subtle.importKey('raw', material.slice(0, 32), { name: 'AES-GCM' }, false, usage); return { key, iv: material.slice(32, 44) }; }
async function sha256Hex(bytes) { const buf = await crypto.subtle.digest('SHA-256', bytes); return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); }
async function hashPin(pin) { const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('vault::' + pin + '::' + currentProfile)); return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); }

function applyTheme(theme) {
    const selected = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.dataset.theme = selected;
    localStorage.setItem('secureDiskTheme', selected);
    const button = document.getElementById('settingsThemeToggleBtn');
    if (button) {
        button.textContent = selected === 'dark' ? '☀️ Светлая тема' : '🌙 Тёмная тема';
        button.setAttribute('aria-label', selected === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему');
        button.title = selected === 'dark' ? 'Переключить на светлую тему' : 'Переключить на тёмную тему';
    }
}

applyTheme(localStorage.getItem('secureDiskTheme') || 'dark');
document.getElementById('settingsThemeToggleBtn')?.addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});
function loadProfileMeta(key) { try { const raw = localStorage.getItem(`secureDiskMeta_${key}`); if (!raw) return { displayName: '', avatarCid: null }; const p = JSON.parse(raw); return { displayName: p.displayName || '', avatarCid: p.avatarCid || null }; } catch (e) { return { displayName: '', avatarCid: null }; } }
function saveProfileMeta(key, meta) { localStorage.setItem(`secureDiskMeta_${key}`, JSON.stringify(meta)); }
const avatarCache = new Map();
async function getAvatarUrl(cid) { if (!cid) return null; if (avatarCache.has(cid)) return avatarCache.get(cid); try { const buf = await fetchFromIPFS(cid); const url = URL.createObjectURL(new Blob([buf], { type: 'image/jpeg' })); avatarCache.set(cid, url); return url; } catch (e) { return null; } }

function uploadBufferToIPFS(buffer, onProgress) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest(); xhr.open('POST', `${IPFS_API}/add?pin=true`); xhr.withCredentials = true; xhr.timeout = 120000;
        xhr.upload.onprogress = (e) => { if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100)); };
        xhr.onload = () => { xhr.status === 200 ? resolve(JSON.parse(xhr.responseText).Hash) : reject(new Error('IPFS: ' + xhr.status)); };
        xhr.ontimeout = () => reject(new Error('Таймаут при загрузке')); xhr.onerror = () => reject(new Error('Сетевая ошибка'));
        const fd = new FormData(); fd.append('file', new Blob([buffer]), 'data.enc'); void ipfsRequestHeaders().then(headers => { for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value); xhr.send(fd); }).catch(reject);
    });
}
function fetchFromIPFS(cid, onProgress, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest(); xhr.open('POST', `${IPFS_API}/cat?arg=${encodeURIComponent(cid)}`); xhr.withCredentials = true; xhr.responseType = 'arraybuffer'; xhr.timeout = timeoutMs;
        if (onProgress) xhr.onprogress = (e) => { if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100)); };
        xhr.onload = () => { xhr.status === 200 ? resolve(xhr.response) : reject(new Error('IPFS cat: ' + xhr.status)); };
        xhr.ontimeout = () => reject(new Error('Таймаут')); xhr.onerror = () => reject(new Error('Сеть'));
        void ipfsRequestHeaders().then(headers => { for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value); xhr.send(); }).catch(reject);
    });
}
async function pinCidLocally(cid, timeoutMs = 30000) { const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeoutMs); try { const headers = await ipfsRequestHeaders(); const res = await fetch(`${IPFS_API}/pin/add?arg=${encodeURIComponent(cid)}`, { method: 'POST', headers, credentials: 'include', signal: controller.signal }); return res.ok; } catch (e) { return false; } finally { clearTimeout(timer); } }

function setSyncStatus(text, isError = false) {
    const el = document.getElementById('syncStatus'); if (!el) return;
    el.textContent = text; el.style.color = isError ? '#ef4444' : '#10b981';
    if (text) setTimeout(() => { if (el.textContent === text) el.textContent = ''; }, 3500);
}

function getDeletedCids() {
    try {
        const stored = JSON.parse(localStorage.getItem(`secureDiskDeleted_${currentProfile}`) || '[]');
        return Array.isArray(stored) ? stored.filter(cid => typeof cid === 'string') : [];
    } catch (_) {
        return [];
    }
}

function markDeletedCids(cids) {
    if (!currentProfile || !Array.isArray(cids) || !cids.length) return;
    const deleted = new Set(getDeletedCids());
    cids.filter(cid => typeof cid === 'string' && cid).forEach(cid => deleted.add(cid));
    localStorage.setItem(`secureDiskDeleted_${currentProfile}`, JSON.stringify([...deleted]));
}

function getDeletedFolderIds() {
    try {
        const stored = JSON.parse(localStorage.getItem(`secureDiskDeletedFolders_${currentProfile}`) || '[]');
        return Array.isArray(stored) ? stored.filter(id => typeof id === 'string') : [];
    } catch (_) { return []; }
}

function markDeletedFolderIds(ids) {
    if (!currentProfile || !Array.isArray(ids) || !ids.length) return;
    const deleted = new Set(getDeletedFolderIds());
    ids.filter(id => typeof id === 'string' && id).forEach(id => deleted.add(id));
    localStorage.setItem(`secureDiskDeletedFolders_${currentProfile}`, JSON.stringify([...deleted]));
}

function applyDeletedFolderIds(ids) {
    if (!Array.isArray(ids) || !ids.length) return false;
    markDeletedFolderIds(ids);
    const deleted = new Set(ids);
    const before = myFiles.length;
    myFiles = myFiles.filter(item => !isFolderRecord(item) || !deleted.has(item.id));
    return myFiles.length !== before;
}

function applyDeletedCids(cids) {
    if (!Array.isArray(cids) || !cids.length) return { changedMy: false, changedVault: false };
    markDeletedCids(cids);
    const deleted = new Set(cids);
    const beforeMy = myFiles.length, beforeVault = vaultFiles.length;
    myFiles = myFiles.filter(file => !deleted.has(file.cid));
    vaultFiles = vaultFiles.filter(file => !deleted.has(file.cid));
    return {
        changedMy: myFiles.length !== beforeMy,
        changedVault: vaultFiles.length !== beforeVault
    };
}

function createSyncSnapshot() {
    return {
        version: 1,
        myFiles: myFiles.map(file => ({ ...file })),
        // Never propagate a legacy plaintext file key through a fresh v0.4 snapshot.
        vaultFiles: vaultFiles.map(({ key, ...file }) => ({ ...file })),
        meta: loadProfileMeta(currentProfile),
        deletedCids: getDeletedCids(),
        deletedFolderIds: getDeletedFolderIds(),
        sentAt: Date.now()
    };
}

function sendSyncSnapshot(targetPeerId) {
    if (!sendSyncData || !p2pDeviceVerified) return;
    const targets = targetPeerId ? [targetPeerId] : [...trustedPeers.keys()];
    const snapshot = createSyncSnapshot();
    for (const peerId of targets) {
        if (!trustedPeers.has(peerId) || quarantinedPeerIds.has(peerId)) continue;
        sendSyncData.send(snapshot, { target: peerId }).catch(error => {
            console.warn('Не удалось отправить снимок синхронизации:', peerId, error);
            setSyncStatus('Ошибка отправки синхронизации', true);
        });
    }
}

async function protectIncomingVaultMetadata(file) {
    const safeFile = { ...file };
    const hasValidEnvelope = safeFile.vaultKeyEnvelope?.format_id === 'vault-file-key-v1';
    const legacyKey = !hasValidEnvelope && typeof safeFile.key === 'string' ? safeFile.key : null;
    // Vault keys are never persisted or forwarded in the plaintext `key` field,
    // including malformed peers that send both a valid envelope and a raw key.
    delete safeFile.key;
    if (legacyKey && typeof safeFile.cid === 'string' && safeFile.cid) {
        if (vaultMasterKey && vaultId && isVaultUnlocked) {
            safeFile.vaultKeyEnvelope = await vaultCrypto.wrapFileKey(vaultMasterKey, {
                userId: authenticatedUser.id, vaultId, cid: safeFile.cid,
            }, legacyKey);
            safeFile.vaultCryptoVersion = 1;
            pendingLegacyVaultKeys.delete(safeFile.cid);
        } else {
            pendingLegacyVaultKeys.set(safeFile.cid, legacyKey);
        }
    }
    return safeFile;
}

async function mergeSyncedFiles(target, incoming, isVault = false) {
    if (!Array.isArray(incoming)) return false;
    let changed = false;

    if (!isVault) {
        const validFolders = buildIncomingFolderMergePlan(target, incoming.filter(isFolderRecord), getDeletedFolderIds());
        for (const folder of validFolders) {
            const index = target.findIndex(item => isFolderRecord(item) && item.id === folder.id);
            if (index < 0) {
                target.push(folder);
                changed = true;
            } else {
                const existing = target[index];
                const incomingTime = Date.parse(folder.updatedAt || folder.createdAt || '') || 0;
                const existingTime = Date.parse(existing.updatedAt || existing.createdAt || '') || 0;
                if (incomingTime > existingTime) {
                    target[index] = folder;
                    changed = true;
                }
            }
        }
    }

    for (const originalItem of incoming) {
        if (!originalItem || typeof originalItem.name !== 'string' || (!isVault && isFolderRecord(originalItem))) continue;
        if (typeof originalItem.cid !== 'string' || !originalItem.cid) continue;
        if (getDeletedCids().includes(originalItem.cid)) continue;

        let file;
        if (isVault) {
            file = await protectIncomingVaultMetadata(originalItem);
        } else {
            let safeName;
            try { safeName = normalizeDriveName(originalItem.name, 'Имя файла'); } catch (_) { continue; }
            const parentId = originalItem.parentId || null;
            const acceptedFolderIds = new Set(target.filter(isFolderRecord).map(item => item.id));
            if (parentId && !acceptedFolderIds.has(parentId)) continue;
            file = { ...originalItem, name: safeName, type: 'file', parentId };
        }

        const existingIndex = target.findIndex(item => item.cid === file.cid);
        if (existingIndex === -1) {
            target.push({ ...file, isImported: true });
            changed = true;
            continue;
        }

        const existing = target[existingIndex];
        let safeExisting = existing;
        if (isVault && typeof existing.key === 'string' && existing.vaultKeyEnvelope?.format_id !== 'vault-file-key-v1') {
            pendingLegacyVaultKeys.set(existing.cid, existing.key);
            safeExisting = { ...existing };
            delete safeExisting.key;
        }
        const incomingTime = Date.parse(file.updatedAt || '') || 0;
        const existingTime = Date.parse(existing.updatedAt || '') || 0;
        const merged = incomingTime > existingTime ? { ...safeExisting, ...file } : { ...file, ...safeExisting };
        for (const [key, value] of Object.entries(file)) {
            if ((merged[key] === undefined || merged[key] === null || merged[key] === '') &&
                value !== undefined && value !== null && value !== '') merged[key] = value;
        }
        if (isVault) delete merged.key;
        if (JSON.stringify(existing) !== JSON.stringify(merged)) {
            target[existingIndex] = merged;
            changed = true;
        }
    }
    return changed;
}

function closePeerTransport(peerId) {
    try {
        const peers = room?.getPeers?.();
        const connection = peers instanceof Map ? peers.get(peerId) : peers?.[peerId];
        if (connection && typeof connection.close === 'function') connection.close();
    } catch (error) {
        console.warn('Не удалось закрыть WebRTC-соединение отозванного пира:', peerId, error);
    }
}

function quarantinePeer(peerId, reason = 'P2P peer failed trust verification') {
    trustedPeers.delete(peerId);
    quarantinedPeerIds.add(peerId);
    closePeerTransport(peerId);
    console.warn(reason, peerId);
}

async function getTrustedPublicKey(deviceId) {
    let publicKey = trustedDeviceKeys.get(deviceId);
    if (publicKey) return publicKey;
    // A device may have been approved since the last 60-second refresh.
    await refreshTrustedDeviceKeys();
    publicKey = trustedDeviceKeys.get(deviceId);
    return publicKey || null;
}

/** Trystero callback: the peer is not admitted until this function resolves. */
async function authenticateTrysteroPeer(peerId, send, receive, isInitiator) {
    if (!p2pDeviceVerified || !localDeviceId || !localDeviceCryptoIdentity || quarantinedPeerIds.has(peerId)) {
        throw new Error('P2P admission denied: local device is not authorized.');
    }
    const handshakeUserId = authenticatedUser?.id;
    const handshakeDeviceId = localDeviceId;
    const handshakeRoomId = syncRoomId;
    if (!handshakeUserId || !handshakeRoomId) {
        throw new Error('P2P admission denied: missing account or room context.');
    }
    // Refresh on every new peer admission, not only on the 60-second timer.
    // This prevents a recently revoked/re-keyed device from using a stale cache
    // to begin a fresh handshake.
    try {
        await refreshTrustedDeviceKeys();
    } catch (error) {
        disableP2P('Не удалось обновить список доверия перед P2P handshake. P2P закрыт.');
        throw error;
    }
    if (!p2pDeviceVerified || authenticatedUser?.id !== handshakeUserId ||
        localDeviceId !== handshakeDeviceId || syncRoomId !== handshakeRoomId) {
        throw new Error('P2P admission denied: local session changed during handshake.');
    }
    const roomContext = await sha256Hex(new TextEncoder().encode(handshakeRoomId));

    const peerIdentity = await performP2PHandshake({
        peerId,
        selfId,
        deviceId: handshakeDeviceId,
        userId: handshakeUserId,
        roomContext,
        isInitiator,
        send,
        receive,
        getTrustedPublicKey,
        sign: transcript => deviceCrypto.signP2PHandshake(handshakeUserId, transcript),
        verify: (publicKey, transcript, signature) =>
            deviceCrypto.verifyP2PHandshakeSignature(publicKey, transcript, signature),
    });

    // Close the approval/revocation race that could occur while the handshake ran.
    try {
        await refreshTrustedDeviceKeys();
    } catch (error) {
        disableP2P('Не удалось повторно подтвердить доверие после P2P handshake. P2P закрыт.');
        throw error;
    }

    if (!p2pDeviceVerified || authenticatedUser?.id !== handshakeUserId ||
        localDeviceId !== handshakeDeviceId || syncRoomId !== handshakeRoomId) {
        throw new Error('P2P admission denied: local authorization changed during handshake.');
    }
    if (trustedDeviceKeys.get(peerIdentity.deviceId) !== peerIdentity.publicKey) {
        throw new Error('P2P admission denied: peer was revoked or re-keyed during handshake.');
    }
    // Admission to Trystero succeeds only after both signatures and the latest local trust set agree.
    trustedPeers.set(peerId, peerIdentity);
    quarantinedPeerIds.delete(peerId);
    return true;
}

async function refreshTrustedDeviceKeys() {
    const userId = authenticatedUser?.id;
    const deviceId = localDeviceId;
    const ownPublicKey = localDeviceCryptoIdentity?.publicKeyBase64;
    if (!userId || !deviceId || !ownPublicKey) throw new Error('Локальное устройство ещё не подтверждено.');
    if (trustedKeysRefreshPromise) return trustedKeysRefreshPromise;
    const refreshTask = (async () => {
        const payload = await authApi.getTrustedDeviceKeys();
        // Do not let a late response from a previous login overwrite another account's trust set.
        if (authenticatedUser?.id !== userId || localDeviceId !== deviceId ||
            localDeviceCryptoIdentity?.publicKeyBase64 !== ownPublicKey) {
            throw new Error('Сессия изменилась во время обновления списка доверенных устройств.');
        }
        if (payload?.version !== 1 || payload?.algorithm !== 'Ed25519' ||
            !payload?.trusted_keys || typeof payload.trusted_keys !== 'object' || Array.isArray(payload.trusted_keys)) {
            throw new Error('Backend вернул некорректный список доверенных устройств или неподдерживаемую версию протокола.');
        }
        const nextKeys = new Map();
        for (const [trustedId, publicKey] of Object.entries(payload.trusted_keys)) {
            if (DEVICE_ID_PATTERN.test(trustedId) && typeof publicKey === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(publicKey)) {
                nextKeys.set(trustedId, publicKey);
            }
        }
        if (!nextKeys.has(deviceId) || nextKeys.get(deviceId) !== ownPublicKey) {
            throw new Error('Backend больше не подтверждает текущее устройство. P2P отключён.');
        }
        trustedDeviceKeys.clear();
        for (const [id, key] of nextKeys) trustedDeviceKeys.set(id, key);
        for (const [peerId, peer] of trustedPeers) {
            if (trustedDeviceKeys.get(peer.deviceId) !== peer.publicKey) {
                quarantinePeer(peerId, 'Устройство отозвано или его ключ изменился; пир заблокирован');
            }
        }
        trustedKeysLastRefreshedAt = Date.now();
        return nextKeys;
    })();
    trustedKeysRefreshPromise = refreshTask;
    try { return await refreshTask; }
    finally { if (trustedKeysRefreshPromise === refreshTask) trustedKeysRefreshPromise = null; }
}

function disableP2P(reason) {
    p2pDeviceVerified = false;
    trustedKeysLastRefreshedAt = 0;
    trustedPeers.clear();
    trustedDeviceKeys.clear();
    quarantinedPeerIds.clear();
    if (room) {
        try { void room.leave(); } catch (error) { console.warn('Ошибка закрытия P2P-комнаты:', error); }
        room = null;
    }
    p2pRoomIdentity = null;
    sendSyncData = sendRequestSync = sendNewFile = null;
    setSyncStatus(reason || 'P2P временно отключён: не удалось подтвердить список устройств', true);
}

function startTrustedDeviceRefreshLoop() {
    if (trustRefreshTimer) clearInterval(trustRefreshTimer);
    trustRefreshTimer = setInterval(async () => {
        try {
            await refreshTrustedDeviceKeys();
            if (!p2pDeviceVerified && authenticatedUser?.id && syncRoomId && localDeviceId) {
                p2pDeviceVerified = true;
            }
            if (p2pDeviceVerified && authenticatedUser?.id && syncRoomId && localDeviceId &&
                (!room || p2pRoomIdentity !== syncRoomId || !sendRequestSync)) {
                initWebRTC(syncRoomId);
            }
        } catch (error) {
            console.warn('Не удалось обновить список доверенных устройств:', error);
            disableP2P('Не удалось подтвердить актуальность устройств. P2P закрыт до восстановления проверки.');
        }
    }, P2P_TRUST_REFRESH_MS);
}

function initWebRTC(roomIdentity) {
    if (!p2pDeviceVerified || !localDeviceId) {
        throw new Error('Устройство ещё не прошло криптографическую проверку.');
    }
    if (typeof roomIdentity !== 'string' || !roomIdentity.trim()) {
        throw new Error('Backend не предоставил sync_room_id.');
    }

    // Повторный вызов для уже работающей комнаты не должен создавать новый P2P-сеанс.
    if (room && p2pRoomIdentity === roomIdentity && sendRequestSync && sendSyncData && sendNewFile) {
        return true;
    }

    try {
        if (room) {
            try { void room.leave(); } catch (_) {}
            room = null;
        }
        p2pRoomIdentity = null;
        sendSyncData = sendRequestSync = sendNewFile = null;

        setSyncStatus('Поиск доверенных устройств P2P…');
        room = joinRoom(
            { appId: 'cloud-p2p-storage-v1' },
            roomIdentity,
            {
                onJoinError: ({ peerId, error }) => {
                    console.warn('P2P admission/connection error:', peerId, error);
                    setSyncStatus('Устройство не прошло проверку или P2P-соединение недоступно', true);
                },
                onPeerHandshake: authenticateTrysteroPeer,
                handshakeTimeoutMs: P2P_HANDSHAKE_TIMEOUT_MS,
            }
        );

        sendSyncData = room.makeAction('sync-data');
        sendRequestSync = room.makeAction('req-sync');
        sendNewFile = room.makeAction('new-file');
        p2pRoomIdentity = roomIdentity;

        room.onPeerJoin = peerId => {
            if (!p2pDeviceVerified || !trustedPeers.has(peerId) || quarantinedPeerIds.has(peerId)) return;
            console.log('P2P admission accepted for trusted device:', trustedPeers.get(peerId).deviceId);
            setSyncStatus('Доверенное устройство найдено. Синхронизация…');
            sendRequestSync.send({ profile: currentProfile, version: 1 }, { target: peerId })
                .catch(error => console.warn('Ошибка запроса синхронизации:', peerId, error));
        };

        room.onPeerLeave = peerId => {
            const wasTrusted = trustedPeers.delete(peerId);
            quarantinedPeerIds.delete(peerId);
            console.log('P2P peer disconnected:', peerId);
            if (wasTrusted) setSyncStatus('Доверенное устройство отключилось');
        };

        sendRequestSync.onMessage = (_data, { peerId }) => {
            if (!p2pDeviceVerified || !trustedPeers.has(peerId) || quarantinedPeerIds.has(peerId)) return;
            sendSyncSnapshot(peerId);
        };

        sendSyncData.onMessage = async (data, { peerId }) => {
            if (!p2pDeviceVerified || !trustedPeers.has(peerId) || quarantinedPeerIds.has(peerId)) return;
            if (!data || typeof data !== 'object' || data.version !== 1) return;

            const tombstoneChanges = applyDeletedCids(data.deletedCids);
            const changedFolders = applyDeletedFolderIds(data.deletedFolderIds);
            const changedMy = await mergeSyncedFiles(myFiles, data.myFiles, false) || tombstoneChanges.changedMy || changedFolders;
            const changedVault = await mergeSyncedFiles(vaultFiles, data.vaultFiles, true) || tombstoneChanges.changedVault;

            if (changedMy) saveFiles(false);
            if (changedVault) saveVaultFiles(false);

            if (data.meta && typeof data.meta === 'object') {
                const currentMeta = loadProfileMeta(currentProfile);
                const mergedMeta = {
                    displayName: currentMeta.displayName || data.meta.displayName || '',
                    avatarCid: currentMeta.avatarCid || data.meta.avatarCid || null
                };
                if (JSON.stringify(currentMeta) !== JSON.stringify(mergedMeta)) {
                    saveProfileMeta(currentProfile, mergedMeta);
                    refreshProfileUI();
                }
            }

            setSyncStatus(
                changedMy || changedVault
                    ? 'Синхронизация завершена'
                    : `Связь с устройством ${String(peerId).slice(0, 6)} установлена`
            );
        };

        sendNewFile.onMessage = (data, { peerId }) => {
            if (!p2pDeviceVerified || !trustedPeers.has(peerId) || quarantinedPeerIds.has(peerId)) return;
            if (data && data.file && data.file.cid) {
                void handleIncomingFile(data.file, Boolean(data.isVault)).catch(error => console.warn('Не удалось импортировать файл из P2P:', error));
            }
        };
    } catch (error) {
        console.error('Не удалось запустить P2P:', error);
        room = null;
        p2pRoomIdentity = null;
        sendSyncData = sendRequestSync = sendNewFile = null;
        setSyncStatus('Ошибка запуска P2P: ' + (error.message || 'неизвестная ошибка'), true);
        return false;
    }
    return true;
}

function broadcastNewFile(fileObj, isVault) {
    if (!sendNewFile || !fileObj || !p2pDeviceVerified) return;
    const safeFile = isVault ? (({ key, ...rest }) => rest)(fileObj) : fileObj;
    for (const peerId of trustedPeers.keys()) {
        if (quarantinedPeerIds.has(peerId)) continue;
        sendNewFile.send({ file: safeFile, isVault: Boolean(isVault) }, { target: peerId }).catch(error => {
            console.warn('Не удалось передать метаданные файла:', peerId, error);
        });
    }
}

async function handleIncomingFile(file, isVault) {
    if (!file || !file.cid || getDeletedCids().includes(file.cid)) return;
    const targetArray = isVault ? vaultFiles : myFiles;
    const safeFile = isVault ? await protectIncomingVaultMetadata(file) : { ...file };
    if (!targetArray.find(f => f.cid === file.cid)) { targetArray.push({ ...safeFile, isImported: true }); if (isVault) saveVaultFiles(false); else saveFiles(false); }
    const chunksToPin = [file.cid, ...(file.chunkCids || [])];
    (async () => {
        for (const c of chunksToPin) await pinCidLocally(c, 10000);
        localPinsCache = null;
        if (isVault) {
            if (isVaultUnlocked) renderVaultFiles();
        } else {
            renderFiles();
        }
    })();
}

function setAuthMessage(message = '', isError = false) {
    const el = document.getElementById('authMessage');
    if (!el) return;
    el.textContent = message;
    el.classList.toggle('is-error', Boolean(isError));
    el.classList.toggle('is-success', Boolean(message) && !isError);
}

function switchAuthTab(tabName) {
    document.querySelectorAll('.auth-tab').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === tabName));
    document.querySelectorAll('.auth-tab-content').forEach(panel => panel.classList.toggle('active', panel.id === `tab-${tabName}`));
}

function setAuthBusy(button, busy, busyLabel = 'Выполняется…') {
    if (!button) return;
    if (busy) {
        button.dataset.originalText = button.textContent;
        button.textContent = busyLabel;
        button.disabled = true;
    } else {
        button.textContent = button.dataset.originalText || button.textContent;
        button.disabled = false;
        delete button.dataset.originalText;
    }
}

function readableAuthError(error) {
    const known = {
        INVALID_CREDENTIALS: 'Неверный email или пароль.',
        EMAIL_NOT_VERIFIED: 'Сначала подтвердите адрес электронной почты.',
        EMAIL_ALREADY_REGISTERED: 'Этот email уже зарегистрирован. Попробуйте войти.',
        TOTP_LOGIN_NOT_IMPLEMENTED: 'Для аккаунта включена двухфакторная TOTP-аутентификация. Её вход ещё не реализован в backend v0.1.',
        VALIDATION_ERROR: 'Проверьте введённые данные. Пароль при регистрации должен содержать не менее 12 символов.',
        NETWORK_ERROR: error.message,
        RATE_LIMITED: 'Слишком много запросов. Попробуйте позже.',
        LOGIN_RATE_LIMITED: 'Слишком много попыток входа. Попробуйте позже.',
        REGISTER_RATE_LIMITED: 'Слишком много попыток регистрации. Попробуйте позже.',
        VERIFY_RATE_LIMITED: 'Слишком много попыток подтверждения. Попробуйте позже.',
        RESEND_RATE_LIMITED: 'Слишком часто запрашивается повторное письмо. Попробуйте позже.',
    };
    return known[error?.code] || (error?.status === 429 ? 'Слишком много запросов. Попробуйте позже.' : '') || error?.message || 'Неизвестная ошибка авторизации.';
}

function profileHasLocalData(profileId) {
    if (!profileId) return false;
    return ['secureDiskFiles_', 'secureDiskVault_', 'secureDiskMeta_', 'secureDiskDeleted_', 'vaultPin_', 'pinataJwt_']
        .some(prefix => localStorage.getItem(`${prefix}${profileId}`) !== null);
}

function resolveLocalProfileForUser(user) {
    if (!user?.id) throw new Error('Backend не вернул user.id.');

    const mappingKey = `secureDiskLocalProfile_${user.id}`;
    const mappedProfile = localStorage.getItem(mappingKey);
    if (mappedProfile && (!localStorage.getItem(`secureDiskProfileOwner_${mappedProfile}`)
        || localStorage.getItem(`secureDiskProfileOwner_${mappedProfile}`) === user.id)) {
        localStorage.setItem(`secureDiskProfileOwner_${mappedProfile}`, user.id);
        localStorage.setItem('activeProfile', mappedProfile);
        localStorage.removeItem('sessionActive');
        return mappedProfile;
    }

    // Migrate the old local profile only after explicit confirmation. Its data
    // remains under the original localStorage keys; it is never renamed/deleted.
    const legacyProfile = localStorage.getItem('activeProfile');
    const legacyOwner = legacyProfile ? localStorage.getItem(`secureDiskProfileOwner_${legacyProfile}`) : null;
    const canOfferLegacy = legacyProfile && profileHasLocalData(legacyProfile)
        && (!legacyOwner || legacyOwner === user.id);
    let localProfile = '';

    if (canOfferLegacy && confirm(
        'На этом устройстве найдены данные старого локального профиля.\n\n' +
        'Привязать их к аккаунту ' + user.email + '?\n' +
        'Файлы останутся на этом устройстве. Для синхронизации других устройств им также потребуется войти в этот аккаунт.'
    )) {
        localProfile = legacyProfile;
    } else {
        localProfile = crypto.randomUUID ? crypto.randomUUID() : `local-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    }

    localStorage.setItem(mappingKey, localProfile);
    localStorage.setItem(`secureDiskProfileOwner_${localProfile}`, user.id);
    localStorage.setItem('activeProfile', localProfile);
    localStorage.removeItem('sessionActive');
    return localProfile;
}

function isSessionDeviceConflict(error) {
    const code = String(error?.code || error?.details?.code || '').toUpperCase();
    const message = [
        error?.message,
        error?.details?.message,
        error?.details?.error,
    ].filter(Boolean).join(' ');
    return code === 'SESSION_DEVICE_CONFLICT' || /bound to another device/i.test(message);
}

async function handleSessionDeviceConflict(error, userId, generation) {
    if (!isSessionDeviceConflict(error) || handlingSessionDeviceConflict) return false;
    if (authenticatedUser?.id !== userId || generation !== deviceCryptoGeneration) return true;

    handlingSessionDeviceConflict = true;
    console.warn('Сессия привязана к другому ключу устройства; требуется повторный вход.', error);

    let logoutConfirmed = false;
    try {
        await authApi.logout();
        logoutConfirmed = true;
    } catch (logoutError) {
        // Локальное состояние всё равно очищаем. Серверную cookie нельзя
        // гарантированно отозвать без успешного ответа logout.
        console.error('Не удалось подтвердить выход на сервере после SESSION_DEVICE_CONFLICT:', logoutError);
    } finally {
        if (authenticatedUser?.id === userId && generation === deviceCryptoGeneration) {
            clearLocalAuthenticatedState();
            showAuth(
                'Ключ устройства изменился. Пожалуйста, войдите в аккаунт заново.' +
                (logoutConfirmed ? '' : ' Не удалось подтвердить выход на сервере; проверьте соединение.'),
                true,
            );
        }
        handlingSessionDeviceConflict = false;
    }
    return true;
}

function describeDeviceCryptoError(error) {
    const message = String(error?.message || error || 'Неизвестная ошибка');
    if (/Web Crypto API|WebCrypto|защищённом контексте|Ed25519|X25519/i.test(message)) {
        return 'WebCrypto/криптография устройства: ' + message;
    }
    if (/IndexedDB|локальн.*хранилищ|запись криптографического устройства/i.test(message)) {
        return 'Ошибка локального хранилища ключей: ' + message;
    }
    if (/challenge|подтвердил владение|подтверждения устройства|приватным ключом/i.test(message)) {
        return 'Ошибка challenge/sign/verify: ' + message;
    }
    if (/Backend|сервер|HTTP|401|403|409|500/i.test(message) || error?.status || error?.code) {
        return 'Сервер отклонил регистрацию или проверку ключа: ' + message;
    }
    return 'Ошибка инициализации криптографии: ' + message;
}

async function initializeDeviceCryptography() {
    if (deviceCryptoInitPromise) return deviceCryptoInitPromise;

    const userId = authenticatedUser?.id;
    const generation = deviceCryptoGeneration;
    if (!userId) {
        setSyncStatus('P2P не запущен: пользователь не авторизован.', true);
        return false;
    }

    const initTask = (async () => {
        p2pDeviceVerified = false;
        setSyncStatus('Подготавливаем криптографию устройства…');
        try {
            if (typeof syncRoomId !== 'string' || !syncRoomId.trim()) {
                throw new Error('В сессии отсутствует sync_room_id.');
            }

            const result = await deviceCrypto.ensureDeviceRegistered(userId);
            if (authenticatedUser?.id !== userId || generation !== deviceCryptoGeneration) return false;
            if (result?.verified !== true || !result.deviceId) {
                throw new Error('Сервер не подтвердил владение приватным ключом устройства (verify не вернул verified=true).');
            }

            localDeviceId = result.deviceId;
            localDeviceCryptoIdentity = await deviceCrypto.getDeviceCryptoIdentity(userId);
            if (authenticatedUser?.id !== userId || generation !== deviceCryptoGeneration) return false;
            if (localDeviceCryptoIdentity.deviceId !== localDeviceId) {
                throw new Error('ID локального устройства не совпадает с подтверждённым ID сервера.');
            }

            await refreshTrustedDeviceKeys();
            if (authenticatedUser?.id !== userId || generation !== deviceCryptoGeneration) return false;

            p2pDeviceVerified = true;
            if (!initWebRTC(syncRoomId)) {
                throw new Error('Не удалось создать P2P-комнату.');
            }
            startTrustedDeviceRefreshLoop();

            setSyncStatus(result.created
                ? 'Ключи устройства созданы; криптографическая проверка завершена'
                : 'Криптографическая идентичность устройства проверена');

            await refreshPairingRoleControls();
            if (authenticatedUser?.id === userId && document.getElementById('tab-devices')?.classList.contains('active')) {
                void loadDevices();
            }
            return true;
        } catch (error) {
            console.error('Не удалось подготовить криптографию устройства:', error);
            if (await handleSessionDeviceConflict(error, userId, generation)) {
                return false;
            }
            if (authenticatedUser?.id === userId && generation === deviceCryptoGeneration) {
                disableP2P(describeDeviceCryptoError(error));
            }
            return false;
        }
    })();

    deviceCryptoInitPromise = initTask;
    try {
        return await initTask;
    } finally {
        if (deviceCryptoInitPromise === initTask) deviceCryptoInitPromise = null;
    }
}


async function refreshPairingRoleControls() {
    try {
        const access = await authApi.getVaultEnvelope();
        currentDeviceHasVaultAccess = Boolean(access?.initialized && access?.envelope);
    } catch (_) {
        currentDeviceHasVaultAccess = false;
    }
    const showButton = document.getElementById('showPairingQRBtn');
    const scanButton = document.getElementById('scanPairingBtn');
    const availability = document.getElementById('pairingQrAvailability');
    const canCreatePairingInvite = Boolean(
        currentDeviceHasVaultAccess && isVaultUnlocked && vaultMasterKey instanceof Uint8Array && vaultId
    );
    if (showButton) {
        showButton.disabled = !canCreatePairingInvite;
        showButton.title = canCreatePairingInvite
            ? 'Показать QR для нового устройства'
            : 'Нужно доверенное устройство с доступом к разблокированному Сейфу';
        showButton.setAttribute('aria-disabled', String(showButton.disabled));
    }
    if (availability) {
        availability.textContent = !currentDeviceHasVaultAccess
            ? 'Это устройство пока не имеет доступа к Сейфу. Создать приглашение можно с уже доверенного устройства.'
            : !isVaultUnlocked
                ? 'Разблокируйте Сейф, чтобы создать QR-приглашение для нового устройства.'
                : !canCreatePairingInvite
                    ? 'Не удалось получить активный ключ Сейфа. Закройте и снова откройте Сейф.'
                    : 'Сейф разблокирован. Можно создать одноразовое QR-приглашение.';
    }
    if (scanButton) {
        scanButton.disabled = currentDeviceHasVaultAccess;
        scanButton.title = scanButton.disabled ? 'Это устройство уже имеет доступ к Сейфу' : 'Сканировать QR доверенного устройства';
    }
    refreshSettingsVaultState();
}


const DEVICE_STATUS_LABELS = { active: 'Доверенное', pending: 'Ожидает подтверждения', revoked: 'Отозвано', blocked: 'Заблокировано' };
function formatDeviceDate(value) {
    if (!value) return 'Нет данных';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Нет данных' : date.toLocaleString('ru-RU');
}
function deviceElement(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}
async function loadDevices() {
    const list = document.getElementById('devicesList');
    const message = document.getElementById('devicesMessage');
    if (!list || !authenticatedUser) return;
    list.replaceChildren();
    message.textContent = 'Загружаем список устройств…';
    try {
        const response = await authApi.listDevices();
        const devices = Array.isArray(response.devices) ? response.devices : [];
        message.textContent = devices.length ? `Устройств: ${devices.length}` : 'Пока нет зарегистрированных устройств.';
        for (const device of devices) {
            const card = deviceElement('article', 'device-card');
            const head = deviceElement('div', 'device-card-head');
            const titleWrap = deviceElement('div', 'device-title-wrap');
            titleWrap.append(deviceElement('h3', '', device.device_name || 'Устройство без имени'));
            titleWrap.append(deviceElement('div', 'device-subtitle', `${device.device_type || 'other'} · ${device.platform || 'Платформа не указана'}`));
            const statusLabel = device.status === 'active' && !device.has_vault_access ? 'Аккаунт активен · Сейф не подключён' : (DEVICE_STATUS_LABELS[device.status] || device.status);
            const status = deviceElement('span', `device-status device-status-${device.status}${device.status === 'active' && !device.has_vault_access ? ' device-status-no-vault' : ''}`, statusLabel);
            head.append(titleWrap, status);
            card.append(head);
            const details = deviceElement('div', 'device-details');
            details.append(
                deviceElement('div', '', `Добавлено: ${formatDeviceDate(device.created_at)}`),
                deviceElement('div', '', `Последнее подтверждение: ${formatDeviceDate(device.last_seen_at)}`),
                deviceElement('div', '', `Подпись: ${device.signing_algorithm || '—'} · Обмен ключами: ${device.encryption_algorithm || '—'}`),
                deviceElement('div', '', `Доступ к Сейфу: ${device.has_vault_access ? 'есть' : 'не подключён'}`),
                deviceElement('div', '', `Отпечаток: ${device.fingerprint || '—'}`),
                deviceElement('div', '', `ID: ${device.id}`),
            );
            card.append(details);
            if (device.is_current) card.append(deviceElement('div', 'device-current-label', 'Текущее устройство — отзыв доступен из другой доверенной сессии'));  
            const actions = deviceElement('div', 'device-actions');
            const historyBtn = deviceElement('button', 'secondary-btn', 'История');
            historyBtn.type = 'button';
            const historyPanel = deviceElement('div', 'device-history');
            historyPanel.hidden = true;
            historyBtn.addEventListener('click', async () => {
                if (!historyPanel.hidden) { historyPanel.hidden = true; historyBtn.textContent = 'История'; return; }
                historyPanel.hidden = false;
                historyPanel.textContent = 'Загружаем историю…';
                try {
                    const history = await authApi.getDeviceHistory(device.id);
                    historyPanel.replaceChildren();
                    const eventTitle = deviceElement('strong', '', 'События');
                    historyPanel.append(eventTitle);
                    for (const event of (history.events || [])) {
                        historyPanel.append(deviceElement('div', 'device-history-row', `${event.event_type} · ${formatDeviceDate(event.created_at)}`));
                    }
                    historyPanel.append(deviceElement('strong', 'device-history-heading', 'История публичных ключей'));
                    for (const key of (history.key_history || [])) {
                        historyPanel.append(deviceElement('div', 'device-history-row', `${key.key_purpose}: ${key.algorithm}, версия ${key.key_version} · ${formatDeviceDate(key.created_at)}`));
                    }
                    if (!(history.events || []).length && !(history.key_history || []).length) historyPanel.append(deviceElement('div', '', 'История пока пуста.'));
                } catch (error) { historyPanel.textContent = error.message || 'Не удалось загрузить историю.'; }
            });
            actions.append(historyBtn);
            if (device.status !== 'revoked' && device.status !== 'blocked' && !device.is_current) {
                const revokeBtn = deviceElement('button', 'danger-btn', 'Отозвать доступ');
                revokeBtn.type = 'button';
                revokeBtn.addEventListener('click', async () => {
                    const warning = device.is_current
                        ? 'Это текущее устройство. Его сессия будет завершена. Отзыв последнего устройства с доступом к Сейфу будет запрещён до настройки восстановления. Продолжить?'
                        : `Отозвать доступ устройства «${device.device_name}»? Все его активные серверные сессии будут завершены.`;
                    if (!confirm(warning)) return;
                    revokeBtn.disabled = true;
                    try {
                        const result = await authApi.revokeDevice(device.id);
                        if (result.current_device) { window.location.reload(); return; }
                        await loadDevices();
                    } catch (error) {
                        message.textContent = error.message || 'Не удалось отозвать устройство.';
                        revokeBtn.disabled = false;
                    }
                });
                actions.append(revokeBtn);
            }
            card.append(actions, historyPanel);
            list.append(card);
        }
    } catch (error) {
        message.textContent = error.message || 'Не удалось загрузить список устройств.';
    }
}





function parseSecureDiskInviteQr(rawText) {
    if (typeof rawText !== 'string' || rawText.length > 1024) throw new Error('QR-код слишком большой или имеет неверный формат.');
    let payload;
    try { payload = JSON.parse(rawText); } catch (_) { throw new Error('QR должен содержать JSON-приглашение NODEX.'); }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Неверная структура QR-кода.');
    const allowed = ['expires_at', 'invite_id', 'invite_token', 'type', 'version'];
    if (Object.keys(payload).sort().join(',') !== allowed.sort().join(',')) throw new Error('QR содержит неизвестные или отсутствующие поля.');
    if (payload.type !== 'secure-disk-pairing-invite' || payload.version !== 1) throw new Error('Неизвестный тип или версия приглашения.');
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (typeof payload.invite_id !== 'string' || !uuid.test(payload.invite_id)) throw new Error('Некорректный ID приглашения.');
    if (typeof payload.invite_token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(payload.invite_token)) throw new Error('Некорректный одноразовый токен приглашения.');
    if (typeof payload.expires_at !== 'string' || !Number.isFinite(Date.parse(payload.expires_at)) || Date.parse(payload.expires_at) <= Date.now()) throw new Error('Срок действия QR-кода истёк. Попросите показать новый.');
    return payload;
}

function buildPairingQr(payload) {
    const qrContainer = document.getElementById('pairingQrContainer');
    if (!qrContainer) throw new Error('В index.html отсутствует контейнер pairingQrContainer.');
    if (typeof window.qrcode !== 'function') {
        throw new Error('Библиотека qrcode-generator не загружена. Проверьте подключение qrcode.min.js.');
    }
    const qr = window.qrcode(0, 'M');
    qr.addData(JSON.stringify(payload));
    qr.make();
    qrContainer.innerHTML = qr.createSvgTag(5, 10);
}
function pairingDelay(ms = 1600) { return new Promise(resolve => setTimeout(resolve, ms)); }

// Trusted device creates and displays a five-minute invitation.
async function showPairingQR() {
    const status = document.getElementById('pairingQrStatus');
    const button = document.getElementById('showPairingQRBtn');
    const modal = document.getElementById('pairingQrModal');
    const qrContainer = document.getElementById('pairingQrContainer');
    if (!status || !modal || !qrContainer) {
        console.error('NODEX Pairing QR: modal elements are missing.');
        return;
    }
    if (!authenticatedUser?.id) {
        document.getElementById('devicesMessage').textContent = 'Сначала войдите в аккаунт на доверенном устройстве.';
        return;
    }
    await refreshPairingRoleControls();
    if (!currentDeviceHasVaultAccess || !isVaultUnlocked || !(vaultMasterKey instanceof Uint8Array) || !vaultId) {
        const availability = document.getElementById('pairingQrAvailability');
        if (availability) availability.textContent = 'Для создания QR необходимо доверенное устройство с разблокированным Сейфом.';
        return;
    }
    try {
        if (button) button.disabled = true;
        qrContainer.replaceChildren();
        status.textContent = 'Создаём одноразовое приглашение…';
        // Open immediately so a slow backend request is visible to the user.
        modal.style.display = 'flex';
        const created = await authApi.createPairingInvite();
        if (!created?.invite_id || !created?.invite_token || !created?.expires_at) throw new Error('Backend вернул неполные данные приглашения.');
        activePairingInvite = { inviteId: created.invite_id, expiresAt: created.expires_at };
        pairingPollCancelled = false;
        buildPairingQr({ type: 'secure-disk-pairing-invite', version: 1, invite_id: created.invite_id, invite_token: created.invite_token, expires_at: created.expires_at });
        const approve = document.getElementById('approvePairingBtn');
        approve.disabled = true; approve.hidden = true;
        status.textContent = `QR готов. Ожидаем сканирования новым устройством. Приглашение действует 5 минут — до ${new Date(created.expires_at).toLocaleTimeString('ru-RU')}.`;
        void pollTrustedPairingInvite(activePairingInvite);
    } catch (error) {
        status.textContent = error.message || 'Не удалось создать приглашение.';
        modal.style.display = 'flex';
        console.error('NODEX Pairing QR generation failed:', error);
    } finally {
        if (button) button.disabled = !(currentDeviceHasVaultAccess && isVaultUnlocked && vaultMasterKey instanceof Uint8Array && vaultId);
    }
}

async function pollTrustedPairingInvite(invite) {
    const status = document.getElementById('pairingQrStatus');
    while (!pairingPollCancelled && activePairingInvite?.inviteId === invite.inviteId) {
        if (Date.now() >= Date.parse(invite.expiresAt)) {
            status.textContent = 'Срок действия приглашения истёк. Закройте окно и создайте новый QR-код.';
            document.getElementById('approvePairingBtn').hidden = true;
            break;
        }
        try {
            const state = await authApi.getPairingInviteStatus(invite.inviteId);
            if (state.status === 'pending') {
                status.textContent = 'QR готов. Ожидаем, когда новое устройство войдёт в тот же аккаунт и отсканирует код…';
            } else if (state.status === 'claimed') {
                const d = state.claimed_device;
                status.textContent = `Устройство найдено: ${d?.device_name || 'Новое устройство'} · ${d?.platform || 'платформа не указана'} · fingerprint ${d?.fingerprint || '—'}. Проверьте устройство перед передачей доступа к Сейфу.`;
                const approve = document.getElementById('approvePairingBtn');
                approve.hidden = false; approve.disabled = false;
            } else if (state.status === 'approved') {
                status.textContent = 'Ключ Сейфа передан в зашифрованном виде. Ожидаем подтверждения расшифровки новым устройством…';
                document.getElementById('approvePairingBtn').hidden = true;
            } else if (state.status === 'completed') {
                status.textContent = 'Новое устройство успешно подключено к Сейфу.';
                activePairingInvite = null;
                document.getElementById('approvePairingBtn').hidden = true;
                void loadDevices();
                break;
            } else {
                status.textContent = `Приглашение больше недействительно (статус: ${state.status}). Создайте новый QR-код.`;
                document.getElementById('approvePairingBtn').hidden = true;
                break;
            }
        } catch (error) {
            status.textContent = error.message || 'Не удалось проверить статус приглашения. Повторяем…';
            if (['PAIRING_INVITE_NOT_FOUND', 'SESSION_EXPIRED', 'DEVICE_REVOKED'].includes(error.code)) break;
        }
        await pairingDelay();
    }
}

async function approvePairingInvite() {
    const invite = activePairingInvite;
    const button = document.getElementById('approvePairingBtn');
    const status = document.getElementById('pairingQrStatus');
    if (!invite || !isVaultUnlocked || !vaultMasterKey || !vaultId) return;
    try {
        button.disabled = true;
        status.textContent = 'Проверяем новое устройство и создаём зашифрованный конверт VMK…';
        const state = await authApi.getPairingInviteStatus(invite.inviteId);
        if (state.status !== 'claimed' || !state.claimed_device) throw new Error('Claim уже недоступен. Обновите приглашение.');
        const target = state.claimed_device;
        const identity = await deviceCrypto.getDeviceCryptoIdentity(authenticatedUser.id);
        if (identity.deviceId === target.id) throw new Error('Нельзя передать ключ самому себе.');
        const context = { userId: authenticatedUser.id, vaultId, deviceId: target.id, purpose: 'pairing', requestId: invite.inviteId };
        const envelope = await vaultCrypto.sealVmkForDevice(vaultMasterKey, target.encryption_public_key, context);
        const digest = await vaultCrypto.pairingEnvelopeDigest(envelope);
        const message = vaultCrypto.buildPairingApprovalMessage(invite.inviteId, identity.deviceId, target.id, vaultId, digest);
        const signature = await deviceCrypto.signDeviceData(authenticatedUser.id, message);
        await authApi.approvePairingInvite(invite.inviteId, { envelope, signature });
        status.textContent = 'Передача одобрена. VMK отправлен серверу только в зашифрованном конверте. Ожидаем подтверждения новым устройством…';
        button.hidden = true;
    } catch (error) {
        status.textContent = error.message || 'Не удалось одобрить приглашение.';
        button.disabled = false;
    }
}

// New device: scan the QR and claim it with its device-proof-verified public keys.
async function scanPairingQR() {
    if (!authenticatedUser?.id) {
        document.getElementById('devicesMessage').textContent = 'Сначала войдите на новом устройстве в тот же аккаунт NODEX.';
        return;
    }
    try {
        // A new browser may not have local keys yet. In that case create and
        // register them, then complete the existing session-bound proof before claim.
        const knownIdentity = await deviceCrypto.getDeviceIdentityInfo(authenticatedUser.id);
        if (!knownIdentity?.deviceId) await deviceCrypto.ensureDeviceRegistered(authenticatedUser.id);
        await deviceCrypto.getDeviceCryptoIdentity(authenticatedUser.id);
        await refreshPairingRoleControls();
        if (currentDeviceHasVaultAccess) {
            document.getElementById('devicesMessage').textContent = 'Это устройство уже имеет доступ к Сейфу. Для него не требуется сканировать QR.';
            return;
        }
    } catch (error) {
        document.getElementById('devicesMessage').textContent = error.message || 'Сначала завершите регистрацию криптографической идентичности устройства.';
        return;
    }
    pairingPollCancelled = false;
    claimedPairingInvite = null;
    document.getElementById('pairingTargetInfo').textContent = 'Войдите в тот же аккаунт, что и на доверенном устройстве, затем отсканируйте его QR-код.';
    document.getElementById('pairingQrManualInput').value = '';
    document.getElementById('pairingScannerModal').style.display = 'flex';
    document.getElementById('closePairingScannerBtn').disabled = false;
    if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
        document.getElementById('pairingTargetInfo').textContent = 'Камера доступна только по HTTPS или localhost. Можно вставить содержимое QR вручную.';
        return;
    }
    if (!window.Html5Qrcode) {
        document.getElementById('pairingTargetInfo').textContent = 'Модуль камеры не загружен. Вставьте содержимое QR вручную.';
        return;
    }
    try {
        pairingScanner = new window.Html5Qrcode('pairingQrReader', { verbose: false });
        await pairingScanner.start(
            { facingMode: 'environment' },
            { fps: 10, qrbox: { width: 240, height: 240 }, aspectRatio: 1 },
            decodedText => { void handleScannedPairingInvite(decodedText); },
            () => {},
        );
    } catch (error) {
        await stopPairingScanner();
        document.getElementById('pairingTargetInfo').textContent = 'Не удалось запустить камеру: ' + (error.message || 'проверьте разрешение камеры').toString();
    }
}

async function stopPairingScanner() {
    const scanner = pairingScanner;
    pairingScanner = null;
    if (!scanner) return;
    try { await scanner.stop(); } catch (_) { }
    try { await scanner.clear(); } catch (_) { }
}

let pairingQrHandling = false;
async function handleScannedPairingInvite(rawText) {
    if (pairingQrHandling || claimedPairingInvite) return;
    pairingQrHandling = true;
    try {
        await stopPairingScanner();
        const qr = parseSecureDiskInviteQr(rawText);
        const identity = await deviceCrypto.getDeviceCryptoIdentity(authenticatedUser.id);
        await authApi.claimPairingInvite({
            invite_id: qr.invite_id,
            invite_token: qr.invite_token,
            public_key: identity.publicKeyBase64,
            encryption_public_key: identity.encryptionPublicKeyBase64,
        });
        claimedPairingInvite = { inviteId: qr.invite_id, expiresAt: qr.expires_at };
        document.getElementById('pairingTargetInfo').textContent = 'QR принят. Это устройство заявлено в приглашении. Теперь на доверенном устройстве нужно проверить имя и fingerprint и нажать «Передать ключ Сейфа». Не закрывайте это окно до завершения.';
        document.getElementById('closePairingScannerBtn').disabled = false;
        document.getElementById('closePairingScannerBtn').textContent = 'Свернуть окно';
        void pollClaimedPairingInvite(claimedPairingInvite);
    } catch (error) {
        document.getElementById('pairingTargetInfo').textContent = error.message || 'Не удалось принять приглашение.';
    } finally {
        pairingQrHandling = false;
    }
}

async function pollClaimedPairingInvite(invite) {
    const status = document.getElementById('pairingTargetInfo');
    while (!pairingPollCancelled && claimedPairingInvite?.inviteId === invite.inviteId) {
        try {
            const state = await authApi.getPairingInviteResult(invite.inviteId);
            if (state.status === 'pending' || state.status === 'claimed') {
                status.textContent = 'Приглашение принято. Ожидаем, когда доверенное устройство проверит это устройство и разрешит передачу ключа Сейфа…';
            } else if (state.status === 'approved' && state.envelope && state.vault_id) {
                status.textContent = 'Получен зашифрованный конверт. Проверяем подпись и локально расшифровываем VMK…';
                const identity = await deviceCrypto.getDeviceCryptoIdentity(authenticatedUser.id);
                const context = { userId: authenticatedUser.id, vaultId: state.vault_id, deviceId: identity.deviceId, purpose: 'pairing', requestId: invite.inviteId };
                let vmk = null;
                try {
                    vmk = await vaultCrypto.openVmkEnvelope(authenticatedUser.id, state.envelope, context);
                    const digest = await vaultCrypto.pairingEnvelopeDigest(state.envelope);
                    const message = vaultCrypto.buildPairingCompletionMessage(invite.inviteId, identity.deviceId, state.vault_id, digest);
                    const signature = await deviceCrypto.signDeviceData(authenticatedUser.id, message);
                    await authApi.completePairingInvite(invite.inviteId, { signature });
                    await activateVaultUi(vmk, state.vault_id);
                    status.textContent = 'Устройство подключено. VMK расшифрован локально.';
                    claimedPairingInvite = null;
                    document.getElementById('pairingScannerModal').style.display = 'none';
                    document.getElementById('vaultPairingMessage').textContent = 'Устройство подключено к Сейфу. VMK расшифрован локально.';
                    void loadDevices();
                    return;
                } finally {
                    if (vmk instanceof Uint8Array) vmk.fill(0);
                }
            } else if (state.status === 'completed') {
                const opened = await vaultCrypto.unlockVaultForCurrentDevice(authenticatedUser.id);
                await activateVaultUi(opened.vmk, opened.vaultId);
                claimedPairingInvite = null;
                document.getElementById('pairingScannerModal').style.display = 'none';
                return;
            } else {
                status.textContent = `Приглашение недействительно (статус: ${state.status}). Закройте окно и создайте новый QR-код.`;
                claimedPairingInvite = null;
                document.getElementById('closePairingScannerBtn').disabled = false;
                break;
            }
        } catch (error) {
            status.textContent = error.message || 'Не удалось получить результат подключения. Повторяем…';
            if (['PAIRING_INVITE_NOT_FOUND', 'SESSION_EXPIRED', 'DEVICE_REVOKED'].includes(error.code)) break;
        }
        await pairingDelay(1800);
    }
}

const showPairingQRButton = document.getElementById('showPairingQRBtn');
if (showPairingQRButton) showPairingQRButton.addEventListener('click', () => { void showPairingQR(); });
else console.error('NODEX: #showPairingQRBtn not found; Pairing QR click handler was not attached.');
const scanPairingButton = document.getElementById('scanPairingBtn');
if (scanPairingButton) scanPairingButton.addEventListener('click', () => void scanPairingQR());
const startPairingButton = document.getElementById('startPairingBtn');
if (startPairingButton) startPairingButton.addEventListener('click', () => void scanPairingQR());
const approvePairingButton = document.getElementById('approvePairingBtn');
if (approvePairingButton) approvePairingButton.addEventListener('click', () => void approvePairingInvite());
const cancelPairingButton = document.getElementById('cancelPairingBtn');
if (cancelPairingButton) cancelPairingButton.addEventListener('click', async () => {
    pairingPollCancelled = true;
    if (activePairingInvite) {
        try { await authApi.cancelPairingInvite(activePairingInvite.inviteId); } catch (_) { }
    }
    activePairingInvite = null;
    document.getElementById('pairingQrModal').style.display = 'none';
});
const closePairingScannerButton = document.getElementById('closePairingScannerBtn');
if (closePairingScannerButton) closePairingScannerButton.addEventListener('click', async () => {
    if (claimedPairingInvite) { document.getElementById('pairingScannerModal').style.display = 'none'; return; }
    pairingPollCancelled = true;
    await stopPairingScanner();
    document.getElementById('pairingScannerModal').style.display = 'none';
});
const manualPairingButton = document.getElementById('pairingUseManualQrBtn');
if (manualPairingButton) manualPairingButton.addEventListener('click', () => void handleScannedPairingInvite(document.getElementById('pairingQrManualInput').value.trim()));


async function activateAuthenticatedSession(session) {
    if (!session?.user?.id || typeof session.sync_room_id !== 'string' || !session.sync_room_id.trim()) {
        throw new Error('Ответ backend не содержит user.id или корректный sync_room_id.');
    }

    stopSyncLoop();
    authenticatedUser = session.user;
    syncRoomId = session.sync_room_id;
    currentProfile = resolveLocalProfileForUser(authenticatedUser);
    loadProfileData();
    showApp();
    // Не возвращаем управление до завершения crypto registration + challenge/sign/verify.
    await initializeDeviceCryptography();
}

async function restoreAuthentication() {
    showAuth('Проверяем сохранённую сессию…');
    try {
        const session = await authApi.restoreSession();
        await activateAuthenticatedSession(session);
    } catch (error) {
        authenticatedUser = null;
        syncRoomId = '';
        currentProfile = '';
        if (error.status === 401) {
            showAuth('');
        } else {
            showAuth('Не удалось проверить сессию: ' + readableAuthError(error), true);
        }
    }
}

// -----------------------------------------------------------------------------
// LAN server discovery. QR contains only public endpoint information; never
// credentials, device keys, VMK, pairing tokens, or account data.
let serverQrScanner = null;
let serverQrHandling = false;

function openServerConnectModal(message = '') {
    const modal = document.getElementById('serverConnectModal');
    if (!modal) return;
    const saved = getSavedServerUrl();
    const input = document.getElementById('serverAddressInput');
    if (input && saved) input.value = saved;
    document.getElementById('serverConnectStatus').textContent = message;
    modal.style.display = 'flex';
}

async function stopServerQrScanner() {
    const scanner = serverQrScanner;
    serverQrScanner = null;
    if (!scanner) return;
    try { await scanner.stop(); } catch (_) {}
    try { await scanner.clear(); } catch (_) {}
    const reader = document.getElementById('serverQrReader');
    if (reader) reader.hidden = true;
    const stopButton = document.getElementById('stopServerQrScanBtn');
    if (stopButton) stopButton.hidden = true;
}

function parseNodeHostQr(rawText) {
    let payload;
    try { payload = JSON.parse(String(rawText)); }
    catch (_) { throw new Error('QR-код не содержит корректный JSON.'); }
    if (!payload || payload.type !== 'NODEX_HOST' || typeof payload.api !== 'string' || typeof payload.ipfs !== 'string') {
        throw new Error('Это не QR-код подключения к NODEX.');
    }
    let api, ipfs;
    try { api = new URL(payload.api); ipfs = new URL(payload.ipfs); }
    catch (_) { throw new Error('В QR-коде указан некорректный адрес.'); }
    if (!['http:', 'https:'].includes(api.protocol) || api.username || api.password ||
        api.pathname.replace(/\/+$/, '') !== '/api/v1' || api.search || api.hash) {
        throw new Error('Некорректный адрес API в QR-коде.');
    }
    if (!['http:', 'https:'].includes(ipfs.protocol) || ipfs.origin !== api.origin ||
        ipfs.pathname.replace(/\/+$/, '') !== '/ipfs/api/v0' || ipfs.username || ipfs.password || ipfs.search || ipfs.hash) {
        throw new Error('IPFS должен указывать на защищённый прокси того же Windows-хоста.');
    }
    return { origin: api.origin };
}

async function acceptNodeHostQr(rawText) {
    if (serverQrHandling) return;
    serverQrHandling = true;
    try {
        await stopServerQrScanner();
        const { origin } = parseNodeHostQr(rawText);
        setServerConfig(origin);
        document.getElementById('serverConnectStatus').textContent = 'Адрес сервера сохранён. Проверяем подключение…';
        document.getElementById('serverConnectModal').style.display = 'none';
        await restoreAuthentication();
    } catch (error) {
        document.getElementById('serverConnectStatus').textContent = error.message || 'Не удалось обработать QR-код.';
    } finally {
        serverQrHandling = false;
    }
}

document.getElementById('openServerConnectBtn')?.addEventListener('click', () => {
    document.getElementById('profileModal').style.display = 'none';
    openServerConnectModal();
});
document.getElementById('serverConnectCloseBtn')?.addEventListener('click', () => {
    if (isNativeClient() && !isServerConfigured()) {
        document.getElementById('serverConnectStatus').textContent = 'Для мобильного приложения сначала укажите адрес Windows-сервера.';
        return;
    }
    void stopServerQrScanner();
    document.getElementById('serverConnectModal').style.display = 'none';
});
document.getElementById('saveServerAddressBtn')?.addEventListener('click', async () => {
    const input = document.getElementById('serverAddressInput');
    const status = document.getElementById('serverConnectStatus');
    try {
        const config = setServerConfig(input.value);
        status.textContent = `Сохранено: ${config.serverUrl}. Проверяем сервер…`;
        await stopServerQrScanner();
        document.getElementById('serverConnectModal').style.display = 'none';
        await restoreAuthentication();
    } catch (error) {
        status.textContent = error.message || 'Не удалось сохранить адрес сервера.';
    }
});
document.getElementById('startServerQrScanBtn')?.addEventListener('click', async () => {
    const status = document.getElementById('serverConnectStatus');
    if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
        status.textContent = 'Для камеры требуется HTTPS или localhost. Используйте ручной ввод адреса.';
        return;
    }
    if (!window.Html5Qrcode) {
        status.textContent = 'Модуль сканирования не загружен. Используйте ручной ввод адреса.';
        return;
    }
    try {
        await stopServerQrScanner();
        document.getElementById('serverQrReader').hidden = false;
        document.getElementById('stopServerQrScanBtn').hidden = false;
        serverQrScanner = new window.Html5Qrcode('serverQrReader', { verbose: false });
        await serverQrScanner.start(
            { facingMode: 'environment' },
            { fps: 10, qrbox: { width: 230, height: 230 }, aspectRatio: 1 },
            decodedText => { void acceptNodeHostQr(decodedText); },
            () => {},
        );
        status.textContent = 'Наведите камеру на QR-код Windows-приложения.';
    } catch (error) {
        await stopServerQrScanner();
        status.textContent = `Не удалось запустить камеру: ${error.message || 'проверьте разрешение'}. Можно ввести адрес вручную.`;
    }
});
document.getElementById('stopServerQrScanBtn')?.addEventListener('click', () => void stopServerQrScanner());

function suggestedLanHost() {
    const hostname = window.location.hostname;
    if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') return '';
    return `https://${hostname}:3001`;
}

document.getElementById('showHostQrBtn')?.addEventListener('click', () => {
    document.getElementById('profileModal').style.display = 'none';
    const input = document.getElementById('hostLanAddressInput');
    if (input && !input.value) input.value = suggestedLanHost();
    document.getElementById('hostQrContainer').hidden = true;
    document.getElementById('hostQrStatus').textContent = '';
    document.getElementById('hostQrModal').style.display = 'flex';
});
document.getElementById('hostQrCloseBtn')?.addEventListener('click', () => {
    document.getElementById('hostQrModal').style.display = 'none';
});
document.getElementById('generateHostQrBtn')?.addEventListener('click', () => {
    const status = document.getElementById('hostQrStatus');
    const container = document.getElementById('hostQrContainer');
    try {
        if (typeof window.qrcode !== 'function') throw new Error('Библиотека qrcode-generator не загружена.');
        const origin = normalizeServerOrigin(document.getElementById('hostLanAddressInput').value);
        const payload = {
            type: 'NODEX_HOST',
            api: `${origin}/api/v1`,
            // This is a future restricted proxy endpoint, not Kubo's admin API.
            ipfs: `${origin}/ipfs/api/v0`,
        };
        const qr = window.qrcode(0, 'M');
        qr.addData(JSON.stringify(payload));
        qr.make();
        container.innerHTML = qr.createSvgTag(5, 10);
        container.hidden = false;
        status.textContent = 'QR-код создан локально. Он не отправлялся во внешний сервис.';
    } catch (error) {
        container.hidden = true;
        status.textContent = error.message || 'Не удалось создать QR-код.';
    }
});

function updateSettingsServerAddress() {
    const label = document.getElementById('settingsServerAddress');
    if (label) label.textContent = getSavedServerUrl() || (isNativeClient() ? 'Адрес сервера не задан' : 'Браузерный режим: localhost');
}
updateSettingsServerAddress();
window.addEventListener('nodex:server-config-changed', updateSettingsServerAddress);

window.addEventListener('load', () => {
    if (!isServerConfigured()) {
        openServerConnectModal();
        return;
    }
    void restoreAuthentication();
});

function showAuth(message = '', isError = false) {
    document.getElementById('appScreen').style.display = 'none';
    document.getElementById('authScreen').style.display = 'flex';
    document.getElementById('loginPasswordInput').value = '';
    document.getElementById('registerPasswordInput').value = '';
    setAuthMessage(message, isError);
    switchAuthTab('login');
}

function showApp() {
    driveViewMode = localStorage.getItem('secureDiskDriveView') === 'list' ? 'list' : 'grid';
    document.getElementById('authScreen').style.display = 'none';
    document.getElementById('appScreen').style.display = 'flex';
    renderFiles();
    refreshProfileUI();
}

function stopSyncLoop() {
    // Invalidate any in-flight device registration before another session starts.
    deviceCryptoGeneration++;
    if (trustRefreshTimer) clearInterval(trustRefreshTimer);
    trustRefreshTimer = null;
    trustedKeysLastRefreshedAt = 0;
    trustedKeysRefreshPromise = null;
    p2pDeviceVerified = false;
    trustedPeers.clear();
    trustedDeviceKeys.clear();
    quarantinedPeerIds.clear();
    localDeviceId = null;
    localDeviceCryptoIdentity = null;
    p2pRoomIdentity = null;
    deviceCryptoInitPromise = null;
    if (room) {
        try { void room.leave(); } catch (error) { console.warn('Ошибка выхода из P2P-комнаты:', error); }
        room = null;
    }
    sendSyncData = sendRequestSync = sendNewFile = null;
}

window.addEventListener('storage', (e) => {
    if (e.key === `secureDiskFiles_${currentProfile}` || e.key === `secureDiskVault_${currentProfile}`) { loadProfileData(); renderFiles(); if (isVaultUnlocked) renderVaultFiles(); }
    if (e.key === `secureDiskMeta_${currentProfile}`) refreshProfileUI();
});
document.getElementById('syncBtn').onclick = () => {
    const button = document.getElementById('syncBtn');
    button.disabled = true;
    button.textContent = '⏳ Синхронизация…';
    if (sendRequestSync && p2pDeviceVerified) {
        const targets = [...trustedPeers.keys()].filter(peerId => !quarantinedPeerIds.has(peerId));
        if (!targets.length) {
            setSyncStatus('Нет подключённых доверенных устройств', true);
        } else {
            Promise.allSettled(targets.map(peerId =>
                sendRequestSync.send({ profile: currentProfile, version: 1 }, { target: peerId })
            )).then(results => {
                const failed = results.filter(result => result.status === 'rejected').length;
                if (failed) setSyncStatus(`Не удалось отправить ${failed} запрос(ов) синхронизации`, true);
                else setSyncStatus('Запрос синхронизации отправлен доверенным устройствам');
            });
        }
    } else {
        setSyncStatus('P2P ещё не подключён', true);
    }
    setTimeout(() => {
        button.disabled = false;
        button.textContent = '🔄 Синхронизировать';
    }, 1200);
};

document.querySelectorAll('.auth-tab').forEach(btn => {
    btn.onclick = () => switchAuthTab(btn.dataset.tab);
});

function triggerButtonOnEnter(inputIds, buttonId) {
    for (const inputId of inputIds) {
        const input = document.getElementById(inputId);
        input?.addEventListener('keydown', event => {
            if (event.key !== 'Enter' || event.isComposing) return;
            event.preventDefault();
            document.getElementById(buttonId)?.click();
        });
    }
}

triggerButtonOnEnter(['loginEmailInput', 'loginPasswordInput'], 'loginBtn');
triggerButtonOnEnter(['registerNameInput', 'registerEmailInput', 'registerPasswordInput'], 'registerBtn');
triggerButtonOnEnter(['verificationTokenInput'], 'verifyEmailBtn');

document.getElementById('loginBtn').onclick = async () => {
    const button = document.getElementById('loginBtn');
    const email = document.getElementById('loginEmailInput').value.trim();
    const password = document.getElementById('loginPasswordInput').value;
    if (!email || !password) return setAuthMessage('Введите email и пароль.', true);

    setAuthMessage('Выполняется вход…');
    setAuthBusy(button, true, 'Входим…');
    try {
        const session = await authApi.login({ email, password });
        document.getElementById('loginPasswordInput').value = '';
        await activateAuthenticatedSession(session);
    } catch (error) {
        if (error.code === 'EMAIL_NOT_VERIFIED') {
            document.getElementById('verificationEmailInput').value = email;
            document.getElementById('verificationPanel').hidden = false;
            setAuthMessage(readableAuthError(error) + ' Введите токен из письма ниже.', true);
        } else {
            setAuthMessage(readableAuthError(error), true);
        }
    } finally {
        setAuthBusy(button, false);
    }
};

document.getElementById('registerBtn').onclick = async () => {
    const button = document.getElementById('registerBtn');
    const email = document.getElementById('registerEmailInput').value.trim();
    const password = document.getElementById('registerPasswordInput').value;
    const displayName = document.getElementById('registerNameInput').value.trim();
    if (!email || !password) return setAuthMessage('Введите email и пароль.', true);
    if (password.length < 12) return setAuthMessage('Пароль должен содержать не менее 12 символов.', true);

    setAuthMessage('Создаём аккаунт…');
    setAuthBusy(button, true, 'Регистрируем…');
    try {
        const result = await authApi.register({ email, password, display_name: displayName });
        document.getElementById('verificationEmailInput').value = email;
        document.getElementById('verificationTokenInput').value = '';
        document.getElementById('registerPasswordInput').value = '';
        document.getElementById('verificationPanel').hidden = false;
        const hasDevelopmentToken = typeof result.dev_verification_token === 'string';
        const verificationMessage = hasDevelopmentToken
            ? 'Аккаунт создан. В локальном режиме SMTP не настроен: тестовый токен не показывается в интерфейсе. Настройте SMTP, чтобы получить письмо.'
            : (result.message || 'Аккаунт создан. Проверьте почту и введите токен подтверждения.');
        setAuthMessage(verificationMessage);
        switchAuthTab('login');
    } catch (error) {
        setAuthMessage(readableAuthError(error), true);
    } finally {
        setAuthBusy(button, false);
    }
};

document.getElementById('verifyEmailBtn').onclick = async () => {
    const button = document.getElementById('verifyEmailBtn');
    const token = document.getElementById('verificationTokenInput').value.trim();
    if (!token) return setAuthMessage('Введите токен подтверждения из письма.', true);
    setAuthBusy(button, true, 'Подтверждаем…');
    try {
        await authApi.verifyEmail(token);
        const email = document.getElementById('verificationEmailInput').value.trim();
        document.getElementById('loginEmailInput').value = email;
        document.getElementById('loginPasswordInput').value = '';
        document.getElementById('verificationPanel').hidden = true;
        document.getElementById('verificationTokenInput').value = '';
        setAuthMessage('Email подтверждён. Теперь войдите, используя пароль.');
        switchAuthTab('login');
    } catch (error) {
        setAuthMessage(readableAuthError(error), true);
    } finally {
        setAuthBusy(button, false);
    }
};

document.getElementById('resendVerificationBtn').onclick = async () => {
    const button = document.getElementById('resendVerificationBtn');
    const email = document.getElementById('verificationEmailInput').value.trim();
    if (!email) return setAuthMessage('Введите email для повторной отправки.', true);
    setAuthBusy(button, true, 'Отправляем…');
    try {
        const result = await authApi.resendVerification(email);
        document.getElementById('verificationTokenInput').value = '';
        setAuthMessage(typeof result.dev_verification_token === 'string'
            ? 'Локальный SMTP не настроен. Тестовый токен не отображается в интерфейсе; настройте SMTP для получения письма.'
            : (result.message || 'Если аккаунт ожидает подтверждения, письмо будет отправлено повторно.'));
    } catch (error) {
        setAuthMessage(readableAuthError(error), true);
    } finally {
        setAuthBusy(button, false);
    }
};

async function performAccountExit(button, successMessage) {
    closeProfileDropdown();
    setAuthBusy(button, true, 'Выходим…');
    try {
        await authApi.logout();
        clearLocalAuthenticatedState();
        showAuth(successMessage || 'Вы вышли из аккаунта. Локальные файлы сохранены на этом устройстве.');
    } catch (error) {
        if (error.status === 401) {
            clearLocalAuthenticatedState();
            showAuth('Сессия истекла. Войдите снова.');
        } else {
            alert('Сервер не подтвердил выход. Сессия может оставаться активной. Проверьте соединение и повторите выход.\n\n' + readableAuthError(error));
        }
    } finally {
        setAuthBusy(button, false);
    }
}

document.getElementById('logoutBtn').onclick = () => performAccountExit(
    document.getElementById('logoutBtn'),
    'Вы вышли из NODEX. Локальные файлы сохранены на этом устройстве.'
);
document.getElementById('switchAccountBtn')?.addEventListener('click', () => performAccountExit(
    document.getElementById('switchAccountBtn'),
    'Сессия завершена. Теперь можно войти в другой аккаунт. Локальные файлы сохранены.'
));

function clearLocalAuthenticatedState() {
    stopSyncLoop();
    authApi.clearClientCsrfState();
    authenticatedUser = null;
    syncRoomId = '';
    currentProfile = '';
    myFiles = [];
    vaultFiles = [];
    myDriveCurrentFolderId = null;
    isVaultUnlocked = false;
    if (vaultMasterKey) vaultMasterKey.fill(0);
    vaultMasterKey = null;
    vaultId = null;
    pendingLegacyVaultKeys.clear();
    selectedMyFiles.clear();
    selectedVaultFiles.clear();
}

function loadProfileData() { const data = localStorage.getItem(`secureDiskFiles_${currentProfile}`), vData = localStorage.getItem(`secureDiskVault_${currentProfile}`); myFiles = data ? JSON.parse(data) : []; vaultFiles = vData ? JSON.parse(vData) : []; myFiles = Array.isArray(myFiles) ? myFiles.map(item => isFolderRecord(item) ? { ...item, type: 'folder', parentId: item.parentId || null } : { ...item, type: 'file', parentId: item.parentId || null }) : []; vaultFiles = Array.isArray(vaultFiles) ? vaultFiles : []; selectedMyFiles.clear(); selectedVaultFiles.clear(); myDriveCurrentFolderId = null; document.getElementById('displayAccountKey').textContent = authenticatedUser?.email || ''; }
function saveFiles(broadcast = true) {
    if (!currentProfile) return;
    localStorage.setItem(`secureDiskFiles_${currentProfile}`, JSON.stringify(myFiles));
    renderFiles();
    if (broadcast) sendSyncSnapshot();
}
function saveVaultFiles(broadcast = true) {
    if (!currentProfile) return;
    localStorage.setItem(`secureDiskVault_${currentProfile}`, JSON.stringify(vaultFiles));
    renderVaultFiles();
    if (broadcast) sendSyncSnapshot();
}

document.querySelectorAll('.nav-item[data-tab]').forEach(btn => {
    btn.onclick = () => {
        document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active')); document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        btn.classList.add('active'); document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        if (btn.dataset.tab === 'vault') { if (!isVaultUnlocked) { document.getElementById('vaultLockedArea').style.display = 'flex'; document.getElementById('vaultContentArea').style.display = 'none'; document.getElementById('vaultPinInput').value = ''; } else { document.getElementById('vaultLockedArea').style.display = 'none'; document.getElementById('vaultContentArea').style.display = 'block'; renderVaultFiles(); } }
        if (btn.dataset.tab === 'rental') activateRentalPane(btn.dataset.subtab || 'provider');
        if (btn.dataset.tab === 'devices') void loadDevices();
    };
});

function activateRentalPane(name) {
    document.querySelectorAll('.rental-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.rtab === name));
    document.querySelectorAll('.rental-pane').forEach(pane => pane.classList.toggle('active', pane.id === `rental-${name}`));
}
document.querySelectorAll('.rental-tab').forEach(tab => {
    tab.onclick = () => activateRentalPane(tab.dataset.rtab);
});

// Compact macOS-style sidebar; preference is local to this browser profile.
const appSidebar = document.getElementById('appSidebar');
const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
function setSidebarCollapsed(collapsed) {
    if (!appSidebar || !sidebarToggleBtn) return;
    appSidebar.classList.toggle('is-collapsed', collapsed);
    sidebarToggleBtn.setAttribute('aria-expanded', String(!collapsed));
    sidebarToggleBtn.setAttribute('aria-label', collapsed ? 'Развернуть меню' : 'Свернуть меню');
    sidebarToggleBtn.title = collapsed ? 'Развернуть меню' : 'Свернуть меню';
    localStorage.setItem('secureDiskSidebarCollapsed', collapsed ? '1' : '0');
}
if (appSidebar && sidebarToggleBtn) {
    const savedSidebarState = localStorage.getItem('secureDiskSidebarCollapsed');
    const startCollapsed = savedSidebarState === null ? Boolean(window.matchMedia?.('(max-width: 760px)').matches) : savedSidebarState === '1';
    setSidebarCollapsed(startCollapsed);
    sidebarToggleBtn.addEventListener('click', () => setSidebarCollapsed(!appSidebar.classList.contains('is-collapsed')));
}

function activateUploadMode(mode = 'upload') {
    const selectedMode = mode === 'download' ? 'download' : 'upload';
    document.querySelectorAll('.upload-mode-tab').forEach(tab => {
        const active = tab.dataset.uploadMode === selectedMode;
        tab.classList.toggle('active', active);
        tab.setAttribute('aria-selected', String(active));
    });
    document.getElementById('uploadModePane')?.classList.toggle('active', selectedMode === 'upload');
    const downloadPane = document.getElementById('tab-download');
    if (downloadPane) {
        downloadPane.classList.toggle('active', selectedMode === 'download');
        downloadPane.hidden = selectedMode !== 'download';
    }
}
document.querySelectorAll('.upload-mode-tab').forEach(tab => tab.addEventListener('click', () => activateUploadMode(tab.dataset.uploadMode)));
activateUploadMode('upload');
document.getElementById('refreshDevicesBtn')?.addEventListener('click', () => void loadDevices());

document.getElementById('vaultPinInput').addEventListener('keydown', event => {
    if (event.key !== 'Enter' || event.isComposing) return;
    event.preventDefault();
    document.getElementById('vaultUnlockBtn').click();
});

async function activateVaultUi(vmk, remoteVaultId) {
    document.getElementById('startPairingBtn').style.display = 'none';
    vaultMasterKey = new Uint8Array(vmk);
    if (vmk instanceof Uint8Array) vmk.fill(0);
    vaultId = remoteVaultId;
    let migration;
    try {
        const filesWithPendingKeys = vaultFiles.map(file => {
            if (!file.key && pendingLegacyVaultKeys.has(file.cid)) {
                return { ...file, key: pendingLegacyVaultKeys.get(file.cid) };
            }
            return file;
        });
        migration = await vaultCrypto.migrateLegacyVaultFileKeys(vaultMasterKey, authenticatedUser.id, vaultId, filesWithPendingKeys);
    } catch (error) {
        vaultMasterKey.fill(0);
        vaultMasterKey = null;
        vaultId = null;
        throw error;
    }
    pendingLegacyVaultKeys.clear();
    if (migration.changed) {
        vaultFiles = migration.files;
        saveVaultFiles();
    }
    isVaultUnlocked = true;
    document.getElementById('vaultLockedArea').style.display = 'none';
    document.getElementById('vaultContentArea').style.display = 'block';
    renderVaultFiles();
    const pairingMessage = document.getElementById('vaultPairingMessage');
    if (pairingMessage) pairingMessage.textContent = '';
    await refreshPairingRoleControls();
}

document.getElementById('vaultUnlockBtn').onclick = async () => {
    const pin = document.getElementById('vaultPinInput').value;
    if (!/^\d{4}$/.test(pin)) return alert('PIN-код должен состоять из 4 цифр');
    const saved = localStorage.getItem(`vaultPin_${currentProfile}`), hashed = await hashPin(pin);
    if (!saved) {
        if (!confirm('Создать локальный PIN-код? Он блокирует интерфейс, но сам по себе не шифрует VMK.')) return;
        localStorage.setItem(`vaultPin_${currentProfile}`, hashed);
    } else if (saved !== hashed && saved !== pin) {
        return alert('Неверный PIN-код!');
    } else if (saved === pin) {
        // Compatibility with legacy plaintext PIN storage.
        localStorage.setItem(`vaultPin_${currentProfile}`, hashed);
    }
    try {
        document.getElementById('vaultUnlockBtn').disabled = true;
        const result = await vaultCrypto.unlockVaultForCurrentDevice(authenticatedUser.id);
        await activateVaultUi(result.vmk, result.vaultId);
    } catch (error) {
        const message = document.getElementById('vaultPairingMessage');
        if (message) message.textContent = error.message || 'Не удалось открыть Сейф.';
        if (error.code === 'VAULT_PAIRING_REQUIRED') {
            document.getElementById('startPairingBtn').style.display = 'inline-flex';
        }
    } finally {
        document.getElementById('vaultUnlockBtn').disabled = false;
    }
};
document.getElementById('vaultLockBtn').onclick = () => { isVaultUnlocked = false; if (vaultMasterKey) vaultMasterKey.fill(0); vaultMasterKey = null; vaultId = null; document.getElementById('vaultLockedArea').style.display = 'flex'; document.getElementById('vaultContentArea').style.display = 'none'; document.getElementById('vaultPinInput').value = ''; void refreshPairingRoleControls(); };
document.getElementById('settingsOpenVaultBtn').onclick = () => { document.getElementById('profileModal').style.display = 'none'; document.querySelector('.nav-item[data-tab="vault"]')?.click(); };
for (const id of ['settingsCloseBtn', 'settingsCancelBtn']) document.getElementById(id)?.addEventListener('click', () => { document.getElementById('profileModal').style.display = 'none'; });

const profileMenuWrap = document.getElementById('profileMenuWrap');
const profileMenuTrigger = document.getElementById('profileMenuTrigger');
const profileDropdown = document.getElementById('profileDropdown');
function setProfileMenuOpen(open) {
    if (!profileMenuTrigger || !profileDropdown) return;
    profileMenuTrigger.setAttribute('aria-expanded', open ? 'true' : 'false');
    profileDropdown.hidden = !open;
}
function closeProfileDropdown() { setProfileMenuOpen(false); }
profileMenuTrigger?.addEventListener('click', () => {
    setProfileMenuOpen(profileMenuTrigger.getAttribute('aria-expanded') !== 'true');
});
document.addEventListener('pointerdown', (event) => {
    if (profileMenuWrap && !profileMenuWrap.contains(event.target)) closeProfileDropdown();
});
document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
        closeProfileDropdown();
        if (document.getElementById('profileModal')?.style.display === 'flex') document.getElementById('profileModal').style.display = 'none';
    }
});
for (const id of ['profileSettingsBtn', 'headerSettingsBtn']) {
    document.getElementById(id)?.addEventListener('click', () => {
        closeProfileDropdown();
        openProfileModal();
    });
}

window.copyText = (text) => {
    if (!text) return;
    const fallbackCopy = () => {
        const input = document.createElement('textarea'); input.value = text; input.setAttribute('readonly', '');
        input.style.position = 'fixed'; input.style.opacity = '0'; document.body.appendChild(input); input.select();
        try { document.execCommand('copy'); alert('Скопировано!'); } catch (_) { alert('Не удалось скопировать.'); }
        input.remove();
    };
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(() => alert('Скопировано!')).catch(fallbackCopy);
    else fallbackCopy();
};
document.getElementById('copyProfileBtn')?.addEventListener('click', (event) => {
    event.stopPropagation();
    const value = authenticatedUser?.email || currentProfile;
    if (value) copyText(value);
});

function createMetaRow(icon, shortText, fullText) {
    const row = document.createElement('div');
    row.className = 'drive-item-sub';
    row.style.display = 'flex'; row.style.alignItems = 'center'; row.style.gap = '6px'; row.style.marginTop = '6px';
    const iconSpan = document.createElement('span'); iconSpan.textContent = icon;
    const textSpan = document.createElement('span'); textSpan.textContent = shortText; textSpan.title = fullText; textSpan.style.fontFamily = 'monospace';
    const copyBtn = document.createElement('button'); copyBtn.className = 'mini-copy-btn'; copyBtn.textContent = '📋'; copyBtn.style.padding = '2px 6px'; copyBtn.style.fontSize = '.72rem';
    copyBtn.onclick = event => { event.stopPropagation(); copyText(fullText); };
    row.append(iconSpan, textSpan, copyBtn);
    return row;
}

function createVaultFileCard(file, index) {
    const div = document.createElement('div'); div.className = 'file-item';
    const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.className = 'file-select-checkbox'; checkbox.dataset.cid = file.cid;
    checkbox.checked = selectedVaultFiles.has(file.cid);
    checkbox.onchange = event => { if (event.target.checked) selectedVaultFiles.add(file.cid); else selectedVaultFiles.delete(file.cid); updateBulkUI(true); };
    div.appendChild(checkbox);
    const info = document.createElement('div'); info.className = 'file-info';
    let fileIcon = '📄'; const ext = (file.name || '').split('.').pop().toLowerCase();
    if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) fileIcon = '🖼️'; else if (['rar', 'zip', '7z', 'tar', 'gz'].includes(ext)) fileIcon = '📦'; else if (['mp3', 'wav', 'ogg'].includes(ext)) fileIcon = '🎵'; else if (['mp4', 'mkv', 'avi'].includes(ext)) fileIcon = '🎬'; else if (ext === 'pdf') fileIcon = '📕';
    const nameEl = document.createElement('strong'); nameEl.textContent = `${fileIcon} ${file.name}`; info.appendChild(nameEl);
    const shortCid = file.cid.substring(0, 8) + '...' + file.cid.substring(file.cid.length - 4); info.appendChild(createMetaRow('🔗', shortCid, file.cid));
    if (file.vaultKeyEnvelope?.format_id === 'vault-file-key-v1') {
        const protectedKey = document.createElement('div'); protectedKey.style.cssText = 'color:var(--success); font-size:.8rem; margin-top:6px;'; protectedKey.textContent = '🔒 Ключ защищён мастер-ключом Сейфа (VMK)'; info.appendChild(protectedKey);
    } else if (!file.key) {
        const noKey = document.createElement('div'); noKey.style.cssText = 'color:var(--danger); font-size:.8rem; margin-top:6px;'; noKey.textContent = '🔒 нет ключа (только метаданные)'; info.appendChild(noKey);
    }
    div.appendChild(info);
    const actions = document.createElement('div'); actions.className = 'file-actions';
    const downloadBtn = document.createElement('button'); downloadBtn.className = 'secondary-btn'; downloadBtn.textContent = '⬇ Скачать'; downloadBtn.onclick = () => downloadFileRecord(file, true); actions.appendChild(downloadBtn);
    const delBtn = document.createElement('button'); delBtn.className = 'danger-btn'; delBtn.textContent = '🗑 Удалить';
    delBtn.onclick = () => { selectedVaultFiles.clear(); selectedVaultFiles.add(file.cid); void deleteSelected(true); };
    actions.appendChild(delBtn); div.append(info, actions); return div;
}

function formatBytes(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return 'Размер неизвестен';
    if (bytes < 1024) return `${bytes} Б`;
    const units = ['КБ', 'МБ', 'ГБ', 'ТБ']; let size = bytes / 1024, unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
    return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unit]}`;
}

function getDriveItemByKey(key) {
    if (typeof key !== 'string') return null;
    if (key.startsWith('folder:')) return myFiles.find(item => isFolderRecord(item) && item.id === key.slice(7)) || null;
    if (key.startsWith('file:')) return myFiles.find(item => !isFolderRecord(item) && item.cid === key.slice(5)) || null;
    return null;
}

function isDriveNameTaken(name, parentId, exceptKey = null) {
    const normalized = name.toLocaleLowerCase('ru');
    return myFiles.some(item => driveItemKey(item) !== exceptKey && (item.parentId || null) === (parentId || null) && String(item.name || '').toLocaleLowerCase('ru') === normalized);
}

function createDriveFolder(name, parentId = null) {
    const safeName = normalizeDriveName(name, 'Имя папки');
    if (isDriveNameTaken(safeName, parentId)) throw new Error('В этой папке уже есть элемент с таким именем.');
    const now = new Date().toISOString();
    const folder = { id: crypto.randomUUID(), type: 'folder', name: safeName, parentId: parentId || null, createdAt: now, updatedAt: now };
    myFiles.push(folder);
    return folder;
}

function renderDriveBreadcrumbs() {
    const root = document.getElementById('driveBreadcrumbs');
    root.replaceChildren();
    let path = [];
    try { path = getDriveFolderPath(myFiles, myDriveCurrentFolderId); } catch (_) { myDriveCurrentFolderId = null; path = []; }
    const crumbs = [{ id: null, name: 'Мой диск' }, ...path.map(item => ({ id: item.id, name: item.name }))];
    crumbs.forEach((crumb, index) => {
        if (index > 0) { const sep = document.createElement('span'); sep.className = 'crumb-separator'; sep.textContent = '›'; root.appendChild(sep); }
        const button = document.createElement('button'); button.textContent = crumb.name;
        if (index === crumbs.length - 1) { button.disabled = true; button.setAttribute('aria-current', 'page'); }
        else button.onclick = () => { myDriveCurrentFolderId = crumb.id; selectedMyFiles.clear(); renderFiles(); };
        root.appendChild(button);
    });
}

function getDriveDisplayItems() {
    const query = document.getElementById('driveSearchInput')?.value.trim().toLocaleLowerCase('ru') || '';
    const source = query ? myFiles : getDriveChildren(myFiles, myDriveCurrentFolderId);
    const filtered = source.filter(item => !query || String(item.name || '').toLocaleLowerCase('ru').includes(query));
    return filtered.sort((a, b) => Number(isFolderRecord(b)) - Number(isFolderRecord(a)) || String(a.name || '').localeCompare(String(b.name || ''), 'ru', { sensitivity: 'base' }));
}

function createDriveItemIcon(item, folder) {
    // Inline SVG keeps the UI self-contained. To switch to asset files later, replace this
    // SVG node with: const img = document.createElement('img'); img.src = 'assets/icons/...svg';
    const ext = String(item.name || '').split('.').pop().toLowerCase();
    const kind = folder ? 'folder' : (ext === 'zip' || ['rar', '7z', 'tar', 'gz'].includes(ext) ? 'archive'
        : (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(ext) ? 'image'
        : (ext === 'pdf' ? 'pdf' : 'file')));
    const shell = document.createElement('div');
    shell.className = `drive-item-icon drive-icon-${kind}`;
    shell.dataset.kind = kind;
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 64 64');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    const paths = {
        folder: '<path d="M7 18.5A5.5 5.5 0 0 1 12.5 13H26l6 7h19.5A5.5 5.5 0 0 1 57 25.5v22a6.5 6.5 0 0 1-6.5 6.5h-37A6.5 6.5 0 0 1 7 47.5z" fill="currentColor" opacity=".2"/><path d="M7 25a5 5 0 0 1 5-5h40a5 5 0 0 1 5 5v22a7 7 0 0 1-7 7H14a7 7 0 0 1-7-7z" fill="currentColor"/><path d="M8 27h48" stroke="white" stroke-opacity=".35" stroke-width="2"/>',
        file: '<path d="M17 7h20l12 12v35a4 4 0 0 1-4 4H17a4 4 0 0 1-4-4V11a4 4 0 0 1 4-4" fill="currentColor" opacity=".2"/><path d="M37 7v12h12" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M18 7h19l12 12v35a4 4 0 0 1-4 4H17a4 4 0 0 1-4-4V11a4 4 0 0 1 5-4" fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round"/><path d="M22 34h20M22 42h20" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>',
        image: '<rect x="9" y="12" width="46" height="40" rx="7" fill="currentColor" opacity=".18"/><rect x="9" y="12" width="46" height="40" rx="7" fill="none" stroke="currentColor" stroke-width="3"/><circle cx="23" cy="25" r="5" fill="currentColor"/><path d="m13 46 13-13 8 8 7-7 11 12" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>',
        archive: '<path d="M13 10h38v44H13z" fill="currentColor" opacity=".18"/><path d="M13 10h38v44H13zM26 10v44M38 10v44" fill="none" stroke="currentColor" stroke-width="3"/><path d="M30 24h4m-4 8h4m-4 8h4" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>',
        pdf: '<path d="M17 7h20l12 12v35a4 4 0 0 1-4 4H17a4 4 0 0 1-4-4V11a4 4 0 0 1 4-4" fill="currentColor" opacity=".18"/><path d="M37 7v12h12M17 7h20l12 12v35a4 4 0 0 1-4 4H17a4 4 0 0 1-4-4V11a4 4 0 0 1 4-4z" fill="none" stroke="currentColor" stroke-width="3"/><path d="M20 39h24M20 46h19" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>'
    };
    svg.innerHTML = paths[kind] || paths.file;
    shell.appendChild(svg);
    return shell;
}

function openDriveItem(item) {
    if (isFolderRecord(item)) {
        myDriveCurrentFolderId = item.id;
        selectedMyFiles.clear();
        renderFiles();
    } else if (/\.zip$/i.test(item.name || '')) {
        void openZipArchive(item);
    } else {
        void openDriveFile(item);
    }
}

function createDriveItemCard(item) {
    const folder = isFolderRecord(item), selectionKey = driveItemKey(item);
    const card = document.createElement('article');
    card.className = `file-item drive-item${folder ? ' drive-item-folder' : ''}`;
    card.dataset.itemKey = selectionKey;
    card.tabIndex = 0;
    card.setAttribute('role', 'group');
    card.setAttribute('aria-label', `${folder ? 'Папка' : 'Файл'}: ${item.name || 'Без имени'}`);

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'drive-item-checkbox';
    checkbox.checked = selectedMyFiles.has(selectionKey);
    checkbox.setAttribute('aria-label', `Выбрать ${item.name}`);
    checkbox.onchange = event => {
        if (event.target.checked) selectedMyFiles.add(selectionKey);
        else selectedMyFiles.delete(selectionKey);
        card.classList.toggle('is-selected', event.target.checked);
        updateBulkUI(false);
    };
    card.appendChild(checkbox);
    card.classList.toggle('is-selected', checkbox.checked);

    const main = document.createElement('div');
    main.className = 'drive-item-main';
    const icon = createDriveItemIcon(item, folder);
    const copy = document.createElement('div');
    copy.className = 'drive-item-copy';
    const title = document.createElement('strong');
    title.textContent = item.name || 'Без имени';
    copy.appendChild(title);
    const sub = document.createElement('div');
    sub.className = 'drive-item-sub';
    if (folder) {
        const count = collectFolderContents(myFiles, item.id).files.length;
        sub.textContent = `${count} ${count === 1 ? 'файл' : count < 5 ? 'файла' : 'файлов'}`;
        if (document.getElementById('driveSearchInput')?.value.trim()) {
            const parentPath = getDriveFolderPath(myFiles, item.id).slice(0, -1).map(part => part.name).join(' / ');
            if (parentPath) sub.textContent += ` · ${parentPath}`;
        }
    } else {
        sub.textContent = `${formatBytes(item.size)}${item.isImported ? ' · получен от другого устройства' : ''}`;
        if (document.getElementById('driveSearchInput')?.value.trim()) {
            const parentPath = getDriveFolderPath(myFiles, item.parentId).map(part => part.name).join(' / ');
            if (parentPath) sub.textContent += ` · ${parentPath}`;
        }
        if (item.cid) {
            const cidLine = document.createElement('span');
            cidLine.className = 'drive-item-cid';
            cidLine.textContent = `CID: ${item.cid.slice(0, 8)}…${item.cid.slice(-4)}`;
            cidLine.title = item.cid;
            sub.appendChild(document.createElement('br'));
            sub.appendChild(cidLine);
        }
    }
    copy.appendChild(sub);
    main.append(icon, copy);
    card.appendChild(main);

    const open = event => {
        if (event.target.closest('input, button, a, label')) return;
        openDriveItem(item);
    };
    card.addEventListener('click', open);
    card.addEventListener('keydown', event => {
        if ((event.key === 'Enter' || event.key === ' ') && event.target === card) {
            event.preventDefault();
            openDriveItem(item);
        }
    });
    card.title = folder ? 'Открыть папку' : (/\.zip$/i.test(item.name || '') ? 'Открыть архив' : 'Открыть файл');
    return card;
}

function updateBulkUI(isVault) {
    const selectedSet = isVault ? selectedVaultFiles : selectedMyFiles;
    const bulkPanel = document.getElementById(isVault ? 'vaultBulkActions' : 'myFilesBulkActions');
    const countSpan = document.getElementById(isVault ? 'vaultSelectedCount' : 'myFilesSelectedCount');
    if (selectedSet.size > 0) { bulkPanel.style.display = 'flex'; countSpan.textContent = `Выбрано: ${selectedSet.size}`; }
    else bulkPanel.style.display = 'none';
    if (!isVault) {
        const renameButton = document.getElementById('myFilesRenameSelectedBtn');
        const selectedItems = getSelectedDriveItems();
        if (renameButton) {
            renameButton.disabled = selectedItems.length !== 1;
            renameButton.title = selectedItems.length === 1 ? 'Переименовать выбранный элемент' : 'Для переименования выберите один элемент';
        }
        const shareButton = document.getElementById('myFilesShareSelectedBtn');
        if (shareButton) {
            const canShare = selectedItems.length === 1 && !isFolderRecord(selectedItems[0]) && Boolean(selectedItems[0].cid && selectedItems[0].key);
            shareButton.disabled = !canShare;
            shareButton.title = canShare ? 'Создать QR-код доступа к файлу' : 'Выберите один файл с ключом доступа';
        }
    }
    if (isVault) {
        const selectAll = document.getElementById('selectAllVault');
        if (selectAll) selectAll.checked = vaultFiles.length > 0 && selectedSet.size === vaultFiles.length;
    } else {
        const visible = getDriveDisplayItems();
        const keys = visible.map(driveItemKey);
        const selectAll = document.getElementById('selectAllMyFiles');
        if (selectAll) selectAll.checked = keys.length > 0 && keys.every(key => selectedSet.has(key));
    }
}

document.getElementById('selectAllMyFiles').onchange = event => {
    const visible = getDriveDisplayItems();
    if (event.target.checked) visible.forEach(item => selectedMyFiles.add(driveItemKey(item)));
    else visible.forEach(item => selectedMyFiles.delete(driveItemKey(item)));
    renderFiles();
};
document.getElementById('selectAllVault').onchange = event => { if (event.target.checked) vaultFiles.forEach(file => selectedVaultFiles.add(file.cid)); else selectedVaultFiles.clear(); renderVaultFiles(); updateBulkUI(true); };
document.getElementById('myFilesClearSelectionBtn').onclick = () => { selectedMyFiles.clear(); renderFiles(); };
document.getElementById('vaultClearSelectionBtn').onclick = () => { selectedVaultFiles.clear(); renderVaultFiles(); updateBulkUI(true); };

function getSelectedDriveItems() { return [...selectedMyFiles].map(getDriveItemByKey).filter(Boolean); }

async function deleteSelected(isVault) {
    const selectedSet = isVault ? selectedVaultFiles : selectedMyFiles, targetArray = isVault ? vaultFiles : myFiles;
    if (selectedSet.size === 0) return;
    if (isVault) {
        if (!confirm(`Удалить выбранные (${selectedSet.size})?`)) return;
        const cidsToDelete = [];
        for (let i = targetArray.length - 1; i >= 0; i--) if (selectedSet.has(targetArray[i].cid)) { cidsToDelete.push(targetArray[i].cid, ...(targetArray[i].chunkCids || [])); targetArray.splice(i, 1); }
        markDeletedCids(cidsToDelete); selectedSet.clear(); saveVaultFiles(); updateBulkUI(true);
        for (const cid of cidsToDelete) { try { const headers = await ipfsRequestHeaders(); await fetch(`${IPFS_API}/pin/rm?arg=${encodeURIComponent(cid)}`, { method: 'POST', headers, credentials: 'include' }); } catch (_) {} }
        if (!isNativeClient()) fetch(`${IPFS_API}/repo/gc`, { method: 'POST' }).catch(() => {}); localPinsCache = null; return;
    }

    const selected = getSelectedDriveItems();
    if (!selected.length) return;
    const selectedFolderIds = new Set(selected.filter(isFolderRecord).map(folder => folder.id));
    const roots = selected.filter(item => !item.parentId || !selectedFolderIds.has(item.parentId));
    const foldersToDelete = new Set(), filesToDelete = new Map();
    for (const item of roots) {
        if (isFolderRecord(item)) {
            const contents = collectFolderContents(myFiles, item.id);
            contents.folderIds.forEach(id => foldersToDelete.add(id));
            contents.files.forEach(file => filesToDelete.set(file.cid, file));
        } else if (item.cid) filesToDelete.set(item.cid, item);
    }
    const count = foldersToDelete.size + filesToDelete.size;
    if (!confirm(`Удалить выбранные элементы и их содержимое (${count})?`)) return;
    const cidsToDelete = [];
    for (const file of filesToDelete.values()) cidsToDelete.push(file.cid, ...(file.chunkCids || []));
    myFiles = myFiles.filter(item => isFolderRecord(item) ? !foldersToDelete.has(item.id) : !filesToDelete.has(item.cid));
    markDeletedCids(cidsToDelete); markDeletedFolderIds([...foldersToDelete]);
    selectedMyFiles.clear(); saveFiles();
    for (const cid of cidsToDelete) { try { const headers = await ipfsRequestHeaders(); await fetch(`${IPFS_API}/pin/rm?arg=${encodeURIComponent(cid)}`, { method: 'POST', headers }); } catch (_) {} }
    if (!isNativeClient()) fetch(`${IPFS_API}/repo/gc`, { method: 'POST' }).catch(() => {}); localPinsCache = null;
}

document.getElementById('myFilesDeleteSelectedBtn').onclick = () => void deleteSelected(false);
document.getElementById('vaultDeleteSelectedBtn').onclick = () => void deleteSelected(true);
document.getElementById('myFilesDownloadSelectedBtn').onclick = () => void downloadSelectedDriveItems();
document.getElementById('myFilesShareSelectedBtn').onclick = () => { const selected = getSelectedDriveItems(); if (selected.length === 1 && !isFolderRecord(selected[0]) && selected[0].cid && selected[0].key) showQR(selected[0].cid, selected[0].key); };
document.getElementById('myFilesMoveSelectedBtn').onclick = () => openDriveMoveDialog();
document.getElementById('myFilesRenameSelectedBtn').onclick = () => { const selected = getSelectedDriveItems(); if (selected.length === 1) void renameDriveItem(selected[0]); };

async function renderFiles() {
    renderDriveBreadcrumbs();
    const list = document.getElementById('filesList');
    list.classList.toggle('list-view', driveViewMode === 'list');
    const items = getDriveDisplayItems();
    list.replaceChildren();
    if (!items.length) {
        const empty = document.createElement('div'); empty.className = 'drive-empty';
        const icon = document.createElement('span'); icon.className = 'empty-icon'; icon.textContent = document.getElementById('driveSearchInput')?.value.trim() ? '🔎' : '☁️';
        const title = document.createElement('strong'); title.textContent = document.getElementById('driveSearchInput')?.value.trim() ? 'Ничего не найдено' : 'Здесь пока пусто';
        const note = document.createElement('p'); note.textContent = document.getElementById('driveSearchInput')?.value.trim() ? 'Попробуйте изменить поисковый запрос.' : 'Создайте папку или загрузите файлы, чтобы начать.';
        empty.append(icon, title, note); list.appendChild(empty);
    } else items.forEach(item => list.appendChild(createDriveItemCard(item)));
    updateBulkUI(false);
    const viewButton = document.getElementById('driveViewToggleBtn');
    if (viewButton) { viewButton.innerHTML = driveViewMode === 'grid' ? '<span class="tool-glyph">≡</span><span>Список</span>' : '<span class="tool-glyph">▦</span><span>Сетка</span>'; viewButton.title = driveViewMode === 'grid' ? 'Переключить на список' : 'Переключить на сетку'; }
}

async function renderVaultFiles() {
    const list = document.getElementById('vaultList');
    if (vaultFiles.length === 0) { list.innerHTML = '<p style="color:var(--text-muted);">В Сейфе пока нет файлов.</p>'; document.getElementById('vaultBulkActions').style.display = 'none'; return; }
    list.replaceChildren(); vaultFiles.forEach((file, index) => list.appendChild(createVaultFileCard(file, index))); updateBulkUI(true);
}

async function renameDriveItem(item) {
    const entered = prompt(`Новое имя для «${item.name}»:`, item.name);
    if (entered === null) return;
    try {
        const name = normalizeDriveName(entered, 'Имя');
        if (isDriveNameTaken(name, item.parentId, driveItemKey(item))) throw new Error('В этой папке уже есть элемент с таким именем.');
        item.name = name; item.updatedAt = new Date().toISOString();
        saveFiles();
    } catch (error) { alert(error.message); }
}

function openDriveMoveDialog() {
    const selected = getSelectedDriveItems();
    if (!selected.length) return alert('Сначала выберите файлы или папки.');
    const select = document.getElementById('driveMoveDestination'); select.replaceChildren();
    const rootOption = document.createElement('option'); rootOption.value = ''; rootOption.textContent = 'Мой диск'; select.appendChild(rootOption);
    const folders = myFiles.filter(isFolderRecord).sort((a, b) => a.name.localeCompare(b.name, 'ru'));
    for (const folder of folders) {
        const option = document.createElement('option'); option.value = folder.id;
        option.textContent = [...getDriveFolderPath(myFiles, folder.id).map(part => part.name)].join(' / ');
        const selectedFolders = selected.filter(isFolderRecord);
        option.disabled = selectedFolders.some(item => !canMoveFolder(myFiles, item.id, folder.id));
        select.appendChild(option);
    }
    document.getElementById('driveMoveModal').style.display = 'flex';
}

document.getElementById('driveMoveCancelBtn').onclick = () => { document.getElementById('driveMoveModal').style.display = 'none'; };
document.getElementById('driveMoveConfirmBtn').onclick = () => {
    let selected = getSelectedDriveItems();
    const selectedFolders = new Set(selected.filter(isFolderRecord).map(item => item.id));
    selected = selected.filter(item => { let parent = item.parentId; while (parent) { if (selectedFolders.has(parent)) return false; const folder = myFiles.find(value => isFolderRecord(value) && value.id === parent); parent = folder?.parentId || null; } return true; });
    const targetParentId = document.getElementById('driveMoveDestination').value || null;
    try {
        for (const item of selected) {
            if (isFolderRecord(item) && !canMoveFolder(myFiles, item.id, targetParentId)) throw new Error('Нельзя переместить папку внутрь самой себя или её вложенной папки.');
            if (isDriveNameTaken(item.name, targetParentId, driveItemKey(item))) throw new Error(`В папке назначения уже есть «${item.name}».`);
        }
        for (const item of selected) { item.parentId = targetParentId; item.updatedAt = new Date().toISOString(); }
        selectedMyFiles.clear(); document.getElementById('driveMoveModal').style.display = 'none'; saveFiles();
    } catch (error) { alert(error.message); }
};

document.getElementById('driveNewFolderBtn').onclick = () => {
    const entered = prompt('Название новой папки:'); if (entered === null) return;
    try { createDriveFolder(entered, myDriveCurrentFolderId); saveFiles(); }
    catch (error) { alert(error.message); }
};
document.addEventListener('click', event => {
    document.querySelectorAll('.drive-more-menu[open]').forEach(menu => { if (!menu.contains(event.target)) menu.open = false; });
});
document.getElementById('driveSearchInput').oninput = () => { selectedMyFiles.clear(); renderFiles(); };
document.getElementById('driveViewToggleBtn').onclick = () => { driveViewMode = driveViewMode === 'grid' ? 'list' : 'grid'; localStorage.setItem('secureDiskDriveView', driveViewMode); renderFiles(); };

async function openDriveFile(file) {
    if (!file?.cid) return;
    if (/\.zip$/i.test(file.name || '')) return openZipArchive(file);
    // Avoid buffering very large objects in a preview tab.
    if (Number(file.size) > 50 * 1024 * 1024) return downloadFileRecord(file, false);
    const previewWindow = window.open('about:blank', '_blank');
    if (!previewWindow) return downloadFileRecord(file, false);
    try {
        previewWindow.document.title = 'NODEX — открытие файла';
        previewWindow.document.body.textContent = 'Расшифровываем файл…';
        previewWindow.opener = null;
        const blob = await decryptFileToBlob(file, false);
        const previewable = /^(?:image\/(?:png|jpeg|gif|webp|avif)|audio\/|video\/|text\/plain|application\/pdf)$/i.test(blob.type || '');
        if (!previewable) {
            previewWindow.close();
            downloadBlob(blob, file.name || 'download');
            return;
        }
        const objectUrl = URL.createObjectURL(blob);
        previewWindow.location.replace(objectUrl);
        previewWindow.addEventListener('pagehide', () => URL.revokeObjectURL(objectUrl), { once: true });
    } catch (error) {
        try { previewWindow.close(); } catch (_) { }
        alert(error.message || 'Не удалось открыть файл.');
    }
}

function downloadBlob(blob, fileName) {
    const url = URL.createObjectURL(blob), anchor = document.createElement('a'); anchor.href = url; anchor.download = fileName;
    document.body.appendChild(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadFileRecord(file, isVault = false) {
    if (!file?.cid) return;
    document.getElementById('downloadCid').value = file.cid;
    document.getElementById('downloadKey').value = isVault ? '' : (file.key || '');
    void performDownload(false);
}

async function downloadSelectedDriveItems() {
    const selected = getSelectedDriveItems(); if (!selected.length) return;
    if (selected.length === 1 && !isFolderRecord(selected[0])) return downloadFileRecord(selected[0], false);
    const zip = new JSZip(); const filesByCid = new Map();
    const selectedFolderIds = new Set(selected.filter(isFolderRecord).map(item => item.id));
    const topLevelSelection = selected.filter(item => {
        let parentId = item.parentId || null;
        while (parentId) {
            if (selectedFolderIds.has(parentId)) return false;
            const parent = myFiles.find(candidate => isFolderRecord(candidate) && candidate.id === parentId);
            parentId = parent?.parentId || null;
        }
        return true;
    });
    for (const item of topLevelSelection) {
        if (isFolderRecord(item)) {
            const contents = collectFolderContents(myFiles, item.id);
            for (const childFolder of contents.folders) {
                const relative = getRelativeFolderPath(myFiles, item.id, childFolder.id);
                zip.folder(relative ? `${item.name}/${relative}` : item.name);
            }
            for (const file of contents.files) filesByCid.set(file.cid, { file, path: `${item.name}/${getRelativePath(myFiles, item.id, file)}` });
        } else if (item.cid) filesByCid.set(item.cid, { file: item, path: item.name });
    }
    if (filesByCid.size > 2000) return alert('Слишком много файлов для одной ZIP-выгрузки. Выберите меньше элементов.');
    const totalSize = [...filesByCid.values()].reduce((sum, value) => sum + (Number(value.file.size) || 0), 0);
    if (totalSize > MAX_ZIP_SIZE) return alert('Для ZIP-выгрузки пока действует ограничение 100 МБ. Загружайте большие файлы по отдельности.');
    try {
        let index = 0;
        for (const { file, path } of filesByCid.values()) {
            if (!isSafeArchivePath(path)) throw new Error('Обнаружен небезопасный путь файла.');
            const blob = await decryptFileToBlob(file, false); zip.file(path, blob); index++;
        }
        const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 3 } });
        downloadBlob(blob, selected.length === 1 ? `${selected[0].name}.zip` : 'nodex-selection.zip');
    } catch (error) { alert('Не удалось собрать ZIP: ' + error.message); }
}

async function downloadDriveFolderAsZip(folderId) {
    const folder = myFiles.find(item => isFolderRecord(item) && item.id === folderId);
    if (!folder) return;
    const contents = collectFolderContents(myFiles, folderId);
    if (contents.files.length > 2000) return alert('В папке слишком много файлов для ZIP-выгрузки.');
    const totalSize = contents.files.reduce((sum, file) => sum + (Number(file.size) || 0), 0);
    if (totalSize > MAX_ZIP_SIZE) return alert('Для ZIP-выгрузки пока действует ограничение 100 МБ.');
    const zip = new JSZip();
    try {
        for (const childFolder of contents.folders) {
            const relative = getRelativeFolderPath(myFiles, folderId, childFolder.id);
            zip.folder(relative ? `${folder.name}/${relative}` : folder.name);
        }
        for (const file of contents.files) {
            const path = getRelativePath(myFiles, folderId, file);
            if (!isSafeArchivePath(path)) throw new Error('Обнаружен небезопасный путь файла.');
            zip.file(`${folder.name}/${path}`, await decryptFileToBlob(file, false));
        }
        const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 3 } });
        downloadBlob(blob, `${folder.name}.zip`);
    } catch (error) { alert('Не удалось собрать ZIP папки: ' + error.message); }
}

async function openZipArchive(file) {
    if (!file?.cid) return;
    if (Number(file.size) > MAX_ZIP_SIZE) return alert('Просмотр ZIP в браузере пока ограничен 100 МБ. Большие архивы можно скачать целиком.');
    const modal = document.getElementById('zipBrowserModal');
    const list = document.getElementById('zipBrowserList');
    list.textContent = 'Загружаем и расшифровываем архив…'; modal.style.display = 'flex';
    try {
        const blob = await decryptFileToBlob(file, false);
        if (blob.size > MAX_ZIP_SIZE) throw new Error('Размер ZIP превышает ограничение 100 МБ.');
        const zip = await JSZip.loadAsync(blob, { checkCRC32: false, createFolders: false });
        const entries = Object.values(zip.files);
        if (entries.length > 10000) throw new Error('В архиве слишком много элементов (лимит 10 000).');
        const totalUncompressed = entries.reduce((sum, entry) => sum + (Number(entry._data?.uncompressedSize) || 0), 0);
        if (totalUncompressed > 500 * 1024 * 1024) throw new Error('Распакованный размер архива превышает ограничение 500 МБ.');
        zipViewerState = { zip, file, path: '', totalUncompressed };
        document.getElementById('zipBrowserTitle').textContent = file.name;
        document.getElementById('zipBrowserDescription').textContent = `${entries.length} элементов · архив расшифрован только в памяти браузера`;
        renderZipBrowser();
    } catch (error) {
        zipViewerState = null; list.textContent = 'Не удалось открыть архив: ' + error.message;
    }
}

function renderZipBrowser() {
    if (!zipViewerState) return;
    const { zip, path } = zipViewerState;
    const crumbs = document.getElementById('zipBrowserBreadcrumbs'); crumbs.replaceChildren();
    const pathParts = path ? path.split('/').filter(Boolean) : [];
    const levels = [{ label: zipViewerState.file.name, path: '' }];
    let acc = '';
    for (const part of pathParts) { acc += `${part}/`; levels.push({ label: part, path: acc }); }
    levels.forEach((crumb, index) => {
        if (index) { const sep = document.createElement('span'); sep.className = 'crumb-separator'; sep.textContent = '›'; crumbs.appendChild(sep); }
        const button = document.createElement('button'); button.textContent = crumb.label; button.disabled = index === levels.length - 1;
        button.onclick = () => { zipViewerState.path = crumb.path; renderZipBrowser(); }; crumbs.appendChild(button);
    });
    const list = document.getElementById('zipBrowserList'); list.replaceChildren();
    const children = listArchiveChildren(Object.values(zip.files), path);
    if (!children.length) { const empty = document.createElement('div'); empty.className = 'zip-entry-empty'; empty.textContent = 'В этой папке нет элементов.'; list.appendChild(empty); return; }
    for (const item of children) {
        const row = document.createElement('div'); row.className = 'zip-entry';
        const icon = document.createElement('span'); icon.textContent = item.dir ? '📁' : '📄';
        const name = document.createElement('span'); name.className = 'zip-entry-name'; name.textContent = item.name;
        row.append(icon, name);
        if (item.dir) {
            const open = document.createElement('button'); open.className = 'zip-entry-open'; open.textContent = 'Открыть'; open.onclick = () => { zipViewerState.path = item.path; renderZipBrowser(); }; row.appendChild(open);
        } else {
            const entry = item.entry;
            const size = document.createElement('span'); size.className = 'zip-entry-meta'; size.textContent = formatBytes(entry?._data?.uncompressedSize || 0); row.appendChild(size);
            const download = document.createElement('button'); download.className = 'secondary-btn zip-entry-download'; download.textContent = 'Скачать';
            download.onclick = async () => {
                try {
                    const expected = Number(entry?._data?.uncompressedSize) || 0;
                    if (expected > 100 * 1024 * 1024) throw new Error('Размер отдельного файла превышает лимит 100 МБ.');
                    const payload = await entry.async('blob');
                    if (payload.size > 100 * 1024 * 1024) throw new Error('Фактический размер файла превышает лимит 100 МБ.');
                    downloadBlob(payload, item.name.replace(/[\\/:*?"<>|]/g, '_'));
                } catch (error) { alert('Не удалось извлечь файл из ZIP: ' + error.message); }
            };
            row.appendChild(download);
        }
        list.appendChild(row);
    }
}

document.getElementById('zipBrowserCloseBtn').onclick = () => { document.getElementById('zipBrowserModal').style.display = 'none'; zipViewerState = null; };

document.getElementById('driveMoveModal').addEventListener('click', event => { if (event.target.id === 'driveMoveModal') event.currentTarget.style.display = 'none'; });
document.getElementById('zipBrowserModal').addEventListener('click', event => { if (event.target.id === 'zipBrowserModal') { event.currentTarget.style.display = 'none'; zipViewerState = null; } });

function showQR(cid, key) { try { const qr = qrcode(0, 'M'); qr.addData(`CID: ${cid}\nKEY: ${key}`); qr.make(); const svg = qr.createSvgTag(4, 10); document.getElementById('qrContainer').innerHTML = svg; document.getElementById('qrModal').style.display = 'flex'; } catch (e) { alert('Ошибка QR: ' + e.message); } }

document.getElementById('exportBtn').onclick = () => { if (myFiles.length === 0) return alert('Нет файлов'); const blob = new Blob([JSON.stringify(myFiles, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob), a = document.createElement('a'); a.href = url; a.download = `secure_disk_access.json`; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); };
document.getElementById('importBtn').onclick = () => document.getElementById('importFileInput').click();
document.getElementById('importFileInput').onchange = (e) => {
    const file = e.target.files[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
        try { const importedData = JSON.parse(event.target.result); if (!Array.isArray(importedData)) throw new Error('Неверный формат'); let count = 0; importedData.forEach(item => { if (item.name && item.cid && item.key) { const existing = myFiles.find(f => f.cid === item.cid); if (!existing) { myFiles.push({ ...item, isImported: true }); count++; } else if (!existing.key) { existing.key = item.key; count++; } } }); if (count > 0) { saveFiles(); alert(`Доступ к файлам: ${count}`); myFiles.slice(-count).forEach(f => broadcastNewFile(f, false)); } else alert('Новых файлов не найдено.'); } catch (err) { alert('Ошибка: ' + err.message); }
    };
    reader.readAsText(file); e.target.value = '';
};

let uploadQueue = [], isUploading = false;
const dropZone = document.getElementById('dropZone'), fileInput = document.getElementById('fileInput'), folderInput = document.getElementById('folderInput');
dropZone.onclick = () => fileInput.click();
dropZone.ondragover = event => { event.preventDefault(); dropZone.classList.add('dragover'); };
dropZone.ondragleave = () => dropZone.classList.remove('dragover');

async function readEntryFile(entry) {
    return new Promise((resolve, reject) => entry.file(resolve, reject));
}

async function readDirectoryEntries(directoryEntry) {
    const reader = directoryEntry.createReader();
    const entries = [];
    while (true) {
        const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
        if (!batch.length) break;
        entries.push(...batch);
    }
    return entries;
}

async function collectDroppedDirectory(entry, relativePrefix = '') {
    const result = { files: [], directories: [] };
    if (entry.isFile) {
        const file = await readEntryFile(entry);
        result.files.push({ file, relativePath: `${relativePrefix}${entry.name}` });
        return result;
    }
    if (!entry.isDirectory) return result;
    const currentPath = relativePrefix ? `${relativePrefix}${entry.name}` : entry.name;
    result.directories.push(currentPath);
    for (const child of await readDirectoryEntries(entry)) {
        const childResult = await collectDroppedDirectory(child, `${currentPath}/`);
        result.files.push(...childResult.files);
        result.directories.push(...childResult.directories);
    }
    return result;
}

async function collectFolderTask(task) {
    if (Array.isArray(task.files)) {
        return {
            files: task.files.map(item => item instanceof File
                ? { file: item, relativePath: item.webkitRelativePath.split('/').slice(1).join('/') || item.name }
                : { file: item.file, relativePath: item.relativePath || item.file?.name }).filter(item => item.file),
            directories: task.directories || [],
        };
    }
    if (task.entry?.isDirectory) {
        const tree = await collectDroppedDirectory(task.entry);
        return { files: tree.files.map(item => ({ ...item, relativePath: item.relativePath.slice(task.name.length + 1) })), directories: tree.directories.map(path => path === task.name ? '' : path.slice(task.name.length + 1)).filter(Boolean) };
    }
    return { files: [], directories: [] };
}

dropZone.ondrop = async event => {
    event.preventDefault(); dropZone.classList.remove('dragover');
    const items = event.dataTransfer.items;
    if (!items) return;
    const tasks = [];
    for (let index = 0; index < items.length; index++) {
        const entry = items[index].webkitGetAsEntry?.();
        if (entry?.isDirectory) {
            tasks.push({ type: 'folder', entry, name: entry.name });
        } else if (entry?.isFile) {
            const file = await readEntryFile(entry); tasks.push({ type: 'file', file, name: file.name });
        } else {
            const file = items[index].getAsFile?.(); if (file) tasks.push({ type: 'file', file, name: file.name });
        }
    }
    if (tasks.length) queueUploads(tasks);
};
fileInput.onchange = () => { if (fileInput.files.length) queueUploads(Array.from(fileInput.files).map(file => ({ type: 'file', file, name: file.name }))); fileInput.value = ''; };
folderInput.onchange = () => {
    if (folderInput.files.length) {
        const groups = new Map();
        for (const file of folderInput.files) {
            const parts = file.webkitRelativePath.split('/'); const root = parts.shift() || 'Папка';
            if (!groups.has(root)) groups.set(root, []);
            groups.get(root).push({ file, relativePath: parts.join('/') || file.name });
        }
        queueUploads([...groups.entries()].map(([name, files]) => ({ type: 'folder', files, name })));
    }
    folderInput.value = '';
};

const driveFileInput = document.getElementById('driveFileInput');
const driveFolderInput = document.getElementById('driveFolderInput');
document.getElementById('driveUploadBtn').onclick = () => driveFileInput.click();
document.getElementById('driveUploadFolderBtn').onclick = () => driveFolderInput.click();
driveFileInput.onchange = () => {
    if (driveFileInput.files.length) queueUploads(Array.from(driveFileInput.files).map(file => ({ type: 'file', file, name: file.name })), { isVault: false, parentId: myDriveCurrentFolderId });
    driveFileInput.value = '';
};
driveFolderInput.onchange = () => {
    if (driveFolderInput.files.length) {
        const groups = new Map();
        for (const file of driveFolderInput.files) {
            const parts = file.webkitRelativePath.split('/'); const root = parts.shift() || 'Папка';
            if (!groups.has(root)) groups.set(root, []);
            groups.get(root).push({ file, relativePath: parts.join('/') || file.name });
        }
        queueUploads([...groups.entries()].map(([name, files]) => ({ type: 'folder', files, name })), { isVault: false, parentId: myDriveCurrentFolderId });
    }
    driveFolderInput.value = '';
};

function getUploadDestination() { const selected = document.querySelector('input[name="uploadDestination"]:checked'); return selected ? selected.value === 'vault' : false; }
function queueUploads(tasks, options = {}) {
    const isVault = typeof options.isVault === 'boolean' ? options.isVault : getUploadDestination();
    const parentId = isVault ? null : (Object.prototype.hasOwnProperty.call(options, 'parentId') ? options.parentId : myDriveCurrentFolderId);
    tasks.forEach(task => uploadQueue.push({ ...task, isVault, parentId: task.parentId ?? parentId }));
    if (!isUploading) { document.getElementById('uploadQueueStatus').dataset.total = uploadQueue.length; void processQueue(); }
}

function ensureFolder(name, parentId, changedFolders) {
    const safeName = normalizeDriveName(name, 'Имя папки');
    const sameName = myFiles.find(item => item.parentId === (parentId || null) && item.name.toLocaleLowerCase('ru') === safeName.toLocaleLowerCase('ru'));
    if (sameName && !isFolderRecord(sameName)) throw new Error(`Вместо папки в этом месте уже существует файл «${safeName}».`);
    if (sameName) return sameName;
    const now = new Date().toISOString();
    const folder = { id: crypto.randomUUID(), type: 'folder', name: safeName, parentId: parentId || null, createdAt: now, updatedAt: now };
    myFiles.push(folder); changedFolders.push(folder); return folder;
}

async function expandFolderUploadTask(task) {
    if (task.isVault) throw new Error('Загрузка структуры папок непосредственно в Сейф пока отключена: сначала нужно перевести имена и дерево Vault на отдельное VMK-шифрование метаданных. Загружайте файлы в Сейф по одному.');
    const collected = await collectFolderTask(task);
    const plan = buildFolderUploadPlan(task.name, task.parentId, collected.files, collected.directories);
    const changedFolders = [];
    const rootFolder = ensureFolder(plan.rootName, plan.parentId, changedFolders);
    const folderIds = new Map([['', rootFolder.id]]);
    for (const relativeDir of plan.directories) {
        const parts = relativeDir.split('/'); let parentId = rootFolder.id; let path = '';
        for (const part of parts) {
            path = path ? `${path}/${part}` : part;
            let folder = folderIds.has(path) ? myFiles.find(item => item.id === folderIds.get(path)) : null;
            if (!folder) folder = ensureFolder(part, parentId, changedFolders);
            folderIds.set(path, folder.id); parentId = folder.id;
        }
    }
    if (changedFolders.length) saveFiles();
    const children = plan.files.map(item => ({
        type: 'file', file: item.file, name: item.name,
        parentId: item.relativeDir ? folderIds.get(item.relativeDir) : rootFolder.id,
        isVault: false,
    }));
    return { rootFolder, children };
}

async function processQueue() {
    if (uploadQueue.length === 0) { isUploading = false; hideProgress('upload'); document.getElementById('uploadQueueStatus').textContent = ''; return; }
    isUploading = true;
    const task = uploadQueue[0];
    const totalTasks = parseInt(document.getElementById('uploadQueueStatus').dataset.total || uploadQueue.length, 10);
    const currentTaskNum = totalTasks - uploadQueue.length + 1;
    document.getElementById('uploadProgressContainer').style.display = 'block';
    document.getElementById('uploadResult').style.display = 'none';
    try {
        if (task.type === 'folder') {
            document.getElementById('uploadQueueStatus').textContent = `(${currentTaskNum}/${totalTasks}) Создание папок: ${task.name}…`;
            const expanded = await expandFolderUploadTask(task);
            uploadQueue.shift();
            if (expanded.children.length) {
                uploadQueue.splice(0, 0, ...expanded.children);
                document.getElementById('uploadQueueStatus').dataset.total = String(totalTasks + expanded.children.length - 1);
            }
            if (!expanded.children.length) setSyncStatus(`Папка «${task.name}» создана`);
            void processQueue();
            return;
        }

        const fileToProcess = task.file;
        if (!(fileToProcess instanceof File)) throw new Error('Не удалось прочитать загружаемый файл.');
        if (task.isVault && (!isVaultUnlocked || !vaultMasterKey || !vaultId)) throw new Error('Сначала разблокируйте Сейф и загрузите VMK.');
        const targetArray = task.isVault ? vaultFiles : myFiles;
        const finalFileName = normalizeDriveName(task.name || fileToProcess.name, 'Имя файла');
        const parentId = task.isVault ? null : (task.parentId || null);
        if (targetArray.some(item => !isFolderRecord(item) && item.parentId === parentId && item.name.toLocaleLowerCase('ru') === finalFileName.toLocaleLowerCase('ru'))) {
            throw new Error(`Файл «${finalFileName}» уже существует в этой папке. Переименуйте файл или удалите предыдущую версию.`);
        }

        document.getElementById('uploadQueueStatus').textContent = `(${currentTaskNum}/${totalTasks}) Шифрование: ${finalFileName}`;
        const master = crypto.getRandomValues(new Uint8Array(32)), salt = crypto.getRandomValues(new Uint8Array(16));
        let keyStr = 'v2:' + encodeBase58(master) + ':' + encodeBase58(salt);
        let finalCid = '', chunkCids = [];

        if (fileToProcess.size <= LARGE_FILE_THRESHOLD) {
            const fileBytes = new Uint8Array(await fileToProcess.arrayBuffer());
            const metaBytes = new TextEncoder().encode(JSON.stringify({ name: finalFileName, type: fileToProcess.type || 'application/octet-stream' }));
            const header = new Uint8Array(4); new DataView(header.buffer).setUint32(0, metaBytes.length, true);
            const combined = new Uint8Array(4 + metaBytes.length + fileBytes.length); combined.set(header, 0); combined.set(metaBytes, 4); combined.set(fileBytes, 4 + metaBytes.length);
            const { key, iv } = await deriveAesKeyAndIv(master, salt, 'single', ['encrypt']);
            const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, combined);
            finalCid = await uploadBufferToIPFS(encrypted, percent => setProgress('upload', percent, `Загрузка ${percent}%`));
            master.fill(0); salt.fill(0); fileBytes.fill(0); combined.fill(0);
        } else {
            const totalChunks = Math.ceil(fileToProcess.size / CHUNK_SIZE), chunkHashes = [];
            for (let index = 0; index < totalChunks; index++) {
                const chunk = fileToProcess.slice(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE), chunkBuffer = await chunk.arrayBuffer();
                chunkHashes.push(await sha256Hex(new Uint8Array(chunkBuffer)));
                const { key, iv } = await deriveAesKeyAndIv(master, salt, 'chunk-' + index, ['encrypt']);
                const encryptedChunk = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, chunkBuffer);
                const cid = await uploadBufferToIPFS(encryptedChunk); chunkCids.push(cid);
                setProgress('upload', Math.round(((index + 1) / totalChunks) * 100), `Часть ${index + 1}/${totalChunks}`);
            }
            const manifest = { name: finalFileName, type: fileToProcess.type || 'application/octet-stream', chunkCids, chunkHashes };
            const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest)), manifestHeader = new Uint8Array(4);
            new DataView(manifestHeader.buffer).setUint32(0, 0xFFFFFFFF, true);
            const manifestCombined = new Uint8Array(4 + manifestBytes.length); manifestCombined.set(manifestHeader, 0); manifestCombined.set(manifestBytes, 4);
            const { key: manifestKey, iv: manifestIv } = await deriveAesKeyAndIv(master, salt, 'manifest', ['encrypt']);
            finalCid = await uploadBufferToIPFS(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: manifestIv }, manifestKey, manifestCombined));
            master.fill(0); salt.fill(0); manifestCombined.fill(0);
        }

        let newFile = { type: 'file', name: finalFileName, cid: finalCid, key: keyStr, size: fileToProcess.size, parentId, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), chunkCids: chunkCids.length ? chunkCids : undefined };
        if (task.isVault) {
            const vaultKeyEnvelope = await vaultCrypto.wrapFileKey(vaultMasterKey, { userId: authenticatedUser.id, vaultId, cid: finalCid }, keyStr);
            const { key: plaintextFileKey, ...safeFile } = newFile;
            newFile = { ...safeFile, vaultCryptoVersion: 1, vaultKeyEnvelope };
        }
        targetArray.push(newFile); localPinsCache = null;
        if (task.isVault) saveVaultFiles(); else saveFiles();
        broadcastNewFile(newFile, task.isVault);
        setProgress('upload', 100, `${finalFileName} загружен`);
    } catch (error) {
        document.getElementById('uploadResult').className = 'result-box error-box';
        document.getElementById('uploadResult').innerText = `❌ Ошибка: ${error.message}`;
        document.getElementById('uploadResult').style.display = 'block';
    }
    uploadQueue.shift();
    void processQueue();
}

function setProgress(type, percent, text) { const container = document.getElementById(`${type}ProgressContainer`), fill = document.getElementById(`${type}ProgressFill`), textEl = document.getElementById(`${type}ProgressText`); if(container) container.style.display = 'block'; if(fill) fill.style.width = `${percent}%`; if(textEl) textEl.textContent = text || `${percent}%`; }
function hideProgress(type) { const el = document.getElementById(`${type}ProgressContainer`); if (el) el.style.display = 'none'; }

async function performDownload(saveToDisk) {
    const cid = document.getElementById('downloadCid').value.trim();
    let keyStr = document.getElementById('downloadKey').value.trim();
    const resultDiv = document.getElementById('downloadResult');
    resultDiv.style.display = 'none';
    const vaultMatch = vaultFiles.find(file => file.cid === cid && file.vaultKeyEnvelope?.format_id === 'vault-file-key-v1');
    const linkedFile = myFiles.find(file => file.cid === cid) || vaultMatch || null;
    if (!cid || (!keyStr && !vaultMatch)) return alert('Введите CID и ключ или выберите CID файла из разблокированного Сейфа.');
    if (vaultMatch) {
        if (saveToDisk && !confirm('Переместить файл из Сейфа в обычный диск? В обычном диске ключ доступа будет сохранён в метаданных, не защищённых VMK.')) return;
        if (!isVaultUnlocked || !vaultMasterKey || !vaultId) return alert('Для скачивания этого файла сначала разблокируйте Сейф.');
        try { keyStr = await vaultCrypto.unwrapVaultFileKey(vaultMasterKey, authenticatedUser.id, vaultId, vaultMatch); }
        catch (error) { return alert('Не удалось открыть ключ файла из Сейфа: ' + error.message); }
    }
    try {
        setProgress('download', 0, 'Поиск...'); const parts = keyStr.split(':'); let master = null, salt = null, isV2 = false, legacyKey = null, legacyIV = null;
        if (parts[0] === 'v2' && parts.length === 3) { master = decodeBase58(parts[1]); salt = decodeBase58(parts[2]); isV2 = true; } else if (parts.length === 2) { legacyKey = decodeBase58(parts[0]); legacyIV = decodeBase58(parts[1]); } else throw new Error('Неверный ключ');
        const encBuf = await fetchFromIPFS(cid, p => setProgress('download', Math.round(p * 0.25), `Скачивание ${p}%`), 60000);
        let manifest = null, fileName = 'file', mimeType = 'application/octet-stream';
        if (isV2) { try { const { key, iv } = await deriveAesKeyAndIv(master, salt, 'manifest', ['decrypt']); const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encBuf), bytes = new Uint8Array(dec); if (new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true) === 0xFFFFFFFF) { manifest = JSON.parse(new TextDecoder().decode(bytes.slice(4))); fileName = manifest.name; mimeType = manifest.type; } } catch (_) { } }
        const canStream = !saveToDisk && manifest && manifest.chunkCids && typeof window.showSaveFilePicker === 'function';
        if (canStream) {
            const handle = await window.showSaveFilePicker({ suggestedName: linkedFile?.name || manifest.name }), writable = await handle.createWritable(), total = manifest.chunkCids.length, replicaCids = [cid];
            try { for (let i = 0; i < total; i++) { setProgress('download', 25 + Math.round((i / total) * 70), `Часть ${i + 1}/${total}`); const { key, iv } = await deriveAesKeyAndIv(master, salt, 'chunk-' + i, ['decrypt']), enc = await fetchFromIPFS(manifest.chunkCids[i], null, 60000), dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, enc); if (manifest.chunkHashes && manifest.chunkHashes[i]) { const got = await sha256Hex(new Uint8Array(dec)); if (got !== manifest.chunkHashes[i]) throw new Error(`Целостность части ${i + 1} нарушена`); } await writable.write(dec); await pinCidLocally(manifest.chunkCids[i], 10000); replicaCids.push(manifest.chunkCids[i]); } await writable.close(); } catch (e) { try { await writable.abort(); } catch(_) {} throw e; }
            hideProgress('download'); resultDiv.className = 'result-box'; resultDiv.innerText = `✅ «${fileName}» сохранён и раздаётся.`; resultDiv.style.display = 'block'; return;
        }
        if (manifest && manifest.chunkCids.length > 20 && !saveToDisk) { if (!confirm(`Файл из ${manifest.chunkCids.length} частей. Собрать в RAM?`)) { hideProgress('download'); return; } }
        const payloadParts = [], replicaCids = [cid];
        if (manifest) { const total = manifest.chunkCids.length; for (let i = 0; i < total; i++) { setProgress('download', 25 + Math.round((i / total) * 70), `Часть ${i + 1}/${total}`); const { key, iv } = await deriveAesKeyAndIv(master, salt, 'chunk-' + i, ['decrypt']), enc = await fetchFromIPFS(manifest.chunkCids[i], null, 60000), dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, enc); if (manifest.chunkHashes && manifest.chunkHashes[i]) { const got = await sha256Hex(new Uint8Array(dec)); if (got !== manifest.chunkHashes[i]) throw new Error(`Целостность части ${i + 1} нарушена`); } payloadParts.push(dec); replicaCids.push(manifest.chunkCids[i]); } }
        else if (isV2) { setProgress('download', 95, 'Расшифровка...'); const { key, iv } = await deriveAesKeyAndIv(master, salt, 'single', ['decrypt']), dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encBuf), bytes = new Uint8Array(dec), metaLen = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true), meta = JSON.parse(new TextDecoder().decode(bytes.slice(4, 4 + metaLen))); fileName = meta.name; mimeType = meta.type; payloadParts.push(bytes.slice(4 + metaLen)); }
        else { const key = await crypto.subtle.importKey('raw', legacyKey, { name: 'AES-GCM' }, false, ['decrypt']), baseIV = legacyIV, manifestIV = new Uint8Array(baseIV); manifestIV[8] = 0xFF; manifestIV[9] = 0xFF; let decrypted; try { decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: manifestIV }, key, encBuf); } catch (_) { decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: baseIV }, key, encBuf); } const bytes = new Uint8Array(decrypted), headerVal = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true); if (headerVal === 0xFFFFFFFF) { const manifestLegacy = JSON.parse(new TextDecoder().decode(bytes.slice(4))); fileName = manifestLegacy.name; mimeType = manifestLegacy.type; const total = manifestLegacy.chunkCids.length; for (let i = 0; i < total; i++) { setProgress('download', 25 + Math.round((i / total) * 70), `Часть ${i+1}/${total}`); const chunkIV = new Uint8Array(baseIV); chunkIV[8] = (i >> 8) & 0xFF; chunkIV[9] = i & 0xFF; const enc = await fetchFromIPFS(manifestLegacy.chunkCids[i], null, 60000), dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: chunkIV }, key, enc); payloadParts.push(dec); replicaCids.push(manifestLegacy.chunkCids[i]); } } else { const metaLen = headerVal, meta = JSON.parse(new TextDecoder().decode(bytes.slice(4, 4 + metaLen))); fileName = meta.name; mimeType = meta.type; payloadParts.push(bytes.slice(4 + metaLen)); } }
        if (!saveToDisk) { setProgress('download', 98, 'Сохранение...'); const blob = new Blob(payloadParts, { type: mimeType }), url = URL.createObjectURL(blob), a = document.createElement('a'); a.href = url; a.download = linkedFile?.name || fileName; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); }
        for (const rc of replicaCids) await pinCidLocally(rc, 10000); localPinsCache = null;
        if (saveToDisk && !myFiles.find(f => f.cid === cid)) { const nf = { name: fileName, cid, key: keyStr, isImported: true, chunkCids: manifest ? manifest.chunkCids : undefined }; myFiles.push(nf); saveFiles(); broadcastNewFile(nf, false); }
        hideProgress('download'); resultDiv.className = 'result-box'; resultDiv.innerText = `✅ Файл «${fileName}» готов. ${replicaCids.length} блок(ов) запиннено.`; resultDiv.style.display = 'block';
    } catch (e) { hideProgress('download'); resultDiv.className = 'result-box error-box'; const isDecrypt = /OperationError|Integrity|decrypt|Целостность/i.test(e.message || ''); resultDiv.innerText = isDecrypt ? '❌ Файл недоступен или ключ неверный.' : '❌ Ошибка: ' + e.message; resultDiv.style.display = 'block'; }
}
async function decryptFileToBlob(file, isVault = false) {
    if (!file?.cid) throw new Error('У файла отсутствует CID.');
    let keyStr = file.key || '';
    if (isVault) {
        if (!isVaultUnlocked || !vaultMasterKey || !vaultId) throw new Error('Сначала разблокируйте Сейф.');
        keyStr = await vaultCrypto.unwrapVaultFileKey(vaultMasterKey, authenticatedUser.id, vaultId, file);
    }
    if (!keyStr) throw new Error('Нет ключа для расшифровки файла.');
    const parts = keyStr.split(':');
    let master = null, salt = null, isV2 = false, legacyKey = null, legacyIV = null;
    if (parts[0] === 'v2' && parts.length === 3) { master = decodeBase58(parts[1]); salt = decodeBase58(parts[2]); isV2 = true; }
    else if (parts.length === 2) { legacyKey = decodeBase58(parts[0]); legacyIV = decodeBase58(parts[1]); }
    else throw new Error('Неверный формат ключа файла.');

    const encrypted = await fetchFromIPFS(file.cid, null, 120000);
    let manifest = null, fileName = file.name || 'file', mimeType = 'application/octet-stream';
    const partsOut = [];
    if (isV2) {
        try {
            const { key, iv } = await deriveAesKeyAndIv(master, salt, 'manifest', ['decrypt']);
            const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
            const bytes = new Uint8Array(raw);
            if (new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true) === 0xFFFFFFFF) manifest = JSON.parse(new TextDecoder().decode(bytes.slice(4)));
        } catch (_) { /* Single-object v2 payload is tried below. */ }
        if (manifest) {
            mimeType = manifest.type || mimeType;
            const total = manifest.chunkCids?.length || 0;
            if (!total || total > 100000) throw new Error('Некорректный манифест файла.');
            for (let index = 0; index < total; index++) {
                const { key, iv } = await deriveAesKeyAndIv(master, salt, 'chunk-' + index, ['decrypt']);
                const encryptedChunk = await fetchFromIPFS(manifest.chunkCids[index], null, 120000);
                const decryptedChunk = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedChunk);
                if (manifest.chunkHashes?.[index]) {
                    const hash = await sha256Hex(new Uint8Array(decryptedChunk));
                    if (hash !== manifest.chunkHashes[index]) throw new Error(`Целостность части ${index + 1} нарушена.`);
                }
                partsOut.push(decryptedChunk);
            }
        } else {
            const { key, iv } = await deriveAesKeyAndIv(master, salt, 'single', ['decrypt']);
            const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
            const bytes = new Uint8Array(raw);
            if (bytes.length < 4) throw new Error('Повреждённый заголовок файла.');
            const metadataLength = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
            if (metadataLength > bytes.length - 4) throw new Error('Некорректные метаданные файла.');
            const metadata = JSON.parse(new TextDecoder().decode(bytes.slice(4, 4 + metadataLength)));
            fileName = file.name || metadata.name || fileName; mimeType = metadata.type || mimeType;
            partsOut.push(bytes.slice(4 + metadataLength));
        }
    } else {
        const key = await crypto.subtle.importKey('raw', legacyKey, { name: 'AES-GCM' }, false, ['decrypt']);
        const baseIV = legacyIV, manifestIV = new Uint8Array(baseIV); manifestIV[8] = 0xFF; manifestIV[9] = 0xFF;
        let raw;
        try { raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: manifestIV }, key, encrypted); }
        catch (_) { raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: baseIV }, key, encrypted); }
        const bytes = new Uint8Array(raw), header = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
        if (header === 0xFFFFFFFF) {
            manifest = JSON.parse(new TextDecoder().decode(bytes.slice(4)));
            fileName = file.name || manifest.name || fileName; mimeType = manifest.type || mimeType;
            const total = manifest.chunkCids?.length || 0;
            if (!total || total > 100000) throw new Error('Некорректный legacy-манифест.');
            for (let index = 0; index < total; index++) {
                const chunkIV = new Uint8Array(baseIV); chunkIV[8] = (index >> 8) & 0xFF; chunkIV[9] = index & 0xFF;
                const encryptedChunk = await fetchFromIPFS(manifest.chunkCids[index], null, 120000);
                const decryptedChunk = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: chunkIV }, key, encryptedChunk);
                partsOut.push(decryptedChunk);
            }
        } else {
            const metadataLength = header;
            if (metadataLength > bytes.length - 4) throw new Error('Некорректные метаданные legacy-файла.');
            const metadata = JSON.parse(new TextDecoder().decode(bytes.slice(4, 4 + metadataLength)));
            fileName = file.name || metadata.name || fileName; mimeType = metadata.type || mimeType;
            partsOut.push(bytes.slice(4 + metadataLength));
        }
    }
    if (master) master.fill(0);
    if (salt) salt.fill(0);
    if (legacyKey) legacyKey.fill(0);
    if (legacyIV) legacyIV.fill(0);
    return new Blob(partsOut, { type: mimeType || 'application/octet-stream' });
}

document.getElementById('downloadDeviceBtn').onclick = () => performDownload(false);
document.getElementById('downloadDiskBtn').onclick = () => performDownload(true);

function initRentalModule() { }
function renderOrders() { }
function renderContracts() { }
function renderProviderContracts() { }
function initWallet() { }
let modalState = {
    avatarCid: null,
    newAvatarFile: null,
    newAvatarImage: null,
    zoom: 1,
    offsetX: 0,
    offsetY: 0,
    previewRequestId: 0
};

async function refreshProfileUI() {
    const meta = loadProfileMeta(currentProfile);
    const name = meta.displayName || authenticatedUser?.display_name || 'Без имени';
    const email = authenticatedUser?.email || '';
    const nameElement = document.getElementById('displayAccountName');
    const emailElement = document.getElementById('displayAccountKey');
    const profileIdElement = document.getElementById('displayProfileId');
    if (nameElement) nameElement.textContent = name;
    if (emailElement) { emailElement.textContent = email || 'Email не указан'; emailElement.title = email; }
    if (profileIdElement) profileIdElement.textContent = currentProfile || '—';
    const copyProfileButton = document.getElementById('copyProfileBtn');
    if (copyProfileButton) {
        const copyLabel = email ? 'Копировать email' : 'Копировать ID профиля';
        copyProfileButton.setAttribute('aria-label', copyLabel);
        copyProfileButton.title = copyLabel;
    }

    const avatarEl = document.getElementById('topbarAvatar');
    if (!avatarEl) return;
    avatarEl.innerHTML = '<svg class="profile-avatar-fallback" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><circle cx="16" cy="11" r="5.2" fill="#9CC5FF"/><path d="M5.5 27c.7-5.4 4.8-8.5 10.5-8.5s9.8 3.1 10.5 8.5" fill="#6D9FEA" stroke="#C4DDFF" stroke-width="1.2" stroke-linecap="round"/></svg>';
    avatarEl.classList.remove('has-avatar');
    if (meta.avatarCid) {
        const url = await getAvatarUrl(meta.avatarCid);
        if (url) {
            const img = document.createElement('img');
            img.src = url; img.alt = ''; img.draggable = false;
            avatarEl.replaceChildren(img);
            avatarEl.classList.add('has-avatar');
        }
    }
}

function refreshSettingsVaultState() {
    const status = document.getElementById('settingsVaultStatus');
    const lockButton = document.getElementById('vaultLockBtn');
    if (status) status.textContent = isVaultUnlocked ? 'Разблокирован на этом устройстве' : (currentDeviceHasVaultAccess ? 'Заблокирован; доступ устройства сохранён' : 'Не подключён на этом устройстве — требуется QR от доверенного устройства');
    if (lockButton) lockButton.hidden = !isVaultUnlocked;
}

function updateAvatarCropReadouts() {
    const zoom = document.getElementById('avatarZoomValue');
    const offsetX = document.getElementById('avatarOffsetXValue');
    const offsetY = document.getElementById('avatarOffsetYValue');
    if (zoom) zoom.value = `${Number(modalState.zoom).toFixed(2)}×`;
    if (offsetX) offsetX.value = String(Math.round(modalState.offsetX));
    if (offsetY) offsetY.value = String(Math.round(modalState.offsetY));
}

function drawAvatarCrop(canvas, image, zoom = 1, offsetX = 0, offsetY = 0) {
    const size = 256;
    canvas.width = size; canvas.height = size;
    const context = canvas.getContext('2d');
    if (!context || !image?.naturalWidth || !image?.naturalHeight) return;
    const baseSize = Math.min(image.naturalWidth, image.naturalHeight);
    const cropSize = baseSize / Math.max(1, Number(zoom) || 1);
    const maxOffsetX = Math.max(0, (image.naturalWidth - cropSize) / 2);
    const maxOffsetY = Math.max(0, (image.naturalHeight - cropSize) / 2);
    const sx = (image.naturalWidth - cropSize) / 2 + (Number(offsetX) / 100) * maxOffsetX;
    const sy = (image.naturalHeight - cropSize) / 2 + (Number(offsetY) / 100) * maxOffsetY;
    context.clearRect(0, 0, size, size);
    context.imageSmoothingEnabled = true;
    context.imageSmoothingQuality = 'high';
    context.drawImage(image, sx, sy, cropSize, cropSize, 0, 0, size, size);
}

async function openProfileModal() {
    const meta = loadProfileMeta(currentProfile);
    document.getElementById('profileNameInput').value = meta.displayName || '';
    document.getElementById('pinataJwtInput').value = localStorage.getItem(`pinataJwt_${currentProfile}`) || '';
    modalState.avatarCid = meta.avatarCid;
    modalState.newAvatarFile = null;
    modalState.newAvatarImage = null;
    modalState.zoom = 1; modalState.offsetX = 0; modalState.offsetY = 0;
    document.getElementById('avatarZoom').value = '1';
    document.getElementById('avatarOffsetX').value = '0';
    document.getElementById('avatarOffsetY').value = '0';
    updateAvatarCropReadouts();
    refreshSettingsVaultState();
    document.getElementById('profileModal').style.display = 'flex';
    await renderModalAvatar();
}

async function renderModalAvatar() {
    const canvas = document.getElementById('profileAvatarPreview');
    const placeholder = document.getElementById('profileAvatarPlaceholder');
    const controls = document.getElementById('avatarControls');
    if (!canvas || !placeholder || !controls) return;
    const requestId = ++modalState.previewRequestId;
    let image = modalState.newAvatarImage;
    const isNewPhoto = Boolean(image);
    if (!image && modalState.avatarCid) {
        const url = await getAvatarUrl(modalState.avatarCid);
        if (requestId !== modalState.previewRequestId) return;
        if (url) {
            try { image = await loadImageFromUrl(url); } catch (error) { console.warn('Не удалось загрузить предпросмотр аватара:', error); }
        }
    }
    if (requestId !== modalState.previewRequestId) return;
    if (image) {
        drawAvatarCrop(canvas, image, isNewPhoto ? modalState.zoom : 1, isNewPhoto ? modalState.offsetX : 0, isNewPhoto ? modalState.offsetY : 0);
        canvas.hidden = false; placeholder.hidden = true;
        controls.hidden = !isNewPhoto;
    } else {
        canvas.hidden = true; placeholder.hidden = false; controls.hidden = true;
    }
    updateAvatarCropReadouts();
}

function onAvatarCropChange() {
    modalState.zoom = Number(document.getElementById('avatarZoom').value);
    modalState.offsetX = Number(document.getElementById('avatarOffsetX').value);
    modalState.offsetY = Number(document.getElementById('avatarOffsetY').value);
    updateAvatarCropReadouts();
    if (modalState.newAvatarImage) drawAvatarCrop(document.getElementById('profileAvatarPreview'), modalState.newAvatarImage, modalState.zoom, modalState.offsetX, modalState.offsetY);
}
for (const id of ['avatarZoom', 'avatarOffsetX', 'avatarOffsetY']) document.getElementById(id).addEventListener('input', onAvatarCropChange);

document.getElementById('avatarCropResetBtn')?.addEventListener('click', () => {
    modalState.zoom = 1; modalState.offsetX = 0; modalState.offsetY = 0;
    document.getElementById('avatarZoom').value = '1';
    document.getElementById('avatarOffsetX').value = '0';
    document.getElementById('avatarOffsetY').value = '0';
    onAvatarCropChange();
});

document.getElementById('avatarUploadBtn').onclick = () => document.getElementById('avatarFileInput').click();
document.getElementById('avatarFileInput').onchange = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (!file.type.startsWith('image/')) { alert('Выберите файл изображения.'); event.target.value = ''; return; }
    if (file.size > 15 * 1024 * 1024) { alert('Размер фотографии не должен превышать 15 МБ.'); event.target.value = ''; return; }
    try {
        const image = await loadImageFromFile(file);
        modalState.newAvatarFile = file;
        modalState.newAvatarImage = image;
        modalState.zoom = 1; modalState.offsetX = 0; modalState.offsetY = 0;
        document.getElementById('avatarZoom').value = '1';
        document.getElementById('avatarOffsetX').value = '0';
        document.getElementById('avatarOffsetY').value = '0';
        await renderModalAvatar();
    } catch (error) {
        alert('Не удалось открыть изображение: ' + error.message);
    } finally { event.target.value = ''; }
};

document.getElementById('profileSaveBtn').onclick = async () => {
    const button = document.getElementById('profileSaveBtn');
    const originalText = button.textContent;
    try {
        button.disabled = true; button.textContent = 'Сохранение…';
        let avatarCid = modalState.avatarCid;
        if (modalState.newAvatarFile && modalState.newAvatarImage) {
            button.textContent = 'Загрузка аватара…';
            avatarCid = await compressAndUploadAvatar(modalState.newAvatarImage);
            if (modalState.avatarCid && modalState.avatarCid !== avatarCid) avatarCache.delete(modalState.avatarCid);
        }
        saveProfileMeta(currentProfile, { displayName: document.getElementById('profileNameInput').value.trim(), avatarCid });
        const jwt = document.getElementById('pinataJwtInput').value.trim();
        if (jwt) localStorage.setItem(`pinataJwt_${currentProfile}`, jwt);
        else localStorage.removeItem(`pinataJwt_${currentProfile}`);
        document.getElementById('profileModal').style.display = 'none';
        await refreshProfileUI();
    } catch (error) {
        alert('Не удалось сохранить настройки: ' + error.message);
    } finally {
        button.disabled = false; button.textContent = originalText;
    }
};

async function compressAndUploadAvatar(image) {
    const canvas = document.createElement('canvas');
    drawAvatarCrop(canvas, image, modalState.zoom, modalState.offsetX, modalState.offsetY);
    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.88));
    if (!blob) throw new Error('Не удалось подготовить изображение.');
    return await uploadBufferToIPFS(await blob.arrayBuffer());
}

function loadImageFromUrl(url) {
    return new Promise((resolve, reject) => {
        const image = new Image();
        image.onload = () => resolve(image);
        image.onerror = () => reject(new Error('Не удалось загрузить изображение.'));
        image.src = url;
    });
}

function loadImageFromFile(file) {
    return new Promise((resolve, reject) => {
        const url = URL.createObjectURL(file);
        const image = new Image();
        image.onload = () => { URL.revokeObjectURL(url); resolve(image); };
        image.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Не удалось открыть изображение.')); };
        image.src = url;
    });
}

