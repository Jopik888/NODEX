import { API_BASE } from './config.js';

let csrfToken = '';

export class AuthApiError extends Error {
    constructor(message, { status = 0, code = 'NETWORK_ERROR', details = null } = {}) {
        super(message);
        this.name = 'AuthApiError';
        this.status = status;
        this.code = code;
        this.details = details;
    }
}

async function request(path, { method = 'GET', body, headers = {} } = {}) {
    let response;
    try {
        response = await fetch(`${API_BASE}${path}`, {
            method,
            credentials: 'include',
            cache: 'no-store',
            headers: {
                Accept: 'application/json',
                ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
                ...headers,
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
    } catch (error) {
        throw new AuthApiError(
            'Не удалось связаться с сервером. Проверьте, запущен ли backend и доступен ли он по адресу ' + API_BASE,
            { code: 'NETWORK_ERROR' },
        );
    }

    const responseText = await response.text();
    let payload = null;
    if (responseText) {
        try {
            payload = JSON.parse(responseText);
        } catch (_) {
            payload = null;
        }
    }

    if (!response.ok) {
        const error = payload?.error || {};
        throw new AuthApiError(error.message || `Ошибка сервера (${response.status}).`, {
            status: response.status,
            code: error.code || 'HTTP_ERROR',
            details: error.details || null,
        });
    }

    return payload || {};
}

export async function getCsrfToken({ force = false } = {}) {
    if (csrfToken && !force) return csrfToken;
    const payload = await request('/csrf-token');
    if (typeof payload.csrf_token !== 'string' || payload.csrf_token.length < 30) {
        throw new AuthApiError('Сервер не вернул корректный CSRF-токен.', { code: 'INVALID_CSRF_RESPONSE' });
    }
    csrfToken = payload.csrf_token;
    return csrfToken;
}

async function postJson(path, body, extraHeaders = {}) {
    const token = await getCsrfToken({ force: true });
    return request(path, {
        method: 'POST',
        body,
        headers: { 'X-CSRF-Token': token, ...extraHeaders },
    });
}

export async function register({ email, password, display_name }) {
    return postJson('/auth/register', {
        email: email.trim(),
        password,
        ...(display_name?.trim() ? { display_name: display_name.trim() } : {}),
    });
}

export async function verifyEmail(token) {
    return postJson('/auth/verify-email', { token: token.trim() });
}

export async function resendVerification(email) {
    return postJson('/auth/resend-verification', { email: email.trim() });
}

export async function login({ email, password }) {
    const payload = await postJson('/auth/login', { email: email.trim(), password });
    if (typeof payload.csrf_token === 'string') csrfToken = payload.csrf_token;
    return payload;
}

export async function registerDevice(device) {
    return postJson('/devices/register', device);
}

export async function listDevices() { return request('/devices'); }
export async function getTrustedDeviceKeys() { return request('/devices/trusted-keys'); }
export async function createDeviceChallenge(deviceId) { return postJson(`/devices/${encodeURIComponent(deviceId)}/challenge`, {}); }
export async function verifyDevice(deviceId, payload) { return postJson(`/devices/${encodeURIComponent(deviceId)}/verify`, payload); }
export async function revokeDevice(deviceId) { return postJson(`/devices/${encodeURIComponent(deviceId)}/revoke`, {}); }
export async function getDeviceHistory(deviceId) { return request(`/devices/${encodeURIComponent(deviceId)}/history`); }

export async function getVaultEnvelope() { return request('/vault/envelope'); }
export async function initializeVault(payload) { return postJson('/vault/initialize', payload); }
export async function startPairing() { return postJson('/devices/pairing/start', {}); }
export async function getPairing(requestId, pairingToken = '') {
    const headers = pairingToken ? { 'X-Pairing-Token': pairingToken } : {};
    return request(`/devices/pairing/${encodeURIComponent(requestId)}`, { headers });
}
export async function approvePairing(requestId, pairingToken, payload) {
    return postJson(`/devices/pairing/${encodeURIComponent(requestId)}/approve`, payload, { 'X-Pairing-Token': pairingToken });
}
export async function completePairing(requestId, payload) {
    return postJson(`/devices/pairing/${encodeURIComponent(requestId)}/complete`, payload);
}
export async function cancelPairing(requestId) {
    return postJson(`/devices/pairing/${encodeURIComponent(requestId)}/cancel`, {});
}

// v0.4.3 trusted-device initiated invite pairing.
export async function createPairingInvite() { return postJson('/devices/pairing/invite', {}); }
export async function getPairingInviteStatus(inviteId) { return request(`/devices/pairing/invite/${encodeURIComponent(inviteId)}/status`); }
export async function claimPairingInvite(payload) { return postJson('/devices/pairing/claim', payload); }
export async function approvePairingInvite(inviteId, payload) { return postJson(`/devices/pairing/${encodeURIComponent(inviteId)}/approve`, payload); }
export async function getPairingInviteResult(inviteId) { return request(`/devices/pairing/${encodeURIComponent(inviteId)}/result`); }
export async function completePairingInvite(inviteId, payload) { return postJson(`/devices/pairing/${encodeURIComponent(inviteId)}/complete`, payload); }
export async function cancelPairingInvite(inviteId) { return postJson(`/devices/pairing/invite/${encodeURIComponent(inviteId)}/cancel`, {}); }

export async function getCurrentSession() {
    return request('/auth/me');
}

export async function refreshSession() {
    // GET /csrf-token rebinds/recovers the readable CSRF cookie using the
    // existing access or refresh cookie before the rotating refresh POST.
    const token = await getCsrfToken({ force: true });
    const payload = await request('/auth/refresh', {
        method: 'POST',
        headers: { 'X-CSRF-Token': token },
    });
    if (typeof payload.csrf_token === 'string') csrfToken = payload.csrf_token;
    return payload;
}

export async function restoreSession() {
    try {
        return await getCurrentSession();
    } catch (error) {
        if (error.status !== 401) throw error;
        await refreshSession();
        return getCurrentSession();
    }
}

export async function logout() {
    try {
        return await postJson('/auth/logout');
    } catch (error) {
        // If the short-lived access cookie expired while the refresh cookie is
        // still valid, rotate once and retry logout with the new access cookie.
        if (error.status !== 401) throw error;
        await refreshSession();
        return postJson('/auth/logout');
    } finally {
        csrfToken = '';
    }
}

export function clearClientCsrfState() {
    csrfToken = '';
}

export const authApiBaseUrl = API_BASE;
