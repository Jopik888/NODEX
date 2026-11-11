// NODEX endpoint configuration. Browser defaults preserve the v0.4.7 setup.
// Native clients must select a Windows host before making API requests.

const DEFAULT_API_BASE = 'http://localhost:3001/api/v1';
const DEFAULT_IPFS_API = 'http://localhost:5001/api/v0';
export const SERVER_URL_STORAGE_KEY = 'nodex_server_url';
export const SERVER_CONFIG_STORAGE_KEY = 'nodex_server_config';

function readMeta(name) {
    if (typeof document === 'undefined') return '';
    return document.querySelector(`meta[name="${name}"]`)?.content?.trim() || '';
}

function normalizeEndpoint(value, fallback, label) {
    const candidate = String(value || fallback).trim();
    let url;
    try { url = new URL(candidate); }
    catch (_) { throw new Error(`Некорректный адрес ${label}: ${candidate}`); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
        throw new Error(`Недопустимый адрес ${label}: используйте HTTP(S) URL без учётных данных, query и fragment`);
    }
    return url.toString().replace(/\/+$/, '');
}

export function isNativeClient() {
    try {
        return Boolean(window.Capacitor && (
            (typeof window.Capacitor.isNativePlatform === 'function' && window.Capacitor.isNativePlatform()) ||
            (typeof window.Capacitor.getPlatform === 'function' && window.Capacitor.getPlatform() !== 'web')
        ));
    } catch (_) { return false; }
}

function readStoredConfig() {
    try {
        const raw = localStorage.getItem(SERVER_CONFIG_STORAGE_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === 'object') return parsed;
        }
    } catch (_) { /* Storage may be unavailable in restricted contexts. */ }
    return {};
}

const injected = typeof window !== 'undefined' && window.NODEX_CONFIG && typeof window.NODEX_CONFIG === 'object'
    ? window.NODEX_CONFIG : {};
const stored = typeof window !== 'undefined' ? readStoredConfig() : {};
const apiMeta = readMeta('nodex-api-base') || readMeta('secure-disk-api-base');
const ipfsMeta = readMeta('nodex-ipfs-api');

function initialValue(key, meta, fallback) {
    return injected[key] || stored[key] || meta || fallback;
}

export let API_BASE = normalizeEndpoint(initialValue('apiBase', apiMeta, DEFAULT_API_BASE), DEFAULT_API_BASE, 'API');
export let IPFS_API = normalizeEndpoint(initialValue('ipfsApi', ipfsMeta, DEFAULT_IPFS_API), DEFAULT_IPFS_API, 'IPFS API');

export const NODEX_CONFIG = Object.freeze({ get apiBase() { return API_BASE; }, get ipfsApi() { return IPFS_API; } });

export function getSavedServerUrl() {
    try { return localStorage.getItem(SERVER_URL_STORAGE_KEY) || ''; } catch (_) { return ''; }
}

export function isServerConfigured() {
    return !isNativeClient() || Boolean(getSavedServerUrl());
}

export function normalizeServerOrigin(value) {
    const candidate = String(value || '').trim();
    if (!candidate) throw new Error('Введите IP-адрес или доменное имя Windows-сервера.');
    const explicitScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(candidate);
    let url;
    try { url = new URL(explicitScheme ? candidate : `https://${candidate}`); }
    catch (_) { throw new Error('Некорректный адрес сервера. Пример: 192.168.1.5:3001'); }
    const loopback = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password ||
        (url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
        throw new Error('Укажите только адрес сервера и порт, без пути, логина или параметров.');
    }
    if (!loopback && url.protocol !== 'https:') {
        throw new Error('Для подключения по локальной сети требуется HTTPS. HTTP разрешён только для localhost.');
    }
    return url.origin;
}

export function setServerConfig(value) {
    const origin = normalizeServerOrigin(value);
    const apiBase = normalizeEndpoint(`${origin}/api/v1`, '', 'API');
    // The IPFS endpoint is a restricted host-side proxy, never the Kubo admin API.
    const ipfsApi = normalizeEndpoint(`${origin}/ipfs/api/v0`, '', 'IPFS proxy');
    const next = { serverUrl: origin, apiBase, ipfsApi };
    try {
        localStorage.setItem(SERVER_URL_STORAGE_KEY, origin);
        localStorage.setItem(SERVER_CONFIG_STORAGE_KEY, JSON.stringify({ apiBase, ipfsApi }));
    } catch (_) { throw new Error('Не удалось сохранить адрес сервера в LocalStorage.'); }
    API_BASE = apiBase;
    IPFS_API = ipfsApi;
    window.dispatchEvent(new CustomEvent('nodex:server-config-changed', { detail: next }));
    return next;
}

export function clearServerConfig() {
    try {
        localStorage.removeItem(SERVER_URL_STORAGE_KEY);
        localStorage.removeItem(SERVER_CONFIG_STORAGE_KEY);
    } catch (_) { /* no-op */ }
    if (!isNativeClient()) {
        API_BASE = normalizeEndpoint(injected.apiBase || apiMeta, DEFAULT_API_BASE, 'API');
        IPFS_API = normalizeEndpoint(injected.ipfsApi || ipfsMeta, DEFAULT_IPFS_API, 'IPFS API');
    }
}
