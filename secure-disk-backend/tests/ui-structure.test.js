import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const html = await readFile(new URL('../../secure-disk/index.html', import.meta.url), 'utf8');
const js = await readFile(new URL('../../secure-disk/app.js', import.meta.url), 'utf8');
const css = await readFile(new URL('../../secure-disk/style.css', import.meta.url), 'utf8');

function section(source, start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from + start.length);
  assert.notEqual(from, -1, `Missing section start: ${start}`);
  assert.notEqual(to, -1, `Missing section end: ${end}`);
  return source.slice(from, to);
}

test('pairing roles are correct: trusted device shows QR, new device scans it', () => {
  assert.match(html, /id="showPairingQRBtn"[^>]*>[^<]*[^<]*Показать QR для нового устройства/);
  assert.match(html, /id="scanPairingBtn"[^>]*>[^<]*Сканировать QR/);
  assert.match(js, /async function showPairingQR\(\)/);
  assert.match(js, /async function scanPairingQR\(\)/);
  const show = section(js, 'async function showPairingQR()', 'async function pollTrustedPairingInvite');
  const scan = section(js, 'async function scanPairingQR()', 'async function stopPairingScanner');
  assert.match(show, /authApi\.createPairingInvite\(\)/);
  assert.match(show, /isVaultUnlocked/);
  assert.match(show, /buildPairingQr\(/);
  assert.match(scan, /getDeviceCryptoIdentity/);
  assert.match(scan, /getDeviceIdentityInfo/);
  assert.match(scan, /ensureDeviceRegistered/);
  assert.doesNotMatch(scan, /isVaultUnlocked\s*\|\|\s*!vaultMasterKey/);
  assert.match(scan, /getUserMedia|Html5Qrcode|pairingScannerModal/);
});

test('invite claim, approval and completion are connected to the frontend API', () => {
  assert.match(js, /authApi\.claimPairingInvite\(/);
  assert.match(js, /authApi\.getPairingInviteStatus\(/);
  assert.match(js, /authApi\.approvePairingInvite\(/);
  assert.match(js, /authApi\.getPairingInviteResult\(/);
  assert.match(js, /authApi\.completePairingInvite\(/);
  assert.match(js, /vaultCrypto\.sealVmkForDevice\(/);
  assert.match(js, /vaultCrypto\.openVmkEnvelope\(/);
  assert.match(js, /buildPairingCompletionMessage\(/);
});

test('drive toolbar is compact and profile settings are available from the topbar dropdown and gear', () => {
  for (const id of ['driveNewFolderBtn', 'driveUploadBtn', 'driveUploadFolderBtn', 'driveViewToggleBtn']) {
    assert.match(html, new RegExp(`id="${id}"[^>]*class="[^"]*drive-tool-btn`));
  }
  assert.match(html, /id="profileMenuTrigger"[^>]*aria-haspopup="menu"/);
  assert.match(html, /id="profileDropdown"[^>]*role="menu"/);
  assert.match(html, /id="profileSettingsBtn"[^>]*role="menuitem"/);
  assert.match(html, /id="headerSettingsBtn"[^>]*aria-label="Открыть настройки"/);
  assert.match(html, /id="switchAccountBtn"/);
  assert.match(html, /id="logoutBtn"[^>]*role="menuitem"/);
  assert.match(html, /id="profileModal"[\s\S]*?Настройки/);
  assert.match(html, /id="settingsThemeToggleBtn"/);
  assert.match(html, /id="profileNameInput"/);
  assert.match(html, /id="avatarUploadBtn"/);
  assert.match(html, /id="settingsVaultStatus"/);
  assert.doesNotMatch(html, /id="themeToggleBtn"/);
  assert.match(css, /\.drive-tool-btn\s*\{/);
  assert.match(css, /\.profile-dropdown\s*\{/);
  assert.match(css, /\.settings-modal-heading\s*\{[^}]*align-items:\s*center/);
});

test('sidebar collapses, upload and download share one navigation entry', () => {
  assert.match(html, /id="sidebarToggleBtn"/);
  assert.match(html, /id="appSidebar"/);
  assert.match(js, /function setSidebarCollapsed\(collapsed\)/);
  assert.match(js, /secureDiskSidebarCollapsed/);
  assert.equal((html.match(/data-tab="download"/g) || []).length, 0);
  assert.match(html, /data-upload-mode="upload"/);
  assert.match(html, /data-upload-mode="download"/);
  assert.match(js, /function activateUploadMode\(/);
});

test('file cards use SVG icons and selection toolbar instead of per-card action menus', () => {
  assert.match(js, /function createDriveItemIcon\(/);
  assert.match(js, /function openDriveItem\(/);
  assert.match(js, /className = 'drive-item-checkbox'/);
  assert.match(js, /myFilesRenameSelectedBtn/);
  assert.match(js, /function updateBulkUI\(isVault\)/);
  assert.doesNotMatch(js, /className = 'drive-open-btn'/);
  assert.doesNotMatch(js, /className = 'drive-more-menu'/);
  assert.match(html, /id="myFilesBulkActions"/);
  assert.match(html, /id="myFilesRenameSelectedBtn"/);
  assert.match(html, /id="myFilesShareSelectedBtn"/);
  assert.match(js, /myFilesShareSelectedBtn/);
  assert.match(css, /\.drive-items:not\(\.list-view\) \.drive-item\s*\{/);
});

test('NODEX branding uses a node-network mark and inline SVG sidebar icons', () => {
  assert.match(html, /<title>NODEX — Distributed Storage<\/title>/);
  assert.match(html, /class="auth-brand-word">NODEX<\/span>/);
  assert.match(html, /class="brand-name">NODEX<\/span>/);
  const navButtons = html.match(/<button class="nav-item[^>]*data-tab=.*?<\/button>/g) || [];
  assert.equal(navButtons.length, 6);
  for (const button of navButtons) {
    assert.match(button, /title="[^"]+"/);
    assert.match(button, /<svg class="sidebar-svg/);
  }
  assert.match(html, /sidebar-svg-folder/);
  assert.match(html, /sidebar-svg-vault/);
  assert.match(html, /sidebar-svg-transfer/);
  assert.match(html, /sidebar-svg-card/);
  assert.match(html, /sidebar-svg-monitor/);
  assert.match(html, /sidebar-svg-wallet/);
});

test('NODEX avatar crop preview and profile identity controls are wired', () => {
  assert.match(html, /id="topbarAvatar"[^>]*>[\s\S]*?profile-avatar-fallback/);
  assert.match(html, /id="displayAccountKey"/);
  assert.match(html, /id="displayProfileId"/);
  assert.match(html, /id="copyProfileBtn"/);
  assert.match(html, /id="profileAvatarPreview" class="profile-avatar-large"/);
  assert.match(html, /id="avatarZoom"/);
  assert.match(html, /id="avatarOffsetX"/);
  assert.match(html, /id="avatarOffsetY"/);
  assert.match(html, /id="avatarCropResetBtn"/);
  assert.match(js, /function drawAvatarCrop\(/);
  assert.match(js, /function onAvatarCropChange\(/);
  assert.match(js, /async function performAccountExit\(/);
  assert.match(js, /function setProfileMenuOpen\(/);
  assert.match(css, /--icon-vault-shackle:/);
  assert.match(css, /--icon-transfer-line:/);
  assert.match(css, /:root\[data-theme=\"light\"\] \.nav-item\.active \{ color: #1E293B/);
  assert.match(css, /\.profile-dropdown\[hidden\] \{ display: none !important/);
  assert.match(css, /\.avatar-range-row/);
});

test('bulk actions remain right-aligned above the drive grid', () => {
  assert.match(css, /\.drive-selection-row > \.bulk-actions\s*\{[^}]*justify-content:\s*flex-end/);
  assert.match(html, /id="myFilesBulkActions"/);
});
