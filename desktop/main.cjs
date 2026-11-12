const { app, BrowserWindow, ipcMain, shell } = require('electron');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { DesktopServiceManager } = require('./service-manager.cjs');

// Prevent two desktop instances from racing over the same PostgreSQL and Kubo repositories.
const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) app.quit();

const FRONTEND_HOST = '127.0.0.1';
const FRONTEND_PORT = 4173;

// Keep NODEX data in a stable product-specific folder, independent of installer version.
app.setPath('userData', path.join(app.getPath('appData'), 'NODEX'));
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.webp': 'image/webp', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
};

let mainWindow;
let staticServer;
let serviceManager;
let isQuitting = false;
let bootstrapStatus = { state: 'starting', message: 'Запуск NODEX…', missing: [] };

function getResourcePath(...parts) {
  return app.isPackaged
    ? path.join(process.resourcesPath, ...parts)
    : path.join(__dirname, '..', ...parts);
}

function startFrontendServer(root) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (!['GET', 'HEAD'].includes(req.method)) {
        res.writeHead(405, { Allow: 'GET, HEAD' }).end();
        return;
      }
      let pathname;
      try { pathname = decodeURIComponent(new URL(req.url, `http://${FRONTEND_HOST}:${FRONTEND_PORT}`).pathname); }
      catch { res.writeHead(400).end('Bad request'); return; }
      if (pathname === '/') pathname = '/index.html';
      const candidate = path.resolve(root, `.${pathname}`);
      const relative = path.relative(root, candidate);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        res.writeHead(403).end('Forbidden');
        return;
      }
      fs.stat(candidate, (statError, stat) => {
        if (statError || !stat.isFile()) { res.writeHead(404).end('Not found'); return; }
        const headers = {
          'Content-Type': MIME[path.extname(candidate).toLowerCase()] || 'application/octet-stream',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
          'Cache-Control': path.basename(candidate) === 'index.html' ? 'no-store' : 'public, max-age=300',
        };
        if (req.method === 'HEAD') {
          res.writeHead(200, headers).end();
          return;
        }
        if (path.basename(candidate).toLowerCase() === 'index.html') {
          fs.readFile(candidate, 'utf8', (readError, html) => {
            if (readError) { res.writeHead(500).end('Unable to load NODEX frontend'); return; }
            const runtimeConfig = '<script>window.NODEX_CONFIG = Object.freeze({apiBase:"http://127.0.0.1:3001/api/v1",ipfsApi:"http://127.0.0.1:5001/api/v0"});</script>';
            const output = html.replace(/<\/head>/i, `${runtimeConfig}</head>`);
            res.writeHead(200, { ...headers, 'Content-Length': Buffer.byteLength(output) });
            res.end(output);
          });
          return;
        }
        res.writeHead(200, headers);
        fs.createReadStream(candidate).pipe(res);
      });
    });
    server.once('error', reject);
    server.listen(FRONTEND_PORT, FRONTEND_HOST, () => resolve(server));
  });
}

function createWindow(url) {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1024,
    minHeight: 680,
    show: false,
    backgroundColor: '#0b1220',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });
  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.webContents.setWindowOpenHandler(({ url: target }) => {
    if (target.startsWith('https://')) shell.openExternal(target);
    return { action: 'deny' };
  });
  mainWindow.loadURL(url);
  mainWindow.on('closed', () => { mainWindow = null; });
}

async function showSetup(status) {
  bootstrapStatus = status;
  if (!mainWindow) createWindow(pathToFileURL(path.join(__dirname, 'setup.html')).href);
  else await mainWindow.loadFile(path.join(__dirname, 'setup.html'));
}

async function bootstrap() {
  bootstrapStatus = { state: 'starting', message: 'Проверка локальных компонентов…', missing: [] };
  if (!staticServer) {
    const frontendRoot = app.isPackaged
      ? getResourcePath('frontend')
      : getResourcePath('secure-disk');
    staticServer = await startFrontendServer(frontendRoot);
  }
  const result = await serviceManager.start();
  if (!result.ok) {
    await showSetup({ state: 'blocked', message: result.message, missing: result.missing || [] });
    return result;
  }
  bootstrapStatus = { state: 'ready', message: 'Локальные службы NODEX запущены.', missing: [] };
  if (!mainWindow) createWindow(`http://${FRONTEND_HOST}:${FRONTEND_PORT}/`);
  else await mainWindow.loadURL(`http://${FRONTEND_HOST}:${FRONTEND_PORT}/`);
  return { ok: true };
}

if (!hasSingleInstanceLock) {
  // A second launch exits before registering handlers or touching local services.
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

app.whenReady().then(async () => {
  const { session } = require('electron');
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    let origin = '';
    try { origin = new URL(details.requestingUrl || webContents.getURL()).origin; } catch (_) {}
    const cameraOnly = permission === 'media' && Array.isArray(details.mediaTypes) &&
      details.mediaTypes.length === 1 && details.mediaTypes[0] === 'video';
    callback(origin === `http://${FRONTEND_HOST}:${FRONTEND_PORT}` && cameraOnly);
  });
  serviceManager = new DesktopServiceManager({
    app,
    getResourcePath,
    userDataPath: app.getPath('userData'),
    onStatus: (status) => { bootstrapStatus = status; },
  });
  ipcMain.handle('nodex:bootstrap-status', () => bootstrapStatus);
  ipcMain.handle('nodex:retry-bootstrap', async () => {
    try { return await bootstrap(); }
    catch (error) {
      const status = { state: 'error', message: error.message, missing: [] };
      await showSetup(status);
      return { ok: false, ...status };
    }
  });
  ipcMain.handle('nodex:open-data-folder', async () => shell.openPath(app.getPath('userData')));
  try { await bootstrap(); }
  catch (error) {
    await showSetup({ state: 'error', message: error.message, missing: [] });
  }
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) void bootstrap(); });
});

app.on('before-quit', async (event) => {
  if (!serviceManager) return;
  event.preventDefault();
  if (isQuitting) return;
  isQuitting = true;
  try { await serviceManager.stop(); }
  catch (error) { console.error('[NODEX] shutdown error:', error.message); }
  if (staticServer) {
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 3000);
      staticServer.close(() => { clearTimeout(timer); resolve(); });
    });
  }
  app.exit(0);
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

}
