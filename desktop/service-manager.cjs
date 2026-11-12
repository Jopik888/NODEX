const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync, fork } = require('node:child_process');
const { validateRuntimeManifest } = require('./runtime-integrity.cjs');
const http = require('node:http');
const net = require('node:net');

class DesktopServiceManager {
  constructor({ app, getResourcePath, userDataPath, onStatus = () => {} }) {
    this.app = app;
    this.getResourcePath = getResourcePath;
    this.userDataPath = userDataPath;
    this.onStatus = onStatus;
    this.children = new Map();
    this.startedPostgres = false;
    this.secrets = null;
    this.stopping = false;
  }

  paths() {
    const resource = (name) => this.app.isPackaged
      ? path.join(process.resourcesPath, name)
      : this.getResourcePath('desktop', 'assets', name);
    const backend = this.app.isPackaged
      ? path.join(process.resourcesPath, 'backend')
      : this.getResourcePath('secure-disk-backend');
    const assetsRoot = this.app.isPackaged ? process.resourcesPath : this.getResourcePath('desktop', 'assets');
    return {
      frontend: this.app.isPackaged ? path.join(process.resourcesPath, 'frontend') : this.getResourcePath('secure-disk'),
      backend,
      assetsRoot,
      runtimeManifest: path.join(assetsRoot, 'RUNTIME-MANIFEST.json'),
      node: path.join(resource('runtime'), 'node.exe'),
      postgresBin: path.join(resource('postgres'), 'bin'),
      postgresShare: path.join(resource('postgres'), 'share'),
      ipfs: path.join(resource('ipfs'), 'ipfs.exe'),
    };
  }

  checkAssets() {
    const p = this.paths();
    const required = [
      ['Node.js runtime (Node 24.22.3 x64)', p.node],
      ['PostgreSQL: bin\\postgres.exe', path.join(p.postgresBin, 'postgres.exe')],
      ['PostgreSQL: bin\\initdb.exe', path.join(p.postgresBin, 'initdb.exe')],
      ['PostgreSQL: bin\\pg_ctl.exe', path.join(p.postgresBin, 'pg_ctl.exe')],
      ['PostgreSQL: bin\\createdb.exe', path.join(p.postgresBin, 'createdb.exe')],
      ['PostgreSQL: lib', path.join(path.dirname(p.postgresBin), 'lib')],
      ['PostgreSQL: share\\server', path.join(p.postgresShare, 'server')],
      ['Kubo: ipfs.exe', p.ipfs],
      ['Backend dependency: argon2', path.join(p.backend, 'node_modules', 'argon2')],
    ];
    const missing = required.filter(([, target]) => !fs.existsSync(target)).map(([label, target]) => ({ label, path: target }));
    try {
      const manifest = JSON.parse(fs.readFileSync(p.runtimeManifest, 'utf8'));
      for (const error of validateRuntimeManifest({ manifest, assetsRoot: p.assetsRoot })) {
        missing.push({ label: 'Runtime integrity verification', path: error });
      }
    } catch (error) {
      missing.push({ label: 'Runtime integrity verification', path: error.message });
    }
    const versionChecks = [
      [p.node, ['--version'], 'v24.22.3', 'Node.js must be exactly v24.22.3'],
      [path.join(p.postgresBin, 'postgres.exe'), ['--version'], 'postgres (PostgreSQL) 17.11', 'PostgreSQL must be exactly 17.11'],
      [p.ipfs, ['--version'], 'ipfs version 0.43.1', 'Kubo must be exactly 0.43.1'],
    ];
    for (const [executable, args, expected, label] of versionChecks) {
      if (!fs.existsSync(executable)) continue;
      const result = spawnSync(executable, args, { windowsHide: true, encoding: 'utf8' });
      if (result.status !== 0 || result.stdout.trim() !== expected) {
        missing.push({ label, path: `${executable} (${(result.stdout || result.stderr || '').trim()})` });
      }
    }
    return missing;
  }

  async start() {
    this.stopping = false;
    if (process.platform !== 'win32') {
      return { ok: false, message: 'Эта сборка Alpha 1 предназначена для Windows 10/11.', missing: [{ label: 'Windows 10/11', path: process.platform }] };
    }
    const missing = this.checkAssets();
    if (missing.length) {
      return {
        ok: false,
        message: 'Отсутствуют runtime-компоненты или не пройдена проверка их целостности. Дистрибутив NODEX должен содержать только проверенные файлы; Docker и ручная установка пользователем не требуются.',
        missing,
      };
    }
    try {
      await this.loadOrCreateSecrets();
      await this.startPostgres();
      await this.startIpfs();
      await this.runMigrations();
      await this.startBackend();
      this.onStatus({ state: 'ready', message: 'PostgreSQL, IPFS и backend запущены.', missing: [] });
      return { ok: true };
    } catch (error) {
      await this.stop();
      throw error;
    }
  }

  async loadOrCreateSecrets() {
    const { safeStorage } = require('electron');
    if (!safeStorage.isEncryptionAvailable()) {
      throw new Error('Windows DPAPI недоступен: невозможно безопасно сохранить секреты NODEX. Запуск остановлен.');
    }
    await fsp.mkdir(this.userDataPath, { recursive: true });
    const file = path.join(this.userDataPath, 'desktop-secrets.bin');
    try {
      const encrypted = await fsp.readFile(file);
      this.secrets = JSON.parse(safeStorage.decryptString(encrypted));
      if (!this.secrets.dbPassword || !this.secrets.syncKey) throw new Error('Invalid secrets file');
    } catch (error) {
      if (error.code !== 'ENOENT') throw new Error(`Не удалось прочитать защищённые секреты NODEX: ${error.message}`);
      this.secrets = {
        dbPassword: crypto.randomBytes(32).toString('base64url'),
        syncKey: crypto.randomBytes(32).toString('base64'),
      };
      const encrypted = safeStorage.encryptString(JSON.stringify(this.secrets));
      const tempFile = `${file}.${crypto.randomUUID()}.tmp`;
      try {
        await fsp.writeFile(tempFile, encrypted, { flag: 'wx', mode: 0o600 });
        await fsp.rename(tempFile, file);
      } finally {
        await fsp.rm(tempFile, { force: true }).catch(() => {});
      }
    }
  }

  async run(executable, args, options = {}) {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, args, { windowsHide: true, ...options });
      let stdout = '', stderr = '';
      child.stdout?.on('data', (chunk) => { stdout += chunk.toString(); });
      child.stderr?.on('data', (chunk) => { stderr += chunk.toString(); });
      child.once('error', reject);
      child.once('close', (code) => code === 0
        ? resolve({ stdout, stderr })
        : reject(new Error(`${path.basename(executable)} завершился с кодом ${code}: ${(stderr || stdout).slice(-1200)}`)));
    });
  }

  spawnService(name, executable, args, env = {}, { ipc = false, cwd = path.dirname(executable) } = {}) {
    const child = ipc
      ? fork(args[0], args.slice(1), {
        execPath: executable,
        execArgv: [],
        cwd,
        env: { ...process.env, ...env },
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      })
      : spawn(executable, args, {
        cwd,
        env: { ...process.env, ...env },
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    child.stdout.on('data', (chunk) => console.log(`[${name}] ${chunk.toString().trim()}`));
    child.stderr.on('data', (chunk) => console.error(`[${name}] ${chunk.toString().trim()}`));
    child.once('exit', (code) => {
      this.children.delete(name);
      if (!this.stopping && code !== 0) console.error(`[NODEX] ${name} exited with code ${code}`);
    });
    this.children.set(name, child);
    return child;
  }

  async assertPortAvailable(port, label) {
    await new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.once('error', (error) => {
        if (error.code === 'EADDRINUSE') reject(new Error(`Порт 127.0.0.1:${port} уже занят (${label}). Закройте конфликтующую службу и повторите запуск NODEX.`));
        else reject(error);
      });
      probe.listen(port, '127.0.0.1', () => probe.close(resolve));
    });
  }

  async waitFor(check, label, timeoutMs = 30000) {
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {
      if (await check()) return;
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
    throw new Error(`Таймаут ожидания службы: ${label}`);
  }

  async startPostgres() {
    const p = this.paths();
    const data = path.join(this.userDataPath, 'postgres-data');
    const log = path.join(this.userDataPath, 'postgres.log');
    const initdb = path.join(p.postgresBin, 'initdb.exe');
    const pgCtl = path.join(p.postgresBin, 'pg_ctl.exe');
    const createdb = path.join(p.postgresBin, 'createdb.exe');
    await fsp.mkdir(data, { recursive: true });
    if (!fs.existsSync(path.join(data, 'PG_VERSION'))) {
      const pwFile = path.join(this.userDataPath, `pg-init-${crypto.randomUUID()}.tmp`);
      await fsp.writeFile(pwFile, this.secrets.dbPassword, { mode: 0o600 });
      try {
        await this.run(initdb, ['-D', data, '-U', 'nodex', '-A', 'scram-sha-256', '--pwfile', pwFile, '--encoding=UTF8'], {
          env: { ...process.env, PATH: `${p.postgresBin};${process.env.PATH}`, PGSHARE: p.postgresShare },
        });
      } finally { await fsp.rm(pwFile, { force: true }); }
    }
    const pgStatus = spawnSync(pgCtl, ['-D', data, 'status'], { windowsHide: true, encoding: 'utf8' });
    if (pgStatus.status !== 0) {
      await this.assertPortAvailable(5432, 'PostgreSQL');
      await this.run(pgCtl, ['-D', data, '-l', log, '-o', '-h 127.0.0.1 -p 5432', '-w', 'start']);
    }
    this.startedPostgres = true;
    const env = { ...process.env, PGPASSWORD: this.secrets.dbPassword };
    try {
      await this.run(createdb, ['-h', '127.0.0.1', '-p', '5432', '-U', 'nodex', 'nodex'], { env });
    } catch (error) {
      if (!/already exists/i.test(error.message)) throw error;
    }
  }

  async startIpfs() {
    const p = this.paths();
    const repo = path.join(this.userDataPath, 'ipfs-repo');
    await fsp.mkdir(repo, { recursive: true });
    const env = { ...process.env, IPFS_PATH: repo };
    if (!fs.existsSync(path.join(repo, 'config'))) {
      await this.run(p.ipfs, ['init'], { env });
    }
    // Enforce loopback-only listeners on every launch, including existing repos.
    await this.run(p.ipfs, ['config', 'Addresses.API', '/ip4/127.0.0.1/tcp/5001'], { env });
    await this.run(p.ipfs, ['config', 'Addresses.Gateway', '/ip4/127.0.0.1/tcp/8080'], { env });
    await this.run(p.ipfs, ['config', '--json', 'API.HTTPHeaders.Access-Control-Allow-Origin', '["http://127.0.0.1:4173"]'], { env });
    await this.run(p.ipfs, ['config', '--json', 'API.HTTPHeaders.Access-Control-Allow-Methods', '["GET","POST","PUT"]'], { env });
    await this.assertPortAvailable(5001, 'Kubo API');
    await this.assertPortAvailable(8080, 'Kubo Gateway');
    const child = this.spawnService('ipfs', p.ipfs, ['daemon'], env);
    await this.waitFor(async () => {
      if (child.exitCode !== null) throw new Error('Kubo process stopped');
      return await new Promise((resolve) => {
        const req = http.request({ hostname: '127.0.0.1', port: 5001, path: '/api/v0/version', method: 'POST', timeout: 1200 }, (res) => {
          res.resume(); resolve(res.statusCode === 200);
        });
        req.on('error', () => resolve(false)); req.on('timeout', () => { req.destroy(); resolve(false); }); req.end();
      });
    }, 'IPFS Kubo', 45000);
  }

  backendEnv() {
    return {
      NODE_ENV: 'development',
      HOST: '127.0.0.1',
      PORT: '3001',
      DATABASE_URL: `postgres://nodex:${encodeURIComponent(this.secrets.dbPassword)}@127.0.0.1:5432/nodex`,
      DATABASE_SSL: 'false',
      FRONTEND_ORIGINS: 'http://127.0.0.1:4173,https://localhost,capacitor://localhost',
      SYNC_ROOM_ENCRYPTION_KEY_BASE64: this.secrets.syncKey,
      SYNC_ROOM_ENCRYPTION_KEY_VERSION: 'alpha1-local-v1',
      DEV_RETURN_VERIFICATION_TOKEN: 'true',
      COOKIE_SECURE: 'false',
      TRUST_PROXY: 'false',
    };
  }

  async runMigrations() {
    const p = this.paths();
    await this.run(p.node, [path.join(p.backend, 'scripts', 'migrate.js')], {
      cwd: p.backend,
      env: { ...process.env, ...this.backendEnv() },
    });
  }

  async startBackend() {
    const p = this.paths();
    await this.assertPortAvailable(3001, 'NODEX backend');
    const child = this.spawnService('backend', p.node, [path.join(p.backend, 'src', 'server.js')], this.backendEnv(), { ipc: true, cwd: p.backend });
    await this.waitFor(async () => {
      if (child.exitCode !== null) throw new Error('Backend process stopped');
      return await new Promise((resolve) => {
        const req = http.get('http://127.0.0.1:3001/healthz', { timeout: 1200 }, (res) => {
          res.resume(); resolve(res.statusCode === 200);
        });
        req.on('error', () => resolve(false)); req.on('timeout', () => { req.destroy(); resolve(false); });
      });
    }, 'NODEX backend', 20000);
  }

  async waitForChildExit(child, timeoutMs = 10000) {
    if (child.exitCode !== null || child.signalCode !== null) return true;
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), timeoutMs);
      child.once('close', () => { clearTimeout(timer); resolve(true); });
    });
  }

  async requestKuboShutdown() {
    return new Promise((resolve) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: 5001,
        path: '/api/v0/shutdown',
        method: 'POST',
        timeout: 2500,
      }, (res) => {
        res.resume();
        resolve(res.statusCode >= 200 && res.statusCode < 500);
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.end();
    });
  }

  async stopChild(name, { kuboShutdown = false } = {}) {
    const child = this.children.get(name);
    if (!child) return;
    if (child.exitCode !== null || child.signalCode !== null) {
      this.children.delete(name);
      return;
    }

    if (kuboShutdown) {
      await this.requestKuboShutdown();
    } else if (name === 'backend' && child.connected && typeof child.send === 'function') {
      try { child.send({ type: 'nodex:shutdown' }); }
      catch (_) { try { child.kill(); } catch (_) {} }
    } else {
      try { child.kill('SIGTERM'); } catch (_) {}
    }

    const stopped = await this.waitForChildExit(child, kuboShutdown ? 12000 : 10000);
    if (!stopped && child.exitCode === null && child.signalCode === null) {
      try { child.kill(); } catch (_) {}
      await this.waitForChildExit(child, 5000);
    }
    this.children.delete(name);
  }

  async stop() {
    this.stopping = true;
    // Stop API consumers first, then ask Kubo to shut down through its loopback API.
    await this.stopChild('backend');
    await this.stopChild('ipfs', { kuboShutdown: true });

    for (const [name] of [...this.children.entries()]) {
      await this.stopChild(name);
    }

    if (this.startedPostgres) {
      const p = this.paths();
      await this.run(path.join(p.postgresBin, 'pg_ctl.exe'), [
        '-D', path.join(this.userDataPath, 'postgres-data'), '-m', 'fast', '-w', 'stop',
      ]).catch((error) => console.error('[NODEX] PostgreSQL stop:', error.message));
      this.startedPostgres = false;
    }
  }
}

module.exports = { DesktopServiceManager };
