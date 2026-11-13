const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { DesktopServiceManager } = require('./service-manager.cjs');

test('shutdown order is backend, graceful Kubo, then fast PostgreSQL stop', async () => {
  const calls = [];
  const manager = new DesktopServiceManager({
    app: {},
    getResourcePath: () => '',
    userDataPath: path.win32.join('C:\\Users', 'tester', 'AppData', 'Roaming', 'NODEX'),
  });
  manager.startedPostgres = true;
  manager.paths = () => ({ postgresBin: 'C:\\NODEX\\postgres\\bin' });
  manager.stopChild = async (name, options) => calls.push(options ? [name, options] : [name]);
  manager.run = async (executable, args) => calls.push([executable, args]);

  await manager.stop();

  assert.deepEqual(calls, [
    ['backend'],
    ['ipfs', { kuboShutdown: true }],
    ['C:\\NODEX\\postgres\\bin\\pg_ctl.exe', [
      '-D', 'C:\\Users\\tester\\AppData\\Roaming\\NODEX\\postgres-data',
      '-m', 'fast', '-t', '10', '-w', 'stop',
    ]],
  ]);
  assert.equal(manager.startedPostgres, false);
});

test('backend shutdown uses IPC before forceful process termination', async () => {
  const manager = new DesktopServiceManager({
    app: {},
    getResourcePath: () => '',
    userDataPath: 'C:\\NODEX',
  });
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.connected = true;
  const messages = [];
  let killed = false;
  child.send = (message) => {
    messages.push(message);
    setImmediate(() => {
      child.exitCode = 0;
      child.connected = false;
      child.emit('close', 0, null);
    });
  };
  child.kill = () => { killed = true; };
  manager.children.set('backend', child);

  await manager.stopChild('backend');

  assert.deepEqual(messages, [{ type: 'nodex:shutdown' }]);
  assert.equal(killed, false);
  assert.equal(manager.children.has('backend'), false);
});


test('Kubo shutdown prefers the ipfs shutdown CLI with its private repository path', async () => {
  const root = path.win32.join('C:\\', 'NODEX');
  const manager = new DesktopServiceManager({
    app: {},
    getResourcePath: () => '',
    userDataPath: root,
  });
  manager.paths = () => ({ ipfs: path.win32.join(root, 'ipfs.exe') });
  let invocation;
  manager.run = async (executable, args, options) => {
    invocation = { executable, args, env: options.env };
    return { stdout: '', stderr: '' };
  };

  assert.equal(await manager.requestKuboShutdown(), true);
  assert.equal(invocation.executable, path.win32.join(root, 'ipfs.exe'));
  assert.deepEqual(invocation.args, ['shutdown']);
  assert.equal(invocation.env.IPFS_PATH, path.win32.join(root, 'ipfs-repo'));
});

test('run() kills a timed-out child process and rejects within its deadline', async () => {
  const manager = new DesktopServiceManager({
    app: {},
    getResourcePath: () => '',
    userDataPath: path.win32.join('C:\\', 'NODEX'),
  });

  await assert.rejects(
    manager.run(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], { timeoutMs: 50 }),
    /timed out after 50 ms/,
  );
});
