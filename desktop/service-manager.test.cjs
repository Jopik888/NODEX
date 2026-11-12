const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
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
      '-m', 'fast', '-w', 'stop',
    ]],
  ]);
  assert.equal(manager.startedPostgres, false);
});
