import { app } from './app.js';
import { config } from './config/index.js';
import { pool } from './db/pool.js';

let server;

async function start() {
  await pool.query('SELECT 1');
  server = app.listen(config.port, config.host, () => {
    console.log(JSON.stringify({
      level: 'info',
      event: 'server_started',
      host: config.host,
      port: config.port,
      environment: config.nodeEnv,
      api_base: `http://${config.host}:${config.port}/api/v1`,
    }));
  });
}

async function shutdown(signal) {
  console.log(JSON.stringify({ level: 'info', event: 'server_shutdown', signal }));
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  await pool.end();
  process.exit(0);
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

start().catch(async (error) => {
  console.error(JSON.stringify({ level: 'fatal', event: 'server_start_failed', message: error.message }));
  await pool.end().catch(() => {});
  process.exit(1);
});
