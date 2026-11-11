import pg from 'pg';
import { config } from '../config/index.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.databaseUrl,
  ssl: config.databaseSsl ? { rejectUnauthorized: true } : undefined,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  application_name: 'secure-disk-backend-v0.4.3',
});

pool.on('error', (error) => {
  console.error(JSON.stringify({ level: 'error', event: 'postgres_pool_error', message: error.message }));
});

export async function withTransaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackError) {
      console.error(JSON.stringify({ level: 'error', event: 'postgres_rollback_failed', message: rollbackError.message }));
    }
    throw error;
  } finally {
    client.release();
  }
}

/** Serialize security-sensitive device/Vault lifecycle transactions per account.
 * These operations are infrequent and must not deadlock when pairings and
 * device revocations touch overlapping rows in opposite orders.
 */
export async function lockUserSecurityState(client, userId) {
  if (typeof userId !== 'string' || !userId) throw new TypeError('userId is required for the security-state lock.');
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`secure-disk-security:${userId}`]);
}
