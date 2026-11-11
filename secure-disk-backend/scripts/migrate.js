import 'dotenv/config';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const { Client } = pg;
const here = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.resolve(here, '../migrations');
const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.error('DATABASE_URL is required. Copy .env.example to .env first.');
  process.exit(1);
}

const client = new Client({
  connectionString: databaseUrl,
  ssl: ['1', 'true', 'yes'].includes(String(process.env.DATABASE_SSL).toLowerCase())
    ? { rejectUnauthorized: true }
    : undefined,
});

async function main() {
  await client.connect();
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      checksum BYTEA NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CONSTRAINT schema_migration_checksum_len CHECK (octet_length(checksum) = 32)
    )
  `);

  await client.query('SELECT pg_advisory_lock($1)', [731_204_019]);
  try {
    const migrationFiles = (await import('node:fs/promises')).readdir(migrationsDir);
    const names = (await migrationFiles).filter((name) => name.endsWith('.sql')).sort();

    for (const name of names) {
      const fullPath = path.join(migrationsDir, name);
      const sql = await readFile(fullPath, 'utf8');
      const checksum = createHash('sha256').update(sql, 'utf8').digest();
      const existing = await client.query('SELECT checksum FROM schema_migrations WHERE name = $1', [name]);

      if (existing.rowCount === 1) {
        if (!existing.rows[0].checksum.equals(checksum)) {
          throw new Error(`Applied migration ${name} has changed. Create a new migration instead of editing it.`);
        }
        console.log(`Already applied: ${name}`);
        continue;
      }

      console.log(`Applying: ${name}`);
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [name, checksum]);
        await client.query('COMMIT');
        console.log(`Applied: ${name}`);
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }

    console.log('Database migrations are up to date.');
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [731_204_019]);
  }
}

main()
  .catch((error) => {
    console.error(`Migration failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await client.end().catch(() => {});
  });
