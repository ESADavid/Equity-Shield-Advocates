import pg from 'pg';
import { env } from './env.js';

const { Pool } = pg;
let pool;

export function getDatabasePool() {
  if (!env.databaseUrl) {
    const error = new Error('Stripe persistence is not configured');
    error.statusCode = 503;
    throw error;
  }

  pool ??= new Pool({
    connectionString: env.databaseUrl,
    max: 10,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000
  });

  return pool;
}

export async function closeDatabasePool() {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}
