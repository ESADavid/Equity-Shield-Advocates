import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

const nodeEnv = String(process.env.NODE_ENV ?? '').trim() || 'development';
const envFile = nodeEnv === 'production' ? '.env.production' : '.env';
const envPath = path.resolve(process.cwd(), envFile);

if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath, override: false });
} else {
  dotenv.config({ override: false });
}

function normalized(value) {
  return String(value ?? '').trim();
}

export const env = {
  nodeEnv: normalized(process.env.NODE_ENV) || 'development',
  port: Number(process.env.PORT || 8080),
  oauthUrl: normalized(process.env.JPM_OAUTH_URL),
  clientId: normalized(process.env.JPM_CLIENT_ID),
  clientSecret: normalized(process.env.JPM_CLIENT_SECRET),
  scope: normalized(process.env.JPM_SCOPE),
  grantType: normalized(process.env.JPM_GRANT_TYPE) || 'client_credentials',
  apiBaseUrl: normalized(process.env.JPM_API_BASE_URL) || 'https://api-sandbox.payments.jpmorgan.com',
  logLevel: normalized(process.env.LOG_LEVEL) || 'info',
  timeoutMs: Number(process.env.REQUEST_TIMEOUT_MS || 15000),
  verboseErrors: normalized(process.env.ENABLE_VERBOSE_ERRORS || 'false').toLowerCase() === 'true',
  internalApiKey: normalized(process.env.INTERNAL_API_KEY)
};

export function getMissingOAuthConfig() {
  const missing = [];
  if (!env.oauthUrl) missing.push('JPM_OAUTH_URL');
  if (!env.clientId) missing.push('JPM_CLIENT_ID');
  if (!env.clientSecret) missing.push('JPM_CLIENT_SECRET');
  if (!env.scope) missing.push('JPM_SCOPE');
  return missing;
}
