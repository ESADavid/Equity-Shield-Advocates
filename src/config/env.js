import 'dotenv/config';

const required = ['JPM_OAUTH_URL', 'JPM_CLIENT_ID', 'JPM_CLIENT_SECRET', 'JPM_SCOPE'];
const missing = [];

for (const key of required) {
  if (!process.env[key]) {
    missing.push(key);
  }
}

if (missing.length > 0) {
  throw new Error(`Missing required env var(s): ${missing.join(', ')}`);
}

export const env = {
  port: Number(process.env.PORT || 8080),
  nodeEnv: process.env.NODE_ENV || 'development',
  oauthUrl: process.env.JPM_OAUTH_URL,
  clientId: process.env.JPM_CLIENT_ID,
  clientSecret: process.env.JPM_CLIENT_SECRET,
  scope: process.env.JPM_SCOPE,
  grantType: process.env.JPM_GRANT_TYPE || 'client_credentials',
  apiBaseUrl: process.env.JPM_API_BASE_URL || 'https://api-sandbox.payments.jpmorgan.com',
  logLevel: process.env.LOG_LEVEL || 'info',
  timeoutMs: Number(process.env.REQUEST_TIMEOUT_MS || 15000),
  enableVerboseErrors: process.env.ENABLE_VERBOSE_ERRORS === 'true'
};
