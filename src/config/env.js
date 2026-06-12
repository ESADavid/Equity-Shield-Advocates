import 'dotenv/config';

const required = ['JPM_OAUTH_URL', 'JPM_CLIENT_ID', 'JPM_CLIENT_SECRET', 'JPM_SCOPE'];

for (const key of required) {
  if (!process.env[key]) {
    throw new Error(`Missing required env var: ${key}`);
  }
}

export const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT || 8080),
  oauthUrl: process.env.JPM_OAUTH_URL,
  clientId: process.env.JPM_CLIENT_ID,
  clientSecret: process.env.JPM_CLIENT_SECRET,
  scope: process.env.JPM_SCOPE,
  grantType: process.env.JPM_GRANT_TYPE || 'client_credentials',
  apiBaseUrl: process.env.JPM_API_BASE_URL || 'https://api-sandbox.payments.jpmorgan.com',
  logLevel: process.env.LOG_LEVEL || 'info',
  timeoutMs: Number(process.env.REQUEST_TIMEOUT_MS || 15000),
  verboseErrors: String(process.env.ENABLE_VERBOSE_ERRORS || 'false').toLowerCase() === 'true',
  internalApiKey: process.env.INTERNAL_API_KEY || ''
};
