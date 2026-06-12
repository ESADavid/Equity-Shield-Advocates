import axios from 'axios';
import { env, getMissingOAuthConfig } from '../config/env.js';

export async function fetchOAuthToken(requestId) {
  const missing = getMissingOAuthConfig();
  if (missing.length > 0) {
    const error = new Error(`Missing required OAuth configuration: ${missing.join(', ')}`);
    error.statusCode = 400;
    error.publicMessage = 'OAuth configuration is incomplete';
    error.validationErrors = missing.map((key) => `${key} is required.`);
    throw error;
  }

  const body = new URLSearchParams({
    client_id: env.clientId,
    client_secret: env.clientSecret,
    grant_type: env.grantType,
    scope: env.scope
  });

  try {
    const res = await axios.post(env.oauthUrl, body.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'x-request-id': requestId
      },
      timeout: env.timeoutMs
    });
    return res.data;
  } catch (e) {
    const error = new Error('Failed to fetch OAuth token from JPM');
    if (e.code === 'ECONNABORTED') {
      error.statusCode = 504;
      error.publicMessage = 'OAuth upstream timeout';
    } else if (e.response?.status) {
      error.statusCode = e.response.status;
      error.publicMessage = 'OAuth upstream request failed';
      error.upstreamStatus = e.response.status;
      error.upstreamBody = e.response.data;
    } else {
      error.statusCode = 502;
      error.publicMessage = 'OAuth upstream unreachable';
    }
    throw error;
  }
}
