import axios from 'axios';
import { env } from '../config/env.js';

export async function fetchOAuthToken(requestId) {
  if (!env.scope || !String(env.scope).trim()) {
    const error = new Error('JPM_SCOPE is required');
    error.statusCode = 400;
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
