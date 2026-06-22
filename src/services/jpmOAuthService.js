import axios from 'axios';
import { env } from '../config/env.js';

/**
 * JPM OAuth Service
 * Handles client credentials token requests to JPMorgan OAuth endpoint
 */
export async function fetchOAuthToken() {
  const body = new URLSearchParams({
    client_id: env.clientId,
    client_secret: env.clientSecret,
    grant_type: env.grantType,
    scope: env.scope
  });

  const res = await axios.post(env.oauthUrl, body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: env.timeoutMs
  });

  return res.data;
}

/**
 * Validate OAuth token (check expiration)
 */
export function isTokenValid(tokenData) {
  if (!tokenData || !tokenData.expires_in) {
    return false;
  }
  
  // Check if token has an explicit expiration
  if (tokenData.expiry) {
    return tokenData.expiry > Date.now();
  }
  
  // Otherwise assume token is valid if it exists
  return !!tokenData.access_token;
}
