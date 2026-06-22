import axios from 'axios';
import { env } from '../config/env.js';

/**
 * JPM API Client
 * Handles authenticated requests to JPM API endpoints
 */
export function createJpmApiClient(accessToken) {
  const client = axios.create({
    baseURL: env.apiBaseUrl,
    timeout: env.timeoutMs,
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    }
  });

  // Request interceptor for logging
  client.interceptors.request.use(
    (config) => {
      console.log(JSON.stringify({
        type: 'request',
        method: config.method,
        url: config.url,
        requestId: config.headers['x-request-id']
      }));
      return config;
    },
    (error) => {
      console.error(JSON.stringify({ type: 'request_error', error: error.message }));
      return Promise.reject(error);
    }
  );

  // Response interceptor for logging
  client.interceptors.response.use(
    (response) => {
      console.log(JSON.stringify({
        type: 'response',
        status: response.status,
        url: response.config.url
      }));
      return response;
    },
    (error) => {
      console.error(JSON.stringify({
        type: 'response_error',
        status: error.response?.status,
        error: error.message
      }));
      return Promise.reject(error);
    }
  );

  return client;
}

/**
 * Ping JPM endpoint (protected)
 */
export async function pingJpm(client) {
  const response = await client.get('/v1/ping');
  return response.data;
}
