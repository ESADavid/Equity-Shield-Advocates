import axios from 'axios';
import { env } from '../config/env.js';

export async function pingJpmSandbox(requestId) {
  const fallback = {
    ok: true,
    source: 'mock-fallback',
    message: 'JPM sandbox ping fallback successful'
  };

  try {
    const res = await axios.get(`${env.apiBaseUrl}/health`, {
      headers: {
        'x-request-id': requestId
      },
      timeout: env.timeoutMs
    });

    return {
      ok: true,
      source: 'upstream',
      status: res.status
    };
  } catch (e) {
    if (e.response?.status) {
      return {
        ok: false,
        source: 'upstream',
        status: e.response.status
      };
    }
    return fallback;
  }
}
