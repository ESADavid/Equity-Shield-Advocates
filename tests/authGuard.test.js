import assert from 'node:assert/strict';
import test from 'node:test';

process.env.JPM_OAUTH_URL ??= 'https://example.invalid/oauth';
process.env.JPM_CLIENT_ID ??= 'test-client';
process.env.JPM_CLIENT_SECRET ??= 'test-secret';
process.env.JPM_SCOPE ??= 'test-scope';
process.env.INTERNAL_API_KEY = 'test-internal-api-key';

const { authGuard } = await import('../src/middleware/authGuard.js');
const { env } = await import('../src/config/env.js');

function createResponse() {
  return {
    statusCode: undefined,
    body: undefined,
    status(statusCode) {
      this.statusCode = statusCode;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    }
  };
}

test('authGuard accepts the configured key as a bearer token', () => {
  const response = createResponse();
  let nextCalled = false;

  authGuard(
    { headers: { authorization: 'Bearer test-internal-api-key' } },
    response,
    () => {
      nextCalled = true;
    }
  );

  assert.equal(nextCalled, true);
  assert.equal(response.statusCode, undefined);
});

test('authGuard rejects an arbitrary non-empty token', () => {
  const response = createResponse();
  let nextCalled = false;

  authGuard(
    { headers: { authorization: 'Bearer anything' } },
    response,
    () => {
      nextCalled = true;
    }
  );

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 401);
  assert.equal(response.body.message, 'Invalid token');
});

test('authGuard fails closed when no internal API key is configured', () => {
  const configuredKey = env.internalApiKey;
  const response = createResponse();
  let nextCalled = false;

  env.internalApiKey = undefined;
  try {
    authGuard(
      { headers: { authorization: 'Bearer test-internal-api-key' } },
      response,
      () => {
        nextCalled = true;
      }
    );
  } finally {
    env.internalApiKey = configuredKey;
  }

  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 503);
  assert.equal(response.body.message, 'Internal API authentication is not configured');
});
