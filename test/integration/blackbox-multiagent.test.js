import request from 'supertest';
import app from '../../server-enhanced.js';
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';

describe('Blackbox Multi-Agent API', () => {
  let server;

  beforeAll(() => {
    server = app.listen();
  });

  afterAll(() => {
    server.close();
  });

  it('should create multi-agent task', async () => {
    const response = await request(app)
      .post('/api/multi-agent/create')
      .send({
        prompt: 'Test Blackbox integration',
        selectedAgents: [
          { agent: 'claude', model: 'blackboxai/anthropic/claude-sonnet-4.5' }
        ]
      })
      .expect(200);

    expect(response.body).toHaveProperty('success', true);
    expect(response.body).toHaveProperty('taskId');
    expect(response.body).toHaveProperty('taskUrl');
  });

  it('should get optimize repo', async () => {
    const response = await request(app)
      .post('/api/multi-agent/optimize')
      .send({ prompt: 'Optimize test' })
      .expect(200);

    expect(response.body).toHaveProperty('success', true);
  });

  it('should return status for non-existing task', async () => {
    const response = await request(app)
      .get('/api/multi-agent/status/test123')
      .expect(500);

    expect(response.body).toHaveProperty('success', false);
  });
});
