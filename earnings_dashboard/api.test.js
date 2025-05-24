const request = require('supertest');
const { app, server } = require('./server_rebuilt');

describe('API Endpoint Tests', () => {
  afterAll(() => {
    server.close();
  });

  const authHeader = 'Basic ' + Buffer.from('admin:securepassword').toString('base64');

  test('GET /api/earnings - success', async () => {
    const res = await request(app)
      .get('/api/earnings')
      .set('Authorization', authHeader);
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('totalAnnualRevenue');
  });

  test('GET /api/earnings - unauthorized', async () => {
    const res = await request(app).get('/api/earnings');
    expect(res.statusCode).toBe(401);
  });

  test('GET /api/earnings/download - success', async () => {
    const res = await request(app)
      .get('/api/earnings/download')
      .set('Authorization', authHeader);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-disposition']).toContain('attachment');
  });

  test('GET / - dashboard page', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.text).toContain('OWLban Earnings Dashboard');
  });
});
