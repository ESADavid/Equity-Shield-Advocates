/** @jest-environment node */
const request = require('supertest');
const express = require('express');

let server;
let app;

beforeAll(() => {
  // Import the server module freshly to avoid caching issues
  const serverModule = require('./server_rebuilt');
  app = serverModule.app;
  server = serverModule.server;
});

afterAll((done) => {
  if (server && typeof server.close === 'function') {
    server.close(done);
  } else {
    done();
  }
});

describe('Earnings Dashboard API Tests', () => {
  test('GET /api/earnings returns earnings data with status 200', async () => {
    const response = await request(app)
      .get('/api/earnings')
      .auth('admin', 'securepassword');
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('totalAnnualRevenue');
    expect(response.body).toHaveProperty('totalDailyRevenue');
    expect(response.body).toHaveProperty('revenueStreams');
    for (const stream of Object.values(response.body.revenueStreams)) {
      expect(stream).toHaveProperty('amount');
      expect(stream).toHaveProperty('accountNumber');
    }
  });

  test('GET /api/earnings without auth returns 401', async () => {
    const response = await request(app).get('/api/earnings');
    expect(response.status).toBe(401);
  });

  test('GET /api/earnings/download returns JSON file with earnings data', async () => {
    const response = await request(app)
      .get('/api/earnings/download')
      .auth('admin', 'securepassword');
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toMatch(/application\/json/);
    expect(response.headers['content-disposition']).toMatch(/attachment/);
    const body = JSON.parse(response.text);
    expect(body).toHaveProperty('totalAnnualRevenue');
    expect(body).toHaveProperty('totalDailyRevenue');
    expect(body).toHaveProperty('revenueStreams');
    for (const stream of Object.values(body.revenueStreams)) {
      expect(stream).toHaveProperty('amount');
      expect(stream).toHaveProperty('accountNumber');
    }
  });

  test('GET /api/earnings/download without auth returns 401', async () => {
    const response = await request(app).get('/api/earnings/download');
    expect(response.status).toBe(401);
  });

  test('GET / returns the HTML dashboard', async () => {
    const response = await request(app)
      .get('/')
      .auth('admin', 'securepassword');
    expect(response.status).toBe(200);
    expect(response.text).toMatch(/OWLban Earnings Dashboard/);
  });

  test('GET unknown route returns 404', async () => {
    const response = await request(app)
      .get('/unknown-route')
      .auth('admin', 'securepassword');
    expect(response.status).toBe(404);
  });

  test('POST /api/earnings returns 404 or 405', async () => {
    const response = await request(app)
      .post('/api/earnings')
      .auth('admin', 'securepassword');
    expect([404, 405]).toContain(response.status);
  });
});
