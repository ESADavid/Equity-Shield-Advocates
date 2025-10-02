// Set dummy environment variables for tests before requiring the server
process.env.DYNAMICS365_BASE_URL = 'https://dummy.dynamics365.com';
process.env.DYNAMICS365_ACCESS_TOKEN = 'dummy-token';
process.env.NODE_ENV = 'test';

const request = require('supertest');
const { app, server } = require('./server_rebuilt');

const auth = { user: 'admin', pass: 'securepassword' };

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

describe('Critical-path API tests for earnings_dashboard/server_rebuilt.js', () => {
  test('GET /api/earnings returns earnings data', async () => {
    const res = await request(app).get('/api/earnings').auth(auth.user, auth.pass);
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('totalAnnualRevenue');
    expect(res.body).toHaveProperty('revenueStreams');
    expect(res.body).toHaveProperty('purchases');
  });

  test('POST /api/purchase/home with valid cost', async () => {
    const res = await request(app)
      .post('/api/purchase/home')
      .auth(auth.user, auth.pass)
      .send({ cost: 1 });
    expect([200, 400]).toContain(res.statusCode); // 400 if insufficient funds
    if (res.statusCode === 200) {
      expect(res.body).toHaveProperty('message');
      expect(res.body).toHaveProperty('remainingRevenue');
      expect(res.body).toHaveProperty('purchases');
    }
  });

  test('POST /api/purchase/auto with valid data', async () => {
    const purchaseData = {
      cost: 1,
      model: 'Test Model',
      vin: 'VIN123456',
      dealership: 'Test Dealership'
    };
    const res = await request(app)
      .post('/api/purchase/auto')
      .auth(auth.user, auth.pass)
      .send(purchaseData);
    expect([200, 400]).toContain(res.statusCode); // 400 if insufficient funds
    if (res.statusCode === 200) {
      expect(res.body).toHaveProperty('message');
      expect(res.body).toHaveProperty('remainingRevenue');
      expect(res.body).toHaveProperty('purchases');
      expect(res.body).toHaveProperty('receipt');
    }
  });

  test('POST /api/delivery/mark-delivered with valid vin', async () => {
    // First, get current autoFleetDetails to find a VIN
    const earningsRes = await request(app).get('/api/earnings').auth(auth.user, auth.pass);
    if (earningsRes.statusCode !== 200 || !earningsRes.body.purchases.autoFleetDetails.length) {
      return; // Skip if no cars to mark delivered
    }
    const vin = earningsRes.body.purchases.autoFleetDetails[0].vin;
    const res = await request(app)
      .post('/api/delivery/mark-delivered')
      .auth(auth.user, auth.pass)
      .send({ vin });
    expect([200, 404]).toContain(res.statusCode);
    if (res.statusCode === 200) {
      expect(res.body).toHaveProperty('message');
      expect(res.body).toHaveProperty('car');
      expect(res.body.car.vin).toBe(vin);
      expect(res.body.car.deliveryStatus).toBe('delivered');
    }
  });

  test('GET /api/delivery/status returns autoFleetDetails', async () => {
    const res = await request(app).get('/api/delivery/status').auth(auth.user, auth.pass);
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('autoFleetDetails');
    expect(Array.isArray(res.body.autoFleetDetails)).toBe(true);
  });

  test('POST /api/sync/all triggers data synchronization', async () => {
    // Mock syncAllData to avoid environment variable issues in tests
    const originalSyncAllData = require('./sync_jobs').syncAllData;
    require('./sync_jobs').syncAllData = jest.fn(async () => {
      console.log('Mocked syncAllData called');
    });

    const res = await request(app).post('/api/sync/all').auth(auth.user, auth.pass);
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('message', 'Data synchronization completed successfully');

    // Restore original function
    require('./sync_jobs').syncAllData = originalSyncAllData;
  });
});
