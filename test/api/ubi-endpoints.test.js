/**
 * UBI API ENDPOINTS TEST
 * Tests all UBI payment route endpoints
 */

import request from 'supertest';
import express from 'express';
import ubiRoutes from '../../routes/ubiPaymentRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/ubi', ubiRoutes);

describe('UBI API Endpoints', () => {
  test('POST /api/ubi/process-payment', async () => {
    const response = await request(app).post('/api/ubi/process-payment').send({
      citizenId: 'CIT-TEST-001',
      amount: 1000,
      paymentDate: new Date().toISOString(),
    });

    expect([200, 201]).toContain(response.status);
  });

  test('GET /api/ubi/payment-history/:citizenId', async () => {
    const response = await request(app).get(
      '/api/ubi/payment-history/CIT-TEST-001'
    );

    expect(response.status).toBe(200);
  });

  test('GET /api/ubi/statistics', async () => {
    const response = await request(app).get('/api/ubi/statistics');

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
  });

  test('GET /api/ubi/health', async () => {
    const response = await request(app).get('/api/ubi/health');

    expect(response.status).toBe(200);
    expect(response.body.status).toBe('operational');
  });
});
