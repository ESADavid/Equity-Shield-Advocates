const request = require('supertest');
const express = require('express');
const bodyParser = require('body-parser');
const jpmorganPaymentRouter = require('./earnings_dashboard/jpmorgan_payment');

// Create test app
const app = express();
app.use(bodyParser.json());
app.use('/api/jpmorgan-payment', jpmorganPaymentRouter);

// Test server
let server;

describe('JPMorgan Payments Integration Tests', () => {
  beforeAll(() => {
    server = app.listen(0);
  });

  afterAll((done) => {
    server.close(done);
  });

  test('Health check endpoint returns status', async () => {
    const res = await request(server).get('/api/jpmorgan-payment/health');
    expect(res.statusCode).toBe(200);
    expect(res.body).toBeDefined();
  });

  test('Create payment validation (missing amount) returns 400', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/create-payment')
      .send({ orderId: 'ORDER123' });
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Create payment validation (missing orderId) returns 400', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/create-payment')
      .send({ amount: 1000 });
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Get payment status returns response', async () => {
    const res = await request(server).get('/api/jpmorgan-payment/payment-status/TEST123');
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBeDefined();
  });

  test('Webhook security (missing signature) returns 401', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/webhook')
      .send({ type: 'test.event' });
    expect(res.statusCode).toBe(401);
  });
});
