const request = require('supertest');
const express = require('express');
const bodyParser = require('body-parser');

// Mock axios before requiring the module
jest.mock('axios', () => ({
  post: jest.fn(),
  get: jest.fn(),
  create: jest.fn(() => ({
    post: jest.fn(),
    get: jest.fn(),
    interceptors: {
      request: { use: jest.fn() },
      response: { use: jest.fn() }
    }
  }))
}));

const jpmorganPaymentRouter = require('./jpmorgan_payment');

const app = express();
app.use(bodyParser.json());
app.use('/api/jpmorgan-payment', jpmorganPaymentRouter);

describe('JPMorgan Payments API', () => {
  let server;
  beforeAll(() => {
    server = app.listen(0);
  });

  afterAll((done) => {
    server.close(done);
  });

  test('Health check endpoint returns healthy status', async () => {
    const res = await request(server).get('/api/jpmorgan-payment/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBeDefined();
  });

  test('Create payment with missing amount returns 400', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/create-payment')
      .send({ orderId: 'ORDER123' });
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Create payment with missing orderId returns 400', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/create-payment')
      .send({ amount: 1000 });
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  // Mock axios for successful payment creation
  test('Create payment success returns payment details', async () => {
    const axios = require('axios');
    axios.post.mockResolvedValue({
      data: {
        id: 'PAY123',
        status: 'AUTHORIZED',
        authorizationCode: 'AUTH456'
      }
    });

    const res = await request(server)
      .post('/api/jpmorgan-payment/create-payment')
      .send({ amount: 1000, orderId: 'ORDER123' });

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.paymentId).toBe('PAY123');
  });

  test('Get payment status returns 200', async () => {
    const axios = require('axios');
    axios.get.mockResolvedValue({
      data: {
        id: 'PAY123',
        status: 'CAPTURED',
        amount: 1000,
        currency: 'USD'
      }
    });

    const res = await request(server).get('/api/jpmorgan-payment/payment-status/PAY123');
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('Refund payment with missing paymentId returns 400', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/refund')
      .send({ amount: 500 });
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Capture payment with missing paymentId returns 400', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/capture')
      .send({});
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Void payment with missing paymentId returns 400', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/void')
      .send({});
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('Get transactions returns 200', async () => {
    const axios = require('axios');
    axios.get.mockResolvedValue({
      data: {
        transactions: [],
        totalCount: 0
      }
    });

    const res = await request(server).get('/api/jpmorgan-payment/transactions');
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('Webhook with missing signature returns 401', async () => {
    const res = await request(server)
      .post('/api/jpmorgan-payment/webhook')
      .send({});
    expect(res.statusCode).toBe(401);
  });

  // Additional tests for webhook signature verification and event handling can be added here
});
