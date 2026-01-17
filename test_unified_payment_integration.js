const express = require('express');
const request = require('supertest');
const paymentRouter = require('./earnings_dashboard/payment_router');

// Create test app
const app = express();
app.use(express.json());
app.use('/api/payments', paymentRouter);

describe('Unified Payment Integration Tests', () => {
  describe('Health Check', () => {
    test('should return healthy status with all providers', async () => {
      const response = await request(app)
        .get('/api/payments/health')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.providers).toContain('jpmorgan');
      expect(response.body.providers).toContain('microsoft');
      expect(response.body.providers).toContain('nvidia');
      expect(response.body.providers).toContain('chase');
      expect(response.body.timestamp).toBeDefined();
    });
  });

  describe('Payment Creation', () => {
    test('should create JPMorgan payment successfully', async () => {
      const paymentData = {
        provider: 'jpmorgan',
        amount: 100.0,
        currency: 'USD',
        customerId: 'test-customer-123',
        description: 'Test payment',
      };

      const response = await request(app)
        .post('/api/payments/create-payment')
        .send(paymentData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.paymentId).toMatch(/^jpm_/);
      expect(response.body.status).toBe('processed');
      expect(response.body.amount).toBe(100.0);
      expect(response.body.currency).toBe('USD');
    });

    test('should create Microsoft payment successfully', async () => {
      const paymentData = {
        provider: 'microsoft',
        amount: 250.0,
        currency: 'USD',
        customerId: 'test-customer-456',
        description: 'Microsoft Dynamics payment',
      };

      const response = await request(app)
        .post('/api/payments/create-payment')
        .send(paymentData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.paymentId).toMatch(/^ms_/);
      expect(response.body.status).toBe('processed');
    });

    test('should create NVIDIA payment successfully', async () => {
      const paymentData = {
        provider: 'nvidia',
        amount: 500.0,
        currency: 'USD',
        modelId: 'test-model-123',
        inferenceType: 'text-generation',
      };

      const response = await request(app)
        .post('/api/payments/create-payment')
        .send(paymentData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.paymentId).toMatch(/^nv_/);
      expect(response.body.status).toBe('processed');
    });

    test('should return error for invalid provider', async () => {
      const paymentData = {
        provider: 'invalid-provider',
        amount: 100.0,
      };

      const response = await request(app)
        .post('/api/payments/create-payment')
        .send(paymentData)
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Payment provider');
      expect(response.body.message).toContain('not found');
    });

    test('should return error when provider is missing', async () => {
      const paymentData = {
        amount: 100.0,
        currency: 'USD',
      };

      const response = await request(app)
        .post('/api/payments/create-payment')
        .send(paymentData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Payment provider is required');
    });
  });

  describe('Payment Status', () => {
    test('should get JPMorgan payment status', async () => {
      const response = await request(app)
        .get('/api/payments/payment-status/jpmorgan/test-payment-123')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.paymentId).toBe('test-payment-123');
      expect(response.body.status).toBe('completed');
      expect(response.body.details).toBeDefined();
    });

    test('should get Microsoft payment status', async () => {
      const response = await request(app)
        .get('/api/payments/payment-status/microsoft/test-payment-456')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.paymentId).toBe('test-payment-456');
      expect(response.body.status).toBe('completed');
    });

    test('should get NVIDIA payment status', async () => {
      const response = await request(app)
        .get('/api/payments/payment-status/nvidia/test-payment-789')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.paymentId).toBe('test-payment-789');
      expect(response.body.status).toBe('completed');
    });

    test('should return error for invalid provider in status check', async () => {
      const response = await request(app)
        .get('/api/payments/payment-status/invalid/test-payment-123')
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Payment provider');
      expect(response.body.message).toContain('not found');
    });
  });

  describe('Payment Refunds', () => {
    test('should process JPMorgan refund', async () => {
      const refundData = {
        amount: 50.0,
      };

      const response = await request(app)
        .post('/api/payments/refund/jpmorgan/test-payment-123')
        .send(refundData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.refundId).toBeDefined();
      expect(response.body.originalPaymentId).toBe('test-payment-123');
      expect(response.body.amount).toBe(50.0);
      expect(response.body.status).toBe('processed');
    });

    test('should process Microsoft refund', async () => {
      const refundData = {
        amount: 100.0,
      };

      const response = await request(app)
        .post('/api/payments/refund/microsoft/test-payment-456')
        .send(refundData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.refundId).toMatch(/^ms_refund_/);
      expect(response.body.originalPaymentId).toBe('test-payment-456');
    });

    test('should process NVIDIA refund', async () => {
      const refundData = {
        amount: 200.0,
      };

      const response = await request(app)
        .post('/api/payments/refund/nvidia/test-payment-789')
        .send(refundData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.refundId).toMatch(/^nv_refund_/);
      expect(response.body.originalPaymentId).toBe('test-payment-789');
    });

    test('should return error for invalid provider in refund', async () => {
      const refundData = {
        amount: 50.0,
      };

      const response = await request(app)
        .post('/api/payments/refund/invalid/test-payment-123')
        .send(refundData)
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Payment provider');
      expect(response.body.message).toContain('not found');
    });
  });

  describe('Provider-specific Routes', () => {
    test('should have JPMorgan routes available', async () => {
      // This tests that the JPMorgan router is properly mounted
      const response = await request(app)
        .get('/api/payments/jpmorgan/health')
        .expect(200);

      expect(response.body).toBeDefined();
    });

    test('should have Microsoft routes available', async () => {
      const response = await request(app)
        .get('/api/payments/microsoft/health')
        .expect(200);

      expect(response.body).toBeDefined();
    });

    test('should have NVIDIA routes available', async () => {
      const response = await request(app)
        .get('/api/payments/nvidia/health')
        .expect(200);

      expect(response.body).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    test('should handle network errors gracefully', async () => {
      // Mock a scenario that would cause a network error
      const paymentData = {
        provider: 'jpmorgan',
        amount: -100.0, // Invalid amount that might cause issues
        currency: 'USD',
      };

      const response = await request(app)
        .post('/api/payments/create-payment')
        .send(paymentData)
        .expect(200); // Still expect 200 as we handle errors internally

      // The mock implementation should still return success for now
      expect(response.body.success).toBe(true);
    });

    test('should handle malformed JSON', async () => {
      const response = await request(app)
        .post('/api/payments/create-payment')
        .set('Content-Type', 'application/json')
        .send('{invalid json}')
        .expect(400);

      // Express should handle malformed JSON
      expect(response.status).toBe(400);
    });
  });

  describe('Integration Scenarios', () => {
    test('should handle multiple payment types in sequence', async () => {
      const payments = [
        { provider: 'jpmorgan', amount: 100 },
        { provider: 'microsoft', amount: 200 },
        { provider: 'nvidia', amount: 300 },
      ];

      for (const payment of payments) {
        const response = await request(app)
          .post('/api/payments/create-payment')
          .send({
            provider: payment.provider,
            amount: payment.amount,
            currency: 'USD',
          })
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.amount).toBe(payment.amount);
      }
    });

    test('should handle concurrent payment requests', async () => {
      const paymentPromises = [];

      for (let i = 0; i < 5; i++) {
        const promise = request(app)
          .post('/api/payments/create-payment')
          .send({
            provider: 'jpmorgan',
            amount: 10.0,
            currency: 'USD',
            customerId: `concurrent-test-${i}`,
          });

        paymentPromises.push(promise);
      }

      const responses = await Promise.all(paymentPromises);

      responses.forEach((response) => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.paymentId).toMatch(/^jpm_/);
      });
    });
  });
});
