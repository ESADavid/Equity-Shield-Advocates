/**
 * NOTIFICATION API ENDPOINTS TEST
 * Tests all notification route endpoints
 */

import request from 'supertest';
import express from 'express';
import notificationRoutes from '../../routes/notificationRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/notifications', notificationRoutes);

describe('Notification API Endpoints', () => {
  describe('POST /api/notifications/send', () => {
    test('should send notification', async () => {
      const response = await request(app)
        .post('/api/notifications/send')
        .send({
          userId: 'test-user',
          templateId: 'ubi-payment-success',
          channels: ['email', 'push'],
          data: {
            citizenName: 'Test User',
            amount: '1000',
            paymentDate: new Date().toISOString(),
            reference: 'TEST-001'
          }
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.notificationId).toBeDefined();
    });

    test('should handle invalid template', async () => {
      const response = await request(app)
        .post('/api/notifications/send')
        .send({
          userId: 'test-user',
          templateId: 'invalid-template',
          channels: ['email'],
          data: {}
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/notifications/batch', () => {
    test('should send batch notifications', async () => {
      const response = await request(app)
        .post('/api/notifications/batch')
        .send({
          notifications: [
            {
              userId: 'user-1',
              templateId: 'citizen-welcome',
              channels: ['email'],
              data: { citizenName: 'User 1', citizenId: 'CIT-001', registrationDate: new Date().toISOString() }
            }
          ]
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe('GET /api/notifications/templates', () => {
    test('should get all templates', async () => {
      const response = await request(app)
        .get('/api/notifications/templates');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.templates).toBeDefined();
    });
  });

  describe('GET /api/notifications/health', () => {
    test('should return health status', async () => {
      const response = await request(app)
        .get('/api/notifications/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('operational');
    });
  });
});
