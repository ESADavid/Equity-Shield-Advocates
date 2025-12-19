/**
 * PARTNER API ENDPOINTS TEST
 * Tests all partner route endpoints
 */

import request from 'supertest';
import express from 'express';
import partnerRoutes from '../../routes/partnerRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/partners', partnerRoutes);

describe('Partner API Endpoints', () => {
  let testPartnerId;

  describe('POST /api/partners/onboard', () => {
    test('should onboard new partner', async () => {
      const response = await request(app)
        .post('/api/partners/onboard')
        .send({
          name: 'API Test Partner',
          type: 'corporate',
          contact: {
            primaryContact: {
              name: 'Test Contact',
              email: 'test@partner.com',
              phone: '+1234567890'
            }
          },
          contract: {
            startDate: new Date().toISOString(),
            duration: 12,
            value: 100000
          }
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.partnerId).toBeDefined();
      
      testPartnerId = response.body.partnerId;
    });
  });

  describe('GET /api/partners', () => {
    test('should get all partners', async () => {
      const response = await request(app)
        .get('/api/partners');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.partners).toBeDefined();
    });

    test('should filter partners by status', async () => {
      const response = await request(app)
        .get('/api/partners?status=active');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe('GET /api/partners/pmc/integration-status', () => {
    test('should get PMC integration status', async () => {
      const response = await request(app)
        .get('/api/partners/pmc/integration-status');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.integration).toBeDefined();
    });
  });

  describe('GET /api/partners/pmc/health', () => {
    test('should return PMC health status', async () => {
      const response = await request(app)
        .get('/api/partners/pmc/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('operational');
    });
  });
});
