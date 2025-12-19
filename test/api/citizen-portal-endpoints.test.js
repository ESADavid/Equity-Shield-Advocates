/**
 * CITIZEN PORTAL API ENDPOINTS TEST
 * Tests all citizen portal route endpoints
 */

import request from 'supertest';
import express from 'express';
import citizenPortalRoutes from '../../routes/citizenPortalRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/citizen-portal', citizenPortalRoutes);

describe('Citizen Portal API Endpoints', () => {
  let testCitizenId;

  describe('POST /api/citizen-portal/register', () => {
    test('should register new citizen', async () => {
      const response = await request(app)
        .post('/api/citizen-portal/register')
        .send({
          firstName: 'API',
          lastName: 'Test',
          dateOfBirth: '1990-01-01',
          gender: 'male',
          nationality: 'US',
          ssn: '123-45-6789',
          email: 'api.test@example.com',
          phone: '+1234567890',
          address: {
            street: '123 Test St',
            city: 'Test City',
            state: 'TS',
            country: 'USA',
            postalCode: '12345',
          },
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.citizenId).toBeDefined();

      testCitizenId = response.body.citizenId;
    });
  });

  describe('GET /api/citizen-portal/profile/:citizenId', () => {
    test('should get citizen profile', async () => {
      const response = await request(app).get(
        `/api/citizen-portal/profile/${testCitizenId}`
      );

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.profile).toBeDefined();
    });

    test('should return 404 for non-existent citizen', async () => {
      const response = await request(app).get(
        '/api/citizen-portal/profile/INVALID-ID'
      );

      expect(response.status).toBe(404);
    });
  });

  describe('PUT /api/citizen-portal/profile/:citizenId', () => {
    test('should update citizen profile', async () => {
      const response = await request(app)
        .put(`/api/citizen-portal/profile/${testCitizenId}`)
        .send({
          contact: { phone: '+1987654321' },
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe('GET /api/citizen-portal/statistics', () => {
    test('should get portal statistics', async () => {
      const response = await request(app).get('/api/citizen-portal/statistics');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.statistics).toBeDefined();
    });
  });

  describe('GET /api/citizen-portal/health', () => {
    test('should return health status', async () => {
      const response = await request(app).get('/api/citizen-portal/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('operational');
    });
  });
});
