/**
 * SERVICE PERFORMANCE TEST
 * Tests service response times and throughput
 */

import CitizenPortalService from '../../services/citizenPortalService.js';
import PartnerCoordinationService from '../../services/partnerCoordinationService.js';
import MultiChannelNotificationService from '../../services/multiChannelNotificationService.js';

describe('Service Performance Tests', () => {
  describe('Citizen Portal Performance', () => {
    test('should register citizen within 200ms', async () => {
      const portalService = new CitizenPortalService();
      const startTime = Date.now();

      await portalService.registerCitizen({
        firstName: 'Performance',
        lastName: 'Test',
        dateOfBirth: '1990-01-01',
        gender: 'male',
        nationality: 'US',
        ssn: '123-45-6789',
        email: 'perf@test.com',
        phone: '+1234567890'
      });

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(200);
    });

    test('should handle 100 concurrent registrations', async () => {
      const portalService = new CitizenPortalService();
      const startTime = Date.now();

      const promises = Array.from({ length: 100 }, (_, i) =>
        portalService.registerCitizen({
          firstName: `User${i}`,
          lastName: 'Test',
          dateOfBirth: '1990-01-01',
          gender: 'male',
          nationality: 'US',
          ssn: '123-45-6789',
          email: `user${i}@test.com`,
          phone: '+1234567890'
        })
      );

      await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(5000); // 5 seconds for 100 registrations
    });
  });

  describe('Notification Service Performance', () => {
    test('should send notification within 100ms', async () => {
      const notificationService = new MultiChannelNotificationService();
      const startTime = Date.now();

      await notificationService.sendNotification({
        userId: 'perf-test',
        templateId: 'citizen-welcome',
        channels: ['email'],
        data: {
          citizenName: 'Test',
          citizenId: 'CIT-001',
          registrationDate: new Date().toISOString()
        }
      });

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(100);
    });

    test('should handle batch notifications efficiently', async () => {
      const notificationService = new MultiChannelNotificationService();
      const startTime = Date.now();

      const notifications = Array.from({ length: 50 }, (_, i) => ({
        userId: `user-${i}`,
        templateId: 'citizen-welcome',
        channels: ['email'],
        data: {
          citizenName: `User ${i}`,
          citizenId: `CIT-${i}`,
          registrationDate: new Date().toISOString()
        }
      }));

      await notificationService.sendBatchNotifications(notifications);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(2000); // 2 seconds for 50 notifications
    });
  });

  describe('Partner Service Performance', () => {
    test('should onboard partner within 150ms', async () => {
      const partnerService = new PartnerCoordinationService();
      const startTime = Date.now();

      await partnerService.onboardPartner({
        name: 'Performance Test Partner',
        type: 'corporate',
        contact: {
          primaryContact: {
            name: 'Test',
            email: 'test@partner.com',
            phone: '+1234567890'
          }
        }
      }, 'test-admin');

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(150);
    });
  });

  describe('Memory Usage', () => {
    test('should not leak memory during repeated operations', async () => {
      const portalService = new CitizenPortalService();
      const initialMemory = process.memoryUsage().heapUsed;

      for (let i = 0; i < 100; i++) {
        await portalService.registerCitizen({
          firstName: `MemTest${i}`,
          lastName: 'Test',
          dateOfBirth: '1990-01-01',
          gender: 'male',
          nationality: 'US',
          ssn: '123-45-6789',
          email: `memtest${i}@test.com`,
          phone: '+1234567890'
        });
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = (finalMemory - initialMemory) / 1024 / 1024; // MB

      expect(memoryIncrease).toBeLessThan(50); // Less than 50MB increase
    });
  });
});
