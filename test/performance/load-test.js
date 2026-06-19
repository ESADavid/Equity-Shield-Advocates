/**
 * LOAD TESTING
 * Tests system performance under load
 */

import CitizenPortalService from '../../services/citizenPortalService.js';
import MultiChannelNotificationService from '../../services/multiChannelNotificationService.js';
import PartnerCoordinationService from '../../services/partnerCoordinationService.js';

describe('Load Testing', () => {
  describe('Concurrent User Load', () => {
    test('should handle 100 concurrent citizen registrations', async () => {
      const portalService = new CitizenPortalService();
      const startTime = Date.now();

      const promises = Array.from({ length: 100 }, (_, i) =>
        portalService.registerCitizen({
          firstName: `LoadTest${i}`,
          lastName: 'User',
          dateOfBirth: '1990-01-01',
          gender: 'male',
          nationality: 'US',
          ssn: '123-45-6789',
          email: `loadtest${i}@test.com`,
          phone: '+1234567890',
        })
      );

      const results = await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(results.every((r) => r.success)).toBe(true);
      expect(duration).toBeLessThan(10000); // 10 seconds
    });

    test('should handle 500 concurrent notifications', async () => {
      const notificationService = new MultiChannelNotificationService();
      const startTime = Date.now();

      const promises = Array.from({ length: 500 }, (_, i) =>
        notificationService.sendNotification({
          userId: `user-${i}`,
          templateId: 'citizen-welcome',
          channels: ['email'],
          data: {
            citizenName: `User ${i}`,
            citizenId: `CIT-${i}`,
            registrationDate: new Date().toISOString(),
          },
        })
      );

      const results = await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(results.filter((r) => r.success).length).toBeGreaterThan(450);
      expect(duration).toBeLessThan(15000); // 15 seconds
    });
  });

  describe('Sustained Load', () => {
    test('should maintain performance over 1000 operations', async () => {
      const portalService = new CitizenPortalService();
      const times = [];

      for (let i = 0; i < 1000; i++) {
        const start = Date.now();
        await portalService.registerCitizen({
          firstName: `Sustained${i}`,
          lastName: 'Test',
          dateOfBirth: '1990-01-01',
          gender: 'male',
          nationality: 'US',
          ssn: '123-45-6789',
          email: `sustained${i}@test.com`,
          phone: '+1234567890',
        });
        times.push(Date.now() - start);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      expect(avgTime).toBeLessThan(50); // Average < 50ms
    });
  });
});
