/**
 * NOTIFICATION DELIVERY INTEGRATION TEST
 * Tests complete multi-channel notification delivery flow
 */

import MultiChannelNotificationService from '../../services/multiChannelNotificationService.js';

describe('Notification Delivery Integration Flow', () => {
  let notificationService;

  beforeAll(() => {
    notificationService = new MultiChannelNotificationService();
  });

  describe('Single Notification Flow', () => {
    test('should send notification through multiple channels', async () => {
      const result = await notificationService.sendNotification({
        userId: 'test-user-001',
        templateId: 'ubi-payment-success',
        channels: ['email', 'push', 'in-app'],
        data: {
          citizenName: 'Test User',
          amount: '1000',
          paymentDate: new Date().toISOString(),
          reference: 'TEST-REF-001'
        }
      });

      expect(result.success).toBe(true);
      expect(result.notificationId).toBeDefined();
      expect(result.deliveryResults).toBeDefined();
    });
  });

  describe('Batch Notification Flow', () => {
    test('should send batch notifications', async () => {
      const notifications = [
        {
          userId: 'user-1',
          templateId: 'citizen-welcome',
          channels: ['email'],
          data: { citizenName: 'User 1', citizenId: 'CIT-001', registrationDate: new Date().toISOString() }
        },
        {
          userId: 'user-2',
          templateId: 'citizen-welcome',
          channels: ['email'],
          data: { citizenName: 'User 2', citizenId: 'CIT-002', registrationDate: new Date().toISOString() }
        }
      ];

      const result = await notificationService.sendBatchNotifications(notifications);

      expect(result.success).toBe(true);
      expect(result.total).toBe(2);
      expect(result.successful).toBeGreaterThan(0);
    });
  });

  describe('Preference Management Flow', () => {
    test('should update and retrieve preferences', () => {
      const updateResult = notificationService.updatePreferences('test-user-001', {
        email: true,
        sms: false,
        push: true,
        inApp: true
      });

      expect(updateResult.success).toBe(true);

      const getResult = notificationService.getPreferences('test-user-001');
      
      expect(getResult.success).toBe(true);
      expect(getResult.preferences.email).toBe(true);
      expect(getResult.preferences.sms).toBe(false);
    });
  });
});
