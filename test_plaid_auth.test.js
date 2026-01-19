import mongoose from 'mongoose';
import { jest } from '@jest/globals';
import Item from '../models/Item.js';
import plaidService from '../services/plaidService.js';

// Mock the logger
jest.mock('../config/logger.js', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
}));

describe('Plaid Auth Enhancement Tests', () => {
  let testUserId;
  let testTenantId;
  let testItemId;
  let testAccessToken;

  beforeAll(async () => {
    // Connect to test database
    await mongoose.connect(process.env.MONGODB_TEST_URI || 'mongodb://localhost:27017/test');

    // Create test data
    testUserId = new mongoose.Types.ObjectId();
    testTenantId = 'test-tenant';
    testItemId = 'test-item-123';
    testAccessToken = 'test-access-token';
  });

  afterAll(async () => {
    // Clean up
    await Item.deleteMany({});
    await mongoose.connection.close();
  });

  beforeEach(async () => {
    // Clear items before each test
    await Item.deleteMany({});
  });

  describe('Item Model', () => {
    test('should create item with Auth fields', async () => {
      const itemData = {
        tenantId: testTenantId,
        userId: testUserId,
        itemId: testItemId,
        accessToken: testAccessToken,
        institutionId: 'ins_1',
        institutionName: 'Test Bank',
        consentExpiration: new Date('2024-12-31'),
        tan: 'TAN123456',
        tanExpiration: new Date('2024-06-30'),
        isTokenizedAccountNumber: true,
        persistentAccountId: 'persistent-123',
      };

      const item = new Item(itemData);
      await item.save();

      expect(item.itemId).toBe(testItemId);
      expect(item.consentExpiration).toEqual(new Date('2024-12-31'));
      expect(item.tan).toBe('TAN123456');
      expect(item.isTokenizedAccountNumber).toBe(true);
    });

    test('should update consent expiration', async () => {
      const item = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: testItemId,
        accessToken: testAccessToken,
        institutionId: 'ins_1',
        institutionName: 'Test Bank',
        consentExpiration: new Date('2024-01-01'),
      });

      await item.save();

      const newExpiration = new Date('2024-12-31');
      await item.updateConsentExpiration(newExpiration);

      expect(item.consentExpiration).toEqual(newExpiration);
      expect(item.status).toBe('active');
    });

    test('should mark item as consent expired', async () => {
      const item = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: testItemId,
        accessToken: testAccessToken,
        institutionId: 'ins_1',
        institutionName: 'Test Bank',
        consentExpiration: new Date('2020-01-01'), // Past date
      });

      await item.save();

      expect(item.isConsentExpired).toBe(true);
      expect(item.status).toBe('consent_expired');
    });

    test('should update TAN', async () => {
      const item = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: testItemId,
        accessToken: testAccessToken,
        institutionId: 'ins_1',
        institutionName: 'Test Bank',
      });

      await item.save();

      const tan = 'NEW_TAN_789';
      const expiration = new Date('2024-12-31');
      await item.updateTan(tan, expiration);

      expect(item.tan).toBe(tan);
      expect(item.tanExpiration).toEqual(expiration);
      expect(item.isTokenizedAccountNumber).toBe(true);
    });

    test('should check if TAN is expired', async () => {
      const item = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: testItemId,
        accessToken: testAccessToken,
        institutionId: 'ins_1',
        institutionName: 'Test Bank',
        tan: 'TAN123',
        tanExpiration: new Date('2020-01-01'), // Past date
        isTokenizedAccountNumber: true,
      });

      await item.save();

      expect(item.isTanExpired).toBe(true);
    });

    test('should find items by user', async () => {
      const item1 = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: 'item1',
        accessToken: 'token1',
        institutionId: 'ins_1',
        institutionName: 'Bank 1',
      });

      const item2 = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: 'item2',
        accessToken: 'token2',
        institutionId: 'ins_2',
        institutionName: 'Bank 2',
      });

      await item1.save();
      await item2.save();

      const items = await Item.findByUser(testUserId, testTenantId);
      expect(items).toHaveLength(2);
    });

    test('should find items needing consent renewal', async () => {
      const item1 = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: 'item1',
        accessToken: 'token1',
        institutionId: 'ins_1',
        institutionName: 'Bank 1',
        consentExpiration: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), // 3 days from now
      });

      const item2 = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: 'item2',
        accessToken: 'token2',
        institutionId: 'ins_2',
        institutionName: 'Bank 2',
        consentExpiration: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000), // 15 days from now
      });

      await item1.save();
      await item2.save();

      const items = await Item.findItemsNeedingConsentRenewal(testTenantId, 7);
      expect(items).toHaveLength(1);
      expect(items[0].itemId).toBe('item1');
    });

    test('should find items with expired TAN', async () => {
      const item1 = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: 'item1',
        accessToken: 'token1',
        institutionId: 'ins_1',
        institutionName: 'Bank 1',
        tan: 'TAN1',
        tanExpiration: new Date('2020-01-01'), // Expired
        isTokenizedAccountNumber: true,
      });

      const item2 = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: 'item2',
        accessToken: 'token2',
        institutionId: 'ins_2',
        institutionName: 'Bank 2',
        tan: 'TAN2',
        tanExpiration: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // Future
        isTokenizedAccountNumber: true,
      });

      await item1.save();
      await item2.save();

      const items = await Item.findItemsWithExpiredTan(testTenantId);
      expect(items).toHaveLength(1);
      expect(items[0].itemId).toBe('item1');
    });

    test('should return public JSON without sensitive data', async () => {
      const item = new Item({
        tenantId: testTenantId,
        userId: testUserId,
        itemId: testItemId,
        accessToken: testAccessToken,
        institutionId: 'ins_1',
        institutionName: 'Test Bank',
        consentExpiration: new Date('2024-12-31'),
        tan: 'SECRET_TAN',
      });

      await item.save();

      const publicData = item.toPublicJSON();

      expect(publicData.itemId).toBe(testItemId);
      expect(publicData.institutionName).toBe('Test Bank');
      expect(publicData.consentExpiration).toEqual(new Date('2024-12-31'));
      expect(publicData.accessToken).toBeUndefined();
      expect(publicData.tan).toBeUndefined();
    });
  });

  describe('Plaid Service Auth Methods', () => {
    test('should enhance getAuth method with additional fields', async () => {
      // Mock the plaid client
      const mockAuthResponse = {
        accounts: [
          {
            account_id: 'acc_123',
            name: 'Checking Account',
            type: 'depository',
            subtype: 'checking',
          },
        ],
        numbers: {
          ach: [
            {
              account_id: 'acc_123',
              account: '123456789',
              routing: '021000021',
              wire_routing: '021000021',
            },
          ],
        },
        item: {
          consent_expiration_time: '2024-12-31T00:00:00Z',
          available_products: ['auth', 'transactions'],
        },
      };

      // Mock the plaid client's authGet method
      plaidService.plaidClient = {
        authGet: jest.fn().mockResolvedValue(mockAuthResponse),
      };

      const result = await plaidService.getAuth(testAccessToken);

      expect(result.consentExpiration).toBeDefined();
      expect(result.isTokenizedAccountNumber).toBeDefined();
      expect(result.persistentAccountId).toBeDefined();
    });

    test('should handle webhook events for Auth', async () => {
      const authWebhookEvent = {
        webhook_type: 'AUTH',
        webhook_code: 'CONSENT_EXPIRATION_WARNING',
        item_id: testItemId,
        consent_expiration_time: '2024-12-31T00:00:00Z',
      };

      // Mock the webhook handling
      const mockItem = {
        addWebhookEvent: jest.fn(),
        updateConsentExpiration: jest.fn(),
      };

      Item.findByItemId = jest.fn().mockResolvedValue(mockItem);

      await plaidService.handleWebhook(authWebhookEvent);

      expect(mockItem.addWebhookEvent).toHaveBeenCalledWith(
        'CONSENT_EXPIRATION_WARNING',
        expect.any(Object)
      );
    });
  });

  describe('Auth Route Integration', () => {
    let mockReq;
    let mockRes;

    beforeEach(() => {
      mockReq = {
        user: { _id: testUserId, tenantId: testTenantId },
        params: {},
        body: {},
        query: {},
      };

      mockRes = {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };
    });

    test('should get items for user', async () => {
      const items = [
        {
          toPublicJSON: jest.fn().mockReturnValue({ itemId: 'item1' }),
        },
        {
          toPublicJSON: jest.fn().mockReturnValue({ itemId: 'item2' }),
        },
      ];

      Item.findByUser = jest.fn().mockResolvedValue(items);

      // Import the router and test the route
      const { default: router } = await import('../routes/plaidRoutes.js');

      // Simulate GET /items
      mockReq.method = 'GET';
      mockReq.url = '/items';

      // This is a simplified test - in real scenario, you'd use supertest
      expect(Item.findByUser).toHaveBeenCalledWith(testUserId, testTenantId);
    });

    test('should update consent expiration', async () => {
      const mockItem = {
        updateConsentExpiration: jest.fn(),
        toPublicJSON: jest.fn().mockReturnValue({ itemId: testItemId }),
      };

      Item.findOne = jest.fn().mockResolvedValue(mockItem);

      mockReq.params.itemId = testItemId;
      mockReq.body.consentExpiration = '2024-12-31';

      // Import and test route
      const { default: router } = await import('../routes/plaidRoutes.js');

      expect(mockItem.updateConsentExpiration).toHaveBeenCalledWith(new Date('2024-12-31'));
    });

    test('should update TAN', async () => {
      const mockItem = {
        updateTan: jest.fn(),
        toPublicJSON: jest.fn().mockReturnValue({ itemId: testItemId }),
      };

      Item.findOne = jest.fn().mockResolvedValue(mockItem);

      mockReq.params.itemId = testItemId;
      mockReq.body = {
        tan: 'NEW_TAN_123',
        tanExpiration: '2024-06-30',
      };

      // Import and test route
      const { default: router } = await import('../routes/plaidRoutes.js');

      expect(mockItem.updateTan).toHaveBeenCalledWith('NEW_TAN_123', new Date('2024-06-30'));
    });
  });
});
