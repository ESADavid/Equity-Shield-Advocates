import { expect } from 'chai';
import sinon from 'sinon';
import plaidService from '../services/plaidService.js';
import Item from '../models/Item.js';
import express from 'express';
import supertest from 'supertest';
import plaidRoutes from '../routes/plaidRoutes.js';

describe('Plaid Layer Integration', () => {
  let sandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

  describe('Layer Session Token Creation', () => {
    it('should create a Layer session token successfully', async () => {
      const mockResponse = {
        data: {
          session_token: 'session-token-123',
          expires_at: '2024-12-31T23:59:59Z',
        },
      };

      // Mock the Plaid client
      const mockClient = {
        sessionTokenCreate: sandbox.stub().resolves(mockResponse),
      };

      // Temporarily replace the client
      const originalClient = plaidService.plaidClient;
      plaidService.plaidClient = mockClient;

      try {
        const result = await plaidService.createSessionToken(
          'template-123',
          'user-456',
          { clientName: 'Test Client' }
        );

        expect(result).to.deep.equal(mockResponse.data);
        expect(mockClient.sessionTokenCreate.calledOnce).to.be.true;

        const callArgs = mockClient.sessionTokenCreate.firstCall.args[0];
        expect(callArgs.template_id).to.equal('template-123');
        expect(callArgs.user.client_user_id).to.equal('user-456');
        expect(callArgs.client_name).to.equal('Test Client');
      } finally {
        // Restore original client
        plaidService.plaidClient = originalClient;
      }
    });

    it('should handle Layer session token creation errors', async () => {
      const mockError = new Error('Invalid template ID');

      const mockClient = {
        sessionTokenCreate: sandbox.stub().rejects(mockError),
      };

      const originalClient = plaidService.plaidClient;
      plaidService.plaidClient = mockClient;

      try {
        await expect(plaidService.createSessionToken('invalid-template', 'user-123'))
          .to.be.rejectedWith('Invalid template ID');
      } finally {
        plaidService.plaidClient = originalClient;
      }
    });
  });

  describe('Layer User Account Session Retrieval', () => {
    it('should retrieve Layer user account session data', async () => {
      const mockSessionData = {
        data: {
          session_id: 'session-123',
          accounts: [
            {
              account_id: 'acc-123',
              name: 'Checking Account',
              type: 'depository',
              subtype: 'checking',
            },
          ],
          identity: {
            names: ['John Doe'],
            addresses: [
              {
                street: '123 Main St',
                city: 'Anytown',
                region: 'CA',
                postal_code: '12345',
                country: 'US',
              },
            ],
            emails: [
              {
                email: 'john.doe@example.com',
                primary: true,
                type: 'primary',
              },
            ],
            phone_numbers: [
              {
                phone_number: '+14155551234',
                primary: true,
                type: 'mobile',
              },
            ],
          },
        },
      };

      const mockClient = {
        userAccountSessionGet: sandbox.stub().resolves(mockSessionData),
      };

      const originalClient = plaidService.plaidClient;
      plaidService.plaidClient = mockClient;

      try {
        const result = await plaidService.getUserAccountSession('session-123');

        expect(result).to.deep.equal(mockSessionData.data);
        expect(mockClient.userAccountSessionGet.calledOnce).to.be.true;
        expect(mockClient.userAccountSessionGet.firstCall.args[0]).to.deep.equal({
          session_id: 'session-123',
        });
      } finally {
        plaidService.plaidClient = originalClient;
      }
    });
  });

  describe('Layer Webhook Handling', () => {
    let loggerStub;

    beforeEach(() => {
      loggerStub = {
        info: sandbox.stub(),
        error: sandbox.stub(),
      };

      // Mock logger in plaidService
      sandbox.stub(plaidService, 'logger').value(loggerStub);
    });

    it('should handle LAYER_AUTHENTICATION_PASSED webhook', async () => {
      const webhookEvent = {
        webhook_type: 'LAYER',
        webhook_code: 'LAYER_AUTHENTICATION_PASSED',
        session_id: 'session-123',
        item_id: 'item-456',
      };

      await plaidService.handleLayerWebhook(webhookEvent);

      expect(loggerStub.info.calledWith(
        'Layer authentication passed for session:',
        {
          session_id: 'session-123',
          item_id: 'item-456',
        }
      )).to.be.true;
    });

    it('should handle SESSION_FINISHED webhook and retrieve session data', async () => {
      const webhookEvent = {
        webhook_type: 'LAYER',
        webhook_code: 'SESSION_FINISHED',
        session_id: 'session-123',
        item_id: 'item-456',
      };

      const mockSessionData = {
        data: {
          accounts: [{ account_id: 'acc-123' }],
          identity: { names: ['John Doe'] },
        },
      };

      const getUserAccountSessionStub = sandbox.stub(plaidService, 'getUserAccountSession')
        .resolves(mockSessionData.data);

      await plaidService.handleLayerWebhook(webhookEvent);

      expect(loggerStub.info.calledWith(
        'Layer session finished:',
        {
          session_id: 'session-123',
          item_id: 'item-456',
        }
      )).to.be.true;

      expect(getUserAccountSessionStub.calledWith('session-123')).to.be.true;

      expect(loggerStub.info.calledWith(
        'Retrieved Layer session data:',
        {
          session_id: 'session-123',
          has_accounts: true,
          has_identity: true,
        }
      )).to.be.true;
    });

    it('should handle unknown Layer webhook codes', async () => {
      const webhookEvent = {
        webhook_type: 'LAYER',
        webhook_code: 'UNKNOWN_CODE',
        session_id: 'session-123',
      };

      await plaidService.handleLayerWebhook(webhookEvent);

      expect(loggerStub.info.calledWith('Unknown Layer webhook code:', 'UNKNOWN_CODE')).to.be.true;
    });

    it('should handle Layer webhook processing errors', async () => {
      const webhookEvent = {
        webhook_type: 'LAYER',
        webhook_code: 'SESSION_FINISHED',
        session_id: 'session-123',
      };

      const mockError = new Error('Session not found');
      sandbox.stub(plaidService, 'getUserAccountSession').rejects(mockError);

      await plaidService.handleLayerWebhook(webhookEvent);

      expect(loggerStub.error.calledWith('Error retrieving Layer session data:', mockError)).to.be.true;
    });
  });

  describe('Layer Sandbox Testing', () => {
    it('should test Layer with sandbox phone numbers', () => {
      // Test data from Plaid documentation
      const sandboxPhoneNumbers = [
        { number: '4155550000', notes: 'Missing all identity and bank data' },
        { number: '4155550011', notes: 'Default number for testing' },
        { number: '4155550012', notes: 'Missing PII; 3 connected banks' },
        { number: '4155550015', notes: 'Standard profile with a single bank' },
      ];

      // Verify test phone numbers are properly formatted
      sandboxPhoneNumbers.forEach((phoneData) => {
        expect(phoneData.number).to.match(/^\d{10}$/);
        expect(phoneData.notes).to.be.a('string');
      });
    });

    it('should validate Layer sandbox date of birth', () => {
      const sandboxDOB = '1975-01-18';

      expect(sandboxDOB).to.match(/^\d{4}-\d{2}-\d{2}$/);
    });
  });

  describe('Layer API Routes', () => {
    let app;
    let request;

    beforeEach(() => {
      // Mock express app for route testing
      app = express();
      app.use(express.json());

      // Import and use the routes
      app.use('/api/plaid', plaidRoutes);

      request = supertest(app);
    });

    it('should create Layer session token via API', async () => {
      const mockSessionToken = {
        session_token: 'session-token-123',
        expires_at: '2024-12-31T23:59:59Z',
      };

      sandbox.stub(plaidService, 'createSessionToken').resolves(mockSessionToken);

      const response = await request
        .post('/api/plaid/layer/session-token')
        .send({
          templateId: 'template-123',
          userId: 'user-456',
        })
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.deep.equal(mockSessionToken);
    });

    it('should retrieve Layer user session data via API', async () => {
      const mockSessionData = {
        session_id: 'session-123',
        accounts: [{ account_id: 'acc-123' }],
        identity: { names: ['John Doe'] },
      };

      sandbox.stub(plaidService, 'getUserAccountSession').resolves(mockSessionData);

      const response = await request
        .get('/api/plaid/layer/user-session/session-123')
        .expect(200);

      expect(response.body.success).to.be.true;
      expect(response.body.data).to.deep.equal(mockSessionData);
    });

    it('should validate required parameters for Layer session token', async () => {
      const response = await request
        .post('/api/plaid/layer/session-token')
        .send({})
        .expect(400);

      expect(response.body.success).to.be.false;
      expect(response.body.message).to.include('Template ID and user ID are required');
    });

    it('should handle Layer API errors gracefully', async () => {
      const mockError = new Error('Layer service unavailable');

      sandbox.stub(plaidService, 'createSessionToken').rejects(mockError);

      const response = await request
        .post('/api/plaid/layer/session-token')
        .send({
          templateId: 'template-123',
          userId: 'user-456',
        })
        .expect(500);

      expect(response.body.success).to.be.false;
      expect(response.body.message).to.include('Failed to create Layer session token');
    });
  });
});
