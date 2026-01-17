const nodemailer = require('nodemailer');
const twilio = require('twilio');

// Mock nodemailer
jest.mock('nodemailer', () => ({
  createTransporter: jest.fn(() => ({
    sendMail: jest.fn(),
  })),
}));

// Mock twilio
jest.mock('twilio', () =>
  jest.fn(() => ({
    messages: {
      create: jest.fn(),
    },
  }))
);

// Import the module after mocking
const merchantBillPay = require('./earnings_dashboard/merchant_bill_pay');

describe('Merchant Notification System', () => {
  let mockTransporter;
  let mockTwilioClient;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Setup mock transporter
    mockTransporter = {
      sendMail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' }),
    };
    nodemailer.createTransporter.mockReturnValue(mockTransporter);

    // Setup mock Twilio client
    mockTwilioClient = {
      messages: {
        create: jest.fn().mockResolvedValue({ sid: 'test-sms-sid' }),
      },
    };
    twilio.mockReturnValue(mockTwilioClient);

    // Set up environment variables for testing
    process.env.SMTP_HOST = 'smtp.test.com';
    process.env.SMTP_PORT = '587';
    process.env.SMTP_USER = 'test@test.com';
    process.env.SMTP_PASS = 'testpass';
    process.env.TWILIO_SID = 'test-sid';
    process.env.TWILIO_AUTH_TOKEN = 'test-token';
    process.env.TWILIO_PHONE_NUMBER = '+1234567890';
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.SMTP_HOST;
    delete process.env.SMTP_PORT;
    delete process.env.SMTP_USER;
    delete process.env.SMTP_PASS;
    delete process.env.TWILIO_SID;
    delete process.env.TWILIO_AUTH_TOKEN;
    delete process.env.TWILIO_PHONE_NUMBER;
  });

  describe('Email Transporter Configuration', () => {
    test('should create transporter with correct configuration', () => {
      // Re-import to trigger the transporter creation
      jest.resetModules();
      require('./earnings_dashboard/merchant_bill_pay');

      expect(nodemailer.createTransporter).toHaveBeenCalledWith({
        host: 'smtp.test.com',
        port: 587,
        secure: false,
        auth: {
          user: 'test@test.com',
          pass: 'testpass',
        },
      });
    });

    test('should use default values when environment variables are not set', () => {
      // Clear environment variables
      delete process.env.SMTP_HOST;
      delete process.env.SMTP_PORT;
      delete process.env.SMTP_USER;
      delete process.env.SMTP_PASS;

      jest.resetModules();
      require('./earnings_dashboard/merchant_bill_pay');

      expect(nodemailer.createTransporter).toHaveBeenCalledWith({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
          user: undefined,
          pass: undefined,
        },
      });
    });
  });

  describe('sendMerchantPaymentSuccessNotification', () => {
    test('should send success email notification', async () => {
      const merchantId = 'merchant_001';
      const amount = 150.0;
      const paymentIntentId = 'pi_test_123';

      // Mock the helper functions
      const originalGetMerchantEmail = merchantBillPay.getMerchantEmail;
      const originalGetMerchantPhone = merchantBillPay.getMerchantPhone;
      merchantBillPay.getMerchantEmail = jest
        .fn()
        .mockReturnValue('merchant1@example.com');
      merchantBillPay.getMerchantPhone = jest
        .fn()
        .mockReturnValue('+1234567890');

      // Call the notification function
      await merchantBillPay.sendMerchantPaymentSuccessNotification(
        merchantId,
        amount,
        paymentIntentId
      );

      // Verify email was sent
      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'test@test.com',
        to: 'merchant1@example.com',
        subject: 'Payment Received - Oscar Broome Revenue System',
        html: expect.stringContaining('Payment Successfully Processed'),
      });

      // Verify SMS was sent
      expect(mockTwilioClient.messages.create).toHaveBeenCalledWith({
        body: `Payment of $${amount.toFixed(2)} received. Payment ID: ${paymentIntentId}`,
        from: '+1234567890',
        to: '+1234567890',
      });

      // Restore original functions
      merchantBillPay.getMerchantEmail = originalGetMerchantEmail;
      merchantBillPay.getMerchantPhone = originalGetMerchantPhone;
    });

    test('should not send email if merchant email is not found', async () => {
      const merchantId = 'unknown_merchant';
      const amount = 100.0;
      const paymentIntentId = 'pi_test_456';

      // Mock the helper functions
      const originalGetMerchantEmail = merchantBillPay.getMerchantEmail;
      const originalGetMerchantPhone = merchantBillPay.getMerchantPhone;
      merchantBillPay.getMerchantEmail = jest.fn().mockReturnValue(null);
      merchantBillPay.getMerchantPhone = jest
        .fn()
        .mockReturnValue('+1234567890');

      // Call the notification function
      await merchantBillPay.sendMerchantPaymentSuccessNotification(
        merchantId,
        amount,
        paymentIntentId
      );

      // Verify email was not sent
      expect(mockTransporter.sendMail).not.toHaveBeenCalled();

      // But SMS should still be sent
      expect(mockTwilioClient.messages.create).toHaveBeenCalled();

      // Restore original functions
      merchantBillPay.getMerchantEmail = originalGetMerchantEmail;
      merchantBillPay.getMerchantPhone = originalGetMerchantPhone;
    });

    test('should handle email sending errors gracefully', async () => {
      const merchantId = 'merchant_001';
      const amount = 200.0;
      const paymentIntentId = 'pi_test_789';

      // Mock email sending to throw error
      mockTransporter.sendMail.mockRejectedValue(
        new Error('SMTP connection failed')
      );

      // Mock the helper functions
      const originalGetMerchantEmail = merchantBillPay.getMerchantEmail;
      merchantBillPay.getMerchantEmail = jest
        .fn()
        .mockReturnValue('merchant1@example.com');

      // Spy on console.error
      const consoleSpy = jest
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      // Call the notification function
      await merchantBillPay.sendMerchantPaymentSuccessNotification(
        merchantId,
        amount,
        paymentIntentId
      );

      // Verify error was logged
      expect(consoleSpy).toHaveBeenCalledWith(
        'Error sending payment success notification:',
        expect.any(Error)
      );

      // Restore
      merchantBillPay.getMerchantEmail = originalGetMerchantEmail;
      consoleSpy.mockRestore();
    });
  });

  describe('sendMerchantPaymentFailureNotification', () => {
    test('should send failure email notification', async () => {
      const merchantId = 'merchant_002';
      const amount = 75.5;
      const paymentIntentId = 'pi_test_failed';
      const errorMessage = 'Card declined';

      // Mock the helper functions
      const originalGetMerchantEmail = merchantBillPay.getMerchantEmail;
      const originalGetMerchantPhone = merchantBillPay.getMerchantPhone;
      merchantBillPay.getMerchantEmail = jest
        .fn()
        .mockReturnValue('merchant2@example.com');
      merchantBillPay.getMerchantPhone = jest
        .fn()
        .mockReturnValue('+0987654321');

      // Call the notification function
      await merchantBillPay.sendMerchantPaymentFailureNotification(
        merchantId,
        amount,
        paymentIntentId,
        errorMessage
      );

      // Verify email was sent with failure content
      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'test@test.com',
        to: 'merchant2@example.com',
        subject: 'Payment Failed - Oscar Broome Revenue System',
        html: expect.stringContaining('Payment Processing Failed'),
      });

      // Verify SMS was sent with failure message
      expect(mockTwilioClient.messages.create).toHaveBeenCalledWith({
        body: `Payment of $${amount.toFixed(2)} failed. Error: ${errorMessage}`,
        from: '+1234567890',
        to: '+0987654321',
      });

      // Restore original functions
      merchantBillPay.getMerchantEmail = originalGetMerchantEmail;
      merchantBillPay.getMerchantPhone = originalGetMerchantPhone;
    });
  });

  describe('SMS Notification', () => {
    test('should not send SMS when Twilio is not configured', async () => {
      // Clear Twilio environment variables
      delete process.env.TWILIO_SID;
      delete process.env.TWILIO_AUTH_TOKEN;

      const merchantId = 'merchant_001';
      const amount = 100.0;
      const paymentIntentId = 'pi_test_123';

      // Mock the helper functions
      const originalGetMerchantEmail = merchantBillPay.getMerchantEmail;
      const originalGetMerchantPhone = merchantBillPay.getMerchantPhone;
      merchantBillPay.getMerchantEmail = jest
        .fn()
        .mockReturnValue('merchant1@example.com');
      merchantBillPay.getMerchantPhone = jest
        .fn()
        .mockReturnValue('+1234567890');

      // Call the notification function
      await merchantBillPay.sendMerchantPaymentSuccessNotification(
        merchantId,
        amount,
        paymentIntentId
      );

      // Verify SMS was not sent
      expect(mockTwilioClient.messages.create).not.toHaveBeenCalled();

      // Restore original functions
      merchantBillPay.getMerchantEmail = originalGetMerchantEmail;
      merchantBillPay.getMerchantPhone = originalGetMerchantPhone;
    });

    test('should handle SMS sending errors gracefully', async () => {
      const merchantId = 'merchant_001';
      const amount = 100.0;
      const paymentIntentId = 'pi_test_123';

      // Mock SMS sending to throw error
      mockTwilioClient.messages.create.mockRejectedValue(
        new Error('Twilio API error')
      );

      // Mock the helper functions
      const originalGetMerchantEmail = merchantBillPay.getMerchantEmail;
      const originalGetMerchantPhone = merchantBillPay.getMerchantPhone;
      merchantBillPay.getMerchantEmail = jest
        .fn()
        .mockReturnValue('merchant1@example.com');
      merchantBillPay.getMerchantPhone = jest
        .fn()
        .mockReturnValue('+1234567890');

      // Spy on console.error
      const consoleSpy = jest
        .spyOn(console, 'error')
        .mockImplementation(() => {});

      // Call the notification function
      await merchantBillPay.sendMerchantPaymentSuccessNotification(
        merchantId,
        amount,
        paymentIntentId
      );

      // Verify error was logged
      expect(consoleSpy).toHaveBeenCalledWith(
        'Error sending SMS notification:',
        expect.any(Error)
      );

      // Restore
      merchantBillPay.getMerchantEmail = originalGetMerchantEmail;
      merchantBillPay.getMerchantPhone = originalGetMerchantPhone;
      consoleSpy.mockRestore();
    });
  });

  describe('Merchant Contact Lookup', () => {
    test('getMerchantEmail should return correct email for known merchant', () => {
      expect(merchantBillPay.getMerchantEmail('merchant_001')).toBe(
        'merchant1@example.com'
      );
      expect(merchantBillPay.getMerchantEmail('merchant_002')).toBe(
        'merchant2@example.com'
      );
    });

    test('getMerchantEmail should return null for unknown merchant', () => {
      expect(merchantBillPay.getMerchantEmail('unknown_merchant')).toBeNull();
    });

    test('getMerchantPhone should return correct phone for known merchant', () => {
      expect(merchantBillPay.getMerchantPhone('merchant_001')).toBe(
        '+1234567890'
      );
      expect(merchantBillPay.getMerchantPhone('merchant_002')).toBe(
        '+0987654321'
      );
    });

    test('getMerchantPhone should return null for unknown merchant', () => {
      expect(merchantBillPay.getMerchantPhone('unknown_merchant')).toBeNull();
    });
  });

  describe('Webhook Integration', () => {
    test('should call success notification on payment_intent.succeeded', async () => {
      const mockReq = {
        headers: { 'stripe-signature': 'test-signature' },
        body: 'test-body',
      };
      const mockRes = {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };

      // Mock Stripe webhook construction
      const mockStripe = {
        webhooks: {
          constructEvent: jest.fn().mockReturnValue({
            type: 'payment_intent.succeeded',
            data: {
              object: {
                id: 'pi_test_123',
                amount: 10000, // $100.00 in cents
                metadata: { merchantId: 'merchant_001' },
                description: 'Test payment',
              },
            },
          }),
        },
      };

      // Mock the notification function
      const notificationSpy = jest
        .spyOn(merchantBillPay, 'sendMerchantPaymentSuccessNotification')
        .mockResolvedValue();

      // Mock readRevenueData and writeRevenueData
      const originalReadRevenueData = merchantBillPay.readRevenueData;
      const originalWriteRevenueData = merchantBillPay.writeRevenueData;
      merchantBillPay.readRevenueData = jest.fn().mockReturnValue({
        merchants: {},
        purchases: { corporateHomes: 0, autoFleet: 0, autoFleetDetails: [] },
      });
      merchantBillPay.writeRevenueData = jest.fn();

      // Temporarily replace stripe import
      const originalStripe = require.cache[require.resolve('stripe')];
      require.cache[require.resolve('stripe')] = {
        exports: jest.fn(() => mockStripe),
      };

      try {
        await merchantBillPay.handleMerchantWebhook(mockReq, mockRes);

        // Verify notification was called
        expect(notificationSpy).toHaveBeenCalledWith(
          'merchant_001',
          100.0,
          'pi_test_123'
        );

        // Verify response
        expect(mockRes.json).toHaveBeenCalledWith({ received: true });
      } finally {
        // Restore original functions
        merchantBillPay.sendMerchantPaymentSuccessNotification =
          notificationSpy.mockRestore();
        merchantBillPay.readRevenueData = originalReadRevenueData;
        merchantBillPay.writeRevenueData = originalWriteRevenueData;
        if (originalStripe) {
          require.cache[require.resolve('stripe')] = originalStripe;
        }
      }
    });

    test('should call failure notification on payment_intent.payment_failed', async () => {
      const mockReq = {
        headers: { 'stripe-signature': 'test-signature' },
        body: 'test-body',
      };
      const mockRes = {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
      };

      // Mock Stripe webhook construction
      const mockStripe = {
        webhooks: {
          constructEvent: jest.fn().mockReturnValue({
            type: 'payment_intent.payment_failed',
            data: {
              object: {
                id: 'pi_test_failed',
                amount: 5000, // $50.00 in cents
                metadata: { merchantId: 'merchant_002' },
                last_payment_error: { message: 'Card declined' },
              },
            },
          }),
        },
      };

      // Mock the notification function
      const notificationSpy = jest
        .spyOn(merchantBillPay, 'sendMerchantPaymentFailureNotification')
        .mockResolvedValue();

      // Mock readRevenueData and writeRevenueData
      const originalReadRevenueData = merchantBillPay.readRevenueData;
      const originalWriteRevenueData = merchantBillPay.writeRevenueData;
      merchantBillPay.readRevenueData = jest.fn().mockReturnValue({
        merchants: {},
        purchases: { corporateHomes: 0, autoFleet: 0, autoFleetDetails: [] },
      });
      merchantBillPay.writeRevenueData = jest.fn();

      // Temporarily replace stripe import
      const originalStripe = require.cache[require.resolve('stripe')];
      require.cache[require.resolve('stripe')] = {
        exports: jest.fn(() => mockStripe),
      };

      try {
        await merchantBillPay.handleMerchantWebhook(mockReq, mockRes);

        // Verify notification was called
        expect(notificationSpy).toHaveBeenCalledWith(
          'merchant_002',
          50.0,
          'pi_test_failed',
          'Card declined'
        );

        // Verify response
        expect(mockRes.json).toHaveBeenCalledWith({ received: true });
      } finally {
        // Restore original functions
        merchantBillPay.sendMerchantPaymentFailureNotification =
          notificationSpy.mockRestore();
        merchantBillPay.readRevenueData = originalReadRevenueData;
        merchantBillPay.writeRevenueData = originalWriteRevenueData;
        if (originalStripe) {
          require.cache[require.resolve('stripe')] = originalStripe;
        }
      }
    });
  });
});
