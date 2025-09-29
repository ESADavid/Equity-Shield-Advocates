import express from 'express';
import Stripe from 'stripe';
import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// Conditionally initialize Stripe only if API key is available
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = Stripe(process.env.STRIPE_SECRET_KEY);
} else {
  console.warn('⚠️  STRIPE_SECRET_KEY not found. Stripe functionality will be disabled for testing.');
  // Create a mock Stripe object for testing
  stripe = {
    paymentIntents: {
      create: async () => {
        throw new Error('Stripe not configured - please set STRIPE_SECRET_KEY');
      }
    },
    webhooks: {
      constructEvent: () => {
        throw new Error('Stripe not configured - please set STRIPE_SECRET_KEY');
      }
    }
  };
}

// Email transporter configuration
let emailTransporter = null;
if (process.env.SMTP_USER && process.env.SMTP_PASS) {
  emailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
} else {
  console.warn('⚠️  SMTP credentials not found. Email functionality will be disabled for testing.');
  // Create a mock transporter for testing
  emailTransporter = {
    sendMail: async () => {
      console.log('Mock email sent (SMTP not configured)');
    }
  };
}

// Notification functions
async function sendMerchantPaymentSuccessNotification(merchantId, amount, paymentIntentId) {
  try {
    // Get merchant contact info (this could be from a database or configuration)
    const merchantEmail = getMerchantEmail(merchantId);
    const merchantPhone = getMerchantPhone(merchantId);

    if (merchantEmail) {
      const mailOptions = {
        from: process.env.SMTP_USER,
        to: merchantEmail,
        subject: 'Payment Received - Oscar Broome Revenue System',
        html: `
          <h2>Payment Successfully Processed</h2>
          <p>Dear Merchant,</p>
          <p>Your payment has been successfully processed.</p>
          <ul>
            <li><strong>Merchant ID:</strong> ${merchantId}</li>
            <li><strong>Amount:</strong> $${amount.toFixed(2)}</li>
            <li><strong>Payment ID:</strong> ${paymentIntentId}</li>
            <li><strong>Date:</strong> ${new Date().toLocaleString()}</li>
          </ul>
          <p>Your account balance has been updated accordingly.</p>
          <p>Thank you for using Oscar Broome Revenue System.</p>
          <br>
          <p>Best regards,<br>Oscar Broome Revenue Team</p>
        `
      };

      await emailTransporter.sendMail(mailOptions);
      console.log(`Email notification sent to merchant ${merchantId}`);
    }

    // SMS notification (if Twilio is configured)
    if (merchantPhone && process.env.TWILIO_SID && process.env.TWILIO_AUTH_TOKEN) {
      await sendSMSNotification(merchantPhone, `Payment of $${amount.toFixed(2)} received. Payment ID: ${paymentIntentId}`);
    }
  } catch (error) {
    console.error('Error sending payment success notification:', error);
  }
}

async function sendMerchantPaymentFailureNotification(merchantId, amount, paymentIntentId, errorMessage) {
  try {
    const merchantEmail = getMerchantEmail(merchantId);
    const merchantPhone = getMerchantPhone(merchantId);

    if (merchantEmail) {
      const mailOptions = {
        from: process.env.SMTP_USER,
        to: merchantEmail,
        subject: 'Payment Failed - Oscar Broome Revenue System',
        html: `
          <h2>Payment Processing Failed</h2>
          <p>Dear Merchant,</p>
          <p>Unfortunately, your payment could not be processed.</p>
          <ul>
            <li><strong>Merchant ID:</strong> ${merchantId}</li>
            <li><strong>Amount:</strong> $${amount.toFixed(2)}</li>
            <li><strong>Payment ID:</strong> ${paymentIntentId}</li>
            <li><strong>Date:</strong> ${new Date().toLocaleString()}</li>
            <li><strong>Error:</strong> ${errorMessage}</li>
          </ul>
          <p>Please check your payment method and try again, or contact support for assistance.</p>
          <p>Thank you for using Oscar Broome Revenue System.</p>
          <br>
          <p>Best regards,<br>Oscar Broome Revenue Team</p>
        `
      };

      await emailTransporter.sendMail(mailOptions);
      console.log(`Failure email notification sent to merchant ${merchantId}`);
    }

    // SMS notification (if Twilio is configured)
    if (merchantPhone && process.env.TWILIO_SID && process.env.TWILIO_AUTH_TOKEN) {
      await sendSMSNotification(merchantPhone, `Payment of $${amount.toFixed(2)} failed. Error: ${errorMessage}`);
    }
  } catch (error) {
    console.error('Error sending payment failure notification:', error);
  }
}

// Helper functions to get merchant contact info
function getMerchantEmail(merchantId) {
  // This should be replaced with actual database lookup
  // For now, return a placeholder or null
  const merchantContacts = {
    'merchant_001': 'merchant1@example.com',
    'merchant_002': 'merchant2@example.com'
  };
  return merchantContacts[merchantId] || null;
}

function getMerchantPhone(merchantId) {
  // This should be replaced with actual database lookup
  const merchantPhones = {
    'merchant_001': '+1234567890',
    'merchant_002': '+0987654321'
  };
  return merchantPhones[merchantId] || null;
}

// SMS notification function (requires Twilio)
async function sendSMSNotification(phoneNumber, message) {
  try {
    const { default: twilio } = await import('twilio');
    const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

    await client.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });

    console.log(`SMS notification sent to ${phoneNumber}`);
  } catch (error) {
    console.error('Error sending SMS notification:', error);
  }
}

const revenueDataPath = path.resolve(__dirname, '../earnings_report_updated.json');

function readRevenueData() {
  if (!fs.existsSync(revenueDataPath)) {
    return null;
  }
  const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
  if (!data.purchases) {
    data.purchases = {
      corporateHomes: 0,
      autoFleet: 0,
      autoFleetDetails: []
    };
  }
  return data;
}

function writeRevenueData(data) {
  fs.writeFileSync(revenueDataPath, JSON.stringify(data, null, 2), 'utf-8');
}

// Reusable function to create a payment intent for merchant bill pay
async function createMerchantPaymentIntent({ amount, currency = 'usd', merchantId, description }) {
  if (!amount) {
    throw new Error('Amount is required');
  }
  if (!merchantId) {
    throw new Error('Merchant ID is required');
  }
  const paymentIntent = await stripe.paymentIntents.create({
    amount,
    currency,
    payment_method_types: ['card'],
    metadata: { merchantId },
    description: description || `Payment to merchant ${merchantId}`,
  });
  return paymentIntent;
}

// Reusable function to handle Stripe webhook events for merchant payments
async function handleMerchantWebhook(req, res) {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Merchant webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'payment_intent.succeeded': {
      const paymentIntent = event.data.object;
      console.log('Merchant PaymentIntent was successful!', paymentIntent.id);
      // handle successful merchant payment here (e.g., update merchant balance, notify merchant)
      const data = readRevenueData();
      if (data) {
        const merchantId = paymentIntent.metadata?.merchantId;
        const amount = paymentIntent.amount / 100; // Convert from cents to dollars
        
        if (merchantId) {
          // Update merchant balance in revenue data
          if (!data.merchants) {
            data.merchants = {};
          }
          
          if (!data.merchants[merchantId]) {
            data.merchants[merchantId] = {
              balance: 0,
              payments: []
            };
          }
          
          // Add payment to merchant balance
          data.merchants[merchantId].balance += amount;
          
          // Record payment transaction
          data.merchants[merchantId].payments.push({
            paymentIntentId: paymentIntent.id,
            amount,
            date: new Date().toISOString(),
            description: paymentIntent.description || `Payment to merchant ${merchantId}`
          });
          
          writeRevenueData(data);
          console.log(`Updated merchant ${merchantId} balance: $${data.merchants[merchantId].balance.toFixed(2)}`);

          // Send notification to merchant
          await sendMerchantPaymentSuccessNotification(merchantId, amount, paymentIntent.id);
        }
      }
      break;
    }
    case 'payment_intent.payment_failed': {
      const failedIntent = event.data.object;
      console.log('Merchant PaymentIntent failed:', failedIntent.last_payment_error && failedIntent.last_payment_error.message);
      // handle failed merchant payment here
      const data = readRevenueData();
      if (data) {
        const merchantId = failedIntent.metadata?.merchantId;
        
        if (merchantId) {
          // Record failed payment attempt for merchant
          if (!data.merchants) {
            data.merchants = {};
          }
          
          if (!data.merchants[merchantId]) {
            data.merchants[merchantId] = {
              balance: 0,
              payments: [],
              failedPayments: []
            };
          }
          
          // Record failed payment
          data.merchants[merchantId].failedPayments = data.merchants[merchantId].failedPayments || [];
          data.merchants[merchantId].failedPayments.push({
            paymentIntentId: failedIntent.id,
            date: new Date().toISOString(),
            error: failedIntent.last_payment_error?.message || 'Unknown error',
            amount: failedIntent.amount / 100
          });
          
          writeRevenueData(data);
          console.log(`Recorded failed payment for merchant ${merchantId}`);

          // Send failure notification to merchant
          await sendMerchantPaymentFailureNotification(merchantId, failedIntent.amount / 100, failedIntent.id, failedIntent.last_payment_error?.message || 'Unknown error');
        }
      }
      break;
    }
    default:
      console.log(`Unhandled merchant event type ${event.type}`);
  }

  res.json({ received: true });
}

// Express route to create payment intent
router.post('/create-merchant-payment-intent', async (req, res) => {
  try {
    console.log('Merchant payment intent request received:', req.body);
    // Mock mode check
    const isMockMode = !process.env.STRIPE_SECRET_KEY;
    console.log('Merchant payment intent creation - Mock mode:', isMockMode, 'STRIPE_SECRET_KEY:', !!process.env.STRIPE_SECRET_KEY);

    if (isMockMode) {
      const { amount, currency = 'usd', merchantId, description } = req.body;

      if (!amount) {
        return res.status(400).json({ error: 'Amount is required' });
      }
      if (!merchantId) {
        return res.status(400).json({ error: 'Merchant ID is required' });
      }

      const mockClientSecret = `pi_mock_${Date.now()}_secret_${Math.random().toString(36).substring(2)}`;
      console.log('Mock payment intent created:', mockClientSecret);

      return res.json({
        success: true,
        clientSecret: mockClientSecret,
        paymentIntent: {
          id: `pi_mock_${Date.now()}`,
          amount,
          currency,
          merchantId,
          description: description || `Payment to merchant ${merchantId}`,
          status: 'requires_payment_method'
        }
      });
    }

    const paymentIntent = await createMerchantPaymentIntent(req.body);
    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error('Error creating merchant payment intent:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Express route for webhook
router.post('/merchant-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    // Mock mode check
    const isMockMode = !process.env.STRIPE_SECRET_KEY;
    console.log('Merchant webhook - Mock mode:', isMockMode);

    if (isMockMode) {
      // Skip signature verification in mock mode
      console.log('Mock webhook received, processing without signature verification');

      // Mock successful payment event
      const mockEvent = {
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: `pi_mock_${Date.now()}`,
            amount: 1000,
            metadata: { merchantId: 'merchant_001' },
            description: 'Mock payment for testing',
            last_payment_error: null
          }
        }
      };

      // Process the mock event
      switch (mockEvent.type) {
        case 'payment_intent.succeeded': {
          const paymentIntent = mockEvent.data.object;
          console.log('Mock PaymentIntent was successful!', paymentIntent.id);

          // Update revenue data with mock payment
          const data = readRevenueData();
          if (data) {
            const merchantId = paymentIntent.metadata?.merchantId;
            const amount = paymentIntent.amount / 100; // Convert from cents to dollars

            if (merchantId) {
              if (!data.merchants) {
                data.merchants = {};
              }

              if (!data.merchants[merchantId]) {
                data.merchants[merchantId] = {
                  balance: 0,
                  payments: []
                };
              }

              data.merchants[merchantId].balance += amount;
              data.merchants[merchantId].payments.push({
                paymentIntentId: paymentIntent.id,
                amount,
                date: new Date().toISOString(),
                description: paymentIntent.description || `Payment to merchant ${merchantId}`
              });

              writeRevenueData(data);
              console.log(`Mock updated merchant ${merchantId} balance: $${data.merchants[merchantId].balance.toFixed(2)}`);

              // Send mock notification
              await sendMerchantPaymentSuccessNotification(merchantId, amount, paymentIntent.id);
            }
          }
          break;
        }
      }

      return res.json({ received: true, mock: true });
    }

    // Real webhook processing
    await handleMerchantWebhook(req, res);
  } catch (error) {
    console.error('Error in merchant webhook:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

export default {
  router,
  createMerchantPaymentIntent,
  handleMerchantWebhook,
  sendMerchantPaymentSuccessNotification,
  sendMerchantPaymentFailureNotification,
  sendSMSNotification,
  getMerchantEmail,
  getMerchantPhone,
};
