const express = require('express');
const Stripe = require('stripe');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

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
          
          // TODO: Add actual merchant notification logic here (email, SMS, etc.)
          console.log(`Notifying merchant ${merchantId} of successful payment of $${amount.toFixed(2)}`);
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
          
          // TODO: Add actual merchant notification logic for failed payments
          console.log(`Notifying merchant ${merchantId} of failed payment attempt`);
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
    const paymentIntent = await createMerchantPaymentIntent(req.body);
    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error('Error creating merchant payment intent:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Express route for webhook
router.post('/merchant-webhook', express.raw({ type: 'application/json' }), handleMerchantWebhook);

module.exports = {
  router,
  createMerchantPaymentIntent,
  handleMerchantWebhook,
};
