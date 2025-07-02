const express = require('express');
const Stripe = require('stripe');
const router = express.Router();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

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
    case 'payment_intent.succeeded':
      const paymentIntent = event.data.object;
      console.log('Merchant PaymentIntent was successful!', paymentIntent.id);
      // TODO: handle successful merchant payment here (e.g., update merchant balance, notify merchant)
      break;
    case 'payment_intent.payment_failed':
      const failedIntent = event.data.object;
      console.log('Merchant PaymentIntent failed:', failedIntent.last_payment_error && failedIntent.last_payment_error.message);
      // TODO: handle failed merchant payment here
      break;
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
