import { info, error, warn, debug } from 'utils/loggerWrapper.js';

const express = require('express');
const router = express.Router();
const Stripe = require('stripe');
const fs = require('fs');
const path = require('path');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Import JPMorgan Authentication Integration
const {
  jpmorganAuthMiddleware,
  jpmorganAdminMiddleware,
  authenticateUser,
  adminOverride,
  verifyToken,
  refreshToken,
  logout,
  getUserProfile,
} = require('../auth/jpmorgan_auth_integration');

const revenueDataPath = path.resolve(
  __dirname,
  '../earnings_report_updated.json'
);

function readRevenueData() {
  if (!fs.existsSync(revenueDataPath)) {
    return null;
  }
  const data = JSON.parse(fs.readFileSync(revenueDataPath, 'utf-8'));
  if (!data.purchases) {
    data.purchases = {
      corporateHomes: 0,
      autoFleet: 0,
      autoFleetDetails: [],
    };
  }
  return data;
}

function writeRevenueData(data) {
  fs.writeFileSync(revenueDataPath, JSON.stringify(data, null, 2), 'utf-8');
}

// Create a payment intent - Protected route requiring JPMorgan authentication
router.post(
  '/create-payment-intent',
  jpmorganAuthMiddleware(['jpmorgan_payments']),
  async (req, res) => {
    try {
      const { amount, currency = 'usd' } = req.body;
      const user = req.user;

      if (!amount) {
        return res.status(400).json({ error: 'Amount is required' });
      }

      // Log authenticated payment request
      logger.info(
        `JPMorgan authenticated payment request by ${user.email} (${user.role})`
      );

      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency,
        payment_method_types: ['card'],
        metadata: {
          userId: user.userId,
          userEmail: user.email,
          department: user.department,
          timestamp: new Date().toISOString(),
        },
      });

      res.json({
        clientSecret: paymentIntent.client_secret,
        paymentIntentId: paymentIntent.id,
        user: {
          id: user.userId,
          email: user.email,
          role: user.role,
          department: user.department,
        },
      });
    } catch (error) {
      logger.error('Error creating payment intent:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

// Stripe webhook endpoint to handle events
router.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      logger.error('Webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    switch (event.type) {
      case 'payment_intent.succeeded': {
        const paymentIntent = event.data.object;
        logger.info('PaymentIntent was successful!', paymentIntent.id);
        // handle successful payment here (e.g., update order status)
        const data = readRevenueData();
        if (data) {
          // Example: mark an order as paid or update revenue data
          // This example assumes paymentIntent.metadata.orderId exists to identify the order
          // If no orderId, just log success
          if (paymentIntent.metadata && paymentIntent.metadata.orderId) {
            // Find order and update status (example logic)
            // Assuming orders are stored in data.orders array (adjust as needed)
            if (Array.isArray(data.orders)) {
              const order = data.orders.find(
                (o) => o.id === paymentIntent.metadata.orderId
              );
              if (order) {
                order.status = 'paid';
                order.paymentIntentId = paymentIntent.id;
                writeRevenueData(data);
                logger.info(`Order ${order.id} marked as paid.`);
              }
            }
          }
        }
        break;
      }
      case 'payment_intent.payment_failed': {
        const failedIntent = event.data.object;
        logger.info(
          'PaymentIntent failed:',
          failedIntent.last_payment_error &&
            failedIntent.last_payment_error.message
        );
        // handle failed payment here
        // Could update order status to failed if orderId metadata exists
        const data = readRevenueData();
        if (data) {
          if (failedIntent.metadata && failedIntent.metadata.orderId) {
            if (Array.isArray(data.orders)) {
              const order = data.orders.find(
                (o) => o.id === failedIntent.metadata.orderId
              );
              if (order) {
                order.status = 'failed';
                order.paymentIntentId = failedIntent.id;
                writeRevenueData(data);
                logger.info(`Order ${order.id} marked as failed.`);
              }
            }
          }
        }
        break;
      }
      default:
        logger.info(`Unhandled event type ${event.type}`);
    }

    res.json({ received: true });
  }
);

module.exports = router;
