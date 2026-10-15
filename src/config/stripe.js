import Stripe from 'stripe';
import { env } from './env.js';

let stripe;

export function getStripeClient() {
  if (!env.stripeApiKey) {
    const error = new Error('Stripe is not configured');
    error.statusCode = 503;
    throw error;
  }

  stripe ??= new Stripe(env.stripeApiKey, {
    maxNetworkRetries: 2,
    timeout: 20000
  });

  return stripe;
}
