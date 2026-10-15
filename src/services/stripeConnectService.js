import { createHash } from 'node:crypto';
import { getDatabasePool } from '../config/database.js';
import { getStripeClient } from '../config/stripe.js';

const ACCOUNTS_V2_API_VERSION = '2026-09-30.preview';

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

async function findProviderAccount(providerId) {
  const { rows } = await getDatabasePool().query(
    `SELECT provider_id, stripe_account_id, card_payments_status
       FROM stripe_connected_accounts
      WHERE provider_id = $1`,
    [providerId]
  );

  return rows[0];
}

export async function createConnectedAccount({ providerId, contactEmail, displayName }) {
  const pool = getDatabasePool();
  const existing = await findProviderAccount(providerId);
  if (existing) {
    return existing;
  }

  const stripe = getStripeClient();
  const account = await stripe.v2.core.accounts.create(
    {
      contact_email: contactEmail,
      display_name: displayName,
      dashboard: 'full',
      identity: {
        country: 'us'
      },
      configuration: {
        merchant: {
          capabilities: {
            card_payments: {
              requested: true
            }
          }
        }
      },
      defaults: {
        currency: 'usd',
        locales: ['en-US'],
        responsibilities: {
          fees_collector: 'stripe',
          losses_collector: 'stripe'
        }
      },
      include: ['configuration.merchant', 'identity', 'requirements']
    },
    {
      apiVersion: ACCOUNTS_V2_API_VERSION,
      idempotencyKey: `esa-provider-${createHash('sha256').update(providerId).digest('hex')}`
    }
  );

  const cardPaymentsStatus =
    account.configuration?.merchant?.capabilities?.card_payments?.status ?? 'pending';
  const result = await pool.query(
    `INSERT INTO stripe_connected_accounts
       (provider_id, stripe_account_id, country, card_payments_status)
     VALUES ($1, $2, 'US', $3)
     ON CONFLICT (provider_id) DO NOTHING
     RETURNING provider_id, stripe_account_id, card_payments_status`,
    [providerId, account.id, cardPaymentsStatus]
  );

  if (result.rowCount === 1) {
    return result.rows[0];
  }

  const concurrentAccount = await findProviderAccount(providerId);
  if (concurrentAccount?.stripe_account_id === account.id) {
    return concurrentAccount;
  }

  throw httpError(409, 'A different Stripe account is already linked to this provider');
}

export async function createOnboardingSession(providerId) {
  const connectedAccount = await findProviderAccount(providerId);
  if (!connectedAccount) {
    throw httpError(404, 'No Stripe account is linked to this provider');
  }

  const session = await getStripeClient().accountSessions.create({
    account: connectedAccount.stripe_account_id,
    components: {
      account_onboarding: {
        enabled: true
      }
    }
  });

  return {
    clientSecret: session.client_secret,
    expiresAt: session.expires_at
  };
}

export async function refreshConnectedAccountStatus(providerId) {
  const connectedAccount = await findProviderAccount(providerId);
  if (!connectedAccount) {
    throw httpError(404, 'No Stripe account is linked to this provider');
  }

  const account = await getStripeClient().v2.core.accounts.retrieve(
    connectedAccount.stripe_account_id,
    {
      include: ['configuration.merchant']
    },
    {
      apiVersion: ACCOUNTS_V2_API_VERSION
    }
  );
  const cardPaymentsStatus =
    account.configuration?.merchant?.capabilities?.card_payments?.status ?? 'pending';

  await getDatabasePool().query(
    `UPDATE stripe_connected_accounts
        SET card_payments_status = $2, updated_at = NOW()
      WHERE provider_id = $1`,
    [providerId, cardPaymentsStatus]
  );

  return {
    providerId,
    stripeAccountId: account.id,
    cardPaymentsStatus,
    canAcceptDirectCharges: cardPaymentsStatus === 'active'
  };
}
