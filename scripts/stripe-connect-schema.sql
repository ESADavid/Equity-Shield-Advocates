CREATE TABLE IF NOT EXISTS stripe_connected_accounts (
  provider_id TEXT PRIMARY KEY,
  stripe_account_id TEXT NOT NULL UNIQUE,
  country CHAR(2) NOT NULL CHECK (country = 'US'),
  card_payments_status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
