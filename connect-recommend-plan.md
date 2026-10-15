## Recommended Connect integration

### A. Account configuration

- Accounts API: `/v2/core/accounts`
- Accounts v2 request version: `2026-09-30.preview` per the current Stripe reference; re-check the version before deployment.
- Legacy account `type`: not used
- Dashboard: Full Stripe Dashboard (`dashboard: "full"`)
- Fee collection: Stripe bills connected accounts (`fees_collector: "stripe"`)
- Negative balance liability: Stripe (`losses_collector: "stripe"`)
- Connected accounts: Configure `configuration.merchant` and request the `card_payments` capability for direct charges.

This setup fits independent US businesses or professional firms that own their customer payment relationship and need independent payment, refund, and payout operations. The dashboard and responsibility choices are made when each connected account is created; confirm them before onboarding providers.

### B. Charge pattern: direct charges

Each provider charges its own customer through its connected account. The provider is the merchant of record; provider branding and payment support belong to that provider. Equity Shield Advocates collects its fee through `application_fee_amount`, rather than collecting customer funds and paying providers out.

### C. Provider onboarding flow

- Onboarding method: embedded `account_onboarding` component.
- Create the connected account with the Accounts v2 API, then collect required business information using Stripe-hosted onboarding components.
- Monitor updated requirements and capability status; keep payment creation disabled until `configuration.merchant.capabilities.card_payments.status` is `active`.
- Use the `notification_banner` component to keep providers informed about outstanding requirements.

### D. Payments dashboard access

Providers sign in to the Full Stripe Dashboard at `dashboard.stripe.com` for independent account operations. The Equity Shield Advocates application can provide a separate support flow for shared refund and dispute assistance.

### E. Embedded components

Recommended components:

- `account_onboarding`
- `notification_banner`
- `account_management`
- `payments`
- `payouts`

Use components for onboarding and in-app status/support; providers retain their full Dashboard access.

### F. Webhook integration

Use signed webhooks for reliable payment and account-status updates, verifying each signature before processing it.

### G. Onboarding status gating

Before creating a direct charge, retrieve the connected account through `stripe.v2.core.accounts.retrieve(id)` and require `configuration.merchant.capabilities.card_payments.status === "active"`. Re-check status as part of ongoing account updates; do not infer readiness from legacy `charges_enabled` or `payouts_enabled` fields.

### H. Fee structure

- Platform fee model: tiered/custom transaction pricing; the schedule is not yet configured.
- `application_fee_amount`: calculated server-side from the configured provider/order tier and set only after that schedule is approved.
- Fail closed: do not create charges when no matching active fee rule exists. Never accept the fee amount or final charge amount as authoritative from the browser.
- With direct charges and Stripe-managed fee collection, Stripe processing fees are charged to the connected provider; the Equity Shield Advocates application fee is separate.
- Verify region- and payment-method-specific terms at [Stripe pricing](https://stripe.com/pricing).

```text
Customer pays provider through the provider's connected account
                         |
                         +-- Stripe processing fee billed to provider
                         |
                         +-- Equity Shield Advocates receives its
                             configured application fee
```

### I. SaaS monetization

Use transaction fees only for the first implementation. Recurring platform subscriptions are not part of the confirmed scope.

### J. Implementation plan

1. Persist provider-to-connected-account mappings and enforce authenticated provider ownership.
2. Implement Accounts v2 creation, embedded onboarding, and capability-status checks.
3. Implement provider-scoped Checkout Sessions/direct charges using server-owned order amounts and a configured tiered fee schedule.
4. Add signed Connect webhooks, durable event idempotency, and payment/account status updates.
5. Test in a Stripe sandbox with separate test credentials before configuring production secrets or enabling live charges.

### K. Risk and liability

- Negative balance liability: Stripe, through `losses_collector: "stripe"`.
- Risk management: Stripe Radar for Platforms should be enabled alongside Stripe-managed negative-balance protection.
- Refund and dispute support: shared. Providers retain independent Stripe operations; define the platform's support actions and authorization before implementing them.

### L. Why this fits your business

- You selected independent businesses/professional firms with their own full Stripe access.
- You selected provider-owned direct payment relationships rather than platform-run checkout and transfers.
- The platform and first providers are in the United States; start with US connected accounts.
- One provider is expected per payment, with no multi-provider split or delayed release.

### M. Open questions before implementation

- The exact tier names, fee rates, and matching rules are pending; payment creation must remain disabled until they are configured.
- The order/catalog source, currency, and durable storage provider have not been selected.
- Define which refund and dispute actions Equity Shield Advocates support versus which remain provider-only.
