# Equity Shield Advocates — Banking Operations Guide
## Real Estate Purchases, Transaction Workflows, Payroll, and Liquidity Withdrawals

> Operational guide for running day-to-day and strategic banking activity with strong controls.  
> This is a practical workflow document, not legal/tax advice. Confirm with counsel/CPA and your bank.

---

## 1) Account Structure (Recommended)

Set up distinct accounts to keep controls clean and reporting accurate:

1. **Operating Checking**
   - Normal business expenses
   - Vendor payments
   - Payroll funding transfers

2. **Reserve / Liquidity Account (Savings or Money Market)**
   - Emergency runway
   - Planned capital deployments
   - Short-term liquidity buffer

3. **Payroll Clearing Account (optional but strongly recommended)**
   - Prefund payroll here
   - Limits fraud blast radius
   - Easier payroll reconciliation

4. **Real Estate Acquisition/Project Account (recommended for property activity)**
   - Earnest money deposits
   - Closing wires
   - Property-level expenses and capex
   - Cleaner audit trail by deal

---

## 2) Roles and Approvals

Define user access before moving money:

- **Admin (Treasury/CFO):** manages users, limits, templates, approvals
- **Initiator (Ops/AP):** creates ACH/wire/payroll files
- **Approver (Officer/Director):** approves high-risk transactions
- **Read-only (Audit/Accounting):** statements, exports, reconciliations

Control baseline:
- MFA required for every user
- No shared credentials
- Dual approval for wires and high-value ACH
- Out-of-band callback verification for first-time counterparties

---

## 3) How to Buy Real Estate (Banking Workflow)

## 3.1 Pre-Acquisition Checklist
Before contract execution:
- Confirm entity name on account exactly matches purchase entity docs
- Verify signer authority (resolution/LLC consent)
- Confirm wire limits are high enough for closing amount
- Enable dual approval + callback confirmation rules
- Pre-create whitelisted counterparties only after independent verification

## 3.2 Funding Plan
For each property:
1. Define **total uses** (purchase price, closing costs, legal, reserves)
2. Define **sources** (cash, investor capital, debt proceeds)
3. Move funds into project/acquisition account in controlled tranches
4. Keep minimum operating runway untouched in reserve account

## 3.3 Earnest Money Deposit (EMD)
- Use wire/ACH only to verified escrow account
- Require:
  - signed purchase agreement
  - escrow instructions verified via independent phone number
  - dual approval before release
- Save payment evidence:
  - confirmation ID
  - timestamp
  - approving users
  - escrow contact verification notes

## 3.4 Closing Wire Procedure (Critical)
Use a “4-eye + callback” process:
1. Initiator enters wire
2. Approver validates amount, beneficiary, purpose memo
3. Separate team member calls title/escrow using independently sourced number
4. Final approver releases wire
5. Archive:
   - HUD/settlement statement
   - wire confirmation
   - callback log

Never rely only on emailed wire instructions.

## 3.5 Post-Close
- Reconcile closing statement to bank debits/credits
- Move property-level recurring bills to property account autopay (where safe)
- Establish monthly reporting package:
  - rent inflows
  - debt service
  - taxes/insurance
  - capex
  - NOI view

---

## 4) Daily Banking Transactions (AP/AR Operations)

## 4.1 Accounts Payable (Vendors)
Standard process:
1. Invoice intake + coding
2. Match invoice to PO/contract (if used)
3. Payment batch creation (ACH/check/wire)
4. Approval based on threshold
5. Release and archive proof

Example approval matrix:
- <$5,000: single approver
- $5,000–$25,000: dual approval
- >$25,000 or first-time vendor: dual approval + callback verification

## 4.2 Accounts Receivable (Collections)
- Separate deposit references by client/property
- Enable incoming payment alerts
- Daily cash application to receivables ledger
- Follow-up rules for unapplied cash > 2 business days

## 4.3 Transfers Between Internal Accounts
- Use named templates:
  - `OPERATING_TO_PAYROLL`
  - `OPERATING_TO_RESERVE`
  - `RESERVE_TO_OPERATING_EMERGENCY`
- Require purpose memo for all reserve drawdowns

---

## 5) Payroll Setup and Operations

## 5.1 Payroll Account Design
- Use payroll clearing account for all payroll outflows
- Keep only required cycle funding in clearing account
- Keep tax withholdings and benefits segregated in payroll reporting

## 5.2 Payroll Runbook (Each Cycle)
1. Freeze payroll inputs (hours/salary changes)
2. Review pre-process register
3. CFO/Treasury approves total payroll funding
4. Transfer net payroll + tax/benefit amounts to payroll clearing
5. Payroll provider debits clearing account
6. Verify:
   - successful direct deposits
   - tax payment scheduling
   - benefit remittances

## 5.3 Payroll Controls
- New employee bank changes require separate verification
- Same-day payroll changes need escalated approval
- Exception report reviewed every cycle:
  - account changes
  - off-cycle payments
  - unusually high net pay variance

---

## 6) Liquidity Withdrawals (Reserve Drawdowns)

(“Liquarity withdraws” interpreted as liquidity withdrawals.)

## 6.1 Policy Structure
Define and document:
- **Minimum reserve floor** (e.g., 3–6 months fixed costs)
- **Permitted reasons** for withdrawal:
  - payroll support
  - debt service bridge
  - approved capex
  - acquisition close shortfall
- **Forbidden reasons**:
  - undocumented owner draws
  - unsupported related-party transfers

## 6.2 Withdrawal Approval Flow
1. Initiator submits request:
   - amount
   - purpose
   - destination account
   - supporting docs
2. Finance review:
   - impact on reserve floor
   - cash forecast impact
3. Approver(s) authorize based on threshold
4. Execute transfer using approved template
5. Record in liquidity register

## 6.3 Liquidity Register (Required Fields)
- Request ID
- Date/time
- Requestor
- Approver(s)
- Amount
- Reason code
- Forecast impact
- New reserve balance
- Supporting document links

## 6.4 Example Limits
- <$10,000: single approver (if above reserve floor)
- $10,000–$100,000: dual approval
- >$100,000: dual approval + executive sign-off + cash forecast attachment

---

## 7) Security and Fraud Controls

Minimum controls to enforce:
- MFA on every user
- Device hygiene policy for banking access
- Dedicated approval devices for officers (recommended)
- Daily alert review:
  - login attempts
  - profile changes
  - payee changes
  - large transfer alerts
- Positive Pay / ACH blocks or filters if available
- Beneficiary changes on hold period (e.g., 24 hours) for high-risk wires

Incident response:
1. Freeze online access/payment rails
2. Contact bank fraud desk immediately
3. Preserve logs + confirmations
4. Notify legal/compliance
5. Execute recovery plan and control remediation

---

## 8) Monthly and Quarterly Governance

Monthly:
- Bank recs for all accounts
- Unusual transaction review
- Approval exception review
- Reserve floor compliance check

Quarterly:
- User access recertification
- Approval threshold review
- Beneficiary whitelist review
- Disaster/fraud simulation tabletop

---

## 9) API/Platform Mapping (Current Project)

Relevant endpoints in this project:
- `POST /api/banking/setup` — base business setup plan
- `POST /api/banking/setup/family-trust` — trust integration plan
- `POST /api/banking/setup/equityshield-advocates` — EquityShield-specific setup plan (code exists; runtime route activation required)
- `GET /api/jpm/ping` — protected route for JPM connectivity/auth guard checks

Use these for planning/validation workflows while operating controls above in production.

---

## 10) Quick Start SOP (One-Page)

1. Confirm account topology (Operating / Reserve / Payroll / Property)
2. Enforce MFA + dual approval + callback verification
3. Use templates for recurring internal transfers
4. Run payroll through dedicated clearing account
5. Execute property payments only with verified instructions
6. Log every reserve withdrawal in liquidity register
7. Reconcile weekly, review exceptions monthly, recertify access quarterly

---

## 11) Implementation Checklist

- [ ] Approval matrix documented and approved
- [ ] Reserve withdrawal policy published
- [ ] Payroll clearing workflow active
- [ ] Real estate closing wire SOP active
- [ ] Callback verification script adopted
- [ ] Fraud alert monitoring assigned
- [ ] Monthly reconciliation calendar enforced
- [ ] Quarterly access recertification scheduled
