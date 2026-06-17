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

### 1.1 Account Topology Activated (Controls + Reporting Tags)

Use this baseline mapping at account opening to keep controls clean and reporting dimensions consistent:

| Account | Primary Purpose | Owner Role | Required Controls | Reporting Tag |
| --- | --- | --- | --- | --- |
| Operating Checking | Core business disbursements and vendor/AP activity | Treasury/Ops | MFA, approval thresholds, vendor verification | `OPERATING_OPEX` |
| Reserve / Liquidity | Emergency runway and planned capital allocation | CFO/Treasury | Reserve floor policy, memo-required drawdowns, dual approval above threshold | `RESERVE_LIQUIDITY` |
| Payroll Clearing | Isolated payroll prefunding and payroll debits | Payroll Admin + Treasury approver | Prefund-per-cycle only, account change verification, cycle exception review | `PAYROLL_CLEARING` |
| Real Estate Acquisition/Project | Property-specific EMD, closing wires, and capex | Deal Lead + Officer approver | 4-eye approval, callback verification, verified escrow/title instructions | `PROPERTY_PROJECT` |

Implementation note:

- Open and name all four accounts as separate rails.
- Map each outgoing transaction to exactly one reporting tag above.
- Prohibit cross-purpose posting (e.g., payroll from operating, property close from reserve unless approved drawdown).

## 2) Roles and Approvals

Define user access before moving money:

- **Admin (Treasury/CFO): David Leeper Jr** — manages users, limits, templates, approvals
- **Initiator (Ops/AP): Lativia L Gibbs** — creates ACH/wire/payroll files
- **Approver (Officer/Director): Trevor T Gibbs** — approves high-risk transactions
- **Read-only (Audit/Accounting):** statements, exports, reconciliations

Control Baseline (Assigned):

- [x] MFA required for every user
- [x] No shared credentials
- [x] Dual approval for wires and high-value ACH
- [x] Out-of-band callback verification for first-time counterparties
- [x] Quarterly user-access recertification ownership assigned to Treasury/CFO

---

## 3) How to Buy Real Estate (Banking Workflow)

This workflow is the required execution standard for property purchases.  
Use Section 2 role assignments for ownership and approvals.

### 3.0 Workflow Ownership and Control Gates

| Stage | Primary Owner | Required Approver | Control Gate | Go/No-Go Output |
| --- | --- | --- | --- | --- |
| Pre-Acquisition | Initiator (Ops/AP) | Admin (Treasury/CFO) | Entity/signer validation complete | Approved to draft funding plan |
| Funding Plan | Admin (Treasury/CFO) | Approver (Officer/Director) | Sources/uses balanced and reserve floor preserved | Approved to prefund project account |
| EMD Release | Initiator (Ops/AP) | Approver (Officer/Director) | Escrow callback + dual approval + verified instructions | Approved to release EMD |
| Closing Wire | Initiator (Ops/AP) | Approver (Officer/Director) | 4-eye review + independent callback + final release | Approved to send closing wire |
| Post-Close Reconciliation | Admin (Treasury/CFO) | Approver (Officer/Director) | Debits/credits tie to settlement docs | Property moved to steady-state reporting |

## 3.1 Pre-Acquisition Checklist (Go/No-Go #1)

Before contract execution:

- Confirm account title exactly matches purchase entity documents.
- Verify signer authority (resolution/LLC consent/trust authority docs).
- Confirm wire/ACH limits support expected EMD and closing amount.
- Confirm dual-approval and callback controls are active.
- Pre-create beneficiaries only after independent verification.

Required artifacts:

- Entity formation and authority package
- Signer authorization documentation
- Limit confirmation evidence (portal screenshot or banker confirmation)

Go/No-Go rule:

- **No contract funding activity** if any authority, limit, or control item is incomplete.

## 3.2 Funding Plan (Go/No-Go #2)

For each property:

1. Define **total uses** (purchase price, closing costs, legal, reserves).
2. Define **sources** (cash, investor capital, debt proceeds).
3. Execute prefunding in controlled tranches into project/acquisition account.
4. Preserve reserve floor and minimum operating runway.

Required artifacts:

- Sources/uses worksheet
- 13-week cash impact note (or equivalent short-term forecast)
- Approval record from Treasury/CFO and Officer/Director

Go/No-Go rule:

- **No EMD release** unless sources/uses are approved and reserve floor remains compliant.

## 3.3 Earnest Money Deposit (EMD) (Go/No-Go #3)

- Use wire/ACH only to independently verified escrow account.
- Require:
  - signed purchase agreement
  - escrow instructions verified via independently sourced phone number
  - dual approval before release
- Save payment evidence:
  - confirmation ID
  - timestamp
  - approving users
  - escrow callback verification notes

Go/No-Go rule:

- **No EMD release** based solely on email instructions.

## 3.4 Closing Wire Procedure (Critical) (Go/No-Go #4)

Use a strict “4-eye + callback” process:

1. Initiator enters wire and purpose memo tied to deal ID.
2. Approver validates amount, beneficiary, and settlement reference.
3. Separate team member performs callback to title/escrow using independently sourced number.
4. Final approver releases wire.
5. Archive:
   - HUD/settlement statement
   - wire confirmation
   - callback log
   - final approval evidence

Never rely only on emailed wire instructions.

Go/No-Go rule:

- **No closing wire release** without completed callback log and dual approval evidence.

## 3.5 Post-Close (Go/No-Go #5)

- Reconcile settlement statement to bank debits/credits within defined close window.
- Move recurring property bills to property account/autopay (where safe).
- Establish monthly reporting package:
  - rent inflows
  - debt service
  - taxes/insurance
  - capex
  - NOI view

Required artifacts:

- Reconciliation worksheet
- Post-close controls sign-off
- Reporting package template activation

Go/No-Go rule:

- **No transition to steady-state operations** until reconciliation variance is resolved or formally approved.

### 3.6 Real Estate Workflow Control Baseline (Assigned)

- [x] Role ownership assigned for each stage (Initiator/Admin/Approver)
- [x] Dual approval enforced for EMD and closing wires
- [x] Independent callback verification required before funds release
- [x] Deal-level evidence retention required (agreement, settlement, confirmations, logs)
- [x] Post-close reconciliation and reporting package activation required

---

## 4) Real Estate Acquisition/Project Account Operations

Use this section as the operating standard after Section 3 workflow approval.
It governs day-to-day activity inside the dedicated property account rail.

## 4.1 Account Scope and Allowed Uses

Allowed transactions in the Real Estate Acquisition/Project Account:

- Earnest money deposits (EMD)
- Closing wires
- Property due-diligence expenses
- Property-specific capex and remediation
- Property utilities, insurance, taxes, and required service contracts

Prohibited transactions:

- Payroll outflows
- General corporate OPEX unrelated to the property
- Owner distributions
- Reserve drawdowns without documented approval chain

Control rule:

- Every transaction must include a property/deal ID and reporting tag
  `PROPERTY_PROJECT`.

## 4.2 Standard Payment Runbook (Property Account)

1. Intake request with property ID, amount, counterparty, due date, and purpose.
2. Validate supporting artifacts (agreement/invoice/escrow instruction).
3. Verify beneficiary status:
   - approved and previously verified, or
   - first-time counterparty requiring callback verification.
4. Create payment in bank platform with required memo fields.
5. Route for approvals based on threshold matrix.
6. Release funds after controls clear.
7. Archive evidence in deal folder and reconciliation register.

Required memo format:

- `PROPERTY_ID | DEAL_STAGE | PURPOSE | APPROVER_INITIALS`

## 4.3 Property Payment Approval Matrix

- <$10,000: single approver (if verified beneficiary and low-risk purpose)
- $10,000–$50,000: dual approval
- >$50,000 or first-time beneficiary: dual approval + callback verification
- Closing wires (any amount): mandatory 4-eye + callback + final approver release

## 4.4 Reconciliation and Exception Controls

Daily:

- Match posted debits/credits to authorized requests.
- Flag and investigate unmatched items same day.

Weekly:

- Tie property account activity to deal ledger and project budget.
- Review exceptions log with Admin + Approver.

Month-end:

- Produce property cash movement summary:
  - opening balance
  - inflows
  - outflows by category
  - ending balance
  - unresolved exceptions

Exception SLA:

- Any unauthorized or unmatched transaction must be escalated within
  1 business day and tracked to closure.

## 4.5 Evidence Retention Standard (Property Account)

Retain, per transaction:

- source document (invoice/agreement/settlement instruction)
- approval evidence (user/time/action)
- callback log (where required)
- payment confirmation ID
- reconciliation reference

Retention rule:

- No transaction is considered complete until evidence package is archived
  and linked to the property/deal record.

---

## 5) Daily Banking Transactions (AP/AR Operations)

## 5.1 Accounts Payable (Vendors)

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

## 5.2 Accounts Receivable (Collections)

- Separate deposit references by client/property
- Enable incoming payment alerts
- Daily cash application to receivables ledger
- Follow-up rules for unapplied cash > 2 business days

## 5.3 Transfers Between Internal Accounts

- Use named templates:
  - `OPERATING_TO_PAYROLL`
  - `OPERATING_TO_RESERVE`
  - `RESERVE_TO_OPERATING_EMERGENCY`
- Require purpose memo for all reserve drawdowns

---

## 6) Payroll Setup and Operations

## 6.1 Payroll Account Design

- Use payroll clearing account for all payroll outflows
- Keep only required cycle funding in clearing account
- Keep tax withholdings and benefits segregated in payroll reporting

## 6.2 Payroll Runbook (Each Cycle)

1. Freeze payroll inputs (hours/salary changes)
2. Review pre-process register
3. CFO/Treasury approves total payroll funding
4. Transfer net payroll + tax/benefit amounts to payroll clearing
5. Payroll provider debits clearing account
6. Verify:
   - successful direct deposits
   - tax payment scheduling
   - benefit remittances

## 6.3 Payroll Controls

- New employee bank changes require separate verification
- Same-day payroll changes need escalated approval
- Exception report reviewed every cycle:
  - account changes
  - off-cycle payments
  - unusually high net pay variance

---

## 7) Liquidity Withdrawals (Reserve Drawdowns)

(“Liquarity withdraws” interpreted as liquidity withdrawals.)

## 7.1 Policy Structure

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

## 7.2 Withdrawal Approval Flow

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

## 7.3 Liquidity Register (Required Fields)

- Request ID
- Date/time
- Requestor
- Approver(s)
- Amount
- Reason code
- Forecast impact
- New reserve balance
- Supporting document links

## 7.4 Example Limits

- <$10,000: single approver (if above reserve floor)
- $10,000–$100,000: dual approval
- >$100,000: dual approval + executive sign-off + cash forecast attachment

---

## 8) Security and Fraud Controls

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

## 9) Monthly and Quarterly Governance

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

## 10) API/Platform Mapping (Current Project)

Relevant endpoints in this project:

- `POST /api/banking/setup` — base business setup plan
- `POST /api/banking/setup/family-trust` — trust integration plan
- `POST /api/banking/setup/equityshield-advocates` — EquityShield-specific setup plan (code exists; runtime route activation required)
- `GET /api/jpm/ping` — protected route for JPM connectivity/auth guard checks

Use these for planning/validation workflows while operating controls above in production.

---

## 11) Quick Start SOP (One-Page)

1. Confirm account topology (Operating / Reserve / Payroll / Property)
2. Enforce MFA + dual approval + callback verification
3. Use templates for recurring internal transfers
4. Run payroll through dedicated clearing account
5. Execute property payments only with verified instructions
6. Log every reserve withdrawal in liquidity register
7. Reconcile weekly, review exceptions monthly, recertify access quarterly

---

## 12) Implementation Checklist

- [x] Account topology confirmed (Operating / Reserve / Payroll / Property)
- [ ] Approval matrix documented and approved
- [ ] Reserve withdrawal policy published
- [ ] Payroll clearing workflow active
- [ ] Real estate closing wire SOP active
- [ ] Callback verification script adopted
- [ ] Fraud alert monitoring assigned
- [ ] Monthly reconciliation calendar enforced
- [ ] Quarterly access recertification scheduled
