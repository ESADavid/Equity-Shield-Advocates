# Company Updates and Integrations Plan  

## Equity Shield Advocates — Consolidated Operational + Technical Execution Blueprint

## 1) Objective

This document consolidates entity updates and integration activities across:

- **LBWG**
- **MERCDEE**
- **Mercier Broome Leeper Family Trust**
- **JPM technical integration workstream**

It is intended as a single execution reference tying together banking setup documentation, AUM structure visibility, and API integration implementation/testing/security requirements.

---

## 2) Consolidated Company Update Snapshot

### A) LBWG (Operational Banking Readiness)

From `LBWG_Business_Banking_Setup_Packet.md`:

- Core account model defined:
  - **LBWG Operating** (checking)
  - **LBWG Reserve** (savings/reserve)
- Required onboarding packet/checklist exists (articles, EIN, bylaws, resolution, signers).
- Governance and controls framework defined:
  - dual approval controls
  - role-based access
  - MFA requirements
  - ACH/wire and fraud controls
- 7-day onboarding execution sequence documented.

### Current status posture

- Structurally ready for onboarding execution.
- Requires completion evidence for checklist items and bank intake artifacts.

---

### B) MERCDEE (Operational Banking Readiness)

From `MERCDEE_Business_Banking_Setup_Packet.md`:

- Core account model defined:
  - **MERCDEE Operating Checking**
  - **MERCDEE Reserve Savings**
- Documentation packet/checklist exists for KYC/compliance/onboarding.
- Controls and audit-readiness workflow documented:
  - segregation of duties
  - approval policy
  - quarterly access reviews
  - fraud incident response expectation
- 7-day onboarding sequence documented.

### Current status posture

- Structurally ready for onboarding execution.
- Requires operational completion tracking and evidence capture.

---

### C) Family Trust (Integration Readiness with Legal Separation)

From `Mercier_Broome_Leeper_Family_Trust_Integration_Addendum.md`:

- Clear trust/entity separation model established.
- Trust account topology documented:
  - **Family Trust Primary Account**
  - **Family Trust Reserve Account**
- Trust-to-entity transfer controls defined:
  - no commingling
  - purpose memo
  - trustee approval
  - retained documentation trail
- 14-day trust integration activation plan documented.

### Current status posture

- Governance and integration model is clearly defined.
- Requires policy operationalization and records packet completion.

---

## 3) Consolidated AUM Topology Alignment

The currently identified core account buckets across documents are:

1. **LBWG Operating**
2. **LBWG Reserve**
3. **MERCDEE Operating Checking**
4. **MERCDEE Reserve Savings**
5. **Family Trust Primary Account**
6. **Family Trust Reserve Account**

These align with `AUM_REVENUE_UPDATE.md` and represent the baseline structure for account-level integration and reporting.

---

## 4) Revenue and Reporting Readiness Summary

Current source materials provide structure and policy but not realized revenue totals.

### Available now

- Account topology by entity
- Operational controls framework
- Governance and segregation principles
- Integration process templates

### Missing for complete numeric reporting

- Transaction-level inflow/outflow exports by period
- Revenue classification policy enforcement data
- finalized reporting cutoffs (MTD/QTD/YTD)
- canonical ledger source per entity

### Immediate reporting action

Adopt a standardized monthly data intake packet per entity with:

- period label
- gross inflows
- excluded transfers
- net recognized revenue
- source-of-truth reference
- as-of date

---

## 5) JPM Technical Integration Workstream (Implementation Alignment)

Based on `jpm_integration_artifacts.md`, required code and security artifacts include:

- `src/config/env.js`
- `src/middleware/requestId.js`
- `src/middleware/authGuard.js`
- `src/middleware/errorHandler.js`
- `src/services/jpmOAuthService.js`
- `src/services/jpmApiClient.js`
- `src/services/bankingSetupService.js`
- `src/routes/healthRoutes.js`
- `src/routes/oauthRoutes.js`
- `src/routes/bankingRoutes.js`
- `src/utils/logger.js`
- `src/utils/redact.js`
- test scripts under `/scripts` and `/tests`

### Endpoint contract (target)

- `GET /health`
- `POST /api/oauth/token`
- `POST /api/banking/setup`
- `GET /api/jpm/ping` (protected)

### Security controls (must-have)

- redact secrets/tokens in logs and responses
- fail-fast required env validation
- request ID propagation across logs/errors
- safe upstream error mapping
- no committed credentials

---

## 6) Phased Execution Plan

### Phase 1 — Documentation and Governance Finalization (Immediate)

Deliverables:

- Entity onboarding packet completeness matrix (LBWG/MERCDEE/Trust)
- Approved signer and approval-threshold matrix
- Trust transfer memo template package

Exit criteria:

- All required document placeholders mapped to owner + due date
- Governance conflicts resolved (trust vs entity authority lines)

---

### Phase 2 — Banking Operations Activation

Deliverables:

- Account opening status tracking for all 6 core buckets
- online/mobile channel enablement confirmation
- ACH/wire/debit/fraud controls activation evidence
- initial reconciliation ownership assignment

Exit criteria:

- accounts active and controlled under documented approval model
- MFA + alert controls validated for all authorized users

---

### Phase 3 — JPM API Integration Rollout

Deliverables:

- local service startup success
- endpoint registration validation
- OAuth flow test results (happy + error paths)
- protected route auth validation
- structured redacted logging verification

Exit criteria:

- curl matrix passes for health/oauth/setup/ping
- no secret leakage observed in logs/responses

---

### Phase 4 — Reporting and Audit Readiness

Deliverables:

- monthly AUM/revenue data intake template operationalized
- entity-separated reconciliation process evidence
- trust/entity transfer audit packet baseline
- cross-entity control review memo

Exit criteria:

- first complete reporting cycle assembled
- audit-ready records package available for legal/accounting review

---

## 7) Ownership and Execution Cadence

Recommended owner model:

- **Banking Operations Owner:** onboarding, account controls, access review
- **Technical Integration Owner:** API/OAuth/logging/security controls
- **Finance/Reporting Owner:** revenue classification and reporting cadence
- **Trust Governance Owner:** trustee approvals and no-commingling compliance

Cadence:

- Weekly execution review
- Monthly control validation
- Quarterly signer/access and compliance review

---

## 8) Risk Register (Top Priority)

1. **Documentation gaps delay account opening**
   - Mitigation: checklist owner assignment + due date governance

2. **Trust/entity commingling risk**
   - Mitigation: mandatory transfer memo + dual approval + ledger segmentation

3. **Secret leakage in technical integration**
   - Mitigation: redact middleware + secure env policy + test evidence

4. **Inconsistent revenue classification**
   - Mitigation: standardized classification policy and monthly reconciliation sign-off

---

## 9) Immediate Next Actions (Actionable)

1. Complete a single status matrix for all open checklist items across LBWG/MERCDEE/Trust.
2. Validate all JPM integration modules are present and wired in runtime.
3. Execute OAuth + banking route curl matrix and archive outputs.
4. Initiate first monthly reporting packet (even if partial) to establish cadence.
5. Publish signed operational control memo covering:
   - approvals
   - transfer governance
   - reconciliation responsibilities
   - escalation workflow

---

## 10) Completion Definition

This consolidation effort is considered complete when:

- Company banking update items are tracked in one status view.
- Technical JPM integration is tested and operational under secure controls.
- Trust and entity boundaries are enforced with documentary evidence.
- Monthly AUM/revenue reporting pipeline is active and repeatable.
