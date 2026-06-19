# Assets Under Management (AUM) and Revenue Update

## 1) Consolidated Assets Under Management (AUM)

The following managed asset/account buckets were identified from the current codebase documents:

1. **LBWG Operating** (Operating Checking)
2. **LBWG Reserve** (Savings/Reserve)
3. **MERCDEE Operating Checking**
4. **MERCDEE Reserve Savings**
5. **Family Trust Primary Account**
6. **Family Trust Reserve Account**

### Source Documents Reviewed

- `LBWG_Business_Banking_Setup_Packet.md`
- `MERCDEE_Business_Banking_Setup_Packet.md`
- `Mercier_Broome_Leeper_Family_Trust_Integration_Addendum.md`

### Scope Notes

- Optional/conditional accounts (e.g., merchant, collections, escrow/settlement) are not included in the core AUM list above.
- This update reflects named account structures in repository documentation, not account balances.

---

## 2) Revenue Update

### Current Revenue Data Status

A review of the referenced source documents confirms there are **no explicit realized revenue figures** (for example, booked MTD/QTD/YTD or monthly totals) available for direct reporting.

### Documents reviewed for this conclusion

- `LBWG_Business_Banking_Setup_Packet.md`
- `MERCDEE_Business_Banking_Setup_Packet.md`
- `Mercier_Broome_Leeper_Family_Trust_Integration_Addendum.md`

### What is present

- Banking setup structures and account topology
- Placeholder fields for expected deposits/volume
- Governance, controls, and operational procedures

### What is missing for a numeric revenue report

- Actual transaction-level inflow data by reporting period
- Revenue classification rules (operating income vs transfers/funding)
- Final reporting period definitions (MTD/QTD/YTD cutoffs)
- Confirmed source-of-truth ledger or bank export

### Revenue Data Required (Ready-to-Fill Template)

|Field|Required Input|
|---|---|
|Reporting Period|`YYYY-MM` or `Q# YYYY`|
|Entity|`LBWG` / `MERCDEE` / `Family Trust`|
|Gross Inflows|Numeric currency value|
|Non-Revenue Transfers Excluded|Numeric currency value|
|Net Recognized Revenue|Numeric currency value|
|Source File|Ledger/report/export file name|
|As-of Date|`YYYY-MM-DD`|

---

## 3) Recommended Next Step for Revenue Reporting

To produce a numeric revenue update in-repository, add one of the following source inputs:

1. A monthly revenue ledger file (CSV/JSON/MD)
2. Sanitized bank transaction exports with classification tags
3. A canonical finance report document to parse and summarize

Once provided, this report can be extended with:

- MTD / QTD / YTD revenue
- Entity-level breakout (LBWG vs MERCDEE vs Trust flows)
- Trend snapshot and variance notes

---

## 4) Snapshot Summary

- **AUM Buckets Identified:** 6
- **Revenue Figure Availability:** Not available in current source documents
- **Status:** Documentation updated in repository with consolidated AUM + revenue data readiness assessment

---

## 5) Cross-Reference: Company Updates + Integrations Execution

For a full consolidated execution view (company updates, banking onboarding readiness, trust/entity governance separation, JPM technical integration rollout, phased deliverables, and risk controls), see:

- `COMPANY_UPDATES_AND_INTEGRATIONS_PLAN.md`
