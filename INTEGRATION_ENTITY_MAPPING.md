# Integration Entity Mapping

> Maps revenue account sources to entity structures for monthly reporting

---

## Revenue Account to Entity Mapping

| Revenue | Source | Entity | Type | Logic |
|---------|--------|--------|------|-------|
| Consulting | ACCT-1001 | LBWG | Operating | Primary revenue source |
| Licensing | ACCT-1002 | MERCDEE | Operating | IP licensing revenue |
| Subscriptions | ACCT-1003 | Family Trust | Primary | Recurring revenue trust |

---

## Entity Account Structure

### LBWG (Operating Checking)

- **Source Accounts**: ACCT-1001 (Consulting)
- **Revenue Type**: Service/income
- **Pattern**: `ACCT-1001`

### LBWG (Reserve Savings)

- **Source**: Internal transfer from Operating
- **Revenue Type**: Accumulated reserves
- **Pattern**: Transfer from ACCT-1001 excess

### MERCDEE (Operating Checking)

- **Source Accounts**: ACCT-1002 (Licensing)
- **Revenue Type**: Licensing income
- **Pattern**: `ACCT-1002`

### MERCDEE (Reserve Savings)

- **Source**: Internal transfer from Operating
- **Revenue Type**: Accumulated reserves
- **Pattern**: Transfer from ACCT-1002 excess

### Mercier Broome Leeper Family Trust (Primary)

- **Source Accounts**: ACCT-1003 (Subscriptions)
- **Revenue Type**: Trust income
- **Pattern**: `ACCT-1003`

### Mercier Broome Leeper Family Trust (Reserve)

- **Source**: Internal transfer from Primary
- **Revenue Type**: Accumulated reserves
- **Pattern**: Transfer from ACCT-1003 excess

---

## Revenue Distribution Matrix

| From Entity | To Entity | Amount | Purpose |
|-------------|----------|--------|---------|
| Consulting (LBWG) | Reserve | [TBD] | Savings allocation |
| Licensing (MERCDEE) | Reserve | [TBD] | Savings allocation |
| Subscriptions (Trust) | Trust Reserve | [TBD] | Savings allocation |
| Family Trust | LBWG | [TBD] | Operational funding |
| Family Trust | MERCDEE | [TBD] | Operational funding |

---

## Data Sync Requirements

### Monthly Sync Actions

1. Pull revenue from ACCT-1001, ACCT-1002, ACCT-1003
2. Map to respective entity accounts
3. Calculate transfers between entities
4. Update monthly_reporting_packet.md

### Account Reconciliation

- Verify revenue amounts match bank statements
- Reconcile inter-entity transfers
- Flag variances > 5%

---

## Integration Status

| Component | Status | Last Sync |
|-----------|--------|------------|
| JPM OAuth | Active | N/A |
| Banking Setup | Configured | N/A |
| Revenue Data Sync | Pending | Not started |
| Monthly Report | Template ready | N/A |

---

*Document Version: 1.0*
*Created: [Current Date]*
