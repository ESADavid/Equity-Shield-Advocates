# Operational Control Memo

> Comprehensive operational control framework for Equity Shield Advocates banking operations, trust/entity separation, and compliance governance

**Effective Date:** [Effective Date]
**Version:** 1.0
**Approved By:** [Board/Trustee Authority]
**Review Frequency:** Quarterly

---

## 1) Purpose and Scope

This Operational Control Memo establishes the governance framework for:

1. **Banking Operations** — Account access, approvals, and payment controls
2. **Trust/Entity Separation** — Preventing commingling between Family Trust and corporate entities
3. **Reconciliation Responsibilities** — Monthly/quarterly review and sign-off
4. **Escalation Workflow** — Issue handling and escalation paths

---

## 2) Approval Matrix

### 2.1 Transaction Approval Thresholds

| Transaction Type | Amount Range | Required Approvals | Notes |
| ---------------- | ------------ | ------------------- | ----- |
| ACH/Wire | $0.01 - $999.99 | 1 authorized signer | Routine operations |
| ACH/Wire | $1,000.00 - $4,999.99 | 1 authorized signer + secondary review | Mid-level approval |
| ACH/Wire | $5,000.00+ | 2 authorized signers | Dual approval required |
| Check issuance | $0.01 - $999.99 | 1 authorized signer | Standard check |
| Check issuance | $1,000.00+ | 2 authorized signers | Dual approval required |
| Online banking login | Any | MFA required | No exception |
| User provisioning | Any | Admin + 1 approver | Access control |

### 2.2 Authorized Signers by Entity

**LBWG:**

- Signer 1: [Name, Title]
- Signer 2: [Name, Title]
- Backup: [Name, Title]

**MERCDEE:**

- Signer 1: [Name, Title]
- Signer 2: [Name, Title]
- Backup: [Name, Title]

**Family Trust:**

- Primary Trustee: [Name]
- Successor Trustee: [Name]

### 2.3 Role Definitions

| Role | Responsibilities | Authority Level |
|------|------------------|-----------------|
| Admin (Controller/CFO) | User provisioning, limit changes, full system access | Highest |
| Approver (Director/Officer) | Transaction approval, policy exceptions | Medium-High |
| Initiator (Bookkeeper) | Payment initiation, limited payments | Low-Medium |
| View-Only | Read-only access, reporting | Lowest |

---

## 3) Trust/Entity Transfer Governance

### 3.1 No Commingling Policy

**Rule:** Trust funds and entity funds must never be mixed in one account.

- Family Trust accounts must be maintained separately from LBWG and MERCDEE accounts
- No joint accounts permitted
- No sweep arrangements between trust and entity accounts

### 3.2 Transfer Approval Requirements

**Any transfer between trust and entity accounts requires:**

1. **Written purpose memo** — Documented reason for transfer
2. **Trustee approval** — If trust is party to transfer
3. **Entity officer approval** — If entity is party to transfer
4. **Legal/accounting rationale** — Supporting documentation
5. **Retention in records** — Kept in trust administration files

### 3.3 Transfer Types and Treatment

| Transfer Type | Treatment Required | Documentation |
| ---------------- | ------------------- | --------------- |
| Loan to entity | Promissory note, repayment terms | Legal review |
| Capital support | Board resolution | Corporate records |
| Reimbursement | Invoice/supporting docs | Accounting records |
| Expense advance | Budget authorization | Approval memo |
| Beneficiary distribution | Trust terms compliance | Trustee approval |

### 3.4 Dual Approval Threshold

All transfers exceeding **$5,000** require dual approval (two signers).

---

## 4) Reconciliation Responsibilities

### 4.1 Monthly Reconciliation Tasks

| Task | Owner | Due Date | Notes |
|------|-------|---------|-------|
| Bank statement retrieval | [Name] | Day 3 of following month | All accounts |
| Reconciliation completion | [Name] | Day 5 of following month | All accounts |
| Variance review | [Name] | Day 7 of following month | Unusual items |
| Sign-off | [Name] | Day 10 of following month | Manager review |

### 4.2 Quarterly Control Tasks

| Task | Owner | Due Date | Notes |
|------|-------|---------|-------|
| Signer/access review | [Name] | End of quarter | Verify current signers |
| Trustee oversight memo | [Name] | End of quarter | Trust activities |
| Policy compliance review | [Name] | End of quarter | Control effectiveness |
| Security audit | [Name] | End of quarter | MFA, alerts |

### 4.3 Annual Control Tasks

| Task | Owner | Due Date | Notes |
| ------ | ------ | -------- | ------- |
| Year-end trust accounting | [Name] | January 31 | Tax package support |
| Bank relationship review | [Name] | Q1 | Fees, performance |
| Control review memo | [Name] | Q1 | Annual assessment |

---

## 5) Escalation Workflow

### 5.1 Issue Severity Levels

| Level | Definition | Response Time | Escalation Path |
|-------|-----------|-------------|--------------|
| **Critical** | Fraud, breach, funds at risk | Immediate | CFO → Board → Legal |
| **High** | System down, failed controls | 1 hour | Manager → CFO |
| **Medium** | Policy variance, delays | 4 hours | Manager |
| **Low** | Minor issues, questions | 24 hours | Team lead |

### 5.2 Escalation Contact List

| Role | Name | Phone | Email | Backup |
|------|------|-------|-------|--------|
| CFO/Controller | [Name] | [Phone] | [Email] | [Backup Name] |
| Board Chair | [Name] | [Phone] | [Email] | [Backup Name] |
| Legal Counsel | [Name] | [Phone] | [Email] | [Firm Name] |
| Bank Relationship Manager | [Name] | [Phone] | [Email] | [Bank Name] |
| IT Security | [Name] | [Phone] | [Email] | [Backup Name] |

### 5.3 Incident Response Steps

1. **Identify** — Determine severity and scope
2. **Contain** — Limit exposure/ damage
3. **Notify** — Escalate per severity matrix
4. **Document** — Capture timeline and details
5. **Resolve** — Implement fix
6. **Review** — Post-incident analysis
7. **Update** — Revise controls if needed

---

## 6) Security Controls

### 6.1 Required Security Measures

- **MFA** — Multi-factor authentication required for all users
- **Alerts** — Real-time transaction alerts enabled
- **Session timeout** — 15 minutes inactivity
- **Password policy** — 12+ characters, complexity required
- **No shared credentials** — Individual accounts only

### 6.2 Fraud Prevention Controls

- **Positive Pay** — Enabled for checks (if available)
- **ACH blocks/filters** — Whitelisted accounts only
- **Dual approval** — For high-value transactions
- **Velocity limits** — Daily transaction caps
- **Geo-blocking** — Restrict high-risk regions

### 6.3 Alert Configuration

| Alert Type | Recipient | Method | Timing |
|------------|----------|--------|--------|
| Login from new device | Admin | Email + SMS | Immediate |
| Transaction > $1,000 | Approver | Email + SMS | Immediate |
| Failed login (3 attempts) | Admin | Email | Immediate |
| Password change | User | Email | Immediate |
| New user added | Admin | Email | Immediate |

---

## 7) Compliance and Audit

### 7.1 Required Compliance Activities

- Quarterly access review
- Annual control assessment
- Segregation of duties verification
- Policy exception documentation
- Training completion tracking

### 7.2 Record Retention

| Document Type | Retention Period | Storage Location |
|-------------|---------------|--------------|
| Bank statements | 7 years | Secure records folder |
| Reconciliation workpapers | 7 years | Accounting system |
| Transfer memos | 7 years | Trust records |
| Approval records | 7 years | Corporate records |
| Alert/incident reports | 7 years | Compliance system |

### 7.3 Audit Readiness

- All supporting documentation available
- Reconciliation sign-off current
- Access list up to date
- Control memo on file
- Escalation contacts verified

---

## 8) Policy Exceptions

### 8.1 Exception Request Process

1. Submit written request to [CFO/Controller]
2. Document business justification
3. Identify compensating controls
4. Get approval from [appropriate authority]
5. Document in exception log
6. Set review date (max 90 days)

### 8.2 Approved Exceptions Log

| Date | Exception | Approved By | Expiry | Status |
|------|----------|------------|--------|--------|
| [Date] | [Description] | [Name] | [Date] | [Active/Closed] |

---

## 9) Training Requirements

| Role | Required Training | Frequency | Completion Due |
|------|----------------|----------|--------------|
| All users | Security awareness | Annual | [Date] |
| Initiators | Payment processing | Annual | [Date] |
| Approvers | Control and compliance | Annual | [Date] |
| Administrators | System administration | Annual | [Date] |
| Trustees | Trust governance | Annual | [Date] |

---

## 10) Acknowledgment

I have read and understand this Operational Control Memo and agree to comply with all policies and procedures outlined herein.

| Role | Name | Signature | Date |
|------|------|----------|------|
| [Role] | [Name] | _________________ | [Date] |
| [Role] | [Name] | _________________ | [Date] |
| [Role] | [Name] | _________________ | [Date] |

---

## 11) Document Control

| Version | Date   | Author   | Changes         |
|---------|--------|----------|-----------------|
| 1.0     | [Date] | [Author] | Initial release |

**Next Review Date:** [Quarter + Year]
**Document Owner:** [CFO/Controller]
**Location:** [SharePoint/Records Folder]

---

*This document establishes operational controls for Equity Shield Advocates entities and should be reviewed by legal counsel before formal adoption.*
