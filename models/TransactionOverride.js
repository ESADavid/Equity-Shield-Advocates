/**
 * Transaction Override Model
 * Manages transaction override requests and approvals
 */

class TransactionOverride {
  constructor(data = {}) {
    this.id = data.id || this.generateId();
    this.originalTransactionId = data.originalTransactionId;
    this.transactionType = data.transactionType; // 'earnings', 'purchase', etc.
    this.overrideType = data.overrideType; // 'amount', 'status', 'date', 'delete'
    this.originalValue = data.originalValue;
    this.newValue = data.newValue;
    this.reason = data.reason;
    this.requestedBy = data.requestedBy;
    this.requestedAt = data.requestedAt || new Date().toISOString();
    this.status = data.status || 'pending'; // pending, approved, rejected
    this.approvedBy = data.approvedBy || null;
    this.approvedAt = data.approvedAt || null;
    this.rejectionReason = data.rejectionReason || null;
    this.auditTrail = data.auditTrail || [];
  }

  generateId() {
    return `override_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  addAuditEntry(action, user, details) {
    this.auditTrail.push({
      action,
      user,
      details,
      timestamp: new Date().toISOString()
    });
  }

  approve(approver, notes = '') {
    this.status = 'approved';
    this.approvedBy = approver;
    this.approvedAt = new Date().toISOString();
    this.addAuditEntry('approved', approver, notes);
  }

  reject(rejector, reason) {
    this.status = 'rejected';
    this.rejectionReason = reason;
    this.addAuditEntry('rejected', rejector, reason);
  }

  toJSON() {
    return {
      id: this.id,
      originalTransactionId: this.originalTransactionId,
      transactionType: this.transactionType,
      overrideType: this.overrideType,
      originalValue: this.originalValue,
      newValue: this.newValue,
      reason: this.reason,
      requestedBy: this.requestedBy,
      requestedAt: this.requestedAt,
      status: this.status,
      approvedBy: this.approvedBy,
      approvedAt: this.approvedAt,
      rejectionReason: this.rejectionReason,
      auditTrail: this.auditTrail
    };
  }
}

module.exports = TransactionOverride;
