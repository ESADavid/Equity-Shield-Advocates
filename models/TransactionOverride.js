import mongoose from 'mongoose';

/**
 * Transaction Override Model
 * Manages transaction override requests and approvals
 */

const transactionOverrideSchema = new mongoose.Schema({
  tenantId: {
    type: String,
    required: true,
    index: true
  },
  originalTransactionId: {
    type: String,
    required: true,
    index: true
  },
  transactionType: {
    type: String,
    required: true,
    enum: ['earnings', 'purchase', 'transfer', 'payment', 'fee', 'refund']
  },
  overrideType: {
    type: String,
    required: true,
    enum: ['amount', 'status', 'date', 'delete', 'merchant', 'description']
  },
  originalValue: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  newValue: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  reason: {
    type: String,
    required: true,
    maxlength: 500
  },
  requestedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'cancelled'],
    default: 'pending'
  },
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  approvedAt: Date,
  rejectionReason: String,
  auditTrail: [{
    action: {
      type: String,
      enum: ['created', 'approved', 'rejected', 'cancelled', 'modified']
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    details: String,
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, {
  timestamps: true
});

// Indexes
transactionOverrideSchema.index({ tenantId: 1, status: 1 });
transactionOverrideSchema.index({ tenantId: 1, requestedBy: 1 });
transactionOverrideSchema.index({ tenantId: 1, originalTransactionId: 1 });
transactionOverrideSchema.index({ tenantId: 1, 'auditTrail.timestamp': -1 });

// Virtual for isPending
transactionOverrideSchema.virtual('isPending').get(function() {
  return this.status === 'pending';
});

// Virtual for isApproved
transactionOverrideSchema.virtual('isApproved').get(function() {
  return this.status === 'approved';
});

// Instance methods
transactionOverrideSchema.methods = {
  // Approve override
  approve: function(approverId, notes = '') {
    this.status = 'approved';
    this.approvedBy = approverId;
    this.approvedAt = new Date();
    this.auditTrail.push({
      action: 'approved',
      user: approverId,
      details: notes,
      timestamp: new Date()
    });
    return this.save();
  },

  // Reject override
  reject: function(approverId, reason) {
    this.status = 'rejected';
    this.approvedBy = approverId;
    this.rejectionReason = reason;
    this.auditTrail.push({
      action: 'rejected',
      user: approverId,
      details: reason,
      timestamp: new Date()
    });
    return this.save();
  },

  // Cancel override
  cancel: function(userId, reason = '') {
    this.status = 'cancelled';
    this.auditTrail.push({
      action: 'cancelled',
      user: userId,
      details: reason,
      timestamp: new Date()
    });
    return this.save();
  },

  // Add audit entry
  addAuditEntry: function(action, userId, details = '') {
    this.auditTrail.push({
      action,
      user: userId,
      details,
      timestamp: new Date()
    });
    return this.save();
  },

  // Get summary
  getSummary: function() {
    return {
      id: this._id,
      originalTransactionId: this.originalTransactionId,
      transactionType: this.transactionType,
      overrideType: this.overrideType,
      originalValue: this.originalValue,
      newValue: this.newValue,
      reason: this.reason,
      status: this.status,
      requestedBy: this.requestedBy,
      requestedAt: this.createdAt,
      approvedBy: this.approvedBy,
      approvedAt: this.approvedAt
    };
  }
};

// Static methods
transactionOverrideSchema.statics = {
  // Get overrides by status within tenant
  getByStatus: function(status, tenantId, limit = 50) {
    return this.find({ tenantId, status })
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('requestedBy', 'username firstName lastName')
      .populate('approvedBy', 'username firstName lastName');
  },

  // Get overrides by user within tenant
  getByUser: function(userId, tenantId, limit = 50) {
    return this.find({ tenantId, requestedBy: userId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('requestedBy', 'username firstName lastName')
      .populate('approvedBy', 'username firstName lastName');
  },

  // Get pending overrides within tenant
  getPending: function(tenantId, limit = 100) {
    return this.find({ tenantId, status: 'pending' })
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('requestedBy', 'username firstName lastName');
  },

  // Get overrides by transaction within tenant
  getByTransaction: function(transactionId, tenantId) {
    return this.find({ tenantId, originalTransactionId: transactionId })
      .sort({ createdAt: -1 })
      .populate('requestedBy', 'username firstName lastName')
      .populate('approvedBy', 'username firstName lastName');
  },

  // Get overrides by tenant
  getByTenant: function(tenantId, limit = 100, skip = 0) {
    return this.find({ tenantId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip)
      .populate('requestedBy', 'username firstName lastName')
      .populate('approvedBy', 'username firstName lastName');
  }
};

export default mongoose.model('TransactionOverride', transactionOverrideSchema);
