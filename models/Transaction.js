import mongoose from 'mongoose';

const transactionSchema = new mongoose.Schema({
  tenantId: {
    type: String,
    required: true,
    index: true
  },
  transactionId: {
    type: String,
    required: true,
    index: true
  },
  type: {
    type: String,
    required: true,
    enum: ['payment', 'transfer', 'withdrawal', 'deposit', 'fee', 'refund', 'override', 'debt_acquisition', 'debt_payment', 'debt_interest']
  },
  amount: {
    type: mongoose.Decimal128,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    required: true,
    default: 'USD',
    enum: ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD']
  },
  status: {
    type: String,
    required: true,
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled', 'overridden'],
    default: 'pending'
  },
  fromAccount: {
    accountId: String,
    accountType: {
      type: String,
      enum: ['checking', 'savings', 'business', 'investment']
    },
    accountHolder: String,
    bankName: String,
    routingNumber: String,
    accountNumber: String
  },
  toAccount: {
    accountId: String,
    accountType: {
      type: String,
      enum: ['checking', 'savings', 'business', 'investment']
    },
    accountHolder: String,
    bankName: String,
    routingNumber: String,
    accountNumber: String
  },
  merchant: {
    merchantId: String,
    name: String,
    category: String,
    location: {
      address: String,
      city: String,
      state: String,
      zipCode: String,
      country: String
    }
  },
  description: {
    type: String,
    maxlength: 500
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  fees: {
    processingFee: { type: mongoose.Decimal128, default: 0 },
    transactionFee: { type: mongoose.Decimal128, default: 0 },
    totalFees: { type: mongoose.Decimal128, default: 0 }
  },
  timestamps: {
    initiated: { type: Date, default: Date.now },
    processed: Date,
    completed: Date,
    failed: Date
  },
  blockchain: {
    recorded: { type: Boolean, default: false },
    blockHash: String,
    transactionHash: String,
    blockIndex: Number,
    merkleRoot: String
  },
  audit: {
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    overriddenBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    overrideReason: String,
    overrideTimestamp: Date,
    ipAddress: String,
    userAgent: String,
    sessionId: String
  },
  risk: {
    score: { type: Number, min: 0, max: 100 },
    flags: [String],
    reviewed: { type: Boolean, default: false },
    reviewNotes: String
  },
  notifications: [{
    type: {
      type: String,
      enum: ['email', 'sms', 'push', 'webhook']
    },
    recipient: String,
    status: {
      type: String,
      enum: ['pending', 'sent', 'delivered', 'failed'],
      default: 'pending'
    },
    sentAt: Date,
    error: String
  }]
}, {
  timestamps: true
});

// Indexes for performance
transactionSchema.index({ tenantId: 1, 'audit.createdBy': 1 });
transactionSchema.index({ tenantId: 1, status: 1 });
transactionSchema.index({ tenantId: 1, type: 1 });
transactionSchema.index({ tenantId: 1, 'timestamps.initiated': -1 });
transactionSchema.index({ tenantId: 1, 'fromAccount.accountId': 1 });
transactionSchema.index({ tenantId: 1, 'toAccount.accountId': 1 });
transactionSchema.index({ tenantId: 1, 'merchant.merchantId': 1 });
transactionSchema.index({ tenantId: 1, 'blockchain.recorded': 1 });
transactionSchema.index({ tenantId: 1, transactionId: 1 }, { unique: true });

// Virtual for total amount including fees
transactionSchema.virtual('totalAmount').get(function() {
  return Number.parseFloat(this.amount.toString()) + Number.parseFloat(this.fees.totalFees.toString());
});

// Virtual for duration
transactionSchema.virtual('processingDuration').get(function() {
  if (this.timestamps.completed && this.timestamps.initiated) {
    return this.timestamps.completed - this.timestamps.initiated;
  }
  return null;
});

// Instance methods
transactionSchema.methods = {
  // Mark as completed
  markCompleted: function(userId) {
    this.status = 'completed';
    this.timestamps.completed = new Date();
    if (userId) {
      this.audit.approvedBy = userId;
    }
    return this.save();
  },

  // Mark as failed
  markFailed: function(reason, userId) {
    this.status = 'failed';
    this.timestamps.failed = new Date();
    this.metadata.failureReason = reason;
    if (userId) {
      this.audit.approvedBy = userId;
    }
    return this.save();
  },

  // Override transaction
  override: function(userId, reason) {
    this.status = 'overridden';
    this.audit.overriddenBy = userId;
    this.audit.overrideReason = reason;
    this.audit.overrideTimestamp = new Date();
    return this.save();
  },

  // Record in blockchain
  recordInBlockchain: function(blockData) {
    this.blockchain.recorded = true;
    this.blockchain.blockHash = blockData.hash;
    this.blockchain.transactionHash = blockData.transactionHash;
    this.blockchain.blockIndex = blockData.blockIndex;
    this.blockchain.merkleRoot = blockData.merkleRoot;
    return this.save();
  },

  // Add notification
  addNotification: function(type, recipient) {
    this.notifications.push({
      type,
      recipient,
      status: 'pending'
    });
    return this.save();
  },

  // Get public transaction data
  toPublicJSON: function() {
    return {
      transactionId: this.transactionId,
      type: this.type,
      amount: this.amount,
      currency: this.currency,
      status: this.status,
      description: this.description,
      timestamps: this.timestamps,
      merchant: this.merchant,
      totalAmount: this.totalAmount,
      processingDuration: this.processingDuration
    };
  }
};

// Static methods
transactionSchema.statics = {
  // Get transactions by user within tenant
  getByUser: function(userId, tenantId, limit = 50, skip = 0) {
    return this.find({ tenantId, 'audit.createdBy': userId })
      .sort({ 'timestamps.initiated': -1 })
      .limit(limit)
      .skip(skip)
      .populate('audit.createdBy', 'username firstName lastName')
      .populate('audit.approvedBy', 'username firstName lastName');
  },

  // Get transactions by status within tenant
  getByStatus: function(status, tenantId, limit = 100) {
    return this.find({ tenantId, status })
      .sort({ 'timestamps.initiated': -1 })
      .limit(limit);
  },

  // Get transactions by date range within tenant
  getByDateRange: function(startDate, endDate, tenantId, status = null) {
    const query = {
      tenantId,
      'timestamps.initiated': {
        $gte: startDate,
        $lte: endDate
      }
    };
    if (status) {
      query.status = status;
    }
    return this.find(query).sort({ 'timestamps.initiated': -1 });
  },

  // Get high-risk transactions within tenant
  getHighRisk: function(tenantId, riskThreshold = 70) {
    return this.find({
      tenantId,
      'risk.score': { $gte: riskThreshold },
      'risk.reviewed': false
    }).sort({ 'risk.score': -1 });
  },

  // Get blockchain-recorded transactions within tenant
  getBlockchainRecorded: function(tenantId, limit = 100) {
    return this.find({ tenantId, 'blockchain.recorded': true })
      .sort({ 'blockchain.blockIndex': -1 })
      .limit(limit);
  },

  // Get transactions by tenant
  getByTenant: function(tenantId, limit = 100, skip = 0) {
    return this.find({ tenantId })
      .sort({ 'timestamps.initiated': -1 })
      .limit(limit)
      .skip(skip);
  }
};

export default mongoose.model('Transaction', transactionSchema);
