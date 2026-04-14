/**
 * UBI PAYMENT MODEL
 * Database model for UBI payment tracking and processing
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import mongoose from 'mongoose';
import { info, error, warn } from '../utils/loggerWrapper.js';

const ubiPaymentSchema = new mongoose.Schema(
  {
    citizenId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Citizen',
      required: true,
      index: true,
    },
    amount: {
      type: Number,
      required: true,
      min: 0,
    },
    paymentDate: {
      type: Date,
      default: Date.now,
      index: true,
    },
    status: {
      type: String,
      enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'],
      default: 'pending',
      index: true,
    },
    transactionId: {
      type: String,
      sparse: true,
      index: true,
    },
    blockchainHash: {
      type: String,
      sparse: true,
    },
    paymentMethod: {
      type: String,
      enum: ['jpmorgan', 'direct', 'check', 'mobile_money'],
      default: 'jpmorgan',
    },
    metadata: {
      jpmorganOrderId: String,
      authorizationCode: String,
      lastStatusCheck: Date,
      retryCount: { type: Number, default: 0 },
      errorMessage: String,
      processedBy: String,
      approvedBy: String,
    },
    auditLog: [
      {
        action: String,
        performedBy: String,
        timestamp: { type: Date, default: Date.now },
        details: mongoose.Schema.Types.Mixed,
      },
    ],
  },
  {
    timestamps: true,
    collection: 'ubi_payments',
  }
);

// Indexes for performance
ubiPaymentSchema.index({ citizenId: 1, paymentDate: -1 });
ubiPaymentSchema.index({ status: 1, paymentDate: -1 });
ubiPaymentSchema.index({ transactionId: 1 });

// Virtual for payment age in days
ubiPaymentSchema.virtual('ageInDays').get(function () {
  return Math.floor(
    (Date.now() - this.paymentDate.getTime()) / (1000 * 60 * 60 * 24)
  );
});

// Method to validate payment data
ubiPaymentSchema.methods.validatePayment = function () {
  if (this.amount <= 0) {
    throw new Error('Payment amount must be greater than 0');
  }

  if (!this.citizenId) {
    throw new Error('Citizen ID is required');
  }

  if (
    !['jpmorgan', 'direct', 'check', 'mobile_money'].includes(
      this.paymentMethod
    )
  ) {
    throw new Error('Invalid payment method');
  }

  return true;
};

// Method to update payment status with audit trail
ubiPaymentSchema.methods.updateStatus = function (
  newStatus,
  performedBy,
  details = {}
) {
  const oldStatus = this.status;

  if (oldStatus === newStatus) {
    return false; // No change needed
  }

  this.status = newStatus;
  this.metadata.lastStatusCheck = new Date();

  // Add to audit log
  this.auditLog.push({
    action: 'STATUS_UPDATE',
    performedBy: performedBy || 'system',
    details: {
      oldStatus,
      newStatus,
      ...details,
    },
  });

  info(`UBI Payment ${this._id} status updated: ${oldStatus} -> ${newStatus}`);
  return true;
};

// Method to mark as failed with error details
ubiPaymentSchema.methods.markAsFailed = function (
  errorMessage,
  performedBy = 'system'
) {
  this.status = 'failed';
  this.metadata.errorMessage = errorMessage;
  this.metadata.lastStatusCheck = new Date();

  this.auditLog.push({
    action: 'PAYMENT_FAILED',
    performedBy,
    details: { errorMessage },
  });

  error(`UBI Payment ${this._id} failed: ${errorMessage}`);
  return this.save();
};

// Method to retry payment
ubiPaymentSchema.methods.retryPayment = function (performedBy = 'system') {
  if (this.status !== 'failed') {
    throw new Error('Can only retry failed payments');
  }

  this.status = 'pending';
  this.metadata.retryCount = (this.metadata.retryCount || 0) + 1;
  this.metadata.errorMessage = null;

  this.auditLog.push({
    action: 'PAYMENT_RETRY',
    performedBy,
    details: { retryCount: this.metadata.retryCount },
  });

  info(
    `UBI Payment ${this._id} queued for retry (attempt ${this.metadata.retryCount})`
  );
  return this.save();
};

// Method to check if payment can be retried
ubiPaymentSchema.methods.canRetry = function () {
  const maxRetries = 3;
  return (
    this.status === 'failed' && (this.metadata.retryCount || 0) < maxRetries
  );
};

// Method to get payment summary
ubiPaymentSchema.methods.getSummary = function () {
  return {
    id: this._id,
    citizenId: this.citizenId,
    amount: this.amount,
    paymentDate: this.paymentDate,
    status: this.status,
    paymentMethod: this.paymentMethod,
    transactionId: this.transactionId,
    blockchainHash: this.blockchainHash,
    ageInDays: this.ageInDays,
    retryCount: this.metadata.retryCount || 0,
    lastUpdated: this.updatedAt,
  };
};

// Static method to find payments by citizen
ubiPaymentSchema.statics.findByCitizen = function (citizenId, limit = 50) {
  return this.find({ citizenId })
    .sort({ paymentDate: -1 })
    .limit(limit)
    .populate(
      'citizenId',
      'citizenId personalInfo.firstName personalInfo.lastName'
    );
};

// Static method to find failed payments for retry
ubiPaymentSchema.statics.findFailedPaymentsForRetry = function () {
  return this.find({
    status: 'failed',
    'metadata.retryCount': { $lt: 3 },
  }).sort({ paymentDate: 1 });
};

// Static method to get payment statistics
ubiPaymentSchema.statics.getPaymentStats = async function (startDate, endDate) {
  const matchStage = {};
  if (startDate && endDate) {
    matchStage.paymentDate = { $gte: startDate, $lte: endDate };
  }

  const stats = await this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        totalAmount: { $sum: '$amount' },
        avgAmount: { $avg: '$amount' },
      },
    },
  ]);

  const result = {
    total: 0,
    byStatus: {},
    totalAmount: 0,
    avgAmount: 0,
  };

  stats.forEach((stat) => {
    result.byStatus[stat._id] = {
      count: stat.count,
      totalAmount: stat.totalAmount,
      avgAmount: Math.round(stat.avgAmount * 100) / 100,
    };
    result.total += stat.count;
    result.totalAmount += stat.totalAmount;
  });

  if (result.total > 0) {
    result.avgAmount =
      Math.round((result.totalAmount / result.total) * 100) / 100;
  }

  return result;
};

// Pre-save middleware
ubiPaymentSchema.pre('save', function (next) {
  // Validate payment before saving
  try {
    this.validatePayment();
    next();
  } catch (err) {
    next(err);
  }
});

// Post-save middleware for logging
ubiPaymentSchema.post('save', function (doc) {
  info(
    `UBI Payment saved: ${doc._id} - Status: ${doc.status} - Amount: $${doc.amount}`
  );
});

export default mongoose.model('UBIPayment', ubiPaymentSchema);
