/**
 * UBI Payment Model
 * Tracks Universal Basic Income payments to citizens
 */

import mongoose from 'mongoose';

const ubiPaymentSchema = new mongoose.Schema(
  {
    citizenId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Citizen',
      required: true,
    },
    amount: {
      type: Number,
      required: true,
      min: 0,
    },
    paymentDate: {
      type: Date,
      default: Date.now,
    },
    status: {
      type: String,
      enum: ['pending', 'processing', 'completed', 'failed'],
      default: 'pending',
    },
    transactionId: {
      type: String,
      unique: true,
      sparse: true,
    },
    blockchainHash: {
      type: String,
    },
    paymentMethod: {
      type: String,
      enum: ['jpmorgan', 'direct', 'check'],
      default: 'jpmorgan',
    },
    failureReason: String,
    metadata: mongoose.Schema.Types.Mixed,
  },
  {
    timestamps: true,
  }
);

// Indexes for efficient queries
ubiPaymentSchema.index({ citizenId: 1, paymentDate: -1 });
ubiPaymentSchema.index({ status: 1 });
ubiPaymentSchema.index({ transactionId: 1 });

export default mongoose.model('UBIPayment', ubiPaymentSchema);
