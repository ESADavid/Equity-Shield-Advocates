// UBI Payment Model
import mongoose from 'mongoose';

const ubiPaymentSchema = new mongoose.Schema({
  citizenId: { type: mongoose.Schema.Types.ObjectId, ref: 'Citizen', required: true },
  amount: { type: Number, required: true },
  paymentDate: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'processing', 'completed', 'failed'], default: 'pending' },
  transactionId: String,
  blockchainHash: String,
  paymentMethod: { type: String, enum: ['jpmorgan', 'direct', 'check'], default: 'jpmorgan' },
  metadata: mongoose.Schema.Types.Mixed
}, { timestamps: true });

export default mongoose.model('UBIPayment', ubiPaymentSchema);
