/**
 * Patent/IP Model
 */

import mongoose from 'mongoose';

const PatentSchema = new mongoose.Schema(
  {
    citizenId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Citizen',
      required: true,
      index: true,
    },
    patentId: {
      type: String,
      required: true,
      unique: true,
    },
    title: { type: String, required: true },
    patentNumber: { type: String, required: true },
    filingDate: { type: Date, required: true },
    issueDate: Date,
    expiryDate: Date,
    status: {
      type: String,
      enum: ['pending', 'issued', 'expired'],
      default: 'pending',
    },
estimatedValue: { type: mongoose.Types.Decimal128, default: 0 },
    description: String,
  },
  { timestamps: true }
);

PatentSchema.statics.generatePatentId = async function () {
  let id;
  do {
    id =
      'PAT-' +
      Date.now() +
      '-' +
      Math.random().toString(36).substr(2, 6).toUpperCase();
  } while (await this.findOne({ patentId: id }));
  return id;
};

PatentSchema.pre('save', async function (next) {
  if (!this.patentId) this.patentId = await this.constructor.generatePatentId();
  next();
});

export default mongoose.model('Patent', PatentSchema);
