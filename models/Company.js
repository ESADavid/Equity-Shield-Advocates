/**
 * Company Ownership Model
 */

import mongoose from 'mongoose';

const CompanySchema = new mongoose.Schema(
  {
    citizenId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Citizen',
      required: true,
      index: true,
    },
    companyId: {
      type: String,
      required: true,
      unique: true,
    },
    name: { type: String, required: true },
    sharesOwned: { type: Number, required: true, min: 0 },
    sharePrice: { type: mongoose.Types.Decimal128, default: 0 },
    totalValue: { type: mongoose.Types.Decimal128, default: 0 },
    ownershipPercentage: { type: Number, min: 0, max: 100 },
    role: { type: String, enum: ['owner', 'shareholder', 'director'] },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
  },
  { timestamps: true }
);

CompanySchema.statics.generateCompanyId = async function () {
  let id;
  do {
    id =
      'COMP-' +
      Date.now() +
      '-' +
      Math.random().toString(36).substr(2, 6).toUpperCase();
  } while (await this.findOne({ companyId: id }));
  return id;
};

CompanySchema.pre('save', async function (next) {
  if (!this.companyId)
    this.companyId = await this.constructor.generateCompanyId();
  next();
});

export default mongoose.model('Company', CompanySchema);
