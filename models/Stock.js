/**
 * Stock Portfolio Model
 */

import mongoose from 'mongoose';

const StockSchema = new mongoose.Schema(
  {
    citizenId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Citizen',
      required: true,
      index: true,
    },
    stockId: {
      type: String,
      required: true,
      unique: true,
    },
    ticker: { type: String, required: true, uppercase: true },
    companyName: { type: String, required: true },
sharesOwned: { type: Number, required: true, min: 0 },
    avgPurchasePrice: { type: mongoose.Types.Decimal128, required: true },
    currentPrice: { type: mongoose.Types.Decimal128, default: 0 },
    totalValue: { type: mongoose.Types.Decimal128, default: 0 },
    status: { type: String, enum: ['active', 'sold'], default: 'active' },
  },
  { timestamps: true }
);

StockSchema.statics.generateStockId = async function () {
  let id;
  do {
    id =
      'STK-' +
      Date.now() +
      '-' +
      Math.random().toString(36).substr(2, 6).toUpperCase();
  } while (await this.findOne({ stockId: id }));
  return id;
};

StockSchema.pre('save', async function (next) {
  if (!this.stockId) this.stockId = await this.constructor.generateStockId();
  this.totalValue = this.sharesOwned * this.currentPrice;
  next();
});

export default mongoose.model('Stock', StockSchema);
