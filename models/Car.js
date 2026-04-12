/**
 * Vehicle Ownership Model (from app.js cars)
 */

import mongoose from 'mongoose';

const CarSchema = new mongoose.Schema({
  citizenId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Citizen',
    required: true,
    index: true
  },
  carId: {
    type: String,
    required: true,
    unique: true
  },
  model: { type: String, required: true },
  vin: { type: String, required: true, unique: true },
  purchasePrice: { type: mongoose.Decimal128, required: true },
  currentValue: { type: mongoose.Decimal128, default: 0 },
  purchaseDate: { type: Date, default: Date.now },
  status: { type: String, enum: ['owned', 'sold', 'totaled'], default: 'owned' },
  dealership: String
}, { timestamps: true });

CarSchema.statics.generateCarId = async function() {
  let id;
  do {
    id = 'CAR-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6).toUpperCase();
  } while (await this.findOne({ carId: id }));
  return id;
};

CarSchema.pre('save', async function(next) {
  if (!this.carId) this.carId = await this.constructor.generateCarId();
  next();
});

export default mongoose.model('Car', CarSchema);

