const mongoose = require('mongoose');

const carSchema = new mongoose.Schema({
  tenantId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Tenant',
    required: true
  },
  carId: {
    type: String,
    required: true,
    unique: true
  },
  make: {
    type: String,
    required: true
  },
  model: {
    type: String,
    required: true
  },
  year: {
    type: Number,
    required: true
  },
  vin: {
    type: String,
    required: true,
    unique: true
  },
  mileage: {
    type: Number,
    required: true
  },
  condition: {
    type: String,
    enum: ['excellent', 'good', 'fair', 'poor'],
    required: true
  },
  purchasePrice: {
    type: Number,
    required: true
  },
  currentValue: {
    type: Number,
    required: true
  },
  askingPrice: {
    type: Number,
    required: true
  },
  soldPrice: {
    type: Number,
    default: null
  },
  status: {
    type: String,
    enum: ['available', 'sold', 'pending'],
    default: 'available'
  },
  location: {
    type: String,
    required: true
  },
  features: [{
    type: String
  }],
  images: [{
    type: String
  }],
  description: {
    type: String
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  soldBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  soldAt: {
    type: Date
  }
}, {
  timestamps: true
});

// Virtual for profit/loss
carSchema.virtual('profitLoss').get(function() {
  if (this.soldPrice) {
    return this.soldPrice - this.purchasePrice;
  }
  return 0;
});

// Virtual for profit/loss percentage
carSchema.virtual('profitLossPercent').get(function() {
  if (this.soldPrice && this.purchasePrice > 0) {
    return ((this.soldPrice - this.purchasePrice) / this.purchasePrice) * 100;
  }
  return 0;
});

// Virtual for days on market
carSchema.virtual('daysOnMarket').get(function() {
  if (this.soldAt) {
    return Math.floor((this.soldAt - this.createdAt) / (1000 * 60 * 60 * 24));
  }
  return Math.floor((new Date() - this.createdAt) / (1000 * 60 * 60 * 24));
});

carSchema.set('toJSON', { virtuals: true });
carSchema.set('toObject', { virtuals: true });

module.exports = mongoose.model('Car', carSchema);
