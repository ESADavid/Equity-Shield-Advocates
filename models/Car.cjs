const mongoose = require('mongoose');

const carSchema = new mongoose.Schema({
  carId: {
    type: String,
    required: true,
    unique: true,
    index: true
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
    default: 0
  },
  condition: {
    type: String,
    enum: ['excellent', 'good', 'fair', 'poor'],
    default: 'good'
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
  location: {
    type: String,
    required: true
  },
  features: [{
    type: String
  }],
  description: {
    type: String
  },
  status: {
    type: String,
    enum: ['available', 'sold', 'reserved'],
    default: 'available'
  },
  soldPrice: {
    type: Number
  },
  soldBy: {
    type: String
  },
  soldAt: {
    type: Date
  },
  tenantId: {
    type: String,
    required: true,
    index: true
  },
  createdBy: {
    type: String,
    required: true
  }
}, {
  timestamps: true
});

// Virtual for profit/loss calculation
carSchema.virtual('profitLoss').get(function() {
  if (this.status === 'sold' && this.soldPrice) {
    return this.soldPrice - this.purchasePrice;
  }
  return 0;
});

// Virtual for profit/loss percentage
carSchema.virtual('profitLossPercent').get(function() {
  if (this.status === 'sold' && this.soldPrice && this.purchasePrice > 0) {
    return ((this.soldPrice - this.purchasePrice) / this.purchasePrice) * 100;
  }
  return 0;
});

// Virtual for days on market
carSchema.virtual('daysOnMarket').get(function() {
  if (this.status === 'sold' && this.soldAt) {
    const diffTime = this.soldAt - this.createdAt;
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }
  return 0;
});

// Ensure virtual fields are serialized
carSchema.set('toJSON', { virtuals: true });
carSchema.set('toObject', { virtuals: true });

// Indexes
carSchema.index({ tenantId: 1, status: 1 });
carSchema.index({ make: 1, model: 1 });
carSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Car', carSchema);
