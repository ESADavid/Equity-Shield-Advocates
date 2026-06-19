import mongoose from 'mongoose';

const foodSupplyChainSchema = new mongoose.Schema(
  {
    tenantId: {
      type: String,
      required: true,
      index: true,
    },
    chainId: {
      type: String,
      required: true,
      index: true,
    },
    company: {
      type: String,
      required: true,
    },
    country: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      required: true,
      enum: ['farm', 'processor', 'distributor', 'retailer', 'global_chain'],
    },
annualCapacity: {
      type: mongoose.Types.Decimal128,
      required: true,
      min: 0,
    },
    acquiredValue: {
      type: mongoose.Types.Decimal128,
      required: true,
      min: 0,
    },
    currentValue: {
      type: mongoose.Types.Decimal128,
      required: true,
      min: 0,
    },
    currency: {
      type: String,
      required: true,
      default: 'USD',
    },
    acquisitionDate: {
      type: Date,
      required: true,
      default: Date.now,
    },
    status: {
      type: String,
      enum: ['active', 'acquired', 'integrated', 'optimized'],
      default: 'active',
    },
    strategicValue: {
      type: String,
      maxlength: 500,
    },
feedsWorldPopulation: {
      type: mongoose.Types.Decimal128,
      default: 0,
    },
    aiOptimized: {
      type: Boolean,
      default: false,
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    audit: {
      acquiredBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
      },
    },
  },
  {
    timestamps: true,
  }
);

foodSupplyChainSchema.index({ tenantId: 1, type: 1 });
foodSupplyChainSchema.index({ tenantId: 1, status: 1 });

foodSupplyChainSchema.statics = {
  getByTenant: function (tenantId) {
    return this.find({ tenantId }).sort({ acquisitionDate: -1 });
  },
  getPortfolioAnalytics: async function (tenantId) {
    const chains = await this.find({ tenantId });
    const totalValue = chains.reduce(
      (sum, chain) => sum + Number(chain.currentValue),
      0
    );
    return { totalChains: chains.length, totalValue };
  },
};

export default mongoose.model('FoodSupplyChain', foodSupplyChainSchema);
