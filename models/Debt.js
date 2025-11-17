import mongoose from 'mongoose';

const debtSchema = new mongoose.Schema({
  tenantId: {
    type: String,
    required: true,
    index: true
  },
  debtId: {
    type: String,
    required: true,
    index: true
  },
  entity: {
    type: String,
    required: true
  },
  entityType: {
    type: String,
    required: true,
    enum: ['sovereign', 'institutional', 'corporate', 'municipal']
  },
  country: {
    type: String,
    required: true
  },
  debtType: {
    type: String,
    required: true,
    enum: ['sovereign_bonds', 'government_bonds', 'institutional_bonds', 'corporate_bonds', 'municipal_bonds']
  },
  faceValue: {
    type: mongoose.Decimal128,
    required: true,
    min: 0
  },
  acquiredValue: {
    type: mongoose.Decimal128,
    required: true,
    min: 0
  },
  currentValue: {
    type: mongoose.Decimal128,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    required: true,
    default: 'USD',
    enum: ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF']
  },
  maturityDate: {
    type: Date,
    required: true
  },
  acquisitionDate: {
    type: Date,
    required: true,
    default: Date.now
  },
  interestRate: {
    type: mongoose.Decimal128,
    required: true,
    min: 0
  },
  expectedYield: {
    type: mongoose.Decimal128,
    required: true,
    min: 0
  },
  status: {
    type: String,
    required: true,
    enum: ['active', 'matured', 'defaulted', 'called', 'exchanged'],
    default: 'active'
  },
  riskRating: {
    type: String,
    required: true,
    enum: ['AAA', 'AA+', 'AA', 'AA-', 'A+', 'A', 'A-', 'BBB+', 'BBB', 'BBB-', 'BB+', 'BB', 'BB-', 'B+', 'B', 'B-', 'CCC+', 'CCC', 'CCC-', 'CC', 'C', 'D']
  },
  strategicValue: {
    type: String,
    maxlength: 500
  },
  collateral: {
    type: String,
    maxlength: 500
  },
  paymentSchedule: {
    type: String,
    enum: ['annual', 'semi-annual', 'quarterly', 'monthly'],
    default: 'semi-annual'
  },
  covenants: [{
    type: String,
    maxlength: 200
  }],
  discount: {
    type: String,
    maxlength: 20
  },
  acquisitionId: {
    type: String,
    required: true,
    index: true
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  audit: {
    acquiredBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    lastValuationBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    ipAddress: String,
    userAgent: String
  },
  risk: {
    score: { type: Number, min: 0, max: 100 },
    flags: [String],
    lastAssessment: Date,
    nextAssessment: Date
  },
  valuations: [{
    date: { type: Date, default: Date.now },
    value: mongoose.Decimal128,
    change: mongoose.Decimal128,
    changePercent: mongoose.Decimal128,
    marketPrice: mongoose.Decimal128,
    interestRate: mongoose.Decimal128,
    riskRating: String,
    assessedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }],
  cashflows: [{
    date: Date,
    amount: mongoose.Decimal128,
    type: {
      type: String,
      enum: ['interest', 'principal', 'fee']
    },
    status: {
      type: String,
      enum: ['scheduled', 'paid', 'missed', 'defaulted'],
      default: 'scheduled'
    }
  }],
  notifications: [{
    type: {
      type: String,
      enum: ['maturity_warning', 'payment_due', 'risk_change', 'valuation_update']
    },
    message: String,
    priority: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium'
    },
    sentAt: Date,
    acknowledgedAt: Date
  }]
}, {
  timestamps: true
});

// Indexes for performance
debtSchema.index({ tenantId: 1, 'audit.acquiredBy': 1 });
debtSchema.index({ tenantId: 1, status: 1 });
debtSchema.index({ tenantId: 1, entityType: 1 });
debtSchema.index({ tenantId: 1, debtType: 1 });
debtSchema.index({ tenantId: 1, riskRating: 1 });
debtSchema.index({ tenantId: 1, maturityDate: 1 });
debtSchema.index({ tenantId: 1, acquisitionDate: -1 });
debtSchema.index({ tenantId: 1, acquisitionId: 1 }, { unique: true });
debtSchema.index({ tenantId: 1, debtId: 1 }, { unique: true });

// Virtual for unrealized gain/loss
debtSchema.virtual('unrealizedGainLoss').get(function() {
  const current = parseFloat(this.currentValue.toString());
  const acquired = parseFloat(this.acquiredValue.toString());
  return current - acquired;
});

// Virtual for unrealized gain/loss percentage
debtSchema.virtual('unrealizedGainLossPercent').get(function() {
  const acquired = parseFloat(this.acquiredValue.toString());
  if (acquired === 0) return 0;
  return ((this.unrealizedGainLoss / acquired) * 100);
});

// Virtual for time to maturity
debtSchema.virtual('timeToMaturity').get(function() {
  const maturity = new Date(this.maturityDate);
  const now = new Date();
  return Math.max(0, Math.ceil((maturity - now) / (1000 * 60 * 60 * 24)));
});

// Virtual for yield to maturity
debtSchema.virtual('yieldToMaturity').get(function() {
  // Simplified YTM calculation
  const face = parseFloat(this.faceValue.toString());
  const current = parseFloat(this.currentValue.toString());
  const coupon = parseFloat(this.interestRate.toString());
  const years = this.timeToMaturity / 365;

  if (years === 0) return 0;

  // Approximate YTM using current yield
  return ((face - current) / current) / years + coupon;
});

// Instance methods
debtSchema.methods = {
  // Update valuation
  updateValuation: function(newValue, assessedBy, marketData = {}) {
    const oldValue = parseFloat(this.currentValue.toString());
    const change = newValue - oldValue;
    const changePercent = oldValue > 0 ? (change / oldValue) * 100 : 0;

    this.currentValue = newValue;
    this.valuations.push({
      value: newValue,
      change: change,
      changePercent: changePercent,
      marketPrice: marketData.marketPrice || newValue,
      interestRate: marketData.interestRate || this.interestRate,
      riskRating: marketData.riskRating || this.riskRating,
      assessedBy: assessedBy
    });

    if (marketData.interestRate) {
      this.interestRate = marketData.interestRate;
    }
    if (marketData.riskRating) {
      this.riskRating = marketData.riskRating;
    }

    this.audit.lastValuationBy = assessedBy;
    return this.save();
  },

  // Mark as matured
  markMatured: function() {
    this.status = 'matured';
    return this.save();
  },

  // Mark as defaulted
  markDefaulted: function(reason) {
    this.status = 'defaulted';
    this.metadata.defaultReason = reason;
    this.metadata.defaultDate = new Date();
    return this.save();
  },

  // Add cashflow
  addCashflow: function(date, amount, type) {
    this.cashflows.push({
      date: date,
      amount: amount,
      type: type,
      status: 'scheduled'
    });
    return this.save();
  },

  // Mark cashflow as paid
  markCashflowPaid: function(cashflowId) {
    const cashflow = this.cashflows.id(cashflowId);
    if (cashflow) {
      cashflow.status = 'paid';
      return this.save();
    }
    return Promise.reject(new Error('Cashflow not found'));
  },

  // Add notification
  addNotification: function(type, message, priority = 'medium') {
    this.notifications.push({
      type,
      message,
      priority,
      sentAt: new Date()
    });
    return this.save();
  },

  // Get public debt data
  toPublicJSON: function() {
    return {
      debtId: this.debtId,
      entity: this.entity,
      entityType: this.entityType,
      country: this.country,
      debtType: this.debtType,
      faceValue: this.faceValue,
      acquiredValue: this.acquiredValue,
      currentValue: this.currentValue,
      currency: this.currency,
      maturityDate: this.maturityDate,
      interestRate: this.interestRate,
      expectedYield: this.expectedYield,
      status: this.status,
      riskRating: this.riskRating,
      strategicValue: this.strategicValue,
      timeToMaturity: this.timeToMaturity,
      unrealizedGainLoss: this.unrealizedGainLoss,
      unrealizedGainLossPercent: this.unrealizedGainLossPercent,
      yieldToMaturity: this.yieldToMaturity
    };
  }
};

// Static methods
debtSchema.statics = {
  // Get debts by tenant
  getByTenant: function(tenantId, limit = 100, skip = 0) {
    return this.find({ tenantId })
      .sort({ acquisitionDate: -1 })
      .limit(limit)
      .skip(skip)
      .populate('audit.acquiredBy', 'username firstName lastName')
      .populate('audit.approvedBy', 'username firstName lastName');
  },

  // Get debts by status within tenant
  getByStatus: function(status, tenantId, limit = 100) {
    return this.find({ tenantId, status })
      .sort({ acquisitionDate: -1 })
      .limit(limit);
  },

  // Get debts by entity type within tenant
  getByEntityType: function(entityType, tenantId, limit = 100) {
    return this.find({ tenantId, entityType })
      .sort({ acquisitionDate: -1 })
      .limit(limit);
  },

  // Get debts by risk rating within tenant
  getByRiskRating: function(riskRating, tenantId, limit = 100) {
    return this.find({ tenantId, riskRating })
      .sort({ acquisitionDate: -1 })
      .limit(limit);
  },

  // Get maturing debts within tenant
  getMaturingSoon: function(days = 90, tenantId) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() + days);

    return this.find({
      tenantId,
      maturityDate: { $lte: cutoffDate },
      status: 'active'
    }).sort({ maturityDate: 1 });
  },

  // Get high-risk debts within tenant
  getHighRisk: function(riskThreshold = 50, tenantId) {
    return this.find({
      tenantId,
      'risk.score': { $gte: riskThreshold },
      status: 'active'
    }).sort({ 'risk.score': -1 });
  },

  // Get debt portfolio analytics within tenant
  getPortfolioAnalytics: async function(tenantId) {
    const debts = await this.find({ tenantId, status: 'active' });

    const totalAcquiredValue = debts.reduce((sum, debt) =>
      sum + parseFloat(debt.acquiredValue.toString()), 0);

    const totalCurrentValue = debts.reduce((sum, debt) =>
      sum + parseFloat(debt.currentValue.toString()), 0);

    const totalUnrealizedGainLoss = totalCurrentValue - totalAcquiredValue;

    const weightedYield = debts.reduce((sum, debt) => {
      const weight = parseFloat(debt.acquiredValue.toString()) / totalAcquiredValue;
      return sum + (parseFloat(debt.expectedYield.toString()) * weight);
    }, 0);

    // Geographic distribution
    const geographicDistribution = {};
    debts.forEach(debt => {
      if (!geographicDistribution[debt.country]) {
        geographicDistribution[debt.country] = { value: 0, count: 0 };
      }
      geographicDistribution[debt.country].value += parseFloat(debt.acquiredValue.toString());
      geographicDistribution[debt.country].count += 1;
    });

    // Entity type distribution
    const entityTypeDistribution = {};
    debts.forEach(debt => {
      if (!entityTypeDistribution[debt.entityType]) {
        entityTypeDistribution[debt.entityType] = { value: 0, count: 0 };
      }
      entityTypeDistribution[debt.entityType].value += parseFloat(debt.acquiredValue.toString());
      entityTypeDistribution[debt.entityType].count += 1;
    });

    return {
      totalDebts: debts.length,
      totalAcquiredValue,
      totalCurrentValue,
      totalUnrealizedGainLoss,
      averageYield: weightedYield,
      geographicDistribution,
      entityTypeDistribution,
      lastUpdated: new Date()
    };
  }
};

export default mongoose.model('Debt', debtSchema);
