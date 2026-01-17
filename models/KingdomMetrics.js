/**
 * KINGDOM METRICS MODEL
 * King Sachem Yochanan ITG Algorithm
 *
 * Tracks sovereignty, divine favor, kingdom expansion, and covenant fulfillment
 */

import mongoose from 'mongoose';

const KingdomMetricsSchema = new mongoose.Schema(
  {
    // King Identity
    kingName: {
      type: String,
      required: true,
      default: 'Sachem Yochanan',
    },

    kingTitle: {
      type: String,
      default: 'King Sachem Yochanan',
    },

    // Sovereignty Tracking
    sovereignty: {
      level: {
        type: Number,
        min: 0,
        max: 100,
        default: 100,
      },
      status: {
        type: String,
        enum: ['Established', 'Growing', 'Challenged', 'Victorious'],
        default: 'Established',
      },
      territories: [
        {
          name: String,
          acquired: Date,
          status: String,
          value: Number,
        },
      ],
      authority: {
        spiritual: { type: Number, default: 100 },
        financial: { type: Number, default: 100 },
        governmental: { type: Number, default: 100 },
        cultural: { type: Number, default: 100 },
      },
    },

    // Divine Favor Measurements
    divineFavor: {
      currentLevel: {
        type: Number,
        min: 0,
        max: 100,
        default: 85,
      },
      components: {
        faithfulness: { type: Number, default: 85 },
        obedience: { type: Number, default: 80 },
        generosity: { type: Number, default: 75 },
        wisdom: { type: Number, default: 90 },
        righteousness: { type: Number, default: 88 },
      },
      blessings: [
        {
          type: String,
          receivedAt: Date,
          description: String,
          value: Number,
        },
      ],
      testimonies: [
        {
          date: Date,
          testimony: String,
          category: String,
        },
      ],
    },

    // Kingdom Expansion Metrics
    kingdomExpansion: {
      influence: {
        current: { type: Number, default: 1000 },
        growth: { type: Number, default: 0 },
        target: { type: Number, default: 10000 },
      },
      resources: {
        current: { type: Number, default: 10000 },
        growth: { type: Number, default: 0 },
        target: { type: Number, default: 100000 },
      },
      territory: {
        current: { type: Number, default: 100 },
        growth: { type: Number, default: 0 },
        target: { type: Number, default: 1000 },
      },
      people: {
        current: { type: Number, default: 100 },
        growth: { type: Number, default: 0 },
        target: { type: Number, default: 10000 },
      },
    },

    // Covenant Fulfillment Tracking
    covenantFulfillment: {
      activeCovenants: [
        {
          name: String,
          establishedDate: Date,
          terms: String,
          status: {
            type: String,
            enum: ['Active', 'Fulfilled', 'In Progress', 'Pending'],
            default: 'Active',
          },
          fulfillmentPercentage: { type: Number, default: 0 },
          blessingsReceived: [String],
          nextMilestone: String,
        },
      ],
      seedsSown: [
        {
          date: Date,
          amount: Number,
          purpose: String,
          expectedReturn: Number,
          actualReturn: Number,
          harvestDate: Date,
        },
      ],
      promises: [
        {
          scripture: String,
          promise: String,
          claimedDate: Date,
          fulfilledDate: Date,
          status: String,
          testimony: String,
        },
      ],
    },

    // Sacred Geometry Alignment
    sacredAlignment: {
      fibonacciAlignment: { type: Number, default: 0 },
      goldenRatioAlignment: { type: Number, default: 0 },
      sacredNumberPatterns: [
        {
          number: Number,
          significance: String,
          occurrences: Number,
          lastDetected: Date,
        },
      ],
      divinePatterns: [
        {
          pattern: String,
          detected: Date,
          significance: String,
          action: String,
        },
      ],
    },

    // Wisdom and Decision Metrics
    wisdomMetrics: {
      currentLevel: {
        type: Number,
        min: 1,
        max: 7,
        default: 5,
      },
      decisions: [
        {
          date: Date,
          decision: String,
          wisdomScore: Number,
          outcome: String,
          lessons: String,
        },
      ],
      propheticInsights: [
        {
          date: Date,
          insight: String,
          source: String,
          fulfillment: String,
          fulfilled: Boolean,
        },
      ],
      counselReceived: [
        {
          date: Date,
          counselor: String,
          topic: String,
          wisdom: String,
          applied: Boolean,
        },
      ],
    },

    // Financial Kingdom Metrics
    financialKingdom: {
      totalAssets: { type: Number, default: 0 },
      monthlyRevenue: { type: Number, default: 0 },
      monthlyGiving: { type: Number, default: 0 },
      investmentReturns: { type: Number, default: 0 },
      debtFree: { type: Boolean, default: true },
      financialFreedom: { type: Number, default: 100 },
      stewardshipScore: { type: Number, default: 85 },
      generosityIndex: { type: Number, default: 80 },
    },

    // Spiritual Kingdom Metrics
    spiritualKingdom: {
      prayerHours: { type: Number, default: 0 },
      fastingDays: { type: Number, default: 0 },
      scriptureStudy: { type: Number, default: 0 },
      worship: { type: Number, default: 0 },
      intercession: { type: Number, default: 0 },
      spiritualWarfare: {
        victories: { type: Number, default: 0 },
        battles: { type: Number, default: 0 },
        strategies: [String],
      },
      anointing: {
        level: { type: Number, default: 85 },
        manifestations: [String],
        gifts: [String],
      },
    },

    // Kingdom Impact Metrics
    kingdomImpact: {
      livesTransformed: { type: Number, default: 0 },
      salvations: { type: Number, default: 0 },
      healings: { type: Number, default: 0 },
      deliverances: { type: Number, default: 0 },
      discipleship: { type: Number, default: 0 },
      churches: { type: Number, default: 0 },
      nations: { type: Number, default: 0 },
      legacy: {
        description: String,
        impact: String,
        generations: Number,
      },
    },

    // Quantum-Enhanced Metrics
    quantumMetrics: {
      quantumAlignment: { type: Number, default: 95 },
      blockchainVerified: { type: Boolean, default: false },
      blockchainHash: String,
      gpuAccelerated: { type: Boolean, default: true },
      aiPredictions: [
        {
          date: Date,
          prediction: String,
          confidence: Number,
          outcome: String,
        },
      ],
    },

    // ITG Algorithm Scores
    itgScores: {
      integration: { type: Number, default: 0 },
      technology: { type: Number, default: 0 },
      growth: { type: Number, default: 0 },
      overall: { type: Number, default: 0 },
      lastCalculated: Date,
    },

    // Timestamps
    createdAt: {
      type: Date,
      default: Date.now,
    },

    updatedAt: {
      type: Date,
      default: Date.now,
    },

    lastReview: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for efficient querying
KingdomMetricsSchema.index({ kingName: 1, createdAt: -1 });
KingdomMetricsSchema.index({ 'sovereignty.level': -1 });
KingdomMetricsSchema.index({ 'divineFavor.currentLevel': -1 });
KingdomMetricsSchema.index({ 'itgScores.overall': -1 });

// Methods
KingdomMetricsSchema.methods.calculateITGScore = function () {
  // Integration Score (0-100)
  const integration =
    this.sovereignty.level * 0.3 +
    this.divineFavor.currentLevel * 0.3 +
    (this.wisdomMetrics.currentLevel / 7) * 100 * 0.2 +
    this.financialKingdom.stewardshipScore * 0.2;

  // Technology Score (0-100)
  const technology =
    this.quantumMetrics.quantumAlignment * 0.4 +
    (this.quantumMetrics.blockchainVerified ? 30 : 0) +
    (this.quantumMetrics.gpuAccelerated ? 30 : 0);

  // Growth Score (0-100)
  const growthRate =
    (this.kingdomExpansion.influence.growth /
      this.kingdomExpansion.influence.current) *
      100 *
      0.25 +
    (this.kingdomExpansion.resources.growth /
      this.kingdomExpansion.resources.current) *
      100 *
      0.25 +
    (this.kingdomExpansion.territory.growth /
      this.kingdomExpansion.territory.current) *
      100 *
      0.25 +
    (this.kingdomExpansion.people.growth /
      this.kingdomExpansion.people.current) *
      100 *
      0.25;
  const growth = Math.min(100, growthRate);

  // Overall ITG Score
  const overall = integration * 0.4 + technology * 0.3 + growth * 0.3;

  this.itgScores = {
    integration,
    technology,
    growth,
    overall,
    lastCalculated: new Date(),
  };

  return this.itgScores;
};

KingdomMetricsSchema.methods.updateDivineFavor = function () {
  const components = this.divineFavor.components;
  const average =
    (components.faithfulness +
      components.obedience +
      components.generosity +
      components.wisdom +
      components.righteousness) /
    5;

  this.divineFavor.currentLevel = average;
  return average;
};

KingdomMetricsSchema.methods.recordBlessing = function (blessing) {
  this.divineFavor.blessings.push({
    type: blessing.type,
    receivedAt: new Date(),
    description: blessing.description,
    value: blessing.value || 0,
  });
  return this.save();
};

KingdomMetricsSchema.methods.recordCovenant = function (covenant) {
  this.covenantFulfillment.activeCovenants.push({
    name: covenant.name,
    establishedDate: new Date(),
    terms: covenant.terms,
    status: 'Active',
    fulfillmentPercentage: 0,
    blessingsReceived: [],
    nextMilestone: covenant.nextMilestone,
  });
  return this.save();
};

KingdomMetricsSchema.methods.sowSeed = function (seed) {
  this.covenantFulfillment.seedsSown.push({
    date: new Date(),
    amount: seed.amount,
    purpose: seed.purpose,
    expectedReturn: seed.expectedReturn || seed.amount * 30,
    actualReturn: 0,
    harvestDate: null,
  });
  return this.save();
};

KingdomMetricsSchema.methods.recordDecision = function (decision) {
  this.wisdomMetrics.decisions.push({
    date: new Date(),
    decision: decision.name,
    wisdomScore: decision.score,
    outcome: decision.outcome || 'Pending',
    lessons: decision.lessons || '',
  });
  return this.save();
};

KingdomMetricsSchema.methods.expandKingdom = function (expansion) {
  if (expansion.influence) {
    this.kingdomExpansion.influence.growth =
      expansion.influence - this.kingdomExpansion.influence.current;
    this.kingdomExpansion.influence.current = expansion.influence;
  }
  if (expansion.resources) {
    this.kingdomExpansion.resources.growth =
      expansion.resources - this.kingdomExpansion.resources.current;
    this.kingdomExpansion.resources.current = expansion.resources;
  }
  if (expansion.territory) {
    this.kingdomExpansion.territory.growth =
      expansion.territory - this.kingdomExpansion.territory.current;
    this.kingdomExpansion.territory.current = expansion.territory;
  }
  if (expansion.people) {
    this.kingdomExpansion.people.growth =
      expansion.people - this.kingdomExpansion.people.current;
    this.kingdomExpansion.people.current = expansion.people;
  }
  return this.save();
};

KingdomMetricsSchema.methods.getKingdomReport = function () {
  return {
    king: this.kingTitle,
    sovereignty: this.sovereignty,
    divineFavor: this.divineFavor.currentLevel,
    kingdomExpansion: this.kingdomExpansion,
    itgScores: this.itgScores,
    spiritualMetrics: this.spiritualKingdom,
    financialMetrics: this.financialKingdom,
    impact: this.kingdomImpact,
    lastUpdated: this.updatedAt,
  };
};

// Static methods
KingdomMetricsSchema.statics.getKingMetrics = async function (
  kingName = 'Sachem Yochanan'
) {
  return await this.findOne({ kingName }).sort({ createdAt: -1 });
};

KingdomMetricsSchema.statics.createKingMetrics = async function (
  kingName = 'Sachem Yochanan'
) {
  const metrics = new this({
    kingName,
    kingTitle: `King ${kingName}`,
  });
  return await metrics.save();
};

const KingdomMetrics = mongoose.model('KingdomMetrics', KingdomMetricsSchema);

export default KingdomMetrics;
