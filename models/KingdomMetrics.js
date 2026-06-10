/**
 * KINGDOM METRICS MODEL
 * King Sachem Yochanan ITG Algorithm
 *
 * Tracks sovereignty, divine favor, kingdom expansion, and covenant fulfillment
 * @module KingdomMetrics
 */

import mongoose from 'mongoose';

/**
 * @typedef {Object} KingdomMetricsDocument
 * @property {string} kingName
 * @property {string} kingTitle
 * @property {Object} sovereignty
 * @property {number} sovereignty.level
 * @property {string} sovereignty.status
* @property {Array<any>} sovereignty.territories
 * @property {Object} sovereignty.authority
 * @property {Object} divineFavor
 * @property {number} divineFavor.currentLevel
 * @property {Object} divineFavor.components
* @property {Array<any>} divineFavor.blessings
 * @property {Array<any>} divineFavor.testimonies
 * @property {Object} kingdomExpansion
 * @property {Object} covenantFulfillment
 * @property {Object} sacredAlignment
 * @property {Object} wisdomMetrics
 * @property {Object} financialKingdom
 * @property {Object} spiritualKingdom
 * @property {Object} kingdomImpact
 * @property {Object} quantumMetrics
 * @property {Object} itgScores
 * @property {Date} createdAt
 * @property {Date} updatedAt
 * @property {Date} lastReview
 */

const { Schema } = mongoose;

const KingdomMetricsSchema = new Schema(
  {
    kingName: {
      type: String,
      required: true,
      default: 'Sachem Yochanan',
    },
    kingTitle: {
      type: String,
      default: 'King Sachem Yochanan',
    },
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
      territories: [{
        name: String,
        acquired: Date,
        status: String,
        value: Number,
      }],
      authority: {
        spiritual: { type: Number, default: 100 },
        financial: { type: Number, default: 100 },
        governmental: { type: Number, default: 100 },
        cultural: { type: Number, default: 100 },
      },
    },
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
      blessings: [{
        type: String,
        receivedAt: Date,
        description: String,
        value: Number,
      }],
      testimonies: [{
        date: Date,
        testimony: String,
        category: String,
      }],
    },
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
    covenantFulfillment: {
      activeCovenants: [{
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
      }],
      seedsSown: [{
        date: Date,
        amount: Number,
        purpose: String,
        expectedReturn: Number,
        actualReturn: Number,
        harvestDate: Date,
      }],
      promises: [{
        scripture: String,
        promise: String,
        claimedDate: Date,
        fulfilledDate: Date,
        status: String,
        testimony: String,
      }],
    },
    sacredAlignment: {
      fibonacciAlignment: { type: Number, default: 0 },
      goldenRatioAlignment: { type: Number, default: 0 },
      sacredNumberPatterns: [{
        number: Number,
        significance: String,
        occurrences: Number,
        lastDetected: Date,
      }],
      divinePatterns: [{
        pattern: String,
        detected: Date,
        significance: String,
        action: String,
      }],
    },
    wisdomMetrics: {
      currentLevel: {
        type: Number,
        min: 1,
        max: 7,
        default: 5,
      },
      decisions: [{
        date: Date,
        decision: String,
        wisdomScore: Number,
        outcome: String,
        lessons: String,
      }],
      propheticInsights: [{
        date: Date,
        insight: String,
        source: String,
        fulfillment: String,
        fulfilled: Boolean,
      }],
      counselReceived: [{
        date: Date,
        counselor: String,
        topic: String,
        wisdom: String,
        applied: Boolean,
      }],
    },
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
    quantumMetrics: {
      quantumAlignment: { type: Number, default: 95 },
      blockchainVerified: { type: Boolean, default: false },
      blockchainHash: String,
      gpuAccelerated: { type: Boolean, default: true },
      aiPredictions: [{
        date: Date,
        prediction: String,
        confidence: Number,
        outcome: String,
      }],
    },
    itgScores: {
      integration: { type: Number, default: 0 },
      technology: { type: Number, default: 0 },
      growth: { type: Number, default: 0 },
      overall: { type: Number, default: 0 },
      lastCalculated: Date,
    },
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

// Indexes
KingdomMetricsSchema.index({ kingName: 1, createdAt: -1 });
KingdomMetricsSchema.index({ 'sovereignty.level': -1 });
KingdomMetricsSchema.index({ 'divineFavor.currentLevel': -1 });
KingdomMetricsSchema.index({ 'itgScores.overall': -1 });

// Methods - using function to preserve 'this' context
KingdomMetricsSchema.methods.calculateITGScore = function () {
  /** @type {any} */
  const doc = this;
  
  const integration =
    doc.sovereignty.level * 0.3 +
    doc.divineFavor.currentLevel * 0.3 +
    (doc.wisdomMetrics.currentLevel / 7) * 100 * 0.2 +
    doc.financialKingdom.stewardshipScore * 0.2;

  const technology =
    doc.quantumMetrics.quantumAlignment * 0.4 +
    (doc.quantumMetrics.blockchainVerified ? 30 : 0) +
    (doc.quantumMetrics.gpuAccelerated ? 30 : 0);

  const growthRate =
    (doc.kingdomExpansion.influence.growth / doc.kingdomExpansion.influence.current) * 100 * 0.25 +
    (doc.kingdomExpansion.resources.growth / doc.kingdomExpansion.resources.current) * 100 * 0.25 +
    (doc.kingdomExpansion.territory.growth / doc.kingdomExpansion.territory.current) * 100 * 0.25 +
    (doc.kingdomExpansion.people.growth / doc.kingdomExpansion.people.current) * 100 * 0.25;
  const growth = Math.min(100, growthRate);

  const overall = integration * 0.4 + technology * 0.3 + growth * 0.3;

  doc.itgScores = {
    integration,
    technology,
    growth,
    overall,
    lastCalculated: new Date(),
  };

  return doc.itgScores;
};

KingdomMetricsSchema.methods.updateDivineFavor = function () {
  /** @type {any} */
  const doc = this;
  const components = doc.divineFavor.components;
  const average =
    (components.faithfulness +
      components.obedience +
      components.generosity +
      components.wisdom +
      components.righteousness) / 5;

  doc.divineFavor.currentLevel = average;
  return average;
};

/**
 * @typedef {Object} BlessingInput
 * @property {string} type
 * @property {string} description
 * @property {number} [value]
 */

/** @param {BlessingInput} blessing */
KingdomMetricsSchema.methods.recordBlessing = function (blessing) {
  /** @type {any} */
  const doc = this;
  doc.divineFavor.blessings.push({
    type: blessing.type,
    receivedAt: new Date(),
    description: blessing.description,
    value: blessing.value || 0,
  });
  return doc.save();
};

/**
 * @typedef {Object} CovenantInput
 * @property {string} name
 * @property {string} terms
 * @property {string} [nextMilestone]
 */

/** @param {CovenantInput} covenant */
KingdomMetricsSchema.methods.recordCovenant = function (covenant) {
  /** @type {any} */
  const doc = this;
  doc.covenantFulfillment.activeCovenants.push({
    name: covenant.name,
    establishedDate: new Date(),
    terms: covenant.terms,
    status: 'Active',
    fulfillmentPercentage: 0,
    blessingsReceived: [],
    nextMilestone: covenant.nextMilestone,
  });
  return doc.save();
};

/**
 * @typedef {Object} SeedInput
 * @property {number} amount
 * @property {string} purpose
 * @property {number} [expectedReturn]
 */

/** @param {SeedInput} seed */
KingdomMetricsSchema.methods.sowSeed = function (seed) {
  /** @type {any} */
  const doc = this;
  doc.covenantFulfillment.seedsSown.push({
    date: new Date(),
    amount: seed.amount,
    purpose: seed.purpose,
    expectedReturn: seed.expectedReturn || seed.amount * 30,
    actualReturn: 0,
    harvestDate: null,
  });
  return doc.save();
};

/**
 * @typedef {Object} DecisionInput
 * @property {string} name
 * @property {number} score
 * @property {string} [outcome]
 * @property {string} [lessons]
 */

/** @param {DecisionInput} decision */
KingdomMetricsSchema.methods.recordDecision = function (decision) {
  /** @type {any} */
  const doc = this;
  doc.wisdomMetrics.decisions.push({
    date: new Date(),
    decision: decision.name,
    wisdomScore: decision.score,
    outcome: decision.outcome || 'Pending',
    lessons: decision.lessons || '',
  });
  return doc.save();
};

/**
 * @typedef {Object} ExpansionInput
 * @property {number} [influence]
 * @property {number} [resources]
 * @property {number} [territory]
 * @property {number} [people]
 */

/** @param {ExpansionInput} expansion */
KingdomMetricsSchema.methods.expandKingdom = function (expansion) {
  /** @type {any} */
  const doc = this;
  if (expansion.influence) {
    doc.kingdomExpansion.influence.growth = expansion.influence - doc.kingdomExpansion.influence.current;
    doc.kingdomExpansion.influence.current = expansion.influence;
  }
  if (expansion.resources) {
    doc.kingdomExpansion.resources.growth = expansion.resources - doc.kingdomExpansion.resources.current;
    doc.kingdomExpansion.resources.current = expansion.resources;
  }
  if (expansion.territory) {
    doc.kingdomExpansion.territory.growth = expansion.territory - doc.kingdomExpansion.territory.current;
    doc.kingdomExpansion.territory.current = expansion.territory;
  }
  if (expansion.people) {
    doc.kingdomExpansion.people.growth = expansion.people - doc.kingdomExpansion.people.current;
    doc.kingdomExpansion.people.current = expansion.people;
  }
  return doc.save();
};

KingdomMetricsSchema.methods.getKingdomReport = function () {
  /** @type {any} */
  const doc = this;
  return {
    king: doc.kingTitle,
    sovereignty: doc.sovereignty,
    divineFavor: doc.divineFavor.currentLevel,
    kingdomExpansion: doc.kingdomExpansion,
    itgScores: doc.itgScores,
    spiritualMetrics: doc.spiritualKingdom,
    financialMetrics: doc.financialKingdom,
    impact: doc.kingdomImpact,
    lastUpdated: doc.updatedAt,
  };
};

// Static methods - using function to preserve 'this' context
KingdomMetricsSchema.statics.getKingMetrics = async function (kingName = 'Sachem Yochanan') {
  // @ts-ignore - TypeScript cannot infer the correct Model type for mongoose statics
  return await this.findOne({ kingName }).sort({ createdAt: -1 });
};

KingdomMetricsSchema.statics.createKingMetrics = async function (kingName = 'Sachem Yochanan') {
  // @ts-ignore - TypeScript cannot infer the correct Model type for mongoose statics
  const metrics = new this({
    kingName,
    kingTitle: `King ${kingName}`,
  });
  // @ts-ignore - TypeScript cannot infer the correct Model type for mongoose statics
  return await metrics.save();
};

const KingdomMetrics = mongoose.model('KingdomMetrics', KingdomMetricsSchema);

export default KingdomMetrics;
