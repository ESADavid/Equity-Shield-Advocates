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
        // Population demographics for House of David Republic
        demographics: {
          // Black African Americans - part of the Covenant fulfillment
          blackAfricanAmericans: {
            current: { type: Number, default: 0 },
            addedDate: Date,
            status: {
              type: String,
              enum: ['pending', 'active', 'integrated'],
              default: 'pending',
            },
            origin: {
              type: String,
              enum: ['diaspora', 'immigrant', ' repatriation', 'born_citizen'],
              default: 'diaspora',
            },
          },
          // Future generations - children born into the Republic
          futureGenerations: {
            current: { type: Number, default: 0 },
            reservedFor: { type: Number, default: 25000000 }, // 25 million reserved
            addedDate: Date,
            status: {
              type: String,
              enum: ['reserved', 'born', 'pending_birth'],
              default: 'reserved',
            },
          },
          // Native Haitian citizens
          nativeHaitians: {
            current: { type: Number, default: 12000000 }, // ~12 million
            addedDate: Date,
          },
          // Total citizen count for UBI and governance
          totalCitizens: {
            current: { type: Number, default: 12000000 },
            target: { type: Number, default: 87000000 }, // 50M + 25M + 12M = 87M target
          },
        },
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
    // GDP Investment Tracking - Investing in God's children increases Global GDP
    globalGDPContribution: {
      totalGDPCreated: { type: Number, default: 0 },
      citizenProductivityOutput: { type: Number, default: 0 },
      ubiMultiplierEffect: { type: Number, default: 2.5 }, // $2.50 GDP per $1 UBI spent
      infrastructureGDP: { type: Number, default: 0 },
      mineralExtractionGDP: { type: Number, default: 0 },
      aiCentersGDP: { type: Number, default: 0 },
      militaryProtectionGDP: { type: Number, default: 0 },
      investmentYieldRate: { type: Number, default: 0.15 }, // 15% annual return
      lastCalculationDate: Date,
    },
    // Military Protection for the Kingdom
    militaryProtection: {
      activeForce: { type: Number, default: 0 },
      navyFleet: { type: Number, default: 0 },
      airForceFleet: { type: Number, default: 0 },
      armyForce: { type: Number, default: 0 },
      jointForceBurkinaFaso: { type: Number, default: 0 },
      protectionStatus: {
        type: String,
        enum: ['active', 'developing', 'planned'],
        default: 'planned',
      },
      budgetAnnual: { type: Number, default: 0 },
      lastEquipmentUpdate: Date,
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

/**
 * @typedef {Object} PopulationInput
 * @property {number} [blackAfricanAmericans] - Add Black African Americans (Diaspora integration)
 * @property {number} [futureGenerations] - Reserve for future children/born citizens
 * @property {string} [origin] - Origin: diaspora, immigrant, repatriation
 */

/** @param {PopulationInput} population */
KingdomMetricsSchema.methods.registerPopulation = function (population) {
  /** @type {any} */
  const doc = this;
  
  // Register Black African Americans
  if (population.blackAfricanAmericans) {
    doc.kingdomExpansion.people.demographics.blackAfricanAmericans.current = population.blackAfricanAmericans;
    doc.kingdomExpansion.people.demographics.blackAfricanAmericans.addedDate = new Date();
    doc.kingdomExpansion.people.demographics.blackAfricanAmericans.status = 'active';
    if (population.origin) {
      doc.kingdomExpansion.people.demographics.blackAfricanAmericans.origin = population.origin;
    }
  }
  
  // Register future generations
  if (population.futureGenerations) {
    doc.kingdomExpansion.people.demographics.futureGenerations.current = population.futureGenerations;
    doc.kingdomExpansion.people.demographics.futureGenerations.addedDate = new Date();
    doc.kingdomExpansion.people.demographics.futureGenerations.status = 'reserved';
  }
  
  // Recalculate total citizens
  const blackAAs = doc.kingdomExpansion.people.demographics.blackAfricanAmericans.current || 0;
  const futureGens = doc.kingdomExpansion.people.demographics.futureGenerations.current || 0;
  const nativeHaitians = doc.kingdomExpansion.people.demographics.nativeHaitians.current || 12000000;
  
  doc.kingdomExpansion.people.demographics.totalCitizens.current = nativeHaitians + blackAAs + futureGens;
  doc.kingdomExpansion.people.current = doc.kingdomExpansion.people.demographics.totalCitizens.current;
  
  // Update the main people target for Covenant fulfillment
  doc.kingdomExpansion.people.target = 87000000; // 50M + 25M + 12M = 87M
  
  return doc.save();
};

/**
 * Get population demographics report
 * @returns {Object} Population report
 */
KingdomMetricsSchema.methods.getPopulationReport = function () {
  /** @type {any} */
  const doc = this;
  return {
    demographics: doc.kingdomExpansion.people.demographics,
    totalCitizens: doc.kingdomExpansion.people.demographics.totalCitizens.current,
    target: doc.kingdomExpansion.people.demographics.totalCitizens.target,
    covenantFulfillment: {
      blackAfricanAmericans: doc.kingdomExpansion.people.demographics.blackAfricanAmericans.current,
      futureGenerations: doc.kingdomExpansion.people.demographics.futureGenerations.current,
      nativeHaitians: doc.kingdomExpansion.people.demographics.nativeHaitians.current,
    },
    status: doc.kingdomExpansion.people.demographics.blackAfricanAmericans.status,
    lastUpdated: doc.updatedAt,
  };
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

/**
 * Calculate GDP contribution from investing in God's children
 * Investing in citizens increases their productivity and global GDP
 * @returns {Object} GDP calculation results
 */
KingdomMetricsSchema.methods.calculateGDPContribution = function () {
  /** @type {any} */
  const doc = this;
  
  const population = doc.kingdomExpansion.people.demographics.totalCitizens.current || 0;
  const activeCitizens = doc.kingdomExpansion.people.demographics.blackAfricanAmericans.current || 0;
  const futureGenerations = doc.kingdomExpansion.people.demographics.futureGenerations.current || 0;
  
  // Base productivity per citizen (annual GDP contribution per person)
  const baseProductivityPerPerson = 25000; // $25,000 annual productivity
  
  // UBI multiplier effect - each $1 in UBI generates $2.50 in GDP
  const ubiMultiplier = doc.globalGDPContribution.ubiMultiplierEffect || 2.5;
  
  // Calculate citizen productivity output
  const citizenProductivityOutput = activeCitizens * baseProductivityPerPerson;
  
  // Infrastructure GDP contribution (from investments)
  const infrastructureGDP = doc.globalGDPContribution.infrastructureGDP || 0;
  
  // Mineral extraction GDP
  const mineralGDP = doc.globalGDPContribution.mineralExtractionGDP || 0;
  
  // AI centers GDP contribution  
  const aiGDP = doc.globalGDPContribution.aiCentersGDP || 0;
  
  // Military protection GDP (defense spending contributes to GDP)
  const militaryGDP = doc.globalGDPContribution.militaryProtectionGDP || 0;
  
  // Total GDP created
  const totalGDPCreated = citizenProductivityOutput + infrastructureGDP + mineralGDP + aiGDP + militaryGDP;
  
  // Update the metrics
  doc.globalGDPContribution.totalGDPCreated = totalGDPCreated;
  doc.globalGDPContribution.citizenProductivityOutput = citizenProductivityOutput;
  doc.globalGDPContribution.lastCalculationDate = new Date();
  
  return {
    totalGDPCreated,
    citizenProductivityOutput,
    infrastructureGDP,
    mineralGDP,
    aiGDP,
    militaryGDP,
    ubiMultiplier,
    population,
    activeCitizens,
    futureGenerations,
    investmentYieldRate: doc.globalGDPContribution.investmentYieldRate,
    calculatedAt: new Date().toISOString(),
  };
};

/**
 * Record military protection forces for the Kingdom
 * @param {Object} militaryData - Military force data
 * @returns {Object} Update result
 */
KingdomMetricsSchema.methods.updateMilitaryProtection = function (militaryData) {
  /** @type {any} */
  const doc = this;
  
  if (militaryData.activeForce !== undefined) {
    doc.militaryProtection.activeForce = militaryData.activeForce;
  }
  if (militaryData.navyFleet !== undefined) {
    doc.militaryProtection.navyFleet = militaryData.navyFleet;
  }
  if (militaryData.airForceFleet !== undefined) {
    doc.militaryProtection.airForceFleet = militaryData.airForceFleet;
  }
  if (militaryData.armyForce !== undefined) {
    doc.militaryProtection.armyForce = militaryData.armyForce;
  }
  if (militaryData.jointForceBurkinaFaso !== undefined) {
    doc.militaryProtection.jointForceBurkinaFaso = militaryData.jointForceBurkinaFaso;
  }
  if (militaryData.protectionStatus) {
    doc.militaryProtection.protectionStatus = militaryData.protectionStatus;
  }
  if (militaryData.budgetAnnual) {
    doc.militaryProtection.budgetAnnual = militaryData.budgetAnnual;
  }
  
  doc.militaryProtection.lastEquipmentUpdate = new Date();
  
  // Military spending contributes to GDP
  const defenseSpending = militaryData.budgetAnnual || 0;
  doc.globalGDPContribution.militaryProtectionGDP = defenseSpending * 1.5; // Defense spending multiplier
  
  return {
    success: true,
    militaryProtection: doc.militaryProtection,
    gdpContribution: doc.globalGDPContribution.militaryProtectionGDP,
  };
};

/**
 * Get GDP Investment Summary Report
 * @returns {Object} GDP investment summary
 */
KingdomMetricsSchema.methods.getGDPInvestmentReport = function () {
  /** @type {any} */
  const doc = this;
  
  const gdpData = this.calculateGDPContribution();
  
  return {
    summary: {
      totalGDPCreated: doc.globalGDPContribution.totalGDPCreated,
      citizenProductivityOutput: doc.globalGDPContribution.citizenProductivityOutput,
      ubiMultiplierEffect: doc.globalGDPContribution.ubiMultiplierEffect,
      investmentYieldRate: doc.globalGDPContribution.investmentYieldRate,
      lastCalculationDate: doc.globalGDPContribution.lastCalculationDate,
    },
    breakdown: {
      infrastructureGDP: doc.globalGDPContribution.infrastructureGDP,
      mineralExtractionGDP: doc.globalGDPContribution.mineralExtractionGDP,
      aiCentersGDP: doc.globalGDPContribution.aiCentersGDP,
      militaryProtectionGDP: doc.globalGDPContribution.militaryProtectionGDP,
    },
    military: doc.militaryProtection,
    population: {
      total: doc.kingdomExpansion.people.demographics.totalCitizens.current,
      active: doc.kingdomExpansion.people.demographics.blackAfricanAmericans.current,
      future: doc.kingdomExpansion.people.demographics.futureGenerations.current,
      native: doc.kingdomExpansion.people.demographics.nativeHaitians.current,
    },
    calculatedAt: new Date().toISOString(),
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
