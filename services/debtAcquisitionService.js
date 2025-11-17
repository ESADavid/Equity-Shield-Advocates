/**
 * DEBT ACQUISITION SERVICE
 * Manages the acquisition and management of sovereign and institutional debts
 * Provides comprehensive debt portfolio management and risk assessment
 */

import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class DebtAcquisitionService {
  constructor() {
    this.acquiredDebts = new Map();
    this.debtMarketData = new Map();
    this.acquisitionHistory = new Map();
    this.riskAssessments = new Map();
    this.debtValuations = new Map();
    this.marketIntelligence = new Map();
  }

  /**
   * Initialize debt acquisition portfolio
   * @param {Array} debtPortfolio - Array of acquired debts
   */
  initializeDebtPortfolio(debtPortfolio = []) {
    // Default sovereign debts for acquisition
    const defaultDebts = [
      {
        id: 'vatican-bank-debt',
        entity: 'Vatican Bank (IOR)',
        entityType: 'sovereign',
        country: 'Vatican City',
        debtType: 'sovereign_bonds',
        faceValue: 5000000000, // $5B
        acquiredValue: 4500000000, // $4.5B (10% discount)
        currency: 'EUR',
        maturityDate: '2045-12-31',
        interestRate: 0.025, // 2.5%
        acquisitionDate: '2024-01-15',
        status: 'active',
        riskRating: 'AAA',
        collateral: 'Vatican Assets',
        strategicValue: 'Religious Institution Influence',
        expectedYield: 0.035, // 3.5%
        paymentSchedule: 'semi-annual',
        covenants: ['No default risk', 'Sovereign immunity', 'Religious tax exemptions']
      },
      {
        id: 'catholic-church-debt',
        entity: 'Catholic Church Global Debt',
        entityType: 'institutional',
        country: 'Global',
        debtType: 'institutional_bonds',
        faceValue: 15000000000, // $15B
        acquiredValue: 13500000000, // $13.5B (10% discount)
        currency: 'USD',
        maturityDate: '2050-06-30',
        interestRate: 0.030, // 3.0%
        acquisitionDate: '2024-01-20',
        status: 'active',
        riskRating: 'AA+',
        collateral: 'Church Properties & Assets',
        strategicValue: 'Global Influence Network',
        expectedYield: 0.042, // 4.2%
        paymentSchedule: 'quarterly',
        covenants: ['Faith-based immunity', 'Tax-exempt status', 'Global asset protection']
      },
      {
        id: 'israel-sovereign-debt',
        entity: 'State of Israel',
        entityType: 'sovereign',
        country: 'Israel',
        debtType: 'government_bonds',
        faceValue: 25000000000, // $25B
        acquiredValue: 22500000000, // $22.5B (10% discount)
        currency: 'USD',
        maturityDate: '2040-03-15',
        interestRate: 0.028, // 2.8%
        acquisitionDate: '2024-01-25',
        status: 'active',
        riskRating: 'A+',
        collateral: 'Israeli Government Assets',
        strategicValue: 'Middle East Strategic Position',
        expectedYield: 0.038, // 3.8%
        paymentSchedule: 'semi-annual',
        covenants: ['Government backing', 'Military protection', 'Economic partnerships']
      }
    ];

    const portfolioToInitialize = debtPortfolio.length > 0 ? debtPortfolio : defaultDebts;

    portfolioToInitialize.forEach(debt => {
      this.acquiredDebts.set(debt.id, {
        ...debt,
        lastUpdated: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        acquisitionId: this.generateAcquisitionId()
      });

      // Initialize acquisition history
      this.acquisitionHistory.set(debt.id, []);
      this.riskAssessments.set(debt.id, []);
      this.debtValuations.set(debt.id, []);
    });

    console.log(`Initialized debt portfolio with ${portfolioToInitialize.length} acquired debts`);
  }

  /**
   * Acquire new debt instrument
   * @param {Object} debtData - Debt acquisition details
   * @returns {Object} Acquisition result
   */
  acquireDebt(debtData) {
    const {
      entity,
      entityType,
      country,
      debtType,
      faceValue,
      acquisitionPrice,
      currency = 'USD',
      maturityDate,
      interestRate,
      riskRating,
      strategicValue
    } = debtData;

    // Validate required fields
    if (!entity || !faceValue || !acquisitionPrice || !maturityDate) {
      return {
        success: false,
        error: 'Missing required debt acquisition data'
      };
    }

    const debtId = this.generateDebtId(entity, debtType);
    const discount = ((faceValue - acquisitionPrice) / faceValue) * 100;
    const expectedYield = interestRate + (discount / 100); // Simplified yield calculation

    const newDebt = {
      id: debtId,
      entity,
      entityType: entityType || 'sovereign',
      country: country || 'Global',
      debtType: debtType || 'sovereign_bonds',
      faceValue,
      acquiredValue: acquisitionPrice,
      currency,
      maturityDate,
      interestRate,
      acquisitionDate: new Date().toISOString().split('T')[0],
      status: 'active',
      riskRating: riskRating || 'AA',
      strategicValue: strategicValue || 'Strategic Investment',
      expectedYield,
      discount: discount.toFixed(2) + '%',
      paymentSchedule: 'semi-annual',
      covenants: this.generateDefaultCovenants(entityType),
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      acquisitionId: this.generateAcquisitionId()
    };

    this.acquiredDebts.set(debtId, newDebt);
    this.acquisitionHistory.set(debtId, [{
      timestamp: new Date().toISOString(),
      action: 'acquired',
      details: `Acquired ${this.formatCurrency(acquisitionPrice, currency)} of ${entity} debt`,
      discount: discount.toFixed(2) + '%'
    }]);

    return {
      success: true,
      debt: this.getDebt(debtId),
      message: `Successfully acquired ${this.formatCurrency(acquisitionPrice, currency)} of ${entity} debt`
    };
  }

  /**
   * Get complete debt portfolio
   * @returns {Array} Array of acquired debts
   */
  getDebtPortfolio() {
    return Array.from(this.acquiredDebts.values()).map(debt => ({
      ...debt,
      faceValue: this.formatCurrency(debt.faceValue, debt.currency),
      acquiredValue: this.formatCurrency(debt.acquiredValue, debt.currency),
      currentValue: this.calculateCurrentValue(debt),
      unrealizedGainLoss: this.calculateUnrealizedGainLoss(debt)
    }));
  }

  /**
   * Get specific debt by ID
   * @param {string} debtId - Debt ID
   * @returns {Object|null} Debt object or null
   */
  getDebt(debtId) {
    const debt = this.acquiredDebts.get(debtId);
    if (!debt) return null;

    return {
      ...debt,
      faceValue: this.formatCurrency(debt.faceValue, debt.currency),
      acquiredValue: this.formatCurrency(debt.acquiredValue, debt.currency),
      currentValue: this.calculateCurrentValue(debt),
      unrealizedGainLoss: this.calculateUnrealizedGainLoss(debt)
    };
  }

  /**
   * Update debt valuation and performance
   * @param {string} debtId - Debt ID
   * @param {Object} valuationData - New valuation data
   * @returns {Object} Update result
   */
  updateDebtValuation(debtId, valuationData = {}) {
    const debt = this.acquiredDebts.get(debtId);
    if (!debt) {
      return { success: false, error: 'Debt not found' };
    }

    const oldValue = this.calculateCurrentValue(debt);
    debt.lastUpdated = new Date().toISOString();

    // Update valuation data
    if (valuationData.marketPrice) {
      debt.marketPrice = valuationData.marketPrice;
    }
    if (valuationData.interestRate) {
      debt.interestRate = valuationData.interestRate;
    }
    if (valuationData.riskRating) {
      debt.riskRating = valuationData.riskRating;
    }

    const newValue = this.calculateCurrentValue(debt);
    const change = newValue - oldValue;
    const changePercent = oldValue > 0 ? (change / oldValue) * 100 : 0;

    // Record valuation history
    const history = this.debtValuations.get(debtId) || [];
    history.push({
      timestamp: new Date().toISOString(),
      value: newValue,
      change: change,
      changePercent: changePercent,
      ...valuationData
    });

    // Keep only last 1000 entries
    if (history.length > 1000) {
      this.debtValuations.set(debtId, history.slice(history.length - 1000));
    } else {
      this.debtValuations.set(debtId, history);
    }

    return {
      success: true,
      debt: this.getDebt(debtId),
      oldValue: this.formatCurrency(oldValue, debt.currency),
      newValue: this.formatCurrency(newValue, debt.currency),
      change: this.formatCurrency(change, debt.currency),
      changePercent: changePercent.toFixed(2) + '%'
    };
  }

  /**
   * Get debt portfolio analytics
   * @returns {Object} Portfolio analytics
   */
  getDebtPortfolioAnalytics() {
    const debts = Array.from(this.acquiredDebts.values());
    const totalAcquiredValue = debts.reduce((sum, debt) => sum + debt.acquiredValue, 0);
    const totalCurrentValue = debts.reduce((sum, debt) => sum + this.calculateCurrentValue(debt), 0);
    const totalUnrealizedGainLoss = totalCurrentValue - totalAcquiredValue;

    // Calculate weighted metrics
    const weightedYield = debts.reduce((sum, debt) => {
      const weight = debt.acquiredValue / totalAcquiredValue;
      return sum + (debt.expectedYield * weight);
    }, 0);

    const weightedRisk = this.calculatePortfolioRisk(debts);

    // Geographic diversification
    const geographicDistribution = {};
    debts.forEach(debt => {
      if (!geographicDistribution[debt.country]) {
        geographicDistribution[debt.country] = { value: 0, count: 0 };
      }
      geographicDistribution[debt.country].value += debt.acquiredValue;
      geographicDistribution[debt.country].count += 1;
    });

    // Entity type distribution
    const entityTypeDistribution = {};
    debts.forEach(debt => {
      if (!entityTypeDistribution[debt.entityType]) {
        entityTypeDistribution[debt.entityType] = { value: 0, count: 0 };
      }
      entityTypeDistribution[debt.entityType].value += debt.acquiredValue;
      entityTypeDistribution[debt.entityType].count += 1;
    });

    return {
      summary: {
        totalDebts: debts.length,
        totalAcquiredValue: this.formatCurrency(totalAcquiredValue, 'USD'),
        totalCurrentValue: this.formatCurrency(totalCurrentValue, 'USD'),
        totalUnrealizedGainLoss: this.formatCurrency(totalUnrealizedGainLoss, 'USD'),
        averageYield: (weightedYield * 100).toFixed(2) + '%',
        portfolioRisk: weightedRisk,
        diversificationRatio: this.calculateDiversificationRatio(debts)
      },
      geographicDistribution,
      entityTypeDistribution,
      debts: debts.map(debt => ({
        id: debt.id,
        entity: debt.entity,
        country: debt.country,
        entityType: debt.entityType,
        acquiredValue: this.formatCurrency(debt.acquiredValue, debt.currency),
        currentValue: this.calculateCurrentValue(debt),
        unrealizedGainLoss: this.calculateUnrealizedGainLoss(debt),
        expectedYield: (debt.expectedYield * 100).toFixed(2) + '%',
        riskRating: debt.riskRating,
        maturityDate: debt.maturityDate
      })),
      lastUpdated: new Date().toISOString()
    };
  }

  /**
   * Calculate current market value of debt
   * @param {Object} debt - Debt object
   * @returns {number} Current value
   */
  calculateCurrentValue(debt) {
    // Simplified valuation - in production would use market data
    const timeToMaturity = this.calculateTimeToMaturity(debt.maturityDate);
    const marketPrice = debt.marketPrice || debt.faceValue;

    // Apply discount based on time to maturity and risk
    const riskDiscount = this.getRiskDiscount(debt.riskRating);
    const timeDiscount = Math.max(0.9, 1 - (timeToMaturity / 365 / 10)); // 10% max discount

    return marketPrice * riskDiscount * timeDiscount;
  }

  /**
   * Calculate unrealized gain/loss
   * @param {Object} debt - Debt object
   * @returns {string} Formatted gain/loss
   */
  calculateUnrealizedGainLoss(debt) {
    const currentValue = this.calculateCurrentValue(debt);
    const gainLoss = currentValue - debt.acquiredValue;
    const percent = debt.acquiredValue > 0 ? (gainLoss / debt.acquiredValue) * 100 : 0;

    return {
      amount: this.formatCurrency(gainLoss, debt.currency),
      percent: percent.toFixed(2) + '%',
      isGain: gainLoss >= 0
    };
  }

  /**
   * Calculate time to maturity in days
   * @param {string} maturityDate - Maturity date string
   * @returns {number} Days to maturity
   */
  calculateTimeToMaturity(maturityDate) {
    const maturity = new Date(maturityDate);
    const now = new Date();
    return Math.max(0, Math.ceil((maturity - now) / (1000 * 60 * 60 * 24)));
  }

  /**
   * Get risk-based discount factor
   * @param {string} riskRating - Risk rating
   * @returns {number} Discount factor
   */
  getRiskDiscount(riskRating) {
    const discounts = {
      'AAA': 1.0,
      'AA+': 0.98,
      'AA': 0.96,
      'AA-': 0.94,
      'A+': 0.92,
      'A': 0.90,
      'A-': 0.88,
      'BBB+': 0.85,
      'BBB': 0.82,
      'BBB-': 0.80
    };
    return discounts[riskRating] || 0.80;
  }

  /**
   * Calculate portfolio risk
   * @param {Array} debts - Array of debts
   * @returns {string} Risk assessment
   */
  calculatePortfolioRisk(debts) {
    if (debts.length === 0) return 'Low';

    const riskScores = debts.map(debt => this.getRiskScore(debt.riskRating));
    const avgRisk = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;

    if (avgRisk >= 9) return 'Very Low';
    if (avgRisk >= 7) return 'Low';
    if (avgRisk >= 5) return 'Medium';
    if (avgRisk >= 3) return 'High';
    return 'Very High';
  }

  /**
   * Get numerical risk score
   * @param {string} riskRating - Risk rating
   * @returns {number} Risk score
   */
  getRiskScore(riskRating) {
    const scores = {
      'AAA': 10,
      'AA+': 9,
      'AA': 8,
      'AA-': 7,
      'A+': 6,
      'A': 5,
      'A-': 4,
      'BBB+': 3,
      'BBB': 2,
      'BBB-': 1
    };
    return scores[riskRating] || 1;
  }

  /**
   * Calculate diversification ratio
   * @param {Array} debts - Array of debts
   * @returns {number} Diversification ratio
   */
  calculateDiversificationRatio(debts) {
    if (debts.length === 0) return 0;

    const totalValue = debts.reduce((sum, debt) => sum + debt.acquiredValue, 0);
    const weights = debts.map(debt => debt.acquiredValue / totalValue);
    const herfindahlIndex = weights.reduce((sum, weight) => sum + weight * weight, 0);

    return (1 / Math.sqrt(herfindahlIndex)).toFixed(2);
  }

  /**
   * Generate default covenants for entity type
   * @param {string} entityType - Entity type
   * @returns {Array} Default covenants
   */
  generateDefaultCovenants(entityType) {
    const covenants = {
      sovereign: [
        'Sovereign immunity protection',
        'Government backing guarantee',
        'No default risk',
        'Priority payment status'
      ],
      institutional: [
        'Asset-backed security',
        'Institutional guarantee',
        'Tax-exempt status',
        'Priority creditor status'
      ],
      corporate: [
        'Corporate guarantee',
        'Asset collateral',
        'Credit enhancement',
        'Subordination provisions'
      ]
    };
    return covenants[entityType] || covenants.sovereign;
  }

  /**
   * Generate unique debt ID
   * @param {string} entity - Entity name
   * @param {string} debtType - Debt type
   * @returns {string} Debt ID
   */
  generateDebtId(entity, debtType) {
    const timestamp = Date.now();
    const random = randomBytes(4).toString('hex');
    const entitySlug = entity.toLowerCase().replace(/[^a-z0-9]/g, '-');
    return `${entitySlug}-${debtType}-${timestamp}-${random}`;
  }

  /**
   * Generate acquisition ID
   * @returns {string} Acquisition ID
   */
  generateAcquisitionId() {
    const timestamp = Date.now();
    const random = randomBytes(6).toString('hex');
    return `ACQ-${timestamp}-${random}`;
  }

  /**
   * Get debt acquisition history
   * @param {string} debtId - Debt ID
   * @returns {Array} Acquisition history
   */
  getAcquisitionHistory(debtId) {
    return this.acquisitionHistory.get(debtId) || [];
  }

  /**
   * Get debt valuation history
   * @param {string} debtId - Debt ID
   * @param {number} days - Number of days of history
   * @returns {Array} Valuation history
   */
  getValuationHistory(debtId, days = 90) {
    const history = this.debtValuations.get(debtId) || [];
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    return history
      .filter(entry => new Date(entry.timestamp) >= cutoffDate)
      .map(entry => ({
        ...entry,
        value: this.formatCurrency(entry.value, 'USD'),
        change: this.formatCurrency(entry.change, 'USD'),
        changePercent: entry.changePercent.toFixed(2) + '%'
      }));
  }

  /**
   * Update market intelligence data
   * @param {Object} intelligenceData - Market intelligence updates
   */
  updateMarketIntelligence(intelligenceData) {
    for (const [key, data] of Object.entries(intelligenceData)) {
      this.marketIntelligence.set(key, {
        ...data,
        lastUpdated: new Date().toISOString()
      });
    }
  }

  /**
   * Get market intelligence
   * @param {string} key - Intelligence key
   * @returns {Object|null} Intelligence data or null
   */
  getMarketIntelligence(key) {
    return this.marketIntelligence.get(key) || null;
  }

  /**
   * Format currency value
   * @param {number} value - Numeric value
   * @param {string} currency - Currency code
   * @returns {string} Formatted currency string
   */
  formatCurrency(value, currency = 'USD') {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency
    }).format(value);
  }

  /**
   * Export debt acquisition data
   * @returns {Object} Complete debt acquisition data
   */
  exportDebtData() {
    return {
      portfolio: Array.from(this.acquiredDebts.values()),
      acquisitionHistory: Object.fromEntries(this.acquisitionHistory),
      valuationHistory: Object.fromEntries(this.debtValuations),
      analytics: this.getDebtPortfolioAnalytics(),
      marketIntelligence: Object.fromEntries(this.marketIntelligence),
      exportTimestamp: new Date().toISOString()
    };
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'healthy',
      acquiredDebts: this.acquiredDebts.size,
      valuationRecords: Array.from(this.debtValuations.values())
        .reduce((sum, history) => sum + history.length, 0),
      marketIntelligencePoints: this.marketIntelligence.size,
      lastUpdate: new Date().toISOString()
    };
  }
}

export default DebtAcquisitionService;
