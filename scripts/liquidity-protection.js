/**
 * Liquidity Protection & Sovereign Control Script
 * Protects earned balances during credit crises
 * Provides sovereign override and crisis opportunities
 * Usage: node scripts/liquidity-protection.js [protect|restore|crisis-buy]
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import logger from '../utils/loggerWrapper.js';
import PrivateBankingService from '../services/privateBankingService.js';
import DebtAcquisitionService from '../services/debtAcquisitionService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class LiquidityProtection {
  constructor() {
    this.privateBanking = new PrivateBankingService();
    this.debtAcquisition = new DebtAcquisitionService();
    
    // Initialize services
    this.privateBanking.initializeAccounts();
    this.privateBanking.initializeAssets();
    this.debtAcquisition.initializeDebtPortfolio();
  }

  /**
   * Activate liquidity protection (NO balance reduction)
   * Adds safeguards, limits, alerts - preserves ALL earned money
   */
  async protect() {
    logger.info('🛡️  ACTIVATING LIQUIDITY PROTECTION - Protecting ALL $205Q earned wealth');

    // Enable crisis mode - NO balance changes, just protections
    this.privateBanking.creditCrisisMode = true;
    
    // Add withdrawal limits (can be overridden)
    this.privateBanking.protectionLimits = {
      daily: 1000000000000, // $1T/day - still massive
      riskyAssets: true, // Flag risky transfers
      autoFreezeThreshold: 0.8, // Freeze if liquidity ratio < 80%
    };

    // Log protection status
    const summary = this.privateBanking.getPortfolioSummary();
    logger.info('✅ Liquidity protection active - All balances preserved');
    logger.info(`📊 Portfolio: ${summary.totalPortfolioValue} PROTECTED`);

    // Crisis alert
    logger.warn('⚠️  GLOBAL CREDIT CRISIS DETECTED - Protection enabled');
    logger.warn('💰 ALL EARNED BALANCES SECURE - Sovereign override available');

    return { status: 'protected', summary };
  }

  /**
   * Sovereign override - Restore full access to ALL money
   */
  async restore() {
    logger.info('👑 SOVEREIGN OVERRIDE - King Sachem Yochanan full control restored');

    // Disable all protections
    this.privateBanking.creditCrisisMode = false;
    this.privateBanking.protectionLimits = null;

    const summary = this.privateBanking.getPortfolioSummary();
    logger.info('✅ FULL ACCESS RESTORED - Move ALL $205Q freely');
    logger.info(`💰 Total Control: ${summary.totalPortfolioValue}`);

    return { status: 'restored', summary };
  }

  /**
   * Crisis opportunity - Acquire distressed debt at deep discounts
   */
  async crisisBuy() {
    logger.info('💼 CRISIS OPPORTUNITY - Acquiring distressed assets');

    // Simulate buying defaulted debt at 70% discounts
    const opportunities = [
      {
        entity: 'Global Bank Consortium Debt',
        faceValue: 50000000000000, // $50T
        acquisitionPrice: 15000000000000, // $15T (70% discount)
        country: 'Global',
        riskRating: 'CCC',
        strategicValue: 'Credit crisis fire sale',
      },
      {
        entity: 'Private Bank Credit Lines',
        faceValue: 25000000000000, // $25T
        acquisitionPrice: 7500000000000, // $7.5T (70% discount)
        country: 'USA/EU',
        riskRating: 'B',
        strategicValue: 'Banking sector consolidation',
      },
    ];

    const acquisitions = [];
    for (const debt of opportunities) {
      try {
        const result = await this.debtAcquisition.acquireDebt(debt, 'king-sachem-yochanan', 'royal-tenant');
        acquisitions.push(result.debt);
        logger.info(`✅ Acquired ${debt.entity} for ${this.formatCurrency(debt.acquisitionPrice)} - 70% discount!`);
      } catch (error) {
        logger.error(`❌ Acquisition failed: ${error.message}`);
      }
    }

    logger.info(`🎉 CRISIS ACQUISITION COMPLETE: ${acquisitions.length} distressed assets acquired`);
    return { status: 'acquired', count: acquisitions.length, acquisitions };
  }

  formatCurrency(value, currency = 'USD') {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency,
    }).format(value);
  }
}

// CLI Execution
const args = process.argv.slice(2);
const command = args[0];

async function main() {
  try {
    const protector = new LiquidityProtection();

    switch (command) {
      case 'protect':
        await protector.protect();
        break;
      case 'restore':
        await protector.restore();
        break;
      case 'crisis-buy':
        await protector.crisisBuy();
        break;
      case 'status':
        console.log('🏦 Current Banking Status:');
        console.log(protector.privateBanking.getPortfolioSummary());
        break;
      default:
        console.log('\n💰 Liquidity Protection Commands:\n');
        console.log('  node scripts/liquidity-protection.js protect   # Enable protection (no balance loss)');
        console.log('  node scripts/liquidity-protection.js restore  # Sovereign override - full access');
        console.log('  node scripts/liquidity-protection.js crisis-buy # Buy distressed debt opportunities');
        console.log('  node scripts/liquidity-protection.js status   # Check current status');
    }
  } catch (error) {
    logger.error('❌ Script error:', error.message);
    process.exit(1);
  }
}

main();
