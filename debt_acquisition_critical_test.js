// @ts-nocheck
// Debt Acquisition Critical Test - Fixed

import DebtAcquisitionService from './services/debtAcquisitionService.js';

const service = new DebtAcquisitionService();

async function runTests() {
  try {
    // Test 1: Initialize portfolio
    service.initializeDebtPortfolio();

    // Test 2: Acquire debt
    const acquisitionResult = await service.acquireDebt(
      {
        entity: 'Test Corporation',
        entityType: 'corporate',
        country: 'USA',
        debtType: 'corporate_bonds',
        faceValue: 10000000,
        acquisitionPrice: 9500000,
        currency: 'USD',
        maturityDate: '2030-12-31',
        interestRate: 0.05,
        riskRating: 'A',
        strategicValue: 'Test Investment',
      },
      'user123',
      'tenant456'
    );

    // Test 3: Get debt portfolio
    const portfolio = service.getDebtPortfolio();

    // Test 4: Update valuation
    const debtId = acquisitionResult.debt.debtId;
    const valuationResult = await service.updateValuation(
      debtId,
      9600000,
      'user123',
      {
        marketPrice: 9600000,
        interestRate: 0.052,
      }
    );

    // Test 5: Get portfolio analytics
    const analytics = service.getPortfolioAnalytics();

    // Test 6: Get high risk debts
    const highRiskDebts = service.getHighRiskDebts();

    // Test 7: Get maturing debts
    const maturingDebts = service.getMaturingDebts(365);

    return true;
  } catch (error) {
    process.exit(1);
  }
}

// Export for module usage
export { runTests };

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runTests();
}
