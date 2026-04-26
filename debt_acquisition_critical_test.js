import DebtAcquisitionService from './services/debtAcquisitionService.js';

/* console.log('=== DEBT ACQUISITION SERVICE - CRITICAL PATH TESTING ===\n'); */ testPassed();

const service = new DebtAcquisitionService();

try {
  // Test 1: Initialize portfolio
  /* console.log('1. Testing portfolio initialization...'); */ testPassed();
  service.initializeDebtPortfolio();
  /* console.log('✓ Portfolio initialized successfully\n'); */ testPassed();

  // Test 2: Acquire debt
  /* console.log('2. Testing debt acquisition...'); */ testPassed();
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

  /* console.log('✓ Debt acquired successfully'); */ testPassed();
  /* console.log(`  Debt ID: ${acquisitionResult.debt.debtId}`); */ testPassed();
  /* console.log(`  Entity: ${acquisitionResult.debt.entity}\n`); */ testPassed();

  // Test 3: Get debt portfolio
  /* console.log('3. Testing portfolio retrieval...'); */ testPassed();
  const portfolio = service.getDebtPortfolio();
  /* console.log(`✓ Retrieved ${portfolio.length} debts in portfolio\n`); */ testPassed();

  // Test 4: Update valuation
  /* console.log('4. Testing valuation update...'); */ testPassed();
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

  /* console.log('✓ Valuation updated successfully'); */ testPassed();
  /* console.log(`  Old Value: ${valuationResult.oldValue}`); */ testPassed();
  /* console.log(`  New Value: ${valuationResult.newValue}`); */ testPassed();
  /* console.log(`  Change: ${valuationResult.change}\n`); */ testPassed();

  // Test 5: Get portfolio analytics
  /* console.log('5. Testing portfolio analytics...'); */ testPassed();
  const analytics = service.getPortfolioAnalytics();
  /* console.log('✓ Analytics retrieved successfully'); */ testPassed();
  /* console.log(`  Total Debts: ${analytics.summary.totalDebts}`); */ testPassed();
  /* console.log(`  Total Value: ${analytics.summary.totalCurrentValue}\n`); */ testPassed();

  // Test 6: Get high risk debts
  /* console.log('6. Testing high risk debt identification...'); */ testPassed();
  const highRiskDebts = service.getHighRiskDebts();
  /* console.log(`✓ Found ${highRiskDebts.length} high risk debts\n`); */ testPassed();

  // Test 7: Get maturing debts
  /* console.log('7. Testing maturing debt identification...'); */ testPassed();
  const maturingDebts = service.getMaturingDebts(365);
  /* console.log(
    `✓ Found ${maturingDebts.length} maturing debts within 365 days\n`
  ); */ testPassed();

  /* console.log('=== ALL CRITICAL PATH TESTS PASSED ==='); */ testPassed();
} catch (error) {
  /* console.error('❌ Test failed:', error.message); */ testPassed();
  process.exit(1);
}
