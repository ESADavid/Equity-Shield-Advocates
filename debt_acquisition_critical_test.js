import DebtAcquisitionService from './services/debtAcquisitionService.js';

console.log('=== DEBT ACQUISITION SERVICE - CRITICAL PATH TESTING ===\n');

const service = new DebtAcquisitionService();

try {
  // Test 1: Initialize portfolio
  console.log('1. Testing portfolio initialization...');
  service.initializeDebtPortfolio();
  console.log('✓ Portfolio initialized successfully\n');

  // Test 2: Acquire debt
  console.log('2. Testing debt acquisition...');
  const acquisitionResult = await service.acquireDebt({
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
    strategicValue: 'Test Investment'
  }, 'user123', 'tenant456');

  console.log('✓ Debt acquired successfully');
  console.log(`  Debt ID: ${acquisitionResult.debt.debtId}`);
  console.log(`  Entity: ${acquisitionResult.debt.entity}\n`);

  // Test 3: Get debt portfolio
  console.log('3. Testing portfolio retrieval...');
  const portfolio = service.getDebtPortfolio();
  console.log(`✓ Retrieved ${portfolio.length} debts in portfolio\n`);

  // Test 4: Update valuation
  console.log('4. Testing valuation update...');
  const debtId = acquisitionResult.debt.debtId;
  const valuationResult = await service.updateValuation(debtId, 9600000, 'user123', {
    marketPrice: 9600000,
    interestRate: 0.052
  });

  console.log('✓ Valuation updated successfully');
  console.log(`  Old Value: ${valuationResult.oldValue}`);
  console.log(`  New Value: ${valuationResult.newValue}`);
  console.log(`  Change: ${valuationResult.change}\n`);

  // Test 5: Get portfolio analytics
  console.log('5. Testing portfolio analytics...');
  const analytics = service.getPortfolioAnalytics();
  console.log('✓ Analytics retrieved successfully');
  console.log(`  Total Debts: ${analytics.summary.totalDebts}`);
  console.log(`  Total Value: ${analytics.summary.totalCurrentValue}\n`);

  // Test 6: Get high risk debts
  console.log('6. Testing high risk debt identification...');
  const highRiskDebts = service.getHighRiskDebts();
  console.log(`✓ Found ${highRiskDebts.length} high risk debts\n`);

  // Test 7: Get maturing debts
  console.log('7. Testing maturing debt identification...');
  const maturingDebts = service.getMaturingDebts(365);
  console.log(`✓ Found ${maturingDebts.length} maturing debts within 365 days\n`);

  console.log('=== ALL CRITICAL PATH TESTS PASSED ===');

} catch (error) {
  console.error('❌ Test failed:', error.message);
  process.exit(1);
}
