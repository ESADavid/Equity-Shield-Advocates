import DebtAcquisitionService from './services/debtAcquisitionService.js';
import Debt from './models/Debt.js';

describe('Debt Acquisition Service', () => {
  let debtService;

  beforeEach(() => {
    debtService = new DebtAcquisitionService();
  });

  test('should initialize with empty portfolio', () => {
    expect(debtService.portfolio.size).toBe(0);
  });

  test('should acquire debt successfully', async () => {
    const debtData = {
      entity: 'US Treasury',
      entityType: 'sovereign',
      country: 'United States',
      debtType: 'government_bonds',
      faceValue: 1000000,
      acquiredValue: 950000,
      currentValue: 950000,
      currency: 'USD',
      maturityDate: new Date('2030-01-01'),
      interestRate: 0.045,
      expectedYield: 0.05,
      riskRating: 'AAA',
      strategicValue: 'Safe haven asset',
    };

    const result = await debtService.acquireDebt(
      debtData,
      'user123',
      'tenant123'
    );

    expect(result.success).toBe(true);
    expect(result.debt).toBeDefined();
    expect(result.debt.entity).toBe('US Treasury');
    expect(debtService.portfolio.size).toBe(1);
  });

  test('should validate debt data', async () => {
    const invalidDebtData = {
      entity: '',
      entityType: 'invalid',
      faceValue: -1000,
    };

    await expect(
      debtService.acquireDebt(invalidDebtData, 'user123', 'tenant123')
    ).rejects.toThrow();
  });

  test('should update debt valuation', async () => {
    const debtData = {
      entity: 'Corporate Bond',
      entityType: 'corporate',
      country: 'United States',
      debtType: 'corporate_bonds',
      faceValue: 500000,
      acquiredValue: 480000,
      currentValue: 480000,
      currency: 'USD',
      maturityDate: new Date('2028-01-01'),
      interestRate: 0.06,
      expectedYield: 0.065,
      riskRating: 'BBB+',
    };

    const acquisition = await debtService.acquireDebt(
      debtData,
      'user123',
      'tenant123'
    );
    const debtId = acquisition.debt.debtId;

    const updateResult = await debtService.updateValuation(
      debtId,
      490000,
      'user456',
      {
        marketPrice: 490000,
        interestRate: 0.061,
      }
    );

    expect(updateResult.success).toBe(true);
    expect(updateResult.debt.currentValue).toBe(490000);
  });

  test('should get portfolio analytics', async () => {
    // Add multiple debts
    await debtService.acquireDebt(
      {
        entity: 'US Treasury',
        entityType: 'sovereign',
        country: 'United States',
        debtType: 'government_bonds',
        faceValue: 1000000,
        acquiredValue: 950000,
        currentValue: 950000,
        currency: 'USD',
        maturityDate: new Date('2030-01-01'),
        interestRate: 0.045,
        expectedYield: 0.05,
        riskRating: 'AAA',
      },
      'user123',
      'tenant123'
    );

    await debtService.acquireDebt(
      {
        entity: 'EU Bond',
        entityType: 'sovereign',
        country: 'Germany',
        debtType: 'government_bonds',
        faceValue: 500000,
        acquiredValue: 475000,
        currentValue: 475000,
        currency: 'EUR',
        maturityDate: new Date('2029-01-01'),
        interestRate: 0.035,
        expectedYield: 0.04,
        riskRating: 'AAA',
      },
      'user123',
      'tenant123'
    );

    const analytics = debtService.getPortfolioAnalytics();

    expect(analytics.totalDebts).toBe(2);
    expect(analytics.totalAcquiredValue).toBe(1425000);
    expect(analytics.geographicDistribution).toBeDefined();
    expect(analytics.entityTypeDistribution).toBeDefined();
  });

  test('should identify high-risk debts', async () => {
    await debtService.acquireDebt(
      {
        entity: 'Risky Corp',
        entityType: 'corporate',
        country: 'Emerging Market',
        debtType: 'corporate_bonds',
        faceValue: 200000,
        acquiredValue: 180000,
        currentValue: 180000,
        currency: 'USD',
        maturityDate: new Date('2027-01-01'),
        interestRate: 0.12,
        expectedYield: 0.15,
        riskRating: 'B-',
      },
      'user123',
      'tenant123'
    );

    const highRiskDebts = debtService.getHighRiskDebts(70);

    expect(highRiskDebts.length).toBeGreaterThan(0);
    expect(highRiskDebts[0].riskRating).toBe('B-');
  });

  test('should handle debt maturity', async () => {
    await debtService.acquireDebt(
      {
        entity: 'Short Term Bond',
        entityType: 'corporate',
        country: 'United States',
        debtType: 'corporate_bonds',
        faceValue: 100000,
        acquiredValue: 98000,
        currentValue: 98000,
        currency: 'USD',
        maturityDate: new Date(Date.now() + 24 * 60 * 60 * 1000), // Tomorrow
        interestRate: 0.05,
        expectedYield: 0.055,
        riskRating: 'A',
      },
      'user123',
      'tenant123'
    );

    const maturingDebts = debtService.getMaturingDebts(7); // Next 7 days

    expect(maturingDebts.length).toBe(1);
    expect(maturingDebts[0].entity).toBe('Short Term Bond');
  });
});

describe('Debt Model', () => {
  test('should create debt with correct virtuals', () => {
    const debt = new Debt({
      tenantId: 'tenant123',
      debtId: 'debt123',
      entity: 'Test Corp',
      entityType: 'corporate',
      country: 'USA',
      debtType: 'corporate_bonds',
      faceValue: 100000,
      acquiredValue: 95000,
      currentValue: 97000,
      maturityDate: new Date('2030-01-01'),
      interestRate: 0.05,
      expectedYield: 0.055,
      riskRating: 'BBB+',
    });

    expect(debt.unrealizedGainLoss).toBe(2000);
    expect(debt.unrealizedGainLossPercent).toBeCloseTo(2.11, 1);
    expect(debt.timeToMaturity).toBeGreaterThan(0);
  });

  test('should calculate yield to maturity', () => {
    const debt = new Debt({
      faceValue: 100000,
      currentValue: 95000,
      interestRate: 0.05,
      maturityDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
    });

    expect(debt.yieldToMaturity).toBeGreaterThan(0);
  });
});
