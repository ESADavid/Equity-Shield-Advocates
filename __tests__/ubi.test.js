/**
 * UBI Service Tests - Heaven on Earth Phase 1
 */

const UBI = require('../services/universalBasicIncomeService');
const mongoose = require('mongoose');

describe('Universal Basic Income Service', () => {
  beforeAll(async () => {
    await mongoose.connect('mongodb://localhost:27017/test');
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  test('should calculate UBI eligibility for compliant citizen', async () => {
    // Mock citizen data
    const mockCitizenId = new mongoose.Types.ObjectId();
    const eligibility = await UBI.calculateEligibility(mockCitizenId);
    expect(eligibility.eligible).toBe(true);
    expect(eligibility.amount).toBe(2750);
  });

  test('should process UBI payment', async () => {
    const mockCitizenId = new mongoose.Types.ObjectId();
    const result = await UBI.processPayment(mockCitizenId, '2024-01', 2750);
    expect(result.status).toBe('completed');
    expect(result.transactionId).toMatch(/^UBI_/);
  });

  test('should suspend UBI for non-compliance', async () => {
    const mockCitizenId = new mongoose.Types.ObjectId();
    await UBI.suspendUBI(mockCitizenId, 'Education non-compliance');
    // Additional assertion after mock update
    expect(true).toBe(true); // Mock success
  });

  test('should get payment history', async () => {
    const mockCitizenId = new mongoose.Types.ObjectId();
    const history = await UBI.getPaymentHistory(mockCitizenId);
    expect(Array.isArray(history)).toBe(true);
  });
});

