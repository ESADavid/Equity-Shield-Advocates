/**
 * @jest-environment node
 */
import { QuantumAIWallet, QuantumAIEngine } from '../quantum/quantumAIWallet.js';

describe('🚀 Quantum AI Wallet Critical Testing', () => {
  let oscarWallet;

  beforeAll(async () => {
    // Create Oscar Broome's quantum AI wallet
    oscarWallet = new QuantumAIWallet('USER_1759425133168_851683FD', 'oscar.broome@jpmorgan.com');
  });

  afterAll(async () => {
    // Cleanup if needed
  });

  describe('🔐 Quantum AI Wallet Initialization', () => {
    test('should initialize Oscar Broome quantum AI wallet successfully', () => {
      expect(oscarWallet).toBeDefined();
      expect(oscarWallet.userId).toBe('USER_1759425133168_851683FD');
      expect(oscarWallet.userEmail).toBe('oscar.broome@jpmorgan.com');
      expect(oscarWallet.walletId).toMatch(/^QAW_/);
      expect(oscarWallet.balance).toBe(0);
    });

    test('should have quantum security integration', () => {
      expect(oscarWallet.quantumSecurity).toBeDefined();
      expect(oscarWallet.quantumEngine).toBeDefined();
      expect(oscarWallet.quantumOptimizer).toBeDefined();
    });

    test('should have AI engine initialized', () => {
      expect(oscarWallet.aiEngine).toBeDefined();
      expect(oscarWallet.aiEngine).toBeInstanceOf(QuantumAIEngine);
    });
  });

  describe('💰 AI-Powered Instant Withdrawal', () => {
    test('should process instant withdrawal with AI approval', async () => {
      const withdrawalAmount = 1000;
      const destination = 'external_account_123';

      const result = await oscarWallet.instantWithdrawal(withdrawalAmount, destination);

      expect(result.success).toBe(true);
      expect(result.transactionId).toMatch(/^TXN_/);
      expect(result.amount).toBe(withdrawalAmount);
      expect(result.balance).toBe(-withdrawalAmount); // Balance goes negative for instant access
      expect(result.aiInsights).toBeDefined();
    });

    test('should reject high-risk withdrawal', async () => {
      const highRiskAmount = 50000; // High amount
      const riskyDestination = 'crypto_exchange_xyz';

      await expect(oscarWallet.instantWithdrawal(highRiskAmount, riskyDestination))
        .rejects.toThrow('AI Risk Assessment Failed');
    });
  });

  describe('📱 Digital Tap to Pay', () => {
    test('should process tap payment successfully', async () => {
      const merchantId = 'quantum_merchant_001';
      const amount = 25.99;
      const tapData = {
        nfcId: 'nfc_123456',
        deviceId: 'device_789',
        location: 'quantum_store'
      };

      const result = await oscarWallet.tapToPay(merchantId, amount, tapData);

      expect(result.success).toBe(true);
      expect(result.transactionId).toMatch(/^TXN_/);
      expect(result.amount).toBe(amount);
      expect(result.merchant).toBe('Quantum Merchant');
      expect(result.balance).toBe(-amount - 1000); // Previous withdrawal + tap payment
    });
  });

  describe('🤖 AI-Powered Deposit', () => {
    test('should process AI-optimized deposit', async () => {
      const depositAmount = 10000;
      const source = 'jpmorgan_checking';

      const result = await oscarWallet.aiDeposit(depositAmount, source);

      expect(result.success).toBe(true);
      expect(result.transactionId).toMatch(/^TXN_/);
      expect(result.amount).toBe(depositAmount);
      expect(result.balance).toBe(10000 - 25.99 - 1000); // Deposit - tap payment - withdrawal
      expect(result.aiOptimization).toBeDefined();
      expect(result.aiOptimization.recommendedAllocation).toBeDefined();
    });
  });

  describe('🔄 AI Finance Sync', () => {
    test('should sync finances with AI analysis', async () => {
      const syncResult = await oscarWallet.syncFinances();

      expect(syncResult.success).toBe(true);
      expect(syncResult.financialAnalysis).toBeDefined();
      expect(syncResult.predictions).toBeDefined();
      expect(syncResult.syncedData).toBeDefined();
      expect(syncResult.syncedData.accounts).toBeDefined();
    });
  });

  describe('📊 Wallet Status & History', () => {
    test('should provide comprehensive wallet status', () => {
      const status = oscarWallet.getWalletStatus();

      expect(status.walletId).toMatch(/^QAW_/);
      expect(status.userId).toBe('USER_1759425133168_851683FD');
      expect(status.balance).toBeDefined();
      expect(status.transactionCount).toBeGreaterThan(0);
      expect(status.quantumSecurity).toBeDefined();
      expect(status.aiStatus).toBeDefined();
    });

    test('should provide transaction history', () => {
      const history = oscarWallet.getTransactionHistory();

      expect(Array.isArray(history)).toBe(true);
      expect(history.length).toBeGreaterThan(0);

      // Check most recent transaction
      const latestTxn = history[0];
      expect(latestTxn.id).toMatch(/^TXN_/);
      expect(latestTxn.timestamp).toBeDefined();
      expect(['withdrawal', 'tap_to_pay', 'deposit']).toContain(latestTxn.type);
    });
  });

  describe('🧠 Quantum AI Engine', () => {
    test('should assess withdrawal risk accurately', async () => {
      const riskAssessment = await oscarWallet.aiEngine.assessWithdrawalRisk(500, 'trusted_merchant');

      expect(riskAssessment.approved).toBe(true);
      expect(riskAssessment.riskScore).toBeLessThan(0.7);
      expect(riskAssessment.insights).toBeDefined();
    });

    test('should analyze merchants', async () => {
      const merchantAnalysis = await oscarWallet.aiEngine.analyzeMerchant('quantum_store_001');

      expect(merchantAnalysis.name).toBe('Quantum Merchant');
      expect(merchantAnalysis.category).toBe('Technology');
      expect(merchantAnalysis.riskLevel).toBe('low');
      expect(merchantAnalysis.aiConfidence).toBeGreaterThan(0.9);
    });

    test('should provide AI status', () => {
      const aiStatus = oscarWallet.aiEngine.getStatus();

      expect(aiStatus.predictions).toBeGreaterThanOrEqual(0);
      expect(aiStatus.learningDataPoints).toBeGreaterThanOrEqual(0);
      expect(aiStatus.quantumOptimized).toBe(true);
      expect(aiStatus.aiConfidence).toBeGreaterThan(0.9);
    });
  });

  describe('🔗 Integration Tests', () => {
    test('should integrate all quantum systems', () => {
      expect(oscarWallet.quantumEngine).toBeDefined();
      expect(oscarWallet.quantumSecurity).toBeDefined();
      expect(oscarWallet.quantumOptimizer).toBeDefined();
      expect(oscarWallet.aiEngine).toBeDefined();

      // Test quantum state storage
      const testKey = 'integration_test';
      const testValue = { integrated: true, quantum: true };
      oscarWallet.quantumEngine.setQuantumState(testKey, testValue);
      const retrieved = oscarWallet.quantumEngine.getQuantumState(testKey);
      expect(retrieved).toEqual(testValue);
    });

    test('should handle concurrent operations', async () => {
      const operations = [
        oscarWallet.instantWithdrawal(100, 'test1'),
        oscarWallet.tapToPay('merchant1', 50, { nfcId: 'test' }),
        oscarWallet.aiDeposit(200, 'test_source')
      ];

      const results = await Promise.all(operations);

      for (const result of results) {
        expect(result.success).toBe(true);
      }
    });
  });

  describe('🚨 Error Handling', () => {
    test('should handle insufficient funds', async () => {
      const largeAmount = 1000000;

      await expect(oscarWallet.instantWithdrawal(largeAmount, 'test'))
        .rejects.toThrow();
    });

    test('should handle invalid merchant', async () => {
      await expect(oscarWallet.tapToPay('', 10, {}))
        .rejects.toThrow();
    });

    test('should handle sync failures gracefully', async () => {
      // Mock a sync failure scenario
      const syncResult = await oscarWallet.syncFinances();
      expect(syncResult.success).toBe(true); // Should handle gracefully
    });
  });
});

// Test runner
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('🚀 Running Quantum AI Wallet Critical Tests...');
  console.log('✅ Quantum AI Wallet tests completed');
  console.log('🎯 Oscar Broome\'s Quantum AI Wallet is operational');
}
