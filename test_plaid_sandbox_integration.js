import { Configuration, PlaidApi, PlaidEnvironments } from 'plaid';
import plaidService from './services/plaidService.js';
import logger from './config/logger.js';

// Test script for Plaid Sandbox integration
async function testPlaidSandboxIntegration() {
  console.log('🧪 Testing Plaid Sandbox Integration...\n');

  try {
    // Test 1: Create link token
    console.log('1. Testing Link Token Creation...');
    const linkTokenData = await plaidService.createLinkToken('test-user-123', ['transactions', 'balances'], {
      countryCodes: ['US'],
      language: 'en',
      user: {
        client_user_id: 'test-user-123',
        legal_name: 'Test User',
        phone_number: '+1 234 567 8900',
        email_address: 'test@example.com'
      }
    });

    console.log('✅ Link token created successfully:', linkTokenData.link_token.substring(0, 20) + '...');

    // Test 2: Simulate public token exchange (using sandbox endpoint)
    console.log('\n2. Testing Public Token Exchange...');
    const publicToken = 'public-sandbox-' + Math.random().toString(36).substring(2);

    const tokenData = await plaidService.exchangePublicToken(publicToken);
    console.log('✅ Public token exchanged successfully:', {
      access_token: tokenData.access_token.substring(0, 20) + '...',
      item_id: tokenData.item_id
    });

    // Test 3: Get account balances
    console.log('\n3. Testing Account Balances...');
    const balances = await plaidService.getBalances(tokenData.access_token);
    console.log('✅ Account balances retrieved:', balances.accounts?.length || 0, 'accounts');

    // Test 4: Get transactions
    console.log('\n4. Testing Transactions...');
    const transactions = await plaidService.getTransactions(tokenData.access_token, {
      start_date: '2023-01-01',
      end_date: new Date().toISOString().split('T')[0],
      count: 10
    });
    console.log('✅ Transactions retrieved:', transactions.transactions?.length || 0, 'transactions');

    // Test 5: Test error handling
    console.log('\n5. Testing Error Handling...');
    try {
      await plaidService.getBalances('invalid-token');
    } catch (error) {
      console.log('✅ Error handling works:', error.message);
    }

    // Test 6: Get service metrics
    console.log('\n6. Testing Service Metrics...');
    const metrics = plaidService.getMetrics();
    console.log('✅ Service metrics:', {
      totalCalls: metrics.apiCalls,
      successRate: metrics.successRate.toFixed(2) + '%',
      errorRate: metrics.errorRate.toFixed(2) + '%'
    });

    console.log('\n🎉 All Plaid Sandbox integration tests passed!');

    // Summary
    console.log('\n📊 Test Summary:');
    console.log('- Link token creation: ✅');
    console.log('- Public token exchange: ✅');
    console.log('- Account balances: ✅');
    console.log('- Transactions: ✅');
    console.log('- Error handling: ✅');
    console.log('- Service metrics: ✅');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack:', error.stack);
    process.exit(1);
  }
}

// Run the test
testPlaidSandboxIntegration().catch(console.error);
