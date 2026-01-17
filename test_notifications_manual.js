#!/usr/bin/env node

const merchantBillPay = require('./earnings_dashboard/merchant_bill_pay');

async function runManualTests() {
  console.log('🧪 Manual Testing of Merchant Notification System\n');
  console.log('='.repeat(60));

  let testCount = 0;
  let passedTests = 0;
  let failedTests = 0;

  // Test 1: Merchant Email Lookup
  testCount++;
  console.log(`\nTest ${testCount}: Merchant Email Lookup`);
  try {
    const email1 = merchantBillPay.getMerchantEmail('merchant_001');
    const email2 = merchantBillPay.getMerchantEmail('merchant_002');
    const email3 = merchantBillPay.getMerchantEmail('unknown_merchant');

    if (
      email1 === 'merchant1@example.com' &&
      email2 === 'merchant2@example.com' &&
      email3 === null
    ) {
      console.log('✅ PASSED: Email lookup working correctly');
      passedTests++;
    } else {
      console.log('❌ FAILED: Email lookup returned incorrect values');
      console.log(
        `   merchant_001: ${email1}, expected: merchant1@example.com`
      );
      console.log(
        `   merchant_002: ${email2}, expected: merchant2@example.com`
      );
      console.log(`   unknown_merchant: ${email3}, expected: null`);
      failedTests++;
    }
  } catch (error) {
    console.log('❌ FAILED: Exception during email lookup:', error.message);
    failedTests++;
  }

  // Test 2: Merchant Phone Lookup
  testCount++;
  console.log(`\nTest ${testCount}: Merchant Phone Lookup`);
  try {
    const phone1 = merchantBillPay.getMerchantPhone('merchant_001');
    const phone2 = merchantBillPay.getMerchantPhone('merchant_002');
    const phone3 = merchantBillPay.getMerchantPhone('unknown_merchant');

    if (
      phone1 === '+1234567890' &&
      phone2 === '+0987654321' &&
      phone3 === null
    ) {
      console.log('✅ PASSED: Phone lookup working correctly');
      passedTests++;
    } else {
      console.log('❌ FAILED: Phone lookup returned incorrect values');
      console.log(`   merchant_001: ${phone1}, expected: +1234567890`);
      console.log(`   merchant_002: ${phone2}, expected: +0987654321`);
      console.log(`   unknown_merchant: ${phone3}, expected: null`);
      failedTests++;
    }
  } catch (error) {
    console.log('❌ FAILED: Exception during phone lookup:', error.message);
    failedTests++;
  }

  // Test 3: Notification Functions Existence
  testCount++;
  console.log(`\nTest ${testCount}: Notification Functions Existence`);
  try {
    if (
      typeof merchantBillPay.sendMerchantPaymentSuccessNotification ===
        'function' &&
      typeof merchantBillPay.sendMerchantPaymentFailureNotification ===
        'function' &&
      typeof merchantBillPay.sendSMSNotification === 'function'
    ) {
      console.log('✅ PASSED: All notification functions are defined');
      passedTests++;
    } else {
      console.log('❌ FAILED: Some notification functions are missing');
      failedTests++;
    }
  } catch (error) {
    console.log(
      '❌ FAILED: Exception checking function existence:',
      error.message
    );
    failedTests++;
  }

  // Test 4: Webhook Handler Existence
  testCount++;
  console.log(`\nTest ${testCount}: Webhook Handler Existence`);
  try {
    if (typeof merchantBillPay.handleMerchantWebhook === 'function') {
      console.log('✅ PASSED: Webhook handler function is defined');
      passedTests++;
    } else {
      console.log('❌ FAILED: Webhook handler function is missing');
      failedTests++;
    }
  } catch (error) {
    console.log(
      '❌ FAILED: Exception checking webhook handler:',
      error.message
    );
    failedTests++;
  }

  // Test 5: Payment Intent Creation Function
  testCount++;
  console.log(`\nTest ${testCount}: Payment Intent Creation Function`);
  try {
    if (typeof merchantBillPay.createMerchantPaymentIntent === 'function') {
      console.log('✅ PASSED: Payment intent creation function is defined');
      passedTests++;
    } else {
      console.log('❌ FAILED: Payment intent creation function is missing');
      failedTests++;
    }
  } catch (error) {
    console.log(
      '❌ FAILED: Exception checking payment intent function:',
      error.message
    );
    failedTests++;
  }

  // Test 6: Module Exports
  testCount++;
  console.log(`\nTest ${testCount}: Module Exports`);
  try {
    const expectedExports = [
      'router',
      'createMerchantPaymentIntent',
      'handleMerchantWebhook',
    ];
    const actualExports = Object.keys(merchantBillPay);

    const hasAllExports = expectedExports.every((exp) =>
      actualExports.includes(exp)
    );

    if (hasAllExports) {
      console.log('✅ PASSED: All expected module exports are present');
      console.log(`   Exports: ${actualExports.join(', ')}`);
      passedTests++;
    } else {
      console.log('❌ FAILED: Missing expected exports');
      console.log(`   Expected: ${expectedExports.join(', ')}`);
      console.log(`   Actual: ${actualExports.join(', ')}`);
      failedTests++;
    }
  } catch (error) {
    console.log('❌ FAILED: Exception checking module exports:', error.message);
    failedTests++;
  }

  // Test 7: Environment Variables Check
  testCount++;
  console.log(`\nTest ${testCount}: Environment Variables Configuration`);
  try {
    const requiredEnvVars = ['STRIPE_SECRET_KEY'];
    const optionalEnvVars = [
      'SMTP_HOST',
      'SMTP_USER',
      'SMTP_PASS',
      'TWILIO_SID',
      'TWILIO_AUTH_TOKEN',
    ];

    const missingRequired = [];
    const presentOptional = [];

    requiredEnvVars.forEach((varName) => {
      if (!process.env[varName]) {
        missingRequired.push(varName);
      }
    });

    optionalEnvVars.forEach((varName) => {
      if (process.env[varName]) {
        presentOptional.push(varName);
      }
    });

    if (missingRequired.length === 0) {
      console.log('✅ PASSED: All required environment variables are set');
      if (presentOptional.length > 0) {
        console.log(
          `   Optional variables configured: ${presentOptional.join(', ')}`
        );
      } else {
        console.log(
          '   Note: Optional email/SMS variables not configured (expected for testing)'
        );
      }
      passedTests++;
    } else {
      console.log('❌ FAILED: Missing required environment variables');
      console.log(`   Missing: ${missingRequired.join(', ')}`);
      failedTests++;
    }
  } catch (error) {
    console.log(
      '❌ FAILED: Exception checking environment variables:',
      error.message
    );
    failedTests++;
  }

  // Test 8: File Structure Check
  testCount++;
  console.log(`\nTest ${testCount}: File Dependencies`);
  try {
    const fs = require('fs');
    const path = require('path');

    const requiredFiles = [
      './earnings_dashboard/merchant_bill_pay.js',
      './earnings_report_updated.json',
    ];

    const missingFiles = [];

    requiredFiles.forEach((filePath) => {
      const fullPath = path.resolve(__dirname, filePath);
      if (!fs.existsSync(fullPath)) {
        missingFiles.push(filePath);
      }
    });

    if (missingFiles.length === 0) {
      console.log('✅ PASSED: All required files exist');
      passedTests++;
    } else {
      console.log('❌ FAILED: Missing required files');
      console.log(`   Missing: ${missingFiles.join(', ')}`);
      failedTests++;
    }
  } catch (error) {
    console.log(
      '❌ FAILED: Exception checking file dependencies:',
      error.message
    );
    failedTests++;
  }

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('📊 TEST SUMMARY');
  console.log('='.repeat(60));
  console.log(`Total Tests: ${testCount}`);
  console.log(`Passed: ${passedTests}`);
  console.log(`Failed: ${failedTests}`);
  console.log(`Success Rate: ${((passedTests / testCount) * 100).toFixed(1)}%`);

  if (failedTests === 0) {
    console.log(
      '\n🎉 ALL TESTS PASSED! The notification system is ready for use.'
    );
    console.log('\n📋 Next Steps:');
    console.log(
      '1. Configure SMTP environment variables for email notifications'
    );
    console.log(
      '2. Configure Twilio environment variables for SMS notifications'
    );
    console.log('3. Test with real Stripe webhooks in a staging environment');
    console.log('4. Update merchant contact information in the database');
  } else {
    console.log('\n⚠️  Some tests failed. Please review the issues above.');
  }

  return failedTests === 0;
}

// Run the tests
runManualTests().catch((error) => {
  console.error('\n💥 Unexpected error during testing:', error);
  process.exit(1);
});
