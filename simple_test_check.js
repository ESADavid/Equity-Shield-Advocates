#!/usr/bin/env node

console.log('🧪 Simple Test Check for Merchant Notification System\n');

try {
  // Test if the module can be loaded
  console.log('1. Testing module import...');
  const merchantBillPay = require('./earnings_dashboard/merchant_bill_pay');
  console.log('✅ Module loaded successfully');

  // Test basic function existence
  console.log('\n2. Testing function existence...');
  const functions = [
    'sendMerchantPaymentSuccessNotification',
    'sendMerchantPaymentFailureNotification',
    'sendSMSNotification',
    'handleMerchantWebhook',
    'createMerchantPaymentIntent',
    'getMerchantEmail',
    'getMerchantPhone'
  ];

  functions.forEach(func => {
    if (typeof merchantBillPay[func] === 'function') {
      console.log(`✅ ${func} exists`);
    } else {
      console.log(`❌ ${func} missing`);
    }
  });

  // Test merchant lookup
  console.log('\n3. Testing merchant lookup...');
  const email1 = merchantBillPay.getMerchantEmail('merchant_001');
  const email2 = merchantBillPay.getMerchantEmail('merchant_002');
  const email3 = merchantBillPay.getMerchantEmail('unknown_merchant');

  console.log(`merchant_001 email: ${email1}`);
  console.log(`merchant_002 email: ${email2}`);
  console.log(`unknown_merchant email: ${email3}`);

  // Test module exports
  console.log('\n4. Testing module exports...');
  const exports = Object.keys(merchantBillPay);
  console.log(`Module exports: ${exports.join(', ')}`);

  console.log('\n🎉 Basic functionality check completed successfully!');

} catch (error) {
  console.error('\n💥 Error during testing:', error.message);
  console.error('Stack trace:', error.stack);
  process.exit(1);
}
