console.log('🧪 Testing JPMorgan Payments module loading...');

try {
  // Test if the module can be required
  const jpmorganPayment = require('./earnings_dashboard/jpmorgan_payment');
  console.log('✅ JPMorgan Payments module loaded successfully');
  
  // Test if it's a router
  if (typeof jpmorganPayment === 'function') {
    console.log('✅ Module exports a function (router)');
  } else {
    console.log('❌ Module does not export a function');
  }
  
  // Test if it has expected properties
  if (jpmorganPayment && typeof jpmorganPayment === 'object') {
    console.log('✅ Module exports an object with expected structure');
  }
  
  console.log('\n📋 Module structure:');
  console.log('- Type:', typeof jpmorganPayment);
  console.log('- Properties:', Object.keys(jpmorganPayment).join(', '));
  
} catch (error) {
  console.error('❌ Failed to load JPMorgan Payments module:', error.message);
  console.error('Stack:', error.stack);
}
