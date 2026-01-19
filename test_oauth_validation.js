console.log('🧪 Validating OAuth Implementation Structure...\n');

// Test 1: Check if services/plaidService.js has OAuth support
console.log('Test 1: Checking plaidService.js for OAuth parameters...');
try {
  const fs = require('fs');
  const path = require('path');

  const servicePath = path.join(__dirname, 'services', 'plaidService.js');
  const serviceContent = fs.readFileSync(servicePath, 'utf8');

  if (serviceContent.includes('oauth:') && serviceContent.includes('redirect_uri:')) {
    console.log('✅ plaidService.js includes OAuth parameters');
  } else {
    console.log('❌ plaidService.js missing OAuth parameters');
  }

  if (serviceContent.includes('createLinkToken') && serviceContent.includes('oauthOptions')) {
    console.log('✅ createLinkToken method accepts OAuth options');
  } else {
    console.log('❌ createLinkToken method missing OAuth options parameter');
  }
} catch (error) {
  console.log('❌ Error reading plaidService.js:', error.message);
}

// Test 2: Check if routes/plaidRoutes.js has OAuth support
console.log('\nTest 2: Checking routes/plaidRoutes.js for OAuth parameters...');
try {
  const fs = require('fs');
  const path = require('path');

  const routesPath = path.join(__dirname, 'routes', 'plaidRoutes.js');
  const routesContent = fs.readFileSync(routesPath, 'utf8');

  if (routesContent.includes('oauth') && routesContent.includes('redirectUri')) {
    console.log('✅ routes/plaidRoutes.js includes OAuth parameter handling');
  } else {
    console.log('❌ routes/plaidRoutes.js missing OAuth parameter handling');
  }

  if (routesContent.includes('/oauth/redirect')) {
    console.log('✅ OAuth redirect route exists');
  } else {
    console.log('❌ OAuth redirect route missing');
  }
} catch (error) {
  console.log('❌ Error reading routes/plaidRoutes.js:', error.message);
}

// Test 3: Check if frontend component has OAuth support
console.log('\nTest 3: Checking frontend PlaidLink component for OAuth support...');
try {
  const fs = require('fs');
  const path = require('path');

  const componentPath = path.join(__dirname, 'earnings_dashboard', 'src', 'PlaidLink.jsx');
  const componentContent = fs.readFileSync(componentPath, 'utf8');

  if (componentContent.includes('oauth') && componentContent.includes('redirectUri')) {
    console.log('✅ Frontend component includes OAuth props');
  } else {
    console.log('❌ Frontend component missing OAuth props');
  }

  if (componentContent.includes('oauth/redirect') || componentContent.includes('oauth/success')) {
    console.log('✅ Frontend handles OAuth redirects');
  } else {
    console.log('❌ Frontend missing OAuth redirect handling');
  }
} catch (error) {
  console.log('❌ Error reading PlaidLink.jsx:', error.message);
}

// Test 4: Check README for OAuth documentation
console.log('\nTest 4: Checking README for OAuth documentation...');
try {
  const fs = require('fs');
  const path = require('path');

  const readmePath = path.join(__dirname, 'PLAID_INTEGRATION_README.md');
  const readmeContent = fs.readFileSync(readmePath, 'utf8');

  if (readmeContent.includes('OAuth') || readmeContent.includes('oauth')) {
    console.log('✅ README includes OAuth documentation');
  } else {
    console.log('❌ README missing OAuth documentation');
  }
} catch (error) {
  console.log('❌ Error reading README:', error.message);
}

// Test 5: Environment variable validation
console.log('\nTest 5: Environment configuration validation...');
const requiredEnvVars = ['PLAID_CLIENT_ID', 'PLAID_SECRET', 'PLAID_ENV'];
const optionalEnvVars = ['FRONTEND_URL'];

requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    console.log(`⚠️  Warning: Required environment variable ${varName} not set`);
  } else {
    console.log(`✅ ${varName} is configured`);
  }
});

optionalEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    console.log(`ℹ️  Info: Optional environment variable ${varName} not set`);
  } else {
    console.log(`✅ ${varName} is configured`);
  }
});

console.log('\n🎉 OAuth implementation validation complete!');
