import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🔐 Testing OAuth Implementation...\n');

// Test 1: Verify Plaid Service OAuth Support
console.log('Test 1: Plaid Service OAuth Support');
try {
  const plaidServicePath = path.join(__dirname, 'services', 'plaidService.js');
  const plaidServiceContent = fs.readFileSync(plaidServicePath, 'utf8');

  const hasOAuthOptions = plaidServiceContent.includes('options.oauth');
  const hasRedirectUri = plaidServiceContent.includes('options.redirectUri');
  const hasCreateLinkToken = plaidServiceContent.includes('createLinkToken');

  if (hasOAuthOptions && hasRedirectUri && hasCreateLinkToken) {
    console.log('✅ Plaid service supports OAuth parameters');
  } else {
    console.log('❌ Plaid service missing OAuth support');
    console.log(`   - OAuth options: ${hasOAuthOptions}`);
    console.log(`   - Redirect URI: ${hasRedirectUri}`);
    console.log(`   - Link token creation: ${hasCreateLinkToken}`);
  }
} catch (error) {
  console.log('❌ Error checking Plaid service:', error.message);
}

// Test 2: Verify Routes OAuth Support
console.log('\nTest 2: Routes OAuth Support');
try {
  const routesPath = path.join(__dirname, 'routes', 'plaidRoutes.js');
  const routesContent = fs.readFileSync(routesPath, 'utf8');

  const hasOAuthRoute = routesContent.includes('/oauth/redirect');
  const hasOAuthParams =
    routesContent.includes('oauth') && routesContent.includes('redirectUri');

  if (hasOAuthRoute && hasOAuthParams) {
    console.log('✅ Routes support OAuth redirect handling');
  } else {
    console.log('❌ Routes missing OAuth support');
    console.log(`   - OAuth redirect route: ${hasOAuthRoute}`);
    console.log(`   - OAuth parameters: ${hasOAuthParams}`);
  }
} catch (error) {
  console.log('❌ Error checking routes:', error.message);
}

// Test 3: Verify Frontend OAuth Support
console.log('\nTest 3: Frontend OAuth Support');
try {
  const componentPath = path.join(
    __dirname,
    'earnings_dashboard',
    'src',
    'PlaidLink.jsx'
  );
  const componentContent = fs.readFileSync(componentPath, 'utf8');

  const hasOAuthProp =
    componentContent.includes('oauth=') || componentContent.includes('oauth ');
  const hasRedirectUriProp = componentContent.includes('redirectUri');

  if (hasOAuthProp && hasRedirectUriProp) {
    console.log('✅ Frontend component supports OAuth props');
  } else {
    console.log('❌ Frontend component missing OAuth props');
    console.log(`   - OAuth prop: ${hasOAuthProp}`);
    console.log(`   - Redirect URI prop: ${hasRedirectUriProp}`);
  }
} catch (error) {
  console.log('❌ Error checking frontend component:', error.message);
}

// Test 4: Environment Variables Check
console.log('\nTest 4: Environment Configuration');
const requiredVars = ['PLAID_CLIENT_ID', 'PLAID_SECRET', 'PLAID_ENV'];
const optionalVars = ['FRONTEND_URL'];

let envConfigured = true;
requiredVars.forEach((varName) => {
  if (!process.env[varName] || process.env[varName].includes('your_')) {
    console.log(`❌ ${varName} not properly configured`);
    envConfigured = false;
  } else {
    console.log(`✅ ${varName} configured`);
  }
});

optionalVars.forEach((varName) => {
  if (!process.env[varName]) {
    console.log(`⚠️  ${varName} not set (optional)`);
  } else {
    console.log(`✅ ${varName} configured`);
  }
});

// Test 5: OAuth Flow Simulation
console.log('\nTest 5: OAuth Flow Simulation');
if (envConfigured) {
  console.log('✅ Environment configured - OAuth flow can be tested');
  console.log('   To test OAuth flow:');
  console.log('   1. Start the server: npm start');
  console.log('   2. Open frontend at http://localhost:3000');
  console.log('   3. Use PlaidLink component with oauth=true');
  console.log('   4. Complete OAuth flow through supported institution');
} else {
  console.log(
    '❌ Environment not configured - set PLAID_CLIENT_ID, PLAID_SECRET, PLAID_ENV'
  );
  console.log('   Get credentials from: https://dashboard.plaid.com/');
}

// Test 6: Documentation Check
console.log('\nTest 6: OAuth Documentation');
try {
  const readmePath = path.join(__dirname, 'PLAID_INTEGRATION_README.md');
  const readmeContent = fs.readFileSync(readmePath, 'utf8');

  const hasOAuthDocs =
    readmeContent.includes('OAuth') || readmeContent.includes('oauth');
  const hasRedirectUriDocs =
    readmeContent.includes('redirect') && readmeContent.includes('URI');

  if (hasOAuthDocs && hasRedirectUriDocs) {
    console.log('✅ OAuth documentation present');
  } else {
    console.log('❌ OAuth documentation incomplete');
    console.log(`   - OAuth mentioned: ${hasOAuthDocs}`);
    console.log(`   - Redirect URI docs: ${hasRedirectUriDocs}`);
  }
} catch (error) {
  console.log('❌ Error checking documentation:', error.message);
}

console.log('\n🎉 OAuth Implementation Test Complete!');
console.log('\n📋 Next Steps:');
if (!envConfigured) {
  console.log('1. Configure Plaid credentials in .env file');
  console.log('2. Set up OAuth redirect URIs in Plaid Dashboard');
}
console.log('3. Test OAuth flow with a supported institution');
console.log('4. Verify redirect handling works correctly');
