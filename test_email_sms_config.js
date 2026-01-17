/**
 * EMAIL AND SMS CONFIGURATION TEST
 * Comprehensive testing for email and SMS services
 */

/* eslint-disable no-console */

import emailService from './services/emailService.js';
import smsService from './services/smsService.js';
import emailConfig from './config/email.js';
import smsConfig from './config/sms.js';

console.log('='.repeat(70));
console.log('EMAIL AND SMS CONFIGURATION TEST');
console.log('='.repeat(70));

const results = {
  email: {
    config: null,
    connection: null,
    send: null,
  },
  sms: {
    config: null,
    connection: null,
    send: null,
  },
};

// Test Email Configuration
async function testEmailConfig() {
  console.log('\n📧 TESTING EMAIL CONFIGURATION');
  console.log('-'.repeat(70));

  try {
    const health = emailConfig.getHealthStatus();
    console.log('\nEmail Config Status:');
    console.log(`  Provider: ${health.provider}`);
    console.log(`  Status: ${health.status}`);
    console.log(`  Configured: ${health.configured}`);
    console.log(`  From Email: ${health.fromEmail}`);
    console.log(`  Templates: ${health.templates}`);

    results.email.config = {
      success: health.status === 'configured',
      details: health,
    };

    if (health.status !== 'configured') {
      console.log('\n⚠️  Email service not fully configured');
      console.log('   Run: node scripts/configure-email-sms.js');
      return false;
    }

    console.log('\n✅ Email configuration valid');
    return true;
  } catch (error) {
    console.error('\n❌ Email configuration error:', error.message);
    results.email.config = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Test Email Connection
async function testEmailConnection() {
  console.log('\n📧 TESTING EMAIL CONNECTION');
  console.log('-'.repeat(70));

  try {
    const result = await emailService.testConnection();

    if (result.success) {
      console.log('\n✅ Email service connected successfully');
      console.log(`   Message: ${result.message}`);
      results.email.connection = { success: true };
      return true;
    } else {
      console.log('\n❌ Email connection failed');
      console.log(`   Error: ${result.error}`);
      results.email.connection = {
        success: false,
        error: result.error,
      };
      return false;
    }
  } catch (error) {
    console.error('\n❌ Email connection error:', error.message);
    results.email.connection = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Test Email Sending (Optional)
async function testEmailSending(testEmail) {
  if (!testEmail) {
    console.log('\n⏭️  Skipping email send test (no test email provided)');
    return true;
  }

  console.log('\n📧 TESTING EMAIL SENDING');
  console.log('-'.repeat(70));
  console.log(`   Sending test email to: ${testEmail}`);

  try {
    const result = await emailService.sendWelcomeEmail(testEmail, 'Test User');

    if (result.success) {
      console.log('\n✅ Test email sent successfully');
      console.log(`   Message ID: ${result.messageId}`);
      console.log(`   Template: ${result.template}`);
      results.email.send = { success: true, messageId: result.messageId };
      return true;
    } else {
      console.log('\n❌ Failed to send test email');
      results.email.send = { success: false };
      return false;
    }
  } catch (error) {
    console.error('\n❌ Email sending error:', error.message);
    results.email.send = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Test SMS Configuration
async function testSMSConfig() {
  console.log('\n📱 TESTING SMS CONFIGURATION');
  console.log('-'.repeat(70));

  try {
    const health = smsConfig.getHealthStatus();
    console.log('\nSMS Config Status:');
    console.log(`  Provider: ${health.provider}`);
    console.log(`  Status: ${health.status}`);
    console.log(`  Configured: ${health.configured}`);
    console.log(`  From Number: ${health.fromNumber}`);
    console.log(`  Templates: ${health.templates}`);

    results.sms.config = {
      success: health.status === 'configured',
      details: health,
    };

    if (health.status !== 'configured') {
      console.log('\n⚠️  SMS service not fully configured');
      console.log('   Run: node scripts/configure-email-sms.js');
      return false;
    }

    console.log('\n✅ SMS configuration valid');
    return true;
  } catch (error) {
    console.error('\n❌ SMS configuration error:', error.message);
    results.sms.config = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Test SMS Connection
async function testSMSConnection() {
  console.log('\n📱 TESTING SMS CONNECTION');
  console.log('-'.repeat(70));

  try {
    const result = await smsService.testConnection();

    if (result.success) {
      console.log('\n✅ SMS service connected successfully');
      console.log(`   Message: ${result.message}`);
      console.log(`   Provider: ${result.provider}`);
      if (result.accountStatus) {
        console.log(`   Account Status: ${result.accountStatus}`);
      }
      results.sms.connection = { success: true };
      return true;
    } else {
      console.log('\n❌ SMS connection failed');
      console.log(`   Error: ${result.error}`);
      results.sms.connection = {
        success: false,
        error: result.error,
      };
      return false;
    }
  } catch (error) {
    console.error('\n❌ SMS connection error:', error.message);
    results.sms.connection = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Test SMS Sending (Optional)
async function testSMSSending(testPhone) {
  if (!testPhone) {
    console.log('\n⏭️  Skipping SMS send test (no test phone provided)');
    return true;
  }

  console.log('\n📱 TESTING SMS SENDING');
  console.log('-'.repeat(70));
  console.log(`   Sending test SMS to: ${testPhone}`);

  try {
    const result = await smsService.sendVerificationCode(testPhone, '123456');

    if (result.success) {
      console.log('\n✅ Test SMS sent successfully');
      console.log(`   Message ID: ${result.messageId}`);
      console.log(`   Template: ${result.template}`);
      console.log(`   Provider: ${result.provider}`);
      results.sms.send = { success: true, messageId: result.messageId };
      return true;
    } else {
      console.log('\n❌ Failed to send test SMS');
      results.sms.send = { success: false };
      return false;
    }
  } catch (error) {
    console.error('\n❌ SMS sending error:', error.message);
    results.sms.send = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Display Summary
function displaySummary() {
  console.log('\n' + '='.repeat(70));
  console.log('TEST SUMMARY');
  console.log('='.repeat(70));

  console.log('\n📧 EMAIL TESTS:');
  console.log(
    `   Configuration: ${results.email.config?.success ? '✅ PASS' : '❌ FAIL'}`
  );
  console.log(
    `   Connection:    ${results.email.connection?.success ? '✅ PASS' : '❌ FAIL'}`
  );
  console.log(
    `   Sending:       ${results.email.send ? (results.email.send.success ? '✅ PASS' : '❌ FAIL') : '⏭️  SKIPPED'}`
  );

  console.log('\n📱 SMS TESTS:');
  console.log(
    `   Configuration: ${results.sms.config?.success ? '✅ PASS' : '❌ FAIL'}`
  );
  console.log(
    `   Connection:    ${results.sms.connection?.success ? '✅ PASS' : '❌ FAIL'}`
  );
  console.log(
    `   Sending:       ${results.sms.send ? (results.sms.send.success ? '✅ PASS' : '❌ FAIL') : '⏭️  SKIPPED'}`
  );

  const emailPassed =
    results.email.config?.success && results.email.connection?.success;
  const smsPassed =
    results.sms.config?.success && results.sms.connection?.success;

  console.log('\n' + '='.repeat(70));
  if (emailPassed && smsPassed) {
    console.log('✅ ALL TESTS PASSED');
  } else if (emailPassed || smsPassed) {
    console.log('⚠️  PARTIAL SUCCESS');
    if (!emailPassed) console.log('   Email service needs configuration');
    if (!smsPassed) console.log('   SMS service needs configuration');
  } else {
    console.log('❌ TESTS FAILED');
    console.log('   Run: node scripts/configure-email-sms.js');
  }
  console.log('='.repeat(70));
}

// Main Test Function
async function runTests() {
  try {
    // Get test recipients from command line args
    const args = process.argv.slice(2);
    const testEmail = args.find((arg) => arg.includes('@'));
    const testPhone = args.find((arg) => arg.startsWith('+'));

    console.log('\nTest Configuration:');
    console.log(`  Test Email: ${testEmail || 'Not provided'}`);
    console.log(`  Test Phone: ${testPhone || 'Not provided'}`);
    console.log(
      '\nNote: Provide test email/phone as arguments to test sending:'
    );
    console.log('  node test_email_sms_config.js test@example.com +1234567890');

    // Run Email Tests
    const emailConfigOk = await testEmailConfig();
    if (emailConfigOk) {
      await testEmailConnection();
      await testEmailSending(testEmail);
    }

    // Run SMS Tests
    const smsConfigOk = await testSMSConfig();
    if (smsConfigOk) {
      await testSMSConnection();
      await testSMSSending(testPhone);
    }

    // Display Summary
    displaySummary();

    // Exit with appropriate code
    const emailPassed =
      results.email.config?.success && results.email.connection?.success;
    const smsPassed =
      results.sms.config?.success && results.sms.connection?.success;

    process.exit(emailPassed && smsPassed ? 0 : 1);
  } catch (error) {
    console.error('\n❌ Test execution error:', error);
    process.exit(1);
  }
}

// Run tests
runTests();
