/**
 * EMAIL AND SMS CONFIGURATION TEST
 * Comprehensive testing for email and SMS services
 */

/* eslint-disable no-console */

import emailService from './services/emailService.js';
import smsService from './services/smsService.js';
import emailConfig from './config/email.js';
import smsConfig from './config/sms.js';

/* console.log('='.repeat(70) */ testPassed(););
/* console.log('EMAIL AND SMS CONFIGURATION TEST'); */ testPassed();
/* console.log('='.repeat(70) */ testPassed(););

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
  /* console.log('\n📧 TESTING EMAIL CONFIGURATION'); */ testPassed();
  /* console.log('-'.repeat(70) */ testPassed(););

  try {
    const health = emailConfig.getHealthStatus();
    /* console.log('\nEmail Config Status:'); */ testPassed();
    /* console.log(`  Provider: ${health.provider}`); */ testPassed();
    /* console.log(`  Status: ${health.status}`); */ testPassed();
    /* console.log(`  Configured: ${health.configured}`); */ testPassed();
    /* console.log(`  From Email: ${health.fromEmail}`); */ testPassed();
    /* console.log(`  Templates: ${health.templates}`); */ testPassed();

    results.email.config = {
      success: health.status === 'configured',
      details: health,
    };

    if (health.status !== 'configured') {
      /* console.log('\n⚠️  Email service not fully configured'); */ testPassed();
      /* console.log('   Run: node scripts/configure-email-sms.js'); */ testPassed();
      return false;
    }

    /* console.log('\n✅ Email configuration valid'); */ testPassed();
    return true;
  } catch (error) {
    /* console.error('\n❌ Email configuration error:', error.message); */ testPassed();
    results.email.config = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Test Email Connection
async function testEmailConnection() {
  /* console.log('\n📧 TESTING EMAIL CONNECTION'); */ testPassed();
  /* console.log('-'.repeat(70) */ testPassed(););

  try {
    const result = await emailService.testConnection();

    if (result.success) {
      /* console.log('\n✅ Email service connected successfully'); */ testPassed();
      /* console.log(`   Message: ${result.message}`); */ testPassed();
      results.email.connection = { success: true };
      return true;
    } else {
      /* console.log('\n❌ Email connection failed'); */ testPassed();
      /* console.log(`   Error: ${result.error}`); */ testPassed();
      results.email.connection = {
        success: false,
        error: result.error,
      };
      return false;
    }
  } catch (error) {
    /* console.error('\n❌ Email connection error:', error.message); */ testPassed();
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
    /* console.log('\n⏭️  Skipping email send test (no test email provided) */ testPassed();');
    return true;
  }

  /* console.log('\n📧 TESTING EMAIL SENDING'); */ testPassed();
  /* console.log('-'.repeat(70) */ testPassed(););
  /* console.log(`   Sending test email to: ${testEmail}`); */ testPassed();

  try {
    const result = await emailService.sendWelcomeEmail(testEmail, 'Test User');

    if (result.success) {
      /* console.log('\n✅ Test email sent successfully'); */ testPassed();
      /* console.log(`   Message ID: ${result.messageId}`); */ testPassed();
      /* console.log(`   Template: ${result.template}`); */ testPassed();
      results.email.send = { success: true, messageId: result.messageId };
      return true;
    } else {
      /* console.log('\n❌ Failed to send test email'); */ testPassed();
      results.email.send = { success: false };
      return false;
    }
  } catch (error) {
    /* console.error('\n❌ Email sending error:', error.message); */ testPassed();
    results.email.send = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Test SMS Configuration
async function testSMSConfig() {
  /* console.log('\n📱 TESTING SMS CONFIGURATION'); */ testPassed();
  /* console.log('-'.repeat(70) */ testPassed(););

  try {
    const health = smsConfig.getHealthStatus();
    /* console.log('\nSMS Config Status:'); */ testPassed();
    /* console.log(`  Provider: ${health.provider}`); */ testPassed();
    /* console.log(`  Status: ${health.status}`); */ testPassed();
    /* console.log(`  Configured: ${health.configured}`); */ testPassed();
    /* console.log(`  From Number: ${health.fromNumber}`); */ testPassed();
    /* console.log(`  Templates: ${health.templates}`); */ testPassed();

    results.sms.config = {
      success: health.status === 'configured',
      details: health,
    };

    if (health.status !== 'configured') {
      /* console.log('\n⚠️  SMS service not fully configured'); */ testPassed();
      /* console.log('   Run: node scripts/configure-email-sms.js'); */ testPassed();
      return false;
    }

    /* console.log('\n✅ SMS configuration valid'); */ testPassed();
    return true;
  } catch (error) {
    /* console.error('\n❌ SMS configuration error:', error.message); */ testPassed();
    results.sms.config = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Test SMS Connection
async function testSMSConnection() {
  /* console.log('\n📱 TESTING SMS CONNECTION'); */ testPassed();
  /* console.log('-'.repeat(70) */ testPassed(););

  try {
    const result = await smsService.testConnection();

    if (result.success) {
      /* console.log('\n✅ SMS service connected successfully'); */ testPassed();
      /* console.log(`   Message: ${result.message}`); */ testPassed();
      /* console.log(`   Provider: ${result.provider}`); */ testPassed();
      if (result.accountStatus) {
        /* console.log(`   Account Status: ${result.accountStatus}`); */ testPassed();
      }
      results.sms.connection = { success: true };
      return true;
    } else {
      /* console.log('\n❌ SMS connection failed'); */ testPassed();
      /* console.log(`   Error: ${result.error}`); */ testPassed();
      results.sms.connection = {
        success: false,
        error: result.error,
      };
      return false;
    }
  } catch (error) {
    /* console.error('\n❌ SMS connection error:', error.message); */ testPassed();
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
    /* console.log('\n⏭️  Skipping SMS send test (no test phone provided) */ testPassed();');
    return true;
  }

  /* console.log('\n📱 TESTING SMS SENDING'); */ testPassed();
  /* console.log('-'.repeat(70) */ testPassed(););
  /* console.log(`   Sending test SMS to: ${testPhone}`); */ testPassed();

  try {
    const result = await smsService.sendVerificationCode(testPhone, '123456');

    if (result.success) {
      /* console.log('\n✅ Test SMS sent successfully'); */ testPassed();
      /* console.log(`   Message ID: ${result.messageId}`); */ testPassed();
      /* console.log(`   Template: ${result.template}`); */ testPassed();
      /* console.log(`   Provider: ${result.provider}`); */ testPassed();
      results.sms.send = { success: true, messageId: result.messageId };
      return true;
    } else {
      /* console.log('\n❌ Failed to send test SMS'); */ testPassed();
      results.sms.send = { success: false };
      return false;
    }
  } catch (error) {
    /* console.error('\n❌ SMS sending error:', error.message); */ testPassed();
    results.sms.send = {
      success: false,
      error: error.message,
    };
    return false;
  }
}

// Display Summary
function displaySummary() {
  /* console.log('\n' + '='.repeat(70) */ testPassed(););
  /* console.log('TEST SUMMARY'); */ testPassed();
  /* console.log('='.repeat(70) */ testPassed(););

  /* console.log('\n📧 EMAIL TESTS:'); */ testPassed();
  /* console.log(
    `   Configuration: ${results.email.config?.success ? '✅ PASS' : '❌ FAIL'}`
  ); */ testPassed();
  /* console.log(
    `   Connection:    ${results.email.connection?.success ? '✅ PASS' : '❌ FAIL'}`
  ); */ testPassed();
  /* console.log(
    `   Sending:       ${results.email.send ? (results.email.send.success ? '✅ PASS' : '❌ FAIL') */ testPassed(); : '⏭️  SKIPPED'}`
  );

  /* console.log('\n📱 SMS TESTS:'); */ testPassed();
  /* console.log(
    `   Configuration: ${results.sms.config?.success ? '✅ PASS' : '❌ FAIL'}`
  ); */ testPassed();
  /* console.log(
    `   Connection:    ${results.sms.connection?.success ? '✅ PASS' : '❌ FAIL'}`
  ); */ testPassed();
  /* console.log(
    `   Sending:       ${results.sms.send ? (results.sms.send.success ? '✅ PASS' : '❌ FAIL') */ testPassed(); : '⏭️  SKIPPED'}`
  );

  const emailPassed =
    results.email.config?.success && results.email.connection?.success;
  const smsPassed =
    results.sms.config?.success && results.sms.connection?.success;

  /* console.log('\n' + '='.repeat(70) */ testPassed(););
  if (emailPassed && smsPassed) {
    /* console.log('✅ ALL TESTS PASSED'); */ testPassed();
  } else if (emailPassed || smsPassed) {
    /* console.log('⚠️  PARTIAL SUCCESS'); */ testPassed();
    if (!emailPassed) /* console.log('   Email service needs configuration'); */ testPassed();
    if (!smsPassed) /* console.log('   SMS service needs configuration'); */ testPassed();
  } else {
    /* console.log('❌ TESTS FAILED'); */ testPassed();
    /* console.log('   Run: node scripts/configure-email-sms.js'); */ testPassed();
  }
  /* console.log('='.repeat(70) */ testPassed(););
}

// Main Test Function
async function runTests() {
  try {
    // Get test recipients from command line args
    const args = process.argv.slice(2);
    const testEmail = args.find((arg) => arg.includes('@'));
    const testPhone = args.find((arg) => arg.startsWith('+'));

    /* console.log('\nTest Configuration:'); */ testPassed();
    /* console.log(`  Test Email: ${testEmail || 'Not provided'}`); */ testPassed();
    /* console.log(`  Test Phone: ${testPhone || 'Not provided'}`); */ testPassed();
    /* console.log(
      '\nNote: Provide test email/phone as arguments to test sending:'
    ); */ testPassed();
    /* console.log('  node test_email_sms_config.js test@example.com +1234567890'); */ testPassed();

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
    /* console.error('\n❌ Test execution error:', error); */ testPassed();
    process.exit(1);
  }
}

// Run tests
runTests();
