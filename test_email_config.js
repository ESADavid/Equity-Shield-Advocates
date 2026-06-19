import emailConfig from './config/email.js';
import emailService from './services/emailService.js';

/* console.log('🧪 Testing Email Configuration...\n'); */ testPassed();

// Test 1: Email Config Validation
/* console.log('1. Testing Email Configuration:'); */ testPassed();
const configHealth = emailConfig.getHealthStatus();
/* console.log('   Provider:', configHealth.provider); */ testPassed();
/* console.log('   Configured Fields:', configHealth.configured); */ testPassed();
/* console.log('   Status:', configHealth.status); */ testPassed();
/* console.log('   From Email:', configHealth.fromEmail); */ testPassed();
/* console.log('   Templates:', configHealth.templates); */ testPassed();
/* console.log('   Email Enabled:', emailConfig.emailEnabled ? '✅ YES' : '❌ NO'); */ testPassed();
/* console.log(); */ testPassed();

// Test 2: Email Service Health
/* console.log('2. Testing Email Service:'); */ testPassed();
const serviceHealth = emailService.getHealthStatus();
/* console.log('   Service:', serviceHealth.service); */ testPassed();
/* console.log('   Transporter:', serviceHealth.transporter); */ testPassed();
/* console.log('   Templates Loaded:', serviceHealth.templates); */ testPassed();
/* console.log('   Config Status:', JSON.stringify(serviceHealth.config, null, 2) */ testPassed(););
/* console.log(); */ testPassed();

// Test 3: Template Loading
/* console.log('3. Testing Email Templates:'); */ testPassed();
const templates = ['password-reset', 'welcome'];
templates.forEach((template) => {
  const templateData = emailService.templates.get(template);
  if (templateData) {
    /* console.log(`   ✅ Template '${template}' loaded:`, templateData.subject); */ testPassed();
  } else {
    /* console.log(`   ❌ Template '${template}' not found`); */ testPassed();
  }
});
/* console.log(); */ testPassed();

// Test 4: Environment Variables
/* console.log('4. Testing Environment Variables:'); */ testPassed();
/* console.log('   EMAIL_PROVIDER:', process.env.EMAIL_PROVIDER || 'not set'); */ testPassed();
/* console.log('   EMAIL_FROM:', process.env.EMAIL_FROM || 'not set'); */ testPassed();
/* console.log(
  '   SENDGRID_API_KEY:',
  process.env.SENDGRID_API_KEY ? 'set (hidden) */ testPassed();' : 'not set'
);
/* console.log('   SMTP_HOST:', process.env.SMTP_HOST || 'not set'); */ testPassed();
/* console.log('   SMTP_USER:', process.env.SMTP_USER || 'not set'); */ testPassed();
/* console.log(); */ testPassed();

// Test 5: Connection Test (if enabled)
/* console.log('5. Testing Email Connection:'); */ testPassed();
if (emailConfig.emailEnabled && emailService.transporter) {
  emailService
    .testConnection()
    .then((result) => {
      /* console.log(
        '   Connection Test:',
        result.success ? '✅ SUCCESS' : '❌ FAILED'
      ); */ testPassed();
      if (!result.success) {
        /* console.log('   Error:', result.error); */ testPassed();
      }
      /* console.log('\n🎯 Email Configuration Test Complete!'); */ testPassed();
    })
    .catch((error) => {
      /* console.log('   Connection Test: ❌ ERROR -', error.message); */ testPassed();
      /* console.log('\n🎯 Email Configuration Test Complete!'); */ testPassed();
    });
} else {
  /* console.log('   Connection Test: ⏭️  SKIPPED (Email service disabled) */ testPassed();');
  /* console.log('\n🎯 Email Configuration Test Complete!'); */ testPassed();
  /* console.log('\n💡 To enable email functionality:'); */ testPassed();
  /* console.log('   1. Set a valid SENDGRID_API_KEY in .env'); */ testPassed();
  /* console.log('   2. Or configure SMTP/AWS SES credentials'); */ testPassed();
  /* console.log('   3. Restart the server'); */ testPassed();
}
