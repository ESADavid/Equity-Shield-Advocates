import emailConfig from './config/email.js';
import emailService from './services/emailService.js';

console.log('🧪 Testing Email Configuration...\n');

// Test 1: Email Config Validation
console.log('1. Testing Email Configuration:');
const configHealth = emailConfig.getHealthStatus();
console.log('   Provider:', configHealth.provider);
console.log('   Configured Fields:', configHealth.configured);
console.log('   Status:', configHealth.status);
console.log('   From Email:', configHealth.fromEmail);
console.log('   Templates:', configHealth.templates);
console.log('   Email Enabled:', emailConfig.emailEnabled ? '✅ YES' : '❌ NO');
console.log();

// Test 2: Email Service Health
console.log('2. Testing Email Service:');
const serviceHealth = emailService.getHealthStatus();
console.log('   Service:', serviceHealth.service);
console.log('   Transporter:', serviceHealth.transporter);
console.log('   Templates Loaded:', serviceHealth.templates);
console.log('   Config Status:', JSON.stringify(serviceHealth.config, null, 2));
console.log();

// Test 3: Template Loading
console.log('3. Testing Email Templates:');
const templates = ['password-reset', 'welcome'];
templates.forEach((template) => {
  const templateData = emailService.templates.get(template);
  if (templateData) {
    console.log(`   ✅ Template '${template}' loaded:`, templateData.subject);
  } else {
    console.log(`   ❌ Template '${template}' not found`);
  }
});
console.log();

// Test 4: Environment Variables
console.log('4. Testing Environment Variables:');
console.log('   EMAIL_PROVIDER:', process.env.EMAIL_PROVIDER || 'not set');
console.log('   EMAIL_FROM:', process.env.EMAIL_FROM || 'not set');
console.log(
  '   SENDGRID_API_KEY:',
  process.env.SENDGRID_API_KEY ? 'set (hidden)' : 'not set'
);
console.log('   SMTP_HOST:', process.env.SMTP_HOST || 'not set');
console.log('   SMTP_USER:', process.env.SMTP_USER || 'not set');
console.log();

// Test 5: Connection Test (if enabled)
console.log('5. Testing Email Connection:');
if (emailConfig.emailEnabled && emailService.transporter) {
  emailService
    .testConnection()
    .then((result) => {
      console.log(
        '   Connection Test:',
        result.success ? '✅ SUCCESS' : '❌ FAILED'
      );
      if (!result.success) {
        console.log('   Error:', result.error);
      }
      console.log('\n🎯 Email Configuration Test Complete!');
    })
    .catch((error) => {
      console.log('   Connection Test: ❌ ERROR -', error.message);
      console.log('\n🎯 Email Configuration Test Complete!');
    });
} else {
  console.log('   Connection Test: ⏭️  SKIPPED (Email service disabled)');
  console.log('\n🎯 Email Configuration Test Complete!');
  console.log('\n💡 To enable email functionality:');
  console.log('   1. Set a valid SENDGRID_API_KEY in .env');
  console.log('   2. Or configure SMTP/AWS SES credentials');
  console.log('   3. Restart the server');
}
