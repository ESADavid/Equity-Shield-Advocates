# Email and SMS Configuration Guide

Complete guide for configuring email and SMS services in the Oscar Broome Revenue System.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Email Configuration](#email-configuration)
4. [SMS Configuration](#sms-configuration)
5. [Testing](#testing)
6. [Troubleshooting](#troubleshooting)
7. [API Usage](#api-usage)

---

## Overview

The Oscar Broome Revenue System supports multiple email and SMS providers:

### Email Providers

- **SendGrid** - Recommended for production
- **AWS SES** - Good for AWS-hosted applications
- **SMTP** - Universal fallback (Gmail, Outlook, etc.)

### SMS Providers

- **Twilio** - Recommended for production
- **AWS SNS** - Good for AWS-hosted applications
- **Nexmo/Vonage** - Alternative SMS provider

---

## Quick Start

### Option 1: Interactive Configuration (Recommended)

Run the configuration wizard:

```bash
node scripts/configure-email-sms.js
```

This will guide you through setting up email and SMS services interactively.

### Option 2: Manual Configuration

1. Copy the example environment file:

```bash
cp .env.example .env
```

1. Edit `.env` and add your credentials (see sections below)

2. Test your configuration:

```bash
node test_email_sms_config.js
```

---

## Email Configuration

### SendGrid Setup (Recommended)

1. **Create SendGrid Account**
   - Go to [SendGrid](https://sendgrid.com/)
   - Sign up for a free account (100 emails/day)

2. **Get API Key**
   - Navigate to Settings → API Keys
   - Click "Create API Key"
   - Give it "Full Access" permissions
   - Copy the API key

3. **Configure Environment Variables**

```env
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=SG.your_api_key_here
EMAIL_FROM=noreply@yourdomain.com
EMAIL_FROM_NAME=Your Company Name
```

1. **Verify Sender**
   - Go to Settings → Sender Authentication
   - Verify your sender email address
   - Or set up domain authentication for production

### AWS SES Setup

1. **Create AWS Account**
   - Go to [AWS Console](https://aws.amazon.com/)
   - Navigate to SES (Simple Email Service)

2. **Verify Email/Domain**
   - Verify your sender email or domain
   - Request production access (starts in sandbox mode)

3. **Create IAM User**
   - Create IAM user with SES permissions

   - Generate access keys

4. **Configure Environment Variables**

```env
EMAIL_PROVIDER=ses
AWS_SES_ACCESS_KEY_ID=your_access_key
AWS_SES_SECRET_ACCESS_KEY=your_secret_key
AWS_SES_REGION=us-east-1
EMAIL_FROM=noreply@yourdomain.com
EMAIL_FROM_NAME=Your Company Name
```

### SMTP Setup (Gmail Example)

1. **Enable 2-Factor Authentication**
   - Go to Google Account settings
   - Enable 2FA

2. **Generate App Password**

   - Go to Security → App passwords
   - Generate password for "Mail"

3. **Configure Environment Variables**

```env
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your.email@gmail.com
SMTP_PASS=your_app_password
SMTP_SECURE=false
EMAIL_FROM=your.email@gmail.com
EMAIL_FROM_NAME=Your Company Name
```

**Note:** Gmail has sending limits (500 emails/day for free accounts)

---

## SMS Configuration

### Twilio Setup (Recommended)

1. **Create Twilio Account**
   - Go to [Twilio](https://www.twilio.com/)
   - Sign up for a free trial ($15 credit)

2. **Get Credentials**
   - From Console Dashboard, copy:
     - Account SID
     - Auth Token

3. **Get Phone Number**

   - Go to Phone Numbers → Buy a Number
   - Choose a number with SMS capabilities
   - Or use trial number for testing

4. **Configure Environment Variables**

```env
SMS_PROVIDER=twilio

TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=+1234567890
```

**Trial Limitations:**

- Can only send to verified numbers
- Messages include "Sent from a Twilio trial account"
- Upgrade to remove limitations

### AWS SNS Setup

1. **Create AWS Account**
   - Navigate to SNS (Simple Notification Service)

2. **Enable SMS**
   - Go to SNS → Text messaging (SMS)

   - Set up SMS preferences

3. **Create IAM User**
   - Create IAM user with SNS permissions
   - Generate access keys

4. **Configure Environment Variables**

```env
SMS_PROVIDER=aws-sns
AWS_SNS_ACCESS_KEY_ID=your_access_key
AWS_SNS_SECRET_ACCESS_KEY=your_secret_key
AWS_SNS_REGION=us-east-1
```

### Nexmo/Vonage Setup

1. **Create Vonage Account**
   - Go to [Vonage API](https://www.vonage.com/)

   - Sign up for account

2. **Get Credentials**
   - From Dashboard, copy:
     - API Key
     - API Secret

3. **Configure Environment Variables**

```env
SMS_PROVIDER=nexmo
NEXMO_API_KEY=your_api_key
NEXMO_API_SECRET=your_api_secret
NEXMO_FROM_NUMBER=YourCompany
```

---

## Testing

### Test Email Configuration

```javascript
import emailService from './services/emailService.js';

// Test connection
const result = await emailService.testConnection();
console.log(result);

// Send test email
await emailService.sendWelcomeEmail(
  'test@example.com',
  'John'
);
```

### Test SMS Configuration

```javascript
import smsService from './services/smsService.js';

// Test connection
const result = await smsService.testConnection();
console.log(result);

// Send test SMS
await smsService.sendVerificationCode(
  '+1234567890',
  '123456'
);
```

### Run Comprehensive Tests

```bash
node test_email_sms_config.js

```

---

## Troubleshooting

### Email Issues

#### Problem: "Email service not configured"

- Check that all required environment variables are set
- Verify EMAIL_PROVIDER matches your configuration
- Check logs in `logs/email-service-error.log`

#### Problem: "Authentication failed"

- Verify API key/credentials are correct
- For Gmail: Ensure you're using App Password, not regular password

- For SendGrid: Check API key has correct permissions

#### Problem: Emails not being received

- Check spam folder

- Verify sender email is verified with provider
- Check provider's sending limits
- Review provider dashboard for bounces/blocks

### SMS Issues

#### Problem: "SMS service not configured"

- Check that all required environment variables are set
- Verify SMS_PROVIDER matches your configuration
- Check logs in `logs/sms-service-error.log`

#### Problem: "Unable to create record" (Twilio)

- Verify phone number format includes country code (+1234567890)
- For trial accounts: Verify recipient number in Twilio console
- Check account balance

#### Problem: SMS not being received

- Verify phone number format
- Check carrier restrictions
- Review provider dashboard for delivery status
- Some carriers block automated messages

### General Issues

#### Problem: Services not initializing

```bash
# Check configuration status
node -e "import emailService from './services/emailService.js'; console.log(emailService.getHealthStatus())"
node -e "import smsService from './services/smsService.js'; console.log(smsService.getHealthStatus())"
```

#### Problem: Environment variables not loading

- Ensure `.env` file is in project root
- Check file encoding (should be UTF-8)
- Restart application after changing `.env`

---

## API Usage

### Email Service API

```javascript
import emailService from './services/emailService.js';

// Send welcome email
await emailService.sendWelcomeEmail(email, firstName);

// Send password reset
await emailService.sendPasswordResetEmail(email, firstName, resetToken);

// Send custom email
await emailService.sendCustomEmail(
  'user@example.com',
  'Subject Line',
  '<h1>HTML Content</h1>'
);

// Get health status
const health = emailService.getHealthStatus();
```

### SMS Service API

```javascript
import smsService from './services/smsService.js';

// Send verification code
await smsService.sendVerificationCode(phoneNumber, code);

// Send 2FA code
await smsService.sendTwoFactorCode(phoneNumber, code);

// Send payment notification
await smsService.sendPaymentNotification(phoneNumber, amount, reference);

// Send custom SMS
await smsService.sendCustomSMS(phoneNumber, message);

// Send bulk SMS
await smsService.sendBulkSMS([
  { phoneNumber: '+1234567890', data: { name: 'John' } },
  { phoneNumber: '+0987654321', data: { name: 'Jane' } }
], 'template-name', { commonData: 'value' });

// Get delivery status
const status = smsService.getDeliveryStatus(messageId);

// Get statistics
const stats = smsService.getStatistics();
```

### Multi-Channel Notifications

```javascript
import MultiChannelNotificationService from './services/multiChannelNotificationService.js';

const notificationService = new MultiChannelNotificationService();

// Send multi-channel notification
await notificationService.sendNotification({
  userId: 'user123',
  templateId: 'ubi-payment-success',
  channels: ['email', 'sms', 'push'],
  data: {
    citizenName: 'John Doe',
    paymentAmount: '1000',
    paymentDate: '2024-01-15',
    reference: 'PAY-123456'
  }
});

// Update user preferences
notificationService.updatePreferences('user123', {
  email: true,
  sms: true,
  push: false,
  inApp: true
});

// Get notification history
const history = notificationService.getNotificationHistory('user123', {
  status: 'sent',
  limit: 50
});
```

---

## Production Checklist

Before deploying to production:

### Email

- [ ] Verify sender domain (not just email)
- [ ] Set up SPF, DKIM, and DMARC records
- [ ] Request production access (if using AWS SES)
- [ ] Set up bounce and complaint handling
- [ ] Configure rate limits
- [ ] Test all email templates
- [ ] Set up monitoring and alerts

### SMS

- [ ] Upgrade from trial account
- [ ] Register business/brand
- [ ] Set up opt-in/opt-out handling
- [ ] Comply with TCPA regulations (US)
- [ ] Configure rate limits
- [ ] Test all SMS templates
- [ ] Set up monitoring and alerts
- [ ] Budget for SMS costs

### Security

- [ ] Store credentials in secure vault (not .env in production)
- [ ] Use environment-specific credentials
- [ ] Enable 2FA on provider accounts

- [ ] Set up IP whitelisting where available
- [ ] Regular credential rotation
- [ ] Monitor for suspicious activity

---

## Cost Estimates

### Email Providers

#### SendGrid

- Free: 100 emails/day
- Essentials: $19.95/month (50,000 emails)
- Pro: $89.95/month (100,000 emails)

**AWS SES**

- $0.10 per 1,000 emails

- First 62,000 emails free (if sent from EC2)

#### SMTP (Gmail)

- Free: 500 emails/day
- Google Workspace: 2,000 emails/day

### SMS Providers

#### Twilio

- US: $0.0079 per SMS
- International: varies by country
- Phone number: $1.15/month

**AWS SNS**

- US: $0.00645 per SMS
- International: varies by country

**Nexmo/Vonage**

- US: $0.0076 per SMS
- International: varies by country

---

## Support

For issues or questions:

1. Check logs in `logs/` directory
2. Review this documentation
3. Check provider documentation:
   - [SendGrid Docs](https://docs.sendgrid.com/)
   - [Twilio Docs](https://www.twilio.com/docs)
   - [AWS SES Docs](https://docs.aws.amazon.com/ses/)
   - [AWS SNS Docs](https://docs.aws.amazon.com/sns/)

4. Contact system administrator

---

## Additional Resources

- [Email Best Practices](https://sendgrid.com/blog/email-best-practices/)
- [SMS Compliance Guide](https://www.twilio.com/learn/sms/sms-compliance)
- [TCPA Compliance](https://www.fcc.gov/general/telemarketing-and-robocalls)
- [CAN-SPAM Act](https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business)

---

**Last Updated:** 2024-01-15
**Version:** 1.0.0
