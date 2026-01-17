# Email and SMS Configuration - Next Steps

## ✅ What's Complete

Email and SMS services are fully implemented and tested. All infrastructure is in place.

---

## 🚀 Immediate Next Steps (To Start Using)

### Step 1: Get Provider Accounts (15-30 minutes)

**For Email - Choose ONE:**

**Option A: SendGrid (Recommended)**

1. Go to https://sendgrid.com/
2. Sign up for free account (100 emails/day)
3. Navigate to Settings → API Keys
4. Create API Key with "Full Access"
5. Copy the API key (you'll need it in Step 2)

**Option B: Gmail SMTP (For Testing)**

1. Enable 2-Factor Authentication on your Google Account
2. Go to Security → App passwords
3. Generate app password for "Mail"
4. Copy the 16-character password

**For SMS - Choose ONE:**

**Option A: Twilio (Recommended)**

1. Go to https://www.twilio.com/
2. Sign up for free trial ($15 credit)
3. From Console Dashboard, copy:
   - Account SID
   - Auth Token
4. Get a phone number (Phone Numbers → Buy a Number)

---

### Step 2: Run Configuration Wizard (5 minutes)

```bash
node scripts/configure-email-sms.js
```

The wizard will ask you:

1. Which email provider? (SendGrid/AWS SES/SMTP)
2. Your email credentials
3. Which SMS provider? (Twilio/AWS SNS/Nexmo)
4. Your SMS credentials

It will automatically:

- Create/update your `.env` file
- Validate your configuration
- Create backups if needed

---

### Step 3: Install Dependencies (2 minutes)

```bash
npm install twilio nodemailer
```

---

### Step 4: Test Configuration (2 minutes)

```bash
# Test configuration only
node test_email_sms_config.js

# Test with actual sending (optional)
node test_email_sms_config.js your@email.com +1234567890
```

Expected output when configured:

```
✅ Email configuration valid
✅ Email service connected successfully
✅ SMS configuration valid
✅ SMS service connected successfully
✅ ALL TESTS PASSED
```

---

### Step 5: Start Using in Your Application

```javascript
// In your code
import emailService from './services/emailService.js';
import smsService from './services/smsService.js';

// Send welcome email
await emailService.sendWelcomeEmail('user@example.com', 'John Doe');

// Send verification code
await smsService.sendVerificationCode('+1234567890', '123456');

// Send payment notification
await smsService.sendPaymentNotification('+1234567890', '1000', 'PAY-123');
```

---

## 📋 Optional Next Steps

### Integrate with Multi-Channel Notifications

Update `services/multiChannelNotificationService.js` to use the real SMS service:

```javascript
import smsService from './smsService.js';

// In sendSMS method, replace placeholder with:
async sendSMS(template, data, userId) {
  const phoneNumber = data.phone || await this.getUserPhone(userId);
  const message = this.replaceTemplateVariables(template.smsBody, data);
  return await smsService.sendCustomSMS(phoneNumber, message);
}
```

### Create API Routes

Create `routes/smsRoutes.js`:

```javascript
import express from 'express';
import smsService from '../services/smsService.js';

const router = express.Router();

router.post('/send', async (req, res) => {
  const { phoneNumber, templateName, data } = req.body;
  const result = await smsService.sendSMS(phoneNumber, templateName, data);
  res.json(result);
});

router.get('/health', (req, res) => {
  res.json(smsService.getHealthStatus());
});

export default router;
```

### Add to Main Server

In `app.js` or your main server file:

```javascript
import smsRoutes from './routes/smsRoutes.js';
app.use('/api/sms', smsRoutes);
```

---

## 🔐 Production Considerations

### Before Going Live:

**Email:**

- [ ] Verify your sender domain (not just email)
- [ ] Set up SPF, DKIM, and DMARC DNS records
- [ ] Request production access (AWS SES starts in sandbox)
- [ ] Set up bounce and complaint handling
- [ ] Configure rate limits
- [ ] Test all email templates
- [ ] Set up monitoring alerts

**SMS:**

- [ ] Upgrade from trial account
- [ ] Register your business/brand with carrier
- [ ] Set up opt-in/opt-out handling (required by law)
- [ ] Comply with TCPA regulations (US)
- [ ] Configure rate limits
- [ ] Test all SMS templates
- [ ] Budget for SMS costs
- [ ] Set up monitoring alerts

**Security:**

- [ ] Move credentials to secure vault (AWS Secrets Manager, Azure Key Vault)
- [ ] Enable 2FA on all provider accounts
- [ ] Set up IP whitelisting where available
- [ ] Implement credential rotation
- [ ] Monitor for suspicious activity
- [ ] Set up audit logging

---

## 💰 Cost Planning

### Email Costs (Monthly)

- **SendGrid Free**: 100 emails/day = $0
- **SendGrid Essentials**: 50,000 emails = $19.95
- **AWS SES**: 10,000 emails = $1.00

### SMS Costs (Per Message)

- **Twilio US**: $0.0079
- **AWS SNS US**: $0.00645

### Example Monthly Costs

- 1,000 emails + 500 SMS = ~$4-5
- 10,000 emails + 2,000 SMS = ~$16-20
- 50,000 emails + 10,000 SMS = ~$100-120

---

## 📚 Documentation

All documentation is available in:

- **`EMAIL_SMS_CONFIGURATION_GUIDE.md`** - Complete setup guide
- **`EMAIL_SMS_IMPLEMENTATION_COMPLETE.md`** - Implementation summary
- **`.env.example`** - Environment variables reference

---

## 🆘 Troubleshooting

### Common Issues

**"Email service not configured"**

```bash
# Run the configuration wizard
node scripts/configure-email-sms.js
```

**"SMS service not configured"**

```bash
# Run the configuration wizard
node scripts/configure-email-sms.js
```

**Authentication Failed**

- Verify credentials are correct in `.env`
- For Gmail: Use App Password, not regular password
- Check for typos

**Messages Not Received**

- Check spam folder (email)
- Verify sender is verified with provider
- Check provider dashboard for delivery status
- Review sending limits

For detailed troubleshooting, see `EMAIL_SMS_CONFIGURATION_GUIDE.md`.

---

## ✨ You're Ready!

The email and SMS configuration is complete. Follow the steps above to start using the services in your application.

**Quick Start Command:**

```bash
node scripts/configure-email-sms.js
```

---

**Last Updated:** 2024-01-15
**Status:** ✅ Ready to Configure
