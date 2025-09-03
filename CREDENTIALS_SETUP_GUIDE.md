# 🔐 Merchant Bill Pay Credentials Setup Guide

This guide will walk you through obtaining and configuring all the necessary credentials for the Merchant Bill Pay system.

## 📋 Required Credentials

1. **Stripe Secret Key** - For payment processing
2. **SMTP Credentials** - For email notifications
3. **Twilio Credentials** - For SMS notifications

---

## 1. 🚀 Stripe Setup

### Step 1: Create Stripe Account
1. Go to [https://stripe.com](https://stripe.com)
2. Click "Start now" and create a free account
3. Complete the account verification process

### Step 2: Get API Keys
1. Log into your Stripe Dashboard
2. Go to "Developers" → "API keys"
3. Copy the **Secret key** (starts with `sk_test_` for test mode)
4. **⚠️ IMPORTANT**: Never share or commit your secret key to version control

### Step 3: Test Mode vs Live Mode
- **Test Mode**: Use `sk_test_` keys for development
- **Live Mode**: Use `sk_live_` keys for production (requires account verification)

---

## 2. 📧 SMTP Email Setup

### Option A: Gmail SMTP (Recommended for Testing)
1. Go to your Gmail account settings
2. Enable 2-Factor Authentication (2FA)
3. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
   - Use this 16-character password (not your regular password)

**SMTP Configuration:**
- **Host**: `smtp.gmail.com`
- **Port**: `587` (TLS) or `465` (SSL)
- **Username**: Your Gmail address
- **Password**: The 16-character app password

### Option B: Professional SMTP Service (Recommended for Production)
Consider services like:
- **SendGrid**: [https://sendgrid.com](https://sendgrid.com)
- **Mailgun**: [https://mailgun.com](https://mailgun.com)
- **AWS SES**: [https://aws.amazon.com/ses](https://aws.amazon.com/ses)

---

## 3. 📱 Twilio SMS Setup

### Step 1: Create Twilio Account
1. Go to [https://twilio.com](https://twilio.com)
2. Click "Sign up" and create an account
3. Verify your email and phone number
4. Complete account setup

### Step 2: Get Twilio Credentials
1. Log into your Twilio Console
2. Go to "Account" → "API keys & tokens"
3. Copy your **Account SID** (starts with `AC`)
4. Copy your **Auth Token** (starts with `SK`)

### Step 3: Get a Phone Number
1. In Twilio Console, go to "Phone Numbers" → "Manage"
2. Click "Buy a number" or use a trial number
3. Copy the phone number (starts with `+1`)

### Step 4: Verify Phone Number (Trial Account)
- Trial accounts can only send SMS to verified numbers
- Add your phone number to "Verified Caller IDs"

---

## 4. 🔧 Environment Configuration

### Option A: .env File (Recommended)
Create a `.env` file in your project root:

```bash
# Stripe Configuration
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key_here

# Email Configuration (Gmail example)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-16-character-app-password

# Twilio Configuration
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_PHONE_NUMBER=+1234567890
```

### Option B: System Environment Variables
Set these in your system environment:

**Windows:**
```cmd
set STRIPE_SECRET_KEY=sk_test_your_key_here
set SMTP_HOST=smtp.gmail.com
set SMTP_PORT=587
set SMTP_USER=your-email@gmail.com
set SMTP_PASS=your-app-password
set TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set TWILIO_AUTH_TOKEN=SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set TWILIO_PHONE_NUMBER=+1234567890
```

**Linux/Mac:**
```bash
export STRIPE_SECRET_KEY=sk_test_your_key_here
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=your-email@gmail.com
export SMTP_PASS=your-app-password
export TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export TWILIO_AUTH_TOKEN=SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export TWILIO_PHONE_NUMBER=+1234567890
```

---

## 5. 🧪 Testing Your Setup

### Test Stripe
```bash
# Test payment creation
curl -X POST https://api.stripe.com/v1/payment_intents \
  -u sk_test_your_key_here: \
  -d amount=1000 \
  -d currency=usd \
  -d "metadata[merchantId]"=merchant_001
```

### Test Email
Use a tool like **MailHog** for local email testing:
```bash
# Install MailHog
go install github.com/mailhog/MailHog@latest

# Run MailHog
MailHog
```

### Test SMS
```bash
# Test SMS via Twilio API
curl -X POST "https://api.twilio.com/2010-04-01/Accounts/ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/Messages.json" \
  --data-urlencode "From=+1234567890" \
  --data-urlencode "To=+1234567890" \
  --data-urlencode "Body=Test SMS" \
  -u ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 6. 🔒 Security Best Practices

### ✅ Do's:
- Use environment variables, never hardcode credentials
- Use test keys for development
- Rotate keys regularly
- Use least-privilege access
- Monitor API usage

### ❌ Don'ts:
- Commit credentials to version control
- Share API keys publicly
- Use live keys in development
- Store credentials in plain text files
- Use weak passwords

### 🔐 Additional Security:
- Enable 2FA on all accounts
- Set up API key restrictions
- Use IP whitelisting when possible
- Monitor for unusual activity
- Set up alerts for failed authentication

---

## 7. 🚀 Quick Setup Script

Run this script to set up your environment variables:

```bash
#!/bin/bash
# setup_credentials.sh

echo "🔐 Setting up Merchant Bill Pay Credentials"
echo ""

# Stripe Setup
read -p "Enter your Stripe Secret Key: " STRIPE_KEY
export STRIPE_SECRET_KEY=$STRIPE_KEY

# Email Setup
read -p "Enter SMTP Host (e.g., smtp.gmail.com): " SMTP_HOST_VAL
export SMTP_HOST=$SMTP_HOST_VAL

read -p "Enter SMTP Port (e.g., 587): " SMTP_PORT_VAL
export SMTP_PORT=$SMTP_PORT_VAL

read -p "Enter SMTP Username: " SMTP_USER_VAL
export SMTP_USER=$SMTP_USER_VAL

read -s -p "Enter SMTP Password: " SMTP_PASS_VAL
export SMTP_PASS=$SMTP_PASS_VAL

# Twilio Setup
read -p "Enter Twilio Account SID: " TWILIO_SID
export TWILIO_ACCOUNT_SID=$TWILIO_SID

read -s -p "Enter Twilio Auth Token: " TWILIO_TOKEN
export TWILIO_AUTH_TOKEN=$TWILIO_TOKEN

read -p "Enter Twilio Phone Number: " TWILIO_PHONE
export TWILIO_PHONE_NUMBER=$TWILIO_PHONE

echo ""
echo "✅ Credentials configured!"
echo "Run 'node comprehensive_merchant_test.js' to test your setup"
```

---

## 8. 🆘 Troubleshooting

### Common Issues:

**Stripe Errors:**
- "Invalid API Key": Check your secret key format
- "Test mode": Use test keys for development

**Email Errors:**
- "Authentication failed": Use app password, not regular password
- "Connection refused": Check SMTP host and port

**SMS Errors:**
- "Trial account": Add recipient to verified numbers
- "Invalid number": Ensure phone number format is correct

### Getting Help:
- **Stripe**: [https://stripe.com/docs](https://stripe.com/docs)
- **Twilio**: [https://www.twilio.com/docs](https://www.twilio.com/docs)
- **Gmail SMTP**: [https://support.google.com/mail](https://support.google.com/mail)

---

## 🎯 Next Steps

1. Follow this guide to obtain all credentials
2. Set up your environment variables
3. Run the comprehensive test: `node comprehensive_merchant_test.js`
4. Verify all services are working correctly
5. Deploy to production with live credentials

**Remember**: Always use test credentials for development and never commit real credentials to version control! 🔒
