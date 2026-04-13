# Email/Nodemailer Integration TODO

## Step 1: Fix NPM Vulnerabilities [PENDING]
- Run `npm audit fix`

## Step 2: Baseline Email Config Test [PENDING]
- Run `node test_email_config.js`
- Expect: Email disabled (missing env vars)

## Step 3: Configure Credentials [PENDING]
- Run `node scripts/configure-email-sms.js` interactively OR
- Manual .env edit:
  ```
  EMAIL_PROVIDER=smtp
  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_USER=your-email@gmail.com
  SMTP_PASS=app-password
  ```
  OR SendGrid:
  ```
  EMAIL_PROVIDER=sendgrid
  SENDGRID_API_KEY=your-api-key
  ```

## Step 4: Verify Configuration [PENDING]
- Re-run `node test_email_config.js`
- Check transporter verified

## Step 5: Test in Server Context [PENDING]
- Start server `node app.js` or `npm start`
- Trigger test email via auth/reset endpoint

## Step 6: Update Tests & Deploy [PENDING]
- Run test_email_sms_config.js
- Add to production deploy checklist

**Progress: 0/6 complete**

