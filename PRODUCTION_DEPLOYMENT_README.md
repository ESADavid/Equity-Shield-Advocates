# 🚀 Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Oscar Broome Revenue Merchant Bill Pay system to production environments.

## 📋 Prerequisites

### System Requirements

- **Node.js**: 14.0.0 or higher (16+ recommended)
- **Memory**: Minimum 512MB RAM, 1GB recommended
- **Storage**: 500MB free space
- **Network**: Stable internet connection for external API calls

### Required Credentials

Before deployment, ensure you have the following credentials configured:

1. **Stripe Account** (for payment processing)
   - `STRIPE_SECRET_KEY` - Your Stripe secret key
   - Webhook endpoint URL for production

2. **SMTP Server** (for email notifications)
   - `SMTP_HOST` - SMTP server hostname
   - `SMTP_PORT` - SMTP server port (usually 587)
   - `SMTP_USER` - SMTP username
   - `SMTP_PASS` - SMTP password

3. **Twilio Account** (for SMS notifications)
   - `TWILIO_ACCOUNT_SID` - Twilio account SID
   - `TWILIO_AUTH_TOKEN` - Twilio auth token
   - `TWILIO_PHONE_NUMBER` - Twilio phone number

## 🛠️ Deployment Methods

### Method 1: Automated Production Deployment (Recommended)

1. **Navigate to project directory:**

   ```bash
   cd OSCAR-BROOME-REVENUE
   ```

2. **Run the production deployment script:**

   ```bash
   node production_deploy.js
   ```

   This script will:
   - ✅ Validate system environment
   - ✅ Install/update dependencies
   - ✅ Set up production environment
   - ✅ Validate configuration
   - ✅ Run pre-flight checks
   - ✅ Start production server with PM2

3. **Monitor the deployment:**
   The script provides real-time feedback and will show any issues that need to be addressed.

### Method 2: Manual Deployment

1. **Install dependencies:**

   ```bash
   npm install
   ```

2. **Configure environment:**

   ```bash
   # Copy and edit environment file
   cp .env.example .env
   # Edit .env with your production credentials
   ```

3. **Start with PM2:**

   ```bash
   # Install PM2 globally (if not already installed)
   npm install -g pm2

   # Start the server
   pm2 start server-enhanced.js --name oscar-broome-revenue

   # Save PM2 configuration
   pm2 save

   # Set up PM2 to start on boot
   pm2 startup
   ```

## 📊 Production Features

The production deployment includes:

### 🔒 Security Features

- **Helmet.js**: Security headers and XSS protection
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **CORS**: Configured for allowed origins
- **Input Validation**: Comprehensive request validation

### 📈 Performance Features

- **Compression**: GZIP compression for responses
- **Clustering**: PM2 process management
- **Logging**: Request logging to files
- **Error Handling**: Graceful error responses

### 🛡️ Reliability Features

- **Health Checks**: `/health` endpoint for monitoring
- **Graceful Shutdown**: Proper cleanup on termination
- **Process Monitoring**: PM2 monitoring and auto-restart
- **Error Recovery**: Comprehensive error handling

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```bash
# Production Environment
NODE_ENV=production
PORT=3000

# Stripe Configuration
STRIPE_SECRET_KEY=sk_live_your_stripe_secret_key_here

# SMTP Configuration
SMTP_HOST=smtp.your-email-provider.com
SMTP_PORT=587
SMTP_USER=your-email@domain.com
SMTP_PASS=your-email-password

# Twilio Configuration
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=+1234567890

# Optional: CORS Origins (comma-separated)
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

### PM2 Configuration

The system uses PM2 for process management. You can create a custom PM2 configuration:

```javascript
// ecosystem.config.js
module.exports = {
  apps: [
    {
      name: 'oscar-broome-revenue',
      script: 'server-enhanced.js',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
      },
      error_file: './logs/err.log',
      out_file: './logs/out.log',
      log_file: './logs/combined.log',
      time: true,
    },
  ],
};
```

## 📡 API Endpoints

Once deployed, the following endpoints are available:

### Health & Status

- `GET /health` - Health check endpoint
- `GET /api/status` - System status and configuration

### Merchant Bill Pay

- `POST /api/merchant/create-payment` - Create payment intent
- `POST /api/merchant/send-success-notification` - Send success notification
- `POST /api/merchant/send-failure-notification` - Send failure notification
- `POST /api/merchant/send-sms` - Send SMS notification

### Webhooks

- `POST /api/webhooks/stripe` - Stripe webhook endpoint

## 📊 Monitoring & Maintenance

### PM2 Commands

```bash
# View logs
pm2 logs oscar-broome-revenue

# Monitor processes
pm2 monit

# Restart application
pm2 restart oscar-broome-revenue

# Stop application
pm2 stop oscar-broome-revenue

# View status
pm2 status
```

### Log Files

- `./logs/access.log` - HTTP request logs
- `./logs/error.log` - Application error logs
- `./logs/combined.log` - All logs combined

### Health Monitoring

- Use `/health` endpoint for automated health checks
- Monitor PM2 status for process health
- Check log files for errors and warnings

## 🔄 Updates & Maintenance

### Updating the Application

1. **Stop the current version:**

   ```bash
   pm2 stop oscar-broome-revenue
   ```

2. **Update the code:**

   ```bash
   git pull origin main
   npm install
   ```

3. **Start the updated version:**
   ```bash
   pm2 start server-enhanced.js --name oscar-broome-revenue
   ```

### Backup Strategy

- **Code**: Use Git for version control
- **Logs**: Archive log files regularly
- **Configuration**: Backup `.env` file securely
- **Database**: If using external database, implement regular backups

## 🚨 Troubleshooting

### Common Issues

1. **Port Already in Use**

   ```bash
   # Find process using port 3000
   netstat -tulpn | grep :3000
   # Kill the process or change port in .env
   ```

2. **PM2 Not Found**

   ```bash
   npm install -g pm2
   ```

3. **Missing Dependencies**

   ```bash
   rm -rf node_modules package-lock.json
   npm install
   ```

4. **Environment Variables Not Loaded**
   - Ensure `.env` file exists in project root
   - Check variable names match exactly
   - Restart the application after changes

### Debug Mode

For troubleshooting, you can run in debug mode:

```bash
NODE_ENV=development npm start
```

## 📞 Support

For production deployment support:

1. Check the logs: `pm2 logs oscar-broome-revenue`
2. Review system status: Visit `/api/status` endpoint
3. Check health: Visit `/health` endpoint
4. Review this documentation

## 🎯 Production Checklist

- [ ] All credentials configured in `.env`
- [ ] SSL certificates installed (for HTTPS)
- [ ] Reverse proxy configured (nginx recommended)
- [ ] Firewall rules configured
- [ ] Monitoring and alerting set up
- [ ] Backup strategy implemented
- [ ] Load testing completed
- [ ] Security audit performed

---

**🚀 Your Merchant Bill Pay system is now ready for production!**

The automated deployment script handles most of the complexity, but always test thoroughly in a staging environment before deploying to production.
