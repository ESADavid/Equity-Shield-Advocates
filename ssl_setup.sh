#!/bin/bash

# SSL Certificate Setup Script for OSCAR BROOME REVENUE
# This script sets up SSL certificates for HTTPS production deployment

echo "🔐 SSL Certificate Setup for OSCAR BROOME REVENUE"
echo "=================================================="

# Check if we're running as root/sudo
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root. Please run as a regular user."
   exit 1
fi

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "📦 Installing Certbot..."
    sudo apt update
    sudo apt install -y certbot python3-certbot-nginx
fi

# Get domain name
read -p "Enter your domain name (e.g., api.oscarbroome.com): " DOMAIN

if [ -z "$DOMAIN" ]; then
    echo "❌ Domain name is required"
    exit 1
fi

echo "🔧 Setting up SSL certificate for $DOMAIN..."

# Create webroot directory for Let's Encrypt verification
sudo mkdir -p /var/www/html/.well-known/acme-challenge

# Get SSL certificate using webroot method
sudo certbot certonly --webroot -w /var/www/html -d $DOMAIN

if [ $? -eq 0 ]; then
    echo "✅ SSL certificate obtained successfully!"
    echo ""
    echo "📋 Certificate Details:"
    echo "   Certificate: /etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    echo "   Private Key: /etc/letsencrypt/live/$DOMAIN/privkey.pem"
    echo ""
    echo "🔄 Setting up auto-renewal..."
    sudo crontab -l | grep -q certbot || (sudo crontab -l ; echo "0 12 * * * /usr/bin/certbot renew --quiet") | sudo crontab -

    echo "✅ SSL setup completed!"
    echo ""
    echo "📝 Next steps:"
    echo "   1. Update your nginx configuration to use the SSL certificates"
    echo "   2. Restart your web server"
    echo "   3. Test HTTPS access: https://$DOMAIN"
else
    echo "❌ SSL certificate setup failed. Please check the error messages above."
    exit 1
fi
