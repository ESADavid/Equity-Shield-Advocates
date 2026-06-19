#!/bin/bash

# Backup and Recovery Setup Script for OSCAR BROOME REVENUE
# This script sets up automated backups and recovery procedures

echo "💾 Setting up Backup and Recovery for OSCAR BROOME REVENUE"
echo "=========================================================="

# Check if we're running as root/sudo
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root or with sudo"
   exit 1
fi

# Create backup directory structure
echo "📁 Creating backup directory structure..."
BACKUP_ROOT="/opt/backups/oscar-broome-revenue"
mkdir -p $BACKUP_ROOT/{daily,weekly,monthly,logs,scripts}

# Create backup configuration
cat > $BACKUP_ROOT/backup_config.json << EOF
{
  "backup": {
    "root_directory": "/opt/backups/oscar-broome-revenue",
    "retention": {
      "daily": 7,
      "weekly": 4,
      "monthly": 12
    },
    "compression": "gzip",
    "encryption": false
  },
  "sources": {
    "application": {
      "path": "/var/www/oscar-broome-revenue",
      "includes": [
        "*.js",
        "*.json",
        "*.html",
        "*.css",
        "logs/*.log",
        "config/*.json"
      ],
      "excludes": [
        "node_modules",
        "*.tmp",
        "cache/*"
      ]
    },
    "database": {
      "type": "mongodb",
      "host": "localhost",
      "port": 27017,
      "database": "oscar_broome_revenue",
      "auth": {
        "username": "backup_user",
        "password": "secure_password"
      }
    },
    "ssl_certificates": {
      "path": "/etc/letsencrypt",
      "includes": [
        "live/*/fullchain.pem",
        "live/*/privkey.pem"
      ]
    }
  },
  "destinations": {
    "local": {
      "path": "/opt/backups/oscar-broome-revenue"
    },
    "remote": {
      "type": "s3",
      "bucket": "oscar-broome-revenue-backups",
      "region": "us-east-1",
      "access_key": "your-access-key",
      "secret_key": "your-secret-key"
    }
  }
}
EOF

# Create backup script
cat > $BACKUP_ROOT/scripts/backup.sh << 'EOF'
#!/bin/bash

# Automated Backup Script for OSCAR BROOME REVENUE
# This script performs comprehensive backups of application, database, and configuration

set -e  # Exit on any error

# Load configuration
CONFIG_FILE="/opt/backups/oscar-broome-revenue/backup_config.json"
BACKUP_ROOT="/opt/backups/oscar-broome-revenue"

# Logging
LOG_FILE="$BACKUP_ROOT/logs/backup_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "🚀 Starting OSCAR BROOME REVENUE Backup - $(date)"
echo "=================================================="

# Create timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_TYPE=$1

if [ -z "$BACKUP_TYPE" ]; then
    BACKUP_TYPE="daily"
fi

BACKUP_DIR="$BACKUP_ROOT/$BACKUP_TYPE/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

echo "📁 Backup directory: $BACKUP_DIR"

# Function to backup application files
backup_application() {
    echo "📦 Backing up application files..."
    APP_SOURCE="/var/www/oscar-broome-revenue"
    APP_BACKUP="$BACKUP_DIR/application.tar.gz"

    if [ -d "$APP_SOURCE" ]; then
        cd "$APP_SOURCE"
        tar -czf "$APP_BACKUP" \
            --exclude='node_modules' \
            --exclude='*.tmp' \
            --exclude='cache' \
            --exclude='logs/*.log' \
            .
        echo "✅ Application backup completed: $APP_BACKUP"
    else
        echo "⚠️  Application directory not found: $APP_SOURCE"
    fi
}

# Function to backup database
backup_database() {
    echo "🗄️  Backing up database..."
    DB_BACKUP="$BACKUP_DIR/database_$(date +%Y%m%d).sql"

    # MongoDB backup (adjust for your database type)
    if command -v mongodump &> /dev/null; then
        mongodump --db oscar_broome_revenue --out "$BACKUP_DIR/mongodb_backup"
        echo "✅ MongoDB backup completed"
    else
        echo "⚠️  MongoDB tools not found, skipping database backup"
    fi

    # MySQL backup (uncomment if using MySQL)
    # if command -v mysqldump &> /dev/null; then
    #     mysqldump -u backup_user -p'secure_password' oscar_broome_revenue > "$DB_BACKUP"
    #     echo "✅ MySQL backup completed: $DB_BACKUP"
    # fi
}

# Function to backup SSL certificates
backup_ssl() {
    echo "🔐 Backing up SSL certificates..."
    SSL_SOURCE="/etc/letsencrypt"
    SSL_BACKUP="$BACKUP_DIR/ssl_certificates.tar.gz"

    if [ -d "$SSL_SOURCE" ]; then
        cd "$SSL_SOURCE"
        tar -czf "$SSL_BACKUP" live/*/fullchain.pem live/*/privkey.pem 2>/dev/null || true
        echo "✅ SSL certificates backup completed: $SSL_BACKUP"
    else
        echo "⚠️  SSL directory not found: $SSL_SOURCE"
    fi
}

# Function to upload to remote storage
upload_remote() {
    echo "☁️  Uploading to remote storage..."
    # AWS S3 upload (requires awscli)
    if command -v aws &> /dev/null; then
        aws s3 sync "$BACKUP_DIR" s3://oscar-broome-revenue-backups/$BACKUP_TYPE/
        echo "✅ Remote backup upload completed"
    else
        echo "⚠️  AWS CLI not found, skipping remote upload"
    fi
}

# Function to cleanup old backups
cleanup_old_backups() {
    echo "🧹 Cleaning up old backups..."

    # Daily backups: keep last 7 days
    find "$BACKUP_ROOT/daily" -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true

    # Weekly backups: keep last 4 weeks
    find "$BACKUP_ROOT/weekly" -type d -mtime +28 -exec rm -rf {} + 2>/dev/null || true

    # Monthly backups: keep last 12 months
    find "$BACKUP_ROOT/monthly" -type d -mtime +365 -exec rm -rf {} + 2>/dev/null || true

    echo "✅ Cleanup completed"
}

# Main backup execution
echo "🔧 Executing backup operations..."

backup_application
backup_database
backup_ssl

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
echo "📊 Backup size: $BACKUP_SIZE"

# Upload to remote storage (uncomment if configured)
# upload_remote

# Cleanup old backups
cleanup_old_backups

echo "✅ Backup completed successfully at $(date)"
echo "📝 Log file: $LOG_FILE"
echo "📁 Backup location: $BACKUP_DIR"
EOF

# Create recovery script
cat > $BACKUP_ROOT/scripts/recovery.sh << 'EOF'
#!/bin/bash

# Recovery Script for OSCAR BROOME REVENUE
# This script restores application, database, and configuration from backups

set -e  # Exit on any error

# Load configuration
CONFIG_FILE="/opt/backups/oscar-broome-revenue/backup_config.json"
BACKUP_ROOT="/opt/backups/oscar-broome-revenue"

# Logging
LOG_FILE="$BACKUP_ROOT/logs/recovery_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "🔄 Starting OSCAR BROOME REVENUE Recovery - $(date)"
echo "==================================================="

# Function to list available backups
list_backups() {
    echo "📋 Available backups:"
    echo "Daily backups:"
    ls -la "$BACKUP_ROOT/daily/" 2>/dev/null || echo "  No daily backups found"
    echo ""
    echo "Weekly backups:"
    ls -la "$BACKUP_ROOT/weekly/" 2>/dev/null || echo "  No weekly backups found"
    echo ""
    echo "Monthly backups:"
    ls -la "$BACKUP_ROOT/monthly/" 2>/dev/null || echo "  No monthly backups found"
}

# Function to restore application files
restore_application() {
    local BACKUP_PATH=$1
    echo "📦 Restoring application files from: $BACKUP_PATH"

    APP_BACKUP="$BACKUP_PATH/application.tar.gz"
    APP_DEST="/var/www/oscar-broome-revenue"

    if [ -f "$APP_BACKUP" ]; then
        echo "🛑 Stopping application services..."
        systemctl stop oscar-broome-revenue 2>/dev/null || true

        echo "📦 Extracting application backup..."
        mkdir -p "$APP_DEST"
        cd "$APP_DEST"
        tar -xzf "$APP_BACKUP"

        echo "🔧 Restoring dependencies..."
        npm install --production

        echo "▶️  Starting application services..."
        systemctl start oscar-broome-revenue 2>/dev/null || true

        echo "✅ Application restore completed"
    else
        echo "❌ Application backup not found: $APP_BACKUP"
        return 1
    fi
}

# Function to restore database
restore_database() {
    local BACKUP_PATH=$1
    echo "🗄️  Restoring database from: $BACKUP_PATH"

    DB_BACKUP="$BACKUP_PATH/mongodb_backup"

    if [ -d "$DB_BACKUP" ]; then
        echo "🛑 Stopping database services..."
        systemctl stop mongod 2>/dev/null || true

        echo "🗄️  Restoring MongoDB database..."
        mongorestore --db oscar_broome_revenue "$DB_BACKUP/oscar_broome_revenue"

        echo "▶️  Starting database services..."
        systemctl start mongod 2>/dev/null || true

        echo "✅ Database restore completed"
    else
        echo "❌ Database backup not found: $DB_BACKUP"
        return 1
    fi
}

# Function to restore SSL certificates
restore_ssl() {
    local BACKUP_PATH=$1
    echo "🔐 Restoring SSL certificates from: $BACKUP_PATH"

    SSL_BACKUP="$BACKUP_PATH/ssl_certificates.tar.gz"
    SSL_DEST="/etc/letsencrypt"

    if [ -f "$SSL_BACKUP" ]; then
        echo "🔐 Extracting SSL certificates..."
        cd "$SSL_DEST"
        tar -xzf "$SSL_BACKUP"

        echo "🔄 Reloading nginx configuration..."
        nginx -t && systemctl reload nginx

        echo "✅ SSL certificates restore completed"
    else
        echo "❌ SSL backup not found: $SSL_BACKUP"
        return 1
    fi
}

# Main recovery execution
if [ $# -eq 0 ]; then
    echo "Usage: $0 <backup_timestamp> [components...]"
    echo "Components: application, database, ssl, all"
    echo ""
    list_backups
    exit 1
fi

BACKUP_TIMESTAMP=$1
shift
COMPONENTS=${@:-"all"}

# Find backup directory
BACKUP_PATH=""
for TYPE in daily weekly monthly; do
    if [ -d "$BACKUP_ROOT/$TYPE/$BACKUP_TIMESTAMP" ]; then
        BACKUP_PATH="$BACKUP_ROOT/$TYPE/$BACKUP_TIMESTAMP"
        break
    fi
done

if [ -z "$BACKUP_PATH" ]; then
    echo "❌ Backup not found: $BACKUP_TIMESTAMP"
    list_backups
    exit 1
fi

echo "📁 Using backup: $BACKUP_PATH"
echo "🔧 Restoring components: $COMPONENTS"

# Execute recovery based on components
if [[ "$COMPONENTS" == *"all"* ]] || [[ "$COMPONENTS" == *"application"* ]]; then
    restore_application "$BACKUP_PATH"
fi

if [[ "$COMPONENTS" == *"all"* ]] || [[ "$COMPONENTS" == *"database"* ]]; then
    restore_database "$BACKUP_PATH"
fi

if [[ "$COMPONENTS" == *"all"* ]] || [[ "$COMPONENTS" == *"ssl"* ]]; then
    restore_ssl "$BACKUP_PATH"
fi

echo "✅ Recovery completed successfully at $(date)"
echo "📝 Log file: $LOG_FILE"
EOF

# Make scripts executable
chmod +x $BACKUP_ROOT/scripts/backup.sh
chmod +x $BACKUP_ROOT/scripts/recovery.sh

# Create cron jobs for automated backups
cat > /etc/cron.d/oscar-broome-revenue-backup << EOF
# OSCAR BROOME REVENUE Automated Backups
# Daily backup at 2:00 AM
0 2 * * * root /opt/backups/oscar-broome-revenue/scripts/backup.sh daily

# Weekly backup every Sunday at 3:00 AM
0 3 * * 0 root /opt/backups/oscar-broome-revenue/scripts/backup.sh weekly

# Monthly backup on the 1st at 4:00 AM
0 4 1 * * root /opt/backups/oscar-broome-revenue/scripts/backup.sh monthly
EOF

# Create systemd service for backup monitoring
cat > /etc/systemd/system/oscar-broome-revenue-backup.service << EOF
[Unit]
Description=OSCAR BROOME REVENUE Backup Service
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/backups/oscar-broome-revenue/scripts/backup.sh daily
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/oscar-broome-revenue-backup.timer << EOF
[Unit]
Description=Run OSCAR BROOME REVENUE backup daily
Requires=oscar-broome-revenue-backup.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start the backup timer
systemctl daemon-reload
systemctl enable oscar-broome-revenue-backup.timer
systemctl start oscar-broome-revenue-backup.timer

# Create backup verification script
cat > $BACKUP_ROOT/scripts/verify_backup.sh << 'EOF'
#!/bin/bash

# Backup Verification Script for OSCAR BROOME REVENUE
# This script verifies the integrity of backups

echo "🔍 Verifying OSCAR BROOME REVENUE Backups"
echo "=========================================="

BACKUP_ROOT="/opt/backups/oscar-broome-revenue"
LOG_FILE="$BACKUP_ROOT/logs/verification_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Function to verify application backup
verify_application() {
    local BACKUP_PATH=$1
    local APP_BACKUP="$BACKUP_PATH/application.tar.gz"

    if [ -f "$APP_BACKUP" ]; then
        echo "📦 Verifying application backup..."
        if tar -tzf "$APP_BACKUP" > /dev/null 2>&1; then
            echo "✅ Application backup is valid"
            return 0
        else
            echo "❌ Application backup is corrupted"
            return 1
        fi
    else
        echo "⚠️  Application backup not found"
        return 1
    fi
}

# Function to verify database backup
verify_database() {
    local BACKUP_PATH=$1
    local DB_BACKUP="$BACKUP_PATH/mongodb_backup"

    if [ -d "$DB_BACKUP" ]; then
        echo "🗄️  Verifying database backup..."
        # Check if backup directory contains expected files
        if [ -d "$DB_BACKUP/oscar_broome_revenue" ]; then
            echo "✅ Database backup structure is valid"
            return 0
        else
            echo "❌ Database backup structure is invalid"
            return 1
        fi
    else
        echo "⚠️  Database backup not found"
        return 1
    fi
}

# Function to verify SSL backup
verify_ssl() {
    local BACKUP_PATH=$1
    local SSL_BACKUP="$BACKUP_PATH/ssl_certificates.tar.gz"

    if [ -f "$SSL_BACKUP" ]; then
        echo "🔐 Verifying SSL certificates backup..."
        if tar -tzf "$SSL_BACKUP" > /dev/null 2>&1; then
            echo "✅ SSL certificates backup is valid"
            return 0
        else
            echo "❌ SSL certificates backup is corrupted"
            return 1
        fi
    else
        echo "⚠️  SSL certificates backup not found"
        return 1
    fi
}

# Main verification
echo "🔧 Starting backup verification..."

# Check latest backups
for TYPE in daily weekly monthly; do
    echo ""
    echo "Checking $TYPE backups..."
    LATEST_BACKUP=$(ls -td "$BACKUP_ROOT/$TYPE/"* 2>/dev/null | head -1)

    if [ -n "$LATEST_BACKUP" ]; then
        echo "📁 Latest $TYPE backup: $(basename "$LATEST_BACKUP")"

        verify_application "$LATEST_BACKUP"
        verify_database "$LATEST_BACKUP"
        verify_ssl "$LATEST_BACKUP"
    else
        echo "⚠️  No $TYPE backups found"
    fi
done

echo ""
echo "✅ Backup verification completed at $(date)"
echo "📝 Log file: $LOG_FILE"
EOF

chmod +x $BACKUP_ROOT/scripts/verify_backup.sh

# Create backup documentation
cat > $BACKUP_ROOT/README.md << EOF
# OSCAR BROOME REVENUE Backup and Recovery

This directory contains automated backup and recovery scripts for the OSCAR BROOME REVENUE system.

## Directory Structure

\`\`\`
/opt/backups/oscar-broome-revenue/
├── backup_config.json          # Backup configuration
├── scripts/
│   ├── backup.sh              # Main backup script
│   ├── recovery.sh            # Recovery script
│   └── verify_backup.sh       # Backup verification script
├── daily/                     # Daily backups
├── weekly/                    # Weekly backups
├── monthly/                   # Monthly backups
├── logs/                      # Backup logs
└── README.md                  # This file
\`\`\`

## Automated Backups

Backups are scheduled automatically:
- **Daily**: 2:00 AM - Full application and database backup
- **Weekly**: Sunday 3:00 AM - Full system backup
- **Monthly**: 1st of month 4:00 AM - Full system backup

## Manual Backup

To run a manual backup:

\`\`\`bash
# Daily backup
sudo /opt/backups/oscar-broome-revenue/scripts/backup.sh daily

# Weekly backup
sudo /opt/backups/oscar-broome-revenue/scripts/backup.sh weekly

# Monthly backup
sudo /opt/backups/oscar-broome-revenue/scripts/backup.sh monthly
\`\`\`

## Recovery

To restore from a backup:

\`\`\`bash
# List available backups
sudo /opt/backups/oscar-broome-revenue/scripts/recovery.sh

# Restore specific backup (replace TIMESTAMP with actual timestamp)
sudo /opt/backups/oscar-broome-revenue/scripts/recovery.sh 20231201_020000 all

# Restore only application
sudo /opt/backups/oscar-broome-revenue/scripts/recovery.sh 20231201_020000 application

# Restore only database
sudo /opt/backups/oscar-broome-revenue/scripts/recovery.sh 20231201_020000 database
\`\`\`

## Verification

To verify backup integrity:

\`\`\`bash
sudo /opt/backups/oscar-broome-revenue/scripts/verify_backup.sh
\`\`\`

## Configuration

Edit \`backup_config.json\` to modify:
- Backup retention policies
- Source directories
- Remote storage destinations
- Database connection details

## Monitoring

Backup status is logged to:
- \`/opt/backups/oscar-broome-revenue/logs/\`

Systemd services:
- \`oscar-broome-revenue-backup.service\`
- \`oscar-broome-revenue-backup.timer\`

## Emergency Contacts

In case of backup/recovery issues, contact:
- System Administrator
- Database Administrator
- DevOps Team
EOF

echo ""
echo "✅ Backup and recovery setup completed!"
echo ""
echo "📊 Backup Schedule:"
echo "   Daily: 2:00 AM - Application + Database"
echo "   Weekly: Sunday 3:00 AM - Full system"
echo "   Monthly: 1st 4:00 AM - Full system"
echo ""
echo "📁 Backup Location: $BACKUP_ROOT"
echo ""
echo "🔧 Useful Commands:"
echo "   Manual backup: sudo $BACKUP_ROOT/scripts/backup.sh daily"
echo "   Recovery: sudo $BACKUP_ROOT/scripts/recovery.sh [timestamp]"
echo "   Verify: sudo $BACKUP_ROOT/scripts/verify_backup.sh"
echo ""
echo "📝 Documentation: $BACKUP_ROOT/README.md"
echo ""
echo "🎯 Next Steps:"
echo "   1. Configure remote storage (AWS S3, etc.)"
echo "   2. Test backup and recovery procedures"
echo "   3. Set up backup monitoring alerts"
echo "   4. Document emergency recovery procedures"
