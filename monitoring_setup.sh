#!/bin/bash

# Monitoring Setup Script for OSCAR BROOME REVENUE
# This script sets up Prometheus, Alertmanager, and Grafana for monitoring

echo "📊 Setting up Monitoring Stack for OSCAR BROOME REVENUE"
echo "======================================================="

# Check if we're running as root/sudo
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root or with sudo"
   exit 1
fi

# Update system
echo "🔄 Updating system packages..."
apt update && apt upgrade -y

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null; then
    echo "🐳 Installing Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# Create monitoring directory
echo "📁 Creating monitoring directory..."
mkdir -p /opt/monitoring
cd /opt/monitoring

# Create Prometheus configuration
cat > prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'oscar-broome-revenue'
    static_configs:
      - targets: ['host.docker.internal:3000']
    metrics_path: '/api/status'
    scrape_interval: 30s
    scrape_timeout: 10s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF

# Create alert rules
cat > alert_rules.yml << EOF
groups:
  - name: oscar-broome-alerts
    rules:
      - alert: OscarBroomeRevenueDown
        expr: up{job="oscar-broome-revenue"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Oscar Broome Revenue service is down"
          description: "Oscar Broome Revenue has been down for more than 5 minutes."

      - alert: HighMemoryUsage
        expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on {{ \$labels.instance }}"
          description: "Memory usage is above 90% for more than 5 minutes."

      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ \$labels.instance }}"
          description: "CPU usage is above 85% for more than 5 minutes."
EOF

# Create Alertmanager configuration
cat > alertmanager.yml << EOF
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@oscarbroome.com'
  smtp_auth_username: 'your-email@gmail.com'
  smtp_auth_password: 'your-app-password'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'email-notifications'
  routes:
  - match:
      severity: critical
    receiver: 'critical-notifications'

receivers:
- name: 'email-notifications'
  email_configs:
  - to: 'admin@oscarbroome.com'
    send_resolved: true

- name: 'critical-notifications'
  email_configs:
  - to: 'emergency@oscarbroome.com'
    send_resolved: true
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
    channel: '#alerts'
    send_resolved: true
EOF

# Create Docker Compose file
cat > docker-compose.yml << EOF
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./alert_rules.yml:/etc/prometheus/alert_rules.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    restart: unless-stopped

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3001:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    restart: unless-stopped

volumes:
  prometheus_data:
  grafana_data:
EOF

# Start monitoring stack
echo "🚀 Starting monitoring stack..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 30

# Check if services are running
echo "🔍 Checking service status..."
docker-compose ps

echo ""
echo "✅ Monitoring setup completed!"
echo ""
echo "📊 Access URLs:"
echo "   Prometheus: http://localhost:9090"
echo "   Alertmanager: http://localhost:9093"
echo "   Grafana: http://localhost:3001 (admin/admin123)"
echo "   Node Exporter: http://localhost:9100"
echo ""
echo "🔧 Next steps:"
echo "   1. Update Alertmanager email credentials in alertmanager.yml"
echo "   2. Configure Slack webhook for critical alerts"
echo "   3. Set up Grafana dashboards for your application metrics"
echo "   4. Configure nginx to proxy monitoring endpoints"
echo ""
echo "📝 Useful commands:"
echo "   View logs: docker-compose logs -f [service-name]"
echo "   Restart: docker-compose restart [service-name]"
echo "   Stop: docker-compose down"
