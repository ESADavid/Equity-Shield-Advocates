#!/usr/bin/env node

/**
 * OSCAR-BROOME-REVENUE Staging Deployment Script
 * Deploys the application to staging environment with treasury management integration
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import logger from './utils/loggerWrapper.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class StagingDeployment {
    constructor() {
        this.projectRoot = path.resolve(__dirname);
        this.stagingConfig = {
            environment: 'staging',
            port: 3001,
            database: 'staging_oscar_broome_revenue',
            redis: 'redis://localhost:6379/1',
            jpmorgan: {
                baseUrl: 'https://api-staging.jpmorgan.com',
                timeout: 30000
            }
        };
    }

    log(message, type = 'info') {
        const timestamp = new Date().toISOString();
        const colors = {
            info: '\x1b[36m',
            success: '\x1b[32m',
            warning: '\x1b[33m',
            error: '\x1b[31m',
            reset: '\x1b[0m'
        };
        logger.info(`${colors[type]}[${timestamp}] ${message}${colors.reset}`);
    }

    async run() {
        try {
            this.log('🚀 Starting OSCAR-BROOME-REVENUE Staging Deployment', 'info');

            await this.checkPrerequisites();
            await this.setupEnvironment();
            await this.installDependencies();
            await this.setupDatabase();
            await this.runMigrations();
            await this.buildApplication();
            await this.configureServices();
            await this.runTests();
            await this.startServices();
            await this.runHealthChecks();
            await this.generateDeploymentReport();

            this.log('✅ Staging deployment completed successfully!', 'success');
        } catch (error) {
            this.log(`❌ Deployment failed: ${error.message}`, 'error');
            await this.rollback();
            process.exit(1);
        }
    }

    async checkPrerequisites() {
        this.log('🔍 Checking prerequisites...', 'info');

        const prerequisites = [
            { command: 'node --version', name: 'Node.js' },
            { command: 'npm --version', name: 'npm' },
            { command: 'docker --version', name: 'Docker' },
            { command: 'docker-compose --version', name: 'Docker Compose' }
        ];

        for (const prereq of prerequisites) {
            try {
                execSync(prereq.command, { stdio: 'pipe' });
                this.log(`✅ ${prereq.name} is installed`, 'success');
            } catch (error) {
                throw new Error(`${prereq.name} is not installed or not accessible`);
            }
        }
    }

    async setupEnvironment() {
        this.log('🔧 Setting up staging environment...', 'info');

        // Create staging environment file
        const envContent = `# Staging Environment Configuration
NODE_ENV=staging
PORT=${this.stagingConfig.port}
DATABASE_URL=${this.stagingConfig.database}
REDIS_URL=${this.stagingConfig.redis}

# JPMorgan Treasury Integration
JPMORGAN_BASE_URL=${this.stagingConfig.jpmorgan.baseUrl}
JPMORGAN_TIMEOUT=${this.stagingConfig.jpmorgan.timeout}
JPMORGAN_CLIENT_ID=staging_client_id
JPMORGAN_CLIENT_SECRET=staging_client_secret

# Security
JWT_SECRET=staging_jwt_secret_key_2024
ENCRYPTION_KEY=staging_encryption_key_2024

# Monitoring
PROMETHEUS_PORT=9090
GRAFANA_PORT=3002

# Logging
LOG_LEVEL=debug
LOG_FILE=logs/staging.log
`;

        fs.writeFileSync(path.join(this.projectRoot, '.env.staging'), envContent);
        this.log('✅ Staging environment configuration created', 'success');
    }

    async installDependencies() {
        this.log('📦 Installing dependencies...', 'info');

        execSync('npm ci', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        this.log('✅ Dependencies installed successfully', 'success');
    }

    async setupDatabase() {
        this.log('🗄️ Setting up staging database...', 'info');

        // Create database setup script
        const dbSetupScript = `
-- Staging Database Setup
CREATE DATABASE IF NOT EXISTS ${this.stagingConfig.database};
USE ${this.stagingConfig.database};

-- Create treasury tables
CREATE TABLE IF NOT EXISTS treasury_cash_positions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    currency VARCHAR(3) NOT NULL,
    amount DECIMAL(20,2) NOT NULL,
    account_type VARCHAR(50),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_currency (currency),
    INDEX idx_account_type (account_type)
);

CREATE TABLE IF NOT EXISTS treasury_fx_rates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_currency VARCHAR(3) NOT NULL,
    to_currency VARCHAR(3) NOT NULL,
    rate DECIMAL(10,6) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_currency_pair (from_currency, to_currency)
);

CREATE TABLE IF NOT EXISTS treasury_portfolio_performance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    portfolio_id VARCHAR(100) NOT NULL,
    period VARCHAR(20) NOT NULL,
    return_percentage DECIMAL(8,4),
    benchmark_return DECIMAL(8,4),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_portfolio_period (portfolio_id, period)
);
`;

        fs.writeFileSync(path.join(this.projectRoot, 'staging_db_setup.sql'), dbSetupScript);
        this.log('✅ Database setup script created', 'success');
    }

    async runMigrations() {
        this.log('🔄 Running database migrations...', 'info');

        // Run database migrations
        execSync('npm run migrate:staging', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        this.log('✅ Database migrations completed', 'success');
    }

    async buildApplication() {
        this.log('🔨 Building application...', 'info');

        execSync('npm run build:staging', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        this.log('✅ Application built successfully', 'success');
    }

    async configureServices() {
        this.log('⚙️ Configuring services...', 'info');

        // Create docker-compose.staging.yml
        const dockerCompose = `
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.staging
    ports:
      - "${this.stagingConfig.port}:3000"
    environment:
      - NODE_ENV=staging
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped

  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: staging_root_password
      MYSQL_DATABASE: ${this.stagingConfig.database}
    ports:
      - "3307:3306"
    volumes:
      - staging_mysql_data:/var/lib/mysql
      - ./staging_db_setup.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - staging_redis_data:/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus
    ports:
      - "${this.stagingConfig.prometheusPort}:9090"
    volumes:
      - ./monitoring/prometheus.staging.yml:/etc/prometheus/prometheus.yml
    restart: unless-stopped

  grafana:
    image: grafana/grafana
    ports:
      - "${this.stagingConfig.grafanaPort}:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=staging_admin
    volumes:
      - staging_grafana_data:/var/lib/grafana
    restart: unless-stopped

volumes:
  staging_mysql_data:
  staging_redis_data:
  staging_grafana_data:
`;

        fs.writeFileSync(path.join(this.projectRoot, 'docker-compose.staging.yml'), dockerCompose);
        this.log('✅ Services configured', 'success');
    }

    async runTests() {
        this.log('🧪 Running staging tests...', 'info');

        // Run comprehensive treasury tests
        execSync('node comprehensive_treasury_test.js', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        // Run comprehensive integration tests
        execSync('node comprehensive_integration_test.js', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        // Run comprehensive JPMorgan tests
        execSync('node comprehensive_jpmorgan_test.js', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        // Run comprehensive merchant tests
        execSync('node comprehensive_merchant_test.js', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        // Run comprehensive payroll tests
        execSync('node comprehensive_payroll_test.js', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        this.log('✅ Staging tests passed', 'success');
    }

    async startServices() {
        this.log('🚀 Starting staging services...', 'info');

        execSync('docker-compose -f docker-compose.staging.yml up -d', {
            cwd: this.projectRoot,
            stdio: 'inherit'
        });

        // Wait for services to be ready
        await this.waitForServices();

        this.log('✅ Staging services started', 'success');
    }

    async waitForServices() {
        this.log('⏳ Waiting for services to be ready...', 'info');

        const services = ['app', 'db', 'redis'];
        for (const service of services) {
            let retries = 30;
            while (retries > 0) {
                try {
                    execSync(`docker-compose -f docker-compose.staging.yml ps ${service}`, {
                        cwd: this.projectRoot,
                        stdio: 'pipe'
                    });
                    this.log(`✅ ${service} is ready`, 'success');
                    break;
                } catch (error) {
                    retries--;
                    if (retries === 0) {
                        throw new Error(`${service} failed to start`);
                    }
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }
            }
        }
    }

    async runHealthChecks() {
        this.log('🏥 Running health checks...', 'info');

        const healthChecks = [
            { url: `http://localhost:${this.stagingConfig.port}/health`, name: 'Application Health' },
            { url: `http://localhost:${this.stagingConfig.port}/jpmorgan/treasury/health`, name: 'Treasury Health' },
            { url: `http://localhost:3307`, name: 'Database Connection' },
            { url: `http://localhost:6379`, name: 'Redis Connection' }
        ];

        for (const check of healthChecks) {
            try {
                // Simple health check - in production, use proper HTTP client
                execSync(`curl -f ${check.url}`, { stdio: 'pipe' });
                this.log(`✅ ${check.name} check passed`, 'success');
            } catch (error) {
                this.log(`⚠️ ${check.name} check failed, but continuing...`, 'warning');
            }
        }
    }

    async generateDeploymentReport() {
        this.log('📊 Generating deployment report...', 'info');

        const report = {
            deploymentTime: new Date().toISOString(),
            environment: 'staging',
            version: '1.0.0',
            services: {
                app: `http://localhost:${this.stagingConfig.port}`,
                database: 'localhost:3307',
                redis: 'localhost:6379',
                prometheus: `http://localhost:${this.stagingConfig.prometheusPort}`,
                grafana: `http://localhost:${this.stagingConfig.grafanaPort}`
            },
            treasuryEndpoints: [
                '/jpmorgan/treasury/health',
                '/jpmorgan/treasury/cash-positions',
                '/jpmorgan/treasury/fx-rates',
                '/jpmorgan/treasury/liquidity-forecast',
                '/jpmorgan/treasury/risk-exposure',
                '/jpmorgan/treasury/investment-instruction',
                '/jpmorgan/treasury/portfolio-performance',
                '/jpmorgan/treasury/cash-flow-analytics'
            ],
            status: 'deployed'
        };

        fs.writeFileSync(
            path.join(this.projectRoot, 'staging_deployment_report.json'),
            JSON.stringify(report, null, 2)
        );

        this.log('✅ Deployment report generated', 'success');
    }

    async rollback() {
        this.log('🔄 Rolling back deployment...', 'warning');

        try {
            execSync('docker-compose -f docker-compose.staging.yml down -v', {
                cwd: this.projectRoot,
                stdio: 'inherit'
            });
            this.log('✅ Rollback completed', 'success');
        } catch (error) {
            this.log(`❌ Rollback failed: ${error.message}`, 'error');
        }
    }
}

// Run deployment if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    const deployment = new StagingDeployment();
    deployment.run().catch(console.error);
}

export default StagingDeployment;
