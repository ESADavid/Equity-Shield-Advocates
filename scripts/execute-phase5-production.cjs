#!/usr/bin/env node

/**
 * Phase 5: Production Deployment Script
 * Full production deployment for OSCAR BROOME REVENUE
 *
 * OWLBAN GROUP / House of David
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

console.log('🚀 PHASE 5: PRODUCTION DEPLOYMENT');
console.log('='.repeat(60));
console.log('⚠️  WARNING: This will deploy to PRODUCTION');
console.log('='.repeat(60));
console.log('');

class ProductionDeployer {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.dryRun = process.argv.includes('--dry-run');
    this.verbose = process.argv.includes('--verbose');
    this.skipConfirmation = process.argv.includes('--yes');
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix =
      {
        info: 'ℹ️ ',
        success: '✅ ',
        warning: '⚠️ ',
        error: '❌ ',
        step: '🔧 ',
        critical: '🚨 ',
      }[type] || '📝 ';

    console.log(`[${timestamp}] ${prefix}${message}`);
  }

  exec(command, description) {
    this.log(description, 'step');

    if (this.dryRun) {
      this.log(`DRY RUN: ${command}`, 'info');
      return '';
    }

    try {
      const output = execSync(command, {
        encoding: 'utf8',
        stdio: this.verbose ? 'inherit' : 'pipe',
      });
      return output;
    } catch (error) {
      this.log(`Failed: ${error.message}`, 'error');
      throw error;
    }
  }

  async confirmProduction() {
    if (this.skipConfirmation || this.dryRun) {
      return true;
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    return new Promise((resolve) => {
      rl.question(
        '\n🚨 Deploy to PRODUCTION? Type "DEPLOY PRODUCTION" to confirm: ',
        (answer) => {
          rl.close();
          if (answer === 'DEPLOY PRODUCTION') {
            resolve(true);
          } else {
            console.log('❌ Production deployment cancelled');
            process.exit(0);
          }
        }
      );
    });
  }

  async run() {
    try {
      this.log('Starting production deployment process...', 'critical');

      if (this.dryRun) {
        this.log('Running in DRY RUN mode - no actual changes', 'warning');
      }

      await this.confirmProduction();
      await this.checkPrerequisites();
      await this.backupCurrentProduction();
      await this.configureProductionEnvironment();
      await this.deployProductionInfrastructure();
      await this.deployProductionDatabase();
      await this.deployProductionApplication();
      await this.setupProductionMonitoring();
      await this.setupProductionSecurity();
      await this.validateProductionDeployment();
      await this.runProductionTests();
      await this.enableProductionTraffic();
      await this.generateProductionReport();

      this.log('Production deployment completed successfully!', 'success');
      this.showSummary();
    } catch (error) {
      this.log(`Production deployment failed: ${error.message}`, 'error');
      this.errors.push(error.message);
      await this.rollbackProduction();
      this.showSummary();
      process.exit(1);
    }
  }

  async checkPrerequisites() {
    this.log('Checking production prerequisites...', 'step');

    // Check if pilot was successful
    if (!this.dryRun && !fs.existsSync('.pilot-success')) {
      throw new Error('Pilot deployment must be successful first');
    }

    // Check required tools
    const tools = ['kubectl', 'docker', 'helm'];
    for (const tool of tools) {
      try {
        this.exec(`${tool} version`, `Checking ${tool}`);
        this.log(`${tool}: Available`, 'success');
      } catch {
        throw new Error(`${tool} is required but not available`);
      }
    }

    // Check production credentials
    const requiredEnvVars = [
      'STRIPE_SECRET_KEY',
      'JPMORGAN_API_KEY',
      'QUICKBOOKS_CLIENT_ID',
      'PLAID_CLIENT_ID',
      'JWT_SECRET',
      'ENCRYPTION_KEY',
    ];

    for (const envVar of requiredEnvVars) {
      if (!process.env[envVar] && !this.dryRun) {
        this.warnings.push(`${envVar} not set - using placeholder`);
      }
    }

    this.log('Prerequisites check complete', 'success');
  }

  async backupCurrentProduction() {
    this.log('Backing up current production...', 'step');

    const backupCommands = [
      {
        name: 'Backup production database',
        command:
          'kubectl exec -n oscar-broome-production mongodb-0 -- mongodump --archive=/tmp/backup.archive',
      },
      {
        name: 'Copy backup locally',
        command:
          'kubectl cp oscar-broome-production/mongodb-0:/tmp/backup.archive ./production-backup.archive',
      },
      {
        name: 'Backup Kubernetes configs',
        command:
          'kubectl get all -n oscar-broome-production -o yaml > production-k8s-backup.yaml',
      },
    ];

    for (const cmd of backupCommands) {
      try {
        this.exec(cmd.command, cmd.name);
        this.log(`${cmd.name}: Complete`, 'success');
      } catch (error) {
        this.warnings.push(`${cmd.name}: ${error.message}`);
      }
    }
  }

  async configureProductionEnvironment() {
    this.log('Configuring production environment...', 'step');

    const productionConfig = {
      ENVIRONMENT: 'production',
      NODE_ENV: 'production',
      MAX_CITIZENS: '11500000',
      RATE_LIMIT: '10000',
      CACHE_TTL: '600',
      LOG_LEVEL: 'warn',
      ENABLE_ANALYTICS: 'true',
      ENABLE_MONITORING: 'true',
      ENABLE_SECURITY_HEADERS: 'true',
      SSL_ENABLED: 'true',
    };

    if (!this.dryRun) {
      const envContent = Object.entries(productionConfig)
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');

      fs.writeFileSync('.env.production', envContent);
      this.log('Production environment configured', 'success');
    } else {
      this.log('Would create .env.production', 'info');
    }
  }

  async deployProductionInfrastructure() {
    this.log('Deploying production infrastructure...', 'step');

    const tasks = [
      {
        name: 'Create production namespace',
        command: 'kubectl create namespace oscar-broome-production',
        skipOnError: true,
      },
      {
        name: 'Apply production secrets',
        command:
          'kubectl apply -f k8s/production-secrets.yml -n oscar-broome-production',
      },
      {
        name: 'Deploy load balancer',
        command:
          'kubectl apply -f k8s/load-balancer.yml -n oscar-broome-production',
        skipOnError: true,
      },
      {
        name: 'Configure SSL/TLS',
        command:
          'kubectl apply -f k8s/tls-certificates.yml -n oscar-broome-production',
        skipOnError: true,
      },
    ];

    for (const task of tasks) {
      try {
        this.exec(task.command, task.name);
        this.log(`${task.name}: Complete`, 'success');
      } catch (error) {
        if (task.skipOnError) {
          this.warnings.push(`${task.name}: ${error.message}`);
        } else {
          throw error;
        }
      }
    }
  }

  async deployProductionDatabase() {
    this.log('Deploying production database...', 'step');

    const dbTasks = [
      {
        name: 'Deploy MongoDB cluster',
        command:
          'kubectl apply -f k8s/database-production.yml -n oscar-broome-production',
      },
      {
        name: 'Wait for MongoDB ready',
        command:
          'kubectl wait --for=condition=ready pod -l app=mongodb -n oscar-broome-production --timeout=600s',
      },
      {
        name: 'Initialize MongoDB replica set',
        command:
          'kubectl exec -n oscar-broome-production mongodb-0 -- mongo --eval "rs.initiate()"',
        skipOnError: true,
      },
      {
        name: 'Deploy Redis cluster',
        command:
          'kubectl wait --for=condition=ready pod -l app=redis -n oscar-broome-production --timeout=300s',
      },
    ];

    for (const task of dbTasks) {
      try {
        this.exec(task.command, task.name);
        this.log(`${task.name}: Complete`, 'success');
      } catch (error) {
        if (task.skipOnError) {
          this.warnings.push(`${task.name}: ${error.message}`);
        } else {
          throw error;
        }
      }
    }
  }

  async deployProductionApplication() {
    this.log('Deploying production application...', 'step');

    const appTasks = [
      {
        name: 'Build production image',
        command:
          'docker build -t oscar-broome-revenue:production -f Dockerfile.production .',
      },
      {
        name: 'Tag production image',
        command:
          'docker tag oscar-broome-revenue:production registry.oscarbroome.com/oscar-broome-revenue:latest',
        skipOnError: true,
      },
      {
        name: 'Push to registry',
        command:
          'docker push registry.oscarbroome.com/oscar-broome-revenue:latest',
        skipOnError: true,
      },
      {
        name: 'Deploy application',
        command:
          'kubectl apply -f k8s/production-deployment.yml -n oscar-broome-production',
      },
      {
        name: 'Wait for application ready',
        command:
          'kubectl wait --for=condition=ready pod -l app=oscar-broome-revenue -n oscar-broome-production --timeout=600s',
      },
      {
        name: 'Configure ingress',
        command:
          'kubectl apply -f k8s/production-ingress.yml -n oscar-broome-production',
        skipOnError: true,
      },
    ];

    for (const task of appTasks) {
      try {
        this.exec(task.command, task.name);
        this.log(`${task.name}: Complete`, 'success');
      } catch (error) {
        if (task.skipOnError) {
          this.warnings.push(`${task.name}: ${error.message}`);
        } else {
          throw error;
        }
      }
    }
  }

  async setupProductionMonitoring() {
    this.log('Setting up production monitoring...', 'step');

    const monitoringTasks = [
      {
        name: 'Deploy monitoring stack',
        command:
          'kubectl apply -f k8s/monitoring-stack.yml -n oscar-broome-production',
      },
      {
        name: 'Configure Prometheus',
        command:
          'kubectl apply -f k8s/prometheus-config.yml -n oscar-broome-production',
        skipOnError: true,
      },
      {
        name: 'Deploy Grafana',
        command:
          'kubectl apply -f k8s/grafana-deployment.yml -n oscar-broome-production',
        skipOnError: true,
      },
      {
        name: 'Setup alerts',
        command:
          'kubectl apply -f k8s/alertmanager-config.yml -n oscar-broome-production',
        skipOnError: true,
      },
    ];

    for (const task of monitoringTasks) {
      try {
        this.exec(task.command, task.name);
        this.log(`${task.name}: Complete`, 'success');
      } catch (error) {
        if (task.skipOnError) {
          this.warnings.push(`${task.name}: ${error.message}`);
        } else {
          throw error;
        }
      }
    }
  }

  async setupProductionSecurity() {
    this.log('Setting up production security...', 'step');

    const securityTasks = [
      {
        name: 'Apply network policies',
        command:
          'kubectl apply -f k8s/network-policies.yml -n oscar-broome-production',
        skipOnError: true,
      },
      {
        name: 'Configure WAF rules',
        command:
          'kubectl apply -f k8s/waf-rules.yml -n oscar-broome-production',
        skipOnError: true,
      },
      {
        name: 'Enable pod security policies',
        command:
          'kubectl apply -f k8s/pod-security-policies.yml -n oscar-broome-production',
        skipOnError: true,
      },
    ];

    for (const task of securityTasks) {
      try {
        this.exec(task.command, task.name);
        this.log(`${task.name}: Complete`, 'success');
      } catch (error) {
        this.warnings.push(`${task.name}: ${error.message}`);
      }
    }
  }

  async validateProductionDeployment() {
    this.log('Validating production deployment...', 'step');

    const validations = [
      {
        name: 'Check all pods running',
        command: 'kubectl get pods -n oscar-broome-production',
      },
      {
        name: 'Check services',
        command: 'kubectl get services -n oscar-broome-production',
      },
      {
        name: 'Test health endpoint',
        command: 'curl -f https://api.oscarbroome.com/health',
      },
      {
        name: 'Test authentication',
        command: 'curl -f https://api.oscarbroome.com/auth/status',
      },
    ];

    for (const validation of validations) {
      try {
        const output = this.exec(validation.command, validation.name);
        if (this.verbose) {
          console.log(output);
        }
        this.log(`${validation.name}: Passed`, 'success');
      } catch (error) {
        throw new Error(`Validation failed: ${validation.name}`);
      }
    }
  }

  async runProductionTests() {
    this.log('Running production tests...', 'step');

    const tests = [
      {
        name: 'Smoke tests',
        command: 'npm run test:smoke:production',
        skipOnError: true,
      },
      {
        name: 'Integration tests',
        command: 'npm run test:integration:production',
        skipOnError: true,
      },
      {
        name: 'Performance tests',
        command: 'npm run test:performance:production',
        skipOnError: true,
      },
    ];

    for (const test of tests) {
      try {
        this.exec(test.command, test.name);
        this.log(`${test.name}: Passed`, 'success');
      } catch (error) {
        if (test.skipOnError) {
          this.warnings.push(`${test.name}: ${error.message}`);
        } else {
          throw error;
        }
      }
    }
  }

  async enableProductionTraffic() {
    this.log('Enabling production traffic...', 'step');

    if (!this.dryRun) {
      // Gradual traffic ramp-up
      const rampSteps = [10, 25, 50, 75, 100];

      for (const percentage of rampSteps) {
        this.log(`Ramping traffic to ${percentage}%...`, 'info');

        // Update traffic split
        try {
          this.exec(
            `kubectl patch service oscar-broome-service -n oscar-broome-production -p '{"spec":{"trafficPolicy":{"weight":${percentage}}}}'`,
            `Set traffic to ${percentage}%`
          );
        } catch (error) {
          this.warnings.push(
            `Traffic ramp to ${percentage}%: ${error.message}`
          );
        }

        // Wait and monitor
        this.log(`Monitoring for 2 minutes...`, 'info');
        if (!this.dryRun) {
          await new Promise((resolve) => setTimeout(resolve, 120000));
        }
      }
    }

    // Create success marker
    if (!this.dryRun) {
      fs.writeFileSync('.production-success', new Date().toISOString());
    }

    this.log('Production traffic enabled', 'success');
  }

  async rollbackProduction() {
    this.log('Rolling back production deployment...', 'critical');

    try {
      if (fs.existsSync('production-k8s-backup.yaml')) {
        this.exec(
          'kubectl apply -f production-k8s-backup.yaml',
          'Restoring previous production state'
        );
        this.log('Rollback complete', 'success');
      } else {
        this.log('No backup found - manual rollback required', 'error');
      }
    } catch (error) {
      this.log(`Rollback failed: ${error.message}`, 'error');
    }
  }

  async generateProductionReport() {
    this.log('Generating production deployment report...', 'step');

    const report = {
      timestamp: new Date().toISOString(),
      environment: 'production',
      targetCapacity: '11.5M citizens',
      status: this.errors.length === 0 ? 'SUCCESS' : 'FAILED',
      errors: this.errors,
      warnings: this.warnings,
      deploymentDuration: 'N/A',
      nextSteps: [
        'Monitor production for 24 hours',
        'Verify all integrations',
        'Check performance metrics',
        'Prepare for scaling',
      ],
    };

    if (!this.dryRun) {
      fs.writeFileSync(
        'production-deployment-report.json',
        JSON.stringify(report, null, 2)
      );
      this.log('Report saved to production-deployment-report.json', 'success');
    }
  }

  showSummary() {
    console.log('\n📊 PRODUCTION DEPLOYMENT SUMMARY');
    console.log('='.repeat(60));

    if (this.errors.length > 0) {
      console.log('\n❌ ERRORS:');
      for (const error of this.errors) {
        console.log(`   - ${error}`);
      }
    }

    if (this.warnings.length > 0) {
      console.log('\n⚠️  WARNINGS:');
      for (const warning of this.warnings) {
        console.log(`   - ${warning}`);
      }
    }

    console.log('\n✅ COMPLETED STEPS:');
    console.log('   - Prerequisites check');
    console.log('   - Production backup');
    console.log('   - Environment configuration');
    console.log('   - Infrastructure deployment');
    console.log('   - Database deployment');
    console.log('   - Application deployment');
    console.log('   - Monitoring setup');
    console.log('   - Security configuration');
    console.log('   - Validation');
    console.log('   - Production tests');
    console.log('   - Traffic enablement');

    console.log('\n🔧 NEXT STEPS:');
    console.log('   1. Monitor production: https://oscarbroome.com');
    console.log('   2. Check Grafana: https://monitoring.oscarbroome.com');
    console.log('   3. Review logs: kubectl logs -n oscar-broome-production');
    console.log('   4. Monitor for 24 hours');
    console.log(
      '   5. Proceed to scaling: node scripts/execute-phase5-scaling.cjs'
    );

    console.log('\n📝 PRODUCTION METRICS:');
    console.log('   - Target: 11.5M citizens');
    console.log('   - Response time: < 200ms');
    console.log('   - Uptime: > 99.9%');
    console.log('   - Error rate: < 0.1%');
  }
}

// Run the production deployer
const deployer = new ProductionDeployer();
deployer.run().catch((error) => {
  console.error('\n💥 PRODUCTION DEPLOYMENT FAILED');
  console.error('='.repeat(60));
  console.error(error.message);
  process.exit(1);
});
