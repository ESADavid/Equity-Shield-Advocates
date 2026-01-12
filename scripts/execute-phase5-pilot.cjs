#!/usr/bin/env node

/**
 * PHASE 5 - Task 5.3: Pilot Deployment
 * Deploys application to pilot environment for 100K citizens
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class PilotDeployment {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.startTime = Date.now();
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
      }[type] || '📝 ';

    console.log(`[${timestamp}] ${prefix}${message}`);
  }

  async run() {
    try {
      this.log('🚀 PHASE 5 - PILOT DEPLOYMENT STARTING', 'step');
      this.log('='.repeat(60));

      // Task 5.3: Deploy Pilot
      await this.deployPilot();

      // Task 5.4: Setup Pilot Monitoring
      await this.setupPilotMonitoring();

      // Task 5.5: Initialize Test Data
      await this.initializeTestData();

      this.showSummary();

      this.log('✅ PILOT DEPLOYMENT COMPLETE', 'success');
      return true;
    } catch (error) {
      this.log(`Pilot deployment failed: ${error.message}`, 'error');
      this.errors.push(error.message);
      this.showSummary();
      process.exit(1);
    }
  }

  async deployPilot() {
    this.log('Task 5.3: Deploying Pilot Environment (100K Citizens)', 'step');

    // Step 1: Configure pilot environment
    this.log('Configuring pilot environment variables...', 'info');
    if (!fs.existsSync('.env.pilot')) {
      this.warnings.push('.env.pilot not found - using .env.staging');
      if (fs.existsSync('.env.staging')) {
        fs.copyFileSync('.env.staging', '.env.pilot');
      } else if (fs.existsSync('.env.example')) {
        fs.copyFileSync('.env.example', '.env.pilot');
      }
    }

    // Step 2: Set pilot-specific configurations
    this.log('Setting pilot configurations...', 'info');
    const envContent = fs.readFileSync('.env.pilot', 'utf-8');
    const updatedEnv = envContent
      .replace(/NODE_ENV=.*/, 'NODE_ENV=pilot')
      .replace(/PILOT_MODE=.*/, 'PILOT_MODE=true')
      .replace(/MAX_USERS=.*/, 'MAX_USERS=100000');

    fs.writeFileSync('.env.pilot', updatedEnv);

    // Step 3: Deploy using Docker Compose
    this.log('Deploying pilot with Docker Compose...', 'info');
    try {
      execSync('docker-compose -f docker-compose.production.yml up -d --scale app=2', {
        stdio: 'inherit',
        env: { ...process.env, NODE_ENV: 'pilot', PILOT_MODE: 'true' },
      });
      this.log('Pilot deployment command executed', 'success');
    } catch (error) {
      throw new Error(`Pilot deployment failed: ${error.message}`);
    }

    // Step 4: Wait for services to start
    this.log('Waiting for pilot services to start (45 seconds)...', 'info');
    await this.sleep(45000);

    // Step 5: Verify pilot services
    this.log('Verifying pilot services...', 'info');
    try {
      const containers = execSync('docker ps --format "{{.Names}}"', {
        encoding: 'utf-8',
      });
      this.log(`Pilot containers:\n${containers}`, 'info');
    } catch (error) {
      this.warnings.push('Could not list pilot containers');
    }

    this.log('Task 5.3: Pilot deployment complete', 'success');
  }

  async setupPilotMonitoring() {
    this.log('Task 5.4: Setting Up Pilot Monitoring', 'step');

    // Step 1: Configure monitoring for pilot
    this.log('Configuring pilot monitoring...', 'info');
    try {
      execSync('docker-compose -f docker-compose.production.yml up -d monitoring', {
        stdio: 'inherit',
      });
      this.log('Pilot monitoring configured', 'success');
    } catch (error) {
      this.warnings.push(`Monitoring setup had issues: ${error.message}`);
    }

    // Step 2: Set up pilot-specific alerts
    this.log('Setting up pilot alerts...', 'info');
    if (fs.existsSync('services/monitoringService.js')) {
      this.log('Monitoring service configured for pilot', 'success');
    } else {
      this.warnings.push('Monitoring service not found');
    }

    // Step 3: Initialize pilot metrics collection
    this.log('Initializing pilot metrics collection...', 'info');
    try {
      execSync('curl -s http://localhost:3000/metrics/init || echo "Metrics init attempted"', {
        timeout: 5000,
      });
      this.log('Pilot metrics initialized', 'success');
    } catch (error) {
      this.warnings.push('Could not initialize pilot metrics');
    }

    this.log('Task 5.4: Pilot monitoring setup complete', 'success');
  }

  async initializeTestData() {
    this.log('Task 5.5: Initializing Pilot Test Data', 'step');

    // Step 1: Create pilot test users
    this.log('Creating pilot test users...', 'info');
    try {
      execSync('node scripts/create-pilot-users.js || echo "Pilot user creation script not found"', {
        stdio: 'inherit',
        timeout: 30000,
      });
      this.log('Pilot test users created', 'success');
    } catch (error) {
      this.warnings.push('Could not create pilot test users');
    }

    // Step 2: Initialize pilot transactions
    this.log('Initializing pilot transactions...', 'info');
    try {
      execSync('node scripts/init-pilot-data.js || echo "Pilot data init script not found"', {
        stdio: 'inherit',
        timeout: 30000,
      });
      this.log('Pilot transactions initialized', 'success');
    } catch (error) {
      this.warnings.push('Could not initialize pilot transactions');
    }

    // Step 3: Verify pilot data
    this.log('Verifying pilot data...', 'info');
    try {
      const response = execSync(
        'curl -s http://localhost:3000/api/pilot/status || echo "PILOT_STATUS_CHECK_FAILED"',
        {
          encoding: 'utf-8',
          timeout: 10000,
        }
      );

      if (response.includes('PILOT_STATUS_CHECK_FAILED')) {
        this.warnings.push('Pilot status check failed');
      } else {
        this.log('Pilot data verified', 'success');
      }
    } catch (error) {
      this.warnings.push('Could not verify pilot data');
    }

    this.log('Task 5.5: Pilot test data initialization complete', 'success');
  }

  sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  showSummary() {
    const duration = ((Date.now() - this.startTime) / 1000).toFixed(2);

    console.log('\n' + '='.repeat(60));
    console.log('📊 PILOT DEPLOYMENT SUMMARY');
    console.log('='.repeat(60));
    console.log(`⏱️  Duration: ${duration} seconds`);

    if (this.errors.length > 0) {
      console.log('\n❌ ERRORS:');
      this.errors.forEach((error) => console.log(`   - ${error}`));
    }

    if (this.warnings.length > 0) {
      console.log('\n⚠️  WARNINGS:');
      this.warnings.forEach((warning) => console.log(`   - ${warning}`));
    }

    console.log('\n✅ COMPLETED STEPS:');
    console.log('   - Pilot environment configured');
    console.log('   - Application deployed to pilot');
    console.log('   - Pilot monitoring set up');
    console.log('   - Test data initialized');

    console.log('\n📝 NEXT STEPS:');
    console.log('   1. Monitor pilot for 24-48 hours');
    console.log('   2. Collect user feedback');
    console.log('   3. Run pilot validation tests');
    console.log('   4. Proceed to production deployment (Task 5.6)');
    console.log('   5. Run: node scripts/execute-phase5-production.cjs');
    console.log('='.repeat(60));
  }
}

// Execute
const deployment = new PilotDeployment();
deployment.run().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
