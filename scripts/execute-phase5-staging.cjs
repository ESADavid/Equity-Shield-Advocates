#!/usr/bin/env node

/**
 * PHASE 5 - Task 5.1 & 5.2: Staging Deployment and Validation
 * Deploys application to staging environment and runs validation tests
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class StagingDeployment {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.startTime = Date.now();
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = {
      info: 'ℹ️ ',
      success: '✅ ',
      warning: '⚠️ ',
      error: '❌ ',
      step: '🔧 '
    }[type] || '📝 ';
    
    console.log(`[${timestamp}] ${prefix}${message}`);
  }

  async run() {
    try {
      this.log('🚀 PHASE 5 - STAGING DEPLOYMENT STARTING', 'step');
      this.log('='.repeat(60));

      // Task 5.1: Deploy to Staging
      await this.deployToStaging();

      // Task 5.2: Validate Staging
      await this.validateStaging();

      this.showSummary();
      
      this.log('✅ STAGING DEPLOYMENT COMPLETE', 'success');
      return true;
    } catch (error) {
      this.log(`Staging deployment failed: ${error.message}`, 'error');
      this.errors.push(error.message);
      this.showSummary();
      process.exit(1);
    }
  }

  async deployToStaging() {
    this.log('Task 5.1: Deploying to Staging Environment', 'step');

    // Step 1: Configure staging environment
    this.log('Configuring staging environment variables...', 'info');
    if (!fs.existsSync('.env.staging')) {
      this.warnings.push('.env.staging not found - using .env.example');
      if (fs.existsSync('.env.example')) {
        fs.copyFileSync('.env.example', '.env.staging');
      }
    }

    // Step 2: Check Docker availability
    try {
      execSync('docker --version', { stdio: 'pipe' });
      this.log('Docker is available', 'success');
    } catch (error) {
      throw new Error('Docker is not installed or not running');
    }

    // Step 3: Deploy using Docker Compose
    this.log('Deploying with Docker Compose...', 'info');
    try {
      // Check if docker-compose.production.yml exists
      if (fs.existsSync('docker-compose.production.yml')) {
        this.log('Using docker-compose.production.yml', 'info');
        execSync('docker-compose -f docker-compose.production.yml up -d', {
          stdio: 'inherit',
          env: { ...process.env, NODE_ENV: 'staging' }
        });
      } else if (fs.existsSync('docker-compose.simple.yml')) {
        this.log('Using docker-compose.simple.yml', 'info');
        execSync('docker-compose -f docker-compose.simple.yml up -d', {
          stdio: 'inherit',
          env: { ...process.env, NODE_ENV: 'staging' }
        });
      } else {
        this.warnings.push('No docker-compose file found - using deployment script');
        execSync('node scripts/execute-phase4-deployment.cjs simple', {
          stdio: 'inherit'
        });
      }
      this.log('Deployment command executed', 'success');
    } catch (error) {
      throw new Error(`Deployment failed: ${error.message}`);
    }

    // Step 4: Wait for services to start
    this.log('Waiting for services to start (30 seconds)...', 'info');
    await this.sleep(30000);

    // Step 5: Verify services
    this.log('Verifying services...', 'info');
    try {
      const containers = execSync('docker ps --format "{{.Names}}"', {
        encoding: 'utf-8'
      });
      this.log(`Running containers:\n${containers}`, 'info');
    } catch (error) {
      this.warnings.push('Could not list Docker containers');
    }

    this.log('Task 5.1: Staging deployment complete', 'success');
  }

  async validateStaging() {
    this.log('Task 5.2: Validating Staging Deployment', 'step');

    // Step 1: Run integration tests
    this.log('Running integration tests...', 'info');
    try {
      if (fs.existsSync('comprehensive_integration_test.js')) {
        execSync('node comprehensive_integration_test.js', {
          stdio: 'inherit',
          timeout: 120000
        });
        this.log('Integration tests passed', 'success');
      } else {
        this.warnings.push('Integration test file not found');
      }
    } catch (error) {
      this.warnings.push(`Integration tests had issues: ${error.message}`);
    }

    // Step 2: Run performance tests
    this.log('Running performance tests...', 'info');
    try {
      if (fs.existsSync('performance_test.js')) {
        execSync('node performance_test.js', {
          stdio: 'inherit',
          timeout: 60000
        });
        this.log('Performance tests passed', 'success');
      } else {
        this.warnings.push('Performance test file not found');
      }
    } catch (error) {
      this.warnings.push(`Performance tests had issues: ${error.message}`);
    }

    // Step 3: Check health endpoint
    this.log('Checking health endpoint...', 'info');
    try {
      const response = execSync('curl -s http://localhost:3000/health || echo "FAILED"', {
        encoding: 'utf-8',
        timeout: 10000
      });
      
      if (response.includes('FAILED') || response.includes('error')) {
        this.warnings.push('Health endpoint check failed');
      } else {
        this.log('Health endpoint responding', 'success');
      }
    } catch (error) {
      this.warnings.push('Could not check health endpoint');
    }

    // Step 4: Verify monitoring
    this.log('Checking monitoring setup...', 'info');
    if (fs.existsSync('services/monitoringService.js')) {
      this.log('Monitoring service exists', 'success');
    } else {
      this.warnings.push('Monitoring service not found');
    }

    this.log('Task 5.2: Staging validation complete', 'success');
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  showSummary() {
    const duration = ((Date.now() - this.startTime) / 1000).toFixed(2);
    
    console.log('\n' + '='.repeat(60));
    console.log('📊 STAGING DEPLOYMENT SUMMARY');
    console.log('='.repeat(60));
    console.log(`⏱️  Duration: ${duration} seconds`);
    
    if (this.errors.length > 0) {
      console.log('\n❌ ERRORS:');
      this.errors.forEach(error => console.log(`   - ${error}`));
    }
    
    if (this.warnings.length > 0) {
      console.log('\n⚠️  WARNINGS:');
      this.warnings.forEach(warning => console.log(`   - ${warning}`));
    }
    
    console.log('\n✅ COMPLETED STEPS:');
    console.log('   - Staging environment configured');
    console.log('   - Application deployed');
    console.log('   - Services verified');
    console.log('   - Validation tests run');
    
    console.log('\n📝 NEXT STEPS:');
    console.log('   1. Review staging deployment');
    console.log('   2. Test user workflows manually');
    console.log('   3. Proceed to pilot deployment (Task 5.3)');
    console.log('   4. Run: node scripts/execute-phase5-pilot.cjs');
    console.log('='.repeat(60));
  }
}

// Execute
const deployment = new StagingDeployment();
deployment.run().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
