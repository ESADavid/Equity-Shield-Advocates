#!/usr/bin/env node

/**
 * OSCAR BROOME REVENUE - Phase 4 Deployment Execution Script
 * 
 * This script orchestrates the complete Phase 4 deployment process:
 * 1. Pre-deployment validation
 * 2. Infrastructure setup
 * 3. Application deployment
 * 4. Post-deployment verification
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class Phase4Deployer {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.completedSteps = [];
    this.deploymentMode = process.argv[2] || 'docker'; // docker, kubernetes, or simple
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const icons = {
      info: 'ℹ️',
      success: '✅',
      warning: '⚠️',
      error: '❌',
      step: '🔧',
      progress: '⏳'
    };
    const icon = icons[type] || '📝';
    console.log(`[${timestamp}] ${icon} ${message}`);
  }

  async execute() {
    try {
      this.log('🚀 PHASE 4: DEPLOYMENT & PRODUCTION READINESS', 'step');
      this.log('='.repeat(60));
      this.log(`Deployment Mode: ${this.deploymentMode.toUpperCase()}`);
      this.log('');

      await this.validatePrerequisites();
      await this.checkInfrastructureFiles();
      await this.validateConfigurations();
      await this.executeDeployment();
      await this.runPostDeploymentChecks();
      
      this.showSummary();
      this.log('Phase 4 deployment execution completed!', 'success');
      
    } catch (error) {
      this.log(`Deployment failed: ${error.message}`, 'error');
      this.errors.push(error.message);
      this.showSummary();
      process.exit(1);
    }
  }

  async validatePrerequisites() {
    this.log('Validating prerequisites...', 'step');

    // Check Node.js version
    const nodeVersion = process.version;
    this.log(`Node.js version: ${nodeVersion}`);
    
    // Check if required tools are installed
    const tools = {
      docker: 'docker --version',
      'docker-compose': 'docker-compose --version',
      kubectl: 'kubectl version --client',
      git: 'git --version'
    };

    for (const [tool, command] of Object.entries(tools)) {
      try {
        const output = execSync(command, { encoding: 'utf8', stdio: 'pipe' });
        this.log(`${tool}: ${output.trim().split('\n')[0]}`, 'success');
      } catch (error) {
        if (tool === 'kubectl' && this.deploymentMode !== 'kubernetes') {
          this.log(`${tool}: Not required for ${this.deploymentMode} mode`, 'warning');
        } else if (tool === 'docker' || tool === 'docker-compose') {
          this.log(`${tool}: Not installed`, 'warning');
          this.warnings.push(`${tool} is not installed`);
        }
      }
    }

    // Check if package.json exists
    if (!fs.existsSync('package.json')) {
      throw new Error('package.json not found. Run from project root.');
    }

    this.completedSteps.push('Prerequisites validation');
    this.log('Prerequisites validation completed', 'success');
  }

  async checkInfrastructureFiles() {
    this.log('Checking infrastructure files...', 'step');

    const requiredFiles = {
      docker: [
        'docker-compose.production.yml',
        'docker-compose.simple.yml',
        'Dockerfile.production',
        'nginx.conf'
      ],
      kubernetes: [
        'k8s/production-deployment.yml',
        'k8s/database-production.yml',
        'k8s/monitoring-stack.yml',
        'k8s/simple-deployment.yml'
      ],
      common: [
        'production_deploy.mjs',
        'production_deploy_simple.mjs',
        '.env.example'
      ]
    };

    const filesToCheck = [
      ...requiredFiles.common,
      ...(this.deploymentMode === 'kubernetes' ? requiredFiles.kubernetes : requiredFiles.docker)
    ];

    let missingFiles = [];
    for (const file of filesToCheck) {
      if (fs.existsSync(file)) {
        this.log(`✓ ${file}`, 'success');
      } else {
        this.log(`✗ ${file} - MISSING`, 'error');
        missingFiles.push(file);
      }
    }

    if (missingFiles.length > 0) {
      throw new Error(`Missing required files: ${missingFiles.join(', ')}`);
    }

    this.completedSteps.push('Infrastructure files check');
    this.log('All infrastructure files present', 'success');
  }

  async validateConfigurations() {
    this.log('Validating configurations...', 'step');

    // Check environment file
    if (!fs.existsSync('.env') && !fs.existsSync('.env.production')) {
      this.log('No .env file found. Creating from example...', 'warning');
      if (fs.existsSync('.env.example')) {
        fs.copyFileSync('.env.example', '.env');
        this.log('.env file created from example', 'success');
        this.warnings.push('Please configure .env file with actual credentials');
      } else {
        this.warnings.push('No .env.example found. Manual configuration required');
      }
    }

    // Validate YAML files for Kubernetes
    if (this.deploymentMode === 'kubernetes') {
      try {
        const yamlFiles = [
          'k8s/production-deployment.yml',
          'k8s/database-production.yml',
          'k8s/monitoring-stack.yml'
        ];

        for (const file of yamlFiles) {
          if (fs.existsSync(file)) {
            // Basic YAML validation - check if file is readable
            const content = fs.readFileSync(file, 'utf8');
            if (content.length === 0) {
              throw new Error(`${file} is empty`);
            }
            this.log(`✓ ${file} validated`, 'success');
          }
        }
      } catch (error) {
        this.warnings.push(`YAML validation warning: ${error.message}`);
      }
    }

    this.completedSteps.push('Configuration validation');
    this.log('Configuration validation completed', 'success');
  }

  async executeDeployment() {
    this.log('Executing deployment...', 'step');

    switch (this.deploymentMode) {
      case 'docker':
        await this.deployDocker();
        break;
      case 'kubernetes':
        await this.deployKubernetes();
        break;
      case 'simple':
        await this.deploySimple();
        break;
      default:
        throw new Error(`Unknown deployment mode: ${this.deploymentMode}`);
    }

    this.completedSteps.push('Deployment execution');
  }

  async deployDocker() {
    this.log('Deploying with Docker Compose (Production)...', 'progress');

    try {
      // Build images
      this.log('Building Docker images...', 'progress');
      execSync('docker-compose -f docker-compose.production.yml build', {
        stdio: 'inherit'
      });

      // Start services
      this.log('Starting services...', 'progress');
      execSync('docker-compose -f docker-compose.production.yml up -d', {
        stdio: 'inherit'
      });

      this.log('Docker deployment completed', 'success');
    } catch (error) {
      throw new Error(`Docker deployment failed: ${error.message}`);
    }
  }

  async deployKubernetes() {
    this.log('Deploying to Kubernetes...', 'progress');

    try {
      // Apply namespace and configs
      this.log('Creating namespace and configurations...', 'progress');
      execSync('kubectl apply -f k8s/production-deployment.yml', {
        stdio: 'inherit'
      });

      // Deploy database
      this.log('Deploying database...', 'progress');
      execSync('kubectl apply -f k8s/database-production.yml', {
        stdio: 'inherit'
      });

      // Deploy monitoring
      this.log('Deploying monitoring stack...', 'progress');
      execSync('kubectl apply -f k8s/monitoring-stack.yml', {
        stdio: 'inherit'
      });

      this.log('Kubernetes deployment completed', 'success');
      this.log('Run "kubectl get pods -n oscar-broome-production" to check status', 'info');
    } catch (error) {
      throw new Error(`Kubernetes deployment failed: ${error.message}`);
    }
  }

  async deploySimple() {
    this.log('Deploying with Simple Configuration...', 'progress');

    try {
      // Use simple docker-compose
      this.log('Starting simple deployment...', 'progress');
      execSync('docker-compose -f docker-compose.simple.yml up -d', {
        stdio: 'inherit'
      });

      this.log('Simple deployment completed', 'success');
    } catch (error) {
      throw new Error(`Simple deployment failed: ${error.message}`);
    }
  }

  async runPostDeploymentChecks() {
    this.log('Running post-deployment checks...', 'step');

    // Wait for services to start
    this.log('Waiting for services to initialize...', 'progress');
    await this.sleep(10000);

    // Check if services are running
    if (this.deploymentMode === 'docker' || this.deploymentMode === 'simple') {
      try {
        const composeFile = this.deploymentMode === 'docker' 
          ? 'docker-compose.production.yml' 
          : 'docker-compose.simple.yml';
        
        const output = execSync(`docker-compose -f ${composeFile} ps`, {
          encoding: 'utf8'
        });
        this.log('Service status:', 'info');
        console.log(output);
      } catch (error) {
        this.warnings.push('Could not check service status');
      }
    }

    if (this.deploymentMode === 'kubernetes') {
      try {
        const output = execSync('kubectl get pods -n oscar-broome-production', {
          encoding: 'utf8'
        });
        this.log('Pod status:', 'info');
        console.log(output);
      } catch (error) {
        this.warnings.push('Could not check pod status');
      }
    }

    this.completedSteps.push('Post-deployment checks');
    this.log('Post-deployment checks completed', 'success');
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  showSummary() {
    console.log('\n' + '='.repeat(60));
    console.log('📊 PHASE 4 DEPLOYMENT SUMMARY');
    console.log('='.repeat(60));

    console.log('\n✅ COMPLETED STEPS:');
    this.completedSteps.forEach(step => {
      console.log(`   ✓ ${step}`);
    });

    if (this.warnings.length > 0) {
      console.log('\n⚠️  WARNINGS:');
      this.warnings.forEach(warning => {
        console.log(`   - ${warning}`);
      });
    }

    if (this.errors.length > 0) {
      console.log('\n❌ ERRORS:');
      this.errors.forEach(error => {
        console.log(`   - ${error}`);
      });
    }

    console.log('\n📝 NEXT STEPS:');
    console.log('   1. Verify all services are running');
    console.log('   2. Check application logs');
    console.log('   3. Run smoke tests');
    console.log('   4. Configure monitoring dashboards');
    console.log('   5. Set up backup procedures');

    console.log('\n🔧 USEFUL COMMANDS:');
    if (this.deploymentMode === 'docker' || this.deploymentMode === 'simple') {
      const file = this.deploymentMode === 'docker' 
        ? 'docker-compose.production.yml' 
        : 'docker-compose.simple.yml';
      console.log(`   - View logs: docker-compose -f ${file} logs -f`);
      console.log(`   - Stop services: docker-compose -f ${file} down`);
      console.log(`   - Restart: docker-compose -f ${file} restart`);
    }
    if (this.deploymentMode === 'kubernetes') {
      console.log('   - View pods: kubectl get pods -n oscar-broome-production');
      console.log('   - View logs: kubectl logs -f <pod-name> -n oscar-broome-production');
      console.log('   - Delete deployment: kubectl delete -f k8s/production-deployment.yml');
    }

    console.log('\n' + '='.repeat(60));
  }
}

// Execute deployment
const deployer = new Phase4Deployer();
deployer.execute().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
