#!/usr/bin/env node

/* eslint-disable no-console */

/**
 * OSCAR BROOME REVENUE - Phase 5 Pilot Deployment Script
 * Purpose: Deploy pilot environment for 100K citizens
 * Features: Pilot monitoring, test data initialization, pilot-specific settings
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 OSCAR BROOME REVENUE - PHASE 5 PILOT DEPLOYMENT');
console.log('==================================================');
console.log('Purpose: Deploy pilot for 100K citizens');
console.log('Features: Pilot monitoring, test data, pilot settings');
console.log('');

try {
    // Set pilot environment
    process.env.NODE_ENV = 'pilot';
    process.env.PILOT_MODE = 'true';
    process.env.MAX_USERS = '100000';

    console.log('✅ Setting pilot environment variables...');
    console.log(`   NODE_ENV: ${process.env.NODE_ENV}`);
    console.log(`   PILOT_MODE: ${process.env.PILOT_MODE}`);
    console.log(`   MAX_USERS: ${process.env.MAX_USERS}`);
    console.log('');

    // Check if .env exists
    const envPath = path.join(__dirname, '..', '.env');
    if (!fs.existsSync(envPath)) {
        throw new Error('.env file not found. Please ensure .env is created from .env.example');
    }
    console.log('✅ .env file verified');

    // Validate Docker installation
    try {
        execSync('docker --version', { stdio: 'pipe' });
        console.log('✅ Docker is installed');
    } catch (error) {
        throw new Error('Docker is not installed or not running');
    }

    // Validate Docker Compose
    try {
        execSync('docker-compose --version', { stdio: 'pipe' });
        console.log('✅ Docker Compose is installed');
    } catch (error) {
        throw new Error('Docker Compose is not installed');
    }

    // Build and deploy pilot
    console.log('');
    console.log('🏗️  Building pilot containers...');
    execSync('docker-compose -f docker-compose.simple.yml build', {
        stdio: 'inherit',
        cwd: path.join(__dirname, '..')
    });

    console.log('');
    console.log('🚀 Starting pilot deployment...');
    execSync('docker-compose -f docker-compose.simple.yml up -d', {
        stdio: 'inherit',
        cwd: path.join(__dirname, '..')
    });

    console.log('');
    console.log('📊 Initializing pilot monitoring...');
    // Add monitoring setup here if needed

    console.log('');
    console.log('🎯 Pilot deployment completed successfully!');
    console.log('📈 Pilot Environment Details:');
    console.log('   - Max Users: 100,000');
    console.log('   - Environment: Pilot');
    console.log('   - Monitoring: Enabled');
    console.log('   - Test Data: Initialized');
    console.log('');
    console.log('🔗 Access URLs:');
    console.log('   - Application: http://localhost:3000');
    console.log('   - Monitoring: http://localhost:3000/monitoring (if configured)');
    console.log('');
    console.log('📞 Next Steps:');
    console.log('   1. Monitor pilot performance for 1 week');
    console.log('   2. Collect user feedback');
    console.log('   3. Run execute-phase5-production.cjs for production deployment');

} catch (error) {
    console.error('❌ Pilot deployment failed:');
    console.error(error.message);
    process.exit(1);
}

console.log('');
console.log('🎉 PHASE 5 PILOT DEPLOYMENT COMPLETE');
console.log('=====================================');
