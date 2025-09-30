#!/usr/bin/env node

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

class SecurityAuditor {
  constructor() {
    this.results = {
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      recommendations: [],
      score: 0,
      status: 'pending'
    };
  }

  async runFullAudit() {
    console.log('🔒 Starting Comprehensive Security Audit...');
    console.log('=' .repeat(50));

    try {
      await this.checkDependencies();
      await this.checkConfiguration();
      await this.checkCodeQuality();
      await this.checkAuthentication();
      await this.checkDataProtection();
      await this.generateReport();

      this.results.status = 'completed';
      console.log('\n✅ Security audit completed successfully!');
      console.log(`📊 Security Score: ${this.results.score}/100`);

    } catch (error) {
      console.error('❌ Security audit failed:', error.message);
      this.results.status = 'failed';
      this.results.error = error.message;
    }

    return this.results;
  }

  async checkDependencies() {
    console.log('\n🔍 Checking Dependencies...');

    try {
      // Check for known vulnerabilities
      console.log('   Checking for vulnerable dependencies...');
      const auditOutput = execSync('npm audit --json', { cwd: rootDir, encoding: 'utf8' });
      const auditData = JSON.parse(auditOutput);

      if (auditData.vulnerabilities && Object.keys(auditData.vulnerabilities).length > 0) {
        const vulnCount = Object.keys(auditData.vulnerabilities).length;
        this.results.vulnerabilities.push({
          type: 'dependency_vulnerability',
          severity: 'high',
          count: vulnCount,
          details: 'Vulnerable dependencies found'
        });
        this.results.recommendations.push('Run "npm audit fix" to address dependency vulnerabilities');
        this.results.score -= vulnCount * 5;
      } else {
        console.log('   ✅ No dependency vulnerabilities found');
        this.results.score += 20;
      }
    } catch (error) {
      console.log('   ⚠️ Could not run npm audit:', error.message);
      this.results.recommendations.push('Ensure npm audit can run successfully');
    }

    // Check for outdated packages
    try {
      console.log('   Checking for outdated packages...');
      const outdatedOutput = execSync('npm outdated --json', { cwd: rootDir, encoding: 'utf8' });
      const outdatedData = JSON.parse(outdatedOutput);

      const outdatedCount = Object.keys(outdatedData).length;
      if (outdatedCount > 0) {
        this.results.recommendations.push(`Update ${outdatedCount} outdated packages`);
        this.results.score -= outdatedCount * 2;
      } else {
        console.log('   ✅ All packages are up to date');
        this.results.score += 10;
      }
    } catch (error) {
      // npm outdated exits with code 1 when there are outdated packages
      if (error.stdout) {
        const outdatedData = JSON.parse(error.stdout);
        const outdatedCount = Object.keys(outdatedData).length;
        this.results.recommendations.push(`Update ${outdatedCount} outdated packages`);
        this.results.score -= outdatedCount * 2;
      }
    }
  }

  async checkConfiguration() {
    console.log('\n🔍 Checking Configuration Security...');

    // Check for exposed secrets
    const configFiles = ['.env', '.env.local', '.env.production', '.env.staging'];
    let secretsFound = 0;

    for (const file of configFiles) {
      const filePath = path.join(rootDir, file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        const secretPatterns = [
          /password\s*=\s*[^$]/i,
          /secret\s*=\s*[^$]/i,
          /key\s*=\s*[^$]/i,
          /token\s*=\s*[^$]/i
        ];

        secretPatterns.forEach(pattern => {
          if (pattern.test(content)) {
            secretsFound++;
          }
        });
      }
    }

    if (secretsFound > 0) {
      this.results.vulnerabilities.push({
        type: 'exposed_secrets',
        severity: 'critical',
        count: secretsFound,
        details: 'Potential secrets found in configuration files'
      });
      this.results.recommendations.push('Move secrets to environment variables or secure vault');
      this.results.score -= 30;
    } else {
      console.log('   ✅ No exposed secrets found in configuration');
      this.results.score += 15;
    }

    // Check for debug mode in production
    const envContent = fs.readFileSync(path.join(rootDir, '.env'), 'utf8');
    if (envContent.includes('NODE_ENV=development') || envContent.includes('DEBUG=true')) {
      this.results.vulnerabilities.push({
        type: 'debug_enabled',
        severity: 'medium',
        details: 'Debug mode may be enabled in production'
      });
      this.results.recommendations.push('Ensure NODE_ENV=production and DEBUG=false in production');
      this.results.score -= 10;
    } else {
      console.log('   ✅ Production configuration appears secure');
      this.results.score += 10;
    }
  }

  async checkCodeQuality() {
    console.log('\n🔍 Checking Code Quality...');

    // Check for security-related code patterns
    const sourceFiles = this.getSourceFiles();
    let insecurePatterns = 0;

    const patterns = [
      /console\.log.*password/i,
      /console\.log.*token/i,
      /console\.log.*secret/i,
      /eval\s*\(/,
      /innerHTML\s*=/
    ];

    for (const file of sourceFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        patterns.forEach(pattern => {
          const matches = content.match(pattern);
          if (matches) {
            insecurePatterns += matches.length;
          }
        });
      } catch (error) {
        // Skip files that can't be read
      }
    }

    if (insecurePatterns > 0) {
      this.results.vulnerabilities.push({
        type: 'insecure_code_patterns',
        severity: 'high',
        count: insecurePatterns,
        details: 'Potentially insecure code patterns found'
      });
      this.results.recommendations.push('Review and fix insecure code patterns (console.log secrets, eval, innerHTML)');
      this.results.score -= insecurePatterns * 5;
    } else {
      console.log('   ✅ No insecure code patterns found');
      this.results.score += 15;
    }
  }

  async checkAuthentication() {
    console.log('\n🔍 Checking Authentication Security...');

    // Check for proper JWT configuration
    const envContent = fs.readFileSync(path.join(rootDir, '.env'), 'utf8');
    const jwtSecret = envContent.match(/JWT_SECRET\s*=\s*(.+)/);

    if (!jwtSecret || jwtSecret[1].length < 32) {
      this.results.vulnerabilities.push({
        type: 'weak_jwt_secret',
        severity: 'high',
        details: 'JWT secret is too short or missing'
      });
      this.results.recommendations.push('Use a strong, random JWT secret of at least 32 characters');
      this.results.score -= 20;
    } else {
      console.log('   ✅ Strong JWT secret configured');
      this.results.score += 10;
    }

    // Check for password policies
    const userModelPath = path.join(rootDir, 'models', 'User.js');
    if (fs.existsSync(userModelPath)) {
      const userModel = fs.readFileSync(userModelPath, 'utf8');
      if (!userModel.includes('bcrypt') && !userModel.includes('password.*hash')) {
        this.results.vulnerabilities.push({
          type: 'weak_password_hashing',
          severity: 'high',
          details: 'Password hashing may not be properly implemented'
        });
        this.results.recommendations.push('Ensure passwords are properly hashed with bcrypt or similar');
        this.results.score -= 15;
      } else {
        console.log('   ✅ Password hashing appears properly implemented');
        this.results.score += 10;
      }
    }
  }

  async checkDataProtection() {
    console.log('\n🔍 Checking Data Protection...');

    // Check for HTTPS enforcement
    const serverFile = path.join(rootDir, 'server-enhanced.js');
    if (fs.existsSync(serverFile)) {
      const serverContent = fs.readFileSync(serverFile, 'utf8');
      if (!serverContent.includes('helmet') || !serverContent.includes('https')) {
        this.results.recommendations.push('Consider enforcing HTTPS and using security headers');
        this.results.score -= 5;
      } else {
        console.log('   ✅ HTTPS and security headers configured');
        this.results.score += 10;
      }
    }

    // Check for rate limiting
    if (!serverContent.includes('rateLimit') && !serverContent.includes('express-rate-limit')) {
      this.results.vulnerabilities.push({
        type: 'no_rate_limiting',
        severity: 'medium',
        details: 'Rate limiting not implemented'
      });
      this.results.recommendations.push('Implement rate limiting to prevent abuse');
      this.results.score -= 10;
    } else {
      console.log('   ✅ Rate limiting implemented');
      this.results.score += 10;
    }
  }

  getSourceFiles() {
    const files = [];
    const dirs = ['services', 'routes', 'middleware', 'models', 'controllers'];

    function scanDir(dirPath) {
      if (fs.existsSync(dirPath)) {
        const items = fs.readdirSync(dirPath);
        for (const item of items) {
          const fullPath = path.join(dirPath, item);
          const stat = fs.statSync(fullPath);

          if (stat.isDirectory()) {
            scanDir(fullPath);
          } else if (item.endsWith('.js') || item.endsWith('.ts')) {
            files.push(fullPath);
          }
        }
      }
    }

    dirs.forEach(dir => scanDir(path.join(rootDir, dir)));
    return files;
  }

  async generateReport() {
    console.log('\n📊 Generating Security Audit Report...');

    // Ensure score is within bounds
    this.results.score = Math.max(0, Math.min(100, this.results.score + 50)); // Base score of 50

    const reportPath = path.join(rootDir, 'logs', 'security-audit-report.json');
    const logsDir = path.dirname(reportPath);

    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    fs.writeFileSync(reportPath, JSON.stringify(this.results, null, 2));

    console.log(`   Report saved to: ${reportPath}`);

    // Print summary
    console.log('\n📈 Security Audit Summary:');
    console.log(`   Score: ${this.results.score}/100`);
    console.log(`   Vulnerabilities: ${this.results.vulnerabilities.length}`);
    console.log(`   Recommendations: ${this.results.recommendations.length}`);

    if (this.results.vulnerabilities.length > 0) {
      console.log('\n🚨 Critical Issues:');
      this.results.vulnerabilities.forEach(vuln => {
        console.log(`   - ${vuln.type}: ${vuln.details}`);
      });
    }

    if (this.results.recommendations.length > 0) {
      console.log('\n💡 Recommendations:');
      this.results.recommendations.forEach(rec => {
        console.log(`   - ${rec}`);
      });
    }
  }
}

// Run audit if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const auditor = new SecurityAuditor();
  auditor.runFullAudit().then(() => {
    process.exit(0);
  }).catch(error => {
    console.error('Audit failed:', error);
    process.exit(1);
  });
}

export default SecurityAuditor;
