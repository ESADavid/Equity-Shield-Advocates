#!/usr/bin/env node

/**
 * JPMorgan Security Scan Script
 *
 * Performs comprehensive security analysis for JPMorgan payment integrations
 * including financial data protection, API security, and compliance validation.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

class JPMorganSecurityScanner {
  constructor() {
    this.vulnerabilities = [];
    this.warnings = [];
    this.secure = [];
    this.riskScore = 0;
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    logger.info(`[${timestamp}] ${type.toUpperCase()}: ${message}`);
  }

  addVulnerability(severity, message, file = null, line = null, cve = null) {
    const vuln = { severity, message, file, line, cve, timestamp: new Date().toISOString() };
    this.vulnerabilities.push(vuln);

    const riskPoints = { critical: 10, high: 7, medium: 4, low: 2, info: 1 };
    this.riskScore += riskPoints[severity] || 1;

    this.log(`${severity.toUpperCase()}: ${message}`, 'error');
  }

  addWarning(message, file = null, line = null) {
    this.warnings.push({ message, file, line, timestamp: new Date().toISOString() });
    this.log(`WARNING: ${message}`, 'warn');
  }

  addSecure(message) {
    this.secure.push({ message, timestamp: new Date().toISOString() });
    this.log(`SECURE: ${message}`, 'success');
  }

  // Check for financial data exposure patterns
  checkFinancialDataExposure() {
    this.log('Scanning for financial data exposure...');

    const financialPatterns = [
      { pattern: /credit.*card|card.*number/i, severity: 'critical', description: 'Credit card number exposure' },
      { pattern: /cvv|cvc|security.*code/i, severity: 'critical', description: 'CVV/security code exposure' },
      { pattern: /social.*security|ssn/i, severity: 'high', description: 'SSN exposure' },
      { pattern: /bank.*account|routing.*number/i, severity: 'high', description: 'Bank account exposure' },
      { pattern: /api.*key.*jpmorgan|jpmorgan.*secret/i, severity: 'critical', description: 'JPMorgan API credentials' },
      { pattern: /password.*jpmorgan|jpmorgan.*password/i, severity: 'high', description: 'JPMorgan password exposure' }
    ];

    const excludeDirs = ['node_modules', '.git', 'logs', 'dist', 'coverage', 'test'];
    const excludeFiles = ['package-lock.json', '.env*', 'secrets.json', '*.log'];

    this.scanForPatterns(rootDir, financialPatterns, excludeDirs, excludeFiles);
  }

  // Check for insecure logging practices
  checkLoggingSecurity() {
    this.log('Checking logging security practices...');

    const logFiles = this.findFiles(rootDir, (file) =>
      file.includes('log') || file.includes('logger') || file.includes('winston')
    );

    for (const file of logFiles) {
      const content = fs.readFileSync(file, 'utf8');

      // Check for sensitive data logging
      if (content.includes('console.log') && (
        content.includes('password') ||
        content.includes('card') ||
        content.includes('secret') ||
        content.includes('key')
      )) {
        this.addVulnerability('medium', 'Potential sensitive data logging in console.log', file);
      }

      // Check for proper log sanitization
      if (!content.includes('sanitize') && !content.includes('mask') && !content.includes('redact')) {
        this.addWarning('No log sanitization found', file);
      } else {
        this.addSecure('Log sanitization implemented', file);
      }
    }
  }

  // Check for secure API communication
  checkAPICommunication() {
    this.log('Checking API communication security...');

    const apiFiles = this.findFiles(rootDir, (file) =>
      file.includes('jpmorgan') || file.includes('payment') || file.includes('api')
    );

    for (const file of apiFiles) {
      const content = fs.readFileSync(file, 'utf8');

      // Check for HTTPS usage
      if (content.includes('http://') && !content.includes('localhost')) {
        this.addVulnerability('high', 'Insecure HTTP communication found', file);
      }

      // Check for certificate validation
      if (content.includes('https') && !content.includes('rejectUnauthorized') && !content.includes('checkServerIdentity')) {
        this.addWarning('No explicit certificate validation found', file);
      }

      // Check for proper timeout settings
      if (!content.includes('timeout') && content.includes('axios') || content.includes('fetch')) {
        this.addWarning('No timeout settings found for API calls', file);
      }
    }
  }

  // Check for encryption implementation
  checkEncryptionImplementation() {
    this.log('Checking encryption implementation...');

    const paymentFiles = this.findFiles(rootDir, (file) =>
      file.includes('payment') || file.includes('jpmorgan') || file.includes('crypto')
    );

    let hasEncryption = false;
    let hasProperEncryption = false;

    for (const file of paymentFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (content.includes('crypto.') || content.includes('bcrypt') || content.includes('encrypt')) {
        hasEncryption = true;

        if (content.includes('AES') || content.includes('RSA') || content.includes('bcrypt')) {
          hasProperEncryption = true;
        }
      }
    }

    if (!hasEncryption) {
      this.addVulnerability('high', 'No encryption found in payment processing');
    } else if (!hasProperEncryption) {
      this.addWarning('Basic encryption found, consider stronger algorithms');
    } else {
      this.addSecure('Proper encryption implemented');
    }
  }

  // Check for rate limiting
  checkRateLimiting() {
    this.log('Checking rate limiting implementation...');

    const serverFiles = this.findFiles(rootDir, (file) =>
      file.includes('server') || file.includes('app') || file.includes('middleware')
    );

    let hasRateLimiting = false;

    for (const file of serverFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (content.includes('rate-limit') || content.includes('express-rate-limit') ||
          content.includes('limiter') || content.includes('throttle')) {
        hasRateLimiting = true;
        break;
      }
    }

    if (!hasRateLimiting) {
      this.addVulnerability('medium', 'No rate limiting found');
    } else {
      this.addSecure('Rate limiting implemented');
    }
  }

  // Check for input validation
  checkInputValidation() {
    this.log('Checking input validation...');

    const routeFiles = this.findFiles(rootDir, (file) =>
      file.includes('route') || file.includes('controller') || file.includes('api')
    );

    let hasValidation = false;

    for (const file of routeFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (content.includes('validator') || content.includes('validate') ||
          content.includes('joi') || content.includes('yup') ||
          content.includes('express-validator')) {
        hasValidation = true;
        break;
      }
    }

    if (!hasValidation) {
      this.addWarning('No comprehensive input validation found');
    } else {
      this.addSecure('Input validation implemented');
    }
  }

  // Check for dependency vulnerabilities
  async checkDependencies() {
    this.log('Checking for dependency vulnerabilities...');

    try {
      const packageJson = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
      const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };

      // Check for known vulnerable packages
      const vulnerablePackages = [
        'lodash', 'underscore', 'minimist', 'axios', 'request'
      ];

      for (const [pkg, version] of Object.entries(dependencies)) {
        if (vulnerablePackages.includes(pkg)) {
          this.addWarning(`Potentially vulnerable package: ${pkg}@${version}`);
        }
      }

      this.addSecure('Dependency vulnerability check completed');
    } catch (error) {
      this.addWarning('Could not check dependencies');
    }
  }

  // Check for proper error handling
  checkErrorHandling() {
    this.log('Checking error handling...');

    const apiFiles = this.findFiles(rootDir, (file) =>
      file.includes('route') || file.includes('controller') || file.includes('api')
    );

    let hasErrorHandling = false;

    for (const file of apiFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (content.includes('try') && content.includes('catch') &&
          (content.includes('error') || content.includes('err'))) {
        hasErrorHandling = true;
      }
    }

    if (!hasErrorHandling) {
      this.addWarning('Limited error handling found');
    } else {
      this.addSecure('Error handling implemented');
    }
  }

  // Utility methods
  scanForPatterns(dir, patterns, excludeDirs = [], excludeFiles = []) {
    const files = fs.readdirSync(dir);

    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);

      if (stat.isDirectory()) {
        if (!excludeDirs.includes(file)) {
          this.scanForPatterns(filePath, patterns, excludeDirs, excludeFiles);
        }
      } else {
        if (!excludeFiles.some(pattern => file.match(pattern))) {
          try {
            const content = fs.readFileSync(filePath, 'utf8');
            const lines = content.split('\n');

            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];

              for (const { pattern, severity, description } of patterns) {
                if (pattern.test(line)) {
                  this.addVulnerability(severity, description, filePath, i + 1);
                }
              }
            }
          } catch (error) {
            // Skip binary files or files that can't be read
          }
        }
      }
    }
  }

  findFiles(dir, filterFn) {
    const files = [];

    function traverse(currentDir) {
      const items = fs.readdirSync(currentDir);

      for (const item of items) {
        const itemPath = path.join(currentDir, item);
        const stat = fs.statSync(itemPath);

        if (stat.isFile() && filterFn(itemPath)) {
          files.push(itemPath);
        } else if (stat.isDirectory() && !['node_modules', '.git'].includes(item)) {
          traverse(itemPath);
        }
      }
    }

    traverse(dir);
    return files;
  }

  // Calculate risk level
  getRiskLevel() {
    if (this.riskScore >= 20) return 'CRITICAL';
    if (this.riskScore >= 15) return 'HIGH';
    if (this.riskScore >= 10) return 'MEDIUM';
    if (this.riskScore >= 5) return 'LOW';
    return 'SAFE';
  }

  // Generate security report
  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        totalVulnerabilities: this.vulnerabilities.length,
        totalWarnings: this.warnings.length,
        totalSecure: this.secure.length,
        riskScore: this.riskScore,
        riskLevel: this.getRiskLevel(),
        scanStatus: this.vulnerabilities.filter(v => v.severity === 'critical').length === 0 ? 'PASSED' : 'FAILED'
      },
      vulnerabilities: this.vulnerabilities,
      warnings: this.warnings,
      secure: this.secure
    };

    return report;
  }

  // Save report to file
  saveReport() {
    const report = this.generateReport();
    const reportPath = path.join(rootDir, 'logs', 'jpmorgan-security-scan-report.json');

    // Ensure logs directory exists
    const logsDir = path.dirname(reportPath);
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    this.log(`Security scan report saved to: ${reportPath}`);
  }

  // Run all security scans
  async runSecurityScan() {
    this.log('Starting JPMorgan security scan...');

    this.checkFinancialDataExposure();
    this.checkLoggingSecurity();
    this.checkAPICommunication();
    this.checkEncryptionImplementation();
    this.checkRateLimiting();
    this.checkInputValidation();
    await this.checkDependencies();
    this.checkErrorHandling();

    this.saveReport();

    // Summary
    logger.info('\n' + '='.repeat(60));
    logger.info('JPMorgan Security Scan Summary');
    logger.info('='.repeat(60));
    logger.info(`Vulnerabilities: ${this.vulnerabilities.length}`);
    logger.info(`Warnings: ${this.warnings.length}`);
    logger.info(`Secure Items: ${this.secure.length}`);
    logger.info(`Risk Score: ${this.riskScore}`);
    logger.info(`Risk Level: ${this.getRiskLevel()}`);

    const criticalVulns = this.vulnerabilities.filter(v => v.severity === 'critical');
    if (criticalVulns.length === 0) {
      logger.info('\n✅ Security scan PASSED');
      process.exit(0);
    } else {
      logger.info('\n❌ Security scan FAILED');
      logger.info('\nCritical vulnerabilities found:');
      criticalVulns.forEach((vuln, index) => {
        logger.info(`${index + 1}. ${vuln.message}`);
        if (vuln.file) {
          logger.info(`   File: ${vuln.file}`);
          if (vuln.line) {
            logger.info(`   Line: ${vuln.line}`);
          }
        }
      });
      process.exit(1);
    }
  }
}

// Run security scan if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const scanner = new JPMorganSecurityScanner();
  scanner.runSecurityScan().catch(error => {
    logger.error('Security scan failed:', error);
    process.exit(1);
  });
}

export default JPMorganSecurityScanner;
