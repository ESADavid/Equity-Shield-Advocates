#!/usr/bin/env node

/**
 * JPMorgan Compliance Check Script
 *
 * Validates compliance with JPMorgan Chase financial services standards
 * and regulatory requirements for payment processing integrations.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

class JPMorganComplianceChecker {
  constructor() {
    this.issues = [];
    this.warnings = [];
    this.passed = [];
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    logger.info(`[${timestamp}] ${type.toUpperCase()}: ${message}`);
  }

  addIssue(message, file = null, line = null) {
    this.issues.push({ message, file, line });
    this.log(`❌ ${message}`, 'error');
  }

  addWarning(message, file = null, line = null) {
    this.warnings.push({ message, file, line });
    this.log(`⚠️  ${message}`, 'warn');
  }

  addPassed(message) {
    this.passed.push(message);
    this.log(`✅ ${message}`, 'success');
  }

  // Check for sensitive data exposure
  checkSensitiveDataExposure() {
    this.log('Checking for sensitive data exposure...');

    const sensitivePatterns = [
      /JPMORGAN.*SECRET/i,
      /JPMORGAN.*KEY/i,
      /credit.*card.*number/i,
      /card.*number/i,
      /cvv|cvc/i,
      /social.*security|ssn/i,
      /bank.*account/i,
      /routing.*number/i,
      /api.*key.*jpmorgan/i,
    ];

    const excludeDirs = ['node_modules', '.git', 'logs', 'dist', 'coverage'];
    const excludeFiles = ['package-lock.json', '.env*', 'secrets.json'];

    this.scanFilesForPatterns(
      rootDir,
      sensitivePatterns,
      excludeDirs,
      excludeFiles
    );

    if (this.issues.length === 0) {
      this.addPassed('No sensitive data exposure detected');
    }
  }

  // Check for proper encryption
  checkEncryptionStandards() {
    this.log('Checking encryption standards...');

    const jpmorganFiles = this.findFiles(
      rootDir,
      (file) => file.includes('jpmorgan') || file.includes('payment')
    );

    let hasEncryption = false;
    let hasProperHashing = false;

    for (const file of jpmorganFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (content.includes('crypto.') || content.includes('bcrypt')) {
        hasEncryption = true;
      }

      if (content.includes('bcrypt') || content.includes('crypto.createHash')) {
        hasProperHashing = true;
      }
    }

    if (!hasEncryption) {
      this.addIssue('No encryption found in JPMorgan payment modules');
    } else {
      this.addPassed('Encryption implemented in payment modules');
    }

    if (!hasProperHashing) {
      this.addWarning('No proper password hashing found');
    } else {
      this.addPassed('Proper password hashing implemented');
    }
  }

  // Check for PCI DSS compliance markers
  checkPCIDSSCompliance() {
    this.log('Checking PCI DSS compliance...');

    const jpmorganFiles = this.findFiles(
      rootDir,
      (file) => file.includes('jpmorgan') || file.includes('payment')
    );

    let hasPCIMarkers = false;

    for (const file of jpmorganFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (
        content.includes('PCI') ||
        content.includes('DSS') ||
        content.includes('payment card') ||
        content.includes('card data')
      ) {
        hasPCIMarkers = true;
        break;
      }
    }

    if (!hasPCIMarkers) {
      this.addWarning('No PCI DSS compliance markers found in payment code');
    } else {
      this.addPassed('PCI DSS compliance markers present');
    }
  }

  // Check for proper logging sanitization
  checkLoggingSanitization() {
    this.log('Checking logging sanitization...');

    const logFiles = this.findFiles(
      rootDir,
      (file) => file.includes('log') || file.includes('logger')
    );

    let hasSanitization = false;

    for (const file of logFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (
        content.includes('sanitize') ||
        content.includes('mask') ||
        content.includes('redact') ||
        content.includes('filter')
      ) {
        hasSanitization = true;
        break;
      }
    }

    if (!hasSanitization) {
      this.addWarning('No logging sanitization found for sensitive data');
    } else {
      this.addPassed('Logging sanitization implemented');
    }
  }

  // Check for rate limiting
  checkRateLimiting() {
    this.log('Checking rate limiting implementation...');

    const serverFiles = this.findFiles(
      rootDir,
      (file) =>
        file.includes('server') ||
        file.includes('app') ||
        file.includes('route')
    );

    let hasRateLimiting = false;

    for (const file of serverFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (
        content.includes('rate-limit') ||
        content.includes('express-rate-limit') ||
        content.includes('limiter')
      ) {
        hasRateLimiting = true;
        break;
      }
    }

    if (!hasRateLimiting) {
      this.addIssue('No rate limiting found in server configuration');
    } else {
      this.addPassed('Rate limiting implemented');
    }
  }

  // Check for HTTPS enforcement
  checkHTTPSEnforcement() {
    this.log('Checking HTTPS enforcement...');

    const serverFiles = this.findFiles(
      rootDir,
      (file) => file.includes('server') || file.includes('app')
    );

    let hasHTTPS = false;

    for (const file of serverFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (
        content.includes('https') ||
        content.includes('ssl') ||
        content.includes('tls') ||
        content.includes('forceSSL')
      ) {
        hasHTTPS = true;
        break;
      }
    }

    if (!hasHTTPS) {
      this.addWarning('No HTTPS enforcement found');
    } else {
      this.addPassed('HTTPS enforcement implemented');
    }
  }

  // Check for audit logging
  checkAuditLogging() {
    this.log('Checking audit logging...');

    const auditFiles = this.findFiles(
      rootDir,
      (file) => file.includes('audit') || file.includes('log')
    );

    let hasAuditLogging = false;

    for (const file of auditFiles) {
      const content = fs.readFileSync(file, 'utf8');

      if (
        content.includes('audit') ||
        content.includes('transaction.*log') ||
        content.includes('payment.*log')
      ) {
        hasAuditLogging = true;
        break;
      }
    }

    if (!hasAuditLogging) {
      this.addWarning('No comprehensive audit logging found');
    } else {
      this.addPassed('Audit logging implemented');
    }
  }

  // Utility methods
  scanFilesForPatterns(dir, patterns, excludeDirs = [], excludeFiles = []) {
    const files = fs.readdirSync(dir);

    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);

      if (stat.isDirectory()) {
        if (!excludeDirs.includes(file)) {
          this.scanFilesForPatterns(
            filePath,
            patterns,
            excludeDirs,
            excludeFiles
          );
        }
      } else {
        if (!excludeFiles.some((pattern) => file.match(pattern))) {
          try {
            const content = fs.readFileSync(filePath, 'utf8');
            const lines = content.split('\n');

            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];

              for (const pattern of patterns) {
                if (pattern.test(line)) {
                  this.addIssue(
                    `Sensitive data pattern found: ${pattern}`,
                    filePath,
                    i + 1
                  );
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
        } else if (
          stat.isDirectory() &&
          !['node_modules', '.git'].includes(item)
        ) {
          traverse(itemPath);
        }
      }
    }

    traverse(dir);
    return files;
  }

  // Generate compliance report
  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        totalIssues: this.issues.length,
        totalWarnings: this.warnings.length,
        totalPassed: this.passed.length,
        compliance: this.issues.length === 0 ? 'PASSED' : 'FAILED',
      },
      issues: this.issues,
      warnings: this.warnings,
      passed: this.passed,
    };

    return report;
  }

  // Save report to file
  saveReport() {
    const report = this.generateReport();
    const reportPath = path.join(
      rootDir,
      'logs',
      'jpmorgan-compliance-report.json'
    );

    // Ensure logs directory exists
    const logsDir = path.dirname(reportPath);
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    this.log(`Compliance report saved to: ${reportPath}`);
  }

  // Run all compliance checks
  async runComplianceChecks() {
    this.log('Starting JPMorgan compliance checks...');

    this.checkSensitiveDataExposure();
    this.checkEncryptionStandards();
    this.checkPCIDSSCompliance();
    this.checkLoggingSanitization();
    this.checkRateLimiting();
    this.checkHTTPSEnforcement();
    this.checkAuditLogging();

    this.saveReport();

    // Summary
    logger.info('\n' + '='.repeat(60));
    logger.info('JPMorgan Compliance Check Summary');
    logger.info('='.repeat(60));
    logger.info(`Issues: ${this.issues.length}`);
    logger.info(`Warnings: ${this.warnings.length}`);
    logger.info(`Passed: ${this.passed.length}`);

    if (this.issues.length === 0) {
      logger.info('\n✅ All compliance checks PASSED');
      process.exit(0);
    } else {
      logger.info('\n❌ Compliance checks FAILED');
      logger.info('\nIssues found:');
      this.issues.forEach((issue, index) => {
        logger.info(`${index + 1}. ${issue.message}`);
        if (issue.file) {
          logger.info(`   File: ${issue.file}`);
          if (issue.line) {
            logger.info(`   Line: ${issue.line}`);
          }
        }
      });
      process.exit(1);
    }
  }
}

// Run compliance checks if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const checker = new JPMorganComplianceChecker();
  checker.runComplianceChecks().catch((error) => {
    logger.error('Compliance check failed:', error);
    process.exit(1);
  });
}

export default JPMorganComplianceChecker;
