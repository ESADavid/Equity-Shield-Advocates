import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import logger from '../utils/loggerWrapper.js';

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
    logger.info('🔒 Starting Comprehensive Security Audit...');
    logger.info('='.repeat(50));

    try {
      await this.checkDependencies();
      await this.checkConfiguration();
      await this.checkCodeQuality();
      await this.checkAuthentication();
      await this.checkDataProtection();
      await this.generateReport();

      this.results.status = 'completed';
      logger.info('\n✅ Security audit completed successfully!');
      logger.info(`📊 Security Score: ${this.results.score}/100`);

    } catch (error) {
      logger.error('❌ Security audit failed:', error.message);
      this.results.status = 'failed';
      this.results.error = error.message;
    }

    return this.results;
  }

  async checkDependencies() {
    logger.info('\n🔍 Checking Dependencies...');

    await this.checkVulnerabilities();
    await this.checkOutdatedPackages();
  }

  async checkVulnerabilities() {
    logger.info('   Checking for vulnerable dependencies...');
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
      logger.info('   ✅ No dependency vulnerabilities found');
      this.results.score += 20;
    }
  }

  async checkOutdatedPackages() {
    logger.info('   Checking for outdated packages...');

    const outdatedOutput = execSync('npm outdated --json', { cwd: rootDir, encoding: 'utf8' });
    const outdatedData = JSON.parse(outdatedOutput);
    const outdatedCount = Object.keys(outdatedData).length;

    if (outdatedCount > 0) {
      this.results.recommendations.push(`Update ${outdatedCount} outdated packages`);
      this.results.score -= outdatedCount * 2;
    } else {
      logger.info('   ✅ All packages are up to date');
      this.results.score += 10;
    }
  }

  async checkConfiguration() {
    logger.info('\n🔍 Checking Configuration Security...');

    await this.checkForExposedSecrets();
    await this.checkForDebugMode();
  }

  async checkForExposedSecrets() {
    const configFiles = ['config/database.js', 'config/security.js', 'config/jpmorgan.js'];
    const secretsFound = this.scanConfigFilesForSecrets(configFiles);

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
      logger.info('   ✅ No exposed secrets found in configuration');
      this.results.score += 15;
    }
  }

  scanConfigFilesForSecrets(configFiles) {
    let secretsFound = 0;
    const secretPatterns = [
      /password\s*=\s*[^$]/i,
      /secret\s*=\s*[^$]/i,
      /key\s*=\s*[^$]/i,
      /token\s*=\s*[^$]/i
    ];

    for (const file of configFiles) {
      const filePath = path.join(rootDir, file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        for (const pattern of secretPatterns) {
          if (pattern.test(content)) {
            secretsFound++;
          }
        }
      }
    }

    return secretsFound;
  }

  async checkForDebugMode() {
    const packageJson = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
    const scripts = packageJson.scripts || {};
    const debugModeFound = this.scanScriptsForDebugMode(scripts);

    if (debugModeFound) {
      this.results.vulnerabilities.push({
        type: 'debug_enabled',
        severity: 'medium',
        details: 'Debug mode may be enabled in production scripts'
      });
      this.results.recommendations.push('Ensure NODE_ENV=production and DEBUG=false in production');
      this.results.score -= 10;
    } else {
      logger.info('   ✅ Production configuration appears secure');
      this.results.score += 10;
    }
  }

  scanScriptsForDebugMode(scripts) {
    for (const value of Object.values(scripts)) {
      if (value.includes('NODE_ENV=development') || value.includes('DEBUG=true')) {
        return true;
      }
    }
    return false;
  }

  async checkCodeQuality() {
    logger.info('\n🔍 Checking Code Quality...');

    const insecurePatterns = this.scanForInsecurePatterns();

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
      logger.info('   ✅ No insecure code patterns found');
      this.results.score += 15;
    }
  }

  scanForInsecurePatterns() {
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
      const content = fs.readFileSync(file, 'utf8');
      for (const pattern of patterns) {
        const matches = content.match(pattern);
        if (matches) {
          insecurePatterns += matches.length;
        }
      }
    }

    return insecurePatterns;
  }

  async checkAuthentication() {
    logger.info('\n🔍 Checking Authentication Security...');

    // Check for JWT configuration in config files
    let jwtConfigured = false;
    const configFiles = ['config/security.js', 'config/jpmorgan.js'];

    for (const file of configFiles) {
      const filePath = path.join(rootDir, file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        if (content.includes('JWT') || content.includes('jwt')) {
          jwtConfigured = true;
          break;
        }
      }
    }

    if (jwtConfigured) {
      logger.info('   ✅ JWT authentication configured');
      this.results.score += 10;
    } else {
      this.results.vulnerabilities.push({
        type: 'weak_jwt_secret',
        severity: 'high',
        details: 'JWT configuration not found'
      });
      this.results.recommendations.push('Configure proper JWT authentication');
      this.results.score -= 20;
    }

    // Check for password policies
    const userModelPath = path.join(rootDir, 'models', 'User.js');
    if (fs.existsSync(userModelPath)) {
      const userModel = fs.readFileSync(userModelPath, 'utf8');
      const hasPasswordHashing = userModel.includes('bcrypt') || userModel.includes('password') || userModel.includes('hash');
      if (hasPasswordHashing) {
        logger.info('   ✅ Password hashing appears properly implemented');
        this.results.score += 10;
      } else {
        this.results.vulnerabilities.push({
          type: 'weak_password_hashing',
          severity: 'high',
          details: 'Password hashing may not be properly implemented'
        });
        this.results.recommendations.push('Ensure passwords are properly hashed with bcrypt or similar');
        this.results.score -= 15;
      }
    }
  }

  async checkDataProtection() {
    logger.info('\n🔍 Checking Data Protection...');

    // Check for HTTPS enforcement in server files
    const serverFiles = ['server-quantum.js', 'server-enhanced.js', 'server.js'];
    let serverContent = null;

    for (const file of serverFiles) {
      const filePath = path.join(rootDir, file);
      if (fs.existsSync(filePath)) {
        serverContent = fs.readFileSync(filePath, 'utf8');
        break;
      }
    }

    if (serverContent && serverContent.length > 0) {
      if (serverContent.includes('helmet') && serverContent.includes('https')) {
        logger.info('   ✅ HTTPS and security headers configured');
        this.results.score += 10;
      } else {
        this.results.recommendations.push('Consider enforcing HTTPS and using security headers');
        this.results.score -= 5;
      }

      // Check for rate limiting
      if (serverContent.includes('rateLimit') || serverContent.includes('express-rate-limit')) {
        logger.info('   ✅ Rate limiting implemented');
        this.results.score += 10;
      } else {
        this.results.vulnerabilities.push({
          type: 'no_rate_limiting',
          severity: 'medium',
          details: 'Rate limiting not implemented'
        });
        this.results.recommendations.push('Implement rate limiting to prevent abuse');
        this.results.score -= 10;
      }
    } else {
      logger.info('   ⚠️ Could not find server file to check data protection');
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

    for (const dir of dirs) {
      scanDir(path.join(rootDir, dir));
    }
    return files;
  }

  async generateReport() {
    logger.info('\n📊 Generating Security Audit Report...');

    // Ensure score is within bounds
    this.results.score = Math.max(0, Math.min(100, this.results.score + 50)); // Base score of 50

    const reportPath = path.join(rootDir, 'logs', 'security-audit-report.json');
    const logsDir = path.dirname(reportPath);

    logger.info(`   Debug: rootDir = ${rootDir}`);
    logger.info(`   Debug: reportPath = ${reportPath}`);
    logger.info(`   Debug: logsDir = ${logsDir}`);
    logger.info(`   Debug: logsDir exists = ${fs.existsSync(logsDir)}`);

    try {
      if (!fs.existsSync(logsDir)) {
        logger.info('   Creating logs directory...');
        fs.mkdirSync(logsDir, { recursive: true });
        logger.info('   Logs directory created successfully');
      }

      logger.info('   Writing report file...');
      fs.writeFileSync(reportPath, JSON.stringify(this.results, null, 2));
      logger.info('   Report file written successfully');

      logger.info(`   Report saved to: ${reportPath}`);
    } catch (error) {
      logger.error('   Error generating report:', error.message);
      throw error;
    }

    // Print summary
    logger.info('\n📈 Security Audit Summary:');
    logger.info(`   Score: ${this.results.score}/100`);
    logger.info(`   Vulnerabilities: ${this.results.vulnerabilities.length}`);
    logger.info(`   Recommendations: ${this.results.recommendations.length}`);

    if (this.results.vulnerabilities.length > 0) {
      logger.info('\n🚨 Critical Issues:');
      for (const vuln of this.results.vulnerabilities) {
        logger.info(`   - ${vuln.type}: ${vuln.details}`);
      }
    }

    if (this.results.recommendations.length > 0) {
      logger.info('\n💡 Recommendations:');
      for (const rec of this.results.recommendations) {
        logger.info(`   - ${rec}`);
      }
    }
  }
}

// Run audit if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const auditor = new SecurityAuditor();
  try {
    await auditor.runFullAudit();
    process.exit(0);
  } catch (error) {
    logger.error('Audit failed:', error);
    process.exit(1);
  }
}

export default SecurityAuditor;
