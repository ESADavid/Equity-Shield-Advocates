import winston from 'winston';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';
import { promisify } from 'util';
import BackupManager from '../scripts/backup-manager.js';

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'disaster-recovery' },
  transports: [
    new winston.transports.File({ filename: 'logs/disaster-recovery.log' }),
    new winston.transports.File({ filename: 'logs/disaster-recovery-error.log', level: 'error' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

class DisasterRecovery {
  constructor(options = {}) {
    this.backupManager = new BackupManager(options.backup || {});
    this.recoveryDir = options.recoveryDir || path.join(__dirname, '..', 'recovery');
    this.maxRecoveryAttempts = options.maxRecoveryAttempts || 3;
    this.recoveryTimeout = options.recoveryTimeout || 3600000; // 1 hour
    this.notificationWebhook = options.notificationWebhook;
    this.secondaryStorage = options.secondaryStorage; // For offsite backups

    // Ensure recovery directory exists
    if (!fs.existsSync(this.recoveryDir)) {
      fs.mkdirSync(this.recoveryDir, { recursive: true });
    }
  }

  // Comprehensive system health check
  async performHealthCheck() {
    logger.info('Starting comprehensive system health check');

    const healthStatus = {
      timestamp: new Date().toISOString(),
      overall: 'healthy',
      components: {},
      recommendations: []
    };

    try {
      // Database health check
      healthStatus.components.database = await this.checkDatabaseHealth();

      // File system health check
      healthStatus.components.filesystem = await this.checkFilesystemHealth();

      // Service health check
      healthStatus.components.services = await this.checkServiceHealth();

      // Network connectivity check
      healthStatus.components.network = await this.checkNetworkHealth();

      // Memory and performance check
      healthStatus.components.performance = await this.checkPerformanceHealth();

      // Determine overall health
      const unhealthyComponents = Object.values(healthStatus.components)
        .filter(component => component.status !== 'healthy');

      if (unhealthyComponents.length > 0) {
        healthStatus.overall = 'degraded';
        healthStatus.recommendations.push('System is in degraded state. Review component statuses below.');
      }

      // Generate specific recommendations
      healthStatus.recommendations.push(...this.generateHealthRecommendations(healthStatus.components));

      logger.info('System health check completed', {
        overall: healthStatus.overall,
        unhealthyComponents: unhealthyComponents.length
      });

      return healthStatus;

    } catch (error) {
      logger.error('System health check failed', { error: error.message });
      healthStatus.overall = 'critical';
      healthStatus.error = error.message;
      return healthStatus;
    }
  }

  // Check database health
  async checkDatabaseHealth() {
    try {
      const mongoose = (await import('mongoose')).default;

      if (mongoose.connection.readyState !== 1) {
        return {
          status: 'unhealthy',
          message: 'Database connection is not ready',
          details: { readyState: mongoose.connection.readyState }
        };
      }

      // Test basic database operations
      const db = mongoose.connection.db;
      await db.admin().ping();

      // Check collection counts
      const collections = await db.listCollections().toArray();

      return {
        status: 'healthy',
        message: 'Database is responding normally',
        details: {
          collections: collections.length,
          database: db.databaseName
        }
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Database health check failed',
        error: error.message
      };
    }
  }

  // Check filesystem health
  async checkFilesystemHealth() {
    try {
      const criticalPaths = [
        path.join(__dirname, '..', 'config'),
        path.join(__dirname, '..', 'logs'),
        path.join(__dirname, '..', 'data'),
        path.join(__dirname, '..', 'backups')
      ];

      const issues = [];

      for (const dirPath of criticalPaths) {
        if (!fs.existsSync(dirPath)) {
          issues.push(`Directory missing: ${dirPath}`);
          continue;
        }

        try {
          // Check write permissions
          const testFile = path.join(dirPath, '.health-check');
          fs.writeFileSync(testFile, 'test');
          fs.unlinkSync(testFile);
        } catch (error) {
          issues.push(`Write permission denied: ${dirPath}`);
        }
      }

      // Check disk space
      const diskUsage = await this.getDiskUsage();
      if (diskUsage.percentage > 90) {
        issues.push(`Low disk space: ${diskUsage.percentage}% used`);
      }

      if (issues.length > 0) {
        return {
          status: 'degraded',
          message: 'Filesystem issues detected',
          issues,
          diskUsage
        };
      }

      return {
        status: 'healthy',
        message: 'Filesystem is healthy',
        diskUsage
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Filesystem health check failed',
        error: error.message
      };
    }
  }

  // Check service health
  async checkServiceHealth() {
    try {
      const services = [
        { name: 'redis', port: 6379 },
        { name: 'mongodb', port: 27017 }
      ];

      const results = {};

      for (const service of services) {
        try {
          const isReachable = await this.checkPort(service.port);
          results[service.name] = {
            status: isReachable ? 'running' : 'stopped',
            port: service.port
          };
        } catch (error) {
          results[service.name] = {
            status: 'error',
            port: service.port,
            error: error.message
          };
        }
      }

      const failedServices = Object.values(results).filter(r => r.status !== 'running');

      return {
        status: failedServices.length > 0 ? 'degraded' : 'healthy',
        message: failedServices.length > 0 ? 'Some services are not running' : 'All services are running',
        services: results
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Service health check failed',
        error: error.message
      };
    }
  }

  // Check network health
  async checkNetworkHealth() {
    try {
      const endpoints = [
        'https://api.github.com',
        'https://registry.npmjs.org',
        process.env.JPMORGAN_API_URL,
        process.env.STRIPE_API_URL
      ].filter(Boolean);

      const results = {};

      for (const endpoint of endpoints) {
        try {
          const response = await fetch(endpoint, { timeout: 5000 });
          results[endpoint] = {
            status: response.ok ? 'reachable' : 'error',
            statusCode: response.status
          };
        } catch (error) {
          results[endpoint] = {
            status: 'unreachable',
            error: error.message
          };
        }
      }

      const unreachable = Object.values(results).filter(r => r.status === 'unreachable');

      return {
        status: unreachable.length > 0 ? 'degraded' : 'healthy',
        message: unreachable.length > 0 ? 'Some external services are unreachable' : 'Network connectivity is good',
        endpoints: results
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Network health check failed',
        error: error.message
      };
    }
  }

  // Check performance health
  async checkPerformanceHealth() {
    try {
      const memUsage = process.memoryUsage();
      const memPercentage = (memUsage.heapUsed / memUsage.heapTotal) * 100;

      const performanceIssues = [];

      if (memPercentage > 80) {
        performanceIssues.push(`High memory usage: ${memPercentage.toFixed(1)}%`);
      }

      // Check event loop lag
      const start = process.hrtime.bigint();
      await new Promise(resolve => setImmediate(resolve));
      const lag = Number(process.hrtime.bigint() - start) / 1000000; // Convert to milliseconds

      if (lag > 100) {
        performanceIssues.push(`High event loop lag: ${lag.toFixed(1)}ms`);
      }

      return {
        status: performanceIssues.length > 0 ? 'degraded' : 'healthy',
        message: performanceIssues.length > 0 ? 'Performance issues detected' : 'Performance is optimal',
        memory: {
          used: memUsage.heapUsed,
          total: memUsage.heapTotal,
          percentage: memPercentage
        },
        eventLoopLag: lag,
        issues: performanceIssues
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Performance health check failed',
        error: error.message
      };
    }
  }

  // Generate health recommendations
  generateHealthRecommendations(components) {
    const recommendations = [];

    if (components.database?.status !== 'healthy') {
      recommendations.push('Review database connection and perform maintenance');
    }

    if (components.filesystem?.status === 'degraded') {
      recommendations.push('Address filesystem issues and check disk space');
    }

    if (components.services?.status === 'degraded') {
      recommendations.push('Restart failed services and check service configurations');
    }

    if (components.network?.status === 'degraded') {
      recommendations.push('Investigate network connectivity issues');
    }

    if (components.performance?.status === 'degraded') {
      recommendations.push('Optimize memory usage and review performance bottlenecks');
    }

    return recommendations;
  }

  // Automated recovery procedures
  async initiateRecovery(options = {}) {
    const recoveryId = `recovery-${Date.now()}`;
    logger.info('Initiating disaster recovery', { recoveryId, options });

    const recoveryPlan = {
      id: recoveryId,
      startTime: new Date().toISOString(),
      steps: [],
      status: 'in_progress',
      options
    };

    try {
      // Step 1: Health assessment
      recoveryPlan.steps.push({
        step: 'health_assessment',
        status: 'in_progress',
        timestamp: new Date().toISOString()
      });

      const healthCheck = await this.performHealthCheck();
      recoveryPlan.healthCheck = healthCheck;

      recoveryPlan.steps[recoveryPlan.steps.length - 1].status = 'completed';

      // Step 2: Create emergency backup if needed
      if (options.createBackup !== false) {
        recoveryPlan.steps.push({
          step: 'emergency_backup',
          status: 'in_progress',
          timestamp: new Date().toISOString()
        });

        const backupResult = await this.backupManager.createFullBackup(`emergency-${recoveryId}`);
        recoveryPlan.emergencyBackup = backupResult;

        recoveryPlan.steps[recoveryPlan.steps.length - 1].status = 'completed';
      }

      // Step 3: Service recovery
      if (healthCheck.components.services?.status === 'degraded') {
        recoveryPlan.steps.push({
          step: 'service_recovery',
          status: 'in_progress',
          timestamp: new Date().toISOString()
        });

        await this.recoverServices(healthCheck.components.services);
        recoveryPlan.steps[recoveryPlan.steps.length - 1].status = 'completed';
      }

      // Step 4: Database recovery
      if (healthCheck.components.database?.status !== 'healthy') {
        recoveryPlan.steps.push({
          step: 'database_recovery',
          status: 'in_progress',
          timestamp: new Date().toISOString()
        });

        await this.recoverDatabase();
        recoveryPlan.steps[recoveryPlan.steps.length - 1].status = 'completed';
      }

      // Step 5: Application restart
      recoveryPlan.steps.push({
        step: 'application_restart',
        status: 'in_progress',
        timestamp: new Date().toISOString()
      });

      await this.restartApplication();
      recoveryPlan.steps[recoveryPlan.steps.length - 1].status = 'completed';

      // Step 6: Verification
      recoveryPlan.steps.push({
        step: 'verification',
        status: 'in_progress',
        timestamp: new Date().toISOString()
      });

      const postRecoveryHealth = await this.performHealthCheck();
      recoveryPlan.postRecoveryHealth = postRecoveryHealth;

      recoveryPlan.steps[recoveryPlan.steps.length - 1].status = 'completed';

      recoveryPlan.status = 'completed';
      recoveryPlan.endTime = new Date().toISOString();

      // Send notification
      if (this.notificationWebhook) {
        await this.sendNotification('recovery_completed', recoveryPlan);
      }

      logger.info('Disaster recovery completed successfully', { recoveryId });

      return recoveryPlan;

    } catch (error) {
      recoveryPlan.status = 'failed';
      recoveryPlan.error = error.message;
      recoveryPlan.endTime = new Date().toISOString();

      // Send failure notification
      if (this.notificationWebhook) {
        await this.sendNotification('recovery_failed', recoveryPlan);
      }

      logger.error('Disaster recovery failed', { recoveryId, error: error.message });
      throw error;
    }
  }

  // Recover services
  async recoverServices(serviceStatus) {
    logger.info('Attempting service recovery');

    for (const [serviceName, status] of Object.entries(serviceStatus.services)) {
      if (status.status !== 'running') {
        try {
          logger.info(`Attempting to restart service: ${serviceName}`);

          // Service-specific restart commands
          switch (serviceName) {
            case 'redis':
              await execAsync('redis-server --daemonize yes');
              break;
            case 'mongodb':
              await execAsync('mongod --fork --logpath /var/log/mongodb.log');
              break;
          }

          // Wait and verify
          await new Promise(resolve => setTimeout(resolve, 2000));
          const newStatus = await this.checkPort(status.port);

          if (newStatus) {
            logger.info(`Service ${serviceName} restarted successfully`);
          } else {
            logger.warn(`Service ${serviceName} restart may have failed`);
          }

        } catch (error) {
          logger.error(`Failed to restart service ${serviceName}`, { error: error.message });
        }
      }
    }
  }

  // Recover database
  async recoverDatabase() {
    logger.info('Attempting database recovery');

    try {
      const mongoose = (await import('mongoose')).default;

      // Disconnect if connected
      if (mongoose.connection.readyState === 1) {
        await mongoose.disconnect();
      }

      // Attempt reconnection
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/oscar-broome-revenue');

      logger.info('Database recovery completed');

    } catch (error) {
      logger.error('Database recovery failed', { error: error.message });
      throw error;
    }
  }

  // Restart application
  async restartApplication() {
    logger.info('Restarting application');

    try {
      // If using PM2
      if (process.env.PM2_HOME) {
        await execAsync('pm2 restart all');
      } else {
        // Graceful restart logic
        process.emit('SIGTERM');
        // The process manager should handle restart
      }

      logger.info('Application restart initiated');

    } catch (error) {
      logger.error('Application restart failed', { error: error.message });
      throw error;
    }
  }

  // Send notification
  async sendNotification(type, data) {
    if (!this.notificationWebhook) return;

    try {
      const payload = {
        type,
        timestamp: new Date().toISOString(),
        system: 'OSCAR-BROOME-REVENUE',
        data
      };

      await fetch(this.notificationWebhook, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

    } catch (error) {
      logger.error('Failed to send notification', { type, error: error.message });
    }
  }

  // Utility methods
  async checkPort(port) {
    return new Promise((resolve) => {
      const net = require('net');
      const client = net.createConnection({ port }, () => {
        client.end();
        resolve(true);
      });

      client.on('error', () => resolve(false));
      client.setTimeout(2000, () => {
        client.destroy();
        resolve(false);
      });
    });
  }

  async getDiskUsage() {
    try {
      // Simple disk usage check (Unix-like systems)
      const { stdout } = await execAsync('df -h . | tail -1');
      const parts = stdout.trim().split(/\s+/);
      const percentage = parseInt(parts[4].replace('%', ''));

      return {
        filesystem: parts[0],
        size: parts[1],
        used: parts[2],
        available: parts[3],
        percentage
      };
    } catch {
      // Fallback for systems without df
      return { percentage: 50 }; // Assume 50% usage
    }
  }

  // Get recovery status
  getStatus() {
    return {
      recoveryDirectory: this.recoveryDir,
      maxRecoveryAttempts: this.maxRecoveryAttempts,
      recoveryTimeout: this.recoveryTimeout,
      notificationEnabled: !!this.notificationWebhook,
      secondaryStorageEnabled: !!this.secondaryStorage,
      backupManagerStatus: this.backupManager.getStatus()
    };
  }
}

export default DisasterRecovery;
