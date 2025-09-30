#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import winston from 'winston';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'backup-manager' },
  transports: [
    new winston.transports.File({ filename: 'logs/backup-manager.log' }),
    new winston.transports.File({ filename: 'logs/backup-manager-error.log', level: 'error' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

class BackupManager {
  constructor(options = {}) {
    this.backupDir = options.backupDir || path.join(__dirname, '..', 'backups');
    this.retentionDays = options.retentionDays || 30;
    this.encryptionKey = options.encryptionKey || process.env.BACKUP_ENCRYPTION_KEY;
    this.maxConcurrentBackups = options.maxConcurrentBackups || 3;
    this.includeFiles = options.includeFiles !== false; // Default true
    this.includeDatabase = options.includeDatabase !== false; // Default true

    // Ensure backup directory exists
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
  }

  // Create full system backup
  async createFullBackup(backupName = null) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupId = backupName || `full-backup-${timestamp}`;
    const backupPath = path.join(this.backupDir, backupId);

    logger.info('Starting full system backup', { backupId, backupPath });

    try {
      // Create backup directory
      fs.mkdirSync(backupPath, { recursive: true });

      const backupManifest = {
        id: backupId,
        type: 'full',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        components: []
      };

      // Backup database
      if (this.includeDatabase) {
        await this.backupDatabase(backupPath, backupManifest);
      }

      // Backup files
      if (this.includeFiles) {
        await this.backupFiles(backupPath, backupManifest);
      }

      // Create backup manifest
      fs.writeFileSync(
        path.join(backupPath, 'manifest.json'),
        JSON.stringify(backupManifest, null, 2)
      );

      // Compress backup
      const archivePath = await this.compressBackup(backupPath, backupId);

      // Encrypt if key is provided
      if (this.encryptionKey) {
        await this.encryptBackup(archivePath);
      }

      // Calculate checksum
      const checksum = await this.calculateChecksum(archivePath);
      fs.writeFileSync(`${archivePath}.sha256`, checksum);

      // Cleanup uncompressed backup
      fs.rmSync(backupPath, { recursive: true, force: true });

      logger.info('Full system backup completed successfully', {
        backupId,
        archivePath,
        size: this.getFileSize(archivePath),
        checksum
      });

      return {
        success: true,
        backupId,
        archivePath,
        size: this.getFileSize(archivePath),
        checksum,
        manifest: backupManifest
      };

    } catch (error) {
      logger.error('Full system backup failed', { backupId, error: error.message });

      // Cleanup on failure
      try {
        if (fs.existsSync(backupPath)) {
          fs.rmSync(backupPath, { recursive: true, force: true });
        }
      } catch (cleanupError) {
        logger.error('Failed to cleanup failed backup', { backupId, error: cleanupError.message });
      }

      throw error;
    }
  }

  // Backup database
  async backupDatabase(backupPath, manifest) {
    const dbBackupPath = path.join(backupPath, 'database');

    logger.info('Starting database backup');

    try {
      // Create database backup directory
      fs.mkdirSync(dbBackupPath, { recursive: true });

      // MongoDB backup using mongodump
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/oscar-broome-revenue';
      const mongoDumpCmd = `mongodump --uri="${mongoUri}" --out="${dbBackupPath}" --gzip`;

      await execAsync(mongoDumpCmd);

      // Get backup size
      const size = this.getDirectorySize(dbBackupPath);

      manifest.components.push({
        type: 'database',
        method: 'mongodump',
        path: 'database',
        size,
        collections: await this.getCollectionCount()
      });

      logger.info('Database backup completed', { size });

    } catch (error) {
      logger.error('Database backup failed', { error: error.message });
      throw new Error(`Database backup failed: ${error.message}`);
    }
  }

  // Backup files and configurations
  async backupFiles(backupPath, manifest) {
    const filesBackupPath = path.join(backupPath, 'files');

    logger.info('Starting files backup');

    try {
      // Create files backup directory
      fs.mkdirSync(filesBackupPath, { recursive: true });

      // Define what to backup
      const backupItems = [
        {
          source: path.join(__dirname, '..', 'config'),
          target: path.join(filesBackupPath, 'config'),
          description: 'Configuration files'
        },
        {
          source: path.join(__dirname, '..', 'data'),
          target: path.join(filesBackupPath, 'data'),
          description: 'Application data'
        },
        {
          source: path.join(__dirname, '..', 'logs'),
          target: path.join(filesBackupPath, 'logs'),
          description: 'Application logs'
        },
        {
          source: path.join(__dirname, '..', 'public', 'uploads'),
          target: path.join(filesBackupPath, 'uploads'),
          description: 'Uploaded files',
          optional: true // Skip if doesn't exist
        }
      ];

      let totalSize = 0;

      for (const item of backupItems) {
        try {
          if (item.optional && !fs.existsSync(item.source)) {
            continue;
          }

          await this.copyDirectory(item.source, item.target);
          const size = this.getDirectorySize(item.target);

          manifest.components.push({
            type: 'files',
            description: item.description,
            path: path.relative(backupPath, item.target),
            size,
            source: path.relative(path.join(__dirname, '..'), item.source)
          });

          totalSize += size;

        } catch (error) {
          if (!item.optional) {
            throw error;
          }
          logger.warn(`Optional backup item skipped: ${item.description}`, { error: error.message });
        }
      }

      logger.info('Files backup completed', { totalSize });

    } catch (error) {
      logger.error('Files backup failed', { error: error.message });
      throw new Error(`Files backup failed: ${error.message}`);
    }
  }

  // Compress backup directory
  async compressBackup(backupPath, backupId) {
    const archiveName = `${backupId}.tar.gz`;
    const archivePath = path.join(this.backupDir, archiveName);

    logger.info('Compressing backup', { backupId, archivePath });

    try {
      // Use tar to compress (works on both Unix and Windows with appropriate tools)
      const tarCmd = `tar -czf "${archivePath}" -C "${path.dirname(backupPath)}" "${path.basename(backupPath)}"`;

      await execAsync(tarCmd);

      logger.info('Backup compression completed', { archivePath });

      return archivePath;

    } catch (error) {
      logger.error('Backup compression failed', { error: error.message });
      throw new Error(`Compression failed: ${error.message}`);
    }
  }

  // Encrypt backup
  async encryptBackup(archivePath) {
    const encryptedPath = `${archivePath}.enc`;

    logger.info('Encrypting backup', { archivePath });

    try {
      // Use openssl for encryption
      const encryptCmd = `openssl enc -aes-256-cbc -salt -in "${archivePath}" -out "${encryptedPath}" -k "${this.encryptionKey}"`;

      await execAsync(encryptCmd);

      // Remove unencrypted file
      fs.unlinkSync(archivePath);

      logger.info('Backup encryption completed', { encryptedPath });

      return encryptedPath;

    } catch (error) {
      logger.error('Backup encryption failed', { error: error.message });
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  // Calculate SHA256 checksum
  async calculateChecksum(filePath) {
    try {
      const { createHash } = await import('crypto');
      const fileBuffer = fs.readFileSync(filePath);
      const hashSum = createHash('sha256');
      hashSum.update(fileBuffer);
      return hashSum.digest('hex');
    } catch (error) {
      logger.error('Checksum calculation failed', { filePath, error: error.message });
      return null;
    }
  }

  // List available backups
  listBackups() {
    try {
      const files = fs.readdirSync(this.backupDir);
      const backups = files
        .filter(file => file.endsWith('.tar.gz') || file.endsWith('.tar.gz.enc'))
        .map(file => {
          const filePath = path.join(this.backupDir, file);
          const stats = fs.statSync(filePath);
          const checksumFile = `${filePath}.sha256`;

          return {
            name: file,
            path: filePath,
            size: stats.size,
            created: stats.birthtime,
            encrypted: file.endsWith('.enc'),
            checksum: fs.existsSync(checksumFile) ? fs.readFileSync(checksumFile, 'utf8').trim() : null
          };
        })
        .sort((a, b) => b.created - a.created);

      return backups;
    } catch (error) {
      logger.error('Failed to list backups', { error: error.message });
      return [];
    }
  }

  // Restore from backup
  async restoreBackup(backupName, options = {}) {
    const backupPath = path.join(this.backupDir, backupName);

    logger.info('Starting backup restoration', { backupName, backupPath });

    try {
      let archivePath = backupPath;

      // Decrypt if encrypted
      if (backupName.endsWith('.enc')) {
        archivePath = await this.decryptBackup(backupPath);
      }

      // Extract archive
      const extractPath = await this.extractBackup(archivePath);

      // Restore components
      const manifestPath = path.join(extractPath, 'manifest.json');
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

      if (options.database !== false && manifest.components.some(c => c.type === 'database')) {
        await this.restoreDatabase(extractPath, manifest);
      }

      if (options.files !== false && manifest.components.some(c => c.type === 'files')) {
        await this.restoreFiles(extractPath, manifest);
      }

      // Cleanup extracted files
      fs.rmSync(extractPath, { recursive: true, force: true });

      // Cleanup decrypted file if it was created
      if (archivePath !== backupPath) {
        fs.unlinkSync(archivePath);
      }

      logger.info('Backup restoration completed successfully', { backupName });

      return { success: true, backupName, restoredComponents: manifest.components };

    } catch (error) {
      logger.error('Backup restoration failed', { backupName, error: error.message });
      throw error;
    }
  }

  // Decrypt backup
  async decryptBackup(encryptedPath) {
    const decryptedPath = encryptedPath.replace('.enc', '');

    logger.info('Decrypting backup', { encryptedPath });

    try {
      const decryptCmd = `openssl enc -d -aes-256-cbc -in "${encryptedPath}" -out "${decryptedPath}" -k "${this.encryptionKey}"`;

      await execAsync(decryptCmd);

      logger.info('Backup decryption completed', { decryptedPath });

      return decryptedPath;

    } catch (error) {
      logger.error('Backup decryption failed', { error: error.message });
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  // Extract backup archive
  async extractBackup(archivePath) {
    const extractPath = archivePath.replace('.tar.gz', '');

    logger.info('Extracting backup', { archivePath, extractPath });

    try {
      // Create extraction directory
      fs.mkdirSync(extractPath, { recursive: true });

      // Extract tar archive
      const extractCmd = `tar -xzf "${archivePath}" -C "${path.dirname(extractPath)}"`;

      await execAsync(extractCmd);

      logger.info('Backup extraction completed', { extractPath });

      return extractPath;

    } catch (error) {
      logger.error('Backup extraction failed', { error: error.message });
      throw new Error(`Extraction failed: ${error.message}`);
    }
  }

  // Restore database
  async restoreDatabase(extractPath, manifest) {
    const dbBackupPath = path.join(extractPath, 'database');

    logger.info('Restoring database from backup');

    try {
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/oscar-broome-revenue';

      // Drop existing database (optional, based on restore options)
      // const dropCmd = `mongosh "${mongoUri}" --eval "db.dropDatabase()"`;

      // Restore from backup
      const restoreCmd = `mongorestore --uri="${mongoUri}" --drop "${dbBackupPath}"`;

      await execAsync(restoreCmd);

      logger.info('Database restoration completed');

    } catch (error) {
      logger.error('Database restoration failed', { error: error.message });
      throw new Error(`Database restoration failed: ${error.message}`);
    }
  }

  // Restore files
  async restoreFiles(extractPath, manifest) {
    const filesBackupPath = path.join(extractPath, 'files');

    logger.info('Restoring files from backup');

    try {
      const fileComponents = manifest.components.filter(c => c.type === 'files');

      for (const component of fileComponents) {
        const sourcePath = path.join(filesBackupPath, path.basename(component.path));
        const targetPath = path.join(__dirname, '..', component.source);

        await this.copyDirectory(sourcePath, targetPath);
      }

      logger.info('Files restoration completed');

    } catch (error) {
      logger.error('Files restoration failed', { error: error.message });
      throw new Error(`Files restoration failed: ${error.message}`);
    }
  }

  // Clean up old backups
  cleanupOldBackups() {
    try {
      const backups = this.listBackups();
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.retentionDays);

      let deletedCount = 0;

      for (const backup of backups) {
        if (backup.created < cutoffDate) {
          fs.unlinkSync(backup.path);

          // Remove checksum file if exists
          const checksumFile = `${backup.path}.sha256`;
          if (fs.existsSync(checksumFile)) {
            fs.unlinkSync(checksumFile);
          }

          deletedCount++;
          logger.info('Old backup deleted', { backupName: backup.name, created: backup.created });
        }
      }

      logger.info('Backup cleanup completed', { deletedCount, retentionDays: this.retentionDays });

      return deletedCount;

    } catch (error) {
      logger.error('Backup cleanup failed', { error: error.message });
      throw error;
    }
  }

  // Utility methods
  async copyDirectory(source, target) {
    const { cp } = fs.promises;
    await cp(source, target, { recursive: true });
  }

  getDirectorySize(dirPath) {
    let totalSize = 0;

    function calculateSize(itemPath) {
      const stats = fs.statSync(itemPath);

      if (stats.isDirectory()) {
        const items = fs.readdirSync(itemPath);
        items.forEach(item => {
          calculateSize(path.join(itemPath, item));
        });
      } else {
        totalSize += stats.size;
      }
    }

    calculateSize(dirPath);
    return totalSize;
  }

  getFileSize(filePath) {
    try {
      return fs.statSync(filePath).size;
    } catch {
      return 0;
    }
  }

  async getCollectionCount() {
    try {
      const db = mongoose.connection.db;
      const collections = await db.listCollections().toArray();
      return collections.length;
    } catch {
      return 0;
    }
  }

  // Health check
  getStatus() {
    const backups = this.listBackups();
    const latestBackup = backups[0];

    return {
      backupDirectory: this.backupDir,
      totalBackups: backups.length,
      latestBackup: latestBackup ? {
        name: latestBackup.name,
        created: latestBackup.created,
        size: latestBackup.size,
        encrypted: latestBackup.encrypted
      } : null,
      retentionDays: this.retentionDays,
      encryptionEnabled: !!this.encryptionKey
    };
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const command = args[0];

  const options = {};
  for (let i = 1; i < args.length; i += 2) {
    const key = args[i].replace('--', '');
    const value = args[i + 1];
    options[key] = value;
  }

  const backupManager = new BackupManager(options);

  switch (command) {
    case 'create':
      backupManager.createFullBackup(options.name)
        .then(result => {
          console.log('✅ Backup created successfully:', result.backupId);
          process.exit(0);
        })
        .catch(error => {
          console.error('❌ Backup creation failed:', error.message);
          process.exit(1);
        });
      break;

    case 'list':
      const backups = backupManager.listBackups();
      console.log('📋 Available backups:');
      backups.forEach(backup => {
        console.log(`  ${backup.name} (${new Date(backup.created).toLocaleString()}) - ${(backup.size / 1024 / 1024).toFixed(2)} MB`);
      });
      break;

    case 'restore':
      if (!options.name) {
        console.error('❌ Please specify backup name with --name');
        process.exit(1);
      }
      backupManager.restoreBackup(options.name, options)
        .then(result => {
          console.log('✅ Backup restored successfully:', result.backupName);
          process.exit(0);
        })
        .catch(error => {
          console.error('❌ Backup restoration failed:', error.message);
          process.exit(1);
        });
      break;

    case 'cleanup':
      backupManager.cleanupOldBackups()
        .then(count => {
          console.log(`🧹 Cleaned up ${count} old backups`);
          process.exit(0);
        })
        .catch(error => {
          console.error('❌ Cleanup failed:', error.message);
          process.exit(1);
        });
      break;

    case 'status':
      const status = backupManager.getStatus();
      console.log('📊 Backup Manager Status:');
      console.log(`  Directory: ${status.backupDirectory}`);
      console.log(`  Total backups: ${status.totalBackups}`);
      console.log(`  Retention: ${status.retentionDays} days`);
      console.log(`  Encryption: ${status.encryptionEnabled ? 'Enabled' : 'Disabled'}`);
      if (status.latestBackup) {
        console.log(`  Latest backup: ${status.latestBackup.name} (${new Date(status.latestBackup.created).toLocaleString()})`);
      }
      break;

    default:
      console.log('Usage:');
      console.log('  create [--name <name>]           Create a new backup');
      console.log('  list                              List all backups');
      console.log('  restore --name <backup>           Restore from backup');
      console.log('  cleanup                           Remove old backups');
      console.log('  status                            Show backup status');
      process.exit(1);
  }
}

export default BackupManager;
