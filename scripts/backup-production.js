

/**
 * Note: Shebang removed for TypeScript compatibility. Run with: node scripts/backup-production.js
 */

/**
 * Backup Production Database
 * Creates a backup of the production database and files
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class ProductionBackup {
  constructor() {
    this.backupDir = path.join(__dirname, '..', 'backups');
    this.timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    this.backupName = `production-backup-${this.timestamp}`;
    this.backupPath = path.join(this.backupDir, this.backupName);
  }

  /**
   * @param {string} message
   * @param {string} [type='info']
   */
  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = {
      info: 'ℹ️ ',
      success: '✅ ',
      warning: '⚠️ ',
      error: '❌ ',
      step: '🔧 ',
    }[type] || '📝 ';

    console.log(`[${timestamp}] ${prefix}${message}`);
  }

  async ensureBackupDir() {
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
      this.log(`Created backup directory: ${this.backupDir}`);
    }
  }

  async backupDatabase() {
    this.log('Starting database backup...', 'step');

    try {
      // Create database backup directory
      const dbBackupPath = path.join(this.backupPath, 'database');
      fs.mkdirSync(dbBackupPath, { recursive: true });

      // MongoDB backup using mongodump
      const mongoUri = process.env.MONGODB_URI || 'mongodb://mongodb:27017/oscar-broome-production';
      const dumpCmd = `mongodump --uri="${mongoUri}" --out="${dbBackupPath}" --gzip --quiet`;

      this.log('Executing mongodump...');
      execSync(dumpCmd, { stdio: 'inherit' });

      // Get backup size
      const size = this.getDirectorySize(dbBackupPath);
      this.log(`Database backup completed: ${(size / 1024 / 1024).toFixed(2)} MB`, 'success');

      return { path: dbBackupPath, size };
    } catch (error) {
      this.log(`Database backup failed: ${error instanceof Error ? error.message : String(error)}`, 'error');
      throw error;
    }
  }

  async backupFiles() {
    this.log('Starting files backup...', 'step');

    try {
      // Create files backup directory
      const filesBackupPath = path.join(this.backupPath, 'files');
      fs.mkdirSync(filesBackupPath, { recursive: true });

      // Define what to backup
      const backupItems = [
        {
          source: path.join(__dirname, '..', 'config'),
          target: path.join(filesBackupPath, 'config'),
          description: 'Configuration files',
        },
        {
          source: path.join(__dirname, '..', 'data'),
          target: path.join(filesBackupPath, 'data'),
          description: 'Application data',
        },
        {
          source: path.join(__dirname, '..', 'logs'),
          target: path.join(filesBackupPath, 'logs'),
          description: 'Application logs',
        },
        {
          source: path.join(__dirname, '..', 'public', 'uploads'),
          target: path.join(filesBackupPath, 'uploads'),
          description: 'Uploaded files',
          optional: true,
        },
      ];

      let totalSize = 0;

      for (const item of backupItems) {
        try {
          if (item.optional && !fs.existsSync(item.source)) {
            this.log(`Skipping optional backup: ${item.description}`);
            continue;
          }

          await this.copyDirectory(item.source, item.target);
          const size = this.getDirectorySize(item.target);
          totalSize += size;
          this.log(`Backed up ${item.description}: ${(size / 1024 / 1024).toFixed(2)} MB`);
        } catch (error) {
          if (item.optional) {
          this.log(`Optional backup failed: ${item.description} - ${error instanceof Error ? error.message : String(error)}`, 'warning');
          } else {
            throw error;
          }
        }
      }

      this.log(`Files backup completed: ${(totalSize / 1024 / 1024).toFixed(2)} MB`, 'success');
      return { path: filesBackupPath, size: totalSize };
    } catch (error) {
      this.log(`Files backup failed: ${(error as Error).message}`, 'error');
      throw error;
    }
  }

  async compressBackup() {
    this.log('Compressing backup...', 'step');

    try {
      const archiveName = `${this.backupName}.tar.gz`;
      const archivePath = path.join(this.backupDir, archiveName);

      // Use tar to compress
      const tarCmd = `tar -czf "${archivePath}" -C "${path.dirname(this.backupPath)}" "${path.basename(this.backupPath)}"`;

      execSync(tarCmd, { stdio: 'inherit' });

      // Calculate checksum
      const checksum = await this.calculateChecksum(archivePath);

      // Write checksum file
      fs.writeFileSync(`${archivePath}.sha256`, checksum);

      // Remove uncompressed backup
      fs.rmSync(this.backupPath, { recursive: true, force: true });

      const size = this.getFileSize(archivePath);
      this.log(`Backup compressed: ${(size / 1024 / 1024).toFixed(2)} MB`, 'success');

      return { archivePath, checksum, size };
    } catch (error) {
      this.log(`Compression failed: ${error.message}`, 'error');
      throw error;
    }
  }

  /**
   * @param {string} filePath
   * @returns {Promise<string>}
   */
  /**
   * @param {string} filePath
   * @returns {Promise<string>}
   */
  async calculateChecksum(filePath) {
    const crypto = require('crypto');
    const fileBuffer = fs.readFileSync(filePath);
    const hashSum = crypto.createHash('sha256');
    hashSum.update(fileBuffer);
    return hashSum.digest('hex');
  }

  /**
   * @param {string} source
   * @param {string} target
   */
  /**
   * @param {string} source
   * @param {string} target
   */
  async copyDirectory(source, target) {
    const { cp } = fs.promises;
    await cp(source, target, { recursive: true });
  }

  /**
   * @param {string} dirPath
   * @returns {number}
   */
  /**
   * @param {string} dirPath
   * @returns {number}
   */
  getDirectorySize(dirPath) {
    let totalSize = 0;

    function calculateSize(itemPath) {
      const stats = fs.statSync(itemPath);
      if (stats.isDirectory()) {
        const items = fs.readdirSync(itemPath);
        items.forEach((item) => {
          calculateSize(path.join(itemPath, item));
        });
      } else {
        totalSize += stats.size;
      }
    }

    calculateSize(dirPath);
    return totalSize;
  }

  /**
   * @param {string} filePath
   * @returns {number}
   */
  /**
   * @param {string} filePath
   * @returns {number}
   */
  getFileSize(filePath) {
    try {
      return fs.statSync(filePath).size;
    } catch {
      return 0;
    }
  }

  /**
   * @param {any} backupInfo
   * @returns {Promise<object>}
   */
  async createManifest(backupInfo) {
    const manifest = {
      id: this.backupName,
      type: 'production-backup',
      timestamp: new Date().toISOString(),
      environment: 'production',
      components: backupInfo.components || [],
      totalSize: backupInfo.totalSize || 0,
      checksum: backupInfo.checksum,
      version: process.env.npm_package_version || '1.0.0',
    };

    const manifestPath = path.join(this.backupDir, `${this.backupName}-manifest.json`);
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    this.log('Backup manifest created', 'success');
    return manifest;
  }

  async run() {
    try {
      this.log('🚀 Starting production backup...', 'step');

      await this.ensureBackupDir();

      // Create backup directory
      fs.mkdirSync(this.backupPath, { recursive: true });

      /** @type {{components: {type: string; path: string; size: number}[], totalSize: number, archivePath?: string, checksum?: string, compressedSize?: number}} */
      const backupInfo = {
        components: [],
        totalSize: 0,
      };

      // Backup database
      const dbBackup = await this.backupDatabase();
      /** @type {{components: {type: string; path: string; size: number}[], totalSize: number, archivePath?: string, checksum?: string, compressedSize?: number}} */
      const backupInfo = {
        components: [],
        totalSize: 0,
      };

      // Backup database
      const dbBackup = await this.backupDatabase();
      backupInfo.components.push({
        type: 'database',
        path: 'database',
        size: dbBackup.size,
      });
      backupInfo.totalSize += dbBackup.size;

      // Backup files
      const filesBackup = await this.backupFiles();
      backupInfo.components.push({
        type: 'files',
        path: 'files',
        size: filesBackup.size,
      });
      backupInfo.totalSize += filesBackup.size;

      // Compress backup
      const compression = await this.compressBackup();
      backupInfo.archivePath = compression.archivePath;
      backupInfo.checksum = compression.checksum;
      backupInfo.compressedSize = compression.size;

      // Create manifest
      const manifest = await this.createManifest(backupInfo);

      this.log('✅ Production backup completed successfully', 'success');
      this.log(`📁 Backup location: ${compression.archivePath}`, 'info');
      this.log(`🔐 Checksum: ${compression.checksum}`, 'info');
      this.log(`📊 Total size: ${(backupInfo.totalSize / 1024 / 1024).toFixed(2)} MB (uncompressed)`, 'info');
      this.log(`📦 Compressed size: ${(compression.size / 1024 / 1024).toFixed(2)} MB`, 'info');

      return {
        success: true,
        backupName: this.backupName,
        archivePath: compression.archivePath,
        checksum: compression.checksum,
        size: compression.size,
        manifest,
      };
    } catch (error) {
      this.log(`❌ Production backup failed: ${error instanceof Error ? error.message : String(error)}`, 'error');

      // Cleanup on failure
      try {
        if (fs.existsSync(this.backupPath)) {
          fs.rmSync(this.backupPath, { recursive: true, force: true });
        }
      } catch (cleanupError) {
        this.log(`Failed to cleanup failed backup: ${(cleanupError as Error).message}`, 'warning');
      }

      throw error;
    }
  }
}

// Execute backup
const backup = new ProductionBackup();
backup.run().catch((error) => {
  error('Fatal error:', error as Error);
  process.exit(1);
});
