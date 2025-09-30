import mongoose from 'mongoose';
import winston from 'winston';
import { exec } from 'child_process';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'database' },
  transports: [
    new winston.transports.File({ filename: 'logs/database-error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/database.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

class Database {
  constructor() {
    this.isConnected = false;
    this.connection = null;
  }

  async connect() {
    try {
      const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/oscar-broome-revenue';

      const options = {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        maxIdleTimeMS: 30000,
        family: 4
      };

      this.connection = await mongoose.connect(mongoURI, options);

      this.isConnected = true;

      logger.info('MongoDB connected successfully', {
        host: this.connection.connection.host,
        port: this.connection.connection.port,
        name: this.connection.connection.name
      });

      // Set up connection event listeners
      mongoose.connection.on('error', (err) => {
        logger.error('MongoDB connection error', { error: err.message });
        this.isConnected = false;
      });

      mongoose.connection.on('disconnected', () => {
        logger.warn('MongoDB disconnected');
        this.isConnected = false;
      });

      mongoose.connection.on('reconnected', () => {
        logger.info('MongoDB reconnected');
        this.isConnected = true;
      });

      return this.connection;
    } catch (error) {
      logger.error('MongoDB connection failed', { error: error.message });
      throw error;
    }
  }

  async disconnect() {
    try {
      await mongoose.connection.close();
      this.isConnected = false;
      logger.info('MongoDB disconnected successfully');
    } catch (error) {
      logger.error('MongoDB disconnection failed', { error: error.message });
      throw error;
    }
  }

  async healthCheck() {
    try {
      if (!this.isConnected) {
        return { status: 'disconnected', latency: null };
      }

      const start = Date.now();
      await mongoose.connection.db.admin().ping();
      const latency = Date.now() - start;

      return {
        status: 'connected',
        latency,
        database: mongoose.connection.db.databaseName,
        collections: await mongoose.connection.db.listCollections().toArray().then(cols => cols.length)
      };
    } catch (error) {
      logger.error('Database health check failed', { error: error.message });
      return { status: 'error', error: error.message };
    }
  }

  async getStats() {
    try {
      const stats = await mongoose.connection.db.stats();
      return {
        collections: stats.collections,
        objects: stats.objects,
        dataSize: stats.dataSize,
        storageSize: stats.storageSize,
        indexes: stats.indexes,
        indexSize: stats.indexSize
      };
    } catch (error) {
      logger.error('Failed to get database stats', { error: error.message });
      throw error;
    }
  }

  async clearDatabase() {
    try {
      if (process.env.NODE_ENV !== 'test') {
        throw new Error('Database clearing is only allowed in test environment');
      }

      const collections = mongoose.connection.collections;

      for (const key in collections) {
        await collections[key].deleteMany({});
      }

      logger.info('Database cleared successfully');
    } catch (error) {
      logger.error('Failed to clear database', { error: error.message });
      throw error;
    }
  }

  async backup(backupPath) {
    try {
      const { exec } = await import('child_process');
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `backup-${timestamp}.gz`;
      const fullPath = `${backupPath}/${filename}`;

      return new Promise((resolve, reject) => {
        exec(`mongodump --db ${mongoose.connection.db.databaseName} --out ${fullPath} --gzip`, (error, stdout, stderr) => {
          if (error) {
            logger.error('Database backup failed', { error: error.message });
            reject(error);
          } else {
            logger.info('Database backup completed successfully', { path: fullPath });
            resolve({ path: fullPath, filename });
          }
        });
      });
    } catch (error) {
      logger.error('Database backup failed', { error: error.message });
      throw error;
    }
  }

  async restore(backupPath) {
    try {
      const { exec } = await import('child_process');

      return new Promise((resolve, reject) => {
        exec(`mongorestore --db ${mongoose.connection.db.databaseName} ${backupPath} --gzip`, (error, stdout, stderr) => {
          if (error) {
            logger.error('Database restore failed', { error: error.message });
            reject(error);
          } else {
            logger.info('Database restore completed successfully');
            resolve({ success: true });
          }
        });
      });
    } catch (error) {
      logger.error('Database restore failed', { error: error.message });
      throw error;
    }
  }
}

// Create singleton instance
const database = new Database();

export default database;
