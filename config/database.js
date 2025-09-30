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
    this.performanceMetrics = {
      queryCount: 0,
      slowQueries: 0,
      connectionPoolSize: 0,
      averageQueryTime: 0
    };
  }

  async connect() {
    try {
      // Skip database connection if explicitly disabled
      if (process.env.SKIP_DATABASE === 'true') {
        console.log('⚠️ Database connection skipped (SKIP_DATABASE=true)');
        this.isConnected = false;
        return null;
      }

      const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/oscar-broome-revenue';

      const options = {
        maxPoolSize: 20, // Increased for better performance
        minPoolSize: 5,  // Minimum connections to maintain
        maxIdleTimeMS: 30000,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        bufferCommands: false, // Disable mongoose buffering
        family: 4,
        // Performance optimizations
        readPreference: 'primaryPreferred',
        retryWrites: true,
        retryReads: true,
        // Connection monitoring
        heartbeatFrequencyMS: 10000,
        // Compression
        compressors: ['zlib']
      };

      this.connection = await mongoose.connect(mongoURI, options);

      this.isConnected = true;

      logger.info('MongoDB connected successfully', {
        host: this.connection.connection.host,
        port: this.connection.connection.port,
        name: this.connection.connection.name,
        maxPoolSize: options.maxPoolSize,
        minPoolSize: options.minPoolSize
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

      // Set up query performance monitoring
      this.setupPerformanceMonitoring();

      return this.connection;
    } catch (error) {
      logger.error('MongoDB connection failed', { error: error.message });
      throw error;
    }
  }

  setupPerformanceMonitoring() {
    // Monitor query performance
    mongoose.set('debug', (collectionName, methodName, ...args) => {
      const startTime = Date.now();
      this.performanceMetrics.queryCount++;

      // Log slow queries (>100ms)
      setImmediate(() => {
        const duration = Date.now() - startTime;
        if (duration > 100) {
          this.performanceMetrics.slowQueries++;
          logger.warn('Slow query detected', {
            collection: collectionName,
            method: methodName,
            duration,
            args: args.length > 0 ? args[0] : null
          });
        }

        // Update average query time
        this.performanceMetrics.averageQueryTime =
          (this.performanceMetrics.averageQueryTime + duration) / 2;
      });
    });
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

      // Get connection pool stats
      const poolStats = await this.getConnectionPoolStats();

      return {
        status: 'connected',
        latency,
        database: mongoose.connection.db.databaseName,
        collections: await mongoose.connection.db.listCollections().toArray().then(cols => cols.length),
        performance: {
          queryCount: this.performanceMetrics.queryCount,
          slowQueries: this.performanceMetrics.slowQueries,
          averageQueryTime: Math.round(this.performanceMetrics.averageQueryTime),
          connectionPool: poolStats
        }
      };
    } catch (error) {
      logger.error('Database health check failed', { error: error.message });
      return { status: 'error', error: error.message };
    }
  }

  async getConnectionPoolStats() {
    try {
      const stats = await mongoose.connection.db.command({ serverStatus: 1 });
      return {
        poolSize: stats.connections?.current || 0,
        available: stats.connections?.available || 0,
        created: stats.connections?.totalCreated || 0
      };
    } catch (error) {
      return { poolSize: 0, available: 0, created: 0 };
    }
  }

  getPerformanceMetrics() {
    return { ...this.performanceMetrics };
  }
}

// Create singleton instance
const database = new Database();

export default database;
