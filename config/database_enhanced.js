import mongoose from 'mongoose';
import winston from 'winston';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'database-enhanced' },
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

class EnhancedDatabase {
  maxRetries = Number.parseInt(process.env.DB_MAX_RETRIES) || 5;
  retryDelay = Number.parseInt(process.env.DB_RETRY_DELAY) || 1000; // Start with 1 second
  maxRetryDelay = 30000; // Max 30 seconds
  connectionTimeout = Number.parseInt(process.env.DB_CONNECTION_TIMEOUT) || 30000;
  isConnected = false;
  connection = null;
  retryCount = 0;
  performanceMetrics = {
    queryCount: 0,
    slowQueries: 0,
    connectionPoolSize: 0,
    averageQueryTime: 0,
    connectionAttempts: 0,
    successfulConnections: 0,
    failedConnections: 0,
    lastConnectionTime: null,
    uptime: 0
  };
  healthCheckInterval = null;
  reconnectOnFailure = process.env.DB_RECONNECT_ON_FAILURE !== 'false';

  async connect() {
    try {
      // Skip database connection if explicitly disabled
      if (process.env.SKIP_DATABASE === 'true') {
        console.log('⚠️ Database connection skipped (SKIP_DATABASE=true)');
        this.isConnected = false;
        return null;
      }

      this.performanceMetrics.connectionAttempts++;

      const mongoURI = this.buildConnectionString();

      const options = {
        maxPoolSize: Number.parseInt(process.env.DB_MAX_POOL_SIZE) || 20,
        minPoolSize: Number.parseInt(process.env.DB_MIN_POOL_SIZE) || 5,
        maxIdleTimeMS: Number.parseInt(process.env.DB_MAX_IDLE_TIME) || 30000,
        serverSelectionTimeoutMS: Number.parseInt(process.env.DB_SERVER_SELECTION_TIMEOUT) || 5000,
        socketTimeoutMS: Number.parseInt(process.env.DB_SOCKET_TIMEOUT) || 45000,
        bufferCommands: false,
        family: 4,
        readPreference: process.env.DB_READ_PREFERENCE || 'primaryPreferred',
        retryWrites: process.env.DB_RETRY_WRITES !== 'false',
        retryReads: process.env.DB_RETRY_READS !== 'false',
        heartbeatFrequencyMS: Number.parseInt(process.env.DB_HEARTBEAT_FREQUENCY) || 10000,
        compressors: process.env.DB_COMPRESSORS ? process.env.DB_COMPRESSORS.split(',') : ['zlib'],
        zlibCompressionLevel: Number.parseInt(process.env.DB_ZLIB_LEVEL) || 6,
        // Connection monitoring
        monitorCommands: process.env.DB_MONITOR_COMMANDS === 'true',
        // SSL/TLS options
        ssl: process.env.DB_SSL === 'true',
        sslCA: process.env.DB_SSL_CA,
        sslCert: process.env.DB_SSL_CERT,
        sslKey: process.env.DB_SSL_KEY,
        // Authentication
        authSource: process.env.DB_AUTH_SOURCE || 'admin',
        authMechanism: process.env.DB_AUTH_MECHANISM || 'SCRAM-SHA-256'
      };

      // Add replica set options if configured
      if (process.env.DB_REPLICA_SET) {
        options.replicaSet = process.env.DB_REPLICA_SET;
      }

      // Add authentication if credentials provided
      if (process.env.DB_USERNAME && process.env.DB_PASSWORD) {
        options.user = process.env.DB_USERNAME;
        options.pass = process.env.DB_PASSWORD;
      } else {
        // Remove auth mechanism if no credentials provided
        delete options.authMechanism;
        delete options.authSource;
      }

      logger.info('Attempting database connection', {
        uri: this.maskConnectionString(mongoURI),
        options: { ...options, pass: options.pass ? '***' : undefined }
      });

      this.connection = await mongoose.connect(mongoURI, options);

      this.isConnected = true;
      this.retryCount = 0;
      this.performanceMetrics.successfulConnections++;
      this.performanceMetrics.lastConnectionTime = Date.now();

      logger.info('MongoDB connected successfully', {
        host: this.connection.connection.host,
        port: this.connection.connection.port,
        name: this.connection.connection.name,
        maxPoolSize: options.maxPoolSize,
        minPoolSize: options.minPoolSize,
        readPreference: options.readPreference
      });

      // Set up enhanced connection event listeners
      this.setupConnectionListeners();

      // Set up query performance monitoring
      this.setupPerformanceMonitoring();

      // Start health check monitoring
      this.startHealthMonitoring();

      return this.connection;
    } catch (error) {
      this.performanceMetrics.failedConnections++;
      logger.error('MongoDB connection failed', {
        error: error.message,
        retryCount: this.retryCount,
        maxRetries: this.maxRetries
      });

      if (this.reconnectOnFailure && this.retryCount < this.maxRetries) {
        return this.retryConnection();
      }

      throw error;
    }
  }

  buildConnectionString() {
    const host = process.env.DB_HOST || 'localhost';
    const port = process.env.DB_PORT || '27017';
    const database = process.env.DB_NAME || 'oscar-broome-revenue';

    let uri = `mongodb://${host}:${port}/${database}`;

    // Add replica set if configured
    if (process.env.DB_REPLICA_SET) {
      uri += `?replicaSet=${process.env.DB_REPLICA_SET}`;
    }

    // Override with full URI if provided
    if (process.env.MONGODB_URI) {
      uri = process.env.MONGODB_URI;
    }

    return uri;
  }

  maskConnectionString(uri) {
    // Mask password in connection string for logging
    return uri.replace(/:([^:@]{4})[^:@]*@/, ':$1****@');
  }

  async retryConnection() {
    this.retryCount++;
    const delay = Math.min(this.retryDelay * Math.pow(2, this.retryCount - 1), this.maxRetryDelay);

    logger.info(`Retrying database connection in ${delay}ms (attempt ${this.retryCount}/${this.maxRetries})`);

    await new Promise(resolve => setTimeout(resolve, delay));
    return this.connect();
  }

  setupConnectionListeners() {
    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error', { error: err.message });
      this.isConnected = false;
      this.performanceMetrics.failedConnections++;
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
      this.isConnected = false;
      this.performanceMetrics.uptime = 0;

      if (this.reconnectOnFailure) {
        logger.info('Attempting to reconnect to MongoDB...');
        setTimeout(() => this.connect(), this.retryDelay);
      }
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected');
      this.isConnected = true;
      this.performanceMetrics.successfulConnections++;
      this.performanceMetrics.lastConnectionTime = Date.now();
    });

    mongoose.connection.on('reconnectFailed', () => {
      logger.error('MongoDB reconnection failed');
      this.performanceMetrics.failedConnections++;
    });

    mongoose.connection.on('close', () => {
      logger.info('MongoDB connection closed');
      this.isConnected = false;
    });
  }

  setupPerformanceMonitoring() {
    // Enhanced query performance monitoring
    mongoose.set('debug', (collectionName, methodName, ...args) => {
      const startTime = Date.now();
      this.performanceMetrics.queryCount++;

      // Log slow queries with more detail
      setImmediate(() => {
        const duration = Date.now() - startTime;
        if (duration > (Number.parseInt(process.env.DB_SLOW_QUERY_THRESHOLD) || 100)) {
          this.performanceMetrics.slowQueries++;
          logger.warn('Slow query detected', {
            collection: collectionName,
            method: methodName,
            duration,
            args: args.length > 0 ? this.sanitizeQueryArgs(args[0]) : null,
            connectionPool: this.getConnectionPoolStats()
          });
        }

        // Update average query time
        this.performanceMetrics.averageQueryTime =
          (this.performanceMetrics.averageQueryTime + duration) / 2;
      });
    });
  }

  sanitizeQueryArgs(args) {
    // Remove sensitive data from query logs
    if (typeof args === 'object' && args !== null) {
      const sanitized = { ...args };
      const sensitiveFields = ['password', 'token', 'secret', 'key', 'ssn', 'creditCard'];

      for (const field of sensitiveFields) {
        if (sanitized[field]) {
          sanitized[field] = '***';
        }
      }

      return sanitized;
    }
    return args;
  }

  startHealthMonitoring() {
    const interval = Number.parseInt(process.env.DB_HEALTH_CHECK_INTERVAL) || 30000; // 30 seconds

    this.healthCheckInterval = setInterval(async () => {
      try {
        if (this.isConnected) {
          const start = Date.now();
          await mongoose.connection.db.admin().ping();
          const latency = Date.now() - start;

          // Update uptime
          if (this.performanceMetrics.lastConnectionTime) {
            this.performanceMetrics.uptime = Date.now() - this.performanceMetrics.lastConnectionTime;
          }

          // Log if latency is high
          if (latency > 1000) {
            logger.warn('High database latency detected', { latency });
          }
        }
      } catch (error) {
        logger.error('Database health check failed', { error: error.message });
        this.isConnected = false;
      }
    }, interval);
  }

  async disconnect() {
    try {
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
        this.healthCheckInterval = null;
      }

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
        return {
          status: 'disconnected',
          latency: null,
          retryCount: this.retryCount,
          maxRetries: this.maxRetries
        };
      }

      const start = Date.now();
      await mongoose.connection.db.admin().ping();
      const latency = Date.now() - start;

      const poolStats = await this.getConnectionPoolStats();
      const dbStats = await this.getDatabaseStats();

      return {
        status: 'connected',
        latency,
        database: mongoose.connection.db.databaseName,
        collections: dbStats.collections || 0,
        dataSize: dbStats.dataSize || 0,
        storageSize: dbStats.storageSize || 0,
        performance: {
          queryCount: this.performanceMetrics.queryCount,
          slowQueries: this.performanceMetrics.slowQueries,
          averageQueryTime: Math.round(this.performanceMetrics.averageQueryTime),
          connectionPool: poolStats,
          uptime: this.performanceMetrics.uptime,
          connectionAttempts: this.performanceMetrics.connectionAttempts,
          successfulConnections: this.performanceMetrics.successfulConnections,
          failedConnections: this.performanceMetrics.failedConnections
        }
      };
    } catch (error) {
      logger.error('Database health check failed', { error: error.message });
      return {
        status: 'error',
        error: error.message,
        retryCount: this.retryCount,
        maxRetries: this.maxRetries
      };
    }
  }

  async getConnectionPoolStats() {
    try {
      const stats = await mongoose.connection.db.command({ serverStatus: 1 });
      return {
        poolSize: stats.connections?.current || 0,
        available: stats.connections?.available || 0,
        created: stats.connections?.totalCreated || 0,
        active: stats.connections?.active || 0
      };
    } catch (error) {
      logger.warn('Failed to get connection pool stats', { error: error.message });
      return {
        poolSize: 0,
        available: 0,
        created: 0,
        active: 0
      };
    }
  }

  async getDatabaseStats() {
    try {
      const stats = await mongoose.connection.db.stats();
      return {
        collections: stats.collections || 0,
        objects: stats.objects || 0,
        dataSize: stats.dataSize || 0,
        storageSize: stats.storageSize || 0,
        indexes: stats.indexes || 0,
        indexSize: stats.indexSize || 0
      };
    } catch (error) {
      logger.warn('Failed to get database stats', { error: error.message });
      return {};
    }
  }

  getPerformanceMetrics() {
    return { ...this.performanceMetrics };
  }

  // Database maintenance methods
  async createIndexes(model, indexes) {
    try {
      const collection = mongoose.connection.db.collection(model.collection.name);
      await collection.createIndexes(indexes);
      logger.info('Indexes created successfully', { model: model.modelName, indexes: indexes.length });
    } catch (error) {
      logger.error('Failed to create indexes', { error: error.message, model: model.modelName });
      throw error;
    }
  }

  async dropIndexes(model, indexNames) {
    try {
      const collection = mongoose.connection.db.collection(model.collection.name);
      for (const indexName of indexNames) {
        await collection.dropIndex(indexName);
      }
      logger.info('Indexes dropped successfully', { model: model.modelName, indexes: indexNames.length });
    } catch (error) {
      logger.error('Failed to drop indexes', { error: error.message, model: model.modelName });
      throw error;
    }
  }

  async optimizeCollection(model) {
    try {
      const collection = mongoose.connection.db.collection(model.collection.name);
      await collection.compact();
      logger.info('Collection optimized', { model: model.modelName });
    } catch (error) {
      logger.error('Failed to optimize collection', { error: error.message, model: model.modelName });
      throw error;
    }
  }

  // Backup and restore methods
  async createBackup(backupPath) {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `backup-${timestamp}.gz`;
      const fullPath = `${backupPath}/${filename}`;

      await execAsync(
        `mongodump --db ${mongoose.connection.db.databaseName} --out ${fullPath} --gzip`
      );

      logger.info('Database backup created', { path: fullPath });
      return fullPath;
    } catch (error) {
      logger.error('Database backup failed', { error: error.message });
      throw error;
    }
  }

  async restoreBackup(backupPath) {
    try {
      await execAsync(
        `mongorestore --db ${mongoose.connection.db.databaseName} --dir ${backupPath} --gzip --drop`
      );

      logger.info('Database restored from backup', { path: backupPath });
    } catch (error) {
      logger.error('Database restore failed', { error: error.message });
      throw error;
    }
  }

  // Multi-database support
  async switchDatabase(dbName) {
    try {
      this.connection = await mongoose.connection.useDb(dbName);
      logger.info('Switched to database', { database: dbName });
      return this.connection;
    } catch (error) {
      logger.error('Failed to switch database', { error: error.message, database: dbName });
      throw error;
    }
  }

  // Transaction support
  async executeTransaction(callback) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const result = await callback(session);
      await session.commitTransaction();
      logger.info('Transaction committed successfully');
      return result;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Transaction aborted', { error: error.message });
      throw error;
    } finally {
      session.endSession();
    }
  }
}

// Create singleton instance
const enhancedDatabase = new EnhancedDatabase();

export default enhancedDatabase;
