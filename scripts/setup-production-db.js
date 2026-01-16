import { info, error, warn, debug } from '../utils/loggerWrapper.js';

#!/usr/bin/env node

/**
 * Setup Production Database
 * Initializes production database with required collections and indexes
 */

const { MongoClient } = require('mongodb');
const fs = require('fs');
const path = require('path');

class ProductionDatabaseSetup {
  constructor() {
    this.mongoUri = process.env.MONGODB_URI || 'mongodb://mongodb:27017/oscar-broome-production';
    this.dbName = 'oscar-broome-production';
    this.client = null;
    this.db = null;
  }

  async connect() {
    try {
      logger.info('🔧 Connecting to production database...');
      this.client = new MongoClient(this.mongoUri);
      await this.client.connect();
      this.db = this.client.db(this.dbName);
      logger.info('✅ Connected to production database');
    } catch (error) {
      logger.error('❌ Failed to connect to database:', error.message);
      throw error;
    }
  }

  async createCollections() {
    logger.info('🔧 Creating collections...');

    const collections = [
      'users',
      'transactions',
      'citizens',
      'partners',
      'analytics',
      'notifications',
      'auditlogs',
      'debtacquisitions',
      'payroll',
      'blockchain',
      'sessions'
    ];

    for (const collectionName of collections) {
      try {
        await this.db.createCollection(collectionName);
        logger.info(`✅ Created collection: ${collectionName}`);
      } catch (error) {
        if (error.code === 48) { // Collection already exists
          logger.info(`ℹ️ Collection already exists: ${collectionName}`);
        } else {
          logger.error(`❌ Failed to create collection ${collectionName}:`, error.message);
        }
      }
    }
  }

  async createIndexes() {
    logger.info('🔧 Creating indexes...');

    const indexes = [
      // Users collection
      { collection: 'users', key: { email: 1 }, options: { unique: true } },
      { collection: 'users', key: { username: 1 }, options: { unique: true } },
      { collection: 'users', key: { createdAt: 1 } },

      // Transactions collection
      { collection: 'transactions', key: { userId: 1 } },
      { collection: 'transactions', key: { createdAt: 1 } },
      { collection: 'transactions', key: { status: 1 } },
      { collection: 'transactions', key: { amount: 1 } },

      // Citizens collection
      { collection: 'citizens', key: { citizenId: 1 }, options: { unique: true } },
      { collection: 'citizens', key: { userId: 1 } },
      { collection: 'citizens', key: { status: 1 } },

      // Partners collection
      { collection: 'partners', key: { partnerId: 1 }, options: { unique: true } },
      { collection: 'partners', key: { name: 1 } },
      { collection: 'partners', key: { status: 1 } },

      // Analytics collection
      { collection: 'analytics', key: { timestamp: 1 } },
      { collection: 'analytics', key: { type: 1 } },

      // Notifications collection
      { collection: 'notifications', key: { userId: 1 } },
      { collection: 'notifications', key: { createdAt: 1 } },
      { collection: 'notifications', key: { status: 1 } },

      // Audit logs collection
      { collection: 'auditlogs', key: { timestamp: 1 } },
      { collection: 'auditlogs', key: { userId: 1 } },
      { collection: 'auditlogs', key: { action: 1 } },

      // Debt acquisitions collection
      { collection: 'debtacquisitions', key: { debtId: 1 }, options: { unique: true } },
      { collection: 'debtacquisitions', key: { status: 1 } },
      { collection: 'debtacquisitions', key: { createdAt: 1 } },

      // Payroll collection
      { collection: 'payroll', key: { employeeId: 1 } },
      { collection: 'payroll', key: { payPeriod: 1 } },
      { collection: 'payroll', key: { status: 1 } },

      // Blockchain collection
      { collection: 'blockchain', key: { transactionId: 1 }, options: { unique: true } },
      { collection: 'blockchain', key: { blockNumber: 1 } },
      { collection: 'blockchain', key: { timestamp: 1 } },

      // Sessions collection
      { collection: 'sessions', key: { sessionId: 1 }, options: { unique: true } },
      { collection: 'sessions', key: { userId: 1 } },
      { collection: 'sessions', key: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } }
    ];

    for (const index of indexes) {
      try {
        await this.db.collection(index.collection).createIndex(index.key, index.options || {});
        logger.info(`✅ Created index on ${index.collection}: ${JSON.stringify(index.key)}`);
      } catch (error) {
        logger.error(`❌ Failed to create index on ${index.collection}:`, error.message);
      }
    }
  }

  async createInitialData() {
    logger.info('🔧 Creating initial data...');

    // Create admin user if it doesn't exist
    const adminUser = {
      email: 'admin@oscar-broome-revenue.com',
      username: 'admin',
      password: '$2b$10$hashedpassword', // This should be properly hashed
      role: 'admin',
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    try {
      const existingAdmin = await this.db.collection('users').findOne({ email: adminUser.email });
      if (!existingAdmin) {
        await this.db.collection('users').insertOne(adminUser);
        logger.info('✅ Created admin user');
      } else {
        logger.info('ℹ️ Admin user already exists');
      }
    } catch (error) {
      logger.error('❌ Failed to create admin user:', error.message);
    }

    // Create system configuration document
    const systemConfig = {
      _id: 'system-config',
      version: '1.0.0',
      environment: 'production',
      features: {
        ubi: true,
        blockchain: true,
        analytics: true,
        notifications: true,
        security: true
      },
      limits: {
        maxUsers: 1000000,
        maxTransactionsPerDay: 10000,
        maxFileSize: 10485760 // 10MB
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };

    try {
      await this.db.collection('system').replaceOne(
        { _id: 'system-config' },
        systemConfig,
        { upsert: true }
      );
      logger.info('✅ Created system configuration');
    } catch (error) {
      logger.error('❌ Failed to create system configuration:', error.message);
    }
  }

  async runMaintenance() {
    logger.info('🔧 Running database maintenance...');

    try {
      // Run database stats
      const stats = await this.db.stats();
      logger.info('📊 Database stats:', {
        collections: stats.collections,
        objects: stats.objects,
        dataSize: `${(stats.dataSize / 1024 / 1024).toFixed(2)} MB`,
        storageSize: `${(stats.storageSize / 1024 / 1024).toFixed(2)} MB`
      });

      // Validate collections
      const collections = await this.db.listCollections().toArray();
      for (const collection of collections) {
        try {
          const validation = await this.db.command({ validate: collection.name });
          if (validation.valid) {
            logger.info(`✅ Collection ${collection.name} is valid`);
          } else {
            logger.warn(`⚠️ Collection ${collection.name} has issues`);
          }
        } catch (error) {
          logger.error(`❌ Failed to validate collection ${collection.name}:`, error.message);
        }
      }
    } catch (error) {
      logger.error('❌ Database maintenance failed:', error.message);
    }
  }

  async disconnect() {
    if (this.client) {
      await this.client.close();
      logger.info('✅ Disconnected from database');
    }
  }

  async run() {
    try {
      logger.info('🚀 Starting production database setup...');

      await this.connect();
      await this.createCollections();
      await this.createIndexes();
      await this.createInitialData();
      await this.runMaintenance();

      logger.info('✅ Production database setup completed successfully');
    } catch (error) {
      logger.error('❌ Production database setup failed:', error.message);
      process.exit(1);
    } finally {
      await this.disconnect();
    }
  }
}

// Execute setup
const setup = new ProductionDatabaseSetup();
setup.run().catch((error) => {
  logger.error('Fatal error:', error);
  process.exit(1);
});
