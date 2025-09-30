import Redis from 'ioredis';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'cache' },
  transports: [
    new winston.transports.File({ filename: 'logs/cache.log' }),
    new winston.transports.File({ filename: 'logs/cache-error.log', level: 'error' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

class CacheService {
  constructor() {
    this.client = null;
    this.isConnected = false;
    this.metrics = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      errors: 0
    };
  }

  async connect() {
    try {
      const redisConfig = {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD || undefined,
        db: process.env.REDIS_DB || 0,
        retryDelayOnFailover: 100,
        maxRetriesPerRequest: 3,
        lazyConnect: true,
        // Performance optimizations
        connectTimeout: 5000,
        commandTimeout: 3000,
        keepAlive: 30000,
        // Clustering support
        cluster: process.env.REDIS_CLUSTER === 'true' ? {
          enableReadyCheck: false,
          redisOptions: {
            password: process.env.REDIS_PASSWORD
          }
        } : undefined
      };

      this.client = new Redis(redisConfig);

      this.client.on('connect', () => {
        this.isConnected = true;
        logger.info('Redis connected successfully');
      });

      this.client.on('error', (error) => {
        this.isConnected = false;
        this.metrics.errors++;
        logger.error('Redis connection error', { error: error.message });
      });

      this.client.on('ready', () => {
        logger.info('Redis client ready');
      });

      await this.client.connect();
      return this.client;
    } catch (error) {
      logger.error('Redis connection failed', { error: error.message });
      // Fallback to in-memory cache if Redis is not available
      this.fallbackToMemoryCache();
      return null;
    }
  }

  fallbackToMemoryCache() {
    logger.warn('Falling back to in-memory cache');
    this.memoryCache = new Map();
    this.memoryCacheTimeouts = new Map();
  }

  async disconnect() {
    if (this.client) {
      await this.client.quit();
      this.isConnected = false;
      logger.info('Redis disconnected');
    }
  }

  // Core caching methods
  async get(key) {
    try {
      if (!this.isConnected && this.memoryCache) {
        return this.memoryCache.get(key);
      }

      if (!this.client) return null;

      const value = await this.client.get(key);
      if (value) {
        this.metrics.hits++;
        return JSON.parse(value);
      } else {
        this.metrics.misses++;
        return null;
      }
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache get error', { key, error: error.message });
      return null;
    }
  }

  async set(key, value, ttl = null) {
    try {
      if (!this.isConnected && this.memoryCache) {
        this.memoryCache.set(key, value);
        if (ttl) {
          setTimeout(() => this.memoryCache.delete(key), ttl * 1000);
        }
        return true;
      }

      if (!this.client) return false;

      const serializedValue = JSON.stringify(value);
      this.metrics.sets++;

      if (ttl) {
        return await this.client.setex(key, ttl, serializedValue);
      } else {
        return await this.client.set(key, serializedValue);
      }
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache set error', { key, error: error.message });
      return false;
    }
  }

  async delete(key) {
    try {
      if (!this.isConnected && this.memoryCache) {
        return this.memoryCache.delete(key);
      }

      if (!this.client) return false;

      this.metrics.deletes++;
      return await this.client.del(key);
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache delete error', { key, error: error.message });
      return false;
    }
  }

  async exists(key) {
    try {
      if (!this.isConnected && this.memoryCache) {
        return this.memoryCache.has(key);
      }

      if (!this.client) return false;

      return await this.client.exists(key);
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache exists error', { key, error: error.message });
      return false;
    }
  }

  // Advanced caching methods
  async getOrSet(key, fetcher, ttl = 300) {
    let value = await this.get(key);
    if (value !== null) {
      return value;
    }

    // Cache miss - fetch from source
    value = await fetcher();
    if (value !== null) {
      await this.set(key, value, ttl);
    }
    return value;
  }

  async invalidatePattern(pattern) {
    try {
      if (!this.isConnected && this.memoryCache) {
        // For memory cache, we can't easily pattern match, so clear all
        this.memoryCache.clear();
        return true;
      }

      if (!this.client) return false;

      const keys = await this.client.keys(pattern);
      if (keys.length > 0) {
        await this.client.del(keys);
        logger.info('Cache pattern invalidated', { pattern, keysDeleted: keys.length });
      }
      return true;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache pattern invalidation error', { pattern, error: error.message });
      return false;
    }
  }

  // Tenant-specific caching methods
  getTenantKey(tenantId, key) {
    return `tenant:${tenantId}:${key}`;
  }

  async getTenantData(tenantId, key) {
    const tenantKey = this.getTenantKey(tenantId, key);
    return await this.get(tenantKey);
  }

  async setTenantData(tenantId, key, value, ttl = 300) {
    const tenantKey = this.getTenantKey(tenantId, key);
    return await this.set(tenantKey, value, ttl);
  }

  async invalidateTenantCache(tenantId) {
    const pattern = `tenant:${tenantId}:*`;
    return await this.invalidatePattern(pattern);
  }

  // User session caching
  async getUserSession(sessionId) {
    return await this.get(`session:${sessionId}`);
  }

  async setUserSession(sessionId, sessionData, ttl = 3600) {
    return await this.set(`session:${sessionId}`, sessionData, ttl);
  }

  async deleteUserSession(sessionId) {
    return await this.delete(`session:${sessionId}`);
  }

  // Analytics caching
  async getAnalyticsData(tenantId, type, dateRange) {
    const key = `analytics:${tenantId}:${type}:${dateRange}`;
    return await this.get(key);
  }

  async setAnalyticsData(tenantId, type, dateRange, data, ttl = 1800) {
    const key = `analytics:${tenantId}:${type}:${dateRange}`;
    return await this.set(key, data, ttl);
  }

  // Health check
  async healthCheck() {
    try {
      // If we have memory cache (fallback), return memory_cache status
      if (this.memoryCache) {
        return {
          status: 'memory_cache',
          memoryCacheSize: this.memoryCache.size,
          metrics: this.metrics
        };
      }

      if (!this.client) {
        return { status: 'disconnected' };
      }

      const start = Date.now();
      await this.client.ping();
      const latency = Date.now() - start;

      const info = await this.client.info();
      const dbSize = await this.client.dbsize();

      return {
        status: 'connected',
        latency,
        dbSize,
        info: info.split('\r\n').slice(0, 10), // First 10 lines of info
        metrics: this.metrics
      };
    } catch (error) {
      // If Redis fails but we have memory cache, still return memory_cache
      if (this.memoryCache) {
        return {
          status: 'memory_cache',
          memoryCacheSize: this.memoryCache.size,
          metrics: this.metrics
        };
      }
      return {
        status: 'error',
        error: error.message,
        metrics: this.metrics
      };
    }
  }

  // Performance monitoring
  getMetrics() {
    const totalRequests = this.metrics.hits + this.metrics.misses;
    const hitRate = totalRequests > 0 ? (this.metrics.hits / totalRequests) * 100 : 0;

    return {
      ...this.metrics,
      hitRate: Math.round(hitRate * 100) / 100,
      totalRequests
    };
  }

  resetMetrics() {
    this.metrics = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      errors: 0
    };
    logger.info('Cache metrics reset');
  }

  // Cache warming for critical data
  async warmCache(tenantId) {
    try {
      // Warm up tenant configuration
      await this.setTenantData(tenantId, 'config', { cached: true }, 3600);

      // Warm up user count
      const User = (await import('../models/User.js')).default;
      const userCount = await User.countDocuments({ tenantId });
      await this.setTenantData(tenantId, 'userCount', userCount, 300);

      // Warm up recent transactions count
      const Transaction = (await import('../models/Transaction.js')).default;
      const recentTxCount = await Transaction.countDocuments({
        tenantId,
        'timestamps.initiated': { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });
      await this.setTenantData(tenantId, 'recentTransactions', recentTxCount, 300);

      logger.info('Cache warmed for tenant', { tenantId });
      return true;
    } catch (error) {
      logger.error('Cache warming failed', { tenantId, error: error.message });
      return false;
    }
  }
}

// Create singleton instance
const cacheService = new CacheService();

export default cacheService;
