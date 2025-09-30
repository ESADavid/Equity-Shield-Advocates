import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const tenantSchema = new mongoose.Schema({
  tenantId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  domain: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['active', 'suspended', 'inactive'],
    default: 'active'
  },
  settings: {
    timezone: {
      type: String,
      default: 'UTC'
    },
    currency: {
      type: String,
      default: 'USD'
    },
    features: {
      payroll: { type: Boolean, default: true },
      merchant: { type: Boolean, default: true },
      jpmorgan: { type: Boolean, default: true },
      analytics: { type: Boolean, default: true },
      blockchain: { type: Boolean, default: true }
    },
    limits: {
      maxUsers: { type: Number, default: 100 },
      maxTransactions: { type: Number, default: 10000 },
      storageLimit: { type: Number, default: 1073741824 } // 1GB in bytes
    }
  },
  contact: {
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true
    },
    phone: {
      type: String,
      trim: true
    },
    address: {
      street: String,
      city: String,
      state: String,
      zipCode: String,
      country: String
    }
  },
  subscription: {
    plan: {
      type: String,
      enum: ['starter', 'professional', 'enterprise'],
      default: 'professional'
    },
    status: {
      type: String,
      enum: ['trial', 'active', 'expired', 'cancelled'],
      default: 'trial'
    },
    startDate: {
      type: Date,
      default: Date.now
    },
    endDate: {
      type: Date
    },
    autoRenew: {
      type: Boolean,
      default: true
    }
  },
  apiKeys: [{
    key: {
      type: String,
      required: true
    },
    name: {
      type: String,
      required: true
    },
    permissions: [{
      type: String,
      enum: ['read', 'write', 'admin']
    }],
    createdAt: {
      type: Date,
      default: Date.now
    },
    lastUsed: Date,
    isActive: {
      type: Boolean,
      default: true
    }
  }],
  audit: {
    createdBy: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedBy: String,
    updatedAt: Date,
    lastActivity: Date
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
tenantSchema.index({ domain: 1 });
tenantSchema.index({ status: 1 });
tenantSchema.index({ 'subscription.status': 1 });
tenantSchema.index({ 'subscription.endDate': 1 });

// Virtual for subscription status
tenantSchema.virtual('isSubscriptionActive').get(function() {
  return this.subscription.status === 'active' ||
         (this.subscription.status === 'trial' && this.subscription.endDate > new Date());
});

// Virtual for usage statistics
tenantSchema.virtual('usageStats').get(async function() {
  const User = mongoose.model('User');
  const Transaction = mongoose.model('Transaction');

  const [userCount, transactionCount] = await Promise.all([
    User.countDocuments({ tenantId: this.tenantId }),
    Transaction.countDocuments({ tenantId: this.tenantId })
  ]);

  return {
    users: userCount,
    transactions: transactionCount,
    userLimit: this.settings.limits.maxUsers,
    transactionLimit: this.settings.limits.maxTransactions
  };
});

// Pre-save middleware to hash API keys
tenantSchema.pre('save', async function(next) {
  if (this.isModified('apiKeys')) {
    for (let apiKey of this.apiKeys) {
      if (apiKey.key && !apiKey.key.startsWith('$2a$')) {
        apiKey.key = await bcrypt.hash(apiKey.key, 12);
      }
    }
  }
  next();
});

// Instance methods
tenantSchema.methods = {
  // Verify API key
  async verifyApiKey(key) {
    for (let apiKey of this.apiKeys) {
      if (apiKey.isActive && await bcrypt.compare(key, apiKey.key)) {
        apiKey.lastUsed = new Date();
        await this.save();
        return { valid: true, permissions: apiKey.permissions, name: apiKey.name };
      }
    }
    return { valid: false };
  },

  // Check feature access
  hasFeature(feature) {
    return this.settings.features[feature] === true;
  },

  // Check limits
  async checkLimits(type) {
    const stats = await this.getUsageStats();
    const limit = this.settings.limits[type + 'Limit'];
    const current = stats[type + 's'];

    return {
      current,
      limit,
      remaining: Math.max(0, limit - current),
      exceeded: current >= limit
    };
  },

  // Get usage statistics
  async getUsageStats() {
    const User = mongoose.model('User');
    const Transaction = mongoose.model('Transaction');

    const [userCount, transactionCount] = await Promise.all([
      User.countDocuments({ tenantId: this.tenantId }),
      Transaction.countDocuments({ tenantId: this.tenantId })
    ]);

    return {
      users: userCount,
      transactions: transactionCount,
      userLimit: this.settings.limits.maxUsers,
      transactionLimit: this.settings.limits.maxTransactions
    };
  },

  // Suspend tenant
  suspend(reason) {
    this.status = 'suspended';
    this.audit.updatedAt = new Date();
    this.audit.updatedBy = 'system';
    return this.save();
  },

  // Reactivate tenant
  reactivate() {
    this.status = 'active';
    this.audit.updatedAt = new Date();
    this.audit.updatedBy = 'system';
    return this.save();
  }
};

// Static methods
tenantSchema.statics = {
  // Find tenant by domain
  findByDomain(domain) {
    return this.findOne({ domain: domain.toLowerCase(), status: 'active' });
  },

  // Find tenants with expired subscriptions
  findExpiredSubscriptions() {
    return this.find({
      'subscription.status': { $in: ['trial', 'active'] },
      'subscription.endDate': { $lt: new Date() }
    });
  },

  // Create default tenant
  async createDefaultTenant() {
    const defaultTenant = {
      tenantId: 'default',
      name: 'Oscar Broome Revenue',
      domain: 'oscarbroome.com',
      description: 'Default tenant for Oscar Broome Revenue system',
      contact: {
        email: 'admin@oscarbroome.com'
      },
      settings: {
        features: {
          payroll: true,
          merchant: true,
          jpmorgan: true,
          analytics: true,
          blockchain: true
        }
      },
      audit: {
        createdBy: 'system'
      }
    };

    return this.findOneAndUpdate(
      { tenantId: 'default' },
      defaultTenant,
      { upsert: true, new: true }
    );
  }
};

const Tenant = mongoose.model('Tenant', tenantSchema);

export default Tenant;
