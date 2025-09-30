import mongoose from 'mongoose';

const dashboardSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true,
    maxlength: 100
  },
  description: String,
  isDefault: {
    type: Boolean,
    default: false
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  layout: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  widgets: [{
    id: {
      type: String,
      required: true
    },
    type: {
      type: String,
      required: true,
      enum: ['chart', 'metric', 'table', 'map', 'calendar', 'notification']
    },
    title: String,
    position: {
      x: { type: Number, default: 0 },
      y: { type: Number, default: 0 },
      width: { type: Number, default: 4 },
      height: { type: Number, default: 3 }
    },
    config: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    dataSource: {
      type: {
        type: String,
        enum: ['api', 'database', 'realtime']
      },
      endpoint: String,
      query: mongoose.Schema.Types.Mixed,
      refreshInterval: { type: Number, default: 30000 } // 30 seconds
    },
    permissions: [{
      type: String,
      enum: ['view', 'edit', 'delete', 'share']
    }]
  }],
  filters: {
    dateRange: {
      start: Date,
      end: Date,
      preset: {
        type: String,
        enum: ['today', 'yesterday', 'last7days', 'last30days', 'thisMonth', 'lastMonth', 'custom']
      }
    },
    categories: [String],
    accounts: [String],
    merchants: [String],
    amountRange: {
      min: mongoose.Decimal128,
      max: mongoose.Decimal128
    }
  },
  settings: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'auto'
    },
    timezone: {
      type: String,
      default: 'America/New_York'
    },
    currency: {
      type: String,
      default: 'USD'
    },
    language: {
      type: String,
      default: 'en'
    },
    autoRefresh: {
      type: Boolean,
      default: true
    },
    refreshInterval: {
      type: Number,
      default: 30000
    },
    notifications: {
      enabled: { type: Boolean, default: true },
      types: [{
        type: String,
        enum: ['alerts', 'updates', 'reminders', 'reports']
      }]
    }
  },
  accessControl: {
    sharedWith: [{
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      permissions: [{
        type: String,
        enum: ['view', 'edit', 'delete', 'share']
      }],
      sharedAt: {
        type: Date,
        default: Date.now
      }
    }],
    groups: [{
      groupId: String,
      permissions: [{
        type: String,
        enum: ['view', 'edit', 'delete', 'share']
      }]
    }]
  },
  metadata: {
    version: { type: Number, default: 1 },
    lastModifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    tags: [String],
    category: {
      type: String,
      enum: ['personal', 'team', 'department', 'organization']
    },
    usage: {
      viewCount: { type: Number, default: 0 },
      lastViewed: Date,
      favoriteCount: { type: Number, default: 0 }
    }
  }
}, {
  timestamps: true
});

// Indexes
dashboardSchema.index({ userId: 1 });
dashboardSchema.index({ isDefault: 1 });
dashboardSchema.index({ isPublic: 1 });
dashboardSchema.index({ 'metadata.category': 1 });
dashboardSchema.index({ 'accessControl.sharedWith.userId': 1 });

// Virtual for total widgets
dashboardSchema.virtual('widgetCount').get(function() {
  return this.widgets.length;
});

// Instance methods
dashboardSchema.methods = {
  // Add widget
  addWidget: function(widgetData) {
    const widget = {
      id: widgetData.id || mongoose.Types.ObjectId().toString(),
      type: widgetData.type,
      title: widgetData.title,
      position: widgetData.position || { x: 0, y: 0, width: 4, height: 3 },
      config: widgetData.config || {},
      dataSource: widgetData.dataSource || {},
      permissions: widgetData.permissions || ['view']
    };
    this.widgets.push(widget);
    return this.save();
  },

  // Remove widget
  removeWidget: function(widgetId) {
    this.widgets = this.widgets.filter(w => w.id !== widgetId);
    return this.save();
  },

  // Update widget
  updateWidget: function(widgetId, updates) {
    const widget = this.widgets.find(w => w.id === widgetId);
    if (widget) {
      Object.assign(widget, updates);
      return this.save();
    }
    throw new Error('Widget not found');
  },

  // Share with user
  shareWithUser: function(userId, permissions = ['view']) {
    const existingShare = this.accessControl.sharedWith.find(
      share => share.userId.toString() === userId.toString()
    );

    if (existingShare) {
      existingShare.permissions = permissions;
      existingShare.sharedAt = new Date();
    } else {
      this.accessControl.sharedWith.push({
        userId,
        permissions,
        sharedAt: new Date()
      });
    }
    return this.save();
  },

  // Check user access
  canUserAccess: function(userId, permission = 'view') {
    // Owner has all permissions
    if (this.userId.toString() === userId.toString()) {
      return true;
    }

    // Check shared access
    const share = this.accessControl.sharedWith.find(
      s => s.userId.toString() === userId.toString()
    );

    if (share && share.permissions.includes(permission)) {
      return true;
    }

    // Check public access
    if (this.isPublic && permission === 'view') {
      return true;
    }

    return false;
  },

  // Increment view count
  incrementViewCount: function() {
    this.metadata.usage.viewCount += 1;
    this.metadata.usage.lastViewed = new Date();
    return this.save();
  },

  // Get dashboard summary
  getSummary: function() {
    return {
      id: this._id,
      name: this.name,
      description: this.description,
      isDefault: this.isDefault,
      isPublic: this.isPublic,
      widgetCount: this.widgetCount,
      category: this.metadata.category,
      lastModified: this.updatedAt,
      usage: this.metadata.usage
    };
  }
};

// Static methods
dashboardSchema.statics = {
  // Get user's dashboards
  getUserDashboards: function(userId) {
    return this.find({
      $or: [
        { userId },
        { 'accessControl.sharedWith.userId': userId },
        { isPublic: true }
      ]
    }).sort({ updatedAt: -1 });
  },

  // Get default dashboard for user
  getDefaultForUser: function(userId) {
    return this.findOne({
      userId,
      isDefault: true
    });
  },

  // Get public dashboards
  getPublicDashboards: function(limit = 20) {
    return this.find({ isPublic: true })
      .sort({ 'metadata.usage.viewCount': -1 })
      .limit(limit);
  },

  // Search dashboards
  search: function(query, userId) {
    const searchQuery = {
      $and: [
        {
          $or: [
            { userId },
            { 'accessControl.sharedWith.userId': userId },
            { isPublic: true }
          ]
        },
        {
          $or: [
            { name: new RegExp(query, 'i') },
            { description: new RegExp(query, 'i') },
            { 'metadata.tags': new RegExp(query, 'i') }
          ]
        }
      ]
    };
    return this.find(searchQuery);
  }
};

export default mongoose.model('Dashboard', dashboardSchema);
