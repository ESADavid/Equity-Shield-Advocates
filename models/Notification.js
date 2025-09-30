import mongoose from 'mongoose';

const notificationSchema = new mongoose.Schema({
  tenantId: {
    type: String,
    required: true,
    index: true
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    required: true,
    enum: [
      'transaction_alert',
      'security_alert',
      'system_notification',
      'payment_reminder',
      'report_ready',
      'maintenance_alert',
      'blockchain_update',
      'ai_insight',
      'custom'
    ]
  },
  title: {
    type: String,
    required: true,
    maxlength: 200
  },
  message: {
    type: String,
    required: true,
    maxlength: 1000
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  category: {
    type: String,
    enum: ['transaction', 'security', 'system', 'payment', 'report', 'maintenance', 'blockchain', 'ai', 'other'],
    default: 'other'
  },
  status: {
    type: String,
    enum: ['unread', 'read', 'archived', 'deleted'],
    default: 'unread'
  },
  channels: [{
    type: {
      type: String,
      enum: ['in_app', 'email', 'sms', 'push', 'webhook']
    },
    status: {
      type: String,
      enum: ['pending', 'sent', 'delivered', 'failed'],
      default: 'pending'
    },
    sentAt: Date,
    deliveredAt: Date,
    error: String,
    recipient: String // email, phone, etc.
  }],
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  actions: [{
    label: String,
    action: {
      type: String,
      enum: ['link', 'button', 'dismiss', 'custom']
    },
    url: String,
    data: mongoose.Schema.Types.Mixed
  }],
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
  },
  relatedEntities: {
    transactionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Transaction'
    },
    dashboardId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Dashboard'
    },
    analyticsId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Analytics'
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }
}, {
  timestamps: true
});

// Indexes
notificationSchema.index({ tenantId: 1, recipient: 1, status: 1 });
notificationSchema.index({ tenantId: 1, type: 1 });
notificationSchema.index({ tenantId: 1, priority: 1 });
notificationSchema.index({ tenantId: 1, category: 1 });
notificationSchema.index({ tenantId: 1, 'channels.status': 1 });
notificationSchema.index({ tenantId: 1, expiresAt: 1 }, { expireAfterSeconds: 0 });
notificationSchema.index({ tenantId: 1, createdAt: -1 });

// Virtual for age
notificationSchema.virtual('age').get(function() {
  return Date.now() - this.createdAt;
});

// Virtual for isExpired
notificationSchema.virtual('isExpired').get(function() {
  return this.expiresAt < new Date();
});

// Instance methods
notificationSchema.methods = {
  // Mark as read
  markAsRead: function() {
    this.status = 'read';
    return this.save();
  },

  // Mark as archived
  archive: function() {
    this.status = 'archived';
    return this.save();
  },

  // Add channel delivery
  addChannelDelivery: function(channelType, status, recipient, error = null) {
    const channel = this.channels.find(c => c.type === channelType);
    if (channel) {
      channel.status = status;
      channel.recipient = recipient;
      if (status === 'sent') channel.sentAt = new Date();
      if (status === 'delivered') channel.deliveredAt = new Date();
      if (error) channel.error = error;
    } else {
      this.channels.push({
        type: channelType,
        status,
        recipient,
        sentAt: status === 'sent' ? new Date() : undefined,
        deliveredAt: status === 'delivered' ? new Date() : undefined,
        error
      });
    }
    return this.save();
  },

  // Add action
  addAction: function(actionData) {
    this.actions.push(actionData);
    return this.save();
  },

  // Get delivery status
  getDeliveryStatus: function() {
    const status = {
      total: this.channels.length,
      sent: 0,
      delivered: 0,
      failed: 0,
      pending: 0
    };

    this.channels.forEach(channel => {
      status[channel.status]++;
    });

    return status;
  },

  // Check if delivered via channel
  isDeliveredVia: function(channelType) {
    const channel = this.channels.find(c => c.type === channelType);
    return channel && channel.status === 'delivered';
  },

  // Get public notification data
  toPublicJSON: function() {
    return {
      id: this._id,
      type: this.type,
      title: this.title,
      message: this.message,
      priority: this.priority,
      category: this.category,
      status: this.status,
      createdAt: this.createdAt,
      actions: this.actions,
      deliveryStatus: this.getDeliveryStatus(),
      metadata: this.metadata
    };
  }
};

// Static methods
notificationSchema.statics = {
  // Get notifications for user within tenant
  getForUser: function(userId, tenantId, status = null, limit = 50, skip = 0) {
    const query = { tenantId, recipient: userId };
    if (status) {
      query.status = status;
    }

    return this.find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);
  },

  // Get unread notifications for user within tenant
  getUnreadForUser: function(userId, tenantId, limit = 50) {
    return this.find({
      tenantId,
      recipient: userId,
      status: 'unread'
    })
    .sort({ priority: -1, createdAt: -1 })
    .limit(limit);
  },

  // Get notifications by type within tenant
  getByType: function(type, tenantId, limit = 100) {
    return this.find({ tenantId, type })
      .sort({ createdAt: -1 })
      .limit(limit);
  },

  // Get notifications by priority within tenant
  getByPriority: function(priority, tenantId, limit = 100) {
    return this.find({ tenantId, priority })
      .sort({ createdAt: -1 })
      .limit(limit);
  },

  // Mark all as read for user within tenant
  markAllAsReadForUser: function(userId, tenantId) {
    return this.updateMany(
      { tenantId, recipient: userId, status: 'unread' },
      { status: 'read' }
    );
  },

  // Get notification statistics for user within tenant
  getStatsForUser: function(userId, tenantId) {
    return this.aggregate([
      { $match: { tenantId, recipient: mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);
  },

  // Get notifications by date range within tenant
  getByDateRange: function(startDate, endDate, tenantId, type = null) {
    const query = {
      tenantId,
      createdAt: {
        $gte: startDate,
        $lte: endDate
      }
    };

    if (type) {
      query.type = type;
    }

    return this.find(query).sort({ createdAt: -1 });
  },

  // Clean expired notifications within tenant
  cleanExpired: function(tenantId) {
    return this.deleteMany({
      tenantId,
      expiresAt: { $lt: new Date() }
    });
  },

  // Send bulk notifications within tenant
  sendBulk: function(notifications, tenantId) {
    const notificationsWithTenant = notifications.map(notification => ({
      ...notification,
      tenantId
    }));
    return this.insertMany(notificationsWithTenant);
  },

  // Get notifications by tenant
  getByTenant: function(tenantId, limit = 100, skip = 0) {
    return this.find({ tenantId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);
  }
};

export default mongoose.model('Notification', notificationSchema);
