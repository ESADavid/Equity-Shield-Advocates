import mongoose from 'mongoose';

const analyticsSchema = new mongoose.Schema(
  {
    tenantId: {
      type: String,
      required: true,
      index: true,
    },
    type: {
      type: String,
      required: true,
      enum: [
        'transaction_volume',
        'user_activity',
        'revenue_trends',
        'risk_analysis',
        'performance_metrics',
        'blockchain_stats',
        'ai_predictions',
        'custom',
      ],
    },
    name: {
      type: String,
      required: true,
      maxlength: 200,
    },
    description: String,
    data: {
      type: mongoose.Schema.Types.Mixed,
      required: true,
    },
    metadata: {
      dateRange: {
        start: { type: Date, required: true },
        end: { type: Date, required: true },
      },
      granularity: {
        type: String,
        enum: ['hour', 'day', 'week', 'month', 'quarter', 'year'],
        default: 'day',
      },
      categories: [String],
      filters: mongoose.Schema.Types.Mixed,
      dataPoints: { type: Number, default: 0 },
    },
    insights: [
      {
        type: {
          type: String,
          enum: ['trend', 'anomaly', 'prediction', 'recommendation', 'alert'],
        },
        title: String,
        description: String,
        severity: {
          type: String,
          enum: ['low', 'medium', 'high', 'critical'],
          default: 'low',
        },
        confidence: {
          type: Number,
          min: 0,
          max: 1,
        },
        data: mongoose.Schema.Types.Mixed,
        timestamp: { type: Date, default: Date.now },
      },
    ],
    predictions: [
      {
        metric: String,
        predictedValue: mongoose.Schema.Types.Mixed,
        confidence: { type: Number, min: 0, max: 1 },
        timeHorizon: {
          type: String,
          enum: ['1day', '1week', '1month', '3months', '6months', '1year'],
        },
        basedOn: mongoose.Schema.Types.Mixed,
        timestamp: { type: Date, default: Date.now },
      },
    ],
    performance: {
      generationTime: Number, // in milliseconds
      dataSize: Number, // in bytes
      cacheHit: { type: Boolean, default: false },
      errorRate: { type: Number, default: 0 },
    },
    access: {
      createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
      },
      sharedWith: [
        {
          userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
          },
          permissions: [
            {
              type: String,
              enum: ['view', 'edit', 'delete', 'share'],
            },
          ],
        },
      ],
      isPublic: { type: Boolean, default: false },
    },
    status: {
      type: String,
      enum: ['processing', 'completed', 'failed', 'expired'],
      default: 'processing',
    },
    expiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
analyticsSchema.index({ tenantId: 1, type: 1 });
analyticsSchema.index({
  tenantId: 1,
  'metadata.dateRange.start': 1,
  'metadata.dateRange.end': 1,
});
analyticsSchema.index({ tenantId: 1, 'access.createdBy': 1 });
analyticsSchema.index({ tenantId: 1, expiresAt: 1 }, { expireAfterSeconds: 0 });
analyticsSchema.index({ tenantId: 1, status: 1 });
analyticsSchema.index({ tenantId: 1, 'insights.severity': 1 });

// Virtual for age
analyticsSchema.virtual('age').get(function () {
  return Date.now() - this.createdAt;
});

// Virtual for isExpired
analyticsSchema.virtual('isExpired').get(function () {
  return this.expiresAt < new Date();
});

// Instance methods
analyticsSchema.methods = {
  // Add insight
  addInsight: function (insightData) {
    this.insights.push({
      ...insightData,
      timestamp: new Date(),
    });
    return this.save();
  },

  // Add prediction
  addPrediction: function (predictionData) {
    this.predictions.push({
      ...predictionData,
      timestamp: new Date(),
    });
    return this.save();
  },

  // Mark as completed
  markCompleted: function (performanceData = {}) {
    this.status = 'completed';
    this.performance = { ...this.performance, ...performanceData };
    return this.save();
  },

  // Mark as failed
  markFailed: function (error) {
    this.status = 'failed';
    this.performance.errorRate = 1;
    this.metadata.error = error;
    return this.save();
  },

  // Share with user
  shareWithUser: function (userId, permissions = ['view']) {
    const existingShare = this.access.sharedWith.find(
      (share) => share.userId.toString() === userId.toString()
    );

    if (existingShare) {
      existingShare.permissions = permissions;
    } else {
      this.access.sharedWith.push({
        userId,
        permissions,
      });
    }
    return this.save();
  },

  // Check user access
  canUserAccess: function (userId, permission = 'view') {
    // Creator has all permissions
    if (this.access.createdBy.toString() === userId.toString()) {
      return true;
    }

    // Check shared access
    const share = this.access.sharedWith.find(
      (s) => s.userId.toString() === userId.toString()
    );

    if (share && share.permissions.includes(permission)) {
      return true;
    }

    // Check public access
    if (this.access.isPublic && permission === 'view') {
      return true;
    }

    return false;
  },

  // Get summary
  getSummary: function () {
    return {
      id: this._id,
      type: this.type,
      name: this.name,
      description: this.description,
      status: this.status,
      dataPoints: this.metadata.dataPoints,
      insightsCount: this.insights.length,
      predictionsCount: this.predictions.length,
      createdAt: this.createdAt,
      expiresAt: this.expiresAt,
      isExpired: this.isExpired,
    };
  },
};

// Static methods
analyticsSchema.statics = {
  // Get analytics by type within tenant
  getByType: function (type, tenantId, limit = 50) {
    return this.find({ tenantId, type, status: 'completed' })
      .sort({ createdAt: -1 })
      .limit(limit);
  },

  // Get analytics by user within tenant
  getByUser: function (userId, tenantId, limit = 50) {
    return this.find({
      tenantId,
      $or: [
        { 'access.createdBy': userId },
        { 'access.sharedWith.userId': userId },
        { 'access.isPublic': true },
      ],
      status: 'completed',
    })
      .sort({ createdAt: -1 })
      .limit(limit);
  },

  // Get analytics by date range within tenant
  getByDateRange: function (startDate, endDate, tenantId, type = null) {
    const query = {
      tenantId,
      'metadata.dateRange.start': { $gte: startDate },
      'metadata.dateRange.end': { $lte: endDate },
      status: 'completed',
    };

    if (type) {
      query.type = type;
    }

    return this.find(query).sort({ createdAt: -1 });
  },

  // Get insights by severity within tenant
  getInsightsBySeverity: function (severity, tenantId, limit = 100) {
    return this.find({
      tenantId,
      'insights.severity': severity,
      status: 'completed',
    })
      .sort({ 'insights.timestamp': -1 })
      .limit(limit);
  },

  // Clean expired analytics within tenant
  cleanExpired: function (tenantId) {
    return this.deleteMany({
      tenantId,
      expiresAt: { $lt: new Date() },
    });
  },

  // Get analytics statistics within tenant
  getStats: function (tenantId) {
    return this.aggregate([
      { $match: { tenantId } },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 },
          avgGenerationTime: { $avg: '$performance.generationTime' },
          totalDataPoints: { $sum: '$metadata.dataPoints' },
          avgInsights: { $avg: { $size: '$insights' } },
        },
      },
    ]);
  },

  // Get analytics by tenant
  getByTenant: function (tenantId, limit = 100, skip = 0) {
    return this.find({ tenantId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);
  },
};

export default mongoose.model('Analytics', analyticsSchema);
