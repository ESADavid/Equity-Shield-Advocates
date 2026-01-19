import mongoose from 'mongoose';

const itemSchema = new mongoose.Schema(
  {
    tenantId: {
      type: String,
      required: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    itemId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    accessToken: {
      type: String,
      required: true,
    },
    institutionId: {
      type: String,
      required: true,
    },
    institutionName: {
      type: String,
      required: true,
    },
    // Auth-specific fields
    consentExpiration: {
      type: Date,
      index: true,
    },
    tan: {
      type: String, // Tokenized Account Number
    },
    tanExpiration: {
      type: Date,
      index: true,
    },
    isTokenizedAccountNumber: {
      type: Boolean,
      default: false,
    },
    persistentAccountId: {
      type: String,
    },
    // Status tracking
    status: {
      type: String,
      enum: ['active', 'inactive', 'error', 'consent_expired'],
      default: 'active',
    },
    errorCode: {
      type: String,
    },
    errorMessage: {
      type: String,
    },
    // Webhook tracking
    lastWebhookReceived: {
      type: Date,
    },
    webhookEvents: [{
      eventType: String,
      timestamp: Date,
      data: mongoose.Schema.Types.Mixed,
    }],
  },
  {
    timestamps: true,
  }
);

// Indexes for performance
itemSchema.index({ tenantId: 1, userId: 1 });
itemSchema.index({ tenantId: 1, status: 1 });
itemSchema.index({ consentExpiration: 1 });
itemSchema.index({ tanExpiration: 1 });

// Virtual for consent status
itemSchema.virtual('isConsentExpired').get(function () {
  return this.consentExpiration && this.consentExpiration < new Date();
});

// Virtual for TAN status
itemSchema.virtual('isTanExpired').get(function () {
  return this.tanExpiration && this.tanExpiration < new Date();
});

// Instance methods
itemSchema.methods = {
  // Update consent expiration
  updateConsentExpiration: function (expirationDate) {
    this.consentExpiration = expirationDate;
    if (this.isConsentExpired) {
      this.status = 'consent_expired';
    } else {
      this.status = 'active';
    }
    return this.save();
  },

  // Update TAN
  updateTan: function (tan, expirationDate) {
    this.tan = tan;
    this.tanExpiration = expirationDate;
    this.isTokenizedAccountNumber = true;
    return this.save();
  },

  // Check if item needs re-auth
  needsReauth: function () {
    return this.status === 'consent_expired' || this.isConsentExpired;
  },

  // Add webhook event
  addWebhookEvent: function (eventType, data = {}) {
    this.webhookEvents.push({
      eventType,
      timestamp: new Date(),
      data,
    });
    this.lastWebhookReceived = new Date();
    return this.save();
  },

  // Get public item info (without sensitive data)
  toPublicJSON: function () {
    return {
      _id: this._id,
      itemId: this.itemId,
      institutionId: this.institutionId,
      institutionName: this.institutionName,
      status: this.status,
      consentExpiration: this.consentExpiration,
      isConsentExpired: this.isConsentExpired,
      isTokenizedAccountNumber: this.isTokenizedAccountNumber,
      tanExpiration: this.tanExpiration,
      isTanExpired: this.isTanExpired,
      lastWebhookReceived: this.lastWebhookReceived,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  },
};

// Static methods
itemSchema.statics = {
  // Find items by user within tenant
  findByUser: function (userId, tenantId) {
    return this.find({ userId, tenantId });
  },

  // Find items needing consent renewal
  findItemsNeedingConsentRenewal: function (tenantId, daysAhead = 7) {
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + daysAhead);
    return this.find({
      tenantId,
      consentExpiration: { $lte: futureDate },
      status: { $ne: 'consent_expired' },
    });
  },

  // Find items with expired TAN
  findItemsWithExpiredTan: function (tenantId) {
    return this.find({
      tenantId,
      tanExpiration: { $lt: new Date() },
      isTokenizedAccountNumber: true,
    });
  },

  // Find items by institution
  findByInstitution: function (institutionId, tenantId) {
    return this.find({ institutionId, tenantId });
  },

  // Get item by itemId
  findByItemId: function (itemId) {
    return this.findOne({ itemId });
  },
};

export default mongoose.model('Item', itemSchema);
