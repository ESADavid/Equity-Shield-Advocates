/**
 * PARTNER MODEL
 * Data model for partner organizations
 * Part of Phase 2: Heaven on Earth Implementation
 */

import mongoose from 'mongoose';

const partnerSchema = new mongoose.Schema(
  {
    // Basic Information
    partnerId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      required: true,
      enum: [
        'pmc', // Private Military Contractor
        'government',
        'ngo',
        'corporate',
        'educational',
        'healthcare',
        'technology',
        'financial',
        'other',
      ],
    },
    status: {
      type: String,
      required: true,
      enum: ['active', 'pending', 'suspended', 'terminated'],
      default: 'pending',
    },

    // Contact Information
    contact: {
      primaryContact: {
        name: String,
        title: String,
        email: String,
        phone: String,
      },
      address: {
        street: String,
        city: String,
        state: String,
        country: String,
        postalCode: String,
      },
      website: String,
      socialMedia: {
        linkedin: String,
        twitter: String,
        facebook: String,
      },
    },

    // Contract Details
    contract: {
      contractId: String,
      startDate: Date,
      endDate: Date,
      duration: Number, // months
      value: Number,
      currency: {
        type: String,
        default: 'USD',
      },
      terms: String,
      renewalOption: Boolean,
      autoRenewal: Boolean,
      paymentSchedule: {
        type: String,
        enum: ['monthly', 'quarterly', 'annually', 'milestone-based'],
      },
      paymentTerms: String,
    },

    // Services & Capabilities
    services: [
      {
        serviceId: String,
        name: String,
        description: String,
        category: String,
        pricing: {
          model: String, // hourly, fixed, subscription
          rate: Number,
          currency: String,
        },
      },
    ],

    capabilities: {
      personnel: Number,
      equipment: [String],
      specializations: [String],
      certifications: [String],
      languages: [String],
      geographicCoverage: [String],
    },

    // Performance Metrics
    performance: {
      rating: {
        type: Number,
        min: 0,
        max: 5,
        default: 0,
      },
      projectsCompleted: {
        type: Number,
        default: 0,
      },
      projectsActive: {
        type: Number,
        default: 0,
      },
      successRate: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
      },
      onTimeDelivery: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
      },
      qualityScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
      },
      customerSatisfaction: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
      },
      incidentRate: {
        type: Number,
        default: 0,
      },
      responseTime: Number, // hours
      lastReview: Date,
      reviews: [
        {
          reviewId: String,
          date: Date,
          reviewer: String,
          rating: Number,
          comments: String,
          category: String,
        },
      ],
    },

    // Financial Information
    financial: {
      totalRevenue: {
        type: Number,
        default: 0,
      },
      totalPaid: {
        type: Number,
        default: 0,
      },
      outstandingBalance: {
        type: Number,
        default: 0,
      },
      paymentHistory: [
        {
          paymentId: String,
          date: Date,
          amount: Number,
          currency: String,
          method: String,
          status: String,
          reference: String,
        },
      ],
      invoices: [
        {
          invoiceId: String,
          date: Date,
          dueDate: Date,
          amount: Number,
          status: String,
          items: [mongoose.Schema.Types.Mixed],
        },
      ],
    },

    // Integration Details
    integration: {
      apiKey: String,
      apiSecret: String,
      webhookUrl: String,
      integrationStatus: {
        type: String,
        enum: ['not-started', 'in-progress', 'completed', 'failed'],
        default: 'not-started',
      },
      lastSync: Date,
      syncFrequency: String, // hourly, daily, weekly
      dataMapping: mongoose.Schema.Types.Mixed,
      customFields: mongoose.Schema.Types.Mixed,
    },

    // Compliance & Security
    compliance: {
      backgroundCheckCompleted: Boolean,
      backgroundCheckDate: Date,
      securityClearance: String,
      insuranceCoverage: {
        liability: Number,
        workers: Number,
        property: Number,
        expiryDate: Date,
      },
      licenses: [
        {
          licenseId: String,
          type: String,
          issuedBy: String,
          issuedDate: Date,
          expiryDate: Date,
          status: String,
        },
      ],
      certifications: [
        {
          certificationId: String,
          name: String,
          issuedBy: String,
          issuedDate: Date,
          expiryDate: Date,
          status: String,
        },
      ],
      auditHistory: [
        {
          auditId: String,
          date: Date,
          auditor: String,
          type: String,
          result: String,
          findings: String,
          recommendations: String,
        },
      ],
    },

    // Communication & Collaboration
    communication: {
      preferredChannel: {
        type: String,
        enum: ['email', 'phone', 'video', 'in-person', 'portal'],
      },
      timezone: String,
      language: String,
      meetingSchedule: String,
      escalationContacts: [
        {
          name: String,
          role: String,
          email: String,
          phone: String,
          level: Number,
        },
      ],
      communicationLog: [
        {
          date: Date,
          type: String,
          subject: String,
          participants: [String],
          summary: String,
          followUp: String,
        },
      ],
    },

    // Projects & Deployments
    projects: [
      {
        projectId: String,
        name: String,
        description: String,
        status: String,
        startDate: Date,
        endDate: Date,
        budget: Number,
        personnel: Number,
        location: String,
        milestones: [mongoose.Schema.Types.Mixed],
      },
    ],

    deployments: [
      {
        deploymentId: String,
        location: String,
        personnel: Number,
        equipment: [String],
        startDate: Date,
        endDate: Date,
        status: String,
        purpose: String,
      },
    ],

    // Documents & Files
    documents: [
      {
        documentId: String,
        name: String,
        type: String,
        category: String,
        uploadDate: Date,
        uploadedBy: String,
        fileUrl: String,
        fileSize: Number,
        expiryDate: Date,
        status: String,
      },
    ],

    // Notes & History
    notes: [
      {
        noteId: String,
        date: Date,
        author: String,
        category: String,
        content: String,
        priority: String,
        tags: [String],
      },
    ],

    activityLog: [
      {
        timestamp: Date,
        action: String,
        performedBy: String,
        details: mongoose.Schema.Types.Mixed,
        ipAddress: String,
      },
    ],

    // Metadata
    createdBy: {
      type: String,
      required: true,
    },
    lastModifiedBy: String,
    tags: [String],
    customData: mongoose.Schema.Types.Mixed,
  },
  {
    timestamps: true,
    collection: 'partners',
  }
);

// Indexes for performance
partnerSchema.index({ name: 1 });
partnerSchema.index({ type: 1 });
partnerSchema.index({ status: 1 });
partnerSchema.index({ 'contract.startDate': 1 });
partnerSchema.index({ 'contract.endDate': 1 });
partnerSchema.index({ 'performance.rating': -1 });
partnerSchema.index({ createdAt: -1 });

// Virtual for contract status
partnerSchema.virtual('contractStatus').get(function () {
  if (!this.contract.endDate) return 'active';

  const now = new Date();
  const endDate = new Date(this.contract.endDate);

  if (endDate < now) return 'expired';

  const daysUntilExpiry = Math.ceil((endDate - now) / (1000 * 60 * 60 * 24));
  if (daysUntilExpiry <= 30) return 'expiring-soon';

  return 'active';
});

// Method to calculate overall health score
partnerSchema.methods.calculateHealthScore = function () {
  const weights = {
    rating: 0.25,
    successRate: 0.2,
    onTimeDelivery: 0.2,
    qualityScore: 0.2,
    customerSatisfaction: 0.15,
  };

  const score =
    (this.performance.rating / 5) * 100 * weights.rating +
    this.performance.successRate * weights.successRate +
    this.performance.onTimeDelivery * weights.onTimeDelivery +
    this.performance.qualityScore * weights.qualityScore +
    this.performance.customerSatisfaction * weights.customerSatisfaction;

  return Math.round(score);
};

// Method to check if partner needs renewal
partnerSchema.methods.needsRenewal = function () {
  if (!this.contract.endDate) return false;

  const now = new Date();
  const endDate = new Date(this.contract.endDate);
  const daysUntilExpiry = Math.ceil((endDate - now) / (1000 * 60 * 60 * 24));

  return daysUntilExpiry <= 60; // 60 days before expiry
};

// Static method to get partners by type
partnerSchema.statics.getByType = function (type) {
  return this.find({ type: type, status: 'active' });
};

// Static method to get top performers
partnerSchema.statics.getTopPerformers = function (limit = 10) {
  return this.find({ status: 'active' })
    .sort({ 'performance.rating': -1 })
    .limit(limit);
};

const Partner = mongoose.model('Partner', partnerSchema);

export default Partner;
