/**
 * PARTNER MODEL
 * Database model for partner coordination in OWLBAN GROUP systems
 */

import mongoose from 'mongoose';

const PartnerSchema = new mongoose.Schema(
  {
    partnerId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    companyName: {
      type: String,
      required: true,
      trim: true,
    },
    contactPerson: {
      firstName: String,
      lastName: String,
      email: { type: String, required: true, lowercase: true },
      phone: String,
    },
    businessInfo: {
      industry: String,
      registrationNumber: String,
      taxId: String,
      address: String,
      country: { type: String, default: 'Haiti' },
    },
    status: {
      type: String,
      enum: ['pending', 'active', 'suspended', 'terminated'],
      default: 'pending',
    },
    performance: {
      rating: { type: Number, min: 0, max: 5, default: 0 },
      projectsCompleted: { type: Number, default: 0 },
      onTimeDelivery: { type: Number, default: 0 },
      totalRevenue: { type: mongoose.Decimal128, default: 0 },
    },
    projects: [
      {
        projectId: String,
        name: String,
        status: String,
        assignedDate: Date,
        deadline: Date,
        value: mongoose.Decimal128,
      },
    ],
    communications: [
      {
        type: String, // email/call/meeting
        date: Date,
        summary: String,
        sentBy: String,
      },
    ],
    onboarding: {
      completed: { type: Boolean, default: false },
      date: Date,
      documents: [String],
    },
    metadata: mongoose.Schema.Types.Mixed,
    audit: {
      createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      activatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    },
  },
  { timestamps: true }
);

PartnerSchema.index({ status: 1 });
PartnerSchema.index({ 'performance.rating': 1 });
PartnerSchema.index({ 'contactPerson.email': 1 });

PartnerSchema.statics.generatePartnerId = async function () {
  let id;
  do {
    id =
      'PARTNER-' +
      Date.now() +
      '-' +
      Math.random().toString(36).substr(2, 6).toUpperCase();
  } while (await this.findOne({ partnerId: id }));
  return id;
};

PartnerSchema.pre('save', async function (next) {
  if (!this.partnerId)
    this.partnerId = await this.constructor.generatePartnerId();
  next();
});

PartnerSchema.methods.activate = function (userId) {
  this.status = 'active';
  this.onboarding.completed = true;
  this.onboarding.date = new Date();
  this.audit.activatedBy = userId;
  return this.save();
};

PartnerSchema.methods.addProject = function (projectData) {
  this.projects.push({ ...projectData, projectId: 'PROJ-' + Date.now() });
  return this.save();
};

export default mongoose.model('Partner', PartnerSchema);
