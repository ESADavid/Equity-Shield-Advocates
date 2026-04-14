/**
 * PMC OPERATION MODEL
 * Database model for PMC integration and operations
 */

import mongoose from 'mongoose';

const PMCOperationSchema = new mongoose.Schema(
  {
    operationId: {
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
      enum: ['training', 'deployment', 'logistics', 'coordination'],
    },
    status: {
      type: String,
      enum: ['planning', 'active', 'completed', 'cancelled'],
      default: 'planning',
    },
    description: String,
    objectives: [String],
    resources: {
      personnel: { type: Number, default: 0 },
      equipment: [String],
      budget: mongoose.Decimal128,
    },
    timeline: {
      startDate: Date,
      endDate: Date,
      milestones: [
        {
          name: String,
          date: Date,
          completed: Boolean,
        },
      ],
    },
    partners: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Partner' }],
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reports: [
      {
        type: { type: String, enum: ['daily', 'weekly', 'final'] },
        date: Date,
        content: String,
        fileId: String,
      },
    ],
    metadata: mongoose.Schema.Types.Mixed,
  },
  { timestamps: true }
);

PMCOperationSchema.index({ status: 1 });
PMCOperationSchema.index({ type: 1 });
PMCOperationSchema.index({ 'timeline.startDate': 1 });

PMCOperationSchema.statics.generateOperationId = async function () {
  let id;
  do {
    id =
      'PMC-OP-' +
      Date.now() +
      '-' +
      Math.random().toString(36).substr(2, 4).toUpperCase();
  } while (await this.findOne({ operationId: id }));
  return id;
};

PMCOperationSchema.pre('save', async function (next) {
  if (!this.operationId)
    this.operationId = await this.constructor.generateOperationId();
  next();
});

PMCOperationSchema.methods.updateStatus = function (status, userId) {
  this.status = status;
  this.assignedTo = userId;
  return this.save();
};

PMCOperationSchema.methods.allocateResources = function (resources) {
  this.resources = { ...this.resources, ...resources };
  return this.save();
};

PMCOperationSchema.methods.addReport = function (reportData) {
  this.reports.push(reportData);
  return this.save();
};

export default mongoose.model('PMCOperation', PMCOperationSchema);
