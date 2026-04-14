/**
 * Education Model - Heaven on Earth Mandatory Education System
 * OSCAR BROOME REVENUE - OWLBAN GROUP
 */

const mongoose = require('mongoose');

const educationSchema = new mongoose.Schema(
  {
    citizenId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Citizen',
      required: true,
    },
    curriculum: {
      type: String,
      enum: ['military', 'law', 'technology', 'agriculture'],
      required: true,
    },
    durationMonths: {
      type: Number,
      required: true,
      min: 4,
      max: 6,
    },
    startDate: {
      type: Date,
      default: Date.now,
    },
    completionDate: Date,
    status: {
      type: String,
      enum: ['enrolled', 'in-progress', 'completed', 'suspended'],
      default: 'enrolled',
    },
    progress: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    complianceStatus: {
      type: String,
      enum: ['compliant', 'warning', 'non-compliant'],
      default: 'compliant',
    },
    ubiImpact: {
      paymentSuspended: { type: Boolean, default: false },
      suspensionDate: Date,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('Education', educationSchema);
