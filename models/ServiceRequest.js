import mongoose from 'mongoose';

const ServiceRequestSchema = new mongoose.Schema(
  {
    requestId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    citizenId: {
      type: String,
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: [
        'ubi_assistance',
        'education_support',
        'health',
        'employment',
        'housing',
        'other',
      ],
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      enum: ['open', 'in_progress', 'resolved', 'closed'],
      default: 'open',
    },
    priority: {
      type: String,
      enum: ['low', 'medium', 'high', 'urgent'],
      default: 'medium',
    },
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    updates: [
      {
        message: String,
        by: String,
        timestamp: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

ServiceRequestSchema.statics.generateRequestId = async function () {
  let id;
  do {
    id =
      'REQ-' +
      Date.now() +
      '-' +
      Math.random().toString(36).slice(2, 8).toUpperCase();
  } while (await this.findOne({ requestId: id }));
  return id;
};

ServiceRequestSchema.pre('save', async function (next) {
  if (!this.requestId)
    this.requestId = await this.constructor.generateRequestId();
  next();
});

export default mongoose.model('ServiceRequest', ServiceRequestSchema);
