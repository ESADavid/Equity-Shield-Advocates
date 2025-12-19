import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const userSchema = new mongoose.Schema(
  {
    tenantId: {
      type: String,
      required: true,
      index: true,
    },
    username: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      maxlength: 50,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        'Please enter a valid email',
      ],
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    role: {
      type: String,
      enum: ['admin', 'manager', 'user'],
      default: 'user',
    },
    firstName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 50,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 50,
    },
    department: {
      type: String,
      trim: true,
      maxlength: 100,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastLogin: {
      type: Date,
    },
    loginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
    },
    permissions: [
      {
        type: String,
        enum: [
          'read_dashboard',
          'manage_transactions',
          'manage_users',
          'view_reports',
          'manage_blockchain',
          'control_websites',
          'manage_banking',
          'system_admin',
        ],
      },
    ],
    profile: {
      avatar: String,
      phone: String,
      timezone: {
        type: String,
        default: 'America/New_York',
      },
      language: {
        type: String,
        default: 'en',
      },
    },
    security: {
      twoFactorEnabled: {
        type: Boolean,
        default: false,
      },
      twoFactorSecret: String,
      passwordResetToken: String,
      passwordResetExpires: Date,
    },
  },
  {
    timestamps: true,
  }
);

// Virtual for full name
userSchema.virtual('fullName').get(function () {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account lock
userSchema.virtual('isLocked').get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Index for performance
userSchema.index({ tenantId: 1, email: 1 }, { unique: true });
userSchema.index({ tenantId: 1, username: 1 }, { unique: true });
userSchema.index({ tenantId: 1, role: 1 });
userSchema.index({ tenantId: 1, isActive: 1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Instance methods
userSchema.methods = {
  // Compare password
  comparePassword: async function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
  },

  // Increment login attempts
  incLoginAttempts: function () {
    if (this.lockUntil && this.lockUntil < Date.now()) {
      return this.updateOne({
        $unset: { lockUntil: 1 },
        $set: { loginAttempts: 1 },
      });
    }

    const updates = { $inc: { loginAttempts: 1 } };
    if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
      updates.$set = {
        lockUntil: Date.now() + 2 * 60 * 60 * 1000, // 2 hours
      };
    }
    return this.updateOne(updates);
  },

  // Reset login attempts
  resetLoginAttempts: function () {
    return this.updateOne({
      $unset: { loginAttempts: 1, lockUntil: 1 },
      $set: { lastLogin: new Date() },
    });
  },

  // Check permissions
  hasPermission: function (permission) {
    if (this.role === 'admin') return true;
    return this.permissions.includes(permission);
  },

  // Generate auth token
  generateAuthToken: function () {
    const token = jwt.sign(
      {
        _id: this._id,
        username: this.username,
        role: this.role,
        permissions: this.permissions,
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    return token;
  },

  // Get user info (without sensitive data)
  toPublicJSON: function () {
    return {
      _id: this._id,
      username: this.username,
      email: this.email,
      firstName: this.firstName,
      lastName: this.lastName,
      fullName: this.fullName,
      role: this.role,
      department: this.department,
      profile: this.profile,
      lastLogin: this.lastLogin,
      isActive: this.isActive,
    };
  },
};

// Static methods
userSchema.statics = {
  // Find user for authentication within tenant
  findForAuth: function (username, tenantId) {
    return this.findOne({
      tenantId,
      $or: [{ username }, { email: username }],
      isActive: true,
    });
  },

  // Get users by role within tenant
  getByRole: function (role, tenantId) {
    return this.find({ tenantId, role, isActive: true });
  },

  // Get active users within tenant
  getActiveUsers: function (tenantId) {
    return this.find({ tenantId, isActive: true });
  },

  // Get users by tenant
  getByTenant: function (tenantId) {
    return this.find({ tenantId });
  },

  // Check if username/email is available within tenant
  isAvailable: function (usernameOrEmail, tenantId) {
    return this.findOne({
      tenantId,
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
    }).then((user) => !user);
  },
};

export default mongoose.model('User', userSchema);
