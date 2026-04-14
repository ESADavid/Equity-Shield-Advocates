/**
 * CITIZEN MODEL
 * Database model for citizen registry in the Universal Basic Income system
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import mongoose from 'mongoose';
import crypto from 'node:crypto';

const CitizenSchema = new mongoose.Schema(
  {
    // Unique Citizen Identifier
    citizenId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    // Personal Information
    personalInfo: {
      firstName: {
        type: String,
        required: true,
        trim: true,
      },
      lastName: {
        type: String,
        required: true,
        trim: true,
      },
      middleName: {
        type: String,
        trim: true,
      },
      dateOfBirth: {
        type: Date,
        required: true,
      },
      gender: {
        type: String,
        enum: ['male', 'female', 'other', 'prefer_not_to_say'],
        required: true,
      },
      nationalId: {
        type: String,
        required: true,
        unique: true,
      },
      biometricHash: {
        type: String,
        required: true,
        unique: true,
      },
      photograph: {
        type: String, // Base64 or URL
        required: false,
      },
    },

    // Contact Information
    contactInfo: {
      address: {
        street: String,
        city: String,
        department: String, // Haiti administrative division
        postalCode: String,
        country: {
          type: String,
          default: 'Haiti',
        },
        coordinates: {
          latitude: Number,
          longitude: Number,
        },
      },
      phone: {
        type: String,
        required: true,
      },
      alternatePhone: String,
      email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
      },
      emergencyContact: {
        name: String,
        relationship: String,
        phone: String,
      },
    },

    // Banking Information (Encrypted)
    bankingInfo: {
      accountNumber: {
        type: String,
        required: true,
        select: false,
      },
      routingNumber: {
        type: String,
        required: true,
        select: false,
      },
      iv: {
        type: String,
        select: false,
      },
      authTagAccount: {
        type: String,
        select: false,
      },
      authTagRouting: {
        type: String,
        select: false,
      },
      bankName: {
        type: String,
        required: true,
      },
      accountType: {
        type: String,
        enum: ['checking', 'savings'],
        default: 'checking',
      },
      swiftCode: String,
      verified: {
        type: Boolean,
        default: false,
      },
      verificationDate: Date,
    },

    // Universal Basic Income Status
    ubiStatus: {
      eligible: {
        type: Boolean,
        default: true,
      },
      enrollmentDate: {
        type: Date,
        default: Date.now,
      },
      monthlyAmount: {
        type: Number,
        default: 33000, // $33,000 per year = $2,750 per month
        required: true,
      },
      annualAmount: {
        type: Number,
        default: 33000,
        required: true,
      },
      lastPaymentDate: Date,
      nextPaymentDate: Date,
      totalReceived: {
        type: Number,
        default: 0,
      },
      paymentsCount: {
        type: Number,
        default: 0,
      },
      suspended: {
        type: Boolean,
        default: false,
      },
      suspensionReason: String,
      suspensionDate: Date,
      gracePeriodEnd: Date,
      paymentMethod: {
        type: String,
        enum: ['direct_deposit', 'mobile_money', 'check', 'cash'],
        default: 'direct_deposit',
      },
    },

    // Education Status - Mandatory for UBI eligibility
    educationStatus: {
      // Military Training (6 months)
      military: {
        enrolled: {
          type: Boolean,
          default: false,
        },
        enrollmentDate: Date,
        completed: {
          type: Boolean,
          default: false,
        },
        completionDate: Date,
        progress: {
          type: Number,
          default: 0,
          min: 0,
          max: 100,
        },
        certificationId: String,
        instructorId: String,
        facilityId: String,
        grade: String,
      },

      // Law Education (4 months)
      law: {
        enrolled: {
          type: Boolean,
          default: false,
        },
        enrollmentDate: Date,
        completed: {
          type: Boolean,
          default: false,
        },
        completionDate: Date,
        progress: {
          type: Number,
          default: 0,
          min: 0,
          max: 100,
        },
        certificationId: String,
        instructorId: String,
        facilityId: String,
        grade: String,
      },

      // Technology Training (6 months)
      tech: {
        enrolled: {
          type: Boolean,
          default: false,
        },
        enrollmentDate: Date,
        completed: {
          type: Boolean,
          default: false,
        },
        completionDate: Date,
        progress: {
          type: Number,
          default: 0,
          min: 0,
          max: 100,
        },
        certificationId: String,
        instructorId: String,
        facilityId: String,
        specialization: String, // AI, Web Dev, Systems, etc.
        grade: String,
      },

      // Agriculture Training (4 months)
      agriculture: {
        enrolled: {
          type: Boolean,
          default: false,
        },
        enrollmentDate: Date,
        completed: {
          type: Boolean,
          default: false,
        },
        completionDate: Date,
        progress: {
          type: Number,
          default: 0,
          min: 0,
          max: 100,
        },
        certificationId: String,
        instructorId: String,
        facilityId: String,
        specialization: String, // Sustainable farming, Hydroponics, etc.
        grade: String,
      },

      // Overall Education Progress
      overallProgress: {
        type: Number,
        default: 0,
        min: 0,
        max: 100,
      },
      totalMonthsCompleted: {
        type: Number,
        default: 0,
      },
      requiredMonths: {
        type: Number,
        default: 20, // 6 + 4 + 6 + 4
      },
      complianceStatus: {
        type: String,
        enum: [
          'compliant',
          'in_progress',
          'non_compliant',
          'grace_period',
          'exempt',
        ],
        default: 'in_progress',
      },
      complianceDeadline: Date,
      exemptionReason: String,
      exemptionApprovedBy: String,
    },

    // Personal Assets Array - Track companies, stocks, patents, cars owned by citizen
    assets: [
      {
        type: {
          type: String,
          enum: [
            'company',
            'stock',
            'patent',
            'car',
            'transaction',
            'education',
          ],
          required: true,
        },
        refId: {
          type: mongoose.Schema.Types.ObjectId,
          refPath: 'assets.type',
          required: true,
        },
        value: {
          type: Number,
          default: 0,
          min: 0,
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],

    // Employment Information
    employmentInfo: {
      employed: {
        type: Boolean,
        default: false,
      },
      employer: String,
      position: String,
      sector: {
        type: String,
        enum: [
          'military',
          'law',
          'technology',
          'agriculture',
          'government',
          'private',
          'self_employed',
          'other',
        ],
      },
      monthlyIncome: Number,
      employmentStartDate: Date,
    },

    // Family/Dependents
    dependents: [
      {
        name: String,
        relationship: String,
        dateOfBirth: Date,
        citizenId: String, // If they're also a citizen
        dependent: Boolean,
      },
    ],

    // Health Information
    healthInfo: {
      bloodType: String,
      allergies: [String],
      medicalConditions: [String],
      disabilities: [String],
      healthInsurance: {
        provider: String,
        policyNumber: String,
        expiryDate: Date,
      },
    },

    // Military Service (if applicable)
    militaryService: {
      active: {
        type: Boolean,
        default: false,
      },
      branch: {
        type: String,
        enum: ['navy', 'army', 'air_force', 'joint_force', 'private_military'],
      },
      rank: String,
      serviceNumber: String,
      enlistmentDate: Date,
      dischargeDate: Date,
      status: {
        type: String,
        enum: ['active', 'reserve', 'veteran', 'honorable_discharge', 'other'],
      },
    },

    // Compliance & Verification
    verification: {
      identityVerified: {
        type: Boolean,
        default: false,
      },
      identityVerifiedDate: Date,
      identityVerifiedBy: String,
      biometricVerified: {
        type: Boolean,
        default: false,
      },
      biometricVerifiedDate: Date,
      addressVerified: {
        type: Boolean,
        default: false,
      },
      addressVerifiedDate: Date,
      bankingVerified: {
        type: Boolean,
        default: false,
      },
      bankingVerifiedDate: Date,
      backgroundCheckCompleted: {
        type: Boolean,
        default: false,
      },
      backgroundCheckDate: Date,
      backgroundCheckStatus: String,
    },

    // Blockchain Integration
    blockchain: {
      walletAddress: String,
      publicKey: String,
      transactionHashes: [String],
      lastBlockchainSync: Date,
    },

    // Notifications & Preferences
    preferences: {
      language: {
        type: String,
        enum: ['creole', 'french', 'english', 'spanish'],
        default: 'creole',
      },
      communicationMethod: {
        type: String,
        enum: ['email', 'sms', 'app', 'all'],
        default: 'all',
      },
      notificationsEnabled: {
        type: Boolean,
        default: true,
      },
      marketingOptIn: {
        type: Boolean,
        default: false,
      },
    },

    // System Metadata
    metadata: {
      registrationSource: {
        type: String,
        enum: [
          'online',
          'in_person',
          'mobile_app',
          'government_office',
          'community_center',
        ],
        default: 'government_office',
      },
      registeredBy: String, // User ID of registrar
      lastUpdatedBy: String,
      notes: [String],
      flags: [String], // For administrative purposes
      priority: {
        type: String,
        enum: ['normal', 'high', 'urgent'],
        default: 'normal',
      },
    },

    // Status
    status: {
      type: String,
      enum: ['active', 'inactive', 'suspended', 'deceased', 'relocated'],
      default: 'active',
    },

    // Audit Trail
    auditLog: [
      {
        action: String,
        performedBy: String,
        timestamp: {
          type: Date,
          default: Date.now,
        },
        details: mongoose.Schema.Types.Mixed,
        ipAddress: String,
      },
    ],
  },
  {
    timestamps: true,
    collection: 'citizens',
  }
);

// Indexes optimized (removed duplicate personalInfo.nationalId)
CitizenSchema.index({ 'contactInfo.email': 1 });
CitizenSchema.index({ 'ubiStatus.eligible': 1 });
CitizenSchema.index({ 'educationStatus.complianceStatus': 1 });
CitizenSchema.index({ status: 1 });
CitizenSchema.index({ createdAt: -1 });
CitizenSchema.index({ 'assets.refId': 1 }); // New assets index

// Virtual for full name
CitizenSchema.virtual('fullName').get(function () {
  return `${this.personalInfo.firstName} ${this.personalInfo.middleName || ''} ${this.personalInfo.lastName}`.trim();
});

// Virtual for age
CitizenSchema.virtual('age').get(function () {
  if (!this.personalInfo.dateOfBirth) return null;
  const today = new Date();
  const birthDate = new Date(this.personalInfo.dateOfBirth);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  if (
    monthDiff < 0 ||
    (monthDiff === 0 && today.getDate() < birthDate.getDate())
  ) {
    age--;
  }
  return age;
});

// Virtual for education completion percentage
CitizenSchema.virtual('educationCompletionPercentage').get(function () {
  let completed = 0;
  if (this.educationStatus.military.completed) completed += 25;
  if (this.educationStatus.law.completed) completed += 25;
  if (this.educationStatus.tech.completed) completed += 25;
  if (this.educationStatus.agriculture.completed) completed += 25;
  return completed;
});

// NEW Virtual for net worth from assets
CitizenSchema.virtual('netWorth').get(function () {
  return this.assets
    ? this.assets.reduce((sum, asset) => sum + (asset.value || 0), 0)
    : 0;
});

// Method to generate unique citizen ID
CitizenSchema.statics.generateCitizenId = async function () {
  let citizenId;
  let exists = true;

  while (exists) {
    // Format: HT-YYYY-XXXXXX (HT = Haiti, YYYY = Year, XXXXXX = Random)
    const year = new Date().getFullYear();
    const random = crypto.randomBytes(3).toString('hex').toUpperCase();
    citizenId = `HT-${year}-${random}`;

    exists = await this.findOne({ citizenId });
  }

  return citizenId;
};

// Method to encrypt sensitive data (AES-256-GCM)
CitizenSchema.methods.encryptBankingInfo = function (
  accountNumber,
  routingNumber
) {
  const algorithm = 'aes-256-gcm';
  const key =
    Buffer.from(process.env.ENCRYPTION_KEY || '', 'hex') ||
    crypto.randomBytes(32);
  const iv = crypto.randomBytes(12); // GCM uses 12-byte IV

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedAccount = cipher.update(accountNumber, 'utf8', 'hex');
  encryptedAccount += cipher.final('hex');
  const authTagAccount = cipher.getAuthTag().toString('hex');

  const cipherRouting = crypto.createCipheriv(algorithm, key, iv);
  let encryptedRouting = cipherRouting.update(routingNumber, 'utf8', 'hex');
  encryptedRouting += cipherRouting.final('hex');
  const authTagRouting = cipherRouting.getAuthTag().toString('hex');

  return {
    accountNumber: encryptedAccount,
    routingNumber: encryptedRouting,
    iv: iv.toString('hex'),
    authTagAccount: authTagAccount,
    authTagRouting: authTagRouting,
  };
};

// Method to decrypt banking info
CitizenSchema.methods.decryptBankingInfo = function () {
  const algorithm = 'aes-256-gcm';
  const key =
    Buffer.from(process.env.ENCRYPTION_KEY || '', 'hex') ||
    crypto.randomBytes(32);
  const iv = Buffer.from(this.bankingInfo.iv, 'hex');

  // Decrypt account
  const decipherAccount = crypto.createDecipheriv(algorithm, key, iv);
  decipherAccount.setAuthTag(
    Buffer.from(this.bankingInfo.authTagAccount, 'hex')
  );
  let decryptedAccount = decipherAccount.update(
    this.bankingInfo.accountNumber,
    'hex',
    'utf8'
  );
  decryptedAccount += decipherAccount.final('utf8');

  // Decrypt routing
  const decipherRouting = crypto.createDecipheriv(algorithm, key, iv);
  decipherRouting.setAuthTag(
    Buffer.from(this.bankingInfo.authTagRouting, 'hex')
  );
  let decryptedRouting = decipherRouting.update(
    this.bankingInfo.routingNumber,
    'hex',
    'utf8'
  );
  decryptedRouting += decipherRouting.final('utf8');

  return {
    accountNumber: decryptedAccount,
    routingNumber: decryptedRouting,
  };
};

// Method to check UBI eligibility
CitizenSchema.methods.checkUBIEligibility = function () {
  // Check if citizen is active
  if (this.status !== 'active') {
    return { eligible: false, reason: 'Citizen status is not active' };
  }

  // Check if already suspended
  if (this.ubiStatus.suspended) {
    return { eligible: false, reason: this.ubiStatus.suspensionReason };
  }

  // Check education compliance
  if (this.educationStatus.complianceStatus === 'non_compliant') {
    return { eligible: false, reason: 'Education requirements not met' };
  }

  // Check verification status
  if (
    !this.verification.identityVerified ||
    !this.verification.bankingVerified
  ) {
    return { eligible: false, reason: 'Verification incomplete' };
  }

  return { eligible: true, reason: 'All requirements met' };
};

// Method to calculate next payment date
CitizenSchema.methods.calculateNextPaymentDate = function () {
  const lastPayment = this.ubiStatus.lastPaymentDate || new Date();
  const nextPayment = new Date(lastPayment);
  nextPayment.setMonth(nextPayment.getMonth() + 1);
  return nextPayment;
};

// Method to update education progress
CitizenSchema.methods.updateEducationProgress = function () {
  const tracks = ['military', 'law', 'tech', 'agriculture'];
  let totalProgress = 0;
  let completedMonths = 0;

  tracks.forEach((track) => {
    totalProgress += this.educationStatus[track].progress || 0;
    if (this.educationStatus[track].completed) {
      const durations = { military: 6, law: 4, tech: 6, agriculture: 4 };
      completedMonths += durations[track];
    }
  });

  this.educationStatus.overallProgress = totalProgress / 4;
  this.educationStatus.totalMonthsCompleted = completedMonths;

  // Update compliance status
  if (completedMonths >= 20) {
    this.educationStatus.complianceStatus = 'compliant';
  } else if (completedMonths > 0) {
    this.educationStatus.complianceStatus = 'in_progress';
  }

  return this.educationStatus;
};

// Pre-save middleware
CitizenSchema.pre('save', async function (next) {
  // Generate citizen ID if not exists
  if (!this.citizenId) {
    this.citizenId = await this.constructor.generateCitizenId();
  }

  // Update education progress
  this.updateEducationProgress();

  // Calculate next payment date
  if (this.ubiStatus.eligible && !this.ubiStatus.suspended) {
    this.ubiStatus.nextPaymentDate = this.calculateNextPaymentDate();
  }

  next();
});

// Export model
const Citizen = mongoose.model('Citizen', CitizenSchema);

export default Citizen;
