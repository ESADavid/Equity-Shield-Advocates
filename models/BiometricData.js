import mongoose from 'mongoose';
import crypto from 'crypto';

const biometricDataSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    tenantId: {
      type: String,
      required: true,
      index: true,
    },
    
    // Biometric Types
    fingerprint: {
      enabled: { type: Boolean, default: false },
      templates: [{
        finger: {
          type: String,
          enum: ['thumb', 'index', 'middle', 'ring', 'pinky'],
        },
        hand: {
          type: String,
          enum: ['left', 'right'],
        },
        hash: String,  // Encrypted biometric hash
        quality: Number,  // Quality score 0-100
        enrolledAt: Date,
        lastUsed: Date,
      }],
      algorithm: {
        type: String,
        default: 'SHA-512-HMAC',
      },
    },
    
    facial: {
      enabled: { type: Boolean, default: false },
      templates: [{
        hash: String,  // Encrypted facial feature hash
        quality: Number,
        enrolledAt: Date,
        lastUsed: Date,
        metadata: {
          captureDevice: String,
          lighting: String,
          angle: String,
        },
      }],
      algorithm: {
        type: String,
        default: 'CUSTOM-NEURAL-NET',
      },
    },
    
    voice: {
      enabled: { type: Boolean, default: false },
      templates: [{
        hash: String,  // Encrypted voice print hash
        quality: Number,
        enrolledAt: Date,
        lastUsed: Date,
        metadata: {
          sampleDuration: Number,
          frequency: String,
        },
      }],
      algorithm: {
        type: String,
        default: 'WAVEFORM-ANALYSIS',
      },
    },
    
    behavioral: {
      enabled: { type: Boolean, default: false },
      keystrokeDynamics: {
        pattern: String,  // Encrypted typing pattern
        accuracy: Number,
        sampleSize: Number,
      },
      mouseMovement: {
        pattern: String,  // Encrypted mouse signature
        accuracy: Number,
        sampleSize: Number,
      },
      navigationPattern: {
        pattern: String,  // Encrypted navigation habits
        accuracy: Number,
        sampleSize: Number,
      },
    },
    
    // Device Fingerprinting
    deviceFingerprints: [{
      deviceId: String,
      deviceType: String,
      browser: String,
      os: String,
      screenResolution: String,
      timezone: String,
      language: String,
      hash: String,  // Device fingerprint hash
      trusted: { type: Boolean, default: false },
      firstSeen: Date,
      lastSeen: Date,
    }],
    
    // Encryption & Security
    encryption: {
      algorithm: {
        type: String,
        default: 'AES-256-GCM',
      },
      keyVersion: {
        type: Number,
        default: 1,
      },
      salt: String,
      iv: String,
    },
    
    // Blockchain Integration
    blockchain: {
      enabled: { type: Boolean, default: true },
      ledgerId: String,
      lastBlockHash: String,
    },
    
    // Security Settings
    security: {
      requireAllBiometrics: { type: Boolean, default: false },
      minimumBiometrics: { type: Number, default: 1 },
      maxFailedAttempts: { type: Number, default: 3 },
      lockoutDuration: { type: Number, default: 3600000 }, // 1 hour in ms
      failedAttempts: { type: Number, default: 0 },
      lockedUntil: Date,
    },
    
    // Audit Trail
    auditLog: [{
      action: String,
      biometricType: String,
      success: Boolean,
      timestamp: Date,
      ipAddress: String,
      deviceId: String,
      blockchainHash: String,
    }],
    
    // Status
    isActive: {
      type: Boolean,
      default: true,
    },
    enrollmentComplete: {
      type: Boolean,
      default: false,
    },
    lastVerification: Date,
    verificationCount: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for performance
biometricDataSchema.index({ userId: 1, tenantId: 1 }, { unique: true });
biometricDataSchema.index({ 'blockchain.ledgerId': 1 });
biometricDataSchema.index({ isActive: 1 });

// Instance Methods
biometricDataSchema.methods = {
  // Encrypt biometric data
  encryptBiometric: function (data) {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(
      process.env.BIOMETRIC_MASTER_KEY || 'default-master-key-change-this',
      this.encryption.salt || crypto.randomBytes(16).toString('hex'),
      32
    );
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    this.encryption.iv = iv.toString('hex');
    
    return {
      encrypted: encrypted,
      authTag: authTag.toString('hex'),
    };
  },
  
  // Decrypt biometric data
  decryptBiometric: function (encryptedData, authTag) {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(
      process.env.BIOMETRIC_MASTER_KEY || 'default-master-key-change-this',
      this.encryption.salt,
      32
    );
    const iv = Buffer.from(this.encryption.iv, 'hex');
    
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  },
  
  // Hash biometric template (one-way)
  hashBiometricTemplate: function (template) {
    const salt = crypto.randomBytes(32).toString('hex');
    const hash = crypto.pbkdf2Sync(
      JSON.stringify(template),
      salt,
      100000,
      64,
      'sha512'
    ).toString('hex');
    
    return { hash, salt };
  },
  
  // Verify biometric template
  verifyBiometricTemplate: function (template, storedHash, salt) {
    const hash = crypto.pbkdf2Sync(
      JSON.stringify(template),
      salt,
      100000,
      64,
      'sha512'
    ).toString('hex');
    
    return hash === storedHash;
  },
  
  // Add fingerprint template
  addFingerprintTemplate: async function (finger, hand, template, quality) {
    const { hash, salt } = this.hashBiometricTemplate(template);
    
    this.fingerprint.templates.push({
      finger,
      hand,
      hash: `${hash}:${salt}`,
      quality,
      enrolledAt: new Date(),
    });
    
    this.fingerprint.enabled = true;
    await this.save();
    
    return true;
  },
  
  // Verify fingerprint
  verifyFingerprint: async function (template) {
    if (!this.fingerprint.enabled || this.fingerprint.templates.length === 0) {
      return false;
    }
    
    for (const stored of this.fingerprint.templates) {
      const [storedHash, salt] = stored.hash.split(':');
      if (this.verifyBiometricTemplate(template, storedHash, salt)) {
        stored.lastUsed = new Date();
        this.lastVerification = new Date();
        this.verificationCount += 1;
        await this.save();
        return true;
      }
    }
    
    return false;
  },
  
  // Add facial template
  addFacialTemplate: async function (template, quality, metadata) {
    const { hash, salt } = this.hashBiometricTemplate(template);
    
    this.facial.templates.push({
      hash: `${hash}:${salt}`,
      quality,
      enrolledAt: new Date(),
      metadata,
    });
    
    this.facial.enabled = true;
    await this.save();
    
    return true;
  },
  
  // Verify facial recognition
  verifyFacial: async function (template) {
    if (!this.facial.enabled || this.facial.templates.length === 0) {
      return false;
    }
    
    for (const stored of this.facial.templates) {
      const [storedHash, salt] = stored.hash.split(':');
      if (this.verifyBiometricTemplate(template, storedHash, salt)) {
        stored.lastUsed = new Date();
        this.lastVerification = new Date();
        this.verificationCount += 1;
        await this.save();
        return true;
      }
    }
    
    return false;
  },
  
  // Add voice template
  addVoiceTemplate: async function (template, quality, metadata) {
    const { hash, salt } = this.hashBiometricTemplate(template);
    
    this.voice.templates.push({
      hash: `${hash}:${salt}`,
      quality,
      enrolledAt: new Date(),
      metadata,
    });
    
    this.voice.enabled = true;
    await this.save();
    
    return true;
  },
  
  // Verify voice
  verifyVoice: async function (template) {
    if (!this.voice.enabled || this.voice.templates.length === 0) {
      return false;
    }
    
    for (const stored of this.voice.templates) {
      const [storedHash, salt] = stored.hash.split(':');
      if (this.verifyBiometricTemplate(template, storedHash, salt)) {
        stored.lastUsed = new Date();
        this.lastVerification = new Date();
        this.verificationCount += 1;
        await this.save();
        return true;
      }
    }
    
    return false;
  },
  
  // Register device fingerprint
  registerDevice: async function (deviceInfo) {
    const deviceHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(deviceInfo))
      .digest('hex');
    
    const existing = this.deviceFingerprints.find(d => d.hash === deviceHash);
    
    if (existing) {
      existing.lastSeen = new Date();
    } else {
      this.deviceFingerprints.push({
        deviceId: crypto.randomBytes(16).toString('hex'),
        deviceType: deviceInfo.deviceType,
        browser: deviceInfo.browser,
        os: deviceInfo.os,
        screenResolution: deviceInfo.screenResolution,
        timezone: deviceInfo.timezone,
        language: deviceInfo.language,
        hash: deviceHash,
        trusted: false,
        firstSeen: new Date(),
        lastSeen: new Date(),
      });
    }
    
    await this.save();
    return deviceHash;
  },
  
  // Check if device is trusted
  isDeviceTrusted: function (deviceHash) {
    const device = this.deviceFingerprints.find(d => d.hash === deviceHash);
    return device ? device.trusted : false;
  },
  
  // Log audit event
  logAudit: async function (action, biometricType, success, ipAddress, deviceId, blockchainHash) {
    this.auditLog.push({
      action,
      biometricType,
      success,
      timestamp: new Date(),
      ipAddress,
      deviceId,
      blockchainHash,
    });
    
    // Keep only last 1000 audit entries
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
    
    await this.save();
  },
  
  // Check if account is locked
  isLocked: function () {
    return this.security.lockedUntil && this.security.lockedUntil > new Date();
  },
  
  // Increment failed attempts
  incrementFailedAttempts: async function () {
    this.security.failedAttempts += 1;
    
    if (this.security.failedAttempts >= this.security.maxFailedAttempts) {
      this.security.lockedUntil = new Date(Date.now() + this.security.lockoutDuration);
    }
    
    await this.save();
  },
  
  // Reset failed attempts
  resetFailedAttempts: async function () {
    this.security.failedAttempts = 0;
    this.security.lockedUntil = null;
    await this.save();
  },
};

// Static Methods
biometricDataSchema.statics = {
  // Find by user and tenant
  findByUser: function (userId, tenantId) {
    return this.findOne({ userId, tenantId, isActive: true });
  },
  
  // Create new biometric record
  createForUser: async function (userId, tenantId) {
    const salt = crypto.randomBytes(32).toString('hex');
    
    return this.create({
      userId,
      tenantId,
      encryption: {
        salt,
        keyVersion: 1,
      },
      blockchain: {
        enabled: true,
      },
    });
  },
};

export default mongoose.model('BiometricData', biometricDataSchema);
