import BiometricData from '../models/BiometricData.js';
import winston from 'winston';
import crypto from 'crypto';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'biometric-auth' },
  transports: [
    new winston.transports.File({ filename: 'logs/biometric-auth.log' }),
    new winston.transports.File({
      filename: 'logs/biometric-auth-error.log',
      level: 'error',
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

class BiometricAuthService {
  constructor() {
    this.blockchainService = null; // Will be injected
  }

  /**
   * Initialize biometric data for a user
   */
  async initializeBiometricData(userId, tenantId) {
    try {
      // Check if already exists
      let biometricData = await BiometricData.findByUser(userId, tenantId);
      
      if (!biometricData) {
        biometricData = await BiometricData.createForUser(userId, tenantId);
        logger.info('Biometric data initialized', { userId, tenantId });
      }
      
      return biometricData;
    } catch (error) {
      logger.error('Failed to initialize biometric data', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Enroll fingerprint
   */
  async enrollFingerprint(userId, tenantId, fingerprintData) {
    try {
      const biometricData = await this.initializeBiometricData(userId, tenantId);
      
      if (biometricData.isLocked()) {
        throw new Error('Account is locked due to too many failed attempts');
      }
      
      const { finger, hand, template, quality } = fingerprintData;
      
      // Validate quality
      if (quality < 60) {
        throw new Error('Fingerprint quality too low. Please try again.');
      }
      
      await biometricData.addFingerprintTemplate(finger, hand, template, quality);
      
      // Log to blockchain
      if (this.blockchainService && biometricData.blockchain.enabled) {
        const blockHash = await this.logToBlockchain({
          action: 'fingerprint_enrolled',
          userId,
          tenantId,
          finger,
          hand,
          quality,
        });
        
        await biometricData.logAudit(
          'fingerprint_enrolled',
          'fingerprint',
          true,
          null,
          null,
          blockHash
        );
      }
      
      logger.info('Fingerprint enrolled', {
        userId,
        tenantId,
        finger,
        hand,
        quality,
      });
      
      return {
        success: true,
        message: 'Fingerprint enrolled successfully',
        quality,
      };
    } catch (error) {
      logger.error('Fingerprint enrollment failed', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Verify fingerprint
   */
  async verifyFingerprint(userId, tenantId, template, context = {}) {
    try {
      const biometricData = await BiometricData.findByUser(userId, tenantId);
      
      if (!biometricData) {
        throw new Error('No biometric data found for user');
      }
      
      if (biometricData.isLocked()) {
        throw new Error('Account is locked due to too many failed attempts');
      }
      
      const verified = await biometricData.verifyFingerprint(template);
      
      if (verified) {
        await biometricData.resetFailedAttempts();
        
        // Log to blockchain
        if (this.blockchainService && biometricData.blockchain.enabled) {
          const blockHash = await this.logToBlockchain({
            action: 'fingerprint_verified',
            userId,
            tenantId,
            success: true,
            ipAddress: context.ipAddress,
            deviceId: context.deviceId,
          });
          
          await biometricData.logAudit(
            'fingerprint_verified',
            'fingerprint',
            true,
            context.ipAddress,
            context.deviceId,
            blockHash
          );
        }
        
        logger.info('Fingerprint verified', { userId, tenantId });
        
        return {
          success: true,
          verified: true,
          message: 'Fingerprint verified successfully',
        };
      } else {
        await biometricData.incrementFailedAttempts();
        
        // Log failed attempt to blockchain
        if (this.blockchainService && biometricData.blockchain.enabled) {
          const blockHash = await this.logToBlockchain({
            action: 'fingerprint_verification_failed',
            userId,
            tenantId,
            success: false,
            ipAddress: context.ipAddress,
            deviceId: context.deviceId,
          });
          
          await biometricData.logAudit(
            'fingerprint_verification_failed',
            'fingerprint',
            false,
            context.ipAddress,
            context.deviceId,
            blockHash
          );
        }
        
        logger.warn('Fingerprint verification failed', {
          userId,
          tenantId,
          failedAttempts: biometricData.security.failedAttempts,
        });
        
        return {
          success: false,
          verified: false,
          message: 'Fingerprint verification failed',
          attemptsRemaining: biometricData.security.maxFailedAttempts - biometricData.security.failedAttempts,
        };
      }
    } catch (error) {
      logger.error('Fingerprint verification error', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Enroll facial recognition
   */
  async enrollFacial(userId, tenantId, facialData) {
    try {
      const biometricData = await this.initializeBiometricData(userId, tenantId);
      
      if (biometricData.isLocked()) {
        throw new Error('Account is locked due to too many failed attempts');
      }
      
      const { template, quality, metadata } = facialData;
      
      // Validate quality
      if (quality < 70) {
        throw new Error('Facial image quality too low. Please ensure good lighting and face the camera directly.');
      }
      
      await biometricData.addFacialTemplate(template, quality, metadata);
      
      // Log to blockchain
      if (this.blockchainService && biometricData.blockchain.enabled) {
        const blockHash = await this.logToBlockchain({
          action: 'facial_enrolled',
          userId,
          tenantId,
          quality,
          metadata,
        });
        
        await biometricData.logAudit(
          'facial_enrolled',
          'facial',
          true,
          null,
          null,
          blockHash
        );
      }
      
      logger.info('Facial recognition enrolled', {
        userId,
        tenantId,
        quality,
      });
      
      return {
        success: true,
        message: 'Facial recognition enrolled successfully',
        quality,
      };
    } catch (error) {
      logger.error('Facial enrollment failed', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Verify facial recognition
   */
  async verifyFacial(userId, tenantId, template, context = {}) {
    try {
      const biometricData = await BiometricData.findByUser(userId, tenantId);
      
      if (!biometricData) {
        throw new Error('No biometric data found for user');
      }
      
      if (biometricData.isLocked()) {
        throw new Error('Account is locked due to too many failed attempts');
      }
      
      const verified = await biometricData.verifyFacial(template);
      
      if (verified) {
        await biometricData.resetFailedAttempts();
        
        // Log to blockchain
        if (this.blockchainService && biometricData.blockchain.enabled) {
          const blockHash = await this.logToBlockchain({
            action: 'facial_verified',
            userId,
            tenantId,
            success: true,
            ipAddress: context.ipAddress,
            deviceId: context.deviceId,
          });
          
          await biometricData.logAudit(
            'facial_verified',
            'facial',
            true,
            context.ipAddress,
            context.deviceId,
            blockHash
          );
        }
        
        logger.info('Facial recognition verified', { userId, tenantId });
        
        return {
          success: true,
          verified: true,
          message: 'Facial recognition verified successfully',
        };
      } else {
        await biometricData.incrementFailedAttempts();
        
        // Log failed attempt to blockchain
        if (this.blockchainService && biometricData.blockchain.enabled) {
          const blockHash = await this.logToBlockchain({
            action: 'facial_verification_failed',
            userId,
            tenantId,
            success: false,
            ipAddress: context.ipAddress,
            deviceId: context.deviceId,
          });
          
          await biometricData.logAudit(
            'facial_verification_failed',
            'facial',
            false,
            context.ipAddress,
            context.deviceId,
            blockHash
          );
        }
        
        logger.warn('Facial verification failed', {
          userId,
          tenantId,
          failedAttempts: biometricData.security.failedAttempts,
        });
        
        return {
          success: false,
          verified: false,
          message: 'Facial recognition verification failed',
          attemptsRemaining: biometricData.security.maxFailedAttempts - biometricData.security.failedAttempts,
        };
      }
    } catch (error) {
      logger.error('Facial verification error', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Enroll voice print
   */
  async enrollVoice(userId, tenantId, voiceData) {
    try {
      const biometricData = await this.initializeBiometricData(userId, tenantId);
      
      if (biometricData.isLocked()) {
        throw new Error('Account is locked due to too many failed attempts');
      }
      
      const { template, quality, metadata } = voiceData;
      
      // Validate quality
      if (quality < 65) {
        throw new Error('Voice sample quality too low. Please speak clearly in a quiet environment.');
      }
      
      await biometricData.addVoiceTemplate(template, quality, metadata);
      
      // Log to blockchain
      if (this.blockchainService && biometricData.blockchain.enabled) {
        const blockHash = await this.logToBlockchain({
          action: 'voice_enrolled',
          userId,
          tenantId,
          quality,
          metadata,
        });
        
        await biometricData.logAudit(
          'voice_enrolled',
          'voice',
          true,
          null,
          null,
          blockHash
        );
      }
      
      logger.info('Voice print enrolled', {
        userId,
        tenantId,
        quality,
      });
      
      return {
        success: true,
        message: 'Voice print enrolled successfully',
        quality,
      };
    } catch (error) {
      logger.error('Voice enrollment failed', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Verify voice print
   */
  async verifyVoice(userId, tenantId, template, context = {}) {
    try {
      const biometricData = await BiometricData.findByUser(userId, tenantId);
      
      if (!biometricData) {
        throw new Error('No biometric data found for user');
      }
      
      if (biometricData.isLocked()) {
        throw new Error('Account is locked due to too many failed attempts');
      }
      
      const verified = await biometricData.verifyVoice(template);
      
      if (verified) {
        await biometricData.resetFailedAttempts();
        
        // Log to blockchain
        if (this.blockchainService && biometricData.blockchain.enabled) {
          const blockHash = await this.logToBlockchain({
            action: 'voice_verified',
            userId,
            tenantId,
            success: true,
            ipAddress: context.ipAddress,
            deviceId: context.deviceId,
          });
          
          await biometricData.logAudit(
            'voice_verified',
            'voice',
            true,
            context.ipAddress,
            context.deviceId,
            blockHash
          );
        }
        
        logger.info('Voice print verified', { userId, tenantId });
        
        return {
          success: true,
          verified: true,
          message: 'Voice print verified successfully',
        };
      } else {
        await biometricData.incrementFailedAttempts();
        
        // Log failed attempt to blockchain
        if (this.blockchainService && biometricData.blockchain.enabled) {
          const blockHash = await this.logToBlockchain({
            action: 'voice_verification_failed',
            userId,
            tenantId,
            success: false,
            ipAddress: context.ipAddress,
            deviceId: context.deviceId,
          });
          
          await biometricData.logAudit(
            'voice_verification_failed',
            'voice',
            false,
            context.ipAddress,
            context.deviceId,
            blockHash
          );
        }
        
        logger.warn('Voice verification failed', {
          userId,
          tenantId,
          failedAttempts: biometricData.security.failedAttempts,
        });
        
        return {
          success: false,
          verified: false,
          message: 'Voice print verification failed',
          attemptsRemaining: biometricData.security.maxFailedAttempts - biometricData.security.failedAttempts,
        };
      }
    } catch (error) {
      logger.error('Voice verification error', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Register device fingerprint
   */
  async registerDevice(userId, tenantId, deviceInfo) {
    try {
      const biometricData = await BiometricData.findByUser(userId, tenantId);
      
      if (!biometricData) {
        throw new Error('No biometric data found for user');
      }
      
      const deviceHash = await biometricData.registerDevice(deviceInfo);
      
      logger.info('Device registered', {
        userId,
        tenantId,
        deviceType: deviceInfo.deviceType,
      });
      
      return {
        success: true,
        deviceHash,
        message: 'Device registered successfully',
      };
    } catch (error) {
      logger.error('Device registration failed', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Verify device
   */
  async verifyDevice(userId, tenantId, deviceHash) {
    try {
      const biometricData = await BiometricData.findByUser(userId, tenantId);
      
      if (!biometricData) {
        return { verified: false, trusted: false };
      }
      
      const trusted = biometricData.isDeviceTrusted(deviceHash);
      
      return {
        verified: true,
        trusted,
      };
    } catch (error) {
      logger.error('Device verification failed', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Multi-factor biometric verification
   */
  async verifyMultipleBiometrics(userId, tenantId, biometrics, context = {}) {
    try {
      const results = {
        fingerprint: null,
        facial: null,
        voice: null,
        overall: false,
        verifiedCount: 0,
        requiredCount: 0,
      };
      
      const biometricData = await BiometricData.findByUser(userId, tenantId);
      
      if (!biometricData) {
        throw new Error('No biometric data found for user');
      }
      
      // Determine required biometrics
      results.requiredCount = biometricData.security.minimumBiometrics;
      
      // Verify each provided biometric
      if (biometrics.fingerprint) {
        const result = await this.verifyFingerprint(userId, tenantId, biometrics.fingerprint, context);
        results.fingerprint = result.verified;
        if (result.verified) results.verifiedCount++;
      }
      
      if (biometrics.facial) {
        const result = await this.verifyFacial(userId, tenantId, biometrics.facial, context);
        results.facial = result.verified;
        if (result.verified) results.verifiedCount++;
      }
      
      if (biometrics.voice) {
        const result = await this.verifyVoice(userId, tenantId, biometrics.voice, context);
        results.voice = result.verified;
        if (result.verified) results.verifiedCount++;
      }
      
      // Check if enough biometrics verified
      results.overall = results.verifiedCount >= results.requiredCount;
      
      logger.info('Multi-factor biometric verification', {
        userId,
        tenantId,
        verifiedCount: results.verifiedCount,
        requiredCount: results.requiredCount,
        overall: results.overall,
      });
      
      return results;
    } catch (error) {
      logger.error('Multi-factor biometric verification failed', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get biometric status
   */
  async getBiometricStatus(userId, tenantId) {
    try {
      const biometricData = await BiometricData.findByUser(userId, tenantId);
      
      if (!biometricData) {
        return {
          enrolled: false,
          fingerprint: false,
          facial: false,
          voice: false,
          devices: 0,
        };
      }
      
      return {
        enrolled: biometricData.enrollmentComplete,
        fingerprint: biometricData.fingerprint.enabled,
        fingerprintCount: biometricData.fingerprint.templates.length,
        facial: biometricData.facial.enabled,
        facialCount: biometricData.facial.templates.length,
        voice: biometricData.voice.enabled,
        voiceCount: biometricData.voice.templates.length,
        behavioral: biometricData.behavioral.enabled,
        devices: biometricData.deviceFingerprints.length,
        trustedDevices: biometricData.deviceFingerprints.filter(d => d.trusted).length,
        lastVerification: biometricData.lastVerification,
        verificationCount: biometricData.verificationCount,
        isLocked: biometricData.isLocked(),
        lockedUntil: biometricData.security.lockedUntil,
      };
    } catch (error) {
      logger.error('Failed to get biometric status', {
        userId,
        tenantId,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Log to blockchain
   */
  async logToBlockchain(data) {
    try {
      if (!this.blockchainService) {
        return null;
      }
      
      const blockHash = crypto
        .createHash('sha256')
        .update(JSON.stringify(data) + Date.now())
        .digest('hex');
      
      // In production, this would call the actual blockchain service
      // await this.blockchainService.addBlock(data);
      
      return blockHash;
    } catch (error) {
      logger.error('Failed to log to blockchain', {
        error: error.message,
      });
      return null;
    }
  }

  /**
   * Set blockchain service
   */
  setBlockchainService(blockchainService) {
    this.blockchainService = blockchainService;
  }
}

export default new BiometricAuthService();
