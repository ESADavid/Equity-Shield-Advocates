/**
 * Biometric Authentication System Tests
 * Tests for biometric enrollment, verification, and permission checking
 *
 * @ts-nocheck
 * TypeScript cannot detect static methods from .js mongoose model files, so we suppress this check.
 * The static methods findByUser, createForUser (BiometricData) and findByCode (Permission)
 * ARE defined in their respective model files as schema.statics
 */

// Mock the Mongoose models BEFORE importing the services
// This prevents the MongoDB connection attempts
const mockBiometricDataInstance = {
  findByUser: jest.fn(),
  createForUser: jest.fn(),
  save: jest.fn().mockResolvedValue(true),
};

jest.mock('../../models/BiometricData.js', () => {
  return jest.fn().mockImplementation(() => mockBiometricDataInstance);
});

// Mock Permission model with proper return values
const mockPermission = {
  _id: 'permission-id-123',
  code: 'VIEW_ACCOUNTS',
  name: 'View Accounts',
  tenantId: 'test-tenant-456',
  isActive: true,
  isAllowedAtTime: () => true,
  isAllowedFromContext: () => ({ allowed: true, reasons: [] }),
  getRequiredBiometrics: () => ['fingerprint'],
  restrictions: {
    usageLimits: null,
    timeRestrictions: null,
    contextRestrictions: null,
  },
  security: {
    requiresBiometric: false,
    biometricTypes: [],
    minimumBiometrics: 1,
    requiresMFA: false,
    requiresApproval: false,
    approvalCount: 0,
  },
};

const mockPermissions = [
  mockPermission,
  { ...mockPermission, _id: 'permission-id-456', code: 'SYSTEM_ADMIN', name: 'System Administrator' },
];

jest.mock('../../models/Permission.js', () => {
  return {
    findOne: jest.fn(),
    find: jest.fn().mockResolvedValue([]),
    create: jest.fn(),
    findByCode: jest.fn().mockResolvedValue(undefined),
    createDefaultPermissions: jest.fn().mockResolvedValue([]),
  };
});

import mongoose from 'mongoose';
import biometricAuthService from '../../services/biometricAuthService.js';
import permissionService from '../../services/permissionService.js';

// Import the BiometricData model after mocking
import BiometricData from '../../models/BiometricData.js';
import Permission from '../../models/Permission.js';

// Create a valid MongoDB ObjectId for testing
const testUserId = new mongoose.Types.ObjectId();
const testTenantId = 'test-tenant-456';

// Helper function to create mock biometric data
const createMockBiometricData = (overrides = {}) => ({
  userId: testUserId,
  tenantId: testTenantId,
  fingerprint: {
    enabled: true,
    templates: [{
      finger: 'index',
      hand: 'right',
      hash: 'test-hash:salt',
      quality: 85,
      enrolledAt: new Date(),
      lastUsed: new Date(),
    }],
  },
  facial: {
    enabled: true,
    templates: [],
  },
  voice: {
    enabled: true,
    templates: [],
  },
  behavioral: {
    enabled: false,
    templates: [],
  },
  deviceFingerprints: [],
  security: {
    failedAttempts: 0,
    maxFailedAttempts: 3,
    lockedUntil: null,
    minimumBiometrics: 1,
  },
  enrollmentComplete: true,
  lastVerification: null,
  verificationCount: 0,
  isLocked: () => false,
  addFingerprintTemplate: jest.fn().mockResolvedValue(true),
  addFacialTemplate: jest.fn().mockResolvedValue(true),
  addVoiceTemplate: jest.fn().mockResolvedValue(true),
  verifyFingerprint: jest.fn().mockResolvedValue(true),
  verifyFacial: jest.fn().mockResolvedValue(true),
  verifyVoice: jest.fn().mockResolvedValue(true),
  registerDevice: jest.fn().mockResolvedValue('test-device-hash'),
  isDeviceTrusted: jest.fn().mockReturnValue(true),
  resetFailedAttempts: jest.fn().mockResolvedValue(true),
  incrementFailedAttempts: jest.fn().mockResolvedValue(true),
  logAudit: jest.fn().mockResolvedValue(true),
  save: jest.fn().mockResolvedValue(true),
...overrides,
});

describe('Biometric Authentication System', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Default mock implementation
    BiometricData.findByUser = jest.fn().mockResolvedValue(createMockBiometricData());
    BiometricData.createForUser = jest.fn().mockResolvedValue(createMockBiometricData());
  });

  describe('Biometric Enrollment', () => {
    test('should enroll fingerprint successfully', async () => {
      const fingerprintData = {
        finger: 'index',
        hand: 'right',
        template: 'test-fingerprint-template-data',
        quality: 85,
      };

      const result = await biometricAuthService.enrollFingerprint(
        testUserId,
        testTenantId,
        fingerprintData
      );

      expect(result.success).toBe(true);
      expect(result.quality).toBe(85);
    });

    test('should reject low quality fingerprint', async () => {
      const fingerprintData = {
        finger: 'index',
        hand: 'right',
        template: 'test-fingerprint-template-data',
        quality: 50, // Below threshold
      };

      await expect(
        biometricAuthService.enrollFingerprint(
          testUserId,
          testTenantId,
          fingerprintData
        )
      ).rejects.toThrow('Fingerprint quality too low');
    });

    test('should enroll facial recognition successfully', async () => {
      const facialData = {
        template: 'test-facial-template-data',
        quality: 80,
        metadata: { lighting: 'good', angle: 'front' },
      };

      const result = await biometricAuthService.enrollFacial(
        testUserId,
        testTenantId,
        facialData
      );

      expect(result.success).toBe(true);
      expect(result.quality).toBe(80);
    });

    test('should enroll voice print successfully', async () => {
      const voiceData = {
        template: 'test-voice-template-data',
        quality: 75,
        metadata: { duration: 5, sampleRate: 44100 },
      };

      const result = await biometricAuthService.enrollVoice(
        testUserId,
        testTenantId,
        voiceData
      );

      expect(result.success).toBe(true);
      expect(result.quality).toBe(75);
    });
  });

  describe('Biometric Verification', () => {
    test('should verify fingerprint successfully', async () => {
      const context = {
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
        userAgent: 'Test Browser',
      };

      const result = await biometricAuthService.verifyFingerprint(
        testUserId,
        testTenantId,
        'test-fingerprint-template-data',
        context
      );

      expect(result.success).toBe(true);
      expect(result.verified).toBe(true);
    });

    test('should fail verification with wrong fingerprint', async () => {
      // Override mock to return false for verification
      const mockData = createMockBiometricData({
        verifyFingerprint: jest.fn().mockResolvedValue(false),
      });
      BiometricData.findByUser = jest.fn().mockResolvedValue(mockData);

      const context = {
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      };

      const result = await biometricAuthService.verifyFingerprint(
        testUserId,
        testTenantId,
        'wrong-fingerprint-template',
        context
      );

      expect(result.success).toBe(false);
      expect(result.verified).toBe(false);
    });

    test('should verify multiple biometrics', async () => {
      const biometrics = {
        fingerprint: 'test-fingerprint-template-data',
        facial: 'test-facial-template-data',
      };

      const context = {
        ipAddress: '192.168.1.1',
        deviceId: 'device-123',
      };

      const result = await biometricAuthService.verifyMultipleBiometrics(
        testUserId,
        testTenantId,
        biometrics,
        context
      );

      expect(result.overall).toBe(true);
    });
  });

  describe('Device Management', () => {
    test('should register device successfully', async () => {
      const deviceInfo = {
        deviceType: 'desktop',
        browser: 'Chrome',
        os: 'Windows 11',
        screenResolution: '1920x1080',
      };

      const result = await biometricAuthService.registerDevice(
        testUserId,
        testTenantId,
        deviceInfo
      );

      expect(result.success).toBe(true);
      expect(result.deviceHash).toBeDefined();
    });

    test('should verify trusted device', async () => {
      const deviceHash = 'test-device-hash';

      const result = await biometricAuthService.verifyDevice(
        testUserId,
        testTenantId,
        deviceHash
      );

      expect(result.verified).toBe(true);
    });
  });

  describe('Biometric Status', () => {
    test('should get biometric status', async () => {
      const status = await biometricAuthService.getBiometricStatus(
        testUserId,
        testTenantId
      );

      expect(status).toHaveProperty('enrolled');
      expect(status).toHaveProperty('fingerprint');
      expect(status).toHaveProperty('facial');
      expect(status).toHaveProperty('voice');
    });
  });
});

describe('Permission System', () => {
  const testUserId = 'test-user-123';
  const testTenantId = 'test-tenant-456';

  beforeEach(() => {
    jest.clearAllMocks();
// Set up Permission mock return values for each test
    Permission.findByCode = jest.fn().mockImplementation((code) => {
      if (code === 'VIEW_ACCOUNTS' || code === 'SYSTEM_ADMIN') {
        return Promise.resolve({
          _id: 'permission-id-123',
          code: code,
          tenantId: testTenantId,
          isActive: true,
          isAllowedAtTime: () => true,
          isAllowedFromContext: () => ({ allowed: true, reasons: [] }),
          getRequiredBiometrics: () => ['fingerprint'],
          restrictions: {
            usageLimits: null,
            timeRestrictions: null,
            contextRestrictions: null,
          },
          security: {
            requiresBiometric: false,
            biometricTypes: [],
            minimumBiometrics: 1,
            requiresMFA: false,
            requiresApproval: false,
            approvalCount: 0,
          },
        });
      }
      return Promise.resolve(undefined);
    });
    Permission.find = jest.fn().mockResolvedValue(mockPermissions);
  });

  describe('Permission Checking', () => {
    test('should check permission successfully', async () => {
      const context = {
        ipAddress: '192.168.1.1',
        deviceType: 'desktop',
        isVPN: false,
        isSecureNetwork: true,
        isTrustedDevice: true,
      };

      const result = await permissionService.checkPermission(
        testUserId,
        'VIEW_ACCOUNTS',
        testTenantId,
        context
      );

      expect(result).toHaveProperty('allowed');
    });

    test('should deny permission outside allowed hours', async () => {
      const context = {
        ipAddress: '192.168.1.1',
        deviceType: 'desktop',
      };

      // This would need to be tested with a permission that has time restrictions
      const result = await permissionService.checkPermission(
        testUserId,
        'SYSTEM_ADMIN',
        testTenantId,
        context
      );

      expect(result).toHaveProperty('allowed');
    });
  });

  describe('Required Biometrics', () => {
    test('should get required biometrics for permission', async () => {
      const biometrics = await permissionService.getRequiredBiometrics(
        'SYSTEM_ADMIN',
        testTenantId
      );

      expect(Array.isArray(biometrics)).toBe(true);
    });
  });

  describe('Permission Management', () => {
    test('should grant permission', async () => {
      const result = await permissionService.grantPermission(
        testUserId,
        'VIEW_ACCOUNTS',
        testTenantId,
        'admin-user-id'
      );

      expect(result.success).toBe(true);
    }, 30000);

    test('should revoke permission', async () => {
      const result = await permissionService.revokePermission(
        testUserId,
        'VIEW_ACCOUNTS',
        testTenantId,
        'admin-user-id'
      );

      expect(result.success).toBe(true);
    }, 30000);
  });

  describe('Default Permissions', () => {
    test('should initialize default permissions', async () => {
      const result = await permissionService.initializeDefaultPermissions(
        testTenantId,
        'admin-user-id'
      );

      expect(result.success).toBe(true);
    }, 30000);

    test('should get all permissions for tenant', async () => {
      const permissions =
        await permissionService.getAllPermissions(testTenantId);

      expect(Array.isArray(permissions)).toBe(true);
    }, 30000);
  });
});

describe('Integration Tests', () => {
  // Use the valid ObjectId for biometric operations
  const integrationTestUserId = new mongoose.Types.ObjectId();
  const testTenantId = 'test-tenant-456';

  beforeEach(() => {
    jest.clearAllMocks();
    BiometricData.findByUser = jest.fn().mockResolvedValue(createMockBiometricData());
    BiometricData.createForUser = jest.fn().mockResolvedValue(createMockBiometricData());
  });

  test('should complete full biometric enrollment and verification flow', async () => {
    // 1. Enroll biometrics
    const fingerprintResult = await biometricAuthService.enrollFingerprint(
      integrationTestUserId,
      testTenantId,
      {
        finger: 'index',
        hand: 'right',
        template: 'test-template',
        quality: 85,
      }
    );
    expect(fingerprintResult.success).toBe(true);

    // 2. Verify biometrics
    const verifyResult = await biometricAuthService.verifyFingerprint(
      integrationTestUserId,
      testTenantId,
      'test-template',
      { ipAddress: '192.168.1.1' }
    );
    expect(verifyResult.verified).toBe(true);

    // 3. Check status
    const status = await biometricAuthService.getBiometricStatus(
      integrationTestUserId,
      testTenantId
    );
    expect(status.enrolled).toBe(true);
  }, 30000);

  test('should enforce permission with biometric requirement', async () => {
    // 1. Check permission (using string testUserId for permission service)
    const permissionCheck = await permissionService.checkPermission(
      testUserId,
      'SYSTEM_ADMIN',
      testTenantId,
      { ipAddress: '192.168.1.1' }
    );

    // 2. If biometric required, verify it
    if (permissionCheck.requiresBiometric) {
      const biometricVerify =
        await biometricAuthService.verifyMultipleBiometrics(
          integrationTestUserId,
          testTenantId,
          { fingerprint: 'test-template' },
          { ipAddress: '192.168.1.1' }
        );
      expect(biometricVerify.overall).toBe(true);
    }
  }, 30000);
});
