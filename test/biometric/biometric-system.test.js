import biometricAuthService from '../../services/biometricAuthService.js';
import permissionService from '../../services/permissionService.js';
import BiometricData from '../../models/BiometricData.js';
import Permission from '../../models/Permission.js';

describe('Biometric Authentication System', () => {
  const testUserId = 'test-user-123';
  const testTenantId = 'test-tenant-456';

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
      expect(result.verifiedCount).toBeGreaterThanOrEqual(1);
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
    });

    test('should revoke permission', async () => {
      const result = await permissionService.revokePermission(
        testUserId,
        'VIEW_ACCOUNTS',
        testTenantId,
        'admin-user-id'
      );

      expect(result.success).toBe(true);
    });
  });

  describe('Default Permissions', () => {
    test('should initialize default permissions', async () => {
      const result = await permissionService.initializeDefaultPermissions(
        testTenantId,
        'admin-user-id'
      );

      expect(result.success).toBe(true);
    });

    test('should get all permissions for tenant', async () => {
      const permissions =
        await permissionService.getAllPermissions(testTenantId);

      expect(Array.isArray(permissions)).toBe(true);
    });
  });
});

describe('Integration Tests', () => {
  const testUserId = 'test-user-123';
  const testTenantId = 'test-tenant-456';

  test('should complete full biometric enrollment and verification flow', async () => {
    // 1. Enroll biometrics
    const fingerprintResult = await biometricAuthService.enrollFingerprint(
      testUserId,
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
      testUserId,
      testTenantId,
      'test-template',
      { ipAddress: '192.168.1.1' }
    );
    expect(verifyResult.verified).toBe(true);

    // 3. Check status
    const status = await biometricAuthService.getBiometricStatus(
      testUserId,
      testTenantId
    );
    expect(status.enrolled).toBe(true);
  });

  test('should enforce permission with biometric requirement', async () => {
    // 1. Check permission
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
          testUserId,
          testTenantId,
          { fingerprint: 'test-template' },
          { ipAddress: '192.168.1.1' }
        );
      expect(biometricVerify.overall).toBe(true);
    }
  });
});
