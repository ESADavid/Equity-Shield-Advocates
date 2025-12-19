import { BiometricAuth } from '../../public/js/biometric-auth.js';

describe('BiometricAuth', () => {
  let biometricAuth;

  beforeEach(() => {
    // Mock globalThis.location.hostname for tests
    globalThis.location = { hostname: 'localhost' };

    // Mock globalThis.PublicKeyCredential and its static methods
    globalThis.PublicKeyCredential = {
      isUserVerifyingPlatformAuthenticatorAvailable: jest
        .fn()
        .mockResolvedValue(true),
      isConditionalMediationAvailable: jest.fn().mockResolvedValue(true),
    };

    // Mock navigator.credentials.create and get
    globalThis.navigator = {
      credentials: {
        create: jest.fn(async () => ({
          rawId: new ArrayBuffer(16),
          response: {},
        })),
        get: jest.fn(async () => ({
          rawId: new ArrayBuffer(16),
          response: {},
        })),
      },
    };

    biometricAuth = new BiometricAuth();
  });

  test('should check WebAuthn support', () => {
    expect(typeof biometricAuth.isSupported).toBe('boolean');
  });

  test('should return false if WebAuthn not supported', async () => {
    biometricAuth.isSupported = false;
    const available = await biometricAuth.isBiometricAvailable();
    expect(available).toBe(false);
  });

  test('should generate challenge as Uint8Array', () => {
    const challenge = biometricAuth.generateChallenge();
    expect(challenge).toBeInstanceOf(Uint8Array);
    expect(challenge.length).toBeGreaterThan(0);
  });

  test('should register biometric credential successfully (mock)', async () => {
    const result = await biometricAuth.registerBiometricCredential(
      'user1',
      'userid1'
    );
    expect(result).toHaveProperty('success', true);
    expect(result).toHaveProperty('credentialId');
    expect(globalThis.navigator.credentials.create).toHaveBeenCalled();
  });

  test('should authenticate biometric successfully (mock)', async () => {
    const result = await biometricAuth.authenticateBiometric('user1');
    expect(result).toHaveProperty('success', true);
    expect(result).toHaveProperty('userId', 'user1');
    expect(globalThis.navigator.credentials.get).toHaveBeenCalled();
  });

  test('should handle errors during registration', async () => {
    globalThis.navigator.credentials.create.mockImplementationOnce(() => {
      throw new Error('Test error');
    });
    try {
      await biometricAuth.registerBiometricCredential('user2', 'userid2');
    } catch (err) {
      expect(err.message).toBe(
        'Biometric authentication failed. Please try again.'
      );
    }
  });

  test('should handle errors during authentication', async () => {
    globalThis.navigator.credentials.get.mockImplementationOnce(() => {
      throw new Error('Test error');
    });
    try {
      await biometricAuth.authenticateBiometric('user2');
    } catch (err) {
      expect(err.message).toBe(
        'Biometric authentication failed. Please try again.'
      );
    }
  });
});
