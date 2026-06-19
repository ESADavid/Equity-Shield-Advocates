/**
 * DATA SANITIZATION SECURITY TEST
 * Tests sensitive data handling and sanitization
 */

import CitizenPortalService from '../../services/citizenPortalService.js';

describe('Data Sanitization Security Tests', () => {
  let portalService;
  let testCitizenId;

  beforeAll(async () => {
    portalService = new CitizenPortalService();

    const result = await portalService.registerCitizen({
      firstName: 'Security',
      lastName: 'Test',
      dateOfBirth: '1990-01-01',
      gender: 'male',
      nationality: 'US',
      ssn: '123-45-6789',
      email: 'security@test.com',
      phone: '+1234567890',
    });

    testCitizenId = result.citizenId;
  });

  describe('SSN Masking', () => {
    test('should mask SSN in citizen profile', () => {
      const result = portalService.getCitizenProfile(testCitizenId);

      expect(result.success).toBe(true);
      expect(result.profile.personalInfo.ssn).toContain('***');
      expect(result.profile.personalInfo.ssn).not.toBe('123-45-6789');
    });
  });

  describe('Bank Account Masking', () => {
    test('should mask bank account numbers', async () => {
      const citizen = portalService.citizens.get(testCitizenId);
      citizen.verificationStatus = 'verified';

      await portalService.enrollInUBI(testCitizenId, {
        paymentMethod: 'direct_deposit',
        bankAccount: {
          accountNumber: '1234567890',
          routingNumber: '987654321',
        },
      });

      const result = portalService.getCitizenProfile(testCitizenId);

      expect(result.profile.ubiEnrollment.bankAccount.accountNumber).toContain(
        '****'
      );
    });
  });

  describe('PII Protection', () => {
    test('should not expose full SSN in API responses', () => {
      const result = portalService.getCitizenProfile(testCitizenId);

      const jsonString = JSON.stringify(result);
      expect(jsonString).not.toContain('123-45-6789');
    });

    test('should sanitize data before external transmission', () => {
      const citizen = portalService.citizens.get(testCitizenId);
      const sanitized = portalService.sanitizeCitizenData(citizen);

      expect(sanitized.personalInfo.ssn).not.toBe(citizen.personalInfo.ssn);
    });
  });

  describe('Sensitive Data Logging', () => {
    test('should not log sensitive information', () => {
      // Verify that sensitive data is not in activity logs
      const citizen = portalService.citizens.get(testCitizenId);

      citizen.activityLog.forEach((log) => {
        const logString = JSON.stringify(log);
        expect(logString).not.toContain('123-45-6789');
      });
    });
  });
});
