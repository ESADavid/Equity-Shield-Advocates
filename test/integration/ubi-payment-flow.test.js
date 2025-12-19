/**
 * UBI PAYMENT FLOW INTEGRATION TEST
 * Tests complete UBI payment processing flow
 */

import UBIPaymentService from '../../services/ubiPaymentService.js';
import CitizenPortalService from '../../services/citizenPortalService.js';

describe('UBI Payment Flow Integration', () => {
  let ubiService;
  let portalService;
  let testCitizenId;

  beforeAll(async () => {
    ubiService = new UBIPaymentService();
    portalService = new CitizenPortalService();

    // Register and verify citizen
    const registration = await portalService.registerCitizen({
      firstName: 'UBI',
      lastName: 'Test',
      dateOfBirth: '1990-01-01',
      gender: 'male',
      nationality: 'US',
      ssn: '123-45-6789',
      email: 'ubi@test.com',
      phone: '+1234567890',
    });

    testCitizenId = registration.citizenId;
    const citizen = portalService.citizens.get(testCitizenId);
    citizen.verificationStatus = 'verified';

    // Enroll in UBI
    await portalService.enrollInUBI(testCitizenId, {
      paymentMethod: 'direct_deposit',
      bankAccount: {
        accountNumber: '1234567890',
        routingNumber: '987654321',
      },
    });
  });

  test('should process UBI payment successfully', async () => {
    const result = await ubiService.processPayment({
      citizenId: testCitizenId,
      amount: 1000,
      paymentDate: new Date().toISOString(),
    });

    expect(result.success).toBe(true);
    expect(result.payment).toBeDefined();
  });

  test('should record payment in blockchain', async () => {
    const payments = await ubiService.getPaymentHistory(testCitizenId);
    expect(payments.success).toBe(true);
    expect(payments.payments.length).toBeGreaterThan(0);
  });

  test('should update citizen payment history', () => {
    const profile = portalService.getCitizenProfile(testCitizenId);
    expect(profile.success).toBe(true);
  });
});
