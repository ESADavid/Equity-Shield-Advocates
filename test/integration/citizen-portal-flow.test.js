/**
 * CITIZEN PORTAL INTEGRATION TEST
 * Tests complete citizen registration and enrollment flow
 */

import CitizenPortalService from '../../services/citizenPortalService.js';

describe('Citizen Portal Integration Flow', () => {
  let portalService;
  let testCitizenId;

  beforeAll(() => {
    portalService = new CitizenPortalService();
  });

  describe('Citizen Registration Flow', () => {
    test('should register a new citizen', async () => {
      const result = await portalService.registerCitizen({
        firstName: 'Integration',
        lastName: 'Test',
        dateOfBirth: '1990-01-01',
        gender: 'male',
        nationality: 'US',
        ssn: '123-45-6789',
        email: 'integration.test@example.com',
        phone: '+1234567890',
        address: {
          street: '123 Test St',
          city: 'Test City',
          state: 'TS',
          country: 'USA',
          postalCode: '12345'
        }
      });

      expect(result.success).toBe(true);
      expect(result.citizenId).toBeDefined();
      expect(result.citizen.personalInfo.ssn).toContain('***');
      
      testCitizenId = result.citizenId;
    });

    test('should retrieve citizen profile', () => {
      const result = portalService.getCitizenProfile(testCitizenId);
      
      expect(result.success).toBe(true);
      expect(result.profile).toBeDefined();
      expect(result.summary).toBeDefined();
    });

    test('should update citizen profile', () => {
      const result = portalService.updateCitizenProfile(testCitizenId, {
        contact: { phone: '+1987654321' }
      });
      
      expect(result.success).toBe(true);
    });
  });

  describe('UBI Enrollment Flow', () => {
    test('should fail UBI enrollment without verification', async () => {
      const result = await portalService.enrollInUBI(testCitizenId, {
        paymentMethod: 'direct_deposit',
        bankAccount: {
          accountNumber: '1234567890',
          routingNumber: '987654321'
        }
      });
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('verified');
    });

    test('should enroll in UBI after verification', async () => {
      // Simulate verification
      const citizen = portalService.citizens.get(testCitizenId);
      citizen.verificationStatus = 'verified';
      
      const result = await portalService.enrollInUBI(testCitizenId, {
        paymentMethod: 'direct_deposit',
        bankAccount: {
          accountNumber: '1234567890',
          routingNumber: '987654321',
          bankName: 'Test Bank'
        }
      });
      
      expect(result.success).toBe(true);
      expect(result.enrollment.enrolled).toBe(true);
    });
  });

  describe('Education Enrollment Flow', () => {
    test('should enroll in education course', async () => {
      const result = await portalService.enrollInCourse(testCitizenId, 'COURSE-TEST-001');
      
      expect(result.success).toBe(true);
      expect(result.courseId).toBe('COURSE-TEST-001');
    });

    test('should prevent duplicate course enrollment', async () => {
      const result = await portalService.enrollInCourse(testCitizenId, 'COURSE-TEST-001');
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('already enrolled');
    });
  });

  describe('Service Request Flow', () => {
    test('should create service request', async () => {
      const result = await portalService.createServiceRequest(testCitizenId, {
        type: 'support',
        category: 'technical',
        subject: 'Test Request',
        description: 'Integration test request',
        priority: 'medium'
      });
      
      expect(result.success).toBe(true);
      expect(result.requestId).toBeDefined();
    });
  });

  describe('Document Upload Flow', () => {
    test('should upload document', async () => {
      const result = await portalService.uploadDocument(testCitizenId, {
        type: 'identity_proof',
        category: 'identity',
        name: 'Test Document',
        fileUrl: '/test/doc.pdf',
        fileSize: 1024,
        mimeType: 'application/pdf'
      });
      
      expect(result.success).toBe(true);
      expect(result.documentId).toBeDefined();
    });
  });
});
