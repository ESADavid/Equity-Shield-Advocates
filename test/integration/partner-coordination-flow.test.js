/**
 * PARTNER COORDINATION INTEGRATION TEST
 * Tests complete partner onboarding and project management flow
 */

import PartnerCoordinationService from '../../services/partnerCoordinationService.js';

describe('Partner Coordination Integration Flow', () => {
  let partnerService;
  let testPartnerId;
  let testProjectId;

  beforeAll(() => {
    partnerService = new PartnerCoordinationService();
  });

  describe('Partner Onboarding Flow', () => {
    test('should onboard a new partner', async () => {
      const result = await partnerService.onboardPartner({
        name: 'Integration Test Partner',
        type: 'corporate',
        contact: {
          primaryContact: {
            name: 'Test Contact',
            email: 'contact@testpartner.com',
            phone: '+1234567890'
          }
        },
        contract: {
          startDate: new Date().toISOString(),
          duration: 12,
          value: 100000
        }
      }, 'test-admin');

      expect(result.success).toBe(true);
      expect(result.partnerId).toBeDefined();
      expect(result.partner.status).toBe('pending');
      
      testPartnerId = result.partnerId;
    });

    test('should activate partner', () => {
      const result = partnerService.activatePartner(testPartnerId, 'test-admin');
      
      expect(result.success).toBe(true);
      expect(result.partner.status).toBe('active');
    });
  });

  describe('Project Management Flow', () => {
    test('should assign project to partner', () => {
      const result = partnerService.assignProject(testPartnerId, {
        name: 'Test Project',
        description: 'Integration test project',
        type: 'development',
        priority: 'high',
        budget: 50000,
        personnel: 5
      }, 'test-admin');

      expect(result.success).toBe(true);
      expect(result.projectId).toBeDefined();
      
      testProjectId = result.projectId;
    });

    test('should update project status', () => {
      const result = partnerService.updateProjectStatus(
        testProjectId,
        'in-progress',
        { notes: 'Project started' },
        'test-admin'
      );

      expect(result.success).toBe(true);
      expect(result.project.status).toBe('in-progress');
    });

    test('should complete project', () => {
      const result = partnerService.updateProjectStatus(
        testProjectId,
        'completed',
        { notes: 'Project completed', onTime: true, qualityScore: 95 },
        'test-admin'
      );

      expect(result.success).toBe(true);
      expect(result.project.status).toBe('completed');
    });
  });

  describe('Performance Management Flow', () => {
    test('should update performance rating', () => {
      const result = partnerService.updatePerformanceRating(testPartnerId, {
        rating: 4.5,
        comments: 'Excellent performance',
        category: 'project-delivery',
        quality: 95,
        timeliness: 90,
        communication: 92,
        professionalism: 94
      }, 'test-admin');

      expect(result.success).toBe(true);
      expect(result.newRating).toBeGreaterThan(0);
    });
  });

  describe('Communication Flow', () => {
    test('should log communication', () => {
      const result = partnerService.logCommunication(testPartnerId, {
        type: 'email',
        subject: 'Project Update',
        summary: 'Discussed project progress',
        participants: ['test-admin', 'partner-contact']
      }, 'test-admin');

      expect(result.success).toBe(true);
      expect(result.communicationId).toBeDefined();
    });
  });
});
