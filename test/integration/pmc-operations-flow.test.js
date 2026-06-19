/**
 * PMC OPERATIONS INTEGRATION TEST
 * Tests complete PMC coordinated operations flow
 */

import PMCIntegrationService from '../../services/pmcIntegrationService.js';

describe('PMC Operations Integration Flow', () => {
  let pmcService;
  let testOperationId;

  beforeAll(() => {
    pmcService = new PMCIntegrationService();
  });

  describe('Operation Creation Flow', () => {
    test('should create coordinated operation', () => {
      const result = pmcService.createCoordinatedOperation(
        {
          name: 'Test Security Operation',
          type: 'security',
          objective: 'Secure test facility',
          description: 'Multi-PMC security operation',
          location: 'Test Location',
          startDate: new Date().toISOString(),
          duration: 30,
          assignedPMCs: ['pmc-academi', 'pmc-g4s'],
          pmcRoles: {
            'pmc-academi': {
              name: 'Perimeter Security',
              type: 'security',
              description: 'Secure outer perimeter',
              personnel: 50,
              budget: 100000,
            },
            'pmc-g4s': {
              name: 'Facility Security',
              type: 'security',
              description: 'Secure facility interior',
              personnel: 30,
              budget: 75000,
            },
          },
          personnel: { required: 80 },
          budget: 175000,
        },
        'test-admin'
      );

      expect(result.success).toBe(true);
      expect(result.operationId).toBeDefined();

      testOperationId = result.operationId;
    });
  });

  describe('Resource Allocation Flow', () => {
    test('should allocate resources to operation', () => {
      const result = pmcService.allocateResources(
        testOperationId,
        {
          personnel: { security: 50, support: 10 },
          equipment: ['vehicles', 'communications'],
          budget: 150000,
        },
        'test-admin'
      );

      expect(result.success).toBe(true);
      expect(result.allocationId).toBeDefined();
    });
  });

  describe('Operation Status Flow', () => {
    test('should update operation status to active', () => {
      const result = pmcService.updateOperationStatus(
        testOperationId,
        'active',
        { notes: 'Operation commenced' },
        'test-admin'
      );

      expect(result.success).toBe(true);
      expect(result.operation.status).toBe('active');
    });

    test('should complete operation', () => {
      const result = pmcService.updateOperationStatus(
        testOperationId,
        'completed',
        { notes: 'Operation completed successfully' },
        'test-admin'
      );

      expect(result.success).toBe(true);
      expect(result.operation.status).toBe('completed');
    });
  });

  describe('Training Program Flow', () => {
    test('should create training program', () => {
      const result = pmcService.createTrainingProgram(
        {
          name: 'Test Training Program',
          type: 'tactical',
          description: 'Test tactical training',
          targetPMCs: ['pmc-academi'],
          targetPersonnel: 20,
          duration: 40,
          location: 'Training Facility',
        },
        'test-admin'
      );

      expect(result.success).toBe(true);
      expect(result.programId).toBeDefined();
    });
  });
});
