import PMCIntegrationService from '../services/pmcIntegrationService.js';
import PMCOperation from '../models/PMCOperation.js';

jest.mock('../models/PMCOperation.js');

describe('PMCIntegrationService', () => {
  let service;

  beforeEach(() => {
    service = new PMCIntegrationService();
    jest.clearAllMocks();
  });

  test('health status healthy', () => {
    const status = service.getHealthStatus();
    expect(status.status).toBe('healthy');
  });

  test('createCoordinatedOperation success', async () => {
    const data = { type: 'training', location: 'Shilo' };
    const userId = 'user123';
    PMCOperation.prototype.save.mockResolvedValue({ operationId: 'OP123' });

    const result = await service.createCoordinatedOperation(data, userId);

    expect(result.success).toBe(true);
    expect(result.operationId).toBe('OP123');
  });

  test('getOperations success', async () => {
    const mockOps = [{ operationId: '1' }];
    PMCOperation.find.mockResolvedValue(mockOps);

    const result = await service.getOperations();

    expect(result.success).toBe(true);
    expect(result.count).toBe(1);
  });
});
