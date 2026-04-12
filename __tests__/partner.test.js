import PartnerCoordinationService from '../services/partnerCoordinationService.js';
import Partner from '../models/Partner.js';

jest.mock('../models/Partner.js');

describe('PartnerCoordinationService', () => {
  let service;

  beforeEach(() => {
    service = new PartnerCoordinationService();
    jest.clearAllMocks();
  });

  test('health status healthy', () => {
    const status = service.getHealthStatus();
    expect(status.status).toBe('healthy');
  });

  test('onboardPartner success', async () => {
    const data = { companyName: 'Academi', contactEmail: 'partner@academi.com' };
    const userId = 'user123';
    Partner.prototype.save.mockResolvedValue({ partnerId: 'PARTNER123', ...data });

    const result = await service.onboardPartner(data, userId);

    expect(Partner).toHaveBeenCalled();
    expect(result.success).toBe(true);
    expect(result.partnerId).toBe('PARTNER123');
  });

  test('onboardPartner error', async () => {
const data = { companyName: 'Test' };
    const userId = 'user123';

    Partner.mockImplementationOnce(() => {
      throw new Error('DB error');
    });

    const result = await service.onboardPartner(data, userId);

    expect(result.success).toBe(false);
  });

  test('getPartners success', async () => {
    const mockPartners = [{ partnerId: '1' }, { partnerId: '2' }];
    Partner.find.mockResolvedValue(mockPartners);

    const result = await service.getPartners();

    expect(Partner.find).toHaveBeenCalledWith({});
    expect(result.success).toBe(true);
    expect(result.count).toBe(2);
  });

  test('createPMCOperation via assignProject', async () => {
    const opData = { partnerId: 'testPartner', type: 'training', location: 'Shilo' };
    Partner.findOne.mockResolvedValue({ projects: [], save: jest.fn().mockResolvedValue() });
    Partner.prototype.projects.push = jest.fn();

    const result = await service.assignProject('testPartner', opData, 'user123');

    expect(result.success).toBe(true);
  });
});
