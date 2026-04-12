import { info, error } from '../utils/logger.js';
import PartnerCoordinationService from './partnerCoordinationService.js';
import PMCIntegrationService from './pmcIntegrationService.js';

export default class PrivateMilitaryService {
  constructor() {
    this.partnerService = new PartnerCoordinationService();
    this.pmcService = new PMCIntegrationService();
    info('PrivateMilitaryService initialized');
  }

  async onboardStrategicPartner(companyName, pmcType) {
    try {
      const data = {
        companyName,
        type: 'strategic-pmc',
        pmcType, // 'academi', 'g4s', 'dyncorp', etc.
        capabilities: this.getCapabilities(pmcType),
        status: 'onboarding'
      };
      const result = await this.partnerService.onboardPartner(data, 'system');
      info(`Strategic PMC ${companyName} (${pmcType}) onboarded`);
      return result;
    } catch (err) {
      error(`Strategic partner onboarding failed for ${companyName}:`, err);
      throw err;
    }
  }

  getCapabilities(pmcType) {
    const capabilities = {
      'academi': ['training', 'security', 'logistics', 'extraction'],
      'g4s': ['security', 'prison', 'cash', 'mining'],
      'dyncorp': ['aviation', 'logistics', 'it', 'training']
    };
    return capabilities[pmcType] || [];
  }

  async createStrategicOperation(partnerId, opType, location) {
    const data = {
      partnerId,
      type: opType,
      location,
      priority: 'high',
      strategic: true
    };
    return await this.pmcService.createCoordinatedOperation(data, 'strategic-system');
  }

  async getStrategicDashboard() {
    const partners = await this.partnerService.getPartners({ type: 'strategic-pmc' });
    const operations = await this.pmcService.getOperations({ strategic: true });
    return {
      partners: partners.partners,
      operations: operations.operations,
      stats: {
        totalStrategicPartners: partners.count,
        activeOperations: operations.count
      }
    };
  }

  getHealthStatus() {
    return { status: 'healthy', service: 'privateMilitary' };
  }
}

