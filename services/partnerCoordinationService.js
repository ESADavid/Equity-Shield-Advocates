/**
 * PARTNER COORDINATION SERVICE
 * Manages partner onboarding, coordination, and performance tracking
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import { info, error, warn, debug } from '../utils/loggerWrapper.js';
import Partner from '../models/Partner.js';
import Citizen from '../models/Citizen.js';
import multiChannelNotificationService from './multiChannelNotificationService.js';
import auditService from './auditService.js';

class PartnerCoordinationService {
  constructor() {
    this.PARTNER_TYPES = ['PMC', 'education', 'service', 'military', 'healthcare', 'infrastructure'];
    this.ONBOARDING_STAGES = ['application', 'review', 'approval', 'setup', 'active'];
    this.PERFORMANCE_THRESHOLDS = {
      excellent: 95,
      good: 85,
      satisfactory: 70,
      needs_improvement: 50
    };

    info('Partner Coordination Service initialized');
  }

  /**
   * Onboard a new partner
   * @param {Object} partnerData - Partner information
   * @param {string} userId - User initiating onboarding
   * @returns {Promise<Object>} Onboarding result
   */
  async onboardPartner(partnerData, userId) {
    try {
      info(`Starting partner onboarding: ${partnerData.name}`);

      // Validate partner data
      this.validatePartnerData(partnerData);

      // Check for existing partner
      const existingPartner = await Partner.findOne({
        $or: [
          { name: partnerData.name },
          { 'contactInfo.email': partnerData.contactInfo?.email }
        ]
      });

      if (existingPartner) {
        throw new Error('Partner with this name or email already exists');
      }

      // Create partner record
      const partner = new Partner({
        name: partnerData.name,
        type: partnerData.type,
        status: 'pending',
        contactInfo: partnerData.contactInfo,
        services: partnerData.services || [],
        contracts: [],
        onboardingStage: 'application',
        metadata: {
          onboardedBy: userId,
          applicationDate: new Date()
        }
      });

      await partner.save();

      // Log onboarding initiation
      await auditService.logActivity(userId, 'PARTNER_ONBOARDING_INITIATED', {
        partnerId: partner._id,
        partnerName: partner.name,
        partnerType: partner.type
      });

      // Send notification
      await this.sendOnboardingNotification(partner, 'initiated');

      info(`Partner onboarding initiated: ${partner.name} (${partner._id})`);
      return {
        success: true,
        partnerId: partner._id,
        status: partner.status,
        message: 'Partner onboarding initiated successfully'
      };

    } catch (err) {
      error('Partner onboarding failed:', err);
      throw err;
    }
  }

  /**
   * Coordinate services with partner
   * @param {string} partnerId - Partner ID
   * @param {string} serviceType - Type of service to coordinate
   * @param {Object} serviceData - Service coordination data
   * @returns {Promise<Object>} Coordination result
   */
  async coordinateServices(partnerId, serviceType, serviceData = {}) {
    try {
      const partner = await Partner.findById(partnerId);
      if (!partner) {
        throw new Error('Partner not found');
      }

      if (partner.status !== 'active') {
        throw new Error('Partner is not active');
      }

      info(`Coordinating ${serviceType} service with partner: ${partner.name}`);

      const coordinationResult = await this.executeServiceCoordination(
        partner,
        serviceType,
        serviceData
      );

      // Update partner performance metrics
      await this.updatePartnerPerformance(partner._id, serviceType, coordinationResult.success);

      // Log coordination
      await auditService.logActivity('system', 'SERVICE_COORDINATION', {
        partnerId: partner._id,
        serviceType,
        success: coordinationResult.success,
        details: coordinationResult.details
      });

      return {
        success: coordinationResult.success,
        partnerId: partner._id,
        serviceType,
        result: coordinationResult.details,
        timestamp: new Date()
      };

    } catch (err) {
      error(`Service coordination failed for partner ${partnerId}:`, err);
      throw err;
    }
  }

  /**
   * Execute specific service coordination
   * @param {Object} partner - Partner document
   * @param {string} serviceType - Service type
   * @param {Object} serviceData - Service data
   * @returns {Promise<Object>} Coordination result
   */
  async executeServiceCoordination(partner, serviceType, serviceData) {
    try {
      switch (serviceType) {
        case 'PMC':
          return await this.coordinatePMCService(partner, serviceData);
        case 'education':
          return await this.coordinateEducationService(partner, serviceData);
        case 'military':
          return await this.coordinateMilitaryService(partner, serviceData);
        case 'healthcare':
          return await this.coordinateHealthcareService(partner, serviceData);
        case 'infrastructure':
          return await this.coordinateInfrastructureService(partner, serviceData);
        default:
          return await this.coordinateGenericService(partner, serviceType, serviceData);
      }
    } catch (err) {
      error(`Service coordination execution failed:`, err);
      return {
        success: false,
        details: { error: err.message }
      };
    }
  }

  /**
   * Coordinate PMC (Private Military Company) services
   */
  async coordinatePMCService(partner, serviceData) {
    // Implementation for PMC coordination
    // This would involve military training coordination, equipment, etc.

    const result = {
      success: true,
      details: {
        serviceType: 'PMC',
        coordinatedElements: ['training', 'equipment', 'logistics'],
        estimatedCompletion: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        assignedPersonnel: serviceData.personnelCount || 0
      }
    };

    info(`PMC service coordinated for partner: ${partner.name}`);
    return result;
  }

  /**
   * Coordinate education services
   */
  async coordinateEducationService(partner, serviceData) {
    // Implementation for education service coordination
    // This would involve curriculum delivery, instructor assignment, etc.

    const result = {
      success: true,
      details: {
        serviceType: 'education',
        coursesAssigned: serviceData.courses || [],
        instructorsAssigned: serviceData.instructors || 0,
        facilitiesAllocated: serviceData.facilities || [],
        startDate: serviceData.startDate || new Date()
      }
    };

    info(`Education service coordinated for partner: ${partner.name}`);
    return result;
  }

  /**
   * Coordinate military services
   */
  async coordinateMilitaryService(partner, serviceData) {
    // Implementation for military service coordination

    const result = {
      success: true,
      details: {
        serviceType: 'military',
        unitsAssigned: serviceData.units || 0,
        missionType: serviceData.missionType || 'training',
        duration: serviceData.duration || 0,
        equipmentProvided: serviceData.equipment || []
      }
    };

    info(`Military service coordinated for partner: ${partner.name}`);
    return result;
  }

  /**
   * Coordinate healthcare services
   */
  async coordinateHealthcareService(partner, serviceData) {
    // Implementation for healthcare service coordination

    const result = {
      success: true,
      details: {
        serviceType: 'healthcare',
        facilities: serviceData.facilities || [],
        medicalStaff: serviceData.staff || 0,
        services: serviceData.services || [],
        coverageArea: serviceData.coverageArea || 'local'
      }
    };

    info(`Healthcare service coordinated for partner: ${partner.name}`);
    return result;
  }

  /**
   * Coordinate infrastructure services
   */
  async coordinateInfrastructureService(partner, serviceData) {
    // Implementation for infrastructure service coordination

    const result = {
      success: true,
      details: {
        serviceType: 'infrastructure',
        projects: serviceData.projects || [],
        budget: serviceData.budget || 0,
        timeline: serviceData.timeline || 0,
        resourcesAllocated: serviceData.resources || []
      }
    };

    info(`Infrastructure service coordinated for partner: ${partner.name}`);
    return result;
  }

  /**
   * Coordinate generic services
   */
  async coordinateGenericService(partner, serviceType, serviceData) {
    const result = {
      success: true,
      details: {
        serviceType,
        coordinatedAt: new Date(),
        parameters: serviceData,
        status: 'coordinated'
      }
    };

    info(`Generic service coordinated for partner: ${partner.name} - ${serviceType}`);
    return result;
  }

  /**
   * Update partner performance metrics
   * @param {string} partnerId - Partner ID
   * @param {string} serviceType - Service type
   * @param {boolean} success - Whether coordination was successful
   */
  async updatePartnerPerformance(partnerId, serviceType, success) {
    try {
      const partner = await Partner.findById(partnerId);
      if (!partner) return;

      // Update performance metrics
      if (!partner.performance) {
        partner.performance = {
          totalCoordinations: 0,
          successfulCoordinations: 0,
          serviceBreakdown: {},
          lastActivity: new Date()
        };
      }

      partner.performance.totalCoordinations++;
      partner.performance.lastActivity = new Date();

      if (success) {
        partner.performance.successfulCoordinations++;
      }

      // Update service-specific metrics
      if (!partner.performance.serviceBreakdown[serviceType]) {
        partner.performance.serviceBreakdown[serviceType] = {
          total: 0,
          successful: 0
        };
      }

      partner.performance.serviceBreakdown[serviceType].total++;
      if (success) {
        partner.performance.serviceBreakdown[serviceType].successful++;
      }

      // Calculate overall performance score
      partner.performance.overallScore = Math.round(
        (partner.performance.successfulCoordinations / partner.performance.totalCoordinations) * 100
      );

      await partner.save();

      debug(`Updated performance for partner ${partnerId}: ${partner.performance.overallScore}%`);
    } catch (err) {
      error(`Failed to update partner performance for ${partnerId}:`, err);
    }
  }

  /**
   * Get partner performance report
   * @param {string} partnerId - Partner ID
   * @returns {Promise<Object>} Performance report
   */
  async getPartnerPerformance(partnerId) {
    try {
      const partner = await Partner.findById(partnerId);
      if (!partner) {
        throw new Error('Partner not found');
      }

      const performance = partner.performance || {};
      const score = performance.overallScore || 0;

      let rating = 'needs_improvement';
      if (score >= this.PERFORMANCE_THRESHOLDS.excellent) rating = 'excellent';
      else if (score >= this.PERFORMANCE_THRESHOLDS.good) rating = 'good';
      else if (score >= this.PERFORMANCE_THRESHOLDS.satisfactory) rating = 'satisfactory';

      return {
        partnerId,
        partnerName: partner.name,
        overallScore: score,
        rating,
        totalCoordinations: performance.totalCoordinations || 0,
        successfulCoordinations: performance.successfulCoordinations || 0,
        serviceBreakdown: performance.serviceBreakdown || {},
        lastActivity: performance.lastActivity,
        recommendations: this.generatePerformanceRecommendations(score, performance)
      };
    } catch (err) {
      error(`Failed to get partner performance for ${partnerId}:`, err);
      throw err;
    }
  }

  /**
   * Generate performance recommendations
   * @param {number} score - Performance score
   * @param {Object} performance - Performance data
   * @returns {Array} Recommendations
   */
  generatePerformanceRecommendations(score, performance) {
    const recommendations = [];

    if (score < this.PERFORMANCE_THRESHOLDS.satisfactory) {
      recommendations.push('Implement additional training programs');
      recommendations.push('Review and optimize service coordination processes');
      recommendations.push('Increase monitoring and quality control measures');
    } else if (score < this.PERFORMANCE_THRESHOLDS.good) {
      recommendations.push('Focus on continuous improvement initiatives');
      recommendations.push('Expand service capabilities');
    } else if (score < this.PERFORMANCE_THRESHOLDS.excellent) {
      recommendations.push('Maintain high performance standards');
      recommendations.push('Consider expanding partnership scope');
    } else {
      recommendations.push('Excellent performance - consider as model partner');
      recommendations.push('Share best practices with other partners');
    }

    return recommendations;
  }

  /**
   * Validate partner data
   * @param {Object} data - Partner data to validate
   */
  validatePartnerData(data) {
    if (!data.name || data.name.trim().length === 0) {
      throw new Error('Partner name is required');
    }

    if (!data.type || !this.PARTNER_TYPES.includes(data.type)) {
      throw new Error(`Invalid partner type. Must be one of: ${this.PARTNER_TYPES.join(', ')}`);
    }

    if (!data.contactInfo || !data.contactInfo.email) {
      throw new Error('Contact information with email is required');
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.contactInfo.email)) {
      throw new Error('Invalid email format');
    }
  }

  /**
   * Send onboarding notification
   * @param {Object} partner - Partner document
   * @param {string} stage - Onboarding stage
   */
  async sendOnboardingNotification(partner, stage) {
    try {
      const messages = {
        initiated: {
          title: 'Partner Onboarding Initiated',
          message: `New partner ${partner.name} has been registered for onboarding.`
        },
        approved: {
          title: 'Partner Approved',
          message: `Partner ${partner.name} has been approved and is ready for setup.`
        },
        active: {
          title: 'Partner Activated',
          message: `Partner ${partner.name} is now active and ready for service coordination.`
        }
      };

      const notification = messages[stage];
      if (notification) {
        await multiChannelNotificationService.send({
          type: 'PARTNER_NOTIFICATION',
          priority: 'medium',
          title: notification.title,
          message: notification.message,
          recipients: ['partner_managers', 'system_administrators'],
          metadata: {
            partnerId: partner._id,
            partnerName: partner.name,
            stage
          }
        });
      }
    } catch (err) {
      warn('Failed to send onboarding notification:', err);
    }
  }

  /**
   * Get partner coordination statistics
   * @returns {Promise<Object>} Statistics
   */
  async getCoordinationStats() {
    try {
      const stats = await Partner.aggregate([
        {
          $group: {
            _id: null,
            totalPartners: { $sum: 1 },
            activePartners: {
              $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
            },
            byType: {
              $push: {
                type: '$type',
                status: '$status',
                performance: '$performance.overallScore'
              }
            },
            totalCoordinations: { $sum: '$performance.totalCoordinations' },
            avgPerformance: { $avg: '$performance.overallScore' }
          }
        }
      ]);

      if (stats.length === 0) {
        return {
          totalPartners: 0,
          activePartners: 0,
          totalCoordinations: 0,
          avgPerformance: 0,
          byType: []
        };
      }

      const result = stats[0];

      // Group by type
      const typeStats = {};
      result.byType.forEach(partner => {
        if (!typeStats[partner.type]) {
          typeStats[partner.type] = {
            total: 0,
            active: 0,
            avgPerformance: 0,
            performances: []
          };
        }
        typeStats[partner.type].total++;
        if (partner.status === 'active') {
          typeStats[partner.type].active++;
        }
        if (partner.performance) {
          typeStats[partner.type].performances.push(partner.performance);
        }
      });

      // Calculate averages
      Object.keys(typeStats).forEach(type => {
        const performances = typeStats[type].performances;
        if (performances.length > 0) {
          typeStats[type].avgPerformance = Math.round(
            performances.reduce((sum, p) => sum + p, 0) / performances.length
          );
        }
        delete typeStats[type].performances;
      });

      result.byType = Object.entries(typeStats).map(([type, stats]) => ({
        type,
        ...stats
      }));

      return result;
    } catch (err) {
      error('Failed to get coordination statistics:', err);
      throw err;
    }
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'operational',
      service: 'Partner Coordination Service',
      partnerTypes: this.PARTNER_TYPES.length,
      onboardingStages: this.ONBOARDING_STAGES.length,
      performanceThresholds: this.PERFORMANCE_THRESHOLDS,
      lastCheck: new Date().toISOString()
    };
  }
}

export default new PartnerCoordinationService();
