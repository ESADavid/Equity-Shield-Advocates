/**
 * PRIVATE MILITARY SERVICE
 * Manages private military contractors (PMCs) and operations
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 *
 * Integrated PMCs:
 * - Academi (formerly Blackwater)
 * - G4S Secure Solutions
 * - DynCorp International
 * - Triple Canopy
 * - Aegis Defence Services
 */

import HaitiStrategicService from './haitiStrategicService.js';
import { createLogger } from '../config/logger.js';

const logger = createLogger('Private-Military-Service');

class PrivateMilitaryService {
  constructor() {
    this.haitiStrategicService = new HaitiStrategicService();
    this.pmcContractors = new Map();
    this.activeDeployments = new Map();
    this.personnel = new Map();
    this.equipment = new Map();
    this.missions = new Map();

    // Initialize PMC contractors
    this.initializePMCContractors();

    logger.info('Private Military Service initialized');
  }

  /**
   * Initialize all PMC contractors
   */
  initializePMCContractors() {
    const contractors = [
      {
        id: 'pmc-academi',
        name: 'Academi',
        formerName: 'Blackwater',
        type: 'private_military_contractor',
        headquarters: 'United States',
        specializations: [
          'Security services',
          'Training',
          'Logistics support',
          'Risk management',
          'Intelligence services',
        ],
        capabilities: {
          personnel: 20000,
          globalPresence: true,
          maritimeSecurity: true,
          airSupport: true,
          cyberSecurity: true,
        },
        contract: {
          status: 'active',
          startDate: new Date().toISOString(),
          duration: 60, // months
          value: 500000000, // $500M
          renewalOption: true,
        },
        deployments: {
          haiti: {
            personnel: 500,
            role: 'Security and training',
            locations: ['Port-au-Prince', 'Cap-Haïtien'],
          },
        },
        performance: {
          rating: 4.5,
          missionsCompleted: 0,
          incidentRate: 0.02,
        },
      },
      {
        id: 'pmc-g4s',
        name: 'G4S Secure Solutions',
        type: 'private_military_contractor',
        headquarters: 'United Kingdom',
        specializations: [
          'Security services',
          'Risk consulting',
          'Cash solutions',
          'Technology solutions',
          'Facility management',
        ],
        capabilities: {
          personnel: 50000,
          globalPresence: true,
          technologyIntegration: true,
          intelligenceServices: true,
          crisisManagement: true,
        },
        contract: {
          status: 'active',
          startDate: new Date().toISOString(),
          duration: 48, // months
          value: 400000000, // $400M
          renewalOption: true,
        },
        deployments: {
          haiti: {
            personnel: 800,
            role: 'Infrastructure security',
            locations: ['Port-au-Prince', 'Gonaïves', 'Les Cayes'],
          },
        },
        performance: {
          rating: 4.7,
          missionsCompleted: 0,
          incidentRate: 0.01,
        },
      },
      {
        id: 'pmc-dyncorp',
        name: 'DynCorp International',
        type: 'private_military_contractor',
        headquarters: 'United States',
        specializations: [
          'Aviation services',
          'Law enforcement training',
          'Logistics',
          'Intelligence support',
          'Contingency operations',
        ],
        capabilities: {
          personnel: 15000,
          aviationFleet: true,
          trainingPrograms: true,
          logisticsSupport: true,
          technicalServices: true,
        },
        contract: {
          status: 'active',
          startDate: new Date().toISOString(),
          duration: 36, // months
          value: 350000000, // $350M
          renewalOption: true,
        },
        deployments: {
          haiti: {
            personnel: 400,
            role: 'Aviation and logistics',
            locations: ['Port-au-Prince Airport', 'Cap-Haïtien'],
          },
        },
        performance: {
          rating: 4.3,
          missionsCompleted: 0,
          incidentRate: 0.03,
        },
      },
      {
        id: 'pmc-triple-canopy',
        name: 'Triple Canopy',
        type: 'private_military_contractor',
        headquarters: 'United States',
        specializations: [
          'Security services',
          'Risk management',
          'Training',
          'Intelligence',
          'Crisis response',
        ],
        capabilities: {
          personnel: 8000,
          rapidDeployment: true,
          specialOperations: true,
          maritimeSecurity: true,
          counterTerrorism: true,
        },
        contract: {
          status: 'active',
          startDate: new Date().toISOString(),
          duration: 48, // months
          value: 300000000, // $300M
          renewalOption: true,
        },
        deployments: {
          haiti: {
            personnel: 300,
            role: 'Special operations and training',
            locations: ['Port-au-Prince', 'Jacmel'],
          },
        },
        performance: {
          rating: 4.6,
          missionsCompleted: 0,
          incidentRate: 0.015,
        },
      },
      {
        id: 'pmc-aegis',
        name: 'Aegis Defence Services',
        type: 'private_military_contractor',
        headquarters: 'United Kingdom',
        specializations: [
          'Risk management',
          'Security services',
          'Training',
          'Intelligence',
          'Maritime security',
        ],
        capabilities: {
          personnel: 12000,
          maritimeExpertise: true,
          intelligenceServices: true,
          trainingPrograms: true,
          globalOperations: true,
        },
        contract: {
          status: 'active',
          startDate: new Date().toISOString(),
          duration: 42, // months
          value: 320000000, // $320M
          renewalOption: true,
        },
        deployments: {
          haiti: {
            personnel: 350,
            role: 'Maritime and coastal security',
            locations: ['Port-au-Prince Port', 'Cap-Haïtien Port', 'Jacmel'],
          },
        },
        performance: {
          rating: 4.4,
          missionsCompleted: 0,
          incidentRate: 0.02,
        },
      },
    ];

    for (const contractor of contractors) {
      this.pmcContractors.set(contractor.id, {
        ...contractor,
        createdAt: new Date().toISOString(),
        lastUpdated: new Date().toISOString(),
      });
    }

    logger.info(`Initialized ${contractors.length} PMC contractors`);
  }

  /**
   * Get all PMC contractors
   * @param {Object} filters - Filter criteria
   * @returns {Object} Contractors list
   */
  getPMCContractors(filters = {}) {
    try {
      let contractors = Array.from(this.pmcContractors.values());

      if (filters.status) {
        contractors = contractors.filter(
          (c) => c.contract.status === filters.status
        );
      }

      if (filters.specialization) {
        contractors = contractors.filter((c) =>
          c.specializations.some((s) =>
            s.toLowerCase().includes(filters.specialization.toLowerCase())
          )
        );
      }

      return {
        success: true,
        contractors: contractors.map((c) => ({
          id: c.id,
          name: c.name,
          type: c.type,
          headquarters: c.headquarters,
          specializations: c.specializations,
          personnel: c.capabilities.personnel,
          contractValue: c.contract.value,
          contractStatus: c.contract.status,
          haitiDeployment: c.deployments.haiti,
          performance: c.performance,
        })),
        count: contractors.length,
        totalPersonnel: contractors.reduce(
          (sum, c) => sum + (c.deployments.haiti?.personnel || 0),
          0
        ),
        totalContractValue: contractors.reduce(
          (sum, c) => sum + c.contract.value,
          0
        ),
      };
    } catch (error) {
      logger.error('Error getting PMC contractors:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Deploy PMC personnel to a location
   * @param {string} pmcId - PMC contractor ID
   * @param {Object} deploymentData - Deployment details
   * @param {string} userId - User ID authorizing deployment
   * @returns {Object} Deployment result
   */
  deployPersonnel(pmcId, deploymentData, userId) {
    try {
      const contractor = this.pmcContractors.get(pmcId);

      if (!contractor) {
        return {
          success: false,
          error: 'PMC contractor not found',
        };
      }

      if (contractor.contract.status !== 'active') {
        return {
          success: false,
          error: 'Contract is not active',
        };
      }

      const deploymentId = `DEP-${pmcId}-${Date.now()}`;

      const deployment = {
        id: deploymentId,
        pmcId: pmcId,
        pmcName: contractor.name,
        location: deploymentData.location,
        personnel: deploymentData.personnel,
        role: deploymentData.role,
        mission: deploymentData.mission,
        startDate: deploymentData.startDate || new Date().toISOString(),
        endDate: deploymentData.endDate,
        status: 'active',
        equipment: deploymentData.equipment || [],
        authorizedBy: userId,
        createdAt: new Date().toISOString(),
      };

      this.activeDeployments.set(deploymentId, deployment);

      logger.info(
        `Deployed ${deploymentData.personnel} personnel from ${contractor.name} to ${deploymentData.location}`
      );

      return {
        success: true,
        deployment: deployment,
        message: 'Personnel deployed successfully',
      };
    } catch (error) {
      logger.error('Error deploying personnel:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Create a new mission for PMC contractors
   * @param {Object} missionData - Mission details
   * @param {string} userId - User ID creating mission
   * @returns {Object} Mission creation result
   */
  createMission(missionData, userId) {
    try {
      const missionId = `MISSION-${Date.now()}`;

      const mission = {
        id: missionId,
        name: missionData.name,
        type: missionData.type, // security, training, logistics, intelligence, etc.
        priority: missionData.priority || 'medium',
        description: missionData.description,
        objectives: missionData.objectives || [],
        location: missionData.location,
        assignedPMCs: missionData.assignedPMCs || [],
        personnel: missionData.personnel || 0,
        equipment: missionData.equipment || [],
        startDate: missionData.startDate || new Date().toISOString(),
        endDate: missionData.endDate,
        status: 'planned',
        budget: missionData.budget || 0,
        createdBy: userId,
        createdAt: new Date().toISOString(),
        updates: [],
      };

      this.missions.set(missionId, mission);

      logger.info(`Mission created: ${missionId} - ${mission.name}`);

      return {
        success: true,
        mission: mission,
        message: 'Mission created successfully',
      };
    } catch (error) {
      logger.error('Error creating mission:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Update mission status
   * @param {string} missionId - Mission ID
   * @param {string} status - New status
   * @param {Object} updateData - Additional update data
   * @param {string} userId - User ID performing update
   * @returns {Object} Update result
   */
  updateMissionStatus(missionId, status, updateData = {}, userId) {
    try {
      const mission = this.missions.get(missionId);

      if (!mission) {
        return {
          success: false,
          error: 'Mission not found',
        };
      }

      mission.status = status;
      mission.lastUpdated = new Date().toISOString();
      mission.lastUpdatedBy = userId;

      mission.updates.push({
        timestamp: new Date().toISOString(),
        status: status,
        updatedBy: userId,
        notes: updateData.notes || '',
        data: updateData,
      });

      if (status === 'completed') {
        mission.completionDate = new Date().toISOString();

        // Update PMC performance metrics
        mission.assignedPMCs.forEach((pmcId) => {
          const contractor = this.pmcContractors.get(pmcId);
          if (contractor) {
            contractor.performance.missionsCompleted += 1;
          }
        });
      }

      logger.info(`Mission ${missionId} updated to status: ${status}`);

      return {
        success: true,
        mission: mission,
        message: `Mission status updated to ${status}`,
      };
    } catch (error) {
      logger.error('Error updating mission status:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get joint force integration status (Haiti-Burkina Faso + PMCs)
   * @returns {Object} Joint force status
   */
  getJointForceStatus() {
    try {
      // Get Haiti military assets from strategic service
      const haitiPortfolio = this.haitiStrategicService.getHaitiPortfolio();
      const haitiMilitary = haitiPortfolio.military;

      // Get PMC contractors
      const pmcContractors = Array.from(this.pmcContractors.values());

      // Calculate total force
      const totalPMCPersonnel = pmcContractors.reduce(
        (sum, pmc) => sum + (pmc.deployments.haiti?.personnel || 0),
        0
      );

      const haitiNavyPersonnel =
        haitiMilitary.find((m) => m.id === 'haiti-navy')?.personnel || 0;
      const haitiArmyPersonnel =
        haitiMilitary.find((m) => m.id === 'haiti-army')?.personnel || 0;
      const haitiAirForcePersonnel =
        haitiMilitary.find((m) => m.id === 'haiti-air-force')?.personnel || 0;
      const burkinaJointForce = haitiMilitary.find(
        (m) => m.id === 'haiti-burkina-joint-force'
      );

      const totalForce = {
        haitiNavy: haitiNavyPersonnel,
        haitiArmy: haitiArmyPersonnel,
        haitiAirForce: haitiAirForcePersonnel,
        pmcContractors: totalPMCPersonnel,
        burkinaFasoJoint: 5000, // From joint force agreement
        total:
          haitiNavyPersonnel +
          haitiArmyPersonnel +
          haitiAirForcePersonnel +
          totalPMCPersonnel +
          5000,
      };

      return {
        success: true,
        jointForce: {
          totalPersonnel: totalForce.total,
          breakdown: totalForce,
          pmcContractors: pmcContractors.length,
          activeDeployments: this.activeDeployments.size,
          activeMissions: this.missions.size,
          capabilities: [
            'Rapid deployment force',
            'Peacekeeping operations',
            'Counter-terrorism',
            'Maritime security',
            'Cyber defense',
            'Training and capacity building',
            'Intelligence operations',
            'Crisis response',
          ],
          integration: {
            sharedCommand:
              burkinaJointForce?.integration.sharedCommand || false,
            jointTraining:
              burkinaJointForce?.integration.jointTraining || false,
            intelligenceSharing:
              burkinaJointForce?.integration.intelligenceSharing || false,
            mutualDefense:
              burkinaJointForce?.integration.mutualDefense || false,
          },
        },
      };
    } catch (error) {
      logger.error('Error getting joint force status:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get PMC contractor details
   * @param {string} pmcId - PMC contractor ID
   * @returns {Object} Contractor details
   */
  getPMCDetails(pmcId) {
    try {
      const contractor = this.pmcContractors.get(pmcId);

      if (!contractor) {
        return {
          success: false,
          error: 'PMC contractor not found',
        };
      }

      // Get active deployments for this PMC
      const deployments = Array.from(this.activeDeployments.values()).filter(
        (d) => d.pmcId === pmcId
      );

      // Get missions assigned to this PMC
      const missions = Array.from(this.missions.values()).filter((m) =>
        m.assignedPMCs.includes(pmcId)
      );

      return {
        success: true,
        contractor: contractor,
        activeDeployments: deployments,
        missions: missions,
        summary: {
          totalDeployments: deployments.length,
          totalMissions: missions.length,
          activeMissions: missions.filter((m) => m.status === 'active').length,
          completedMissions: missions.filter((m) => m.status === 'completed')
            .length,
          personnelDeployed: deployments.reduce(
            (sum, d) => sum + d.personnel,
            0
          ),
        },
      };
    } catch (error) {
      logger.error('Error getting PMC details:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get all active missions
   * @param {Object} filters - Filter criteria
   * @returns {Object} Missions list
   */
  getActiveMissions(filters = {}) {
    try {
      let missions = Array.from(this.missions.values());

      if (filters.status) {
        missions = missions.filter((m) => m.status === filters.status);
      }

      if (filters.type) {
        missions = missions.filter((m) => m.type === filters.type);
      }

      if (filters.priority) {
        missions = missions.filter((m) => m.priority === filters.priority);
      }

      return {
        success: true,
        missions: missions,
        count: missions.length,
        summary: {
          planned: missions.filter((m) => m.status === 'planned').length,
          active: missions.filter((m) => m.status === 'active').length,
          completed: missions.filter((m) => m.status === 'completed').length,
          cancelled: missions.filter((m) => m.status === 'cancelled').length,
        },
      };
    } catch (error) {
      logger.error('Error getting active missions:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get service statistics
   * @returns {Object} Service statistics
   */
  getStatistics() {
    try {
      const contractors = Array.from(this.pmcContractors.values());
      const deployments = Array.from(this.activeDeployments.values());
      const missions = Array.from(this.missions.values());

      return {
        success: true,
        statistics: {
          contractors: {
            total: contractors.length,
            active: contractors.filter((c) => c.contract.status === 'active')
              .length,
            totalContractValue: contractors.reduce(
              (sum, c) => sum + c.contract.value,
              0
            ),
          },
          personnel: {
            totalAvailable: contractors.reduce(
              (sum, c) => sum + c.capabilities.personnel,
              0
            ),
            deployed: contractors.reduce(
              (sum, c) => sum + (c.deployments.haiti?.personnel || 0),
              0
            ),
            deploymentRate: 0, // Will be calculated
          },
          deployments: {
            active: deployments.length,
            locations: [...new Set(deployments.map((d) => d.location))].length,
          },
          missions: {
            total: missions.length,
            active: missions.filter((m) => m.status === 'active').length,
            completed: missions.filter((m) => m.status === 'completed').length,
            successRate:
              missions.length > 0
                ? (
                    (missions.filter((m) => m.status === 'completed').length /
                      missions.length) *
                    100
                  ).toFixed(2) + '%'
                : '0%',
          },
          performance: {
            averageRating: (
              contractors.reduce((sum, c) => sum + c.performance.rating, 0) /
              contractors.length
            ).toFixed(2),
            averageIncidentRate: (
              contractors.reduce(
                (sum, c) => sum + c.performance.incidentRate,
                0
              ) / contractors.length
            ).toFixed(4),
          },
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Error getting statistics:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'operational',
      service: 'Private Military Service',
      pmcContractors: this.pmcContractors.size,
      activeDeployments: this.activeDeployments.size,
      activeMissions: this.missions.size,
      lastCheck: new Date().toISOString(),
    };
  }

  /**
   * Export complete PMC data
   * @returns {Object} Complete PMC data
   */
  exportPMCData() {
    return {
      contractors: this.getPMCContractors(),
      jointForce: this.getJointForceStatus(),
      statistics: this.getStatistics(),
      healthStatus: this.getHealthStatus(),
      exportTimestamp: new Date().toISOString(),
      classification: 'Strategic Military - Confidential',
      owner: 'OWLBAN GROUP / House of David',
    };
  }
}

export default PrivateMilitaryService;
