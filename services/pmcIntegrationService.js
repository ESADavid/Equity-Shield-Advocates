/**
 * PMC INTEGRATION SERVICE
 * Enhanced integration with Private Military Contractors
 * Part of Phase 2: Heaven on Earth Implementation
 *
 * Integrates with existing privateMilitaryService.js
 * Provides enhanced coordination, resource allocation, and mission management
 */

import { createLogger } from '../config/logger.js';
import PrivateMilitaryService from './privateMilitaryService.js';

const logger = createLogger('PMC-Integration-Service');

class PMCIntegrationService {
  constructor() {
    this.pmcService = new PrivateMilitaryService();
    this.operations = new Map();
    this.resourceAllocations = new Map();
    this.missionCoordination = new Map();
    this.trainingPrograms = new Map();

    logger.info('PMC Integration Service initialized');
  }

  /**
   * Create coordinated operation across multiple PMCs
   * @param {Object} operationData - Operation details
   * @param {string} userId - User ID
   * @returns {Object} Operation creation result
   */
  createCoordinatedOperation(operationData, userId) {
    try {
      const operationId = `OP-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      const operation = {
        operationId: operationId,
        name: operationData.name,
        type: operationData.type, // security, training, logistics, humanitarian, etc.
        classification: operationData.classification || 'confidential',
        priority: operationData.priority || 'medium',
        status: 'planning',

        // Operation Details
        objective: operationData.objective,
        description: operationData.description,
        location: operationData.location,
        startDate: operationData.startDate,
        endDate: operationData.endDate,
        duration: operationData.duration,

        // PMC Assignments
        assignedPMCs: operationData.assignedPMCs || [],
        pmcRoles: operationData.pmcRoles || {},

        // Resources
        personnel: {
          required: operationData.personnel?.required || 0,
          allocated: 0,
          breakdown: operationData.personnel?.breakdown || {},
        },
        equipment: {
          required: operationData.equipment?.required || [],
          allocated: [],
          status: {},
        },
        budget: {
          total: operationData.budget || 0,
          allocated: 0,
          spent: 0,
          breakdown: {},
        },

        // Coordination
        commandStructure: operationData.commandStructure || {},
        communicationProtocol: operationData.communicationProtocol || {},
        coordinationMeetings: [],

        // Phases
        phases: operationData.phases || [],
        currentPhase: null,

        // Risk Assessment
        riskLevel: operationData.riskLevel || 'medium',
        threats: operationData.threats || [],
        mitigationStrategies: operationData.mitigationStrategies || [],

        // Reporting
        reports: [],
        incidents: [],
        achievements: [],

        // Metadata
        createdBy: userId,
        createdAt: new Date().toISOString(),
        lastUpdated: new Date().toISOString(),
        updates: [],
      };

      this.operations.set(operationId, operation);

      // Create missions for each assigned PMC
      for (const pmcId of operation.assignedPMCs) {
        const role = operation.pmcRoles[pmcId];
        this.createPMCMission(operationId, pmcId, role, userId);
      }

      logger.info(
        `Coordinated operation created: ${operationId} - ${operation.name}`
      );

      return {
        success: true,
        operationId: operationId,
        operation: operation,
        message: 'Coordinated operation created successfully',
      };
    } catch (error) {
      logger.error('Error creating coordinated operation:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Create mission for specific PMC within an operation
   * @param {string} operationId - Operation ID
   * @param {string} pmcId - PMC ID
   * @param {Object} role - PMC role details
   * @param {string} userId - User ID
   * @returns {Object} Mission creation result
   */
  createPMCMission(operationId, pmcId, role, userId) {
    try {
      const operation = this.operations.get(operationId);

      if (!operation) {
        return {
          success: false,
          error: 'Operation not found',
        };
      }

      const missionData = {
        name: `${operation.name} - ${role.name}`,
        type: role.type,
        priority: operation.priority,
        description: role.description,
        objectives: role.objectives || [],
        location: operation.location,
        assignedPMCs: [pmcId],
        personnel: role.personnel || 0,
        equipment: role.equipment || [],
        startDate: operation.startDate,
        endDate: operation.endDate,
        budget: role.budget || 0,
      };

      const missionResult = this.pmcService.createMission(missionData, userId);

      if (missionResult.success) {
        // Link mission to operation
        if (!this.missionCoordination.has(operationId)) {
          this.missionCoordination.set(operationId, []);
        }
        this.missionCoordination
          .get(operationId)
          .push(missionResult.mission.id);

        logger.info(
          `PMC mission created for operation ${operationId}: ${missionResult.mission.id}`
        );
      }

      return missionResult;
    } catch (error) {
      logger.error('Error creating PMC mission:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Allocate resources to operation
   * @param {string} operationId - Operation ID
   * @param {Object} resources - Resources to allocate
   * @param {string} userId - User ID
   * @returns {Object} Allocation result
   */
  allocateResources(operationId, resources, userId) {
    try {
      const operation = this.operations.get(operationId);

      if (!operation) {
        return {
          success: false,
          error: 'Operation not found',
        };
      }

      const allocationId = `ALLOC-${operationId}-${Date.now()}`;

      const allocation = {
        allocationId: allocationId,
        operationId: operationId,
        timestamp: new Date().toISOString(),
        allocatedBy: userId,

        personnel: resources.personnel || {},
        equipment: resources.equipment || [],
        budget: resources.budget || 0,

        status: 'allocated',
        notes: resources.notes || '',
      };

      // Update operation resources
      if (resources.personnel) {
        operation.personnel.allocated += Object.values(
          resources.personnel
        ).reduce((sum, val) => sum + val, 0);
      }

      if (resources.equipment) {
        operation.equipment.allocated.push(...resources.equipment);
      }

      if (resources.budget) {
        operation.budget.allocated += resources.budget;
      }

      this.resourceAllocations.set(allocationId, allocation);

      operation.updates.push({
        timestamp: new Date().toISOString(),
        type: 'resource_allocation',
        performedBy: userId,
        details: allocation,
      });

      logger.info(
        `Resources allocated to operation ${operationId}: ${allocationId}`
      );

      return {
        success: true,
        allocationId: allocationId,
        allocation: allocation,
        operationStatus: {
          personnelAllocated: operation.personnel.allocated,
          personnelRequired: operation.personnel.required,
          budgetAllocated: operation.budget.allocated,
          budgetTotal: operation.budget.total,
        },
      };
    } catch (error) {
      logger.error('Error allocating resources:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Update operation status
   * @param {string} operationId - Operation ID
   * @param {string} status - New status
   * @param {Object} updateData - Additional update data
   * @param {string} userId - User ID
   * @returns {Object} Update result
   */
  updateOperationStatus(operationId, status, updateData = {}, userId) {
    try {
      const operation = this.operations.get(operationId);

      if (!operation) {
        return {
          success: false,
          error: 'Operation not found',
        };
      }

      const previousStatus = operation.status;
      operation.status = status;
      operation.lastUpdated = new Date().toISOString();

      operation.updates.push({
        timestamp: new Date().toISOString(),
        type: 'status_change',
        previousStatus: previousStatus,
        newStatus: status,
        performedBy: userId,
        notes: updateData.notes || '',
        data: updateData,
      });

      // Handle status-specific actions
      if (status === 'active') {
        operation.activatedAt = new Date().toISOString();
        operation.activatedBy = userId;

        // Update all linked missions to active
        const linkedMissions = this.missionCoordination.get(operationId) || [];
        for (const missionId of linkedMissions) {
          this.pmcService.updateMissionStatus(
            missionId,
            'active',
            updateData,
            userId
          );
        }
      }

      if (status === 'completed') {
        operation.completedAt = new Date().toISOString();
        operation.completedBy = userId;

        // Generate completion report
        this.generateOperationReport(operationId, 'completion', userId);
      }

      logger.info(`Operation ${operationId} status updated to ${status}`);

      return {
        success: true,
        operation: operation,
        message: `Operation status updated to ${status}`,
      };
    } catch (error) {
      logger.error('Error updating operation status:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Generate operation report
   * @param {string} operationId - Operation ID
   * @param {string} reportType - Report type
   * @param {string} userId - User ID
   * @returns {Object} Report generation result
   */
  generateOperationReport(operationId, reportType, userId) {
    try {
      const operation = this.operations.get(operationId);

      if (!operation) {
        return {
          success: false,
          error: 'Operation not found',
        };
      }

      const reportId = `REPORT-${operationId}-${reportType}-${Date.now()}`;

      const report = {
        reportId: reportId,
        operationId: operationId,
        operationName: operation.name,
        type: reportType,
        generatedAt: new Date().toISOString(),
        generatedBy: userId,

        summary: {
          status: operation.status,
          duration: this.calculateDuration(
            operation.startDate,
            operation.endDate
          ),
          personnelDeployed: operation.personnel.allocated,
          budgetSpent: operation.budget.spent,
          budgetUtilization:
            ((operation.budget.spent / operation.budget.total) * 100).toFixed(
              2
            ) + '%',
        },

        pmcPerformance: this.assessPMCPerformance(operationId),

        achievements: operation.achievements,
        incidents: operation.incidents,

        resourceUtilization: {
          personnel: {
            required: operation.personnel.required,
            allocated: operation.personnel.allocated,
            utilization:
              (
                (operation.personnel.allocated / operation.personnel.required) *
                100
              ).toFixed(2) + '%',
          },
          budget: {
            total: operation.budget.total,
            allocated: operation.budget.allocated,
            spent: operation.budget.spent,
            remaining: operation.budget.total - operation.budget.spent,
          },
        },

        recommendations: this.generateRecommendations(operation),

        lessonsLearned: operation.lessonsLearned || [],
      };

      operation.reports.push(report);

      logger.info(`Operation report generated: ${reportId}`);

      return {
        success: true,
        reportId: reportId,
        report: report,
      };
    } catch (error) {
      logger.error('Error generating operation report:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Assess PMC performance in operation
   */
  assessPMCPerformance(operationId) {
    const linkedMissions = this.missionCoordination.get(operationId) || [];
    const performance = {};

    for (const missionId of linkedMissions) {
      // Get mission details from PMC service
      const missions = this.pmcService.getActiveMissions({ status: 'all' });
      const mission = missions.missions?.find((m) => m.id === missionId);

      if (mission) {
        const pmcId = mission.assignedPMCs[0];
        if (!performance[pmcId]) {
          performance[pmcId] = {
            missions: 0,
            completed: 0,
            rating: 0,
          };
        }
        performance[pmcId].missions += 1;
        if (mission.status === 'completed') {
          performance[pmcId].completed += 1;
        }
      }
    }

    return performance;
  }

  /**
   * Generate recommendations based on operation
   */
  generateRecommendations(operation) {
    const recommendations = [];

    // Budget recommendations
    if (operation.budget.spent > operation.budget.total * 0.9) {
      recommendations.push({
        category: 'budget',
        priority: 'high',
        recommendation:
          'Budget utilization exceeded 90%. Consider increasing budget allocation for similar operations.',
      });
    }

    // Personnel recommendations
    if (operation.personnel.allocated < operation.personnel.required * 0.8) {
      recommendations.push({
        category: 'personnel',
        priority: 'medium',
        recommendation:
          'Personnel allocation was below 80% of requirements. Review staffing strategy.',
      });
    }

    // Risk recommendations
    if (operation.incidents.length > 5) {
      recommendations.push({
        category: 'risk',
        priority: 'high',
        recommendation:
          'High incident rate detected. Review risk mitigation strategies.',
      });
    }

    return recommendations;
  }

  /**
   * Calculate duration between dates
   */
  calculateDuration(startDate, endDate) {
    if (!startDate || !endDate) return 'N/A';

    const start = new Date(startDate);
    const end = new Date(endDate);
    const days = Math.ceil((end - start) / (1000 * 60 * 60 * 24));

    return `${days} days`;
  }

  /**
   * Create training program for PMC personnel
   * @param {Object} programData - Training program details
   * @param {string} userId - User ID
   * @returns {Object} Program creation result
   */
  createTrainingProgram(programData, userId) {
    try {
      const programId = `TRAIN-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      const program = {
        programId: programId,
        name: programData.name,
        type: programData.type, // tactical, technical, leadership, etc.
        description: programData.description,

        targetPMCs: programData.targetPMCs || [],
        targetPersonnel: programData.targetPersonnel || 0,

        curriculum: programData.curriculum || [],
        duration: programData.duration, // hours
        schedule: programData.schedule,

        instructors: programData.instructors || [],
        location: programData.location,

        requirements: programData.requirements || [],
        certifications: programData.certifications || [],

        status: 'scheduled',
        enrollments: [],
        completions: [],

        createdBy: userId,
        createdAt: new Date().toISOString(),
      };

      this.trainingPrograms.set(programId, program);

      logger.info(`Training program created: ${programId} - ${program.name}`);

      return {
        success: true,
        programId: programId,
        program: program,
        message: 'Training program created successfully',
      };
    } catch (error) {
      logger.error('Error creating training program:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get PMC integration status
   * @returns {Object} Integration status
   */
  getIntegrationStatus() {
    try {
      const pmcContractors = this.pmcService.getPMCContractors();
      const jointForce = this.pmcService.getJointForceStatus();

      return {
        success: true,
        integration: {
          pmcContractors: pmcContractors.count,
          totalPersonnel: pmcContractors.totalPersonnel,
          totalContractValue: pmcContractors.totalContractValue,

          operations: {
            total: this.operations.size,
            active: Array.from(this.operations.values()).filter(
              (o) => o.status === 'active'
            ).length,
            completed: Array.from(this.operations.values()).filter(
              (o) => o.status === 'completed'
            ).length,
          },

          resourceAllocations: this.resourceAllocations.size,
          trainingPrograms: this.trainingPrograms.size,

          jointForce: jointForce.jointForce,

          capabilities: [
            'Multi-PMC coordination',
            'Resource allocation',
            'Mission management',
            'Training programs',
            'Performance tracking',
            'Reporting & analytics',
          ],
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error('Error getting integration status:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get operation details
   * @param {string} operationId - Operation ID
   * @returns {Object} Operation details
   */
  getOperation(operationId) {
    try {
      const operation = this.operations.get(operationId);

      if (!operation) {
        return {
          success: false,
          error: 'Operation not found',
        };
      }

      // Get linked missions
      const linkedMissions = this.missionCoordination.get(operationId) || [];

      return {
        success: true,
        operation: operation,
        linkedMissions: linkedMissions.length,
        resourceAllocations: Array.from(
          this.resourceAllocations.values()
        ).filter((a) => a.operationId === operationId),
      };
    } catch (error) {
      logger.error('Error getting operation:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get all operations with filters
   * @param {Object} filters - Filter criteria
   * @returns {Object} Operations list
   */
  getOperations(filters = {}) {
    try {
      let operations = Array.from(this.operations.values());

      if (filters.status) {
        operations = operations.filter((o) => o.status === filters.status);
      }

      if (filters.type) {
        operations = operations.filter((o) => o.type === filters.type);
      }

      if (filters.priority) {
        operations = operations.filter((o) => o.priority === filters.priority);
      }

      return {
        success: true,
        operations: operations,
        count: operations.length,
      };
    } catch (error) {
      logger.error('Error getting operations:', error);
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
      const operations = Array.from(this.operations.values());
      const pmcStats = this.pmcService.getStatistics();

      return {
        success: true,
        statistics: {
          operations: {
            total: operations.length,
            active: operations.filter((o) => o.status === 'active').length,
            completed: operations.filter((o) => o.status === 'completed')
              .length,
            planning: operations.filter((o) => o.status === 'planning').length,
          },
          resources: {
            allocations: this.resourceAllocations.size,
            totalBudgetAllocated: operations.reduce(
              (sum, o) => sum + o.budget.allocated,
              0
            ),
            totalPersonnelDeployed: operations.reduce(
              (sum, o) => sum + o.personnel.allocated,
              0
            ),
          },
          training: {
            programs: this.trainingPrograms.size,
            active: Array.from(this.trainingPrograms.values()).filter(
              (p) => p.status === 'active'
            ).length,
          },
          pmcIntegration: pmcStats.statistics,
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
    const pmcHealth = this.pmcService.getHealthStatus();

    return {
      status: 'operational',
      service: 'PMC Integration Service',
      pmcService: pmcHealth.status,
      operations: this.operations.size,
      resourceAllocations: this.resourceAllocations.size,
      trainingPrograms: this.trainingPrograms.size,
      lastCheck: new Date().toISOString(),
    };
  }
}

export default PMCIntegrationService;
