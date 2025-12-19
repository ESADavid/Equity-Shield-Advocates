/**
 * PARTNER COORDINATION SERVICE
 * Manages partner relationships, coordination, and collaboration
 * Part of Phase 2: Heaven on Earth Implementation
 *
 * Features:
 * - Partner onboarding and management
 * - Communication workflows
 * - Performance tracking
 * - Contract management
 * - Project coordination
 * - Resource allocation
 */

import { info, error, warn, debug } from '../utils/loggerWrapper.js';
import Partner from '../models/Partner.js';

class PartnerCoordinationService {
  constructor() {
    this.partners = new Map();
    this.projects = new Map();
    this.communications = new Map();
    this.workflows = new Map();

    info('Partner Coordination Service initialized');
  }

  /**
   * Onboard a new partner
   * @param {Object} partnerData - Partner information
   * @param {string} userId - User ID performing onboarding
   * @returns {Object} Onboarding result
   */
  async onboardPartner(partnerData, userId) {
    try {
      const partnerId = `PARTNER-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      const partner = {
        partnerId: partnerId,
        name: partnerData.name,
        type: partnerData.type,
        status: 'pending',
        contact: partnerData.contact || {},
        contract: {
          ...partnerData.contract,
          contractId: `CONTRACT-${partnerId}`,
          startDate:
            partnerData.contract?.startDate || new Date().toISOString(),
        },
        services: partnerData.services || [],
        capabilities: partnerData.capabilities || {},
        performance: {
          rating: 0,
          projectsCompleted: 0,
          projectsActive: 0,
          successRate: 0,
          onTimeDelivery: 0,
          qualityScore: 0,
          customerSatisfaction: 0,
          incidentRate: 0,
          reviews: [],
        },
        financial: {
          totalRevenue: 0,
          totalPaid: 0,
          outstandingBalance: 0,
          paymentHistory: [],
          invoices: [],
        },
        integration: {
          integrationStatus: 'not-started',
          customFields: {},
        },
        compliance: {
          backgroundCheckCompleted: false,
          licenses: [],
          certifications: [],
          auditHistory: [],
        },
        communication: {
          preferredChannel:
            partnerData.communication?.preferredChannel || 'email',
          communicationLog: [],
        },
        projects: [],
        deployments: [],
        documents: [],
        notes: [],
        activityLog: [
          {
            timestamp: new Date().toISOString(),
            action: 'partner_onboarded',
            performedBy: userId,
            details: { status: 'pending' },
          },
        ],
        createdBy: userId,
        createdAt: new Date().toISOString(),
        lastModified: new Date().toISOString(),
      };

      this.partners.set(partnerId, partner);

      // Create onboarding workflow
      await this.createOnboardingWorkflow(partnerId, userId);

      info(`Partner onboarded: ${partnerId} - ${partner.name}`);

      return {
        success: true,
        partnerId: partnerId,
        partner: partner,
        message: 'Partner onboarded successfully',
      };
    } catch (error) {
      error('Error onboarding partner:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Create onboarding workflow for new partner
   * @param {string} partnerId - Partner ID
   * @param {string} userId - User ID
   * @returns {Object} Workflow creation result
   */
  async createOnboardingWorkflow(partnerId, userId) {
    try {
      const workflowId = `WORKFLOW-${partnerId}-ONBOARDING`;

      const workflow = {
        workflowId: workflowId,
        partnerId: partnerId,
        type: 'onboarding',
        status: 'in-progress',
        steps: [
          {
            stepId: 'step-1',
            name: 'Document Collection',
            description: 'Collect required documents and information',
            status: 'pending',
            required: true,
            documents: [
              'Business License',
              'Insurance Certificate',
              'Tax ID',
              'Bank Details',
              'References',
            ],
          },
          {
            stepId: 'step-2',
            name: 'Background Check',
            description: 'Conduct background and compliance checks',
            status: 'pending',
            required: true,
            checks: [
              'Business verification',
              'Credit check',
              'Legal compliance',
              'Security clearance',
            ],
          },
          {
            stepId: 'step-3',
            name: 'Contract Negotiation',
            description: 'Negotiate and finalize contract terms',
            status: 'pending',
            required: true,
          },
          {
            stepId: 'step-4',
            name: 'System Integration',
            description: 'Set up system integration and access',
            status: 'pending',
            required: true,
          },
          {
            stepId: 'step-5',
            name: 'Training & Orientation',
            description: 'Provide training and orientation',
            status: 'pending',
            required: false,
          },
          {
            stepId: 'step-6',
            name: 'Activation',
            description: 'Activate partner account',
            status: 'pending',
            required: true,
          },
        ],
        createdBy: userId,
        createdAt: new Date().toISOString(),
        completedSteps: 0,
        totalSteps: 6,
      };

      this.workflows.set(workflowId, workflow);

      info(`Onboarding workflow created for partner ${partnerId}`);

      return {
        success: true,
        workflowId: workflowId,
        workflow: workflow,
      };
    } catch (error) {
      error('Error creating onboarding workflow:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Update workflow step status
   * @param {string} workflowId - Workflow ID
   * @param {string} stepId - Step ID
   * @param {string} status - New status
   * @param {string} userId - User ID
   * @returns {Object} Update result
   */
  updateWorkflowStep(workflowId, stepId, status, userId) {
    try {
      const workflow = this.workflows.get(workflowId);

      if (!workflow) {
        return {
          success: false,
          error: 'Workflow not found',
        };
      }

      const step = workflow.steps.find((s) => s.stepId === stepId);

      if (!step) {
        return {
          success: false,
          error: 'Step not found',
        };
      }

      step.status = status;
      step.completedBy = userId;
      step.completedAt = new Date().toISOString();

      // Update completed steps count
      workflow.completedSteps = workflow.steps.filter(
        (s) => s.status === 'completed'
      ).length;

      // Check if all required steps are completed
      const allRequiredCompleted = workflow.steps
        .filter((s) => s.required)
        .every((s) => s.status === 'completed');

      if (allRequiredCompleted) {
        workflow.status = 'completed';
        workflow.completedAt = new Date().toISOString();

        // Activate partner if onboarding workflow is complete
        if (workflow.type === 'onboarding') {
          this.activatePartner(workflow.partnerId, userId);
        }
      }

      info(
        `Workflow step updated: ${workflowId} - ${stepId} - ${status}`
      );

      return {
        success: true,
        workflow: workflow,
        message: 'Workflow step updated successfully',
      };
    } catch (error) {
      error('Error updating workflow step:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Activate partner after successful onboarding
   * @param {string} partnerId - Partner ID
   * @param {string} userId - User ID
   * @returns {Object} Activation result
   */
  activatePartner(partnerId, userId) {
    try {
      const partner = this.partners.get(partnerId);

      if (!partner) {
        return {
          success: false,
          error: 'Partner not found',
        };
      }

      partner.status = 'active';
      partner.lastModified = new Date().toISOString();
      partner.lastModifiedBy = userId;

      partner.activityLog.push({
        timestamp: new Date().toISOString(),
        action: 'partner_activated',
        performedBy: userId,
        details: { previousStatus: 'pending', newStatus: 'active' },
      });

      info(`Partner activated: ${partnerId} - ${partner.name}`);

      return {
        success: true,
        partner: partner,
        message: 'Partner activated successfully',
      };
    } catch (error) {
      error('Error activating partner:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Assign project to partner
   * @param {string} partnerId - Partner ID
   * @param {Object} projectData - Project details
   * @param {string} userId - User ID
   * @returns {Object} Assignment result
   */
  assignProject(partnerId, projectData, userId) {
    try {
      const partner = this.partners.get(partnerId);

      if (!partner) {
        return {
          success: false,
          error: 'Partner not found',
        };
      }

      if (partner.status !== 'active') {
        return {
          success: false,
          error: 'Partner is not active',
        };
      }

      const projectId = `PROJECT-${partnerId}-${Date.now()}`;

      const project = {
        projectId: projectId,
        partnerId: partnerId,
        partnerName: partner.name,
        name: projectData.name,
        description: projectData.description,
        type: projectData.type,
        status: 'assigned',
        priority: projectData.priority || 'medium',
        startDate: projectData.startDate || new Date().toISOString(),
        endDate: projectData.endDate,
        budget: projectData.budget || 0,
        personnel: projectData.personnel || 0,
        location: projectData.location,
        objectives: projectData.objectives || [],
        deliverables: projectData.deliverables || [],
        milestones: projectData.milestones || [],
        resources: projectData.resources || [],
        assignedBy: userId,
        assignedAt: new Date().toISOString(),
        updates: [],
      };

      // Add to partner's projects
      partner.projects.push(project);
      partner.performance.projectsActive += 1;

      // Store in projects map
      this.projects.set(projectId, project);

      // Log activity
      partner.activityLog.push({
        timestamp: new Date().toISOString(),
        action: 'project_assigned',
        performedBy: userId,
        details: { projectId: projectId, projectName: project.name },
      });

      info(`Project assigned to partner ${partnerId}: ${projectId}`);

      return {
        success: true,
        projectId: projectId,
        project: project,
        message: 'Project assigned successfully',
      };
    } catch (error) {
      error('Error assigning project:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Update project status
   * @param {string} projectId - Project ID
   * @param {string} status - New status
   * @param {Object} updateData - Additional update data
   * @param {string} userId - User ID
   * @returns {Object} Update result
   */
  updateProjectStatus(projectId, status, updateData = {}, userId) {
    try {
      const project = this.projects.get(projectId);

      if (!project) {
        return {
          success: false,
          error: 'Project not found',
        };
      }

      const previousStatus = project.status;
      project.status = status;
      project.lastUpdated = new Date().toISOString();
      project.lastUpdatedBy = userId;

      // Add update to project history
      project.updates.push({
        timestamp: new Date().toISOString(),
        status: status,
        updatedBy: userId,
        notes: updateData.notes || '',
        data: updateData,
      });

      // Update partner performance metrics
      const partner = this.partners.get(project.partnerId);
      if (partner) {
        if (status === 'completed') {
          partner.performance.projectsActive -= 1;
          partner.performance.projectsCompleted += 1;
          project.completedAt = new Date().toISOString();

          // Calculate success metrics
          if (updateData.onTime) {
            partner.performance.onTimeDelivery =
              this.calculateOnTimeDelivery(partner);
          }
          if (updateData.qualityScore) {
            partner.performance.qualityScore =
              this.calculateAverageQuality(partner);
          }
        }

        partner.activityLog.push({
          timestamp: new Date().toISOString(),
          action: 'project_status_updated',
          performedBy: userId,
          details: {
            projectId: projectId,
            previousStatus: previousStatus,
            newStatus: status,
          },
        });
      }

      info(`Project ${projectId} status updated to ${status}`);

      return {
        success: true,
        project: project,
        message: `Project status updated to ${status}`,
      };
    } catch (error) {
      error('Error updating project status:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Log communication with partner
   * @param {string} partnerId - Partner ID
   * @param {Object} communicationData - Communication details
   * @param {string} userId - User ID
   * @returns {Object} Log result
   */
  logCommunication(partnerId, communicationData, userId) {
    try {
      const partner = this.partners.get(partnerId);

      if (!partner) {
        return {
          success: false,
          error: 'Partner not found',
        };
      }

      const communicationId = `COMM-${partnerId}-${Date.now()}`;

      const communication = {
        communicationId: communicationId,
        date: new Date().toISOString(),
        type: communicationData.type, // email, phone, meeting, etc.
        subject: communicationData.subject,
        participants: communicationData.participants || [],
        summary: communicationData.summary,
        followUp: communicationData.followUp,
        attachments: communicationData.attachments || [],
        loggedBy: userId,
      };

      partner.communication.communicationLog.push(communication);
      this.communications.set(communicationId, communication);

      info(
        `Communication logged for partner ${partnerId}: ${communicationId}`
      );

      return {
        success: true,
        communicationId: communicationId,
        communication: communication,
      };
    } catch (error) {
      error('Error logging communication:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Update partner performance rating
   * @param {string} partnerId - Partner ID
   * @param {Object} ratingData - Rating details
   * @param {string} userId - User ID
   * @returns {Object} Update result
   */
  updatePerformanceRating(partnerId, ratingData, userId) {
    try {
      const partner = this.partners.get(partnerId);

      if (!partner) {
        return {
          success: false,
          error: 'Partner not found',
        };
      }

      const review = {
        reviewId: `REVIEW-${partnerId}-${Date.now()}`,
        date: new Date().toISOString(),
        reviewer: userId,
        rating: ratingData.rating,
        comments: ratingData.comments,
        category: ratingData.category,
        metrics: {
          quality: ratingData.quality || 0,
          timeliness: ratingData.timeliness || 0,
          communication: ratingData.communication || 0,
          professionalism: ratingData.professionalism || 0,
        },
      };

      partner.performance.reviews.push(review);

      // Calculate new average rating
      const totalRating = partner.performance.reviews.reduce(
        (sum, r) => sum + r.rating,
        0
      );
      partner.performance.rating =
        totalRating / partner.performance.reviews.length;
      partner.performance.lastReview = new Date().toISOString();

      info(
        `Performance rating updated for partner ${partnerId}: ${review.rating}`
      );

      return {
        success: true,
        review: review,
        newRating: partner.performance.rating,
        message: 'Performance rating updated successfully',
      };
    } catch (error) {
      error('Error updating performance rating:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Calculate on-time delivery percentage
   */
  calculateOnTimeDelivery(partner) {
    const completedProjects = partner.projects.filter(
      (p) => p.status === 'completed'
    );
    if (completedProjects.length === 0) return 0;

    const onTimeProjects = completedProjects.filter((p) => {
      if (!p.endDate || !p.completedAt) return false;
      return new Date(p.completedAt) <= new Date(p.endDate);
    });

    return Math.round((onTimeProjects.length / completedProjects.length) * 100);
  }

  /**
   * Calculate average quality score
   */
  calculateAverageQuality(partner) {
    const reviews = partner.performance.reviews;
    if (reviews.length === 0) return 0;

    const totalQuality = reviews.reduce(
      (sum, r) => sum + (r.metrics?.quality || 0),
      0
    );
    return Math.round(totalQuality / reviews.length);
  }

  /**
   * Get partner details
   * @param {string} partnerId - Partner ID
   * @returns {Object} Partner details
   */
  getPartner(partnerId) {
    try {
      const partner = this.partners.get(partnerId);

      if (!partner) {
        return {
          success: false,
          error: 'Partner not found',
        };
      }

      // Get active projects
      const activeProjects = partner.projects.filter(
        (p) => p.status === 'active' || p.status === 'assigned'
      );

      // Get recent communications
      const recentCommunications = partner.communication.communicationLog
        .slice(-10)
        .reverse();

      return {
        success: true,
        partner: partner,
        summary: {
          activeProjects: activeProjects.length,
          completedProjects: partner.performance.projectsCompleted,
          rating: partner.performance.rating,
          healthScore: this.calculateHealthScore(partner),
          recentCommunications: recentCommunications.length,
        },
      };
    } catch (error) {
      error('Error getting partner:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Calculate partner health score
   */
  calculateHealthScore(partner) {
    const weights = {
      rating: 0.25,
      successRate: 0.2,
      onTimeDelivery: 0.2,
      qualityScore: 0.2,
      customerSatisfaction: 0.15,
    };

    const score =
      (partner.performance.rating / 5) * 100 * weights.rating +
      partner.performance.successRate * weights.successRate +
      partner.performance.onTimeDelivery * weights.onTimeDelivery +
      partner.performance.qualityScore * weights.qualityScore +
      partner.performance.customerSatisfaction * weights.customerSatisfaction;

    return Math.round(score);
  }

  /**
   * Get all partners with filters
   * @param {Object} filters - Filter criteria
   * @returns {Object} Partners list
   */
  getPartners(filters = {}) {
    try {
      let partners = Array.from(this.partners.values());

      // Apply filters
      if (filters.status) {
        partners = partners.filter((p) => p.status === filters.status);
      }

      if (filters.type) {
        partners = partners.filter((p) => p.type === filters.type);
      }

      if (filters.minRating) {
        partners = partners.filter(
          (p) => p.performance.rating >= filters.minRating
        );
      }

      // Sort
      if (filters.sortBy === 'rating') {
        partners.sort((a, b) => b.performance.rating - a.performance.rating);
      } else if (filters.sortBy === 'name') {
        partners.sort((a, b) => a.name.localeCompare(b.name));
      }

      return {
        success: true,
        partners: partners.map((p) => ({
          partnerId: p.partnerId,
          name: p.name,
          type: p.type,
          status: p.status,
          rating: p.performance.rating,
          activeProjects: p.performance.projectsActive,
          completedProjects: p.performance.projectsCompleted,
          healthScore: this.calculateHealthScore(p),
        })),
        count: partners.length,
      };
    } catch (error) {
      error('Error getting partners:', error);
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
      const partners = Array.from(this.partners.values());
      const projects = Array.from(this.projects.values());

      return {
        success: true,
        statistics: {
          partners: {
            total: partners.length,
            active: partners.filter((p) => p.status === 'active').length,
            pending: partners.filter((p) => p.status === 'pending').length,
            suspended: partners.filter((p) => p.status === 'suspended').length,
            byType: this.getPartnersByType(partners),
          },
          projects: {
            total: projects.length,
            active: projects.filter((p) => p.status === 'active').length,
            completed: projects.filter((p) => p.status === 'completed').length,
            assigned: projects.filter((p) => p.status === 'assigned').length,
          },
          performance: {
            averageRating: this.calculateAverageRating(partners),
            topPerformers: this.getTopPerformers(partners, 5),
          },
          workflows: {
            total: this.workflows.size,
            inProgress: Array.from(this.workflows.values()).filter(
              (w) => w.status === 'in-progress'
            ).length,
            completed: Array.from(this.workflows.values()).filter(
              (w) => w.status === 'completed'
            ).length,
          },
        },
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      error('Error getting statistics:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get partners grouped by type
   */
  getPartnersByType(partners) {
    const byType = {};
    partners.forEach((p) => {
      byType[p.type] = (byType[p.type] || 0) + 1;
    });
    return byType;
  }

  /**
   * Calculate average rating across all partners
   */
  calculateAverageRating(partners) {
    if (partners.length === 0) return 0;
    const totalRating = partners.reduce(
      (sum, p) => sum + p.performance.rating,
      0
    );
    return (totalRating / partners.length).toFixed(2);
  }

  /**
   * Get top performing partners
   */
  getTopPerformers(partners, limit = 5) {
    return partners
      .filter((p) => p.status === 'active')
      .sort((a, b) => b.performance.rating - a.performance.rating)
      .slice(0, limit)
      .map((p) => ({
        partnerId: p.partnerId,
        name: p.name,
        rating: p.performance.rating,
        completedProjects: p.performance.projectsCompleted,
      }));
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'operational',
      service: 'Partner Coordination Service',
      partners: this.partners.size,
      activeProjects: this.projects.size,
      activeWorkflows: this.workflows.size,
      lastCheck: new Date().toISOString(),
    };
  }
}

export default PartnerCoordinationService;
