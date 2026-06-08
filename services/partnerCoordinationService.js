/**
 * PARTNER COORDINATION SERVICE
 * ESM Version - Converted from partnerCoordinationService.ts
 */

import { info, error } from '../utils/loggerWrapper.js';
import Partner from '../models/Partner.js';
import mongoose from 'mongoose';

// Type definitions for subdocuments
class PartnerCoordinationService {
  constructor() {
    info('PartnerCoordinationService initialized (real DB mode)');
  }

  /**
   * Onboard a new partner
   */
  async onboardPartner(data, userId) {
    try {
      const partner = new Partner({
        ...data,
        audit: { createdBy: new mongoose.Types.ObjectId(userId) }
      });
      await partner.save();
      info(`Partner onboarded: ${partner.partnerId} by ${userId}`);
      return {
        success: true,
        partnerId: String(partner.partnerId),
        message: 'Partner onboarded',
      };
    } catch (err) {
      error('Partner onboarding failed:', err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Get partners with optional filters
   */
  async getPartners(filters = {}) {
    try {
      const partners = await Partner.find(filters).limit(50);
      info(`Found ${partners.length} partners`);
      const partnersList = partners.map(p => p.toObject());
      return { success: true, partners: partnersList, count: partners.length };
    } catch (err) {
      error('Get partners failed:', err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Get a specific partner
   */
  async getPartner(partnerId) {
    try {
      const partner = await Partner.findOne({ partnerId });
      if (!partner) return { success: false, error: 'Partner not found' };
      const partnerObj = partner.toObject();
      return { success: true, partner: partnerObj };
    } catch (err) {
      error(`Get partner ${partnerId} failed:`, err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Activate a partner
   */
  async activatePartner(partnerId, userId) {
    try {
      const partner = await Partner.findOneAndUpdate(
        { partnerId },
        {
          status: 'active',
          'audit.activatedBy': new mongoose.Types.ObjectId(userId)
        },
        { new: true }
      );
      if (!partner) return { success: false, error: 'Partner not found' };
      info(`Partner ${partnerId} activated by ${userId}`);
      return { success: true, message: 'Activated' };
    } catch (err) {
      error(`Activate partner ${partnerId} failed:`, err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Assign a project to a partner
   */
  async assignProject(partnerId, projectData, userId) {
    try {
      const partner = await Partner.findOne({ partnerId });
      if (!partner) return { success: false, error: 'Partner not found' };
      const projectId = 'PROJ-' + Date.now();
      const newProject = {
        ...projectData,
        projectId,
        assignedDate: new Date(),
      };
      partner.projects.push(newProject);
      await partner.save();
      info(`Project ${projectId} assigned to ${partnerId}`);
      return { success: true, projectId };
    } catch (err) {
      error(`Assign project failed for ${partnerId}:`, err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Update project status
   */
  async updateProjectStatus(projectId, status, data, userId) {
    try {
      const partner = await Partner.findOne({
        'projects.projectId': projectId,
      });
      if (!partner) return { success: false, error: 'Project not found' };

      const projectsArray = partner.projects;
      const projectIndex = projectsArray.findIndex(
        (p) => p.projectId === projectId
      );
      if (projectIndex === -1)
        return { success: false, error: 'Project not found' };

      const updateData = {
        status,
        ...data,
        updatedAt: new Date(),
      };
      projectsArray[projectIndex] = {
        ...projectsArray[projectIndex],
        ...updateData,
      };
      await partner.save();

      info(`Project ${projectId} status updated to ${status} by ${userId}`);
      return { success: true, message: 'Project status updated' };
    } catch (err) {
      error(`Update project ${projectId} failed:`, err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Log communication with partner
   */
  async logCommunication(partnerId, data, userId) {
    try {
      const partner = await Partner.findOne({ partnerId });
      if (!partner) return { success: false, error: 'Partner not found' };

      const communication = {
        type: data.type || 'email',
        date: new Date(),
        summary: data.summary,
        sentBy: userId,
      };
      partner.communications.push(communication);
      await partner.save();

      info(`Communication logged for ${partnerId} by ${userId}`);
      return { success: true };
    } catch (err) {
      error(`Log communication failed for ${partnerId}:`, err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Update performance rating for a partner
   */
  async updatePerformanceRating(partnerId, data, userId) {
    try {
      const partner = await Partner.findOne({ partnerId });
      if (!partner) return { success: false, error: 'Partner not found' };

      // Initialize performance object if null/undefined
      if (!partner.performance) {
        partner.performance = {
          rating: 0,
          projectsCompleted: 0,
          onTimeDelivery: 100,
        };
      }

      // Update performance fields
      const newRating = data.rating || partner.performance.rating;
      const newProjectsCompleted = data.projectsCompleted ?? partner.performance.projectsCompleted;
      const newOnTimeDelivery = data.onTimeDelivery ?? partner.performance.onTimeDelivery;

      partner.performance.rating = newRating;
      partner.performance.projectsCompleted = newProjectsCompleted ?? 0;
      partner.performance.onTimeDelivery = newOnTimeDelivery ?? 100;
      
      await partner.save();

      info(`Rating updated for ${partnerId}: ${data.rating} by ${userId}`);
      return { success: true };
    } catch (err) {
      error(`Update rating failed for ${partnerId}:`, err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Update workflow step for a partner
   */
  async updateWorkflowStep(workflowId, stepId, status, userId) {
    try {
      const partner = await Partner.findOne({ partnerId: workflowId });
      if (!partner) return { success: false, error: 'Partner not found' };

      // Initialize metadata if null/undefined
      if (!partner.metadata) {
        partner.metadata = {};
      }

      // Initialize workflow in metadata if it doesn't exist
      if (!partner.metadata.workflow) {
        partner.metadata.workflow = {};
      }

      // Update workflow step
      partner.metadata.workflow[stepId] = {
        status,
        updatedBy: userId,
        updatedAt: new Date()
      };
      await partner.save();

      info(`Workflow step ${stepId} updated for ${workflowId}`);
      return { success: true };
    } catch (err) {
      error(`Update workflow step failed:`, err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Get partner statistics
   */
  async getStatistics() {
    try {
      const total = await Partner.countDocuments();
      const active = await Partner.countDocuments({ status: 'active' });
      const avgRating = await Partner.aggregate([
        { $match: { 'performance.rating': { $gt: 0 } } },
        { $group: { _id: null, avg: { $avg: '$performance.rating' } } },
      ]);

      return {
        success: true,
        stats: {
          totalPartners: total,
          activePartners: active,
          avgRating: Math.round((avgRating[0]?.avg || 0) * 10) / 10,
          projectsActive: 0,
        },
      };
    } catch (err) {
      error('Statistics failed:', err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Get health status
   */
  getHealthStatus() {
    return { status: 'healthy', mode: 'real-db-enhanced' };
  }
}

export default new PartnerCoordinationService();
