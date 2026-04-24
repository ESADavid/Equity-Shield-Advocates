import { info, error } from 'utils/loggerWrapper.js';
import Partner from '../models/Partner.js';

export default class PartnerCoordinationService {
  constructor() {
    info('PartnerCoordinationService initialized (real DB mode)');
  }

  async onboardPartner(data, userId) {
    try {
      const partner = new Partner({ ...data, audit: { createdBy: userId } });
      await partner.save();
      info(`Partner onboarded: ${partner.partnerId} by ${userId}`);
      return {
        success: true,
        partnerId: partner.partnerId,
        message: 'Partner onboarded',
      };
    } catch (err) {
      error('Partner onboarding failed:', err);
      return { success: false, error: err.message };
    }
  }

  async getPartners(filters = {}) {
    try {
      const partners = await Partner.find(filters).limit(50);
      info(`Found ${partners.length} partners`);
      return { success: true, partners, count: partners.length };
    } catch (err) {
      error('Get partners failed:', err);
      return { success: false, error: err.message };
    }
  }

  async getPartner(partnerId) {
    try {
      const partner = await Partner.findOne({ partnerId });
      if (!partner) return { success: false, error: 'Partner not found' };
      return { success: true, partner };
    } catch (err) {
      error(`Get partner ${partnerId} failed:`, err);
      return { success: false, error: err.message };
    }
  }

  async activatePartner(partnerId, userId) {
    try {
      const partner = await Partner.findOneAndUpdate(
        { partnerId },
        { status: 'active', 'audit.activatedBy': userId },
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

  async assignProject(partnerId, projectData, userId) {
    try {
      const partner = await Partner.findOne({ partnerId });
      if (!partner) return { success: false, error: 'Partner not found' };
      const projectId = 'PROJ-' + Date.now();
      partner.projects.push({
        ...projectData,
        projectId,
        assignedDate: new Date(),
      });
      await partner.save();
      info(`Project ${projectId} assigned to ${partnerId}`);
      return { success: true, projectId };
    } catch (err) {
      error(`Assign project failed for ${partnerId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async updateProjectStatus(projectId, status, data, userId) {
    try {
      const partner = await Partner.findOne({
        'projects.projectId': projectId,
      });
      if (!partner) return { success: false, error: 'Project not found' };

      const projectIndex = partner.projects.findIndex(
        (p) => p.projectId === projectId
      );
      if (projectIndex === -1)
        return { success: false, error: 'Project not found' };

      partner.projects[projectIndex] = {
        ...partner.projects[projectIndex],
        status,
        ...data,
      };
      await partner.save();

      info(`Project ${projectId} status updated to ${status} by ${userId}`);
      return { success: true, message: 'Project status updated' };
    } catch (err) {
      error(`Update project ${projectId} failed:`, err);
      return { success: false, error: err.message };
    }
  }

  async logCommunication(partnerId, data, userId) {
    try {
      const partner = await Partner.findOne({ partnerId });
      if (!partner) return { success: false, error: 'Partner not found' };

      partner.communications.push({
        type: data.type || 'email',
        date: new Date(),
        summary: data.summary,
        sentBy: userId,
      });
      await partner.save();

      info(`Communication logged for ${partnerId} by ${userId}`);
      return { success: true };
    } catch (err) {
      error(`Log communication failed for ${partnerId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async updatePerformanceRating(partnerId, data, userId) {
    try {
      const partner = await Partner.findOne({ partnerId });
      if (!partner) return { success: false, error: 'Partner not found' };

      partner.performance.rating = data.rating;
      partner.performance.projectsCompleted =
        data.projectsCompleted || partner.performance.projectsCompleted;
      partner.performance.onTimeDelivery =
        data.onTimeDelivery || partner.performance.onTimeDelivery;
      await partner.save();

      info(`Rating updated for ${partnerId}: ${data.rating} by ${userId}`);
      return { success: true };
    } catch (err) {
      error(`Update rating failed for ${partnerId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async updateWorkflowStep(workflowId, stepId, status, userId) {
    try {
      const partner = await Partner.findOne({ partnerId: workflowId });
      if (!partner) return { success: false, error: 'Partner not found' };

      partner.metadata = partner.metadata || {};
      partner.metadata.workflow = partner.metadata.workflow || {};
      partner.metadata.workflow[stepId] = {
        status,
        updatedBy: userId,
        updatedAt: new Date(),
      };
      await partner.save();

      info(`Workflow step ${stepId} updated for ${workflowId}`);
      return { success: true };
    } catch (err) {
      error(`Update workflow step failed:`, err);
      return { success: false, error: err.message };
    }
  }

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
          projectsActive: await Partner.aggregate([
            { $unwind: '$projects' },
            { $match: { 'projects.status': { $ne: 'completed' } } },
            { $count: 'activeProjects' },
          ]).then((res) => res[0]?.activeProjects || 0),
        },
      };
    } catch (err) {
      error('Statistics failed:', err);
      return { success: false, error: err.message };
    }
  }

  getHealthStatus() {
    return { status: 'healthy', mode: 'real-db-enhanced' };
  }
}
