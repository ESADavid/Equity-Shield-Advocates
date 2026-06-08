import { info, error } from '../utils/loggerWrapper.js';
import Partner from '../models/Partner';
import type { IPartner } from '../models/Partner';
import mongoose from 'mongoose';

// Type definitions for subdocuments
interface IProject {
  projectId: string;
  name: string;
  status?: string;
  assignedDate: Date;
  deadline?: Date;
  value?: mongoose.Types.Decimal128;
}

interface ICommunication {
  type?: string;
  date: Date;
  summary: string;
  sentBy: string;
}

interface IWorkflowStep {
  status: string;
  updatedBy: string;
  updatedAt: Date;
  [key: string]: unknown;
}

export interface IPartnerData {
  partnerId?: string;
  name: string;
  type: string;
  status?: string;
  contactEmail?: string;
  contactPhone?: string;
}

export interface IProjectData {
  name: string;
  description?: string;
  status?: string;
  budget?: number;
}

export interface ICommunicationData {
  type?: string;
  summary: string;
}

interface IPerformanceDataInput {
  rating: number;
  projectsCompleted?: number;
  onTimeDelivery?: number;
}

// Service return types
interface OnboardResult {
  success: boolean;
  partnerId?: string;
  message?: string;
  error?: string;
}

interface GetPartnersResult {
  success: boolean;
  partners?: IPartner[];
  count?: number;
  error?: string;
}

interface GetPartnerResult {
  success: boolean;
  partner?: IPartner;
  error?: string;
}

interface ActivateResult {
  success: boolean;
  message?: string;
  error?: string;
}

interface AssignProjectResult {
  success: boolean;
  projectId?: string;
  error?: string;
}

interface UpdateProjectStatusResult {
  success: boolean;
  message?: string;
  error?: string;
}

interface LogCommunicationResult {
  success: boolean;
  error?: string;
}

interface UpdatePerformanceResult {
  success: boolean;
  error?: string;
}

interface UpdateWorkflowResult {
  success: boolean;
  error?: string;
}

interface GetStatisticsResult {
  success: boolean;
  stats?: {
    totalPartners: number;
    activePartners: number;
    avgRating: number;
    projectsActive: number;
  };
  error?: string;
}

interface HealthStatus {
  status: string;
  mode: string;
}

export default class PartnerCoordinationService {
  constructor() {
    info('PartnerCoordinationService initialized (real DB mode)');
  }

/**
   * Onboard a new partner
   */
  async onboardPartner(data: IPartnerData, userId: string): Promise<OnboardResult> {
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
      return { success: false, error: (err as Error).message };
    }
  }

/**
   * Get partners with optional filters
   */
  async getPartners(filters: Record<string, unknown> = {}): Promise<GetPartnersResult> {
    try {
      const partners = await Partner.find(filters as mongoose.FilterQuery<IPartner>).limit(50);
      info(`Found ${partners.length} partners`);
      // Convert mongoose documents to plain objects
      const partnersList = partners.map(p => p.toObject()) as unknown as IPartner[];
      return { success: true, partners: partnersList, count: partners.length };
    } catch (err) {
      error('Get partners failed:', err);
      return { success: false, error: (err as Error).message };
    }
  }

/**
   * Get a specific partner
   */
  async getPartner(partnerId: string): Promise<GetPartnerResult> {
    try {
      const partner = await Partner.findOne({ partnerId } as mongoose.FilterQuery<IPartner>);
      if (!partner) return { success: false, error: 'Partner not found' };
      const partnerObj = partner.toObject() as unknown as IPartner;
      return { success: true, partner: partnerObj };
    } catch (err) {
      error(`Get partner ${partnerId} failed:`, err);
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * Activate a partner
   */
  async activatePartner(partnerId: string, userId: string): Promise<ActivateResult> {
    try {
      const partner = await Partner.findOneAndUpdate(
        { partnerId } as mongoose.FilterQuery<IPartner>,
        { 
          status: 'active', 
          'audit.activatedBy': new mongoose.Types.ObjectId(userId) 
        } as mongoose.UpdateQuery<IPartner>,
        { new: true }
      );
      if (!partner) return { success: false, error: 'Partner not found' };
      info(`Partner ${partnerId} activated by ${userId}`);
      return { success: true, message: 'Activated' };
    } catch (err) {
      error(`Activate partner ${partnerId} failed:`, err);
      return { success: false, error: (err as Error).message };
    }
  }

/**
   * Assign a project to a partner
   */
  async assignProject(partnerId: string, projectData: IProjectData, _userId: string): Promise<AssignProjectResult> {
    try {
      const partner = await Partner.findOne({ partnerId } as mongoose.FilterQuery<IPartner>);
      if (!partner) return { success: false, error: 'Partner not found' };
      const projectId = 'PROJ-' + Date.now();
      const newProject = {
        ...projectData,
        projectId,
        assignedDate: new Date(),
      };
      (partner.projects as unknown as IProject[]).push(newProject as IProject);
      await partner.save();
      info(`Project ${projectId} assigned to ${partnerId}`);
      return { success: true, projectId };
    } catch (err) {
      error(`Assign project failed for ${partnerId}:`, err);
      return { success: false, error: (err as Error).message };
    }
  }

/**
   * Update project status
   */
  async updateProjectStatus(
    projectId: string,
    status: string,
    data: Record<string, unknown>,
    userId: string
  ): Promise<UpdateProjectStatusResult> {
    try {
      const partner = await Partner.findOne({
        'projects.projectId': projectId,
      } as mongoose.FilterQuery<IPartner>);
      if (!partner) return { success: false, error: 'Project not found' };

      const projectsArray = partner.projects as unknown as IProject[];
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
      } as IProject;
      await partner.save();

      info(`Project ${projectId} status updated to ${status} by ${userId}`);
      return { success: true, message: 'Project status updated' };
    } catch (err) {
      error(`Update project ${projectId} failed:`, err);
      return { success: false, error: (err as Error).message };
    }
  }

/**
   * Log communication with partner
   */
  async logCommunication(
    partnerId: string,
    data: ICommunicationData,
    userId: string
  ): Promise<LogCommunicationResult> {
    try {
      const partner = await Partner.findOne({ partnerId } as mongoose.FilterQuery<IPartner>);
      if (!partner) return { success: false, error: 'Partner not found' };

      const communication = {
        type: data.type || 'email',
        date: new Date(),
        summary: data.summary,
        sentBy: userId,
      };
      (partner.communications as unknown as ICommunication[]).push(communication as ICommunication);
      await partner.save();

      info(`Communication logged for ${partnerId} by ${userId}`);
      return { success: true };
    } catch (err) {
      error(`Log communication failed for ${partnerId}:`, err);
      return { success: false, error: (err as Error).message };
    }
  }

/**
   * Update performance rating for a partner
   */
  async updatePerformanceRating(
    partnerId: string,
    data: IPerformanceDataInput,
    userId: string
  ): Promise<UpdatePerformanceResult> {
    try {
      const partner = await Partner.findOne({ partnerId } as mongoose.FilterQuery<IPartner>);
      if (!partner) return { success: false, error: 'Partner not found' };

      // Initialize performance object if null/undefined - cast properly
      const perfObj = partner.performance as unknown as { rating: number; projectsCompleted: number; onTimeDelivery: number } | null | undefined;
      if (!perfObj) {
        (partner as unknown as { performance: { rating: number; projectsCompleted: number; onTimeDelivery: number } }).performance = {
          rating: 0,
          projectsCompleted: 0,
          onTimeDelivery: 100,
        };
      } else {
        // Update performance fields with proper casting
        const currentPerf = partner.performance as unknown as { rating: number; projectsCompleted: number; onTimeDelivery: number };
        const newRating = data.rating || currentPerf.rating;
        const newProjectsCompleted = data.projectsCompleted ?? currentPerf.projectsCompleted;
        const newOnTimeDelivery = data.onTimeDelivery ?? currentPerf.onTimeDelivery;

        currentPerf.rating = newRating;
        currentPerf.projectsCompleted = newProjectsCompleted ?? 0;
        currentPerf.onTimeDelivery = newOnTimeDelivery ?? 100;
        (partner as unknown as { performance: { rating: number; projectsCompleted: number; onTimeDelivery: number } }).performance = currentPerf;
      }
      await partner.save();

      info(`Rating updated for ${partnerId}: ${data.rating} by ${userId}`);
      return { success: true };
    } catch (err) {
      error(`Update rating failed for ${partnerId}:`, err);
      return { success: false, error: (err as Error).message };
    }
  }

/**
   * Update workflow step for a partner
   */
  async updateWorkflowStep(
    workflowId: string,
    stepId: string,
    status: string,
    userId: string
  ): Promise<UpdateWorkflowResult> {
    try {
      const partner = await Partner.findOne({ partnerId: workflowId } as mongoose.FilterQuery<IPartner>);
      if (!partner) return { success: false, error: 'Partner not found' };

// Initialize metadata and workflow if null/undefined
      if (!partner.metadata) {
        partner.metadata = {};
      }
      
      // Initialize workflow in metadata if it doesn't exist
      if (!('workflow' in partner.metadata)) {
        (partner.metadata as unknown as { workflow: Record<string, IWorkflowStep> }).workflow = {};
      }

      // Get properly typed workflow object
      const workflowObj = (partner.metadata as unknown as { workflow: Record<string, IWorkflowStep> }).workflow;
      
      // Update workflow step with proper typing
      workflowObj[stepId] = {
        status,
        updatedBy: userId,
        updatedAt: new Date(),
      };
      await partner.save();

      info(`Workflow step ${stepId} updated for ${workflowId}`);
      return { success: true };
    } catch (err) {
      error(`Update workflow step failed:`, err);
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * Get partner statistics
   */
  async getStatistics(): Promise<GetStatisticsResult> {
    try {
      const total = await Partner.countDocuments();
      const active = await Partner.countDocuments({ status: 'active' } as mongoose.FilterQuery<IPartner>);
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
          projectsActive: 0, // Will be computed separately if needed
        },
      };
    } catch (err) {
      error('Statistics failed:', err);
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * Get health status
   */
  getHealthStatus(): HealthStatus {
    return { status: 'healthy', mode: 'real-db-enhanced' };
  }
}
