/**
 * Partner type definitions for TypeScript
 */

import mongoose from 'mongoose';

/**
 * Project subdocument interface
 */
export interface IProject {
  projectId: string;
  name: string;
  status?: string;
  assignedDate: Date;
  deadline?: Date;
  value?: mongoose.Types.Decimal128;
}

/**
 * Communication subdocument interface
 */
export interface ICommunication {
  type?: string;
  date: Date;
  summary: string;
  sentBy: string;
}

/**
 * Performance data interface
 */
export interface IPerformance {
  rating: number;
  projectsCompleted: number;
  onTimeDelivery: number;
  totalRevenue?: mongoose.Types.Decimal128;
}

/**
 * Partner document interface
 */
export interface IPartner extends mongoose.Document {
  partnerId: string;
  companyName: string;
  contactPerson: {
    firstName?: string;
    lastName?: string;
    email: string;
    phone?: string;
  };
  businessInfo: {
    industry?: string;
    registrationNumber?: string;
    taxId?: string;
    address?: string;
    country: string;
  };
  status: 'pending' | 'active' | 'suspended' | 'terminated';
  performance: IPerformance;
  projects: IProject[];
  communications: ICommunication[];
  onboarding: {
    completed: boolean;
    date?: Date;
    documents?: string[];
  };
  metadata?: Record<string, unknown>;
  audit: {
    createdBy?: mongoose.Types.ObjectId;
    activatedBy?: mongoose.Types.ObjectId;
  };
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Partner model type
 */
export type PartnerModel = mongoose.Model<IPartner,Record<string,unknown>,Record<string,unknown>, IPersist<IPartner>, mongoose.Schema<IPartner, PartnerModel>, IPartner>;

interface IPersist<T extends mongoose.Document> extends mongoose.Model<T> {
  generatePartnerId(): Promise<string>;
}

export default PartnerModel;
