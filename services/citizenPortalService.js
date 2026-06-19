import { info, error } from '../utils/loggerWrapper.js';
import Citizen from '../models/Citizen.js';
import ServiceRequest from '../models/ServiceRequest.js';

export default class CitizenPortalService {
  constructor() {
    info('CitizenPortalService initialized (real DB mode)');
  }

  async registerCitizen(data) {
    try {
      const citizen = new Citizen(data);
      await citizen.save();
      info(`Citizen registered: ${citizen.citizenId}`);
      
      // Mask SSN for security
      const citizenObj = citizen.toObject();
      if (citizenObj.personalInfo?.ssn) {
        citizenObj.personalInfo.ssn = '***-**-' + citizenObj.personalInfo.ssn.slice(-4);
      }
      
      return { success: true, citizenId: citizen.citizenId, citizen: citizenObj };
    } catch (err) {
      error('Citizen registration failed:', err);
      return { success: false, error: err.message };
    }
  }

  async getCitizenProfile(citizenId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };
      return { success: true, profile: citizen.toObject() };
    } catch (err) {
      error(`Get profile failed for ${citizenId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async updateCitizenProfile(citizenId, data) {
    try {
      const citizen = await Citizen.findOneAndUpdate({ citizenId }, data, {
        new: true,
      });
      if (!citizen) return { success: false, error: 'Citizen not found' };
      return { success: true, citizenId: citizen.citizenId };
    } catch (err) {
      error(`Update profile failed for ${citizenId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async enrollInUBI(citizenId, data) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };
      
      // Check verification status before allowing UBI enrollment
      if (!citizen.verification?.identityVerified || !citizen.verification?.bankingVerified) {
        return { success: false, error: 'Citizen not verified for UBI enrollment' };
      }
      
      citizen.ubiStatus.enrollmentDate = new Date();
      await citizen.save();
      info(`UBI enrolled for ${citizenId}`);
      return { success: true };
    } catch (err) {
      error(`UBI enrollment failed for ${citizenId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async enrollInCourse(citizenId, courseId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };
      
      // Check for duplicate enrollment
      if (citizen.educationStatus.tech?.enrolled) {
        return { success: false, error: 'Citizen already enrolled in this course' };
      }
      
      // Enroll in tech
      citizen.educationStatus.tech.enrolled = true;
      citizen.educationStatus.tech.enrollmentDate = new Date();
      await citizen.save();
      info(`Course ${courseId} enrolled for ${citizenId}`);
      return { success: true, courseId };
    } catch (err) {
      error(`Course enrollment failed for ${citizenId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async createServiceRequest(citizenId, data) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };

      const serviceRequest = new ServiceRequest({
        citizenId,
        ...data,
      });
      await serviceRequest.save();

      info(
        `Service request created: ${serviceRequest.requestId} for ${citizenId}`
      );
      return { success: true, requestId: serviceRequest.requestId };
    } catch (err) {
      error(`Service request failed for ${citizenId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async getServiceRequest(citizenId, requestId) {
    try {
      const request = await ServiceRequest.findOne({
        requestId,
        citizenId,
      }).populate('assignedTo', 'username');

      if (!request)
        return { success: false, error: 'Service request not found' };

      return { success: true, request };
    } catch (err) {
      error(`Get service request failed: ${requestId}`, err);
      return { success: false, error: err.message };
    }
  }

  async uploadDocument(citizenId, data) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) return { success: false, error: 'Citizen not found' };
      const documentId = 'DOC-' + Date.now();
      citizen.metadata.notes = citizen.metadata.notes || [];
      citizen.metadata.notes.push(`Document ${documentId} uploaded`);
      await citizen.save();
      return { success: true, documentId };
    } catch (err) {
      error(`Document upload failed for ${citizenId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async getCitizenNotifications(citizenId, filters) {
    try {
      const citizen = await Citizen.findOne({ citizenId }).select('auditLog');
      const notifications = citizen?.auditLog || [];

      // Filter unread if requested
      if (filters.unreadOnly) {
        // Assuming auditLog has 'read' flag; filter mock
        notifications.filter((n) => !n.read);
      }

      return { success: true, notifications };
    } catch (err) {
      error(`Get notifications failed for ${citizenId}:`, err);
      return { success: false, error: err.message };
    }
  }

  async getStatistics() {
    try {
      const stats = await Promise.all([
        Citizen.countDocuments({ status: 'active' }),
        Citizen.countDocuments({ 'ubiStatus.enrolled': true }),
        Citizen.aggregate([
          {
            $group: {
              _id: null,
              avgEducation: { $avg: '$educationStatus.overallProgress' },
            },
          },
        ]),
        ServiceRequest.countDocuments({
          status: { $in: ['open', 'in_progress'] },
        }),
      ]);

      return {
        success: true,
        stats: {
          activeCitizens: stats[0],
          ubiEnrolled: stats[1],
          avgEducationProgress: Math.round(stats[2][0]?.avgEducation || 0),
          openRequests: stats[3],
        },
      };
    } catch (err) {
      error('Statistics aggregation failed:', err);
      return { success: false, error: err.message };
    }
  }

  getHealthStatus() {
    return { status: 'healthy', mode: 'real-db' };
  }
}
