/**
 * CITIZEN PORTAL SERVICE
 * Backend service for citizen-facing portal
 * Part of Phase 2: Heaven on Earth Implementation
 * 
 * Features:
 * - Citizen registration and profile management
 * - UBI enrollment and tracking
 * - Education access and progress
 * - Service requests and support
 * - Document management
 * - Communication with administrators
 */

import { createLogger } from '../config/logger.js';

const logger = createLogger('Citizen-Portal-Service');

class CitizenPortalService {
  constructor() {
    this.citizens = new Map();
    this.serviceRequests = new Map();
    this.documents = new Map();
    this.messages = new Map();
    this.notifications = new Map();
    
    logger.info('Citizen Portal Service initialized');
  }

  /**
   * Register a new citizen
   * @param {Object} citizenData - Citizen registration data
   * @returns {Object} Registration result
   */
  async registerCitizen(citizenData) {
    try {
      const citizenId = `CIT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      const citizen = {
        citizenId: citizenId,
        
        // Personal Information
        personalInfo: {
          firstName: citizenData.firstName,
          lastName: citizenData.lastName,
          middleName: citizenData.middleName || '',
          dateOfBirth: citizenData.dateOfBirth,
          gender: citizenData.gender,
          nationality: citizenData.nationality,
          ssn: citizenData.ssn, // Encrypted in production
          profilePhoto: citizenData.profilePhoto || null
        },
        
        // Contact Information
        contact: {
          email: citizenData.email,
          phone: citizenData.phone,
          alternatePhone: citizenData.alternatePhone || '',
          address: {
            street: citizenData.address?.street || '',
            city: citizenData.address?.city || '',
            state: citizenData.address?.state || '',
            country: citizenData.address?.country || '',
            postalCode: citizenData.address?.postalCode || ''
          },
          emergencyContact: citizenData.emergencyContact || {}
        },
        
        // Account Status
        status: 'active',
        verificationStatus: 'pending',
        registrationDate: new Date().toISOString(),
        lastLogin: null,
        
        // UBI Enrollment
        ubiEnrollment: {
          enrolled: false,
          enrollmentDate: null,
          status: 'not-enrolled',
          paymentMethod: null,
          bankAccount: null,
          totalReceived: 0,
          lastPayment: null,
          paymentHistory: []
        },
        
        // Education
        education: {
          enrolled: false,
          courses: [],
          completedCourses: [],
          inProgressCourses: [],
          certificates: [],
          totalHours: 0,
          achievements: []
        },
        
        // Healthcare
        healthcare: {
          enrolled: false,
          provider: null,
          insuranceNumber: null,
          medicalHistory: [],
          appointments: [],
          prescriptions: []
        },
        
        // Employment
        employment: {
          status: citizenData.employmentStatus || 'unemployed',
          employer: citizenData.employer || null,
          occupation: citizenData.occupation || null,
          income: citizenData.income || 0,
          employmentHistory: []
        },
        
        // Family
        family: {
          maritalStatus: citizenData.maritalStatus || 'single',
          dependents: citizenData.dependents || 0,
          householdSize: citizenData.householdSize || 1,
          householdIncome: citizenData.householdIncome || 0
        },
        
        // Services
        services: {
          active: [],
          requested: [],
          completed: []
        },
        
        // Documents
        documents: {
          identityProof: null,
          addressProof: null,
          birthCertificate: null,
          other: []
        },
        
        // Preferences
        preferences: {
          language: citizenData.language || 'en',
          timezone: citizenData.timezone || 'UTC',
          notifications: {
            email: true,
            sms: true,
            push: true
          },
          privacy: {
            shareData: false,
            publicProfile: false
          }
        },
        
        // Activity
        activityLog: [{
          timestamp: new Date().toISOString(),
          action: 'citizen_registered',
          details: { status: 'pending_verification' }
        }],
        
        // Metadata
        createdAt: new Date().toISOString(),
        lastUpdated: new Date().toISOString()
      };

      this.citizens.set(citizenId, citizen);

      // Send welcome notification
      await this.sendWelcomeNotification(citizenId);

      logger.info(`Citizen registered: ${citizenId} - ${citizen.personalInfo.firstName} ${citizen.personalInfo.lastName}`);

      return {
        success: true,
        citizenId: citizenId,
        citizen: this.sanitizeCitizenData(citizen),
        message: 'Registration successful. Please verify your account.'
      };
    } catch (error) {
      logger.error('Error registering citizen:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send welcome notification to new citizen
   */
  async sendWelcomeNotification(citizenId) {
    try {
      const notificationId = `NOTIF-${citizenId}-WELCOME`;
      
      const notification = {
        notificationId: notificationId,
        citizenId: citizenId,
        type: 'welcome',
        title: 'Welcome to Heaven on Earth Initiative',
        message: 'Your registration is complete. Please verify your account to access all services.',
        priority: 'high',
        read: false,
        createdAt: new Date().toISOString()
      };

      this.notifications.set(notificationId, notification);

      logger.info(`Welcome notification sent to citizen ${citizenId}`);
    } catch (error) {
      logger.error('Error sending welcome notification:', error);
    }
  }

  /**
   * Enroll citizen in UBI program
   * @param {string} citizenId - Citizen ID
   * @param {Object} enrollmentData - Enrollment details
   * @returns {Object} Enrollment result
   */
  async enrollInUBI(citizenId, enrollmentData) {
    try {
      const citizen = this.citizens.get(citizenId);

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found'
        };
      }

      if (citizen.verificationStatus !== 'verified') {
        return {
          success: false,
          error: 'Account must be verified before enrolling in UBI'
        };
      }

      if (citizen.ubiEnrollment.enrolled) {
        return {
          success: false,
          error: 'Already enrolled in UBI program'
        };
      }

      // Update UBI enrollment
      citizen.ubiEnrollment = {
        enrolled: true,
        enrollmentDate: new Date().toISOString(),
        status: 'active',
        paymentMethod: enrollmentData.paymentMethod,
        bankAccount: enrollmentData.bankAccount, // Encrypted in production
        totalReceived: 0,
        lastPayment: null,
        paymentHistory: []
      };

      citizen.services.active.push('ubi');
      citizen.lastUpdated = new Date().toISOString();

      citizen.activityLog.push({
        timestamp: new Date().toISOString(),
        action: 'ubi_enrolled',
        details: { paymentMethod: enrollmentData.paymentMethod }
      });

      logger.info(`Citizen ${citizenId} enrolled in UBI program`);

      return {
        success: true,
        enrollment: citizen.ubiEnrollment,
        message: 'Successfully enrolled in UBI program'
      };
    } catch (error) {
      logger.error('Error enrolling in UBI:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Enroll citizen in education course
   * @param {string} citizenId - Citizen ID
   * @param {string} courseId - Course ID
   * @returns {Object} Enrollment result
   */
  async enrollInCourse(citizenId, courseId) {
    try {
      const citizen = this.citizens.get(citizenId);

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found'
        };
      }

      // Check if already enrolled
      if (citizen.education.courses.includes(courseId)) {
        return {
          success: false,
          error: 'Already enrolled in this course'
        };
      }

      // Add course enrollment
      citizen.education.enrolled = true;
      citizen.education.courses.push(courseId);
      citizen.education.inProgressCourses.push({
        courseId: courseId,
        enrollmentDate: new Date().toISOString(),
        progress: 0,
        status: 'in-progress'
      });

      if (!citizen.services.active.includes('education')) {
        citizen.services.active.push('education');
      }

      citizen.lastUpdated = new Date().toISOString();

      citizen.activityLog.push({
        timestamp: new Date().toISOString(),
        action: 'course_enrolled',
        details: { courseId: courseId }
      });

      logger.info(`Citizen ${citizenId} enrolled in course ${courseId}`);

      return {
        success: true,
        courseId: courseId,
        message: 'Successfully enrolled in course'
      };
    } catch (error) {
      logger.error('Error enrolling in course:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Create service request
   * @param {string} citizenId - Citizen ID
   * @param {Object} requestData - Service request details
   * @returns {Object} Request creation result
   */
  async createServiceRequest(citizenId, requestData) {
    try {
      const citizen = this.citizens.get(citizenId);

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found'
        };
      }

      const requestId = `REQ-${citizenId}-${Date.now()}`;

      const serviceRequest = {
        requestId: requestId,
        citizenId: citizenId,
        citizenName: `${citizen.personalInfo.firstName} ${citizen.personalInfo.lastName}`,
        
        type: requestData.type, // support, complaint, inquiry, etc.
        category: requestData.category,
        subject: requestData.subject,
        description: requestData.description,
        priority: requestData.priority || 'medium',
        
        status: 'submitted',
        assignedTo: null,
        
        attachments: requestData.attachments || [],
        
        timeline: [{
          timestamp: new Date().toISOString(),
          status: 'submitted',
          note: 'Service request submitted'
        }],
        
        responses: [],
        resolution: null,
        
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      this.serviceRequests.set(requestId, serviceRequest);
      citizen.services.requested.push(requestId);

      citizen.activityLog.push({
        timestamp: new Date().toISOString(),
        action: 'service_request_created',
        details: { requestId: requestId, type: requestData.type }
      });

      logger.info(`Service request created: ${requestId} for citizen ${citizenId}`);

      return {
        success: true,
        requestId: requestId,
        serviceRequest: serviceRequest,
        message: 'Service request submitted successfully'
      };
    } catch (error) {
      logger.error('Error creating service request:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Upload document for citizen
   * @param {string} citizenId - Citizen ID
   * @param {Object} documentData - Document details
   * @returns {Object} Upload result
   */
  async uploadDocument(citizenId, documentData) {
    try {
      const citizen = this.citizens.get(citizenId);

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found'
        };
      }

      const documentId = `DOC-${citizenId}-${Date.now()}`;

      const document = {
        documentId: documentId,
        citizenId: citizenId,
        type: documentData.type,
        category: documentData.category,
        name: documentData.name,
        fileUrl: documentData.fileUrl, // In production, store in secure storage
        fileSize: documentData.fileSize,
        mimeType: documentData.mimeType,
        uploadDate: new Date().toISOString(),
        status: 'pending-review',
        verifiedBy: null,
        verifiedAt: null
      };

      this.documents.set(documentId, document);

      // Update citizen's documents
      if (documentData.category === 'identity') {
        citizen.documents.identityProof = documentId;
      } else if (documentData.category === 'address') {
        citizen.documents.addressProof = documentId;
      } else {
        citizen.documents.other.push(documentId);
      }

      citizen.activityLog.push({
        timestamp: new Date().toISOString(),
        action: 'document_uploaded',
        details: { documentId: documentId, type: documentData.type }
      });

      logger.info(`Document uploaded for citizen ${citizenId}: ${documentId}`);

      return {
        success: true,
        documentId: documentId,
        document: document,
        message: 'Document uploaded successfully'
      };
    } catch (error) {
      logger.error('Error uploading document:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get citizen profile
   * @param {string} citizenId - Citizen ID
   * @returns {Object} Citizen profile
   */
  getCitizenProfile(citizenId) {
    try {
      const citizen = this.citizens.get(citizenId);

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found'
        };
      }

      return {
        success: true,
        profile: this.sanitizeCitizenData(citizen),
        summary: {
          ubiEnrolled: citizen.ubiEnrollment.enrolled,
          educationEnrolled: citizen.education.enrolled,
          activeCourses: citizen.education.inProgressCourses.length,
          completedCourses: citizen.education.completedCourses.length,
          activeServices: citizen.services.active.length,
          pendingRequests: citizen.services.requested.filter(reqId => {
            const req = this.serviceRequests.get(reqId);
            return req && req.status !== 'resolved';
          }).length
        }
      };
    } catch (error) {
      logger.error('Error getting citizen profile:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Update citizen profile
   * @param {string} citizenId - Citizen ID
   * @param {Object} updates - Profile updates
   * @returns {Object} Update result
   */
  updateCitizenProfile(citizenId, updates) {
    try {
      const citizen = this.citizens.get(citizenId);

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found'
        };
      }

      // Update allowed fields
      if (updates.contact) {
        citizen.contact = { ...citizen.contact, ...updates.contact };
      }

      if (updates.preferences) {
        citizen.preferences = { ...citizen.preferences, ...updates.preferences };
      }

      if (updates.employment) {
        citizen.employment = { ...citizen.employment, ...updates.employment };
      }

      citizen.lastUpdated = new Date().toISOString();

      citizen.activityLog.push({
        timestamp: new Date().toISOString(),
        action: 'profile_updated',
        details: { fields: Object.keys(updates) }
      });

      logger.info(`Citizen profile updated: ${citizenId}`);

      return {
        success: true,
        profile: this.sanitizeCitizenData(citizen),
        message: 'Profile updated successfully'
      };
    } catch (error) {
      logger.error('Error updating citizen profile:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get citizen notifications
   * @param {string} citizenId - Citizen ID
   * @param {Object} filters - Filter options
   * @returns {Object} Notifications list
   */
  getCitizenNotifications(citizenId, filters = {}) {
    try {
      let notifications = Array.from(this.notifications.values())
        .filter(n => n.citizenId === citizenId);

      if (filters.unreadOnly) {
        notifications = notifications.filter(n => !n.read);
      }

      // Sort by date (newest first)
      notifications.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      return {
        success: true,
        notifications: notifications,
        count: notifications.length,
        unreadCount: notifications.filter(n => !n.read).length
      };
    } catch (error) {
      logger.error('Error getting citizen notifications:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get service request details
   * @param {string} requestId - Request ID
   * @returns {Object} Request details
   */
  getServiceRequest(requestId) {
    try {
      const request = this.serviceRequests.get(requestId);

      if (!request) {
        return {
          success: false,
          error: 'Service request not found'
        };
      }

      return {
        success: true,
        serviceRequest: request
      };
    } catch (error) {
      logger.error('Error getting service request:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Sanitize citizen data (remove sensitive information)
   */
  sanitizeCitizenData(citizen) {
    const sanitized = { ...citizen };
    
    // Remove or mask sensitive data
    if (sanitized.personalInfo?.ssn) {
      sanitized.personalInfo.ssn = '***-**-' + sanitized.personalInfo.ssn.slice(-4);
    }
    
    if (sanitized.ubiEnrollment?.bankAccount) {
      sanitized.ubiEnrollment.bankAccount = {
        ...sanitized.ubiEnrollment.bankAccount,
        accountNumber: '****' + sanitized.ubiEnrollment.bankAccount.accountNumber?.slice(-4)
      };
    }

    return sanitized;
  }

  /**
   * Get service statistics
   * @returns {Object} Service statistics
   */
  getStatistics() {
    try {
      const citizens = Array.from(this.citizens.values());
      const requests = Array.from(this.serviceRequests.values());

      return {
        success: true,
        statistics: {
          citizens: {
            total: citizens.length,
            active: citizens.filter(c => c.status === 'active').length,
            verified: citizens.filter(c => c.verificationStatus === 'verified').length,
            pending: citizens.filter(c => c.verificationStatus === 'pending').length
          },
          ubi: {
            enrolled: citizens.filter(c => c.ubiEnrollment.enrolled).length,
            totalPaid: citizens.reduce((sum, c) => sum + c.ubiEnrollment.totalReceived, 0)
          },
          education: {
            enrolled: citizens.filter(c => c.education.enrolled).length,
            totalCourses: citizens.reduce((sum, c) => sum + c.education.courses.length, 0),
            completedCourses: citizens.reduce((sum, c) => sum + c.education.completedCourses.length, 0)
          },
          serviceRequests: {
            total: requests.length,
            submitted: requests.filter(r => r.status === 'submitted').length,
            inProgress: requests.filter(r => r.status === 'in-progress').length,
            resolved: requests.filter(r => r.status === 'resolved').length
          },
          documents: this.documents.size
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('Error getting statistics:', error);
      return {
        success: false,
        error: error.message
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
      service: 'Citizen Portal Service',
      citizens: this.citizens.size,
      serviceRequests: this.serviceRequests.size,
      documents: this.documents.size,
      notifications: this.notifications.size,
      lastCheck: new Date().toISOString()
    };
  }
}

export default CitizenPortalService;
