/**
 * CITIZEN PORTAL SERVICE
 * Self-service portal for citizens to access UBI, education, and government services
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import { info, error, warn, debug } from '../utils/loggerWrapper.js';
import Citizen from '../models/Citizen.js';
import UBIPayment from '../models/UBIPayment.js';
import Course from '../models/Course.js';
import multiChannelNotificationService from './multiChannelNotificationService.js';
import auditService from './auditService.js';

class CitizenPortalService {
  constructor() {
    this.SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
    this.MAX_LOGIN_ATTEMPTS = 5;
    this.LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

    info('Citizen Portal Service initialized');
  }

  /**
   * Register a new citizen
   * @param {Object} citizenData - Citizen registration data
   * @returns {Promise<Object>} Registration result
   */
  async registerCitizen(citizenData) {
    try {
      info(`Registering new citizen: ${citizenData.personalInfo?.firstName} ${citizenData.personalInfo?.lastName}`);

      // Validate registration data
      this.validateRegistrationData(citizenData);

      // Check for existing citizen
      const existingCitizen = await Citizen.findOne({
        $or: [
          { 'personalInfo.nationalId': citizenData.personalInfo.nationalId },
          { 'contactInfo.email': citizenData.contactInfo.email }
        ]
      });

      if (existingCitizen) {
        throw new Error('Citizen with this national ID or email already exists');
      }

      // Generate citizen ID
      const citizenId = await Citizen.generateCitizenId();

      // Create citizen record
      const citizen = new Citizen({
        citizenId,
        personalInfo: citizenData.personalInfo,
        contactInfo: citizenData.contactInfo,
        bankingInfo: citizenData.bankingInfo,
        ubiStatus: {
          eligible: true,
          enrollmentDate: new Date(),
          monthlyAmount: 2750, // $33,000 / 12
          annualAmount: 33000
        },
        educationStatus: {
          complianceStatus: 'in_progress',
          requiredMonths: 20
        },
        metadata: {
          registrationSource: 'citizen_portal',
          registeredBy: 'self'
        }
      });

      await citizen.save();

      // Log registration
      await auditService.logActivity('system', 'CITIZEN_REGISTRATION', {
        citizenId: citizen._id,
        citizenIdNumber: citizen.citizenId,
        registrationMethod: 'portal'
      });

      // Send welcome notification
      await this.sendWelcomeNotification(citizen);

      info(`Citizen registered successfully: ${citizen.citizenId}`);
      return {
        success: true,
        citizenId: citizen.citizenId,
        message: 'Registration completed successfully',
        nextSteps: [
          'Complete biometric verification',
          'Verify banking information',
          'Enroll in education programs'
        ]
      };

    } catch (err) {
      error('Citizen registration failed:', err);
      throw err;
    }
  }

  /**
   * Authenticate citizen login
   * @param {string} identifier - Email or citizen ID
   * @param {string} password - Password (placeholder for now)
   * @returns {Promise<Object>} Authentication result
   */
  async authenticateCitizen(identifier, password) {
    try {
      // Find citizen by email or citizen ID
      const citizen = await Citizen.findOne({
        $or: [
          { 'contactInfo.email': identifier },
          { citizenId: identifier }
        ]
      });

      if (!citizen) {
        throw new Error('Invalid credentials');
      }

      // Check if account is locked
      if (citizen.metadata?.loginAttempts?.lockedUntil > new Date()) {
        throw new Error('Account is temporarily locked due to too many failed attempts');
      }

      // For now, we'll use a simple authentication
      // In production, this would use proper password hashing/verification
      const isValidPassword = this.verifyPassword(password, citizen);

      if (!isValidPassword) {
        await this.recordFailedLogin(citizen._id);
        throw new Error('Invalid credentials');
      }

      // Reset login attempts on successful login
      await this.resetLoginAttempts(citizen._id);

      // Create session
      const session = await this.createSession(citizen._id);

      // Log successful login
      await auditService.logActivity(citizen._id, 'CITIZEN_LOGIN', {
        citizenId: citizen.citizenId,
        loginMethod: 'portal'
      });

      info(`Citizen authenticated: ${citizen.citizenId}`);
      return {
        success: true,
        citizenId: citizen.citizenId,
        sessionToken: session.token,
        citizen: {
          id: citizen._id,
          citizenId: citizen.citizenId,
          name: `${citizen.personalInfo.firstName} ${citizen.personalInfo.lastName}`,
          email: citizen.contactInfo.email
        }
      };

    } catch (err) {
      error('Citizen authentication failed:', err);
      throw err;
    }
  }

  /**
   * Get citizen dashboard data
   * @param {string} citizenId - Citizen ID
   * @returns {Promise<Object>} Dashboard data
   */
  async getCitizenDashboard(citizenId) {
    try {
      const citizen = await Citizen.findOne({ citizenId })
        .populate('dependents')
        .select('-bankingInfo.accountNumber -bankingInfo.routingNumber');

      if (!citizen) {
        throw new Error('Citizen not found');
      }

      // Get recent UBI payments
      const recentPayments = await UBIPayment.find({ citizenId: citizen._id })
        .sort({ paymentDate: -1 })
        .limit(5)
        .select('amount paymentDate status transactionId');

      // Get enrolled courses
      const enrolledCourses = await Course.find({
        'enrolledStudents.studentId': citizen._id
      })
      .select('title category difficulty enrolledStudents.$')
      .limit(10);

      // Calculate dashboard metrics
      const dashboardData = {
        profile: {
          citizenId: citizen.citizenId,
          name: `${citizen.personalInfo.firstName} ${citizen.personalInfo.lastName}`,
          email: citizen.contactInfo.email,
          phone: citizen.contactInfo.phone,
          status: citizen.status,
          registrationDate: citizen.createdAt
        },
        ubiStatus: {
          eligible: citizen.ubiStatus.eligible,
          monthlyAmount: citizen.ubiStatus.monthlyAmount,
          totalReceived: citizen.ubiStatus.totalReceived || 0,
          lastPaymentDate: citizen.ubiStatus.lastPaymentDate,
          nextPaymentDate: citizen.ubiStatus.nextPaymentDate,
          status: citizen.ubiStatus.suspended ? 'suspended' : 'active',
          suspensionReason: citizen.ubiStatus.suspensionReason
        },
        educationProgress: {
          overallProgress: citizen.educationStatus.overallProgress || 0,
          complianceStatus: citizen.educationStatus.complianceStatus,
          completedTracks: this.countCompletedTracks(citizen.educationStatus),
          totalRequired: 4,
          complianceDeadline: citizen.educationStatus.complianceDeadline
        },
        recentPayments: recentPayments.map(payment => ({
          id: payment._id,
          amount: payment.amount,
          date: payment.paymentDate,
          status: payment.status,
          transactionId: payment.transactionId
        })),
        enrolledCourses: enrolledCourses.map(course => ({
          id: course._id,
          title: course.title,
          category: course.category,
          difficulty: course.difficulty,
          progress: course.enrolledStudents[0]?.progress || 0,
          status: course.enrolledStudents[0]?.status || 'enrolled'
        })),
        notifications: await this.getCitizenNotifications(citizen._id),
        quickActions: this.getQuickActions(citizen)
      };

      return dashboardData;

    } catch (err) {
      error(`Failed to get dashboard for citizen ${citizenId}:`, err);
      throw err;
    }
  }

  /**
   * Update citizen profile
   * @param {string} citizenId - Citizen ID
   * @param {Object} updates - Profile updates
   * @returns {Promise<Object>} Update result
   */
  async updateCitizenProfile(citizenId, updates) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) {
        throw new Error('Citizen not found');
      }

      // Validate updates
      this.validateProfileUpdates(updates);

      // Apply updates
      if (updates.contactInfo) {
        Object.assign(citizen.contactInfo, updates.contactInfo);
      }

      if (updates.personalInfo) {
        Object.assign(citizen.personalInfo, updates.personalInfo);
      }

      if (updates.preferences) {
        citizen.preferences = { ...citizen.preferences, ...updates.preferences };
      }

      citizen.metadata.lastUpdatedBy = citizenId;
      await citizen.save();

      // Log profile update
      await auditService.logActivity(citizenId, 'PROFILE_UPDATE', {
        citizenId: citizen.citizenId,
        updatedFields: Object.keys(updates)
      });

      info(`Citizen profile updated: ${citizenId}`);
      return {
        success: true,
        message: 'Profile updated successfully',
        updatedFields: Object.keys(updates)
      };

    } catch (err) {
      error(`Profile update failed for citizen ${citizenId}:`, err);
      throw err;
    }
  }

  /**
   * Enroll citizen in UBI program
   * @param {string} citizenId - Citizen ID
   * @returns {Promise<Object>} Enrollment result
   */
  async enrollInUBI(citizenId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) {
        throw new Error('Citizen not found');
      }

      if (!citizen.ubiStatus.eligible) {
        throw new Error('Citizen is not eligible for UBI');
      }

      if (citizen.ubiStatus.enrollmentDate) {
        throw new Error('Citizen is already enrolled in UBI');
      }

      // Update UBI status
      citizen.ubiStatus.enrollmentDate = new Date();
      citizen.ubiStatus.nextPaymentDate = this.calculateNextPaymentDate(new Date());

      await citizen.save();

      // Log UBI enrollment
      await auditService.logActivity(citizenId, 'UBI_ENROLLMENT', {
        citizenId: citizen.citizenId,
        enrollmentDate: citizen.ubiStatus.enrollmentDate
      });

      // Send enrollment confirmation
      await this.sendUBIEnrollmentNotification(citizen);

      info(`Citizen enrolled in UBI: ${citizenId}`);
      return {
        success: true,
        message: 'Successfully enrolled in Universal Basic Income program',
        enrollmentDate: citizen.ubiStatus.enrollmentDate,
        nextPaymentDate: citizen.ubiStatus.nextPaymentDate,
        monthlyAmount: citizen.ubiStatus.monthlyAmount
      };

    } catch (err) {
      error(`UBI enrollment failed for citizen ${citizenId}:`, err);
      throw err;
    }
  }

  /**
   * Get citizen notifications
   * @param {string} citizenId - Citizen MongoDB ID
   * @returns {Promise<Array>} Notifications
   */
  async getCitizenNotifications(citizenId) {
    try {
      // This would integrate with a notification system
      // For now, return mock notifications based on citizen status

      const citizen = await Citizen.findById(citizenId);
      const notifications = [];

      if (!citizen.verification.identityVerified) {
        notifications.push({
          id: 'identity_verification',
          type: 'warning',
          title: 'Identity Verification Required',
          message: 'Please complete identity verification to access all services',
          action: 'Verify Identity',
          priority: 'high'
        });
      }

      if (!citizen.ubiStatus.enrollmentDate) {
        notifications.push({
          id: 'ubi_enrollment',
          type: 'info',
          title: 'UBI Enrollment Available',
          message: 'You are eligible for Universal Basic Income. Enroll now to start receiving payments.',
          action: 'Enroll in UBI',
          priority: 'medium'
        });
      }

      if (citizen.educationStatus.complianceStatus === 'non_compliant') {
        notifications.push({
          id: 'education_compliance',
          type: 'alert',
          title: 'Education Compliance Required',
          message: 'Complete your education requirements to maintain UBI eligibility.',
          action: 'View Education Programs',
          priority: 'high'
        });
      }

      return notifications;

    } catch (err) {
      error(`Failed to get notifications for citizen ${citizenId}:`, err);
      return [];
    }
  }

  /**
   * Get quick actions for citizen
   * @param {Object} citizen - Citizen document
   * @returns {Array} Quick actions
   */
  getQuickActions(citizen) {
    const actions = [];

    if (!citizen.verification.identityVerified) {
      actions.push({
        id: 'verify_identity',
        title: 'Verify Identity',
        description: 'Complete biometric verification',
        icon: 'fingerprint',
        priority: 'high'
      });
    }

    if (!citizen.ubiStatus.enrollmentDate) {
      actions.push({
        id: 'enroll_ubi',
        title: 'Enroll in UBI',
        description: 'Start receiving Universal Basic Income',
        icon: 'payment',
        priority: 'high'
      });
    }

    actions.push({
      id: 'view_education',
      title: 'Education Programs',
      description: 'Browse and enroll in courses',
      icon: 'school',
      priority: 'medium'
    });

    actions.push({
      id: 'payment_history',
      title: 'Payment History',
      description: 'View your UBI payment records',
      icon: 'history',
      priority: 'medium'
    });

    actions.push({
      id: 'update_profile',
      title: 'Update Profile',
      description: 'Manage your personal information',
      icon: 'person',
      priority: 'low'
    });

    return actions;
  }

  /**
   * Validate registration data
   * @param {Object} data - Registration data
   */
  validateRegistrationData(data) {
    const required = ['personalInfo', 'contactInfo'];
    for (const field of required) {
      if (!data[field]) {
        throw new Error(`${field} is required`);
      }
    }

    // Validate personal info
    const personalInfo = data.personalInfo;
    if (!personalInfo.firstName || !personalInfo.lastName || !personalInfo.dateOfBirth) {
      throw new Error('First name, last name, and date of birth are required');
    }

    // Validate contact info
    const contactInfo = data.contactInfo;
    if (!contactInfo.email || !contactInfo.phone) {
      throw new Error('Email and phone are required');
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(contactInfo.email)) {
      throw new Error('Invalid email format');
    }
  }

  /**
   * Validate profile updates
   * @param {Object} updates - Profile updates
   */
  validateProfileUpdates(updates) {
    // Add validation logic for profile updates
    // This would include email format validation, phone validation, etc.
  }

  /**
   * Count completed education tracks
   * @param {Object} educationStatus - Education status
   * @returns {number} Number of completed tracks
   */
  countCompletedTracks(educationStatus) {
    let completed = 0;
    const tracks = ['military', 'law', 'tech', 'agriculture'];

    tracks.forEach(track => {
      if (educationStatus[track]?.completed) {
        completed++;
      }
    });

    return completed;
  }

  /**
   * Calculate next payment date
   * @param {Date} fromDate - Date to calculate from
   * @returns {Date} Next payment date
   */
  calculateNextPaymentDate(fromDate) {
    const nextPayment = new Date(fromDate);
    nextPayment.setMonth(nextPayment.getMonth() + 1);
    return nextPayment;
  }

  /**
   * Send welcome notification
   * @param {Object} citizen - Citizen document
   */
  async sendWelcomeNotification(citizen) {
    try {
      await multiChannelNotificationService.send({
        type: 'CITIZEN_WELCOME',
        priority: 'medium',
        title: 'Welcome to Heaven on Earth',
        message: `Welcome ${citizen.personalInfo.firstName}! Your citizen portal is ready.`,
        recipients: [citizen.contactInfo.email],
        metadata: {
          citizenId: citizen.citizenId,
          welcome: true
        }
      });
    } catch (err) {
      warn('Failed to send welcome notification:', err);
    }
  }

  /**
   * Send UBI enrollment notification
   * @param {Object} citizen - Citizen document
   */
  async sendUBIEnrollmentNotification(citizen) {
    try {
      await multiChannelNotificationService.send({
        type: 'UBI_ENROLLMENT',
        priority: 'high',
        title: 'UBI Enrollment Confirmed',
        message: `Congratulations! You are now enrolled in Universal Basic Income. Your first payment will be processed on ${citizen.ubiStatus.nextPaymentDate.toDateString()}.`,
        recipients: [citizen.contactInfo.email],
        metadata: {
          citizenId: citizen.citizenId,
          ubiAmount: citizen.ubiStatus.monthlyAmount
        }
      });
    } catch (err) {
      warn('Failed to send UBI enrollment notification:', err);
    }
  }

  /**
   * Verify password (placeholder implementation)
   * @param {string} password - Password to verify
   * @param {Object} citizen - Citizen document
   * @returns {boolean} Verification result
   */
  verifyPassword(password, citizen) {
    // Placeholder - in production, this would use proper password hashing
    // For now, accept any non-empty password
    return password && password.length > 0;
  }

  /**
   * Record failed login attempt
   * @param {string} citizenId - Citizen MongoDB ID
   */
  async recordFailedLogin(citizenId) {
    try {
      const citizen = await Citizen.findById(citizenId);
      if (!citizen) return;

      citizen.metadata = citizen.metadata || {};
      citizen.metadata.loginAttempts = citizen.metadata.loginAttempts || { count: 0 };

      citizen.metadata.loginAttempts.count++;

      // Lock account if too many attempts
      if (citizen.metadata.loginAttempts.count >= this.MAX_LOGIN_ATTEMPTS) {
        citizen.metadata.loginAttempts.lockedUntil = new Date(Date.now() + this.LOCKOUT_DURATION);
      }

      await citizen.save();
    } catch (err) {
      error('Failed to record failed login:', err);
    }
  }

  /**
   * Reset login attempts
   * @param {string} citizenId - Citizen MongoDB ID
   */
  async resetLoginAttempts(citizenId) {
    try {
      await Citizen.findByIdAndUpdate(citizenId, {
        'metadata.loginAttempts': { count: 0 }
      });
    } catch (err) {
      error('Failed to reset login attempts:', err);
    }
  }

  /**
   * Create session (placeholder)
   * @param {string} citizenId - Citizen MongoDB ID
   * @returns {Promise<Object>} Session object
   */
  async createSession(citizenId) {
    // Placeholder session creation
    // In production, this would create a proper session with JWT or similar
    return {
      token: `session_${citizenId}_${Date.now()}`,
      expiresAt: new Date(Date.now() + this.SESSION_TIMEOUT)
    };
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'operational',
      service: 'Citizen Portal Service',
      sessionTimeout: `${this.SESSION_TIMEOUT / 1000}s`,
      maxLoginAttempts: this.MAX_LOGIN_ATTEMPTS,
      lockoutDuration: `${this.LOCKOUT_DURATION / 1000}s`,
      lastCheck: new Date().toISOString()
    };
  }
}

export default new CitizenPortalService();
