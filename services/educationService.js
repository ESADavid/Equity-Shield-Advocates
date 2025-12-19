/**
 * EDUCATION SERVICE
 * Manages mandatory education programs for all citizens
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 *
 * Four Mandatory Tracks:
 * - Military Training (6 months)
 * - Law Education (4 months)
 * - Technology Training (6 months)
 * - Agriculture Training (4 months)
 *
 * Total Required: 20 months for UBI eligibility
 */

import EducationProgram from '../models/Education.js';
import Citizen from '../models/Citizen.js';
import { info, error, warn, debug } from '../utils/loggerWrapper.js';

class EducationService {
  constructor() {
    this.programTypes = ['military', 'law', 'tech', 'agriculture'];
    this.programDurations = {
      military: 6,
      law: 4,
      tech: 6,
      agriculture: 4,
    };
    this.totalRequiredMonths = 20;

    info('Education Service initialized');
  }

  /**
   * Create a new education program
   * @param {Object} programData - Program details
   * @param {string} userId - User ID creating the program
   * @returns {Promise<Object>} Creation result
   */
  async createProgram(programData, userId) {
    try {
      info(
        `Creating ${programData.programType} program: ${programData.programInfo?.name}`
      );

      // Validate program type
      if (!this.programTypes.includes(programData.programType)) {
        return {
          success: false,
          error: `Invalid program type. Must be one of: ${this.programTypes.join(', ')}`,
        };
      }

      // Set duration based on program type
      if (!programData.programInfo) {
        programData.programInfo = {};
      }
      programData.programInfo.duration =
        this.programDurations[programData.programType];

      // Create program
      const program = new EducationProgram({
        ...programData,
        metadata: {
          ...programData.metadata,
          createdBy: userId,
        },
        status: 'active',
      });

      await program.save();

      info(`Program created successfully: ${program.programId}`);

      return {
        success: true,
        program: {
          programId: program.programId,
          programType: program.programType,
          name: program.programInfo.name,
          duration: program.programInfo.duration,
          capacity: program.enrollment.capacity,
          status: program.status,
        },
        message: 'Education program created successfully',
      };
    } catch (error) {
      error('Error creating program:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Enroll a citizen in an education program
   * @param {string} citizenId - Citizen ID
   * @param {string} programId - Program ID
   * @param {string} userId - User ID performing enrollment
   * @returns {Promise<Object>} Enrollment result
   */
  async enrollCitizen(citizenId, programId, userId) {
    try {
      info(`Enrolling citizen ${citizenId} in program ${programId}`);

      // Get citizen
      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      // Get program
      const program = await EducationProgram.findOne({ programId });
      if (!program) {
        return {
          success: false,
          error: 'Program not found',
        };
      }

      // Check if program is active
      if (program.status !== 'active') {
        return {
          success: false,
          error: 'Program is not currently active',
        };
      }

      // Enroll citizen in program
      const enrollmentResult = program.enrollCitizen(citizenId);
      if (!enrollmentResult.success) {
        return enrollmentResult;
      }

      await program.save();

      // Update citizen's education status
      const programType = program.programType;
      citizen.educationStatus[programType].enrolled = true;
      citizen.educationStatus[programType].enrollmentDate = new Date();
      citizen.educationStatus[programType].facilityId =
        program.facilities[0]?.facilityId;

      // Add audit log
      citizen.auditLog.push({
        action: 'EDUCATION_ENROLLED',
        performedBy: userId,
        timestamp: new Date(),
        details: {
          programId: programId,
          programType: programType,
          programName: program.programInfo.name,
        },
      });

      await citizen.save();

      info(
        `Citizen ${citizenId} enrolled successfully in ${programType} program`
      );

      return {
        success: true,
        enrollment: {
          citizenId: citizenId,
          citizenName: citizen.fullName,
          programId: programId,
          programType: programType,
          programName: program.programInfo.name,
          enrollmentDate: enrollmentResult.enrollmentDate,
          duration: program.programInfo.duration,
        },
        message: 'Citizen enrolled successfully',
      };
    } catch (error) {
      error('Error enrolling citizen:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Update citizen's progress in a program
   * @param {string} citizenId - Citizen ID
   * @param {string} programId - Program ID
   * @param {Object} progressData - Progress update data
   * @param {string} userId - User ID performing update
   * @returns {Promise<Object>} Update result
   */
  async updateProgress(citizenId, programId, progressData, userId) {
    try {
      info(
        `Updating progress for citizen ${citizenId} in program ${programId}`
      );

      // Get program
      const program = await EducationProgram.findOne({ programId });
      if (!program) {
        return {
          success: false,
          error: 'Program not found',
        };
      }

      // Update progress in program
      const updateResult = program.updateCitizenProgress(
        citizenId,
        progressData
      );
      if (!updateResult.success) {
        return updateResult;
      }

      await program.save();

      // Update citizen's education status
      const citizen = await Citizen.findOne({ citizenId });
      if (citizen) {
        const programType = program.programType;

        citizen.educationStatus[programType].progress =
          updateResult.citizen.progress;
        citizen.educationStatus[programType].currentModule =
          updateResult.citizen.currentModule;

        // Check if completed
        if (updateResult.citizen.status === 'completed') {
          citizen.educationStatus[programType].completed = true;
          citizen.educationStatus[programType].completionDate =
            updateResult.citizen.completionDate;
          citizen.educationStatus[programType].certificationId =
            updateResult.citizen.certificationId;

          // Add audit log
          citizen.auditLog.push({
            action: 'EDUCATION_COMPLETED',
            performedBy: userId,
            timestamp: new Date(),
            details: {
              programId: programId,
              programType: programType,
              certificationId: updateResult.citizen.certificationId,
            },
          });
        }

        // Update overall education progress
        citizen.updateEducationProgress();

        await citizen.save();
      }

      info(`Progress updated successfully for citizen ${citizenId}`);

      return {
        success: true,
        progress: {
          citizenId: citizenId,
          programId: programId,
          progress: updateResult.citizen.progress,
          status: updateResult.citizen.status,
          completionDate: updateResult.citizen.completionDate,
          certificationId: updateResult.citizen.certificationId,
        },
        message: 'Progress updated successfully',
      };
    } catch (error) {
      error('Error updating progress:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get all education programs
   * @param {Object} filters - Filter criteria
   * @returns {Promise<Object>} Programs list
   */
  async getPrograms(filters = {}) {
    try {
      const query = {};

      if (filters.programType) {
        query.programType = filters.programType;
      }

      if (filters.status) {
        query.status = filters.status;
      }

      const programs = await EducationProgram.find(query)
        .sort({ createdAt: -1 })
        .limit(filters.limit || 100);

      return {
        success: true,
        programs: programs.map((p) => ({
          programId: p.programId,
          programType: p.programType,
          name: p.programInfo.name,
          duration: p.programInfo.duration,
          enrollment: p.enrollment,
          enrollmentPercentage: p.enrollmentPercentage,
          completionRate: p.completionRate,
          status: p.status,
          startDate: p.schedule.startDate,
          endDate: p.schedule.endDate,
        })),
        count: programs.length,
      };
    } catch (error) {
      error('Error getting programs:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get citizen's education progress
   * @param {string} citizenId - Citizen ID
   * @returns {Promise<Object>} Progress details
   */
  async getCitizenProgress(citizenId) {
    try {
      const citizen = await Citizen.findOne({ citizenId });

      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      // Get enrolled programs
      const enrolledPrograms = await EducationProgram.find({
        'enrolledCitizens.citizenId': citizenId,
      });

      const programDetails = enrolledPrograms.map((program) => {
        const enrollment = program.enrolledCitizens.find(
          (ec) => ec.citizenId === citizenId
        );
        return {
          programId: program.programId,
          programType: program.programType,
          programName: program.programInfo.name,
          enrollmentDate: enrollment.enrollmentDate,
          status: enrollment.status,
          progress: enrollment.progress,
          currentModule: enrollment.currentModule,
          completedModules: enrollment.completedModules,
          attendance: enrollment.attendance,
          grades: enrollment.grades,
          completionDate: enrollment.completionDate,
          certificationId: enrollment.certificationId,
        };
      });

      return {
        success: true,
        citizen: {
          citizenId: citizen.citizenId,
          fullName: citizen.fullName,
        },
        educationStatus: citizen.educationStatus,
        enrolledPrograms: programDetails,
        summary: {
          overallProgress: citizen.educationStatus.overallProgress,
          totalMonthsCompleted: citizen.educationStatus.totalMonthsCompleted,
          requiredMonths: citizen.educationStatus.requiredMonths,
          complianceStatus: citizen.educationStatus.complianceStatus,
          tracksCompleted: {
            military: citizen.educationStatus.military.completed,
            law: citizen.educationStatus.law.completed,
            tech: citizen.educationStatus.tech.completed,
            agriculture: citizen.educationStatus.agriculture.completed,
          },
        },
      };
    } catch (error) {
      error('Error getting citizen progress:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Issue certification to a citizen
   * @param {string} citizenId - Citizen ID
   * @param {string} programId - Program ID
   * @param {string} userId - User ID issuing certification
   * @returns {Promise<Object>} Certification result
   */
  async issueCertification(citizenId, programId, userId) {
    try {
      info(
        `Issuing certification for citizen ${citizenId} in program ${programId}`
      );

      const program = await EducationProgram.findOne({ programId });
      if (!program) {
        return {
          success: false,
          error: 'Program not found',
        };
      }

      const citizen = await Citizen.findOne({ citizenId });
      if (!citizen) {
        return {
          success: false,
          error: 'Citizen not found',
        };
      }

      // Find enrollment
      const enrollment = program.enrolledCitizens.find(
        (ec) => ec.citizenId === citizenId
      );
      if (!enrollment) {
        return {
          success: false,
          error: 'Citizen not enrolled in this program',
        };
      }

      // Check if completed
      if (enrollment.status !== 'completed') {
        return {
          success: false,
          error: 'Citizen has not completed the program',
        };
      }

      // Check if certification already issued
      if (enrollment.certificationId) {
        return {
          success: true,
          certification: {
            certificationId: enrollment.certificationId,
            programType: program.programType,
            programName: program.programInfo.name,
            citizenName: citizen.fullName,
            completionDate: enrollment.completionDate,
            issuedDate: enrollment.completionDate,
          },
          message: 'Certification already issued',
        };
      }

      // Generate certification ID
      const certificationId = `CERT-${program.programType.toUpperCase()}-${citizenId}-${Date.now()}`;
      enrollment.certificationId = certificationId;

      // Update certification count
      program.certification.issued += 1;

      await program.save();

      // Update citizen
      const programType = program.programType;
      citizen.educationStatus[programType].certificationId = certificationId;

      citizen.auditLog.push({
        action: 'CERTIFICATION_ISSUED',
        performedBy: userId,
        timestamp: new Date(),
        details: {
          programId: programId,
          programType: programType,
          certificationId: certificationId,
        },
      });

      await citizen.save();

      info(`Certification issued: ${certificationId}`);

      return {
        success: true,
        certification: {
          certificationId: certificationId,
          programType: program.programType,
          programName: program.programInfo.name,
          citizenId: citizenId,
          citizenName: citizen.fullName,
          completionDate: enrollment.completionDate,
          issuedDate: new Date(),
          issuedBy: userId,
        },
        message: 'Certification issued successfully',
      };
    } catch (error) {
      error('Error issuing certification:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get education system statistics
   * @returns {Promise<Object>} System statistics
   */
  async getStatistics() {
    try {
      const totalPrograms = await EducationProgram.countDocuments();
      const activePrograms = await EducationProgram.countDocuments({
        status: 'active',
      });

      const programsByType = await EducationProgram.aggregate([
        { $group: { _id: '$programType', count: { $sum: 1 } } },
      ]);

      const totalEnrollments = await EducationProgram.aggregate([
        { $group: { _id: null, total: { $sum: '$enrollment.enrolled' } } },
      ]);

      const totalCompletions = await EducationProgram.aggregate([
        { $group: { _id: null, total: { $sum: '$enrollment.completed' } } },
      ]);

      const certificationsIssued = await EducationProgram.aggregate([
        { $group: { _id: null, total: { $sum: '$certification.issued' } } },
      ]);

      // Get citizen compliance statistics
      const totalCitizens = await Citizen.countDocuments({ status: 'active' });
      const compliantCitizens = await Citizen.countDocuments({
        status: 'active',
        'educationStatus.complianceStatus': 'compliant',
      });
      const inProgressCitizens = await Citizen.countDocuments({
        status: 'active',
        'educationStatus.complianceStatus': 'in_progress',
      });
      const nonCompliantCitizens = await Citizen.countDocuments({
        status: 'active',
        'educationStatus.complianceStatus': 'non_compliant',
      });

      return {
        success: true,
        statistics: {
          programs: {
            total: totalPrograms,
            active: activePrograms,
            byType: programsByType.reduce((acc, item) => {
              acc[item._id] = item.count;
              return acc;
            }, {}),
          },
          enrollments: {
            total: totalEnrollments[0]?.total || 0,
            completed: totalCompletions[0]?.total || 0,
            completionRate:
              totalEnrollments[0]?.total > 0
                ? (
                    ((totalCompletions[0]?.total || 0) /
                      totalEnrollments[0].total) *
                    100
                  ).toFixed(2) + '%'
                : '0%',
          },
          certifications: {
            issued: certificationsIssued[0]?.total || 0,
          },
          citizens: {
            total: totalCitizens,
            compliant: compliantCitizens,
            inProgress: inProgressCitizens,
            nonCompliant: nonCompliantCitizens,
            complianceRate:
              totalCitizens > 0
                ? ((compliantCitizens / totalCitizens) * 100).toFixed(2) + '%'
                : '0%',
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
   * Initialize default education programs
   * @param {string} userId - User ID creating programs
   * @returns {Promise<Object>} Initialization result
   */
  async initializeDefaultPrograms(userId) {
    try {
      info('Initializing default education programs');

      const defaultPrograms = [
        {
          programType: 'military',
          programInfo: {
            name: 'Basic Military Training',
            description:
              'Comprehensive 6-month military training program covering combat, discipline, leadership, and strategic thinking',
            level: 'beginner',
            objectives: [
              'Physical fitness and endurance',
              'Weapons handling and safety',
              'Combat tactics and strategy',
              'Leadership and teamwork',
              'Discipline and military protocol',
            ],
          },
          enrollment: { capacity: 10000 },
        },
        {
          programType: 'law',
          programInfo: {
            name: 'Legal Fundamentals',
            description:
              '4-month law education program covering constitutional law, civil rights, and legal procedures',
            level: 'beginner',
            objectives: [
              'Understanding constitutional law',
              'Civil rights and responsibilities',
              'Legal procedures and court systems',
              'Conflict resolution',
              'Civic engagement',
            ],
          },
          enrollment: { capacity: 15000 },
        },
        {
          programType: 'tech',
          programInfo: {
            name: 'Technology Fundamentals',
            description:
              '6-month technology training covering programming, AI, web development, and cybersecurity',
            level: 'beginner',
            objectives: [
              'Programming fundamentals',
              'AI and machine learning basics',
              'Web development',
              'Systems administration',
              'Cybersecurity principles',
            ],
          },
          enrollment: { capacity: 20000 },
        },
        {
          programType: 'agriculture',
          programInfo: {
            name: 'Sustainable Agriculture',
            description:
              '4-month agriculture training covering sustainable farming, hydroponics, and food security',
            level: 'beginner',
            objectives: [
              'Sustainable farming practices',
              'Hydroponics and modern agriculture',
              'Crop management',
              'Food security principles',
              'Agricultural technology',
            ],
          },
          enrollment: { capacity: 12000 },
        },
      ];

      const createdPrograms = [];

      for (const programData of defaultPrograms) {
        const result = await this.createProgram(programData, userId);
        if (result.success) {
          createdPrograms.push(result.program);
        }
      }

      info(`Initialized ${createdPrograms.length} default programs`);

      return {
        success: true,
        programs: createdPrograms,
        message: `${createdPrograms.length} default programs initialized`,
      };
    } catch (error) {
      error('Error initializing default programs:', error);
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
      service: 'Education Service',
      programTypes: this.programTypes,
      totalRequiredMonths: this.totalRequiredMonths,
      lastCheck: new Date().toISOString(),
    };
  }
}

export default EducationService;
