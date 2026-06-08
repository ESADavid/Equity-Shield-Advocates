/**
 * Education Service - Heaven on Earth Phase 2
 * Mandatory education management and compliance
 */

import { info, warn, error } from '../utils/loggerWrapper.js';
import Education from '../models/Education.js';
import Citizen from '../models/Citizen.js';
import UniversalBasicIncomeService from './universalBasicIncomeService.js';

class EducationService {
  /**
   * Enroll a citizen in mandatory education
   * @param {string} citizenId - Citizen ID
   * @param {string} curriculum - Curriculum type (military, law, technology, agriculture)
   * @param {number} durationMonths - Duration in months
   * @returns {Promise<{enrolled: boolean, reason?: string, educationId?: import('mongoose').Types.ObjectId}>}
   */
  static async enrollCitizen(
    /** @type {string} */ citizenId,
    /** @type {string} */ curriculum,
    /** @type {number} */ durationMonths
  ) {
    // Check if already enrolled
    const existing = await Education.findOne({ citizenId });
    if (existing) {
      return { enrolled: false, reason: 'Already enrolled' };
    }

    const educationRecord = new Education({
      citizenId,
      curriculum,
      durationMonths,
    });

    await educationRecord.save();
    info(
      `Citizen ${citizenId} enrolled in ${curriculum} (${durationMonths} months)`
    );
    return { enrolled: true, educationId: educationRecord._id };
  }

  /**
   * Update education progress for a citizen
   * @param {string} citizenId - Citizen ID
   * @param {number} progress - Progress percentage (0-100)
   * @returns {Promise<import('../models/Education.js').default>}
   */
  static async updateProgress(
    /** @type {string} */ citizenId,
    /** @type {number} */ progress
  ) {
    const education = await Education.findOne({ citizenId });
    if (!education) throw new Error('Education record not found');

    // Use type assertion for mongoose document fields
    /** @type {number} */
    const progressValue = Math.min(100, Math.max(0, progress));
    education.progress = progressValue;
    education.completionDate = progressValue >= 100 ? new Date() : null;
    education.complianceStatus =
      progressValue >= 100 ? 'compliant' : 'in-progress';

    await education.save();

    // Check UBI compliance
    if (progressValue < 80) {
      await UniversalBasicIncomeService.suspendUBI(citizenId, 'Education progress below threshold');
    } else if (progressValue >= 95) {
      await UniversalBasicIncomeService.reinstateUBI(citizenId);
    }

    info(`Education progress updated for ${citizenId}: ${progress}%`);
    return education;
  }

  /**
   * Get compliance report for a citizen
   * @param {string} citizenId - Citizen ID
   * @returns {Promise<{citizenId: string, curriculum?: string, progress: number, complianceStatus: string, ubiSuspended: boolean}>}
   */
  static async getComplianceReport(
    /** @type {string} */ citizenId
  ) {
    const education = await Education.findOne({ citizenId }).populate(
      'citizenId'
    );
    const citizen = await Citizen.findById(citizenId);

    return {
      citizenId,
      curriculum: education?.curriculum,
      progress: education?.progress || 0,
      complianceStatus: education?.complianceStatus || 'not-enrolled',
      // Fix: ubiSuspended is nested under ubiStatus in Citizen model
      ubiSuspended: citizen?.ubiStatus?.suspended || false,
    };
  }

  /**
   * Get all non-compliant citizens
   * @returns {Promise<import('../models/Education.js').default[]>}
   */
  static async getNonCompliantCitizens() {
    const nonCompliant = await Education.find({
      complianceStatus: 'non-compliant',
    });
    return nonCompliant;
  }

  /**
   * Generate curriculum statistics report
   * @param {string} curriculum - Curriculum type
   * @returns {Promise<{total: number, averageProgress: number, completed: number}>}
   */
  static async generateCurriculumReport(
    /** @type {string} */ curriculum
  ) {
    const stats = await Education.aggregate([
      { $match: { curriculum } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          averageProgress: { $avg: '$progress' },
          completed: { $sum: { $cond: [{ $gte: ['$progress', 100] }, 1, 0] } },
        },
      },
    ]);

    return stats[0] || { total: 0, averageProgress: 0, completed: 0 };
  }
}

export default EducationService;
