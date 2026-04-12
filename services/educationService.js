/**
 * Education Service - Heaven on Earth Phase 2
 * Mandatory education management and compliance
 */

import { info, warn, error } from '../utils/logger.js';
const Education = require('../models/Education');
const Citizen = require('../models/Citizen');
const UBI = require('./universalBasicIncomeService');

class EducationService {
  static async enrollCitizen(citizenId, curriculum, durationMonths) {
    // Check if already enrolled
    const existing = await Education.findOne({ citizenId });
    if (existing) {
      return { enrolled: false, reason: 'Already enrolled' };
    }

    const educationRecord = new Education({
      citizenId,
      curriculum,
      durationMonths
    });

    await educationRecord.save();
    logger.info(`Citizen ${citizenId} enrolled in ${curriculum} (${durationMonths} months)`);
    return { enrolled: true, educationId: educationRecord._id };
  }

  static async updateProgress(citizenId, progress) {
    const education = await Education.findOne({ citizenId });
    if (!education) throw new Error('Education record not found');

    education.progress = Math.min(100, Math.max(0, progress));
    education.completionDate = education.progress >= 100 ? new Date() : null;
    education.complianceStatus = education.progress >= 100 ? 'compliant' : 'in-progress';

    await education.save();

    // Check UBI compliance
    if (education.progress < 80) {
      await UBI.suspendUBI(citizenId, 'Education progress below threshold');
    } else if (education.progress >= 95) {
      await UBI.reinstateUBI(citizenId);
    }

    logger.info(`Education progress updated for ${citizenId}: ${progress}%`);
    return education;
  }

  static async getComplianceReport(citizenId) {
    const education = await Education.findOne({ citizenId }).populate('citizenId');
    const citizen = await Citizen.findById(citizenId);

    return {
      citizenId,
      curriculum: education?.curriculum,
      progress: education?.progress || 0,
      complianceStatus: education?.complianceStatus || 'not-enrolled',
      ubiSuspended: citizen?.ubiSuspended || false
    };
  }

  static async getNonCompliantCitizens() {
    const nonCompliant = await Education.find({ complianceStatus: 'non-compliant' });
    return nonCompliant;
  }

  static async generateCurriculumReport(curriculum) {
    const stats = await Education.aggregate([
      { $match: { curriculum } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          averageProgress: { $avg: '$progress' },
          completed: { $sum: { $cond: [{ $gte: ['$progress', 100] }, 1, 0] } }
        }
      }
    ]);

    return stats[0] || { total: 0, averageProgress: 0, completed: 0 };
  }
}

module.exports = EducationService;

