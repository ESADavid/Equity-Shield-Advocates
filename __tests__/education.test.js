/**
 * Education Service Tests - Heaven on Earth Phase 2
 */

const EducationService = require('../services/educationService');
const mongoose = require('mongoose');

describe('Education Service', () => {
  beforeAll(async () => {
    await mongoose.connect('mongodb://localhost:27017/test');
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  test('should enroll citizen in curriculum', async () => {
    const mockCitizenId = new mongoose.Types.ObjectId();
    const result = await EducationService.enrollCitizen(mockCitizenId, 'military', 6);
    expect(result.enrolled).toBe(true);
  });

  test('should update education progress', async () => {
    const mockCitizenId = new mongoose.Types.ObjectId();
    const education = await EducationService.updateProgress(mockCitizenId, 75);
    expect(education.progress).toBe(75);
  });

  test('should generate compliance report', async () => {
    const mockCitizenId = new mongoose.Types.ObjectId();
    const report = await EducationService.getComplianceReport(mockCitizenId);
    expect(report).toHaveProperty('citizenId');
    expect(report).toHaveProperty('progress');
  });

  test('should get curriculum report', async () => {
    const report = await EducationService.generateCurriculumReport('military');
    expect(report).toHaveProperty('total');
    expect(report.averageProgress).toBeDefined();
  });
});

