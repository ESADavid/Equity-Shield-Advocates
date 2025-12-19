/**
 * EDUCATION ENROLLMENT INTEGRATION TEST
 * Tests complete education system integration
 */

import AILearningService from '../../services/aiLearningService.js';
import CitizenPortalService from '../../services/citizenPortalService.js';

describe('Education Enrollment Integration', () => {
  let learningService;
  let portalService;
  let testCitizenId;
  let testCourseId;

  beforeAll(async () => {
    learningService = new AILearningService();
    portalService = new CitizenPortalService();

    // Register citizen
    const registration = await portalService.registerCitizen({
      firstName: 'Education',
      lastName: 'Student',
      dateOfBirth: '1995-01-01',
      gender: 'female',
      nationality: 'US',
      ssn: '987-65-4321',
      email: 'student@test.com',
      phone: '+1234567890',
    });

    testCitizenId = registration.citizenId;

    // Create course
    const course = await learningService.createCourse(
      {
        title: 'Integration Test Course',
        description: 'Test course for integration testing',
        category: 'technology',
        level: 'beginner',
        duration: 40,
      },
      'test-admin'
    );

    testCourseId = course.courseId;
  });

  test('should enroll citizen in course', async () => {
    const result = await portalService.enrollInCourse(
      testCitizenId,
      testCourseId
    );
    expect(result.success).toBe(true);
  });

  test('should get AI learning recommendations', async () => {
    const result = await learningService.getRecommendations(testCitizenId);
    expect(result.success).toBe(true);
    expect(result.recommendations).toBeDefined();
  });

  test('should track learning progress', async () => {
    const result = await learningService.updateProgress(
      testCitizenId,
      testCourseId,
      {
        progress: 50,
        completedLessons: 5,
      }
    );
    expect(result.success).toBe(true);
  });
});
