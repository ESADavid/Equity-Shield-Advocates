/**
 * EDUCATION API ENDPOINTS TEST
 * Tests all education route endpoints
 */

import request from 'supertest';
import express from 'express';
import educationRoutes from '../../routes/educationRoutes.js';

const app = express();
app.use(express.json());
app.use('/api/education', educationRoutes);

describe('Education API Endpoints', () => {
  let testCourseId;

  test('POST /api/education/courses', async () => {
    const response = await request(app).post('/api/education/courses').send({
      title: 'API Test Course',
      description: 'Course for API testing',
      category: 'technology',
      level: 'beginner',
      duration: 40,
    });

    expect([200, 201]).toContain(response.status);
    if (response.body.courseId) {
      testCourseId = response.body.courseId;
    }
  });

  test('GET /api/education/courses', async () => {
    const response = await request(app).get('/api/education/courses');

    expect(response.status).toBe(200);
  });

  test('POST /api/education/enroll', async () => {
    const response = await request(app)
      .post('/api/education/enroll')
      .send({
        studentId: 'STU-TEST-001',
        courseId: testCourseId || 'COURSE-001',
      });

    expect([200, 201, 400]).toContain(response.status);
  });

  test('GET /api/education/recommendations/:studentId', async () => {
    const response = await request(app).get(
      '/api/education/recommendations/STU-TEST-001'
    );

    expect(response.status).toBe(200);
  });

  test('GET /api/education/health', async () => {
    const response = await request(app).get('/api/education/health');

    expect(response.status).toBe(200);
    expect(response.body.status).toBe('operational');
  });
});
