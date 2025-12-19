/**
 * Education Routes
 * API endpoints for educational services
 */

import express from 'express';
import { info } from '../utils/loggerWrapper.js';
import Course from '../models/Course.js';
import aiLearningService from '../services/aiLearningService.js';

const router = express.Router();

/**
 * GET /api/education/courses
 * Get all available courses
 */
router.get('/courses', async (req, res, next) => {
  try {
    const { category, difficulty, search } = req.query;
    const query = { isActive: true };

    if (category) query.category = category;
    if (difficulty) query.difficulty = difficulty;
    if (search) query.title = { $regex: search, $options: 'i' };

    const courses = await Course.find(query)
      .select(
        'title description category difficulty instructor rating estimatedDuration'
      )
      .sort({ 'rating.average': -1 });

    res.json({ success: true, courses, count: courses.length });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/education/courses/:courseId
 * Get course details
 */
router.get('/courses/:courseId', async (req, res, next) => {
  try {
    const course = await Course.findById(req.params.courseId);
    if (!course) {
      return res
        .status(404)
        .json({ success: false, message: 'Course not found' });
    }
    res.json({ success: true, course });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/education/enroll
 * Enroll student in a course
 */
router.post('/enroll', async (req, res, next) => {
  try {
    const { courseId, citizenId } = req.body;

    if (!courseId || !citizenId) {
      return res.status(400).json({
        success: false,
        message: 'Course ID and Citizen ID are required',
      });
    }

    const course = await Course.findById(courseId);
    if (!course) {
      return res
        .status(404)
        .json({ success: false, message: 'Course not found' });
    }

    await course.enrollStudent(citizenId);
    info(`Citizen ${citizenId} enrolled in course ${courseId}`);

    res.json({
      success: true,
      message: 'Successfully enrolled in course',
      course: {
        id: course._id,
        title: course.title,
      },
    });
  } catch (err) {
    if (
      err.message === 'Course is full' ||
      err.message === 'Student already enrolled'
    ) {
      return res.status(400).json({ success: false, message: err.message });
    }
    next(err);
  }
});

/**
 * POST /api/education/progress
 * Update student progress
 */
router.post('/progress', async (req, res, next) => {
  try {
    const { courseId, citizenId, lessonNumber } = req.body;

    const course = await Course.findById(courseId);
    if (!course) {
      return res
        .status(404)
        .json({ success: false, message: 'Course not found' });
    }

    await course.updateProgress(citizenId, lessonNumber);
    info(`Progress updated for citizen ${citizenId} in course ${courseId}`);

    const student = course.enrolledStudents.find(
      (s) => s.citizenId.toString() === citizenId.toString()
    );

    res.json({
      success: true,
      progress: student.progress,
      completedLessons: student.completedLessons.length,
    });
  } catch (err) {
    if (err.message === 'Student not enrolled') {
      return res.status(400).json({ success: false, message: err.message });
    }
    next(err);
  }
});

/**
 * GET /api/education/my-courses/:citizenId
 * Get courses for a citizen
 */
router.get('/my-courses/:citizenId', async (req, res, next) => {
  try {
    const courses = await Course.find({
      'enrolledStudents.citizenId': req.params.citizenId,
    });

    const myCourses = courses.map((course) => {
      const student = course.enrolledStudents.find(
        (s) => s.citizenId.toString() === req.params.citizenId.toString()
      );

      return {
        id: course._id,
        title: course.title,
        category: course.category,
        progress: student.progress,
        completedLessons: student.completedLessons.length,
        totalLessons: course.curriculum.length,
        lastAccessed: student.lastAccessedAt,
        enrolledAt: student.enrolledAt,
      };
    });

    res.json({ success: true, courses: myCourses, count: myCourses.length });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/education/recommendations/:citizenId
 * Get AI-powered course recommendations
 */
router.get('/recommendations/:citizenId', async (req, res, next) => {
  try {
    // Get current progress
    const courses = await Course.find({
      'enrolledStudents.citizenId': req.params.citizenId,
    });

    const progress = {
      completedCourses: courses.filter((c) => {
        const student = c.enrolledStudents.find(
          (s) => s.citizenId.toString() === req.params.citizenId.toString()
        );
        return student && student.progress >= 100;
      }),
      currentCourse: courses.find((c) => {
        const student = c.enrolledStudents.find(
          (s) => s.citizenId.toString() === req.params.citizenId.toString()
        );
        return student && student.progress < 100;
      })?.title,
      totalLessons: courses.reduce((sum, c) => sum + c.curriculum.length, 0),
      completedLessons: courses.reduce((sum, c) => {
        const student = c.enrolledStudents.find(
          (s) => s.citizenId.toString() === req.params.citizenId.toString()
        );
        return sum + (student?.completedLessons.length || 0);
      }, 0),
    };

    const recommendations = await aiLearningService.generateRecommendations(
      req.params.citizenId,
      progress
    );

    res.json({ success: true, recommendations });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/education/analytics/:citizenId
 * Get learning analytics
 */
router.get('/analytics/:citizenId', async (req, res, next) => {
  try {
    const analytics = await aiLearningService.analyzeProgress(
      req.params.citizenId
    );
    res.json({ success: true, analytics });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/education/study-plan/:citizenId
 * Generate personalized study plan
 */
router.get('/study-plan/:citizenId', async (req, res, next) => {
  try {
    const hoursPerWeek = parseInt(req.query.hours) || 5;
    const studyPlan = await aiLearningService.generateStudyPlan(
      req.params.citizenId,
      hoursPerWeek
    );
    res.json({ success: true, studyPlan });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/education/courses
 * Create a new course (admin)
 */
router.post('/courses', async (req, res, next) => {
  try {
    const course = new Course(req.body);
    await course.save();
    info(`New course created: ${course.title}`);
    res.status(201).json({ success: true, course });
  } catch (err) {
    next(err);
  }
});

export default router;
