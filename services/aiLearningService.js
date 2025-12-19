/**
 * AI Learning Service
 * Provides AI-powered learning recommendations and analytics
 */

import { info, error } from '../utils/loggerWrapper.js';
import Course from '../models/Course.js';

class AILearningService {
  /**
   * Generate personalized course recommendations
   */
  async generateRecommendations(citizenId, currentProgress) {
    try {
      const recommendations = {
        nextCourses: await this.recommendNextCourses(
          citizenId,
          currentProgress
        ),
        focusAreas: this.identifyFocusAreas(currentProgress),
        estimatedCompletion: this.estimateCompletion(currentProgress),
        learningPath: await this.generateLearningPath(
          citizenId,
          currentProgress
        ),
      };

      info(`Generated AI recommendations for citizen ${citizenId}`);
      return recommendations;
    } catch (err) {
      error('Failed to generate recommendations:', err);
      throw err;
    }
  }

  /**
   * Recommend next courses based on progress and interests
   */
  async recommendNextCourses(citizenId, progress) {
    try {
      // Get completed courses
      const completedCategories =
        progress.completedCourses?.map((c) => c.category) || [];

      // Find courses in similar categories
      const recommendations = await Course.find({
        isActive: true,
        category: {
          $in:
            completedCategories.length > 0
              ? completedCategories
              : ['technology', 'business'],
        },
        'enrolledStudents.citizenId': { $ne: citizenId },
      })
        .limit(5)
        .select('title description category difficulty rating');

      return recommendations.map((course) => ({
        courseId: course._id,
        title: course.title,
        category: course.category,
        difficulty: course.difficulty,
        relevance: this.calculateRelevance(course, progress),
        rating: course.rating.average,
      }));
    } catch (err) {
      error('Failed to recommend courses:', err);
      return [];
    }
  }

  /**
   * Calculate course relevance score
   */
  calculateRelevance(course, progress) {
    let score = 0.5; // Base score

    // Increase score for matching categories
    if (progress.interests?.includes(course.category)) {
      score += 0.3;
    }

    // Adjust for difficulty
    if (progress.averageScore > 85 && course.difficulty === 'advanced') {
      score += 0.2;
    } else if (progress.averageScore < 70 && course.difficulty === 'beginner') {
      score += 0.2;
    }

    return Math.min(score, 1.0);
  }

  /**
   * Identify areas needing focus
   */
  identifyFocusAreas(progress) {
    const focusAreas = [];

    if (progress.quizScores) {
      const weakAreas = Object.entries(progress.quizScores)
        .filter(([_, score]) => score < 70)
        .map(([area, _]) => area);

      focusAreas.push(...weakAreas);
    }

    // Default focus areas if none identified
    if (focusAreas.length === 0) {
      focusAreas.push(
        'Problem Solving',
        'Critical Thinking',
        'Practical Application'
      );
    }

    return focusAreas;
  }

  /**
   * Estimate course completion timeline
   */
  estimateCompletion(progress) {
    const totalLessons = progress.totalLessons || 10;
    const completedLessons = progress.completedLessons || 0;
    const remainingLessons = totalLessons - completedLessons;

    // Assume 2 lessons per week
    const weeksRemaining = Math.ceil(remainingLessons / 2);
    const daysRemaining = weeksRemaining * 7;

    const completionRate =
      totalLessons > 0 ? (completedLessons / totalLessons) * 100 : 0;

    return {
      days: daysRemaining,
      weeks: weeksRemaining,
      percentage: Math.round(completionRate),
      estimatedDate: new Date(Date.now() + daysRemaining * 24 * 60 * 60 * 1000),
    };
  }

  /**
   * Generate personalized learning path
   */
  async generateLearningPath(citizenId, progress) {
    try {
      const currentLevel = this.determineSkillLevel(progress);
      const interests = progress.interests || ['technology'];

      const path = {
        current: progress.currentCourse || 'Getting Started',
        level: currentLevel,
        next: [],
        timeline: '3-6 months',
      };

      // Find courses for next steps
      const nextCourses = await Course.find({
        isActive: true,
        category: { $in: interests },
        difficulty: currentLevel === 'beginner' ? 'intermediate' : 'advanced',
      })
        .limit(3)
        .select('title category difficulty');

      path.next = nextCourses.map((c) => c.title);

      return path;
    } catch (err) {
      error('Failed to generate learning path:', err);
      return {
        current: 'Getting Started',
        level: 'beginner',
        next: [
          'Introduction to Technology',
          'Business Basics',
          'Communication Skills',
        ],
        timeline: '3-6 months',
      };
    }
  }

  /**
   * Determine student's skill level
   */
  determineSkillLevel(progress) {
    const avgScore = progress.averageScore || 0;
    const completedCourses = progress.completedCourses?.length || 0;

    if (completedCourses >= 5 && avgScore >= 85) {
      return 'advanced';
    } else if (completedCourses >= 2 && avgScore >= 70) {
      return 'intermediate';
    }
    return 'beginner';
  }

  /**
   * Analyze student progress and provide insights
   */
  async analyzeProgress(citizenId) {
    try {
      // Get all courses for citizen
      const courses = await Course.find({
        'enrolledStudents.citizenId': citizenId,
      });

      if (courses.length === 0) {
        return {
          overallScore: 0,
          coursesEnrolled: 0,
          coursesCompleted: 0,
          strengths: [],
          improvements: ['Start your learning journey'],
          predictions: {
            completionDate: null,
            successProbability: 0,
          },
        };
      }

      let totalProgress = 0;
      let completedCount = 0;

      courses.forEach((course) => {
        const student = course.enrolledStudents.find(
          (s) => s.citizenId.toString() === citizenId.toString()
        );
        if (student) {
          totalProgress += student.progress;
          if (student.progress >= 100) completedCount++;
        }
      });

      const avgProgress = totalProgress / courses.length;

      return {
        overallScore: Math.round(avgProgress),
        coursesEnrolled: courses.length,
        coursesCompleted: completedCount,
        strengths: this.identifyStrengths(avgProgress),
        improvements: this.identifyImprovements(avgProgress),
        predictions: {
          completionDate: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
          successProbability: avgProgress / 100,
        },
      };
    } catch (err) {
      error('Progress analysis failed:', err);
      throw err;
    }
  }

  /**
   * Identify student strengths
   */
  identifyStrengths(avgProgress) {
    const strengths = [];

    if (avgProgress >= 80) {
      strengths.push('Excellent Progress', 'Consistent Learner');
    } else if (avgProgress >= 60) {
      strengths.push('Good Progress', 'Dedicated Student');
    } else {
      strengths.push('Getting Started', 'Building Foundation');
    }

    return strengths;
  }

  /**
   * Identify areas for improvement
   */
  identifyImprovements(avgProgress) {
    const improvements = [];

    if (avgProgress < 50) {
      improvements.push('Increase study time', 'Complete more lessons');
    } else if (avgProgress < 80) {
      improvements.push('Focus on challenging topics', 'Practice regularly');
    } else {
      improvements.push(
        'Explore advanced topics',
        'Share knowledge with others'
      );
    }

    return improvements;
  }

  /**
   * Generate study plan
   */
  async generateStudyPlan(citizenId, hoursPerWeek = 5) {
    try {
      const courses = await Course.find({
        'enrolledStudents.citizenId': citizenId,
        'enrolledStudents.progress': { $lt: 100 },
      });

      const plan = {
        weeklyHours: hoursPerWeek,
        dailyGoal: Math.ceil(hoursPerWeek / 7),
        schedule: [],
        milestones: [],
      };

      courses.forEach((course, index) => {
        const student = course.enrolledStudents.find(
          (s) => s.citizenId.toString() === citizenId.toString()
        );

        if (student) {
          const remainingLessons =
            course.curriculum.length - student.completedLessons.length;
          plan.schedule.push({
            course: course.title,
            lessonsRemaining: remainingLessons,
            estimatedWeeks: Math.ceil(remainingLessons / 2),
          });
        }
      });

      return plan;
    } catch (err) {
      error('Failed to generate study plan:', err);
      throw err;
    }
  }
}

export default new AILearningService();
