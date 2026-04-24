/**
 * COURSE MODEL
 * Database model for education courses in the UBI system
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 */

import mongoose from 'mongoose';
import { info, error, warn } from 'utils/loggerWrapper.js';

const courseSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    curriculum: [
      {
        title: {
          type: String,
          required: true,
        },
        content: {
          type: String,
          required: true,
        },
        duration: {
          type: Number, // in hours
          required: true,
          min: 0,
        },
        order: {
          type: Number,
          default: 0,
        },
        prerequisites: [
          {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Course',
          },
        ],
        resources: [
          {
            type: {
              type: String,
              enum: ['video', 'document', 'quiz', 'assignment', 'link'],
            },
            title: String,
            url: String,
            content: String,
          },
        ],
      },
    ],
    difficulty: {
      type: String,
      enum: ['beginner', 'intermediate', 'advanced'],
      required: true,
      index: true,
    },
    category: {
      type: String,
      required: true,
      enum: ['military', 'law', 'technology', 'agriculture'],
      index: true,
    },
    instructor: {
      type: String,
      required: true,
      trim: true,
    },
    instructorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    enrolledStudents: [
      {
        studentId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'Citizen',
          required: true,
        },
        enrollmentDate: {
          type: Date,
          default: Date.now,
        },
        completionDate: Date,
        progress: {
          type: Number,
          default: 0,
          min: 0,
          max: 100,
        },
        status: {
          type: String,
          enum: ['enrolled', 'in_progress', 'completed', 'dropped'],
          default: 'enrolled',
        },
        grade: String,
        certificateId: String,
      },
    ],
    prerequisites: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Course',
      },
    ],
    totalDuration: {
      type: Number, // total hours
      default: 0,
    },
    maxStudents: {
      type: Number,
      default: 50,
    },
    status: {
      type: String,
      enum: ['draft', 'published', 'archived'],
      default: 'draft',
      index: true,
    },
    tags: [String],
    metadata: {
      version: {
        type: String,
        default: '1.0',
      },
      lastUpdatedBy: String,
      approvalStatus: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending',
      },
      approvedBy: String,
      approvalDate: Date,
      qualityScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
      },
    },
    statistics: {
      totalEnrollments: {
        type: Number,
        default: 0,
      },
      completions: {
        type: Number,
        default: 0,
      },
      averageProgress: {
        type: Number,
        default: 0,
      },
      averageGrade: String,
      completionRate: {
        type: Number,
        default: 0,
      },
    },
  },
  {
    timestamps: true,
    collection: 'courses',
  }
);

// Indexes for performance
courseSchema.index({ category: 1, difficulty: 1 });
courseSchema.index({ status: 1, createdAt: -1 });
courseSchema.index({ 'enrolledStudents.studentId': 1 });

// Virtual for available spots
courseSchema.virtual('availableSpots').get(function () {
  return Math.max(0, this.maxStudents - this.enrolledStudents.length);
});

// Virtual for completion rate
courseSchema.virtual('completionRate').get(function () {
  if (this.enrolledStudents.length === 0) return 0;
  const completed = this.enrolledStudents.filter(
    (s) => s.status === 'completed'
  ).length;
  return Math.round((completed / this.enrolledStudents.length) * 100);
});

// Method to enroll a student
courseSchema.methods.enrollStudent = function (studentId, enrollmentData = {}) {
  // Check if student is already enrolled
  const existingEnrollment = this.enrolledStudents.find(
    (s) => s.studentId.toString() === studentId.toString()
  );

  if (existingEnrollment) {
    throw new Error('Student is already enrolled in this course');
  }

  // Check capacity
  if (this.enrolledStudents.length >= this.maxStudents) {
    throw new Error('Course is at maximum capacity');
  }

  // Check prerequisites
  // This would need to be implemented with actual prerequisite checking logic

  const enrollment = {
    studentId,
    enrollmentDate: new Date(),
    status: 'enrolled',
    progress: 0,
    ...enrollmentData,
  };

  this.enrolledStudents.push(enrollment);
  this.statistics.totalEnrollments = this.enrolledStudents.length;

  info(`Student ${studentId} enrolled in course ${this._id}`);
  return enrollment;
};

// Method to update student progress
courseSchema.methods.updateStudentProgress = function (
  studentId,
  progress,
  additionalData = {}
) {
  const enrollment = this.enrolledStudents.find(
    (s) => s.studentId.toString() === studentId.toString()
  );

  if (!enrollment) {
    throw new Error('Student is not enrolled in this course');
  }

  enrollment.progress = Math.min(100, Math.max(0, progress));
  enrollment.status = enrollment.progress >= 100 ? 'completed' : 'in_progress';

  if (enrollment.status === 'completed' && !enrollment.completionDate) {
    enrollment.completionDate = new Date();
  }

  // Update with additional data
  Object.assign(enrollment, additionalData);

  // Update course statistics
  this.updateStatistics();

  info(
    `Updated progress for student ${studentId} in course ${this._id}: ${progress}%`
  );
  return enrollment;
};

// Method to complete course for student
courseSchema.methods.completeCourse = function (
  studentId,
  grade = null,
  certificateId = null
) {
  const enrollment = this.enrolledStudents.find(
    (s) => s.studentId.toString() === studentId.toString()
  );

  if (!enrollment) {
    throw new Error('Student is not enrolled in this course');
  }

  enrollment.status = 'completed';
  enrollment.progress = 100;
  enrollment.completionDate = new Date();

  if (grade) enrollment.grade = grade;
  if (certificateId) enrollment.certificateId = certificateId;

  // Update course statistics
  this.updateStatistics();

  info(`Student ${studentId} completed course ${this._id}`);
  return enrollment;
};

// Method to drop student from course
courseSchema.methods.dropStudent = function (studentId, reason = '') {
  const enrollmentIndex = this.enrolledStudents.findIndex(
    (s) => s.studentId.toString() === studentId.toString()
  );

  if (enrollmentIndex === -1) {
    throw new Error('Student is not enrolled in this course');
  }

  const enrollment = this.enrolledStudents[enrollmentIndex];
  enrollment.status = 'dropped';
  enrollment.metadata = enrollment.metadata || {};
  enrollment.metadata.dropReason = reason;
  enrollment.metadata.dropDate = new Date();

  // Update course statistics
  this.updateStatistics();

  info(`Student ${studentId} dropped from course ${this._id}`);
  return enrollment;
};

// Method to update course statistics
courseSchema.methods.updateStatistics = function () {
  const enrollments = this.enrolledStudents;
  this.statistics.totalEnrollments = enrollments.length;

  const completed = enrollments.filter((e) => e.status === 'completed');
  this.statistics.completions = completed.length;

  if (enrollments.length > 0) {
    this.statistics.completionRate = Math.round(
      (completed.length / enrollments.length) * 100
    );

    const totalProgress = enrollments.reduce(
      (sum, e) => sum + (e.progress || 0),
      0
    );
    this.statistics.averageProgress = Math.round(
      totalProgress / enrollments.length
    );
  }

  // Calculate average grade for completed enrollments
  const graded = completed.filter((e) => e.grade);
  if (graded.length > 0) {
    // This would need grade parsing logic
    this.statistics.averageGrade = 'B'; // Placeholder
  }
};

// Method to get course summary
courseSchema.methods.getSummary = function () {
  return {
    id: this._id,
    title: this.title,
    description: this.description,
    category: this.category,
    difficulty: this.difficulty,
    instructor: this.instructor,
    totalDuration: this.totalDuration,
    enrolledStudents: this.enrolledStudents.length,
    maxStudents: this.maxStudents,
    availableSpots: this.availableSpots,
    status: this.status,
    completionRate: this.completionRate,
    statistics: this.statistics,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

// Method to check if student can enroll
courseSchema.methods.canEnroll = function (studentId) {
  // Check if already enrolled
  const existing = this.enrolledStudents.find(
    (s) => s.studentId.toString() === studentId.toString()
  );

  if (existing) {
    return { canEnroll: false, reason: 'Already enrolled' };
  }

  // Check capacity
  if (this.enrolledStudents.length >= this.maxStudents) {
    return { canEnroll: false, reason: 'Course at capacity' };
  }

  // Check course status
  if (this.status !== 'published') {
    return { canEnroll: false, reason: 'Course not available' };
  }

  return { canEnroll: true };
};

// Static method to find courses by category and difficulty
courseSchema.statics.findByCategoryAndDifficulty = function (
  category,
  difficulty,
  limit = 20
) {
  return this.find({
    category,
    difficulty,
    status: 'published',
  })
    .sort({ createdAt: -1 })
    .limit(limit);
};

// Static method to get popular courses
courseSchema.statics.getPopularCourses = function (limit = 10) {
  return this.find({ status: 'published' })
    .sort({ 'statistics.totalEnrollments': -1 })
    .limit(limit);
};

// Static method to get course statistics
courseSchema.statics.getCourseStats = async function () {
  const stats = await this.aggregate([
    { $match: { status: 'published' } },
    {
      $group: {
        _id: null,
        totalCourses: { $sum: 1 },
        byCategory: {
          $push: {
            category: '$category',
            enrollments: '$statistics.totalEnrollments',
            completions: '$statistics.completions',
          },
        },
        totalEnrollments: { $sum: '$statistics.totalEnrollments' },
        totalCompletions: { $sum: '$statistics.completions' },
      },
    },
  ]);

  if (stats.length === 0) {
    return {
      totalCourses: 0,
      totalEnrollments: 0,
      totalCompletions: 0,
      byCategory: [],
    };
  }

  const result = stats[0];

  // Group by category
  const categoryStats = {};
  result.byCategory.forEach((course) => {
    if (!categoryStats[course.category]) {
      categoryStats[course.category] = {
        count: 0,
        enrollments: 0,
        completions: 0,
      };
    }
    categoryStats[course.category].count++;
    categoryStats[course.category].enrollments += course.enrollments || 0;
    categoryStats[course.category].completions += course.completions || 0;
  });

  result.byCategory = Object.entries(categoryStats).map(
    ([category, stats]) => ({
      category,
      ...stats,
    })
  );

  return result;
};

// Pre-save middleware
courseSchema.pre('save', function (next) {
  // Calculate total duration
  this.totalDuration = this.curriculum.reduce(
    (total, module) => total + (module.duration || 0),
    0
  );

  // Sort curriculum by order
  if (this.curriculum.length > 0) {
    this.curriculum.sort((a, b) => (a.order || 0) - (b.order || 0));
  }

  next();
});

// Post-save middleware for logging
courseSchema.post('save', function (doc) {
  info(`Course saved: ${doc._id} - ${doc.title} (${doc.category})`);
});

export default mongoose.model('Course', courseSchema);
