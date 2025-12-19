/**
 * EDUCATION MODEL
 * Database model for mandatory education programs
 * Part of the OWLBAN GROUP Heaven on Earth Initiative
 *
 * Four Mandatory Tracks:
 * - Military Training (6 months)
 * - Law Education (4 months)
 * - Technology Training (6 months)
 * - Agriculture Training (4 months)
 */

import mongoose from 'mongoose';

const EducationProgramSchema = new mongoose.Schema(
  {
    // Program Identification
    programId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    // Program Type
    programType: {
      type: String,
      required: true,
      enum: ['military', 'law', 'tech', 'agriculture'],
      index: true,
    },

    // Program Details
    programInfo: {
      name: {
        type: String,
        required: true,
      },
      description: String,
      duration: {
        type: Number, // in months
        required: true,
      },
      level: {
        type: String,
        enum: ['beginner', 'intermediate', 'advanced', 'expert'],
        default: 'beginner',
      },
      language: {
        type: String,
        enum: ['creole', 'french', 'english', 'spanish'],
        default: 'creole',
      },
      prerequisites: [String],
      objectives: [String],
      outcomes: [String],
    },

    // Curriculum
    curriculum: [
      {
        moduleId: String,
        moduleName: String,
        description: String,
        duration: Number, // in weeks
        topics: [String],
        learningMaterials: [
          {
            type: String,
            title: String,
            url: String,
            format: String, // video, pdf, interactive, etc.
          },
        ],
        assessments: [
          {
            assessmentId: String,
            type: String, // quiz, exam, practical, project
            passingScore: Number,
            weight: Number, // percentage of final grade
          },
        ],
        order: Number,
      },
    ],

    // Instructors
    instructors: [
      {
        instructorId: String,
        name: String,
        specialization: String,
        qualifications: [String],
        experience: Number, // years
        rating: Number,
        contactInfo: {
          email: String,
          phone: String,
        },
        availability: {
          days: [String],
          hours: String,
        },
      },
    ],

    // Facilities
    facilities: [
      {
        facilityId: String,
        name: String,
        type: String, // classroom, lab, field, virtual
        location: {
          address: String,
          city: String,
          department: String,
          coordinates: {
            latitude: Number,
            longitude: Number,
          },
        },
        capacity: Number,
        equipment: [String],
        availability: String,
      },
    ],

    // Enrollment
    enrollment: {
      capacity: {
        type: Number,
        required: true,
      },
      enrolled: {
        type: Number,
        default: 0,
      },
      waitlist: {
        type: Number,
        default: 0,
      },
      completed: {
        type: Number,
        default: 0,
      },
      dropouts: {
        type: Number,
        default: 0,
      },
    },

    // Enrolled Citizens
    enrolledCitizens: [
      {
        citizenId: String,
        enrollmentDate: Date,
        status: {
          type: String,
          enum: ['active', 'completed', 'dropped', 'suspended'],
          default: 'active',
        },
        progress: {
          type: Number,
          default: 0,
          min: 0,
          max: 100,
        },
        currentModule: String,
        completedModules: [String],
        grades: [
          {
            moduleId: String,
            assessmentId: String,
            score: Number,
            date: Date,
          },
        ],
        attendance: {
          total: Number,
          attended: Number,
          percentage: Number,
        },
        completionDate: Date,
        certificationId: String,
        finalGrade: String,
      },
    ],

    // Schedule
    schedule: {
      startDate: Date,
      endDate: Date,
      sessions: [
        {
          sessionId: String,
          date: Date,
          startTime: String,
          endTime: String,
          moduleId: String,
          instructorId: String,
          facilityId: String,
          type: String, // lecture, lab, practical, exam
          status: String, // scheduled, completed, cancelled
        },
      ],
    },

    // Certification
    certification: {
      certificateTemplate: String,
      issuingAuthority: String,
      validityPeriod: Number, // months, 0 = lifetime
      requirements: {
        minimumAttendance: Number, // percentage
        minimumGrade: Number,
        practicalExam: Boolean,
        finalProject: Boolean,
      },
      issued: Number,
      revoked: Number,
    },

    // AI Integration
    aiFeatures: {
      personalizedLearning: {
        type: Boolean,
        default: true,
      },
      adaptiveTesting: {
        type: Boolean,
        default: true,
      },
      performancePrediction: {
        type: Boolean,
        default: true,
      },
      recommendationEngine: {
        type: Boolean,
        default: true,
      },
      virtualAssistant: {
        type: Boolean,
        default: true,
      },
    },

    // Program Status
    status: {
      type: String,
      enum: ['planning', 'active', 'completed', 'suspended', 'cancelled'],
      default: 'planning',
    },

    // Statistics
    statistics: {
      averageCompletionRate: Number,
      averageGrade: Number,
      averageAttendance: Number,
      employmentRate: Number, // post-graduation
      satisfactionScore: Number,
    },

    // Metadata
    metadata: {
      createdBy: String,
      lastUpdatedBy: String,
      version: {
        type: Number,
        default: 1,
      },
      tags: [String],
      notes: [String],
    },
  },
  {
    timestamps: true,
    collection: 'education_programs',
  }
);

// Indexes
EducationProgramSchema.index({ programType: 1, status: 1 });
EducationProgramSchema.index({ 'schedule.startDate': 1 });
EducationProgramSchema.index({ 'enrolledCitizens.citizenId': 1 });

// Virtual for enrollment percentage
EducationProgramSchema.virtual('enrollmentPercentage').get(function () {
  if (this.enrollment.capacity === 0) return 0;
  return (this.enrollment.enrolled / this.enrollment.capacity) * 100;
});

// Virtual for completion rate
EducationProgramSchema.virtual('completionRate').get(function () {
  if (this.enrollment.enrolled === 0) return 0;
  return (this.enrollment.completed / this.enrollment.enrolled) * 100;
});

// Method to generate unique program ID
EducationProgramSchema.statics.generateProgramId = async function (
  programType
) {
  let programId;
  let exists = true;

  while (exists) {
    // Format: TYPE-YYYY-XXXX (e.g., MIL-2024-A1B2)
    const year = new Date().getFullYear();
    const typePrefix = {
      military: 'MIL',
      law: 'LAW',
      tech: 'TECH',
      agriculture: 'AGR',
    }[programType];

    const random = Math.random().toString(36).substring(2, 6).toUpperCase();
    programId = `${typePrefix}-${year}-${random}`;

    exists = await this.findOne({ programId });
  }

  return programId;
};

// Method to enroll a citizen
EducationProgramSchema.methods.enrollCitizen = function (citizenId) {
  // Check capacity
  if (this.enrollment.enrolled >= this.enrollment.capacity) {
    return {
      success: false,
      error: 'Program is at full capacity',
      waitlist: true,
    };
  }

  // Check if already enrolled
  const alreadyEnrolled = this.enrolledCitizens.some(
    (ec) => ec.citizenId === citizenId && ec.status === 'active'
  );

  if (alreadyEnrolled) {
    return {
      success: false,
      error: 'Citizen is already enrolled in this program',
    };
  }

  // Enroll citizen
  this.enrolledCitizens.push({
    citizenId: citizenId,
    enrollmentDate: new Date(),
    status: 'active',
    progress: 0,
    attendance: {
      total: 0,
      attended: 0,
      percentage: 0,
    },
  });

  this.enrollment.enrolled += 1;

  return {
    success: true,
    message: 'Citizen enrolled successfully',
    enrollmentDate: new Date(),
  };
};

// Method to update citizen progress
EducationProgramSchema.methods.updateCitizenProgress = function (
  citizenId,
  progressData
) {
  const citizen = this.enrolledCitizens.find(
    (ec) => ec.citizenId === citizenId && ec.status === 'active'
  );

  if (!citizen) {
    return {
      success: false,
      error: 'Citizen not found in this program',
    };
  }

  // Update progress
  if (progressData.progress !== undefined) {
    citizen.progress = progressData.progress;
  }

  if (progressData.currentModule) {
    citizen.currentModule = progressData.currentModule;
  }

  if (progressData.completedModule) {
    if (!citizen.completedModules.includes(progressData.completedModule)) {
      citizen.completedModules.push(progressData.completedModule);
    }
  }

  if (progressData.grade) {
    citizen.grades.push(progressData.grade);
  }

  if (progressData.attendance) {
    citizen.attendance = progressData.attendance;
  }

  // Check if completed
  if (citizen.progress >= 100) {
    citizen.status = 'completed';
    citizen.completionDate = new Date();
    this.enrollment.completed += 1;

    // Generate certification ID
    citizen.certificationId = `CERT-${this.programId}-${citizenId}-${Date.now()}`;
  }

  return {
    success: true,
    citizen: citizen,
  };
};

// Method to calculate program statistics
EducationProgramSchema.methods.calculateStatistics = function () {
  const activeCitizens = this.enrolledCitizens.filter(
    (ec) => ec.status === 'active'
  );
  const completedCitizens = this.enrolledCitizens.filter(
    (ec) => ec.status === 'completed'
  );

  if (this.enrolledCitizens.length === 0) {
    return {
      averageCompletionRate: 0,
      averageGrade: 0,
      averageAttendance: 0,
    };
  }

  // Average completion rate
  const totalProgress = this.enrolledCitizens.reduce(
    (sum, ec) => sum + ec.progress,
    0
  );
  const averageCompletionRate = totalProgress / this.enrolledCitizens.length;

  // Average grade
  const allGrades = completedCitizens.flatMap((ec) =>
    ec.grades.map((g) => g.score)
  );
  const averageGrade =
    allGrades.length > 0
      ? allGrades.reduce((sum, score) => sum + score, 0) / allGrades.length
      : 0;

  // Average attendance
  const attendancePercentages = this.enrolledCitizens
    .filter((ec) => ec.attendance.total > 0)
    .map((ec) => ec.attendance.percentage);
  const averageAttendance =
    attendancePercentages.length > 0
      ? attendancePercentages.reduce((sum, pct) => sum + pct, 0) /
        attendancePercentages.length
      : 0;

  this.statistics = {
    averageCompletionRate,
    averageGrade,
    averageAttendance,
    employmentRate: this.statistics?.employmentRate || 0,
    satisfactionScore: this.statistics?.satisfactionScore || 0,
  };

  return this.statistics;
};

// Pre-save middleware
EducationProgramSchema.pre('save', async function (next) {
  // Generate program ID if not exists
  if (!this.programId) {
    this.programId = await this.constructor.generateProgramId(this.programType);
  }

  // Calculate statistics
  this.calculateStatistics();

  next();
});

const EducationProgram = mongoose.model(
  'EducationProgram',
  EducationProgramSchema
);

export default EducationProgram;
