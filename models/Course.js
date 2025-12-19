/**
 * Course Model
 * Educational course management
 */

import mongoose from 'mongoose';

const lessonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: String,
  videoUrl: String,
  duration: Number, // in minutes
  order: { type: Number, required: true },
  resources: [{
    title: String,
    url: String,
    type: { type: String, enum: ['pdf', 'video', 'link', 'document'] }
  }],
  quiz: [{
    question: String,
    options: [String],
    correctAnswer: Number
  }]
});

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true, unique: true },
  description: { type: String, required: true },
  category: {
    type: String,
    required: true,
    enum: ['technology', 'business', 'healthcare', 'education', 'trades', 'arts', 'other']
  },
  difficulty: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced'],
    default: 'beginner'
  },
  instructor: {
    name: String,
    bio: String,
    credentials: [String]
  },
  curriculum: [lessonSchema],
  enrolledStudents: [{
    citizenId: { type: mongoose.Schema.Types.ObjectId, ref: 'Citizen' },
    enrolledAt: { type: Date, default: Date.now },
    progress: { type: Number, default: 0 }, // percentage
    completedLessons: [Number],
    lastAccessedAt: Date
  }],
  maxStudents: { type: Number, default: 100 },
  prerequisites: [String],
  learningOutcomes: [String],
  estimatedDuration: Number, // total hours
  certificateOffered: { type: Boolean, default: true },
  isActive: { type: Boolean, default: true },
  rating: {
    average: { type: Number, default: 0 },
    count: { type: Number, default: 0 }
  },
  tags: [String]
}, { 
  timestamps: true 
});

// Indexes
courseSchema.index({ title: 1 });
courseSchema.index({ category: 1, difficulty: 1 });
courseSchema.index({ 'enrolledStudents.citizenId': 1 });
courseSchema.index({ isActive: 1 });

// Methods
courseSchema.methods.enrollStudent = function(citizenId) {
  if (this.enrolledStudents.length >= this.maxStudents) {
    throw new Error('Course is full');
  }
  
  const alreadyEnrolled = this.enrolledStudents.some(
    student => student.citizenId.toString() === citizenId.toString()
  );
  
  if (alreadyEnrolled) {
    throw new Error('Student already enrolled');
  }
  
  this.enrolledStudents.push({ citizenId });
  return this.save();
};

courseSchema.methods.updateProgress = function(citizenId, lessonNumber) {
  const student = this.enrolledStudents.find(
    s => s.citizenId.toString() === citizenId.toString()
  );
  
  if (!student) {
    throw new Error('Student not enrolled');
  }
  
  if (!student.completedLessons.includes(lessonNumber)) {
    student.completedLessons.push(lessonNumber);
  }
  
  student.progress = (student.completedLessons.length / this.curriculum.length) * 100;
  student.lastAccessedAt = new Date();
  
  return this.save();
};

export default mongoose.model('Course', courseSchema);
