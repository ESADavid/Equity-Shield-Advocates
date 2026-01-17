// Course Model
import mongoose from 'mongoose';

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  curriculum: [{ title: String, content: String, duration: Number }],
  difficulty: { type: String, enum: ['beginner', 'intermediate', 'advanced'] },
  category: String,
  instructor: String,
  enrolledStudents: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Citizen' }]
}, { timestamps: true });

export default mongoose.model('Course', courseSchema);
