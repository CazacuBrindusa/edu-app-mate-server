const mongoose = require('./db');

const GradeSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Student' },
  classId: { type: mongoose.Schema.Types.ObjectId, ref: 'Class' },
  testName: String,
  score: Number,
  exercises: [{
    exercise: String,
    obtainedPoints: Number,
    maxPoints: Number,
  }],
  date: { type: Date, default: Date.now },
  testId: { type: mongoose.Schema.Types.ObjectId, ref: 'Test' }
});

const TestSchema = new mongoose.Schema({
  classId: { type: mongoose.Schema.Types.ObjectId, ref: 'Class' },
  name: String,
  date: Date,
  file: String,
  exercises: [{
    exercise: String,
    maxPoints: Number,
  }],
});

const StudentSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  classId: { type: mongoose.Schema.Types.ObjectId, ref: 'Class' },
  homework: [{
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
    professorFile: String,
    studentFile: String,
    postedAt: { type: Date, default: Date.now }
  }]
});

const ProfessorSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  classes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Class' }]
});

const ClassSchema = new mongoose.Schema({
  name: String,
  professorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Professor' },
  students: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Student' }],
  materials: [String],
  announcements: [{ professor: String, message: String, date: Date }]
});

const Student = mongoose.model('Student', StudentSchema);
const Professor = mongoose.model('Professor', ProfessorSchema);
const Class = mongoose.model('Class', ClassSchema);
const Grade = mongoose.model('Grade', GradeSchema);
const Test = mongoose.model('Test', TestSchema);

module.exports = { Student, Professor, Class, Grade, Test };
