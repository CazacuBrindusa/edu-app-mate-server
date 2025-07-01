// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const { execSync } = require('child_process');
const PDFDocument = require('pdfkit');
const { Student, Professor, Class, Grade, Test } = require('./models');
const nodemailer = require('nodemailer');

const axios = require('axios');

const app = express();
app.use(cors({
  origin: 'https://edu-app-mate-client.onrender.com',
  credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const SECRET_KEY = 'your_secret_key';

// In-memory reset‐token store (demo only)
const resetTokens = {};

// Multer setup pentru upload fisiere
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const type = req.params.type;
    const ext = path.extname(file.originalname).toLowerCase();
    const mime = file.mimetype;

    if (type === 'test') {
      // Allow both .tex and .pdf
      if (ext !== '.tex' && ext !== '.pdf') {
        return cb(new Error('Only .tex or .pdf files allowed for tests'));
      }
    }

    if (type === 'material') {
      // Only allow PDFs
      if (mime !== 'application/pdf') {
        return cb(new Error('Only PDFs allowed for materials'));
      }
    }

    cb(null, true);
  }
});

// Middleware pentru verificare JWT
const authMiddleware = (req, res, next) => {
  const rawHeader = req.headers.authorization;
  if (!rawHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = rawHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (!decoded || !decoded.userType || !decoded.id) {
      return res.status(403).json({ error: 'Invalid token payload' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// configure a transporter using .env
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  }
});

transporter.verify()
  .then(() => console.log('✅ SMTP server is reachable'))
  .catch(err => console.error('❌ SMTP connection error:', err));

// helper to send the reset email
async function sendResetEmail(email, token) {
  const resetUrl = `http://localhost:3000/reset-password/${token}`;
  await transporter.sendMail({
    from: process.env.FROM_ADDRESS,
    to: email,
    subject: 'Your password reset link',
    html: `<p>You requested a password reset. Click <a href="${resetUrl}">here</a> to choose a new password.</p>`
  });
}

function cleanupTexArtifacts(uploadsDir, basename) {
  ['.aux', '.log', '.tex'].forEach(ext => {
    const file = path.join(uploadsDir, basename + ext);
    if (fs.existsSync(file)) {
      try { fs.unlinkSync(file) }
      catch (err) { console.warn(`⚠️ couldn’t delete ${file}:`, err.message) }
    }
  });
}

// ------------------------------------------------------ AUTH ------------------------------------------------------

// Inregistrare student sau profesor
app.post('/register', async (req, res) => {
  const { name, email, password, userType, professorClasses, className } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    if (userType === 'student') {
      if (!className?.trim()) {
        return res.status(400).json({ error: 'Class name required' });
      }
      let classData = await Class.findOne({ name: className.trim() })
        || await Class.create({ name: className.trim(), students: [] });
      const student = await Student.create({
        name,
        email,
        password: hashedPassword,
        classId: classData._id
      });
      classData.students.push(student._id);
      await classData.save();
      return res.status(201).json({ message: 'Student registered' });
    }
    if (userType === 'professor') {
      if (!Array.isArray(professorClasses) || professorClasses.length === 0) {
        return res.status(400).json({ error: 'Classes required' });
      }
      const classIds = await Promise.all(
        professorClasses.map(async cn => {
          let c = await Class.findOne({ name: cn.trim() })
            || await Class.create({ name: cn.trim(), students: [] });
          return c._id;
        })
      );
      await Professor.create({ name, email, password: hashedPassword, classes: classIds });
      return res.status(201).json({ message: 'Professor registered' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Error registering' });
  }
});

// Login pentru student sau profesor
app.post('/login', async (req, res) => {
  const { email, password, userType } = req.body;
  const user = userType === 'student'
    ? await Student.findOne({ email })
    : await Professor.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user._id, userType }, SECRET_KEY, { expiresIn: '1h' });
  return res.json({ token, name: user.name });
});

// ------------------------------------------------------ PASSWORD RESET ------------------------------------------------------

// Request a reset link
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await Student.findOne({ email }) || await Professor.findOne({ email });
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  resetTokens[token] = { email, expires: Date.now() + 15 * 60 * 1000 }; // 15m

  try {
    await sendResetEmail(email, token);
    return res.json({ message: 'Reset link sent—check your inbox!' });
  } catch (err) {
    console.error('Error sending reset email:', err);
    return res.status(500).json({ error: 'Failed to send reset email' });
  }
});

// Perform the reset
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const entry = resetTokens[token];
  if (!entry || entry.expires < Date.now()) {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }
  const user = await Student.findOne({ email: entry.email })
    || await Professor.findOne({ email: entry.email });
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();
  delete resetTokens[token];

  return res.json({ message: 'Password has been reset.' });
});

// ------------------------------------------------------ PROFESSOR ------------------------------------------------------

// Returneaza toate clasele profesorului autentificat
app.get('/api/professor/classes', authMiddleware, async (req, res) => {
  if (req.user.userType !== 'professor') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const professor = await Professor.findById(req.user.id).populate({
    path: 'classes',
    populate: { path: 'students', select: 'name' }
  });
  if (!professor) {
    return res.status(404).json({ error: 'Not found' });
  }
  return res.json(professor.classes);
});

// Returneaza detalii despre o clasa (inclusiv studenti si note)
app.get('/api/professor/class/:classId', authMiddleware, async (req, res) => {
  try {
    if (req.user.userType !== 'professor') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const classData = await Class.findById(req.params.classId)
      .populate('students', 'name')
      .lean();
    if (!classData) {
      return res.status(404).json({ error: 'Class not found' });
    }

    const grades = await Grade.find({ classId: req.params.classId }).lean();
    const prof = await Professor.findById(req.user.id).select('name').lean();

    return res.json({
      ...classData,
      grades,
      professorName: prof?.name || 'Unknown Professor'
    });
  } catch (err) {
    console.error('GET /api/professor/class/:classId error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Profesorul posteaza tema pentru un student anume
app.post('/api/student/:studentId/homework', authMiddleware, upload.single('file'), async (req, res) => {
  if (req.user.userType !== 'professor') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const student = await Student.findById(req.params.studentId);
  const fileName = req.file?.filename;
  if (!student || !fileName) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  student.homework.push({ professorFile: fileName, postedAt: new Date() });
  await student.save();
  return res.status(201).json({ message: 'Homework posted' });
});

// Pentru a vedea temele postate de student
app.get('/api/student/details/:studentId', authMiddleware, async (req, res) => {
  if (req.user.userType !== 'professor') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const student = await Student.findById(req.params.studentId);
  if (!student) {
    return res.status(404).json({ error: 'Student not found' });
  }
  return res.json(student);
});

// List tests for a class
app.get('/api/class/:classId/tests', authMiddleware, async (req, res) => {
  const tests = await Test.find({ classId: req.params.classId }).sort({ date: -1 });
  return res.json(tests);
});

// ------------------------------------------------------ STUDENT ------------------------------------------------------

// 1) Student dashboard (profile, class, materials, tests, grades, homework slots)
app.get('/api/student/dashboard', authMiddleware, async (req, res) => {
  if (!req.user || req.user.userType !== 'student') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const student = await Student.findById(req.user.id);
  if (!student) return res.status(404).json({ error: 'Student not found' });

  const classData = await Class.findById(student.classId);
  if (!classData) return res.status(404).json({ error: 'Class not found' });

  const professor = await Professor.findOne({ classes: classData._id });
  const grades = await Grade.find({ studentId: student._id });
  const testDocs = await Test.find({ classId: classData._id }).sort({ date: -1 });

  const testsForStudent = testDocs.map(t => ({
    _id: t._id,
    name: t.name,
    file: t.file,
    pdfFile: t.pdfFile
  }));

  return res.json({
    student,
    class: {
      name: classData.name,
      materials: classData.materials,
      tests: testsForStudent,
      announcements: classData.announcements,
      professorName: professor?.name || 'Unknown'
    },
    grades,
    homework: student.homework || []
  });
});

// 2) Student uploads their solution to a homework slot
app.post('/api/student/homework/:homeworkId/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (req.user.userType !== 'student') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const student = await Student.findById(req.user.id);
  const hwItem = student.homework.id(req.params.homeworkId);
  const fileName = req.file?.filename;
  if (!hwItem || !fileName) {
    return res.status(400).json({ error: 'Invalid request' });
  }
  hwItem.studentFile = fileName;
  await student.save();
  return res.json({ message: 'Uploaded' });
});

// ------------------------------------------------------ GRADES ------------------------------------------------------

// 1) Student views own grades
app.get('/api/grades', authMiddleware, async (req, res) => {
  if (req.user.userType !== 'student') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    const grades = await Grade.find({ studentId: req.user.id });
    return res.json(grades);
  } catch (err) {
    console.error('GET /api/grades error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// 2) Professor creates a grade + AI‐generated homework PDF (prof copy only)
app.post('/api/grades', authMiddleware, async (req, res) => {
  console.log('POST /api/grades body:', req.body);
  if (req.user.userType !== 'professor') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { studentId, classId, testId, exercises, date, score: frontScore } = req.body;

  if (!studentId || !classId || !testId || !Array.isArray(exercises) || !exercises.length) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (!mongoose.Types.ObjectId.isValid(testId)) {
    return res.status(400).json({ error: 'Invalid testId' });
  }

  if (await Grade.findOne({ studentId, testId })) {
    return res.status(400).json({ error: 'Grade already exists for this student & test' });
  }

  const test = await Test.findById(testId);
  if (!test) return res.status(404).json({ error: 'Test not found' });

  const totalObt = exercises.reduce((sum, ex) => sum + Number(ex.obtainedPoints || 0), 0) + 1;
  const totalMax = exercises.reduce((sum, ex) => sum + Number(ex.maxPoints || 0), 0);
  if (totalMax !== 9) {
    return res.status(400).json({ error: 'Max points must be 9' });
  }

  const score = typeof frontScore === 'number' ? frontScore : totalObt;

  const grade = await Grade.create({
    studentId,
    classId,
    testId,
    testName: test.name,
    exercises,
    score,
    date: date ? new Date(date) : new Date()
  });

  const weakExercises = exercises.filter(
    ex => Number(ex.obtainedPoints) < Number(ex.maxPoints) / 2
  );

  if (weakExercises.length === 0) {
    return res.status(400).json({ error: 'No underperforming exercises found' });
  }

  const uploadsDir = path.join(__dirname, 'uploads');
  const texFile = `hw-${grade._id}.tex`;
  const pdfFile = `hw-${grade._id}.pdf`;
  const texPath = path.join(uploadsDir, texFile);

  // Infer dominant language from test content
  const sampleExerciseText = test?.exercises?.[0]?.exercise || '';
  const inferLanguage = (code) => {
    if (/SELECT|FROM|WHERE/i.test(code)) return 'SQL';
    if (/#include|cout|cin|int\s+main/i.test(code)) return 'C++';
    return 'pseudocode';
  };
  const detectedLanguage = inferLanguage(sampleExerciseText);

  const systemPrompt = `
You are an AI teaching assistant specialized in informatics: C++, pseudocode, or SQL.

You will be given weak student answers and their original exercise source code.

For each, generate 3 new exercises of the SAME style, in the SAME language (${detectedLanguage}).

Follow this format strictly:
\\section*{AI-Generated Homework}
\\subsection*{Exercise 1 variants}
\\begin{enumerate}
  \\item Ce afiseaza codul pentru input 97?\\\\
        \\verb|...|
  \\item ...
\\end{enumerate}

Do:
- Only vary the numeric input (e.g. 97 → 58, 103)
- Use the same language and logic pattern as the original
- Return ONLY valid LaTeX content

Do NOT:
- Use Markdown or comments
- Use \\begin{verbatim} or lstlisting
- Explain the code — just show the question and the code

Make sure the output compiles with pdflatex.
`.trim();

  const userPrompt = `
Original exercise code the student struggled with:
${weakExercises.map((ex, i) => `Exercise ${i + 1}: ${ex.exercise}`).join('\n')}
`.trim();

  let aiTex;
  try {
    const response = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        model: process.env.GROQ_MODEL || 'llama3-70b-8192',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.7
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    aiTex = response.data?.choices?.[0]?.message?.content?.trim();
    if (!aiTex) throw new Error('No reply from AI');

    // Clean up accidental markdown
    aiTex = aiTex.replace(/```(latex|tex)?/g, '').replace(/```/g, '').trim();

    // Convert texttt to safer form if needed (optional fallback)
    aiTex = aiTex.replace(/\\texttt\{([^}]*)\}/g, (_, code) => `\\verb|${code}|`);

  } catch (err) {
    console.error('❌ AI error:', err?.response?.data || err.message);
    return res.status(502).json({ error: 'AI generation failed' });
  }

  try {
    const fullTex = `
      \\documentclass{article}
      \\usepackage[utf8]{inputenc}
      \\usepackage{enumitem}
      \\title{Homework}
      \\begin{document}

      ${aiTex}

      \\end{document}
      `.trim();

    fs.writeFileSync(texPath, fullTex);
  } catch (err) {
    console.error('❌ Failed to write .tex file:', err.message);
    return res.status(500).json({ error: 'Failed to save LaTeX file' });
  }

  // Compile LaTeX
  try {
    execSync(`pdflatex -output-directory="${uploadsDir}" "${texPath}"`, { stdio: 'pipe' });
  } catch (err) {
    const stderr = err.stderr?.toString() || err.message;
    console.error('❌ LaTeX compile stderr:', stderr);
    return res.status(500).json({ error: 'LaTeX compilation failed', details: stderr });
  }

  grade.homeworkFile = pdfFile;
  await grade.save();

  const student = await Student.findById(studentId);
  if (student) {
    student.homework.push({
      professorFile: pdfFile,
      postedAt: new Date()
    });
    await student.save();
  }

  const result = {
    ...(grade.toObject ? grade.toObject() : grade._doc),
    homeworkUrl: `/uploads/${pdfFile}`
  };

  return res.status(201).json(result);
});

// 3) Professor deletes a grade (unchanged)
app.delete('/api/grades/:id', authMiddleware, async (req, res) => {
  if (req.user.userType !== 'professor') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid grade ID' });
  }
  try {
    const deleted = await Grade.findByIdAndDelete(id);
    if (!deleted) return res.status(404).json({ error: 'Grade not found' });
    return res.json({ message: 'Grade deleted' });
  } catch (err) {
    console.error('Error deleting grade:', err);
    return res.status(500).json({ error: 'Failed to delete grade' });
  }
});

// ------------------------------------------------------ FILES ------------------------------------------------------

// Upload fisiere (material sau test) intr-o clasa
app.post('/api/upload/:type/:classId', upload.single('file'), async (req, res) => {
  const { type, classId } = req.params;
  const fileName = req.file?.filename;
  if (!fileName || !['material', 'test'].includes(type)) {
    return res.status(400).json({ error: 'Invalid type or file' });
  }
  const classData = await Class.findById(classId);
  if (!classData) {
    return res.status(404).json({ error: 'Class not found' });
  }

  if (type === 'material') {
    classData.materials.push(fileName);
    await classData.save();
    return res.json({ message: 'Material uploaded', fileName });
  }

  // test upload
  const test = await Test.create({
    classId,
    name: req.body.name || `Test - ${new Date().toLocaleDateString()}`,
    date: new Date(),
    file: fileName,
    exercises: []
  });
  return res.status(201).json({ message: 'Test uploaded', test });
});

// Stergere fisier material/test dintr-o clasa
app.delete('/api/delete/:type/:classId/:fileName', async (req, res) => {
  const { type, classId, fileName } = req.params;
  if (!['material', 'test'].includes(type)) {
    return res.status(400).json({ error: 'Invalid type' });
  }
  const classData = await Class.findById(classId);
  if (!classData) {
    return res.status(404).json({ error: 'Class not found' });
  }

  if (type === 'material') {
    classData.materials = classData.materials.filter(f => f !== fileName);
    await classData.save();
  } else {
    await Test.deleteOne({ classId, file: fileName });
  }

  fs.unlink(path.join(__dirname, 'uploads', fileName), err => {
    if (err && err.code !== 'ENOENT') {
      return res.status(500).json({ error: 'Delete failed' });
    }
    return res.json({ message: 'Deleted' });
  });
});


// ------------------------------------------------------ ANNOUNCEMENTS ------------------------------------------------------

// Postare anunt nou in clasa
app.post('/api/class/:classId/announcement', authMiddleware, async (req, res) => {
  const { message } = req.body;
  const professor = await Professor.findById(req.user.id);
  const classData = await Class.findById(req.params.classId);
  if (!message || !classData || !professor) {
    return res.status(400).json({ error: 'Invalid' });
  }
  const ann = { professorName: professor.name, message, date: new Date() };
  classData.announcements.push(ann);
  await classData.save();
  return res.status(201).json(ann);
});

// Editare anunt existent
app.put('/api/class/:classId/announcement/:announcementId', authMiddleware, async (req, res) => {
  const { message } = req.body;
  const classData = await Class.findById(req.params.classId);
  const ann = classData.announcements.id(req.params.announcementId);
  if (!ann) {
    return res.status(404).json({ error: 'Not found' });
  }
  ann.message = message;
  await classData.save();
  return res.status(200).json(ann);
});


// ------------------------------------------------------ PROF LIST ------------------------------------------------------

// Returneaza lista tuturor profesorilor (doar id si nume)
app.get('/api/professors', authMiddleware, async (req, res) => {
  const profs = await Professor.find({}, 'id name');
  return res.json(profs);
});


// ------------------------------------------------------ SERVER START ------------------------------------------------------
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
