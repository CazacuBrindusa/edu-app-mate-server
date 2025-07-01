const mongoose = require('mongoose');
require('dotenv').config(); // Ensure dotenv is loaded

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/edu-app';

if (!MONGODB_URI) {
  console.error("❌ MONGO_URI is missing. Please check your .env file.");
  process.exit(1);
}

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

module.exports = mongoose;
