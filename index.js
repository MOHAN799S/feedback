const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const { ObjectId } = require('mongodb');

// Initialize app and configuration
dotenv.config();
const app = express();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Add cookie parser for JWT cookies
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
mongoose.connect('mongodb://localhost:27017/feedback')
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.log("MongoDB connection failed", err));

// Schema definitions
const adminSchema = new mongoose.Schema({
  _id: Number,
  username: String,
  password: Number,
  email: String,
  phone: Number,
});

const facultySchema = new mongoose.Schema({
  username: String,
  password: String,
  section: String,
  subject: String,
}, { versionKey: false });

const scheduleSchema = new mongoose.Schema({
  section: String,
}, { versionKey: false });

const Admin = mongoose.model('admin', adminSchema, 'admin');
const Faculty = mongoose.model('faculty', facultySchema, 'faculty_credentials');
const Schedule = mongoose.model('schedule', scheduleSchema, 'scheduleFeedback');

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.jwt || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  
  if (!token) {
    return res.sendFile(path.join(__dirname, 'public', 'login.html'));
    // return res.status(401).json({ success: false, message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT verification error:', error.message);
     res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};

app.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const adminUser = await Admin.findOne({ username });
    
    if (!adminUser || adminUser.password !== parseInt(password)) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: adminUser._id, username: adminUser.username, role: 'admin' },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '1h' }
    );
    
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000
    });
    
    res.json({
      success: true,
      token,
      admin: {
        id: adminUser._id,
        username: adminUser.username,
        email: adminUser.email
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

app.get('/check/login',authenticateToken, (req, res) => {
  const token = req.cookies.jwt;
  
  if (!token) {
    return res.status(404).json({ loggedIn: false });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    return res.json({ 
      loggedIn: true,
      user: {
        id: decoded.id,
        username: decoded.username,
        role: decoded.role
      }
    });
  } catch (error) {
    console.error('JWT verification error:', error.message);
    res.clearCookie('jwt'); // Clear invalid token
    return res.json({ loggedIn: false });
  }
});

// app.get('/logout', (req, res) => {
//   res.clearCookie('jwt');
//   return res.status(200).json({ success: true, message: 'Logged out successfully' });
// });
app.post('/logout', (req, res) => {
  try {
    // Clear the JWT cookie
    res.clearCookie('jwt', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      // Add path and domain if needed for your setup
      // path: '/', 
      // domain: 'yourdomain.com',
    });
    
    // Also clear any other session-related cookies
    res.clearCookie('feedback_session');
    
    return res.status(200).json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Error during logout', 
      error: error.message 
    });
  }
});

// Routes - Faculty
app.post('/faculty/register',authenticateToken ,async (req, res) => {
  try {
    const { username, password, section, subject } = req.body;
    
    if (!username || !password || !section || !subject) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    const existingFaculty = await Faculty.findOne({
      username,
      section,
      subject,
    });
    
    if (existingFaculty) {
      return res.status(400).json({ success: false, message: 'Faculty with these credentials already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newFaculty = new Faculty({
      username,
      password: hashedPassword,
      section,
      subject,
    });
    
    await newFaculty.save();
    res.status(201).json({ success: true, message: 'Faculty registered successfully' });
  } catch (err) {
    console.error('Faculty registration error:', err);
    res.status(500).json({ success: false, message: 'Registration failed', error: err.message });
  }
});

// Middleware to verify faculty authentication
const authenticateFaculty = async (req, res, next) => {
  try {
    // Get token from authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Get the token part from "Bearer TOKEN"
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }
    
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user is faculty
    if (decoded.role !== 'faculty') {
      return res.status(403).json({ success: false, message: 'Access denied. Not authorized as faculty.' });
    }
    
    // Find faculty in database to ensure they still exist
    const faculty = await Faculty.findById(decoded.id);
    if (!faculty) {
      return res.status(401).json({ success: false, message: 'Invalid faculty account.' });
    }
    
    // Attach faculty info to request object for use in subsequent route handlers
    req.faculty = {
      id: faculty._id,
      username: faculty.username,
      section: faculty.section,
      subject: faculty.subject,
      role: 'faculty'
    };
    
    // Proceed to the next middleware or route handler
    next();
    
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token.' });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired.' });
    } else {
      console.error('Authentication error:', error);
      return res.status(500).json({ success: false, message: 'Authentication failed.', error: error.message });
    }
  }
};

app.get('/faculty/dashboard', authenticateFaculty, (req, res) => {
  // Access faculty info with req.faculty
  res.json({ 
    success: true, 
    message: 'Faculty dashboard accessed successfully', 
    faculty: req.faculty 
  });
});

app.get('/facultyhome',(req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'facultydashboard.html'));  

});


app.get('/faculty', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'facultylogin.html'));
});
app.post('/faculty/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }
    
    // Find the faculty by username
    const faculty = await Faculty.findOne({ username });
    
    if (!faculty) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Compare the provided password with the hashed password
    const isPasswordValid = await bcrypt.compare(password, faculty.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: faculty._id, username: faculty.username, role: 'faculty' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      faculty: {
        id: faculty._id,
        username: faculty.username,
        section: faculty.section,
        subject: faculty.subject
      }
    });
    
  } catch (err) {
    console.error('Faculty login error:', err);
    res.status(500).json({ success: false, message: 'Login failed', error: err.message });
  }
});


// API endpoint to get faculty feedback data
app.get('/faculty/feedback-data', authenticateFaculty, async (req, res) => {
  try {
    // Get faculty info from authenticated middleware
    const { id, username, section, subject } = req.faculty;
    
    // Find feedback for this faculty
    const feedbackData = await Feedback.find({ facultyId: id });
    
    res.status(200).json({
      success: true,
      faculty: {
        username,
        section,
        subject
      },
      feedbackData
    });
    
  } catch (error) {
    console.error('Error fetching feedback data:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch feedback data', 
      error: error.message 
    });
  }
});
// Routes - Schedule and Feedback
app.post('/schedule/feedback', authenticateToken, async (req, res) => {
  try {
    const data = req.body;
    
    if (!data.section) {
      return res.status(400).json({ success: false, message: 'Section is required' });
    }
    
    await Schedule.deleteOne({ section: data.section });
    const newSchedule = new Schedule(data);
    await newSchedule.save();
    
    res.status(200).json({ success: true, id: newSchedule._id });
  } catch (err) {
    console.error('Schedule feedback error:', err);
    res.status(500).json({ success: false, message: 'Failed to save feedback', error: err.message });
  }
});

app.post('/validate/passkey', async (req, res) => {
  try {
    const { passkey } = req.body;
    
    if (!passkey) {
      return res.status(400).json({ success: false, message: 'Passkey is required' });
    }
    
    const numericPasskey = ObjectId.createFromHexString(passkey);
    const schedule = await Schedule.findOne({ _id: numericPasskey });
    
    if (!schedule) {
      return res.status(404).json({ success: false, message: 'Invalid passkey' });
    }
    
    const facultyData = await Faculty.find({ section: schedule.section });
    
    // Create a token for feedback session
    const token = jwt.sign(
      { section: schedule.section, type: 'feedback' },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '1h' }
    );
    
    res.cookie('feedback_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000
    });
    
    return res.status(200).json({ 
      success: true,
      message: 'Valid passkey',
      facultyData: facultyData.map(f => ({
        id: f._id,
        username: f.username,
        subject: f.subject,
        section: f.section
      })),
      section: schedule.section
    });
  } catch (error) {
    console.error('Passkey validation error:', error);
    return res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

app.post('/submit-feedback', async (req, res) => {
  try {
    const { feedback } = req.body;
    
    if (!feedback || !Array.isArray(feedback)) {
      return res.status(400).json({ success: false, message: 'Invalid feedback data' });
    }
    
    // You need to create a feedback model and save the data
    // This is a placeholder - implement your feedback storage logic
    for (const item of feedback) {
      // await Feedback.create({
      //   facultyId: item.facultyId,
      //   rating: item.rating,
      //   comments: item.comments,
      // });
      console.log('Feedback received:', item);
    }
    
    return res.json({ success: true, message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Error submitting feedback:', error);
    return res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

app.get('/admin',(req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/adminhome', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'adminhome.html'));
});

app.get('/admin/schedule', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'schedule.html'));
});

app.get('/student', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'feedbackhome.html'));
});

app.get('/register',authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/feedbackform', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'feedbackform.html'));
});

app.get('/api/faculty-data', (req, res) => {
  const token = req.cookies.feedback_session;
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No session found. Please validate your passkey first.' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    
    if (decoded.type !== 'feedback') {
      return res.status(403).json({ success: false, message: 'Invalid session type' });
    }
    
    return res.json({ success: true, section: decoded.section });
  } catch (error) {
    console.error('Faculty data retrieval error:', error);
    return res.status(403).json({ success: false, message: 'Invalid or expired session' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

const PORT = 5005;
app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`);
});