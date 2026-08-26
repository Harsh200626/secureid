const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-iam-key-change-in-prod';
const PORT = process.env.PORT || 3000;

// ==========================================
// IN-MEMORY STORAGE (Simulated Database)
// ==========================================
const users = [];       // { id, name, email, mobile, passwordHash, mfaEnabled }
const challenges = {};  // challengeId -> { userId, channel, otpHash, expiresAt, attempts }
const sessions = {};    // sessionId -> userId

// Utility Helpers
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
const hashData = async (data) => await bcrypt.hash(data, 10);
const verifyHash = async (data, hash) => await bcrypt.compare(data, hash);

// ==========================================
// REGISTRATION JOURNEY ENDPOINTS
// ==========================================

// 1. Submit Registration Details & Send Email OTP
app.post('/api/register', async (req, res) => {
  const { name, email, mobile, password } = req.body;

  if (!name || !email || !mobile || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).json({ error: 'User with this email already exists.' });
  }

  const passwordHash = await hashData(password);
  const userId = `usr_${Date.now()}`;
  
  users.push({
    id: userId,
    name,
    email,
    mobile,
    passwordHash,
    mfaEnabled: false
  });

  // Generate Email OTP Challenge
  const otp = generateOTP();
  const challengeId = `ch_email_${Date.now()}`;
  
  console.log(`\n==========================================`);
  console.log(`[SIMULATED EMAIL SERVICE]`);
  console.log(`To: ${email}`);
  console.log(`OTP Code: ${otp}`);
  console.log(`==========================================\n`);

  challenges[challengeId] = {
    userId,
    channel: 'email',
    otpHash: await hashData(otp),
    expiresAt: Date.now() + 3 * 60 * 1000, // 3 Minutes Expiry
    attempts: 0
  };

  res.json({ message: 'Registration initiated.', challengeId });
});

// 2. Verify Email OTP
app.post('/api/verify-email-otp', async (req, res) => {
  const { challengeId, otp } = req.body;
  const challenge = challenges[challengeId];

  if (!challenge || challenge.channel !== 'email') {
    return res.status(400).json({ error: 'Invalid or missing challenge.' });
  }

  if (Date.now() > challenge.expiresAt) {
    delete challenges[challengeId];
    return res.status(400).json({ error: 'Code expired. Please request a new code.' });
  }

  if (challenge.attempts >= 3) {
    delete challenges[challengeId];
    return res.status(400).json({ error: 'Maximum attempts reached. Request a new code.' });
  }

  const isValid = await verifyHash(otp, challenge.otpHash);
  if (!isValid) {
    challenge.attempts += 1;
    const remaining = 3 - challenge.attempts;
    return res.status(400).json({ 
      error: `Incorrect code. Please try again.`, 
      attemptsLeft: remaining 
    });
  }

  const userId = challenge.userId;
  delete challenges[challengeId];

  res.json({ message: 'Email verified successfully.', userId });
});

// 3. Send SMS OTP
app.post('/api/send-sms-otp', async (req, res) => {
  const { userId } = req.body;
  const user = users.find(u => u.id === userId);

  if (!user) {
    return res.status(404).json({ error: 'User account not found.' });
  }

  const otp = generateOTP();
  const challengeId = `ch_sms_${Date.now()}`;

  console.log(`\n==========================================`);
  console.log(`[SIMULATED SMS SERVICE]`);
  console.log(`To: ${user.mobile}`);
  console.log(`OTP Code: ${otp}`);
  console.log(`==========================================\n`);

  challenges[challengeId] = {
    userId,
    channel: 'sms',
    otpHash: await hashData(otp),
    expiresAt: Date.now() + 3 * 60 * 1000,
    attempts: 0
  };

  res.json({ message: 'SMS OTP sent.', challengeId });
});

// 4. Verify SMS OTP & Enable MFA
app.post('/api/verify-sms-otp', async (req, res) => {
  const { challengeId, otp } = req.body;
  const challenge = challenges[challengeId];

  if (!challenge || challenge.channel !== 'sms') {
    return res.status(400).json({ error: 'Invalid challenge state.' });
  }

  if (Date.now() > challenge.expiresAt) {
    delete challenges[challengeId];
    return res.status(400).json({ error: 'Code expired.' });
  }

  const isValid = await verifyHash(otp, challenge.otpHash);
  if (!isValid) {
    challenge.attempts += 1;
    return res.status(400).json({ error: 'Incorrect SMS code.' });
  }

  // Finalize Registration & Mark MFA Active
  const user = users.find(u => u.id === challenge.userId);
  if (user) {
    user.mfaEnabled = true;
  }

  delete challenges[challengeId];
  res.json({ message: 'Account created successfully and MFA enabled.' });
});

// ==========================================
// LOGIN JOURNEY ENDPOINTS
// ==========================================

// 5. Submit Credentials & Trigger Login OTP
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  if (!user || !(await verifyHash(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  // Issue Login MFA Challenge
  const otp = generateOTP();
  const challengeId = `ch_login_${Date.now()}`;

  console.log(`\n==========================================`);
  console.log(`[SIMULATED LOGIN MFA]`);
  console.log(`To: ${user.email}`);
  console.log(`OTP Code: ${otp}`);
  console.log(`==========================================\n`);

  challenges[challengeId] = {
    userId: user.id,
    channel: 'login',
    otpHash: await hashData(otp),
    expiresAt: Date.now() + 3 * 60 * 1000,
    attempts: 0
  };

  res.json({ 
    mfaRequired: true, 
    method: 'email', 
    challengeId 
  });
});

// 6. Verify Login OTP & Establish Authenticated Session
app.post('/api/verify-login-otp', async (req, res) => {
  const { challengeId, otp } = req.body;
  const challenge = challenges[challengeId];

  if (!challenge || !(await verifyHash(otp, challenge.otpHash))) {
    return res.status(400).json({ error: 'Invalid or expired OTP.' });
  }

  const userId = challenge.userId;
  delete challenges[challengeId];

  // Set HTTP-Only Session Cookie
  const sessionId = `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  sessions[sessionId] = userId;

  res.cookie('sessionId', sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  });

  res.json({ message: 'Login successful!' });
});

// ==========================================
// SESSION & JWT MANAGEMENT
// ==========================================

// Get Current User Profile via Session
app.get('/api/me', (req, res) => {
  const sessionId = req.cookies.sessionId;
  const userId = sessions[sessionId];

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized. No active session.' });
  }

  const user = users.find(u => u.id === userId);
  res.json({ 
    id: user.id, 
    name: user.name, 
    email: user.email, 
    mobile: user.mobile,
    mfaEnabled: user.mfaEnabled 
  });
});

// Session Logout
app.post('/api/logout', (req, res) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId) {
    delete sessions[sessionId];
  }
  res.clearCookie('sessionId');
  res.json({ message: 'Logged out successfully.' });
});

// Issue JWT Token from Active Session
app.post('/api/token', (req, res) => {
  const sessionId = req.cookies.sessionId;
  const userId = sessions[sessionId];

  if (!userId) {
    return res.status(401).json({ error: 'Session required to request JWT token.' });
  }

  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '15m' });
  res.json({ token });
});

// Protected Endpoint (Requires Bearer Token)
app.get('/api/protected', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Bearer token.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: 'Access Granted: Protected Payload', data: decoded });
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token.' });
  }
});

// Fallback for Vercel / Single Page App
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});