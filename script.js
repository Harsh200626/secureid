const state = {
  challengeId: null,
  userId: null,
  jwtToken: null
};

function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
  document.getElementById(screenId).classList.remove('hidden');
  hideAlert();
}

function showAlert(message) {
  const alertBox = document.getElementById('alert-box');
  alertBox.innerText = message;
  alertBox.classList.remove('hidden');
}

function hideAlert() {
  const alertBox = document.getElementById('alert-box');
  alertBox.classList.add('hidden');
  alertBox.innerText = '';
}

// 1. Submit Registration
async function handleRegister() {
  const name = document.getElementById('reg-name').value;
  const email = document.getElementById('reg-email').value;
  const mobile = document.getElementById('reg-mobile').value;
  const password = document.getElementById('reg-password').value;

  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, mobile, password })
  });

  const data = await res.json();
  if (!res.ok) return showAlert(data.error);

  state.challengeId = data.challengeId;
  document.getElementById('email-otp-desc').innerText = `Enter the 6-digit code sent to ${email}`;
  showScreen('screen-email-otp');
}

// 2. Verify Email OTP
async function handleVerifyEmailOTP() {
  const otp = document.getElementById('email-otp-code').value;

  const res = await fetch('/api/verify-email-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: state.challengeId, otp })
  });

  const data = await res.json();
  if (!res.ok) return showAlert(data.error);

  state.userId = data.userId;

  // Trigger SMS OTP request
  const smsRes = await fetch('/api/send-sms-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: state.userId })
  });

  const smsData = await smsRes.json();
  if (!smsRes.ok) return showAlert(smsData.error);

  state.challengeId = smsData.challengeId;
  showScreen('screen-sms-otp');
}

// 3. Verify SMS OTP & Complete Setup
async function handleVerifySMSOTP() {
  const otp = document.getElementById('sms-otp-code').value;

  const res = await fetch('/api/verify-sms-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: state.challengeId, otp })
  });

  const data = await res.json();
  if (!res.ok) return showAlert(data.error);

  alert('Registration Complete & MFA Enabled! Please log in.');
  showScreen('screen-login');
}

// 4. Login Credentials
async function handleLogin() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;

  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (!res.ok) return showAlert(data.error);

  state.challengeId = data.challengeId;
  showScreen('screen-login-otp');
}

// 5. Verify Login OTP
async function handleVerifyLoginOTP() {
  const otp = document.getElementById('login-otp-code').value;

  const res = await fetch('/api/verify-login-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: state.challengeId, otp })
  });

  const data = await res.json();
  if (!res.ok) return showAlert(data.error);

  loadDashboard();
}

// 6. Fetch Dashboard Info & Request JWT Token
async function loadDashboard() {
  const res = await fetch('/api/me');
  if (!res.ok) return showScreen('screen-login');

  const user = await res.json();
  document.getElementById('user-profile').innerHTML = `
    <strong>Name:</strong> ${user.name}<br>
    <strong>Email:</strong> ${user.email}<br>
    <strong>Mobile:</strong> ${user.mobile}<br>
    <strong>User ID:</strong> ${user.id}
  `;

  // Request JWT Token
  const tokenRes = await fetch('/api/token', { method: 'POST' });
  const tokenData = await tokenRes.json();
  state.jwtToken = tokenData.token;

  showScreen('screen-dashboard');
}

// Test JWT Endpoint
async function testProtectedAPI() {
  const res = await fetch('/api/protected', {
    headers: { 'Authorization': `Bearer ${state.jwtToken}` }
  });

  const data = await res.json();
  alert(JSON.stringify(data, null, 2));
}

// Handle Logout
async function handleLogout() {
  await fetch('/api/logout', { method: 'POST' });
  state.jwtToken = null;
  showScreen('screen-login');
}