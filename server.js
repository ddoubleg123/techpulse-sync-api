const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = 'https://techpulse-sync-api.onrender.com/api/auth/google/callback';
const APP_URL = 'https://techpulse-remotepc-automation.onrender.com/app';

app.use(cors({
  origin: ['https://techpulse.dev', 'https://www.techpulse.dev', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// OTP storage removed 2026-04-29 (G12). The OTP routes were broken on Render free tier
// (in-memory Map blown away on cold start every 15 min) and no email-sending lib was installed.
// sync-api retires under G4 — replaced by Supabase Auth's built-in magic-link if ever needed.

// In-memory user store (resets on each Render restart)
const userStore = new Map();

// In-memory user store (resets on each Render restart)
const userStore = new Map();

userStore.set('test@example.com', { id: '1', email: 'test@example.com', name: 'Test User', hasPaymentMethodOnFile: false });
userStore.set('demo@techpulse.dev', { id: '2', email: 'demo@techpulse.dev', name: 'Demo User', hasPaymentMethodOnFile: true });

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateToken(user) {
  const payload = { userId: user.id, email: user.email, exp: Date.now() + (24 * 60 * 60 * 1000) };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

async function getGoogleUser(code) {
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code'
    })
  });
  const tokens = await tokenRes.json();
  if (!tokens.access_token) throw new Error('Token exchange failed: ' + JSON.stringify(tokens));
  const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${tokens.access_token}` }
  });
  return userRes.json();
}

app.get('/health', (req, res) => res.json({ status: 'OK', timestamp: new Date().toISOString() }));
app.get('/', (req, res) => res.json({ status: 'TechPulse Auth API' }));

// OTP routes (/api/auth/email/send-otp, /api/auth/email/verify-otp) removed 2026-04-29 (G12).
// Reason: routes were broken on Render free tier and no email transport was configured.
// Auth flow now uses Google OAuth only (the routes below).
// sync-api retires under G4 — Supabase Auth has built-in magic-link if needed.


// Initiates Google OAuth — redirect_uri must match Google Cloud Console exactly
app.get('/api/auth/google', (req, res) => {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account'
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// Google OAuth callback — always redirects to app, never returns JSON
app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.redirect(`${APP_URL}?error=no_code`);
    const googleUser = await getGoogleUser(code);
    console.log(`Google user authenticated: ${googleUser.email}`);
    let user = userStore.get(googleUser.email);
    if (!user) {
      user = { id: googleUser.id || crypto.randomUUID(), email: googleUser.email, name: googleUser.name, hasPaymentMethodOnFile: false };
      userStore.set(googleUser.email, user);
    }
    const token = generateToken(user);
    const redirectUrl = new URL(APP_URL);
    redirectUrl.searchParams.set('token', token);
    redirectUrl.searchParams.set('email', user.email);
    res.redirect(302, redirectUrl.toString());
  } catch (err) {
    console.error('Google auth error:', err);
    res.redirect(302, 'https://www.techpulse.dev?error=auth_failed');
  }
});

app.use((err, req, res, next) => res.status(500).json({ message: 'Internal server error' }));
app.use('*', (req, res) => res.status(404).json({ message: 'Endpoint not found' }));

app.listen(PORT, () => {
  console.log(`TechPulse Auth API running on port ${PORT}`);
});

module.exports = app;
