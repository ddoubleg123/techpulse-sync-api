const express = require('express');
const cors = require('cors');
const crypto = require('crypto'); const jwt = (() => { try { return require('jsonwebtoken'); } catch (e) { return null; } })();
const { Resend } = require('resend');
const { createClient: createRedisClient } = require('redis');

const app = express();
const PORT = process.env.PORT || 3001;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = 'https://techpulse-sync-api.onrender.com/api/auth/google/callback';
const APP_URL = 'https://techpulse-remotepc-automation.onrender.com/app'; const SUPABASE_URL = process.env.SUPABASE_URL; const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY; const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET; const SUPABASE_AUTH_ENABLED = !!(SUPABASE_URL && SUPABASE_SERVICE_KEY && SUPABASE_JWT_SECRET);

app.use(cors({
  origin: ['https://techpulse.dev', 'https://www.techpulse.dev', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// ===== Email OTP (added 2026-05-17) =====
// Restores email-OTP login for marketing site (techpulse.dev sign-in modal).
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM = process.env.RESEND_FROM_EMAIL || process.env.RESEND_FROM || 'TechPulse <invites@auth.techpulse.dev>';
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
const OTP_TTL_SEC = 10 * 60; // 10 minutes

// Redis client for OTP storage (survives restarts and free-tier spin-downs)
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = parseInt(process.env.REDIS_PORT || '6379', 10);
const redisClient = REDIS_HOST ? createRedisClient({ socket: { host: REDIS_HOST, port: REDIS_PORT } }) : null;
let redisReady = false;
if (redisClient) {
  redisClient.on('error', e => console.error('[redis] error:', e.message));
  redisClient.on('ready', () => { redisReady = true; console.log('[redis] connected'); });
  redisClient.connect().catch(e => console.error('[redis] connect failed:', e.message));
}
const otpKey = email => `otp:${email}`;


// OTP storage removed 2026-04-29 (G12). The OTP routes were broken on Render free tier
// (in-memory Map blown away on cold start every 15 min) and no email-sending lib was installed.
// sync-api retires under G4 — replaced by Supabase Auth's built-in magic-link if ever needed.

// In-memory user store (resets on each Render restart)
const userStore = new Map();

userStore.set('test@example.com', { id: '1', email: 'test@example.com', name: 'Test User', hasPaymentMethodOnFile: false });
userStore.set('demo@techpulse.dev', { id: '2', email: 'demo@techpulse.dev', name: 'Demo User', hasPaymentMethodOnFile: true });

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function findOrCreateSupabaseUser(email, name) { if (!SUPABASE_AUTH_ENABLED) return null; const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json' }; try { const createRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, { method: 'POST', headers, body: JSON.stringify({ email, email_confirm: true, user_metadata: { name: name || '' } }) }); if (createRes.ok) return await createRes.json(); const listRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users?per_page=1000`, { headers }); if (listRes.ok) { const data = await listRes.json(); const users = data.users || []; return users.find(u => (u.email || '').toLowerCase() === email.toLowerCase()) || null; } return null; } catch (err) { console.error('Supabase admin error:', err.message); return null; } } function generateToken(user, supabaseUser) {
  if (SUPABASE_AUTH_ENABLED && jwt && supabaseUser && supabaseUser.id) { try { return jwt.sign({ sub: supabaseUser.id, email: user.email, aud: 'authenticated', role: 'authenticated' }, SUPABASE_JWT_SECRET, { algorithm: 'HS256', expiresIn: '7d' }); } catch (err) { console.error('JWT sign failed, falling back:', err.message); } } const payload = { userId: user.id, email: user.email, exp: Date.now() + (24 * 60 * 60 * 1000) };
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
    const supabaseUser = await findOrCreateSupabaseUser(user.email, user.name); const token = generateToken(user, supabaseUser);
    const redirectUrl = new URL(APP_URL);
    redirectUrl.searchParams.set('token', token);
    redirectUrl.searchParams.set('email', user.email);
    res.redirect(302, redirectUrl.toString());
  } catch (err) {
    console.error('Google auth error:', err);
    res.redirect(302, 'https://www.techpulse.dev?error=auth_failed');
  }
});

// ===== Email OTP routes =====
app.post('/api/auth/email/send-otp', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Valid email required' });
    }
    if (!resend) {
      console.error('[send-otp] RESEND_API_KEY not configured');
      return res.status(500).json({ message: 'Email service not configured on server' });
    }
    const otp = generateOTP();
    if (!redisReady) {
      console.error('[send-otp] Redis not ready');
      return res.status(503).json({ message: 'OTP service temporarily unavailable, please retry' });
    }
    await redisClient.set(otpKey(email), String(otp), { EX: OTP_TTL_SEC });
    const html = '<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;color:#1a1a1a;">' +
      '<div style="font-weight:700;font-size:18px;color:#0d9e7e;margin-bottom:8px;">TechPulse</div>' +
      '<h2 style="font-size:20px;margin:8px 0 16px;">Your verification code</h2>' +
      '<p style="font-size:14px;color:#555;margin:0 0 16px;">Enter this code to finish signing in. It expires in 10 minutes.</p>' +
      '<div style="font-size:32px;font-weight:700;letter-spacing:8px;padding:20px;background:#f4f5f7;border-radius:10px;text-align:center;margin:16px 0;">' + otp + '</div>' +
      '<p style="font-size:12px;color:#888;margin-top:24px;">If you didn\'t request this, you can safely ignore this email.</p>' +
      '</div>';
    const result = await resend.emails.send({
      from: RESEND_FROM,
      to: [email],
      subject: 'Your TechPulse verification code: ' + otp,
      html,
      text: 'Your TechPulse verification code: ' + otp + '\n\nThis code expires in 10 minutes.'
    });
    if (result && result.error) {
      console.error('[send-otp] Resend error:', result.error);
      return res.status(500).json({ message: 'Failed to send verification code', detail: result.error.message || String(result.error) });
    }
    return res.json({ success: true });
  } catch (e) {
    console.error('[send-otp] exception:', e);
    return res.status(500).json({ message: 'Failed to send verification code' });
  }
});

app.post('/api/auth/email/verify-otp', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const otp = String(req.body?.otp || '').trim();
    if (!email || !otp) return res.status(400).json({ message: 'Email and code required' });
    if (!redisReady) {
      console.error('[verify-otp] Redis not ready');
      return res.status(503).json({ message: 'OTP service temporarily unavailable, please retry' });
    }
    const stored = await redisClient.get(otpKey(email));
    if (!stored) return res.status(401).json({ message: 'Code expired or not found' });
    if (String(stored) !== String(otp)) return res.status(401).json({ message: 'Invalid code' });
    await redisClient.del(otpKey(email));
    const user = await findOrCreateSupabaseUser(email);
    const token = generateToken(user);
    return res.json({ token, user });
  } catch (e) {
    console.error('[verify-otp] exception:', e);
    return res.status(500).json({ message: 'Verification failed' });
  }
});

app.use((err, req, res, next) => res.status(500).json({ message: 'Internal server error' }));
app.use('*', (req, res) => res.status(404).json({ message: 'Endpoint not found' }));


app.listen(PORT, () => {
  console.log(`TechPulse Auth API running on port ${PORT}`);
});

module.exports = app;
