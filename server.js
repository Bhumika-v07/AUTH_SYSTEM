/**
 * NexAuth — Production-grade Express Backend
 * Features: bcrypt hashing, JWT auth, HTTP-only cookies,
 *           rate limiting, RBAC, session management
 */

const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const rateLimit  = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const cors       = require('cors');
const path       = require('path');

const app = express();

// ─────────────────────────────────────────────
// CONFIG  (use .env in real projects)
// ─────────────────────────────────────────────
const CONFIG = {
  JWT_SECRET:        process.env.JWT_SECRET        || 'super-secret-key-change-in-prod',
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'refresh-secret-change-in-prod',
  ACCESS_TOKEN_TTL:  '15m',   // short-lived access token
  REFRESH_TOKEN_TTL: '7d',    // long-lived refresh token
  BCRYPT_ROUNDS:     12,      // higher = slower hash = harder to brute-force
  PORT:              process.env.PORT || 3000,
};

// ─────────────────────────────────────────────
// IN-MEMORY "DATABASE"  (swap with MongoDB/PostgreSQL)
// ─────────────────────────────────────────────
const DB = {
  users: [
    // Pre-seeded demo users — passwords will be hashed at startup
    { id: '1', name: 'Alex Admin',  email: 'admin@nexauth.com', passwordHash: '', role: 'admin',     createdAt: new Date() },
    { id: '2', name: 'Sam Mod',     email: 'mod@nexauth.com',   passwordHash: '', role: 'moderator', createdAt: new Date() },
    { id: '3', name: 'Jamie User',  email: 'user@nexauth.com',  passwordHash: '', role: 'user',      createdAt: new Date() },
  ],
  refreshTokens: new Set(),  // store valid refresh tokens (use Redis in prod)
  loginAttempts: new Map(),  // track failed attempts per IP (use Redis in prod)
};

// Hash demo passwords at startup
(async () => {
  const seeds = ['Admin@123', 'Mod@1234', 'User@123'];
  for (let i = 0; i < DB.users.length; i++) {
    DB.users[i].passwordHash = await bcrypt.hash(seeds[i], CONFIG.BCRYPT_ROUNDS);
  }
  console.log('✅ Demo users seeded with hashed passwords');
})();

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.static(__dirname));

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────

// 1. Global limiter — every endpoint
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

// 2. Strict auth limiter — login/register only
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,                    // only 10 login attempts
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  skipSuccessfulRequests: true, // don't count successful logins
});

app.use(globalLimiter);

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function generateTokens(user) {
  const payload = { sub: user.id, email: user.email, role: user.role, name: user.name };

  const accessToken = jwt.sign(payload, CONFIG.JWT_SECRET, {
    expiresIn: CONFIG.ACCESS_TOKEN_TTL,
    issuer: 'nexauth',
    audience: 'nexauth-client',
  });

  const refreshToken = jwt.sign({ sub: user.id }, CONFIG.JWT_REFRESH_SECRET, {
    expiresIn: CONFIG.REFRESH_TOKEN_TTL,
  });

  DB.refreshTokens.add(refreshToken);
  return { accessToken, refreshToken };
}

function setTokenCookies(res, { accessToken, refreshToken }) {
  // HTTP-only = JS cannot read this cookie → XSS protection
  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
    sameSite: 'strict',  // CSRF protection
    maxAge: 15 * 60 * 1000, // 15 min
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth/refresh', // only sent to refresh endpoint
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
}

// ─────────────────────────────────────────────
// MIDDLEWARE: Authenticate JWT
// ─────────────────────────────────────────────
function authenticate(req, res, next) {
  // Read token from HTTP-only cookie (preferred) or Authorization header
  const token = req.cookies.accessToken
    || req.headers.authorization?.replace('Bearer ', '');

  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET, {
      issuer: 'nexauth',
      audience: 'nexauth-client',
    });
    req.user = decoded; // attach user info to request
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ─────────────────────────────────────────────
// MIDDLEWARE: Role-Based Access Control
// ─────────────────────────────────────────────
function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied. Required role: ${allowedRoles.join(' or ')}`,
        yourRole: req.user.role,
      });
    }
    next();
  };
}

// ─────────────────────────────────────────────
// ROUTES: AUTH
// ─────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password, role = 'user' } = req.body;

    // Validate inputs
    if (!name || name.trim().length < 2)
      return res.status(400).json({ error: 'Name must be at least 2 characters' });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email))
      return res.status(400).json({ error: 'Invalid email address' });

    const strongPw = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{8,}$/;
    if (!strongPw.test(password))
      return res.status(400).json({ error: 'Password must be 8+ chars with uppercase, number & symbol' });

    const allowedRoles = ['user', 'moderator', 'admin'];
    if (!allowedRoles.includes(role))
      return res.status(400).json({ error: 'Invalid role' });

    // Check duplicate email
    if (DB.users.find(u => u.email === email))
      return res.status(409).json({ error: 'Email already registered' });

    // Hash password with bcrypt (12 salt rounds)
    const passwordHash = await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS);

    const newUser = {
      id: String(Date.now()),
      name: name.trim(),
      email: email.toLowerCase(),
      passwordHash,  // NEVER store plain password
      role,
      createdAt: new Date(),
    };
    DB.users.push(newUser);

    const tokens = generateTokens(newUser);
    setTokenCookies(res, tokens);

    // Never send passwordHash to client
    res.status(201).json({
      message: 'Account created successfully',
      user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role },
      accessToken: tokens.accessToken, // also return in body for frontend convenience
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip;

    // Check brute-force attempts per IP
    const attempts = DB.loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
    if (Date.now() < attempts.lockedUntil) {
      const secs = Math.ceil((attempts.lockedUntil - Date.now()) / 1000);
      return res.status(429).json({ error: `Account locked. Try again in ${secs}s` });
    }

    const user = DB.users.find(u => u.email === email?.toLowerCase());

    // Use bcrypt.compare — timing-safe comparison
    const valid = user && await bcrypt.compare(password, user.passwordHash);

    if (!valid) {
      attempts.count++;
      if (attempts.count >= 5) {
        attempts.lockedUntil = Date.now() + 15 * 60 * 1000; // lock 15 min
        attempts.count = 0;
      }
      DB.loginAttempts.set(ip, attempts);
      // Vague error message — don't reveal which field is wrong
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset attempts on success
    DB.loginAttempts.delete(ip);

    const tokens = generateTokens(user);
    setTokenCookies(res, tokens);

    res.json({
      message: 'Login successful',
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      accessToken: tokens.accessToken,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/refresh — get new access token using refresh token
app.post('/api/auth/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token || !DB.refreshTokens.has(token))
    return res.status(401).json({ error: 'Invalid refresh token' });

  try {
    const decoded = jwt.verify(token, CONFIG.JWT_REFRESH_SECRET);
    const user = DB.users.find(u => u.id === decoded.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });

    // Rotate refresh token (one-time use)
    DB.refreshTokens.delete(token);
    const tokens = generateTokens(user);
    setTokenCookies(res, tokens);

    res.json({ accessToken: tokens.accessToken });
  } catch {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', authenticate, (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) DB.refreshTokens.delete(refreshToken);

  res.clearCookie('accessToken');
  res.clearCookie('refreshToken', { path: '/api/auth/refresh' });
  res.json({ message: 'Logged out successfully' });
});

// ─────────────────────────────────────────────
// ROUTES: PROTECTED (require authentication)
// ─────────────────────────────────────────────

// GET /api/me — any logged-in user
app.get('/api/me', authenticate, (req, res) => {
  const user = DB.users.find(u => u.id === req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role, createdAt: user.createdAt });
});

// GET /api/users — moderator + admin only
app.get('/api/users', authenticate, authorize('moderator', 'admin'), (req, res) => {
  const safeUsers = DB.users.map(({ id, name, email, role, createdAt }) => ({ id, name, email, role, createdAt }));
  res.json({ users: safeUsers, total: safeUsers.length });
});

// DELETE /api/users/:id — admin only
app.delete('/api/users/:id', authenticate, authorize('admin'), (req, res) => {
  const idx = DB.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  if (req.params.id === req.user.sub) return res.status(400).json({ error: 'Cannot delete yourself' });
  DB.users.splice(idx, 1);
  res.json({ message: 'User deleted' });
});

// GET /api/admin/stats — admin only
app.get('/api/admin/stats', authenticate, authorize('admin'), (req, res) => {
  res.json({
    totalUsers: DB.users.length,
    byRole: {
      admin: DB.users.filter(u => u.role === 'admin').length,
      moderator: DB.users.filter(u => u.role === 'moderator').length,
      user: DB.users.filter(u => u.role === 'user').length,
    },
    activeSessions: DB.refreshTokens.size,
  });
});

// Catch-all: serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(CONFIG.PORT, () => {
  console.log(`\n🚀 NexAuth server running → http://localhost:${CONFIG.PORT}`);
  console.log(`   Demo logins: admin@nexauth.com/Admin@123  |  user@nexauth.com/User@123\n`);
});
