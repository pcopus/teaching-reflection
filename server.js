// server.js — Teaching Reflection backend
// Express + better-sqlite3 + bcrypt + sessions

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('better-sqlite3-session-store')(session);
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// ── Config ───────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'app.db');
const SESSIONS_DB_PATH = path.join(DATA_DIR, 'sessions.db');

const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('FATAL: SESSION_SECRET must be set and at least 32 characters.');
  process.exit(1);
}

const ADMIN_BOOTSTRAP_EMAIL = (process.env.ADMIN_BOOTSTRAP_EMAIL || '').toLowerCase().trim();
const ADMIN_BOOTSTRAP_PASSWORD = process.env.ADMIN_BOOTSTRAP_PASSWORD;
const ADMIN_BOOTSTRAP_NAME = process.env.ADMIN_BOOTSTRAP_NAME || 'Administrator';

// ── DB setup ─────────────────────────────────────────────────────────────────

fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS responses (
    user_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'draft',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    submitted_at TEXT,
    data_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Sessions DB (separate file so wiping sessions never touches user data)
const sessionsDb = new Database(SESSIONS_DB_PATH);
sessionsDb.pragma('journal_mode = WAL');

// Bootstrap admin if env vars provided and no admin exists
function bootstrapAdmin() {
  const adminCount = db.prepare('SELECT COUNT(*) AS c FROM users WHERE is_admin = 1').get().c;
  if (adminCount > 0) return;
  if (!ADMIN_BOOTSTRAP_EMAIL || !ADMIN_BOOTSTRAP_PASSWORD) {
    console.warn('No admin in DB and ADMIN_BOOTSTRAP_EMAIL/PASSWORD not set. Set them and restart to create the first admin.');
    return;
  }
  const hash = bcrypt.hashSync(ADMIN_BOOTSTRAP_PASSWORD, 12);
  db.prepare(`
    INSERT INTO users (name, email, password_hash, is_admin, must_change_password)
    VALUES (?, ?, ?, 1, 1)
  `).run(ADMIN_BOOTSTRAP_NAME, ADMIN_BOOTSTRAP_EMAIL, hash);
  console.log(`Bootstrap admin created: ${ADMIN_BOOTSTRAP_EMAIL}`);
}
bootstrapAdmin();

// ── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '256kb' }));

app.use(session({
  store: new SQLiteStore({
    client: sessionsDb,
    expired: { clear: true, intervalMs: 15 * 60 * 1000 }
  }),
  name: 'tr.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8, // 8 hours
  }
}));

// Same-origin check on state-changing requests as belt-and-suspenders against CSRF
app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  if (!req.path.startsWith('/api/')) return next();
  const origin = req.get('Origin');
  const host = req.get('Host');
  if (!origin) return next(); // same-origin form post; SameSite=lax already protects us
  try {
    const originHost = new URL(origin).host;
    if (originHost !== host) return res.status(403).json({ error: 'Cross-origin requests not allowed' });
  } catch (e) {
    return res.status(400).json({ error: 'Bad Origin header' });
  }
  next();
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

function userPublic(u) {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    isAdmin: !!u.is_admin,
    mustChangePassword: !!u.must_change_password,
    createdAt: u.created_at,
  };
}

function getSetting(key, defaultVal) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : defaultVal;
}

function setSetting(key, value) {
  db.prepare(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
    .run(key, String(value));
}

function isSubmissionsLocked() { return getSetting('submissions_locked', '0') === '1'; }

function isValidEmail(s) {
  return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 200;
}

function isValidPassword(s) {
  return typeof s === 'string' && s.length >= 10 && s.length <= 200;
}

function isValidName(s) {
  return typeof s === 'string' && s.trim().length >= 1 && s.length <= 120;
}

// ── Auth routes ──────────────────────────────────────────────────────────────

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
});

// Pre-computed dummy hash for timing-safe response when user not found
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing-safety', 12);

app.post('/api/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const cleanEmail = email.toLowerCase().trim();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);

  // Always run bcrypt to keep response time constant whether or not user exists
  const ok = user
    ? bcrypt.compareSync(password, user.password_hash)
    : (bcrypt.compareSync(password, DUMMY_HASH), false);

  if (!user || !ok) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  if (isSubmissionsLocked() && !user.is_admin) {
    return res.status(403).json({ error: 'Submissions are currently closed. Please contact the department chair.' });
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.userId = user.id;
    req.session.isAdmin = !!user.is_admin;
    req.session.save(() => res.json({ user: userPublic(user) }));
  });
});

app.post('/api/logout', (req, res) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy(() => {
    res.clearCookie('tr.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'User not found' });
  }
  res.json({ user: userPublic(user), submissionsLocked: isSubmissionsLocked() });
});

// Public: lock state for login screen banner
app.get('/api/status', (req, res) => {
  res.json({ submissionsLocked: isSubmissionsLocked() });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  if (!isValidPassword(newPassword)) {
    return res.status(400).json({ error: 'New password must be 10–200 characters' });
  }
  if (currentPassword === newPassword) {
    return res.status(400).json({ error: 'New password must be different from current password' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user || !bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const newHash = bcrypt.hashSync(newPassword, 12);
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?')
    .run(newHash, user.id);
  res.json({ ok: true });
});

// ── Faculty: own responses ───────────────────────────────────────────────────

app.get('/api/responses', requireAuth, (req, res) => {
  const row = db.prepare('SELECT status, updated_at, submitted_at, data_json FROM responses WHERE user_id = ?')
    .get(req.session.userId);
  if (!row) {
    return res.json({ status: null, data: {}, updatedAt: null, submittedAt: null });
  }
  let data = {};
  try { data = JSON.parse(row.data_json); } catch (e) { /* leave empty */ }
  res.json({
    status: row.status,
    data,
    updatedAt: row.updated_at,
    submittedAt: row.submitted_at,
  });
});

app.put('/api/responses', requireAuth, (req, res) => {
  if (req.session.isAdmin) {
    return res.status(403).json({ error: 'Admin accounts cannot submit responses' });
  }
  if (isSubmissionsLocked()) {
    return res.status(403).json({ error: 'Submissions are currently locked. Contact the department chair to make changes.' });
  }
  const { data, submit } = req.body || {};
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return res.status(400).json({ error: 'data must be an object' });
  }
  const json = JSON.stringify(data);
  if (json.length > 250000) {
    return res.status(413).json({ error: 'Response too large (max 250KB)' });
  }
  const status = submit ? 'submitted' : 'draft';
  const submittedAt = submit ? new Date().toISOString() : null;

  // Preserve existing submitted_at if already submitted and not re-submitting fresh
  const existing = db.prepare('SELECT submitted_at FROM responses WHERE user_id = ?').get(req.session.userId);
  const finalSubmittedAt = submit ? submittedAt : (existing ? existing.submitted_at : null);

  db.prepare(`
    INSERT INTO responses (user_id, status, updated_at, submitted_at, data_json)
    VALUES (?, ?, datetime('now'), ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      status = excluded.status,
      updated_at = excluded.updated_at,
      submitted_at = COALESCE(excluded.submitted_at, responses.submitted_at),
      data_json = excluded.data_json
  `).run(req.session.userId, status, finalSubmittedAt, json);

  res.json({ ok: true, status });
});

// ── Admin: users ─────────────────────────────────────────────────────────────

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT * FROM users ORDER BY is_admin DESC, name COLLATE NOCASE').all();
  res.json({ users: users.map(userPublic) });
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { name, email, password, isAdmin } = req.body || {};
  if (!isValidName(name)) return res.status(400).json({ error: 'Valid name required' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!isValidPassword(password)) return res.status(400).json({ error: 'Password must be 10–200 characters' });

  const cleanEmail = email.toLowerCase().trim();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
  if (existing) return res.status(409).json({ error: 'A user with that email already exists' });

  const hash = bcrypt.hashSync(password, 12);
  const result = db.prepare(`
    INSERT INTO users (name, email, password_hash, is_admin, must_change_password)
    VALUES (?, ?, ?, ?, 1)
  `).run(name.trim(), cleanEmail, hash, isAdmin ? 1 : 0);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ user: userPublic(user) });
});

app.patch('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid user id' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { name, password, isAdmin } = req.body || {};
  const sets = [];
  const params = [];

  if (name !== undefined) {
    if (!isValidName(name)) return res.status(400).json({ error: 'Valid name required' });
    sets.push('name = ?'); params.push(name.trim());
  }
  if (typeof isAdmin === 'boolean') {
    if (user.is_admin && !isAdmin) {
      const adminCount = db.prepare('SELECT COUNT(*) AS c FROM users WHERE is_admin = 1').get().c;
      if (adminCount <= 1) return res.status(400).json({ error: 'Cannot demote the only admin' });
    }
    sets.push('is_admin = ?'); params.push(isAdmin ? 1 : 0);
  }
  if (password !== undefined) {
    if (!isValidPassword(password)) return res.status(400).json({ error: 'Password must be 10–200 characters' });
    sets.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 12));
    sets.push('must_change_password = 1');
  }
  if (sets.length === 0) return res.json({ user: userPublic(user) });

  params.push(id);
  db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.json({ user: userPublic(updated) });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid user id' });
  if (id === req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.is_admin) {
    const adminCount = db.prepare('SELECT COUNT(*) AS c FROM users WHERE is_admin = 1').get().c;
    if (adminCount <= 1) return res.status(400).json({ error: 'Cannot delete the only admin' });
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true });
});

// ── Admin: settings (lock toggle) ────────────────────────────────────────────

app.get('/api/admin/settings', requireAdmin, (req, res) => {
  res.json({
    submissionsLocked: isSubmissionsLocked(),
    lockedAt: getSetting('submissions_locked_at', null),
  });
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const { submissionsLocked } = req.body || {};
  if (typeof submissionsLocked !== 'boolean') {
    return res.status(400).json({ error: 'submissionsLocked must be a boolean' });
  }
  setSetting('submissions_locked', submissionsLocked ? '1' : '0');
  setSetting('submissions_locked_at', submissionsLocked ? new Date().toISOString() : '');
  res.json({
    submissionsLocked: isSubmissionsLocked(),
    lockedAt: getSetting('submissions_locked_at', null),
  });
});

// ── Admin: submissions ───────────────────────────────────────────────────────

app.get('/api/admin/submissions', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id AS user_id, u.name, u.email,
           r.status, r.updated_at, r.submitted_at, r.data_json
    FROM users u
    LEFT JOIN responses r ON r.user_id = u.id
    WHERE u.is_admin = 0
    ORDER BY u.name COLLATE NOCASE
  `).all();

  const submissions = rows.map(r => {
    let data = {};
    if (r.data_json) {
      try { data = JSON.parse(r.data_json); } catch (e) { /* leave empty */ }
    }
    return {
      userId: r.user_id,
      name: r.name,
      email: r.email,
      status: r.status, // null if no row in responses yet
      updatedAt: r.updated_at,
      submittedAt: r.submitted_at,
      data,
    };
  });
  res.json({ submissions });
});

// ── Healthcheck ──────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ── Static frontend ──────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '5m',
  index: 'index.html',
}));

// Catch-all: serve index.html for any non-API route
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Error handler ────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Teaching Reflection server listening on port ${PORT} (${NODE_ENV})`);
});
