// auth.js — Session middleware helpers
const { query, queryOne } = require('./db');

/**
 * Parse session cookie and attach user to req.user
 */
async function sessionMiddleware(req, res, next) {
  req.user = null;
  const sessionId = req.cookies?.sessionId;
  if (!sessionId) return next();

  try {
    const session = await queryOne(
      'SELECT s.*, u.id as uid, u.username, u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > NOW()',
      [sessionId]
    );
    if (session) {
      req.user = {
        id: session.uid,
        username: session.username,
        email: session.email,
        role: session.role,
      };
    }
  } catch (err) {
    console.error('[session]', err.message);
  }
  next();
}

/**
 * Require authenticated user
 */
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required.' });
  next();
}

/**
 * Require admin role
 */
function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required.' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

/**
 * Create a new session in DB and set cookie
 */
async function createSession(res, userId) {
  const { v4: uuidv4 } = require('uuid');
  const sessionId = uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
  const expiresSeconds = parseInt(process.env.SESSION_EXPIRES_SECONDS || '86400');
  const expiresAt = new Date(Date.now() + expiresSeconds * 1000);

  await query(
    'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)',
    [sessionId, userId, expiresAt]
  );

  res.cookie('sessionId', sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    expires: expiresAt,
    path: '/',
  });

  return sessionId;
}

/**
 * Destroy session
 */
async function destroySession(req, res) {
  const sessionId = req.cookies?.sessionId;
  if (sessionId) {
    await query('DELETE FROM sessions WHERE id = ?', [sessionId]).catch(() => {});
  }
  res.clearCookie('sessionId', { path: '/' });
}

module.exports = { sessionMiddleware, requireAuth, requireAdmin, createSession, destroySession };
