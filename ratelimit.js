// ratelimit.js — In-memory rate limiter with per-IP and global limits
// Supports: max N actions per second globally, max 1 per IP persistently, 60s timeout on violation

const BLOCK_MS = parseInt(process.env.BLOCK_SECONDS_ON_VIOLATION || '60') * 1000;

// Structure: { ip -> { action -> { blockedUntil: Date, count: int, windowStart: Date } } }
const ipState = new Map();

// Global action counters: { action -> { count: int, windowStart: Date } }
const globalState = new Map();

function now() { return Date.now(); }

/**
 * Check and record a rate-limited action.
 * Returns { allowed: boolean, retryAfter: number (ms) }
 */
function check(ip, action, globalLimitPerSecond = 1) {
  const t = now();

  // --- Global limit ---
  if (!globalState.has(action)) {
    globalState.set(action, { count: 0, windowStart: t });
  }
  const gs = globalState.get(action);
  if (t - gs.windowStart > 1000) {
    gs.count = 0;
    gs.windowStart = t;
  }
  if (gs.count >= globalLimitPerSecond) {
    // Global limit hit — block this IP too
    blockIp(ip, action);
    return { allowed: false, retryAfter: 1000 - (t - gs.windowStart) };
  }

  // --- Per-IP limit ---
  if (!ipState.has(ip)) ipState.set(ip, new Map());
  const ipActions = ipState.get(ip);

  if (!ipActions.has(action)) {
    ipActions.set(action, { blockedUntil: null, count: 0, windowStart: t });
  }
  const ipData = ipActions.get(action);

  // Check if currently blocked
  if (ipData.blockedUntil && t < ipData.blockedUntil) {
    return { allowed: false, retryAfter: ipData.blockedUntil - t };
  }

  // Reset window if expired
  if (t - ipData.windowStart > 1000) {
    ipData.count = 0;
    ipData.windowStart = t;
  }

  // Per-IP: max 1 per second
  if (ipData.count >= 1) {
    blockIp(ip, action);
    return { allowed: false, retryAfter: BLOCK_MS };
  }

  // Allow
  ipData.count++;
  gs.count++;
  return { allowed: true, retryAfter: 0 };
}

function blockIp(ip, action) {
  if (!ipState.has(ip)) ipState.set(ip, new Map());
  const ipActions = ipState.get(ip);
  if (!ipActions.has(action)) {
    ipActions.set(action, { blockedUntil: null, count: 0, windowStart: Date.now() });
  }
  const ipData = ipActions.get(action);
  const until = Date.now() + BLOCK_MS;
  // Only extend block if not already blocked longer
  if (!ipData.blockedUntil || until > ipData.blockedUntil) {
    ipData.blockedUntil = until;
  }
}

function isBlocked(ip, action) {
  if (!ipState.has(ip)) return false;
  const ipActions = ipState.get(ip);
  if (!ipActions.has(action)) return false;
  const d = ipActions.get(action);
  if (d.blockedUntil && Date.now() < d.blockedUntil) {
    return { blocked: true, retryAfter: d.blockedUntil - Date.now() };
  }
  return false;
}

/**
 * Express middleware factory
 */
function rateLimitMiddleware(action, globalLimitPerSecond = 1) {
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const result = check(ip, action, globalLimitPerSecond);
    if (!result.allowed) {
      return res.status(429).json({
        error: `Too many requests. Retry after ${Math.ceil(result.retryAfter / 1000)}s.`,
        retryAfter: result.retryAfter,
      });
    }
    next();
  };
}

// Clean up old entries periodically
setInterval(() => {
  const t = Date.now();
  for (const [ip, actions] of ipState.entries()) {
    for (const [action, data] of actions.entries()) {
      // Remove entries that are not blocked and window is old (> 10 min)
      if ((!data.blockedUntil || t > data.blockedUntil) && t - data.windowStart > 600000) {
        actions.delete(action);
      }
    }
    if (actions.size === 0) ipState.delete(ip);
  }
}, 60000);

module.exports = { check, blockIp, isBlocked, rateLimitMiddleware };
