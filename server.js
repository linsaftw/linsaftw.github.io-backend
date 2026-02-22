// server.js — LinsaFTW Blog Backend
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const http = require('http');
const WebSocket = require('ws');
const { query, queryOne } = require('./db');
const { sessionMiddleware, requireAuth, requireAdmin, createSession, destroySession } = require('./auth');
const { rateLimitMiddleware } = require('./ratelimit');

// ===== APP SETUP =====
const app = express();
const server = http.createServer(app);

app.set('trust proxy', 1);

app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:4000',
  credentials: true,
}));

app.use(express.json({ limit: '5mb' }));

// Simple cookie parser (no dependency)
app.use((req, res, next) => {
  req.cookies = {};
  const raw = req.headers.cookie;
  if (raw) {
    raw.split(';').forEach(pair => {
      const [k, ...v] = pair.trim().split('=');
      if (k) req.cookies[k.trim()] = decodeURIComponent(v.join('='));
    });
  }
  next();
});

app.use(sessionMiddleware);

// ===== AUTH ROUTES =====

// POST /api/auth/register
app.post('/api/auth/register',
  rateLimitMiddleware('register', parseInt(process.env.RATE_LIMIT_REGISTER_PER_SECOND || '1')),
  async (req, res) => {
    try {
      const { username, email, password } = req.body;
      if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email and password are required.' });
      }
      if (username.length < 3 || username.length > 50) {
        return res.status(400).json({ error: 'Username must be 3–50 characters.' });
      }
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters.' });
      }

      // Check existing
      const existing = await queryOne(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        [username, email]
      );
      if (existing) {
        return res.status(409).json({ error: 'Username or email already taken.' });
      }

      const hash = await bcrypt.hash(password, 12);
      const result = await query(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
        [username, email, hash]
      );

      const userId = result.insertId;
      await createSession(res, userId);

      console.log(`[register] New user: ${username} <${email}>`);
      return res.status(201).json({ message: 'Registered successfully.' });
    } catch (err) {
      console.error('[register]', err.message);
      return res.status(500).json({ error: 'Server error.' });
    }
  }
);

// POST /api/auth/login
app.post('/api/auth/login',
  rateLimitMiddleware('login', parseInt(process.env.RATE_LIMIT_LOGIN_PER_SECOND || '1')),
  async (req, res) => {
    try {
      const { usernameOrEmail, password } = req.body;
      if (!usernameOrEmail || !password) {
        return res.status(400).json({ error: 'Username/email and password required.' });
      }

      const user = await queryOne(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [usernameOrEmail, usernameOrEmail]
      );
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials.' });
      }

      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid credentials.' });
      }

      await createSession(res, user.id);
      console.log(`[login] ${user.username}`);
      return res.json({ message: 'Logged in.', user: { id: user.id, username: user.username, role: user.role } });
    } catch (err) {
      console.error('[login]', err.message);
      return res.status(500).json({ error: 'Server error.' });
    }
  }
);

// POST /api/auth/logout
app.post('/api/auth/logout', async (req, res) => {
  await destroySession(req, res);
  return res.json({ message: 'Logged out.' });
});

// GET /api/auth/me
app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated.' });
  return res.json({ user: req.user });
});

// ===== POST ROUTES =====

// GET /api/posts
app.get('/api/posts', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 20;
    const offset = (page - 1) * limit;

    let visibilityFilter = "visibility = 'public'";
    if (req.user && (req.query.visibility === 'all')) {
      visibilityFilter = '1=1'; // Show all to logged in users
    }

    const posts = await query(
      `SELECT id, author_id, title, caption, image_path, visibility, created_at, updated_at,
       SUBSTRING(content_markdown, 1, 200) as excerpt
       FROM posts WHERE ${visibilityFilter}
       ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    return res.json({ posts });
  } catch (err) {
    console.error('[posts list]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/posts/:id
app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await queryOne('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (!post) return res.status(404).json({ error: 'Post not found.' });

    // Private posts only visible to authenticated users
    if (post.visibility === 'private' && !req.user) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    // Fetch edit history
    const edits = await query(
      'SELECT pe.*, u.username as editor_username FROM post_edits pe LEFT JOIN users u ON u.id = pe.editor_id WHERE pe.post_id = ? ORDER BY pe.edited_at DESC',
      [post.id]
    );

    return res.json({ post, edits });
  } catch (err) {
    console.error('[post get]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/posts (create)
app.post('/api/posts', requireAuth, async (req, res) => {
  try {
    const { title, caption, image_path, content_markdown, visibility } = req.body;
    if (!title || !content_markdown) {
      return res.status(400).json({ error: 'Title and content are required.' });
    }

    const vis = visibility === 'private' ? 'private' : 'public';
    const result = await query(
      'INSERT INTO posts (author_id, title, caption, image_path, content_markdown, visibility) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, title, caption || null, image_path || null, content_markdown, vis]
    );

    console.log(`[post create] id=${result.insertId} by ${req.user.username}`);
    return res.status(201).json({ post: { id: result.insertId } });
  } catch (err) {
    console.error('[post create]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// PUT /api/posts/:id (update)
app.put('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const post = await queryOne('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (!post) return res.status(404).json({ error: 'Post not found.' });

    // Only author or admin can edit
    if (post.author_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden.' });
    }

    const { title, caption, image_path, content_markdown, visibility, edit_message } = req.body;

    // Save edit history
    await query(
      'INSERT INTO post_edits (post_id, editor_id, old_content, new_content, old_title, new_title, edit_message) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [post.id, req.user.id, post.content_markdown, content_markdown, post.title, title, edit_message || null]
    );

    const vis = visibility === 'private' ? 'private' : 'public';
    await query(
      'UPDATE posts SET title=?, caption=?, image_path=?, content_markdown=?, visibility=?, updated_at=NOW() WHERE id=?',
      [title || post.title, caption ?? post.caption, image_path ?? post.image_path, content_markdown || post.content_markdown, vis, post.id]
    );

    console.log(`[post update] id=${post.id} by ${req.user.username}`);
    return res.json({ message: 'Post updated.' });
  } catch (err) {
    console.error('[post update]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// DELETE /api/posts/:id
app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    const post = await queryOne('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (!post) return res.status(404).json({ error: 'Post not found.' });

    if (post.author_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden.' });
    }

    await query('DELETE FROM posts WHERE id = ?', [post.id]);
    console.log(`[post delete] id=${post.id} by ${req.user.username}`);
    return res.json({ message: 'Post deleted.' });
  } catch (err) {
    console.error('[post delete]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// PATCH /api/posts/:id/visibility
app.patch('/api/posts/:id/visibility', requireAuth, async (req, res) => {
  try {
    const post = await queryOne('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (!post) return res.status(404).json({ error: 'Post not found.' });

    if (post.author_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden.' });
    }

    const vis = req.body.visibility === 'private' ? 'private' : 'public';
    await query('UPDATE posts SET visibility=? WHERE id=?', [vis, post.id]);
    return res.json({ message: 'Visibility updated.', visibility: vis });
  } catch (err) {
    console.error('[visibility]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ===== ADMIN ROUTES =====

// GET /api/admin/users
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await query(
      'SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 200'
    );
    return res.json({ users });
  } catch (err) {
    console.error('[admin users]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ===== WEBSOCKET ADMIN TERMINAL =====
const wss = new WebSocket.Server({ server, path: '/ws/admin/terminal' });

const ALLOWED_TERMINAL_IPS = (process.env.TERMINAL_ALLOWED_IPS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

// Safe built-in commands (no shell execution of arbitrary commands)
const TERMINAL_COMMANDS = {
  help: async () => [
    '// LinsaFTW Blog Backend Terminal',
    'Available commands:',
    '  users          - List latest registered users',
    '  posts          - List latest posts',
    '  status         - Server status',
    '  clear          - Clear terminal',
    '  help           - Show this help',
    '  block <ip>     - Manually block an IP',
    '  unblock <ip>   - Unblock an IP',
  ].join('\n'),

  status: async () => {
    const userCount = await queryOne('SELECT COUNT(*) as c FROM users');
    const postCount = await queryOne('SELECT COUNT(*) as c FROM posts');
    const sessionCount = await queryOne('SELECT COUNT(*) as c FROM sessions WHERE expires_at > NOW()');
    return [
      `// Server Status — ${new Date().toISOString()}`,
      `Users:    ${userCount.c}`,
      `Posts:    ${postCount.c}`,
      `Sessions: ${sessionCount.c} active`,
      `Uptime:   ${Math.floor(process.uptime())}s`,
      `Memory:   ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
    ].join('\n');
  },

  users: async () => {
    const users = await query('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 20');
    if (!users.length) return 'No users registered.';
    return users.map(u => `[${u.id}] ${u.username} <${u.email}> (${u.role}) — ${u.created_at}`).join('\n');
  },

  posts: async () => {
    const posts = await query('SELECT id, title, visibility, created_at FROM posts ORDER BY created_at DESC LIMIT 20');
    if (!posts.length) return 'No posts.';
    return posts.map(p => `[${p.id}] [${p.visibility}] ${p.title} — ${p.created_at}`).join('\n');
  },
};

wss.on('connection', async (ws, req) => {
  // Auth check — parse cookie
  const cookieHeader = req.headers['cookie'] || '';
  const cookies = {};
  cookieHeader.split(';').forEach(pair => {
    const [k, ...v] = pair.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('='));
  });

  const sessionId = cookies['sessionId'];
  if (!sessionId) {
    ws.send('ERROR: Not authenticated.');
    ws.close();
    return;
  }

  const session = await queryOne(
    'SELECT s.*, u.id as uid, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > NOW()',
    [sessionId]
  ).catch(() => null);

  if (!session || session.role !== 'admin') {
    ws.send('ERROR: Admin access required.');
    ws.close();
    return;
  }

  const ip = req.socket.remoteAddress;
  if (ALLOWED_TERMINAL_IPS.length > 0 && !ALLOWED_TERMINAL_IPS.includes(ip)) {
    ws.send(`ERROR: IP ${ip} not allowed to access terminal.`);
    ws.close();
    return;
  }

  ws.send(`// Connected as ${session.username} — type 'help' for commands`);

  ws.on('message', async raw => {
    let parsed;
    try { parsed = JSON.parse(raw); } catch { parsed = { cmd: String(raw) }; }

    const cmdLine = (parsed.cmd || '').trim();
    const [cmdName, ...args] = cmdLine.split(/\s+/);

    if (!cmdName) return;

    if (cmdName === 'clear') {
      ws.send('\x1Bc');
      return;
    }

    if (TERMINAL_COMMANDS[cmdName]) {
      try {
        const output = await TERMINAL_COMMANDS[cmdName](args);
        ws.send(Array.isArray(output) ? output.join('\n') : output);
      } catch (err) {
        ws.send(`ERROR: ${err.message}`);
      }
      return;
    }

    // block / unblock helpers
    if (cmdName === 'block') {
      const ip = args[0];
      if (!ip) { ws.send('Usage: block <ip>'); return; }
      const { blockIp } = require('./ratelimit');
      blockIp(ip, 'register');
      blockIp(ip, 'login');
      ws.send(`Blocked IP: ${ip} for 60s`);
      return;
    }

    ws.send(`Unknown command: ${cmdName}. Type 'help' for available commands.`);
  });

  ws.on('error', err => console.error('[ws terminal]', err.message));
});

// ===== START =====
const PORT = parseInt(process.env.PORT || '3000');
server.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║  LinsaFTW Blog Backend               ║
  ║  Running on port ${PORT}               ║
  ╚══════════════════════════════════════╝
  `);
  console.log(`API:      http://localhost:${PORT}/api`);
  console.log(`Terminal: ws://localhost:${PORT}/ws/admin/terminal`);
});

// ===== ADMIN CONSOLE (local terminal via stdin) =====
if (process.stdin.isTTY) {
  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'blog> ' });
  rl.prompt();
  rl.on('line', async line => {
    const cmd = line.trim();
    const [name, ...args] = cmd.split(/\s+/);
    if (TERMINAL_COMMANDS[name]) {
      try {
        console.log(await TERMINAL_COMMANDS[name](args));
      } catch (e) {
        console.error('Error:', e.message);
      }
    } else if (name === 'exit' || name === 'quit') {
      process.exit(0);
    } else if (name) {
      console.log(`Unknown command: ${name}. Commands: ${Object.keys(TERMINAL_COMMANDS).join(', ')}, exit`);
    }
    rl.prompt();
  });
}
