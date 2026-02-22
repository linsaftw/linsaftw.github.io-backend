// create-admin.js — One-time script to create an admin user
// Usage: node create-admin.js <username> <email> <password>
require('dotenv').config();

const bcrypt = require('bcryptjs');
const { query } = require('./db');

async function createAdmin() {
  const [,, username, email, password] = process.argv;

  if (!username || !email || !password) {
    console.error('Usage: node create-admin.js <username> <email> <password>');
    process.exit(1);
  }

  if (password.length < 8) {
    console.error('Password must be at least 8 characters');
    process.exit(1);
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    await query(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, \'admin\') ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), role=\'admin\'',
      [username, email, hash]
    );
    console.log(`✓ Admin user created: ${username} <${email}>`);
    console.log('  You can now log in at /login.html');
  } catch (err) {
    console.error('Error:', err.message);
  } finally {
    process.exit(0);
  }
}

createAdmin();
