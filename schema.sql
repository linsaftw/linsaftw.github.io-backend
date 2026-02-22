-- ======= LinsaFTW Blog — Database Schema =======
-- Run: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS `db`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `db`;

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('user', 'admin') DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- SESSIONS
CREATE TABLE IF NOT EXISTS sessions (
  id CHAR(64) PRIMARY KEY,
  user_id INT NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- POSTS
CREATE TABLE IF NOT EXISTS posts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  author_id INT,
  title VARCHAR(255) NOT NULL,
  caption VARCHAR(512) DEFAULT NULL,
  image_path VARCHAR(512) DEFAULT NULL,
  content_markdown LONGTEXT NOT NULL,
  visibility ENUM('public', 'private') DEFAULT 'public',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  timezone VARCHAR(64) DEFAULT 'America/Argentina/Buenos_Aires',
  FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- POST EDIT HISTORY
CREATE TABLE IF NOT EXISTS post_edits (
  id INT AUTO_INCREMENT PRIMARY KEY,
  post_id INT NOT NULL,
  editor_id INT,
  old_content LONGTEXT,
  new_content LONGTEXT,
  old_title VARCHAR(255),
  new_title VARCHAR(255),
  edit_message VARCHAR(255),
  edited_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (editor_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- RATE LIMITS (persistent blocked IPs)
CREATE TABLE IF NOT EXISTS rate_limits (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip VARCHAR(45) NOT NULL,
  action VARCHAR(64) NOT NULL,
  blocked_until DATETIME DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_ip_action (ip, action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ======= INITIAL ADMIN USER =======
-- Password: change_me_please (bcrypt hash — you MUST change this)
-- To create: run `node create-admin.js` after setup
-- INSERT INTO users (username, email, password_hash, role) VALUES
-- ('LinsaFTW', 'your@email.com', '$2a$12$...', 'admin');
