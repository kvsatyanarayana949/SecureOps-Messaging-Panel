-- =========================
-- RESET (DEV ONLY)
-- =========================
DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;

-- =========================
-- USERS TABLE
-- =========================
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,

    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,

    role ENUM('user','admin') DEFAULT 'user',
    is_banned BOOLEAN DEFAULT FALSE,
    is_deleted BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP NULL,
    last_login_ip VARCHAR(100) NULL

) ENGINE=InnoDB;

-- =========================
-- MESSAGES TABLE
-- =========================
CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,

    message TEXT NOT NULL,
    sender_id INT NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sender
        FOREIGN KEY (sender_id)
        REFERENCES users(id)
        ON DELETE CASCADE

) ENGINE=InnoDB;

-- =========================
-- LOGS TABLE (AUDIT)
-- =========================
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,

    event_type VARCHAR(100),
    user_id INT NULL,
    username VARCHAR(100),
    ip_address VARCHAR(100),
    status VARCHAR(50),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_log_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL

) ENGINE=InnoDB;

-- =========================
-- INDEXES (PERFORMANCE)
-- =========================

-- USERS
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_banned ON users(is_banned);

-- MESSAGES
CREATE INDEX idx_messages_id_desc ON messages(id DESC);
CREATE INDEX idx_messages_sender_id ON messages(sender_id);
CREATE INDEX idx_messages_sender_created ON messages(sender_id, created_at);

-- LOGS
CREATE INDEX idx_logs_created_at ON logs(created_at);
CREATE INDEX idx_logs_user_id ON logs(user_id);
