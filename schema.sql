-- ============================================================================
-- Secure File Sharing System — Database Schema
-- Engine: MySQL 8.0+ / MariaDB 10.4+
-- ============================================================================

CREATE DATABASE IF NOT EXISTS secure_file_sharing
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE secure_file_sharing;

-- ----------------------------------------------------------------------------
-- users
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(50)  NOT NULL,
    email           VARCHAR(255) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            ENUM('user', 'moderator', 'admin') NOT NULL DEFAULT 'user',
    failed_logins   TINYINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until    DATETIME NULL DEFAULT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_username (username),
    UNIQUE KEY uniq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- files
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS files (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    original_name   VARCHAR(255) NOT NULL,
    stored_name     VARCHAR(255) NOT NULL,
    file_size       BIGINT UNSIGNED NOT NULL,
    mime_type       VARCHAR(127) NOT NULL,
    owner_id        INT UNSIGNED NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_stored_name (stored_name),
    KEY idx_owner (owner_id),
    CONSTRAINT fk_files_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- file_permissions
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_permissions (
    id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    file_id          INT UNSIGNED NOT NULL,
    user_id          INT UNSIGNED NOT NULL,
    permission_type  ENUM('viewer', 'editor') NOT NULL DEFAULT 'viewer',
    granted_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_file_user (file_id, user_id),
    KEY idx_user (user_id),
    CONSTRAINT fk_perm_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    CONSTRAINT fk_perm_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- audit_logs
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NULL,
    action      ENUM('UPLOAD','DOWNLOAD','SHARE','UNSHARE','DELETE','PERMISSION_CHANGE',
                      'LOGIN_SUCCESS','LOGIN_FAILURE','LOGOUT','REGISTER','ACCESS_DENIED')
                      NOT NULL,
    file_id     INT UNSIGNED NULL,
    ip_address  VARCHAR(45) NOT NULL,
    details     VARCHAR(500) NULL,
    timestamp   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_user (user_id),
    KEY idx_action (action),
    KEY idx_file (file_id),
    KEY idx_timestamp (timestamp),
    CONSTRAINT fk_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_log_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------------------
-- Optional: seed an initial admin account.
-- Password below is 'ChangeMe!123' hashed with password_hash() (bcrypt).
-- CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN.
-- ----------------------------------------------------------------------------
-- INSERT INTO users (username, email, password_hash, role)
-- VALUES ('admin', '[email protected]',
--         '$2y$12$k4qk8Zt0F0m2y8h1H2iM6uJt1z0m4o8h3X6f0Fq0m8sB2Q8bV1S7C', 'admin');
