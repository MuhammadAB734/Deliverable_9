-- Run after the existing members table is created. API also creates these on startup.
CREATE TABLE IF NOT EXISTS app_users (
 user_id BIGINT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(60) NOT NULL UNIQUE,
 password_hash VARCHAR(255) NOT NULL, role ENUM('ORGANIZER','MEMBER') NOT NULL,
 member_id INT NULL UNIQUE, account_status ENUM('ACTIVE','LOCKED','DISABLED') NOT NULL DEFAULT 'ACTIVE',
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT fk_app_user_member FOREIGN KEY (member_id) REFERENCES members(member_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS app_sessions (
 session_id BIGINT AUTO_INCREMENT PRIMARY KEY, user_id BIGINT NOT NULL,
 token_hash CHAR(64) NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP NULL,
 CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES app_users(user_id) ON DELETE CASCADE,
 INDEX idx_session_expiry (expires_at)
) ENGINE=InnoDB;
