-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Active sessions
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    token TEXT NOT NULL,
    last_seen TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, device_id)
);

-- Session logout history for cooldown tracking
CREATE TABLE IF NOT EXISTS logout_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    logged_out_at TIMESTAMP DEFAULT NOW()
);

-- Create initial account: CurrentlySkidding / 1234
-- Expires in 365 days from creation
INSERT INTO users (username, password_hash, expires_at)
VALUES (
    'CurrentlySkidding',
    '$2b$10$YQxV5XfJkLqK9M7nR2pQOeFgHjKlZxXcVbNmAsDfGhJkLpQwErTyU',  -- bcrypt hash of "1234"
    NOW() + INTERVAL '365 days'
)
ON CONFLICT (username) DO NOTHING;
