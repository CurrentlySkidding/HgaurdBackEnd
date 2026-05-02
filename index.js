
import express from 'express';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper: Get device fingerprint from request
const getDeviceId = (req) => {
  // Use IP + User-Agent as simple fingerprint (for demo)
  // In production, use a proper fingerprinting library
  return req.headers['user-agent'] + '|' + req.ip;
};

// Middleware: Verify JWT & session
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const deviceId = getDeviceId(req);

    // Check session exists and matches device
    const result = await pool.query(
      `SELECT s.*, u.expires_at, u.username 
       FROM sessions s 
       JOIN users u ON s.user_id = u.id 
       WHERE s.token = $1 AND s.device_id = $2 AND u.expires_at > NOW()`,
      [token, deviceId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid session or wrong device' });
    }

    // Update last_seen
    await pool.query('UPDATE sessions SET last_seen = NOW() WHERE token = $1', [token]);
    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// REGISTER
app.post('/register', async (req, res) => {
  const { username, password, expires_in_days } = req.body;

  if (!username || !password || !expires_in_days) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expires_in_days);
  const hashed = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      'INSERT INTO users (username, password_hash, expires_at) VALUES ($1, $2, $3)',
      [username, hashed, expiresAt]
    );
    res.json({ message: 'User created', expires_at: expiresAt });
  } catch (err) {
    if (err.code === '23505') res.status(400).json({ error: 'Username exists' });
    else res.status(500).json({ error: err.message });
  }
});

// LOGIN
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const deviceId = getDeviceId(req);

  try {
    // Get user
    const userRes = await pool.query(
      'SELECT * FROM users WHERE username = $1 AND expires_at > NOW()',
      [username]
    );
    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired user' });
    }
    const user = userRes.rows[0];

    // Check password
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Wrong password' });

    // Check cooldown for NEW devices only
    const existingSession = await pool.query(
      'SELECT device_id FROM sessions WHERE user_id = $1 AND device_id = $2',
      [user.id, deviceId]
    );

    const isSameDevice = existingSession.rows.length > 0;

    if (!isSameDevice) {
      // Check if user logged out in last 30 mins from another device
      const logoutCheck = await pool.query(
        `SELECT logged_out_at FROM logout_log 
         WHERE user_id = $1 AND logged_out_at > NOW() - INTERVAL '30 minutes'
         ORDER BY logged_out_at DESC LIMIT 1`,
        [user.id]
      );

      if (logoutCheck.rows.length > 0) {
        return res.status(403).json({ 
          error: 'Must wait 30 minutes after logout before using a new device' 
        });
      }

      // Count active devices (unique device_ids)
      const activeDevices = await pool.query(
        'SELECT COUNT(DISTINCT device_id) FROM sessions WHERE user_id = $1',
        [user.id]
      );
      if (parseInt(activeDevices.rows[0].count) >= 2) {
        return res.status(403).json({ error: 'Max 2 devices allowed' });
      }
    }

    // Generate token
    const token = jwt.sign(
      { userId: user.id, username: user.username, deviceId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Upsert session
    await pool.query(
      `INSERT INTO sessions (user_id, device_id, token) 
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, device_id) 
       DO UPDATE SET token = $3, last_seen = NOW()`,
      [user.id, deviceId, token]
    );

    res.json({ 
      token, 
      expires_at: user.expires_at,
      username: user.username 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LOGOUT
app.post('/logout', authMiddleware, async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  // Log the logout time for cooldown
  await pool.query(
    'INSERT INTO logout_log (user_id) VALUES ($1)',
    [req.user.user_id]
  );
  
  // Remove session
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  
  res.json({ message: 'Logged out. New devices blocked for 30 mins.' });
});

// CHECK STATUS
app.get('/me', authMiddleware, async (req, res) => {
  res.json({
    username: req.user.username,
    expires_at: req.user.expires_at,
    device_id: getDeviceId(req)
  });
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
