require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const https = require('https');
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
const axios = require('axios');

const app = express();
const db = new Database('data.db');

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    intra_id INTEGER UNIQUE NOT NULL,
    email TEXT NOT NULL,
    access_token TEXT,
    campus_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    keyword TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS processed_events (
    event_id INTEGER PRIMARY KEY,
    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // only require HTTPS in production
    httpOnly: true, 
    maxAge: 24 * 60 * 60 * 1000 
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Configure 42 OAuth
passport.use('42', new OAuth2Strategy({
    authorizationURL: 'https://api.intra.42.fr/oauth/authorize',
    tokenURL: 'https://api.intra.42.fr/oauth/token',
    clientID: process.env.FORTYTWO_CLIENT_ID,
    clientSecret: process.env.FORTYTWO_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || 'http://localhost:8000/auth/callback',
    scope: ['public']
  },
  async (accessToken, refreshToken, profile, cb) => {
    try {
      // Get user info from 42 API
      const response = await axios.get('https://api.intra.42.fr/v2/me', {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      
      const userData = response.data;
      const email = userData.email;
      const intraId = userData.id;
      const campusId = userData.campus_users?.[0]?.campus_id || null;

      // Insert or update user
      await dbRun(`
        INSERT INTO users (intra_id, email, access_token, campus_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(intra_id) DO UPDATE SET
          email = excluded.email,
          access_token = excluded.access_token,
          campus_id = excluded.campus_id
      `, [intraId, email, accessToken, campusId]);

      const user = await dbGet('SELECT * FROM users WHERE intra_id = ?', [intraId]);
      
      // Send notification email to host about new user registration
      try {
        await transporter.sendMail({
          from: process.env.GMAIL_USER,
          to: process.env.GMAIL_USER,
          subject: 'New User Registration - 42 Event Notifier',
          html: `
            <h2>New User Registered</h2>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Intra ID:</strong> ${intraId}</p>
            <p><strong>Campus ID:</strong> ${campusId || 'N/A'}</p>
            <p><strong>Registration Time:</strong> ${new Date().toLocaleString()}</p>
          `
        });
        console.log(`Sent registration notification for new user: ${email}`);
      } catch (error) {
        console.error('Failed to send registration notification:', error.message);
      }
      
      return cb(null, user);
    } catch (error) {
      return cb(error);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

// Routes
app.get('/auth/42', passport.authenticate('42'));

app.get('/auth/callback',
  passport.authenticate('42', { failureRedirect: '/' }),
  (req, res) => res.redirect('/dashboard')
);

app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.get('/api/user', isAuthenticated, async (req, res) => {
  try {
    const keywords = await dbAll('SELECT * FROM keywords WHERE user_id = ?', [req.user.id]);
    res.json({
      email: req.user.email,
      keywords: keywords.map(k => ({ id: k.id, keyword: k.keyword }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/keywords', isAuthenticated, async (req, res) => {
  const { keyword } = req.body;
  if (!keyword || keyword.trim().length === 0) {
    return res.status(400).json({ error: 'Keyword cannot be empty' });
  }

  try {
    const result = await dbRun('INSERT INTO keywords (user_id, keyword) VALUES (?, ?)', 
      [req.user.id, keyword.trim().toLowerCase()]);
    res.json({ id: result.lastID, keyword: keyword.trim().toLowerCase() });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/keywords/:id', isAuthenticated, async (req, res) => {
  try {
    await dbRun('DELETE FROM keywords WHERE id = ? AND user_id = ?', 
      [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Event checking function
async function checkForNewEvents() {
  console.log('Checking for new events...');
  
  try {
    // Get a valid access token from any user
    const user = await dbGet('SELECT access_token FROM users LIMIT 1');
    if (!user) {
      console.log('No users registered yet');
      return;
    }

    // Fetch recent events from 42 API
    const now = new Date();
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    
    const response = await axios.get('https://api.intra.42.fr/v2/events', {
      headers: { Authorization: `Bearer ${user.access_token}` },
      params: {
        'filter[campus_id]': '', // Remove campus filter to get all events
        'filter[future]': true,   // Only future events
        'page[size]': 100,
        'page[number]': 1
      }
    });

    const events = response.data;

    for (const event of events) {
      // Check if event already processed
      const processed = await dbGet('SELECT 1 FROM processed_events WHERE event_id = ?', [event.id]);
      if (processed) continue;

      // Mark as processed
      await dbRun('INSERT INTO processed_events (event_id) VALUES (?)', [event.id]);

      const eventText = `${event.name} ${event.description || ''}`.toLowerCase();
      const eventCampusId = event.campus_ids?.[0] || null;

      // Get all keywords to check against this event
      const allKeywords = await dbAll('SELECT DISTINCT keyword FROM keywords');
      
      // Track which users to notify (user_id -> list of matched keywords)
      const usersToNotify = new Map();

      for (const { keyword } of allKeywords) {
        // Check if keyword matches the event text (case-insensitive partial match)
        if (eventText.includes(keyword.toLowerCase())) {
          // Find all users with this keyword and matching campus
          const users = await dbAll(`
            SELECT DISTINCT u.id, u.email, u.campus_id
            FROM users u
            JOIN keywords k ON u.id = k.user_id
            WHERE k.keyword = ?
            AND (u.campus_id = ? OR ? IS NULL)
          `, [keyword, eventCampusId, eventCampusId]);
          
          for (const user of users) {
            if (!usersToNotify.has(user.id)) {
              usersToNotify.set(user.id, {
                email: user.email,
                keywords: []
              });
            }
            usersToNotify.get(user.id).keywords.push(keyword);
          }
        }
      }

      // Send emails to all matching users
      for (const [userId, { email, keywords }] of usersToNotify) {
        try {
          await transporter.sendMail({
            from: process.env.GMAIL_USER,
            to: email,
            subject: `New 42 Event: ${event.name}`,
            html: `
              <h2>${event.name}</h2>
              <p><strong>When:</strong> ${new Date(event.begin_at).toLocaleString()}</p>
              <p><strong>Location:</strong> ${event.location || 'TBD'}</p>
              <p><strong>Description:</strong></p>
              <p>${event.description || 'No description'}</p>
              <p><a href="https://profile.intra.42.fr/events/${event.id}">View on Intra</a></p>
              <hr>
              <small>You received this because your keyword(s) "${keywords.join('", "')}" matched this event.</small>
            `
          });
          console.log(`Sent notification to ${email} for event: ${event.name} (matched keywords: ${keywords.join(', ')})`);
        } catch (error) {
          console.error(`Failed to send email to ${email}:`, error.message);
        }
      }
    }
  } catch (error) {
    console.error('Error checking events:', error.message);
  }
}

// Schedule event checking every 10 seconds
cron.schedule('*/10 * * * * *', checkForNewEvents);

// HTML routes
app.get('/', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start server (HTTP for development, HTTPS for production)
const PORT = process.env.PORT || 8000;

if (process.env.NODE_ENV === 'production') {
  const httpsOptions = {
    key: fs.readFileSync(process.env.SSL_KEY_PATH || './cert/privkey.pem'),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH || './cert/fullchain.pem')
  };
  
  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`Server running on https://localhost:${PORT}`);
    console.log('Event checking scheduled every 10 seconds');
  });
} else {
  // Development mode - use HTTP
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Event checking scheduled every 10 seconds');
    console.log('Running in development mode (HTTP)');
  });
}