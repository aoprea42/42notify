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
const initSqlJs = require('sql.js');
const axios = require('axios');

const app = express();
let db;

// Initialize SQL.js database
async function initDatabase() {
  const SQL = await initSqlJs();
  
  // Try to load existing database
  let buffer;
  try {
    buffer = fs.readFileSync('data.db');
  } catch (err) {
    // Database doesn't exist yet
    buffer = null;
  }
  
  db = new SQL.Database(buffer);
  
  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      intra_id INTEGER UNIQUE NOT NULL,
      email TEXT NOT NULL,
      access_token TEXT,
      campus_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS keywords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      keyword TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS processed_events (
      event_id INTEGER PRIMARY KEY,
      processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  // Save database periodically
  setInterval(saveDatabase, 5000);
}

function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync('data.db', buffer);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
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
      db.run(`
        INSERT INTO users (intra_id, email, access_token, campus_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(intra_id) DO UPDATE SET
          email = excluded.email,
          access_token = excluded.access_token,
          campus_id = excluded.campus_id
      `, [intraId, email, accessToken, campusId]);
      
      saveDatabase();

      const result = db.exec('SELECT * FROM users WHERE intra_id = ?', [intraId]);
      const user = result[0] ? {
        id: result[0].values[0][0],
        intra_id: result[0].values[0][1],
        email: result[0].values[0][2],
        access_token: result[0].values[0][3],
        campus_id: result[0].values[0][4]
      } : null;
      
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
passport.deserializeUser((id, done) => {
  try {
    const result = db.exec('SELECT * FROM users WHERE id = ?', [id]);
    if (result[0]) {
      const user = {
        id: result[0].values[0][0],
        intra_id: result[0].values[0][1],
        email: result[0].values[0][2],
        access_token: result[0].values[0][3],
        campus_id: result[0].values[0][4]
      };
      done(null, user);
    } else {
      done(null, null);
    }
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

app.get('/api/user', isAuthenticated, (req, res) => {
  try {
    const result = db.exec('SELECT * FROM keywords WHERE user_id = ?', [req.user.id]);
    const keywords = result[0] ? result[0].values.map(row => ({
      id: row[0],
      keyword: row[2]
    })) : [];
    
    res.json({
      email: req.user.email,
      keywords
    });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/keywords', isAuthenticated, (req, res) => {
  const { keyword } = req.body;
  if (!keyword || keyword.trim().length === 0) {
    return res.status(400).json({ error: 'Keyword cannot be empty' });
  }

  try {
    db.run('INSERT INTO keywords (user_id, keyword) VALUES (?, ?)', 
      [req.user.id, keyword.trim().toLowerCase()]);
    saveDatabase();
    
    const result = db.exec('SELECT last_insert_rowid()');
    const id = result[0].values[0][0];
    
    res.json({ id, keyword: keyword.trim().toLowerCase() });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/keywords/:id', isAuthenticated, (req, res) => {
  try {
    db.run('DELETE FROM keywords WHERE id = ? AND user_id = ?', 
      [req.params.id, req.user.id]);
    saveDatabase();
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
    const userResult = db.exec('SELECT access_token FROM users LIMIT 1');
    if (!userResult[0]) {
      console.log('No users registered yet');
      return;
    }
    const accessToken = userResult[0].values[0][0];

    // Fetch recent events from 42 API
    const response = await axios.get('https://api.intra.42.fr/v2/events', {
      headers: { Authorization: `Bearer ${accessToken}` },
      params: {
        'filter[campus_id]': '',
        'filter[future]': true,
        'page[size]': 100,
        'page[number]': 1
      }
    });

    const events = response.data;

    for (const event of events) {
      // Check if event already processed
      const processedResult = db.exec('SELECT 1 FROM processed_events WHERE event_id = ?', [event.id]);
      if (processedResult[0]) continue;

      // Mark as processed
      db.run('INSERT INTO processed_events (event_id) VALUES (?)', [event.id]);
      saveDatabase();

      const eventText = `${event.name} ${event.description || ''}`.toLowerCase();
      const eventCampusId = event.campus_ids?.[0] || null;

      // Get all keywords
      const keywordsResult = db.exec('SELECT DISTINCT keyword FROM keywords');
      const allKeywords = keywordsResult[0] ? keywordsResult[0].values.map(row => row[0]) : [];
      
      // Track which users to notify
      const usersToNotify = new Map();

      for (const keyword of allKeywords) {
        // Check if keyword matches the event text
        if (eventText.includes(keyword.toLowerCase())) {
          // Find all users with this keyword and matching campus
          const usersResult = db.exec(`
            SELECT DISTINCT u.id, u.email, u.campus_id
            FROM users u
            JOIN keywords k ON u.id = k.user_id
            WHERE k.keyword = ?
            AND (u.campus_id = ? OR ? IS NULL)
          `, [keyword, eventCampusId, eventCampusId]);
          
          if (usersResult[0]) {
            for (const row of usersResult[0].values) {
              const userId = row[0];
              const userEmail = row[1];
              
              if (!usersToNotify.has(userId)) {
                usersToNotify.set(userId, {
                  email: userEmail,
                  keywords: []
                });
              }
              usersToNotify.get(userId).keywords.push(keyword);
            }
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

initDatabase().then(() => {
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
});