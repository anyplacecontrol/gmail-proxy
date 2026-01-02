// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');

const app = express();
const PORT = 3001;

// ===== GOOGLE CONSOLE CREDENTIALS (use env vars) =====
const GOOGLE_CONFIG = {
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.REDIRECT_URI || 'http://localhost:3001/auth/callback',
  scopes: [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.email'
  ]
};

if (!GOOGLE_CONFIG.clientId || !GOOGLE_CONFIG.clientSecret) {
  console.error('ERROR: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set in .env file');
  process.exit(1);
}

// Session secret should come from env in production. Fallback only for local dev.
const SESSION_SECRET = process.env.SESSION_SECRET || ('dev-secret-' + Date.now());

app.use(cors({
  origin: true, // Allow any localhost origin
  credentials: true
}));

app.use(express.json());

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// ===== OAuth endpoints =====
app.get('/auth/login', (req, res) => {
  const returnTo = req.query.returnTo || req.headers.referer || 'http://localhost:3000';
  req.session.returnTo = returnTo;
  
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${GOOGLE_CONFIG.clientId}&` +
    `redirect_uri=${encodeURIComponent(GOOGLE_CONFIG.redirectUri)}&` +
    `response_type=code&` +
    `scope=${encodeURIComponent(GOOGLE_CONFIG.scopes.join(' '))}&` +
    `access_type=offline&` +
    `prompt=consent`;
  
  res.redirect(authUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send('Error: no authorization code provided');
  }

  // Debug: log what we're sending to Google
  console.log('Token exchange request:', {
    client_id: GOOGLE_CONFIG.clientId,
    redirect_uri: GOOGLE_CONFIG.redirectUri,
    code_length: code.length
  });

  try {
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: GOOGLE_CONFIG.clientId,
      client_secret: GOOGLE_CONFIG.clientSecret,
      redirect_uri: GOOGLE_CONFIG.redirectUri,
      grant_type: 'authorization_code'
    });

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    req.session.accessToken = access_token;
    req.session.refreshToken = refresh_token;
    req.session.tokenExpiry = Date.now() + (expires_in * 1000);

    // Retrieve user's email
    try {
      const userInfoResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${access_token}` }
      });
      req.session.userEmail = userInfoResponse.data.email;
    } catch (error) {
      console.error('Error retrieving email:', error);
    }

    const returnUrl = req.session.returnTo || 'http://localhost:3000';
    res.redirect(`${returnUrl}?auth=success`);
  } catch (error) {
    console.error('Error exchanging code for token:', error.response?.data || error.message);
    res.status(500).send('Authorization error');
  }
});

app.get('/auth/status', (req, res) => {
  const isAuthenticated = !!req.session.accessToken;
  res.json({ 
    authenticated: isAuthenticated,
    email: req.session.userEmail || null
  });
});

app.post('/auth/logout', async (req, res) => {
  const accessToken = req.session && req.session.accessToken;

  // Try to revoke token at Google (best-effort for testing)
  if (accessToken) {
    try {
      await axios.post(`https://oauth2.googleapis.com/revoke?token=${accessToken}`);
    } catch (err) {
      console.error('Token revoke failed:', err.response?.data || err.message);
      // continue — don't fail logout if revoke fails
    }
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Session destroy error:', err);
      return res.status(500).json({ success: false, error: 'Session destroy error' });
    }
    res.json({ success: true });
  });
});

// ===== Middleware: token verification =====
const ensureAuthenticated = async (req, res, next) => {
  if (!req.session.accessToken) {
    return res.status(401).json({ error: 'Not authorized' });
  }

  if (req.session.tokenExpiry && Date.now() >= req.session.tokenExpiry && req.session.refreshToken) {
    try {
      const refreshResponse = await axios.post('https://oauth2.googleapis.com/token', {
        refresh_token: req.session.refreshToken,
        client_id: GOOGLE_CONFIG.clientId,
        client_secret: GOOGLE_CONFIG.clientSecret,
        grant_type: 'refresh_token'
      });

      req.session.accessToken = refreshResponse.data.access_token;
      req.session.tokenExpiry = Date.now() + (refreshResponse.data.expires_in * 1000);
    } catch (error) {
      console.error('Error refreshing token:', error.response?.data);
      return res.status(401).json({ error: 'Token expired' });
    }
  }

  next();
};

// ===== Gmail API endpoints =====
app.get('/api/gmail/messages', ensureAuthenticated, async (req, res) => {
  try {
    const { q = 'is:unread', maxResults = 20, pageToken } = req.query;

    const response = await axios.get(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages`,
      {
        headers: { Authorization: `Bearer ${req.session.accessToken}` },
        params: { q, maxResults, pageToken }
      }
    );

    // If client requests expanded info, fetch metadata for each message
    const expand = req.query.expand !== 'false'; // Default to true unless expand=false
    console.log('Expand requested:', expand, 'Messages count:', response.data.messages?.length || 0);

    if (expand && Array.isArray(response.data.messages) && response.data.messages.length) {
      console.log('Fetching detailed metadata for messages...');
      const ids = response.data.messages.map(m => m.id);

      // Fetch metadata (From, Subject, Date) for each message in parallel
      const detailPromises = ids.map(id =>
        axios.get(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}`, {
          headers: { Authorization: `Bearer ${req.session.accessToken}` },
          params: { format: 'metadata', metadataHeaders: ['From', 'Subject', 'Date'] }
        }).then(r => r.data).catch(err => ({ id, error: err.response?.data || err.message }))
      );

      const details = await Promise.all(detailPromises);

      // Merge basic list response with details
      const enriched = response.data.messages.map(m => {
        const d = details.find(x => x.id === m.id) || {};
        const headers = (d.payload && d.payload.headers) || [];
        const get = name => (headers.find(h => h.name.toLowerCase() === name.toLowerCase()) || {}).value || null;

        return {
          id: m.id,
          threadId: m.threadId,
          snippet: d.snippet || m.snippet || null,
          from: get('From'),
          subject: get('Subject'),
          date: get('Date'),    
        };
      });

      return res.json({ messages: enriched, resultSizeEstimate: response.data.resultSizeEstimate });
    }

    res.json(response.data);
  } catch (error) {
    console.error('Error Gmail API:', error.response?.data);
    res.status(error.response?.status || 500).json({
      error: error.response?.data || 'Request error'
    });
  }
});

app.get('/api/gmail/messages/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    const { format = 'full' } = req.query;

    const response = await axios.get(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}`,
      {
        headers: { Authorization: `Bearer ${req.session.accessToken}` },
        params: { format }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('Error Gmail API:', error.response?.data);
    res.status(error.response?.status || 500).json({
      error: error.response?.data || 'Request error'
    });
  }
});

app.listen(PORT, () => {
  console.log(`\n🚀 Server running at http://localhost:${PORT}`);
  console.log(`📧 XMLUI app can run on any port\n`);
});
