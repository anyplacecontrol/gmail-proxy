// server.js
const express = require('express');
// Load local .env into process.env (dev only) - kept out of git
try { require('dotenv').config(); } catch (e) { /* dotenv may be absent in some environments */ }
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
SESSION_SECRET=`f3c7e9a2b5d4c6e1f8a9b0c3d2e1f4a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2`

const app = express();
const PORT = 3001;

REDIRECT_URI=`http://localhost:${PORT}/auth/callback`

// ===== GOOGLE CONSOLE CREDENTIALS (load from env) =====
// IMPORTANT: set these in your local .env (development) or environment.
const GOOGLE_CONFIG = {
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
  scopes: [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.email'
  ]
};


// Single-user global auth storage (WARNING: NOT SECURE, dev/testing only)
// This allows client to make API requests without any auth headers
let globalAuth = null;

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
    httpOnly: true,
    sameSite: 'lax', // Allow cookies on redirects from Google
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Debug middleware - log session state
app.use((req, res, next) => {
  if (req.path.includes('/auth')) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`, {
      sessionID: req.sessionID,
      hasAccessToken: !!globalAuth?.accessToken,
      userEmail: globalAuth?.userEmail
    });
  }
  next();
});

// ===== OAuth endpoints =====
app.get('/auth/login', (req, res) => {
  const returnTo = req.query.returnTo || req.headers.referer ;
  if (!returnTo) {
    return res.status(400).send('Error: returnTo URL is required');
  }
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

    // Store tokens globally (single-user mode - no client auth required)
    globalAuth = {
      accessToken: access_token,
      refreshToken: refresh_token,
      tokenExpiry: Date.now() + (expires_in * 1000),
      userEmail: null
    };

    // Retrieve user's email
    try {
      const userInfoResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${access_token}` }
      });
      globalAuth.userEmail = userInfoResponse.data.email;
    } catch (error) {
      console.error('Error retrieving email:', error);
    }

    const returnUrl = req.session.returnTo ;
    if (!returnUrl) {
      return res.status(400).send('Error: no return URL in session');
    }
    res.redirect(`${returnUrl}?auth=success`);
  } catch (error) {
    console.error('Error exchanging code for token:', error.response?.data || error.message);
    res.status(500).send('Authorization error');
  }
});

app.get('/auth/status', (req, res) => {
  const isAuthenticated = !!globalAuth && !!globalAuth.accessToken;
  res.json({ 
    authenticated: isAuthenticated,
    email: globalAuth?.userEmail || null
  });
});

app.post('/auth/logout', async (req, res) => {
  // Don't revoke token - Google seems to lose gmail.readonly scope after revoke
  // Just clear the global auth cache
  globalAuth = null;
  console.log('Global auth cleared');
  res.json({ success: true });
});

// ===== Middleware: token verification (single-user global) =====
const ensureAuthenticated = async (req, res, next) => {
  if (!globalAuth || !globalAuth.accessToken) {
    return res.status(401).json({ error: 'Not authorized' });
  }

  if (globalAuth.tokenExpiry && Date.now() >= globalAuth.tokenExpiry && globalAuth.refreshToken) {
    try {
      const refreshResponse = await axios.post('https://oauth2.googleapis.com/token', {
        refresh_token: globalAuth.refreshToken,
        client_id: GOOGLE_CONFIG.clientId,
        client_secret: GOOGLE_CONFIG.clientSecret,
        grant_type: 'refresh_token'
      });

      globalAuth.accessToken = refreshResponse.data.access_token;
      globalAuth.tokenExpiry = Date.now() + (refreshResponse.data.expires_in * 1000);
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
        headers: { Authorization: `Bearer ${globalAuth.accessToken}` },
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
          headers: { Authorization: `Bearer ${globalAuth.accessToken}` },
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
        headers: { Authorization: `Bearer ${globalAuth.accessToken}` },
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
