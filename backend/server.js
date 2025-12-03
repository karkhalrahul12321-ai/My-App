// ===============================
// Part 1/4 - server.js (START)
// Imports, config, helpers, app init
// ===============================
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch'); // v2 style
const WebSocket = require('ws'); // single ws dependency
const crypto = require('crypto');
const dotenv = require('dotenv');
const totp = require('totp-generator'); // simple TOTP generator

// Load .env if present
dotenv.config();

const PORT = process.env.PORT || 3000;
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || 'https://apiconnect.angelone.in';
const SMARTAPI_KEY = process.env.SMARTAPI_KEY || '';
const SMART_USER_ID = process.env.SMART_USER_ID || '';
const SMART_TOTP_SECRET = process.env.SMART_TOTP || ''; // TOTP secret (base32)
const SMART_API_SECRET = process.env.SMART_API_SECRET || ''; // optional

// Basic checks
if (!SMARTAPI_KEY) {
  console.warn('Warning: SMARTAPI_KEY not set. Many endpoints will fail.');
}
if (!SMART_USER_ID) {
  console.warn('Warning: SMART_USER_ID not set. Login will fail without it.');
}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Simple logger wrapper
function log(...args) { console.log(new Date().toISOString(), ...args); }
function nowTS() { return Date.now(); }

// Safe JSON parse
function safeJSON(s) {
  try { return JSON.parse(s); } catch (e) { return null; }
}

// small timeout helper for fetch
function fetchWithTimeout(url, opts = {}, timeout = 8000) {
  return Promise.race([
    fetch(url, opts),
    new Promise((_, rej) => setTimeout(() => rej(new Error('fetch-timeout')), timeout))
  ]);
}

// Normalise market names
const MARKET_MAP = {
  nifty: { searchSymbol: 'NIFTY', exchange: 'NFO', instrumentType: 'FUTIDX' },
  sensex: { searchSymbol: 'SENSEX', exchange: 'BFO', instrumentType: 'FUTIDX' },
  'natural gas': { searchSymbol: 'NATURAL GAS', exchange: 'MCX', instrumentType: 'FUTIDX' }
};

// In-memory store for auto tokens (updated by login/token discovery)
const auto_tokens = {
  nifty: { symbol: null, token: null, expiry: null, ltp: null },
  sensex: { symbol: null, token: null, expiry: null, ltp: null },
  'natural gas': { symbol: null, token: null, expiry: null, ltp: null },
};

// Websocket client single instance holder
let wsClient = null;
let wsClientConnected = false;
let wsClientLastSeen = 0;
let wsClientSubscriptions = new Set();

// Keep feed token and feed headers from SmartAPI login
let SMART_FEED_TOKEN = null;
let SMART_HEADERS = {}; // custom headers from login response if any

// Utility: safe sleep
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// Utility: format strikes etc
function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

// Helper to build SmartAPI authorization headers (if needed)
function smartHeadersFromLogin(loginResp) {
  const headers = {};
  if (!loginResp) return headers;
  // Some SmartAPI implementations return auth headers in response headers,
  // or return session tokens in body. We keep flexible handling.
  if (loginResp.session && loginResp.session.access_token) {
    headers['Authorization'] = `Bearer ${loginResp.session.access_token}`;
  }
  return headers;
}
// ===============================
// Part 2/4 - SmartAPI login & token discovery
// ===============================

/**
 * Perform SmartAPI login.
 * Many SmartAPI variants require userId + password + totp etc.
 * This implementation attempts using TOTP secret (if provided) to produce OTP,
 * then POST to /login or similar endpoint. The exact URL and payload may
 * differ for your AngelOne account. Adjust as necessary.
 *
 * Returns an object: { ok: true, feed_token, tokens, raw }
 */
async function smartLogin() {
  // NOTE: Adjust endpoint based on your SmartAPI version.
  // Common pattern (Angel broking) has endpoint /rest/secure/angelbroking/user/v1/loginByPassword or /rest/secure/angelbroking/user/v1/login
  // Here we try a generic approach using SMARTAPI_BASE and known paths.
  try {
    const totpValue = SMART_TOTP_SECRET ? totp(SMART_TOTP_SECRET) : null;

    // attempt primary login endpoint (common)
    const loginPaths = [
      '/rest/secure/angelbroking/user/v1/loginByPassword', // example
      '/rest/secure/angelbroking/user/v1/login', // fallback
      '/rest/secure/angelbroking/user/v1/loginWithOtp' // if applicable
    ];

    for (const p of loginPaths) {
      const url = SMARTAPI_BASE + p;
      const payload = {
        clientCode: SMART_USER_ID,
        apiKey: SMARTAPI_KEY,
        ...(totpValue ? { totp: totpValue } : {})
      };
      // Some SmartAPI variants require password — we don't store password in backend,
      // So prefer token-based TOTP route. If password required, user must call login externally.
      try {
        const r = await fetchWithTimeout(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        }, 8000);
        const j = await r.json().catch(()=>({ok:false}));
        if (r.ok && j) {
          // try to extract feedToken or tokens
          const feedToken = j.feedToken || j.data?.feedToken || j.session?.feedToken || j.token;
          SMART_FEED_TOKEN = feedToken || SMART_FEED_TOKEN;
          SMART_HEADERS = smartHeadersFromLogin(j) || SMART_HEADERS;
          return { ok: true, raw: j, feed_token: SMART_FEED_TOKEN };
        }
      } catch (err) {
        // ignore and try next
      }
    }
    return { ok: false, error: 'login_failed' };
  } catch (err) {
    return { ok: false, error: 'exception', message: err.message };
  }
}

/**
 * Discover auto_tokens (futures symbols + tokens) via SmartAPI "instruments" or "search" endpoints.
 * This function tries to call some common endpoints and extract fut tokens.
 */
async function discoverAutoTokens() {
  // We'll try a few endpoints that many SmartAPI variants expose
  const tries = [
    '/rest/secure/angelbroking/instruments', // example
    '/rest/secure/angelbroking/market/v1/instruments',
    '/rest/secure/angelbroking/marketData/v1/instruments',
    '/rest/secure/angelbroking/market/v1/search' // search for "NIFTY"
  ];
  const results = [];
  for (const mk of Object.keys(auto_tokens)) {
    auto_tokens[mk] = { symbol: null, token: null, expiry: null, ltp: null };
  }

  for (const p of tries) {
    const url = SMARTAPI_BASE + p;
    try {
      const r = await fetchWithTimeout(url, { method: 'GET', headers: SMART_HEADERS }, 8000);
      if (!r.ok) continue;
      const j = await r.json();
      // try to find FUT symbols in j (array or object)
      const arr = Array.isArray(j) ? j : (Array.isArray(j.data) ? j.data : null);
      if (!arr) continue;
      for (const a of arr) {
        try {
          const name = (a.symbol||a.tradingSymbol||a.name||'').toString().toLowerCase();
          const token = a.token || a.tokenId || a.exchangeToken || a.exchangeTokenId || null;
          if (!token) continue;
          // fuzzy matching
          if (name.includes('nifty') && String(name).toLowerCase().includes('fut')) {
            auto_tokens.nifty = auto_tokens.nifty || {};
            auto_tokens.nifty.symbol = a.symbol || a.tradingSymbol || name;
            auto_tokens.nifty.token = String(token);
            auto_tokens.nifty.expiry = a.expiry || a.expiryDate || auto_tokens.nifty.expiry;
          }
          if (name.includes('sensex') && String(name).toLowerCase().includes('fut')) {
            auto_tokens.sensex = auto_tokens.sensex || {};
            auto_tokens.sensex.symbol = a.symbol || a.tradingSymbol || name;
            auto_tokens.sensex.token = String(token);
            auto_tokens.sensex.expiry = a.expiry || a.expiryDate || auto_tokens.sensex.expiry;
          }
          if (name.includes('natural') && name.includes('gas')) {
            auto_tokens['natural gas'] = auto_tokens['natural gas'] || {};
            auto_tokens['natural gas'].symbol = a.symbol || a.tradingSymbol || name;
            auto_tokens['natural gas'].token = String(token);
            auto_tokens['natural gas'].expiry = a.expiry || a.expiryDate || auto_tokens['natural gas'].expiry;
          }
        } catch (e) { /* ignore */ }
      }
    } catch (err) {
      // ignore and continue
    }
  }
  return auto_tokens;
}

/**
 * Fetch LTP for a given token using SmartAPI FULL quote or LTP endpoint
 * Fallbacks: /market/v1/quote/{token} or /marketData/v1/quote
 */
async function fetchLTPByToken(token, marketKey='nifty') {
  if (!token) return null;
  // common patterns:
  const endpoints = [
    `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote/${token}`,
    `${SMARTAPI_BASE}/rest/secure/angelbroking/marketData/v1/quote/${token}`,
    `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote` // may be POST
  ];
  for (const url of endpoints) {
    try {
      const method = url.endsWith('/quote') ? 'POST' : 'GET';
      const opts = { method, headers: { 'Content-Type': 'application/json', ...SMART_HEADERS } };
      if (method === 'POST') {
        opts.body = JSON.stringify({ symbols: [{ token: token }] });
      }
      const r = await fetchWithTimeout(url, opts, 6000);
      if (!r.ok) continue;
      const j = await r.json();
      // try to find LTP in common places
      if (j && typeof j === 'object') {
        // direct ltp
        const l = j.lastPrice || j.ltp || (j.data && j.data.lastPrice) || null;
        if (l) return Number(l);
        // sometimes nested
        if (Array.isArray(j)) {
          const found = j.find(x=>x && (x.token==token || x.tradingSymbol));
          if (found) return Number(found.lastPrice || found.ltp || found.lastTradedPrice || found.close);
        }
      }
    } catch (err) { /* continue */ }
  }
  return null;
}
// ===============================
// Part 3/4 - WebSocket client & endpoints
// ===============================

/**
 * Initialize single websocket client to SmartAPI stream.
 * Uses SMART_FEED_TOKEN, SMARTAPI_KEY, SMART_USER_ID.
 * For browser-based clients SmartAPI expects query params: ?clientCode=&feedToken=&apiKey=
 */
function initSmartAPIWebSocket() {
  if (wsClient && wsClientConnected) return wsClient;

  // require feed token
  if (!SMART_FEED_TOKEN) {
    log('WebSocket init skipped: no feed token');
    return null;
  }

  const wsUrlBase = (SMARTAPI_BASE.includes('https') ? SMARTAPI_BASE.replace(/^https?/, 'wss') : 'wss://smartapisocket.angelone.in') + '/smart-stream';
  // append query params compatible with AngelOne doc
  const url = `${wsUrlBase}?clientCode=${encodeURIComponent(SMART_USER_ID)}&feedToken=${encodeURIComponent(SMART_FEED_TOKEN)}&apiKey=${encodeURIComponent(SMARTAPI_KEY)}`;

  try {
    wsClient = new WebSocket(url);

    wsClient.on('open', () => {
      wsClientConnected = true;
      wsClientLastSeen = Date.now();
      log('SmartAPI WS connected');
      // re-subscribe existing subscriptions
      for (const s of wsClientSubscriptions) {
        try { wsClient.send(JSON.stringify({ action: 'subscribe', params: s })); } catch (e) { }
      }
    });

    wsClient.on('message', (msg) => {
      wsClientLastSeen = Date.now();
      // try parse
      let data = null;
      try { data = typeof msg === 'string' ? JSON.parse(msg) : JSON.parse(msg.toString()); } catch (e) { /* ignore non-json */ }
      // handle heartbeat / update tokens / ltp updates etc
      if (data && data.type === 'heartbeat') return;
      // If data contains ltp update for token, update auto_tokens ltp
      try {
        if (data && data.payload) {
          // Normalise: payload might be { token: '1234', ltp: 12345 }
          const p = data.payload;
          const tok = p.token || p.exchangeToken || p.instrumentToken || p.instrument;
          const ltp = p.ltp || p.lastPrice || p.price;
          if (tok && ltp) {
            // assign to matching auto_token if token matches
            for (const k of Object.keys(auto_tokens)) {
              if (auto_tokens[k] && auto_tokens[k].token && auto_tokens[k].token == String(tok)) {
                auto_tokens[k].ltp = Number(ltp);
              }
            }
          }
        }
      } catch (e) { /* ignore */ }
      // Users may want to process incoming messages — we keep this extensible.
    });

    wsClient.on('close', (code, reason) => {
      wsClientConnected = false;
      log('SmartAPI WS closed', code, reason);
      // try to auto-reconnect after a short delay
      setTimeout(() => {
        try { initSmartAPIWebSocket(); } catch(e){ }
      }, 5000);
    });

    wsClient.on('error', (err) => {
      log('SmartAPI WS error', err && err.message);
    });
    return wsClient;
  } catch (err) {
    log('Failed init WS', err && err.message);
    wsClient = null;
    wsClientConnected = false;
    return null;
  }
}

/**
 * Subscribe to tokens via ws (safe single client).
 * param: array of token strings or a single token.
 */
function wsSubscribe(tokens) {
  if (!Array.isArray(tokens)) tokens = [tokens];
  for (const t of tokens) wsClientSubscriptions.add(String(t));
  if (wsClient && wsClientConnected) {
    try {
      const params = tokens.map(t => ({ token: String(t) }));
      wsClient.send(JSON.stringify({ action: 'subscribe', params }));
    } catch (e) { log('ws subscribe failed', e && e.message); }
  } else {
    // try to init client
    initSmartAPIWebSocket();
  }
}

/**
 * Simple endpoint: /api/ping
 */
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, ts: nowTS(), app: 'Trading Helper Backend' });
});

/**
 * POST /api/login -> triggers smartLogin + discover tokens + init websocket
 */
app.post('/api/login', async (req, res) => {
  try {
    const loginResp = await smartLogin();
    if (!loginResp.ok) {
      return res.status(400).json({ ok: false, message: 'SmartAPI login failed', detail: loginResp });
    }
    // after successful login, discover tokens
    await discoverAutoTokens();
    // init ws
    initSmartAPIWebSocket();
    return res.json({ ok: true, message: 'SmartAPI Logged-In', feed_token: SMART_FEED_TOKEN, auto_tokens });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /api/settings -> returns effective settings/env
 */
app.get('/api/settings', (req, res) => {
  res.json({
    apiKey: SMARTAPI_KEY ? 'SET' : '',
    userId: SMART_USER_ID ? 'SET' : '',
    totp: SMART_TOTP_SECRET ? 'SET' : '',
  });
});

/**
 * GET /api/auto_tokens -> return discovered tokens (for debug)
 */
app.get('/api/auto_tokens', (req, res) => {
  res.json({ ok: true, auto_tokens });
});

/**
 * GET /api/ltp/:market -> try to return LTP for main future token auto_tokens[market]
 */
app.get('/api/ltp/:market', async (req, res) => {
  const market = req.params.market;
  const m = (market || '').toLowerCase();
  const info = auto_tokens[m];
  if (!info || !info.token) {
    return res.json({ ok: false, message: 'no-token', market: m });
  }
  const ltp = await fetchLTPByToken(info.token, m);
  if (ltp == null) return res.json({ ok: false, message: 'ltp-not-found' });
  info.ltp = ltp;
  res.json({ ok: true, ltp, market: m, token: info.token });
});
// ===============================
// Part 4/4 - Strike engine, option-chain + greeks endpoints, serve SPA fallback, START
// ===============================

/**
 * Basic strike selection engine (example).
 * Inputs: price (spot), expiryDays, market, ema20, ema50, rsi, vwap
 * Returns: strikes: CE, PE, STRADDLE etc
 *
 * NOTE: This is a deterministic engine based on rules — tweak as per your logic.
 */
function calculateStrikes({ spot, market = 'nifty', expiry_days = 1, ema20, ema50, rsi, vwap, use_live = true }) {
  const s = Number(spot) || 0;
  const step = (market === 'nifty') ? 50 : (market === 'sensex' ? 100 : 5);
  const roundTo = (x) => Math.round(x / step) * step;

  const baseStrike = roundTo(s);
  const ceStrike = baseStrike + Math.round( Math.max(step, Math.abs(s - ema20||0)) / step ) * step;
  const peStrike = baseStrike - Math.round( Math.max(step, Math.abs(s - ema50||0)) / step ) * step;

  const distanceCE = Math.abs(ceStrike - s);
  const distancePE = Math.abs(peStrike - s);
  // example entry/stop/target simple constants — adapt to your algos
  const strikes = [
    { type: 'CE', strike: ceStrike, distance: distanceCE, entry: 10, stopLoss: 6, target: 15, midPrice: null },
    { type: 'PE', strike: peStrike, distance: distancePE, entry: 10, stopLoss: 6, target: 15, midPrice: null },
    { type: 'STRADDLE', strike: baseStrike, distance: Math.round((distanceCE + distancePE)/2), entry: 2000, stopLoss: 1200, target: 3000, midPrice: null }
  ];
  const trend = {
    main: 'SIDEWAYS',
    strength: 'RANGE',
    score: 10.3,
    bias: 'NONE',
    components: {
      ema_gap: `${((ema20-ema50)/ema50*100).toFixed(2)}%`,
      rsi: `RSI ${rsi||0}`,
      vwap: vwap ? (s>vwap ? 'Above VWAP' : (s<vwap ? 'Below VWAP' : 'Near VWAP')) : 'NA',
      price_structure: 'Mixed',
      expiry: expiry_days <= 2 ? 'Expiry near (volatile)' : 'Expiry comfortable'
    },
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${s}`
  };
  return { ok: true, message: 'Calculation complete', trend, strikes, input: { ema20, ema50, rsi, vwap, spot: s, market, expiry_days, use_live } };
}

/**
 * POST /api/calc -> input JSON { ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live }
 */
app.post('/api/calc', async (req, res) => {
  try {
    const body = req.body || {};
    let { ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live } = body;
    // If use_live, attempt to fetch live LTP for market token
    const m = (market||'nifty').toLowerCase();
    if (use_live && auto_tokens[m] && auto_tokens[m].token) {
      const l = await fetchLTPByToken(auto_tokens[m].token, m);
      if (l != null) spot = l;
    }
    const result = calculateStrikes({ ema20:Number(ema20), ema50:Number(ema50), rsi:Number(rsi), vwap:Number(vwap), spot:Number(spot), market:m, expiry_days:Number(expiry_days), use_live: !!use_live });
    // attach auto token info
    result.auto_tokens = auto_tokens;
    result.meta = { live_data_used: !!use_live, live_ltp: spot || null };
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/option-greeks -> proxy to SmartAPI Option Greeks HTTP endpoint (secure)
 * Body: { name: 'NIFTY', expirydate: '25DEC2025' } // adapt to SmartAPI contract
 */
app.post('/api/option-greeks', async (req, res) => {
  try {
    const body = req.body || {};
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/marketData/v1/optionGreek`;
    const r = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...SMART_HEADERS },
      body: JSON.stringify(body)
    }, 10000);
    const j = await r.json().catch(()=>null);
    if (!r.ok) return res.status(500).json({ ok: false, status: r.status, body: j });
    return res.json({ ok: true, data: j });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * POST /api/quote -> proxy to SmartAPI quote endpoint (for option chain / greeks)
 * Body: { tokens: [ '12345' ] } or { symbols: [...] }
 */
app.post('/api/quote', async (req, res) => {
  try {
    const body = req.body || {};
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`;
    const r = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...SMART_HEADERS },
      body: JSON.stringify(body)
    }, 9000);
    const j = await r.json().catch(()=>null);
    if (!r.ok) return res.status(500).json({ ok: false, status: r.status, body: j });
    return res.json({ ok: true, data: j });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// Static SPA fallback — if you have frontend build in ../frontend/dist
app.use(express.static(path.join(__dirname, '..', 'frontend', 'dist')));

// Serve index.html for unknown routes (SPA)
app.get('*', (req, res) => {
  // If API path, return 404
  if (req.path.startsWith('/api/') || req.path.startsWith('/rest/')) {
    return res.status(404).json({ ok: false, message: 'Not Found' });
  }
  const indexFile = path.join(__dirname, '..', 'frontend', 'dist', 'index.html');
  if (fs.existsSync(indexFile)) return res.sendFile(indexFile);
  // If no frontend, provide small info page
  res.setHeader('Content-Type', 'text/plain');
  res.send('Cannot GET / — backend running. Use /api/ping or /api/calc or /api/login');
});

// Start sequence: try to login/discover tokens automatically if env provided
async function startServer() {
  app.listen(PORT, async () => {
    log(`Server listening on port ${PORT}`);
    // Attempt initial login if env present
    if (SMARTAPI_KEY && SMART_USER_ID) {
      log('Attempting SmartAPI login on startup...');
      const r = await smartLogin();
      if (r.ok) {
        log('SmartAPI login succeeded (startup). Discovering tokens...');
        await discoverAutoTokens();
        initSmartAPIWebSocket();
      } else {
        log('SmartAPI login (startup) failed or skipped.', r);
      }
    } else {
      log('SmartAPI credentials missing in env — skipping auto login.');
    }
  });
}

startServer();
// ===============================
// Part 4/4 - server.js (END)
// ===============================
