// ==============================
// Part 1/4
// server.js (START)
// Trading Helper Backend (FINAL) - PART 1
// ==============================

/*
  Usage:
  - Put this file at backend/server.js
  - Add ENV: SMARTAPI_KEY, SMART_TOTP, SMART_USER_ID, SMARTAPI_SECRET(optional), SMARTAPI_BASE(optional)
  - package.json must include dependencies:
    "axios", "express", "node-fetch", "ws", "zlib", "body-parser", "dotenv", "totp-generator"
*/

const fs = require('fs');
const path = require('path');
const http = require('http');
const zlib = require('zlib');
const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch'); // node-fetch v2 style used
const axios = require('axios');
const WebSocket = require('ws');     // ensure ws is in package.json
const dotenv = require('dotenv');
const totp = require('totp-generator');

// load env from .env if present
dotenv.config();

// Config / ENV
const SMARTAPI_KEY = process.env.SMARTAPI_KEY || '';
const SMARTAPI_SECRET = process.env.SMARTAPI_SECRET || ''; // optional
const SMART_TOTP = process.env.SMART_TOTP || ''; // secret used for totp generation if provided
const SMART_USER_ID = process.env.SMART_USER_ID || '';
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || 'https://apiconnect.angelone.in/rest/secure/angelbroking'; // default base used in docs
const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;

// Basic application
const app = express();
app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// ---- Internal state ----
let SMART_SESSION = {
  loggedIn: false,
  feedToken: null,
  accessToken: null,
  refreshToken: null,
  tokenExpiry: null,
  userId: SMART_USER_ID || null,
  lastLoginTs: null
};

// auto_tokens cache (nifty/sensex/natural gas)
const auto_tokens = {
  nifty: { symbol: null, token: null, expiry: null, ltp: null },
  sensex: { symbol: null, token: null, expiry: null, ltp: null },
  "natural gas": { symbol: null, token: null, expiry: null, ltp: null }
};

// utility helpers
function nowTS() { return Math.floor(Date.now()/1000); }
function sleep(ms){ return new Promise(resolve=>setTimeout(resolve,ms)); }
function safeJSON(x){ try { return JSON.parse(x); } catch(e){ return null; } }
function num(v,d=0){ const n = Number(v); return Number.isFinite(n) ? n : d; }
function clamp(v,min,max){ return Math.max(min, Math.min(max, v)); }
function roundToStep(v, step){ if(!step) return v; return Math.round(v/step)*step; }

// generate TOTP if SMART_TOTP (base32 secret) provided
function makeTotp(){
  if (!SMART_TOTP) return null;
  try { return totp(SMART_TOTP); } catch(e){ return null; }
}

// ---- SmartAPI HTTP helpers ----
async function smartapiRequest(pathRel, opts = {}) {
  // pathRel: eg "/user/v1/login" or "/market/v1/..."
  const url = (SMARTAPI_BASE.replace(/\/+$/,'') + '/' + pathRel.replace(/^\/+/,''));
  const method = (opts.method || 'GET').toUpperCase();
  const headers = Object.assign({
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-API-KEY': SMARTAPI_KEY || ''
  }, opts.headers || {});
  const body = (opts.body && typeof opts.body === 'object') ? JSON.stringify(opts.body) : opts.body;

  try {
    const resp = await fetch(url, { method, headers, body, timeout: opts.timeout || 15000 });
    const txt = await resp.text();
    let data = null;
    try { data = JSON.parse(txt); } catch(e) { data = txt; }
    return { ok: resp.ok, status: resp.status, data, raw: txt };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

// SmartAPI login flow (HTTP -> returns feed token + access tokens)
async function smartLogin() {
  // Many SmartAPI deployments require totp + apiKey + userId
  // This function attempts to call login endpoint(s) - adapt if your broker uses different path.
  // We'll attempt two common endpoints (angelbroking's documented flows).
  const totpCode = makeTotp();
  const body = {
    apiKey: SMARTAPI_KEY,
    clientCode: SMART_USER_ID,
  };
  if (totpCode) body.totp = totpCode;
  if (SMARTAPI_SECRET) body.secret = SMARTAPI_SECRET;

  // Primary attempt: historical doc endpoint /user/v1/login (or similar).
  // We'll try multiple common endpoints if the first fails.
  const endpointsToTry = [
    '/user/v1/login',
    '/user/v1/loginByPassword', // fallback name
    '/session/validate',        // other vendors
  ];

  for (let ep of endpointsToTry) {
    const r = await smartapiRequest(ep, { method: 'POST', body });
    if (r.ok && r.data) {
      // Extract feed_token / access token fields depending on response shape
      const d = r.data;
      // Common keys: data.feedToken, data.token, data.refreshToken
      const feedToken = d.feedToken || d.data && d.data.feedToken || d.data && d.data.feed_token || d.feed_token;
      const accessToken = d.data && d.data.accessToken || d.accessToken || d.token || d.data && d.data.token;
      const refreshToken = d.data && d.data.refreshToken || d.refreshToken || d.refresh_token;
      SMART_SESSION.loggedIn = true;
      SMART_SESSION.feedToken = feedToken || null;
      SMART_SESSION.accessToken = accessToken || null;
      SMART_SESSION.refreshToken = refreshToken || null;
      SMART_SESSION.lastLoginTs = Date.now();
      return { ok: true, resp: d, feedToken: SMART_SESSION.feedToken, accessToken: SMART_SESSION.accessToken };
    }
    // else continue trying other endpoints
  }
  return { ok: false, error: 'SmartAPI login failed (all endpoints tried)' };
}
// ==============================
// Part 2/4
// WebSocket manager, token auto-discovery, option-chain helpers
// ==============================

/*
  WebSocket notes:
  - We'll maintain ONE ws client instance (single global). Use ws.connect(url) and handle reconnect/backoff.
  - For browser-based streaming, SmartAPI docs show query params usage; for server-side we use ws with headers.
*/

let wsClient = null;
let wsConnected = false;
let wsReconnectIn = 0;
let wsSubscriptions = new Set();

function wsUrlForFeed({ clientCode, feedToken, apiKey } = {}) {
  // For AngelOne style: wss://smartapisocket.angelone.in/smart-stream?clientCode=&feedToken=&apiKey=
  const base = (process.env.SMART_WEBSOCKET_BASE || 'wss://smartapisocket.angelone.in/smart-stream');
  const params = new URLSearchParams();
  if(clientCode) params.set('clientCode', clientCode);
  if(feedToken) params.set('feedToken', feedToken);
  if(apiKey) params.set('apiKey', apiKey);
  return base + '?' + params.toString();
}

function initWebSocket() {
  if (wsClient) return wsClient;
  if (!SMART_SESSION.feedToken || !SMART_SESSION.userId || !SMARTAPI_KEY) return null;
  const url = wsUrlForFeed({ clientCode: SMART_SESSION.userId, feedToken: SMART_SESSION.feedToken, apiKey: SMARTAPI_KEY });
  wsClient = new WebSocket(url, { handshakeTimeout: 15000 });

  wsClient.on('open', () => {
    wsConnected = true;
    wsReconnectIn = 0;
    console.log('WS open');
    // re-subscribe existing
    wsSubscriptions.forEach(s => wsSend({ action: 'subscribe', ...s }).catch(()=>{}));
  });
  wsClient.on('message', (msg) => {
    // SmartAPI often sends binary; handle string and buffer
    let payload = msg;
    if (Buffer.isBuffer(msg)) {
      try { payload = msg.toString('utf8'); } catch(e) { payload = null; }
    }
    try {
      const data = JSON.parse(payload);
      handleWsMessage(data);
    } catch(e) {
      // ignore or attempt zlib inflate
      try {
        const buf = Buffer.from(msg);
        zlib.inflate(buf, (err, res) => {
          if (!err) {
            try {
              const d = JSON.parse(res.toString());
              handleWsMessage(d);
            } catch(e2){}
          }
        });
      } catch(e2){}
    }
  });
  wsClient.on('close', (code, reason) => {
    wsConnected = false;
    wsClient = null;
    console.warn('WS closed', code, reason);
    scheduleWsReconnect();
  });
  wsClient.on('error', (err) => {
    wsConnected = false;
    console.error('WS error', err && err.message);
    // will close and trigger reconnect
  });
  return wsClient;
}

function scheduleWsReconnect() {
  if (wsReconnectIn) return;
  wsReconnectIn = 2000 + Math.floor(Math.random()*4000);
  setTimeout(() => {
    wsReconnectIn = 0;
    try { initWebSocket(); } catch(e){ console.error('ws reconnect fail', e && e.message); }
  }, wsReconnectIn);
}

async function wsSend(obj){
  if (!wsClient || wsClient.readyState !== WebSocket.OPEN) {
    // try init
    initWebSocket();
    await sleep(500);
    if (!wsClient || wsClient.readyState !== WebSocket.OPEN) throw new Error('WS not connected');
  }
  return new Promise((resolve, reject) => {
    wsClient.send(JSON.stringify(obj), (err) => { if(err) reject(err); else resolve(true); });
  });
}

function handleWsMessage(data){
  // Application-specific: look for LTP payloads, best-5, etc.
  // We'll detect option-chain or futures LTP updates and update auto_tokens.ltp if token matches.
  try {
    if (!data) return;
    // Example SmartAPI payload shapes vary; detect common keys
    if (data.payload && Array.isArray(data.payload)) {
      data.payload.forEach(p=>{
        if (p.token && p.ltp) {
          // update if token matches known auto_tokens
          Object.keys(auto_tokens).forEach(k=>{
            if (String(auto_tokens[k].token) === String(p.token)) {
              auto_tokens[k].ltp = num(p.ltp, auto_tokens[k].ltp);
            }
          });
        }
      });
    } else if (Array.isArray(data)) {
      data.forEach(item=> {
        if (item && item.ltp && item.token) {
          Object.keys(auto_tokens).forEach(k=>{
            if (String(auto_tokens[k].token) === String(item.token)) {
              auto_tokens[k].ltp = num(item.ltp, auto_tokens[k].ltp);
            }
          });
        }
      });
    }
    // other message handling can be extended
  } catch(e){}
}

// Auto-token discovery via HTTP symbol list (attempt)
async function discoverAutoTokens() {
  // Try futures symbol listing endpoint: /market/v1/instruments or similar
  // We'll try a few paths and parse arrays to find "NIFTY" "FUT" or "NIFTY30DEC".
  const tryPaths = [
    '/market/v1/instruments',
    '/market/v1/symbols',
    '/market/v1/instruments/future'
  ];
  for (let p of tryPaths){
    const r = await smartapiRequest(p, { method: 'GET' });
    if (!r.ok || !r.data) continue;
    const data = r.data.data || r.data || [];
    try {
      const arr = Array.isArray(data) ? data : (Array.isArray(data.instruments) ? data.instruments : []);
      for (const item of arr) {
        const s = JSON.stringify(item).toLowerCase();
        if (s.includes('nifty') && s.includes('fut')) {
          // extract token & symbol
          const sym = item.symbol || item.name || item.tradingSymbol || item.instrument || null;
          const tok = item.token || item.tokenId || item.exchangeToken || item.tokenId || null;
          if (sym && tok) auto_tokens.nifty = { symbol: String(sym), token: String(tok), expiry: item.expiry || null, ltp: null };
        }
        if (s.includes('sensex') && s.includes('fut')) {
          const sym = item.symbol || item.name || item.tradingSymbol || item.instrument || null;
          const tok = item.token || item.tokenId || item.exchangeToken || null;
          if (sym && tok) auto_tokens.sensex = { symbol: String(sym), token: String(tok), expiry: item.expiry || null, ltp: null };
        }
        if (s.includes('natural') && s.includes('gas') && s.includes('fut')) {
          const sym = item.symbol || item.name || item.tradingSymbol || item.instrument || null;
          const tok = item.token || item.tokenId || item.exchangeToken || null;
          if (sym && tok) auto_tokens['natural gas'] = { symbol: String(sym), token: String(tok), expiry: item.expiry || null, ltp: null };
        }
      }
      // if we found something, stop
      if (auto_tokens.nifty.token || auto_tokens.sensex.token || auto_tokens['natural gas'].token) break;
    } catch(e){}
  }
}

// Option-chain and greeks HTTP helpers
async function fetchOptionGreeks(symbolName, expiryDate) {
  // Example SmartAPI greeks endpoint (doc): /marketData/v1/optionGreek
  // We'll call documented path and pass name & expirydate
  const endpoint = '/marketData/v1/optionGreek';
  const payload = { name: symbolName, expirydate: expiryDate };
  const r = await smartapiRequest(endpoint, { method: 'POST', body: payload });
  if (r.ok) return { ok: true, data: r.data };
  return { ok: false, error: r.error || r.data || 'no-data' };
}

async function fetchQuote(symbol) {
  // Quote endpoint per docs: /market/v1/quote/<symbol> or /market/v1/quote with body
  // We'll try the documented route: /market/v1/quote/<symbol>
  const p = `/market/v1/quote/${encodeURIComponent(symbol)}`;
  const r = await smartapiRequest(p, { method: 'GET' });
  if (r.ok) return { ok: true, data: r.data };
  // fallback POST to /market/v1/quote with {symbol}
  const r2 = await smartapiRequest('/market/v1/quote/', { method: 'POST', body: { symbol } });
  if (r2.ok) return { ok: true, data: r2.data };
  return { ok: false, error: r.error || r2.error || 'quote failed' };
}
// ==============================
// Part 3/4
// Trend / strike engine and endpoints (part 1)
// ==============================

/*
  This part contains the trading logic to compute trend & strikes (EMA/RSi/VWAP inputs are fed from UI or live)
  and the API endpoints to compute & return JSON used by the frontend.
*/

// FUTURE rules (market config)
const FUTURE_RULES = {
  nifty: { searchSymbol: "NIFTY", exchange: "NFO", instrumentType: "FUTIDX", strikeStep: 50, baseDistances: { far: 250, mid: 200, near: 150 } },
  sensex: { searchSymbol: "SENSEX", exchange: "BFO", instrumentType: "FUTIDX", strikeStep: 100, baseDistances: { far: 500, mid: 400, near: 300 } },
  "natural gas": { searchSymbol: "Natural Gas", exchange: "MCX", instrumentType: "FUTCOM", strikeStep: 5, baseDistances: { far: 80, mid: 60, near: 50 } }
};

// Trend / strike engine
function computeTrendAndStrikes(input) {
  // input: { ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live }
  const ema20 = num(input.ema20, 0);
  const ema50 = num(input.ema50, 0);
  const rsi = num(input.rsi, 50);
  const vwap = num(input.vwap, 0);
  const spot = num(input.spot, 0);
  const market = (input.market || 'nifty').toLowerCase();
  const expiry_days = Math.max(0, Number(input.expiry_days || 0));
  const use_live = !!input.use_live;

  // Basic trend logic (example; you can extend)
  let main = 'SIDEWAYS';
  let bias = 'NONE';
  let score = 0;
  // ema gap
  const gap = ema20 && ema50 ? ((ema20 - ema50) / ema50) * 100 : 0;
  if (gap > 0.4) { main = 'UPTREND'; bias = 'CE'; score += 30; }
  else if (gap < -0.4) { main = 'DOWNTREND'; bias = 'PE'; score += 30; }
  else { main = 'SIDEWAYS'; bias = 'NONE'; score += 5; }

  // rsi
  if (rsi < 30) { score -= 5; }
  else if (rsi > 70) { score += 5; }

  // vwap vs spot
  if (vwap && spot) {
    const diff = ((spot - vwap) / vwap) * 100;
    if (diff > 0.5) { score += 5; }
    else if (diff < -0.5) { score -= 5; }
  }

  // expiry factor
  if (expiry_days <= 2) score -= 3;

  // decide strikes
  const rule = FUTURE_RULES[market] || FUTURE_RULES['nifty'];
  const step = rule.strikeStep || 50;
  // center strike approximate = round spot to nearest step
  const centre = roundToStep(spot, step);
  // distances based on score / baseDistances
  let base = rule.baseDistances ? rule.baseDistances.mid : 200;
  // adapt base by score magnitude
  if (score > 30) base = rule.baseDistances.far;
  if (score < 10) base = rule.baseDistances.near;

  // choose CE/PE distances
  const ceStrike = centre + (Math.round((base/step)) * step * 0.5); // approximate
  const peStrike = centre - (Math.round((base/step)) * step * 0.5);
  const straddleStrike = centre; // nearest

  // compute entry/stop/target (example defaults)
  function makeStrike(type, strikeVal, distance) {
    return {
      type,
      strike: strikeVal,
      distance: distance,
      entry: type === 'STRADDLE' ? 2000 : 10,
      stopLoss: type === 'STRADDLE' ? 1200 : 6,
      target: type === 'STRADDLE' ? 3000 : 15,
      midPrice: null
    };
  }

  const results = [
    makeStrike('CE', ceStrike, Math.abs(ceStrike - centre)),
    makeStrike('PE', peStrike, Math.abs(peStrike - centre)),
    makeStrike('STRADDLE', straddleStrike, Math.abs(straddleStrike - centre))
  ];

  const out = {
    success: true,
    message: 'Calculation complete',
    login_status: SMART_SESSION.loggedIn ? 'SmartAPI Logged-In' : 'SmartAPI Logged-Out',
    input: { ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live },
    trend: {
      main,
      strength: score > 25 ? 'STRONG' : (score > 12 ? 'MODERATE' : 'RANGE'),
      score,
      bias,
      components: {
        ema_gap: `${gap.toFixed(2)}%`,
        rsi: `RSI ${rsi.toFixed(2)} ${rsi<40?'(bearish)':''}`,
        vwap: vwap ? (spot < vwap ? `Below VWAP` : `Above VWAP`) : 'No VWAP',
        price_structure: 'Mixed structure',
        expiry: expiry_days <= 2 ? 'Expiry near (volatile)' : 'Expiry comfortable'
      },
      comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
    },
    strikes: results,
    auto_tokens,
    meta: {
      live_data_used: use_live,
      live_ltp: auto_tokens[market] && auto_tokens[market].ltp ? auto_tokens[market].ltp : null,
      live_error: null
    }
  };
  return out;
}

// ---- HTTP API endpoints ----
app.get('/api/ping', (req,res) => {
  return res.json({ ok:true, ts: nowTS(), app: 'Trading Helper Backend' });
});

// POST /api/login -> attempt SmartAPI login and return feed token + tokens
app.post('/api/login', async (req, res) => {
  try {
    const resp = await smartLogin();
    if (!resp.ok) return res.status(500).json({ ok:false, error: resp.error || 'login failed' });
    // After login, try discover tokens
    await discoverAutoTokens();
    // init ws (attempt)
    initWebSocket();
    return res.json({ ok:true, feed_token: SMART_SESSION.feedToken, accessToken: SMART_SESSION.accessToken, auto_tokens });
  } catch (e) {
    return res.status(500).json({ ok:false, error: e.message || String(e) });
  }
});

// GET /api/auto_tokens -> return discovered auto tokens
app.get('/api/auto_tokens', (req,res) => {
  return res.json({ ok:true, auto_tokens, smart_session: { loggedIn: SMART_SESSION.loggedIn } });
});

// POST /api/compute -> compute trend & strikes (body contains inputs)
app.post('/api/compute', (req, res) => {
  try {
    const input = req.body || {};
    const out = computeTrendAndStrikes(input);
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ ok:false, error: e.message || String(e) });
  }
});
// ==============================
// Part 4/4
// Option-chain endpoints, greeks, websocket subscribe, start server
// ==============================

/*
  Endpoints here:
  - POST /api/option-greeks  { name, expirydate } -> calls SmartAPI greeks endpoint
  - GET  /api/quote?symbol=... -> fetch quote
  - POST /api/ws/subscribe -> subscribe to token(s) via ws
  - GET  /api/settings -> return current settings/env summary
*/

app.post('/api/option-greeks', async (req, res) => {
  const body = req.body || {};
  const name = body.name;
  const expiry = body.expirydate || body.expiry || null;
  if (!name || !expiry) return res.status(400).json({ ok:false, error: 'missing name or expirydate' });
  try {
    const g = await fetchOptionGreeks(name, expiry);
    if (!g.ok) return res.status(500).json({ ok:false, error: g.error || 'failed' });
    return res.json({ ok:true, data: g.data });
  } catch(e){
    return res.status(500).json({ ok:false, error: e.message || String(e) });
  }
});

app.get('/api/quote', async (req, res) => {
  const symbol = req.query.symbol || req.query.sym;
  if (!symbol) return res.status(400).json({ ok:false, error: 'missing symbol query param' });
  try {
    const q = await fetchQuote(symbol);
    if (!q.ok) return res.status(500).json({ ok:false, error: q.error || 'quote fail' });
    return res.json({ ok:true, data: q.data });
  } catch(e){
    return res.status(500).json({ ok:false, error: e.message || String(e) });
  }
});

// WS subscribe POST body: { tokens: [token1, token2], mode: 'ltp' }
app.post('/api/ws/subscribe', async (req, res) => {
  const body = req.body || {};
  const tokens = body.tokens || [];
  if (!Array.isArray(tokens) || tokens.length === 0) return res.status(400).json({ ok:false, error:'missing tokens array' });
  // ensure logged in and ws
  if (!SMART_SESSION.feedToken || !SMART_SESSION.userId) {
    return res.status(400).json({ ok:false, error: 'not logged in to SmartAPI' });
  }
  try {
    tokens.forEach(t => wsSubscriptions.add({ token: String(t) }));
    // send subscribe messages (wrapped)
    for (const t of tokens) {
      try {
        await wsSend({ action: 'subscribe', token: String(t) });
      } catch(e){}
    }
    return res.json({ ok:true, subscribed: tokens.length, wsConnected });
  } catch(e){
    return res.status(500).json({ ok:false, error: e.message || String(e) });
  }
});

// settings endpoint
app.get('/api/settings', (req,res) => {
  return res.json({
    ok: true,
    env: {
      SMARTAPI_KEY: !!SMARTAPI_KEY,
      SMARTAPI_BASE: SMARTAPI_BASE,
      SMART_SESSION: { loggedIn: SMART_SESSION.loggedIn, hasFeedToken: !!SMART_SESSION.feedToken }
    }
  });
});

// graceful shutdown / health check
app.get('/api/health', (req,res)=> res.json({ ok:true, ts: nowTS(), wsConnected }));

// Start HTTP server
const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`Trading helper backend listening on port ${PORT}`);
  // if we have login info auto attempt login on boot (only if env present)
  (async ()=>{
    if (SMARTAPI_KEY && (SMART_USER_ID || SMART_SESSION.userId)) {
      try {
        await smartLogin();
        await discoverAutoTokens();
        initWebSocket();
      } catch(e){ console.error('auto-init failed', e && e.message); }
    }
  })();
});

// Export for testing if needed
module.exports = app;
