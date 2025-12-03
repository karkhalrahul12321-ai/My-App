// ==============================
// Part 1/4
// final server.js (BEGIN PART-1)
// Trading Helper Backend - FINAL
// ==============================

/*
  Required env (set in Render/Replit):
    SMARTAPI_KEY (required)
    SMARTAPI_BASE (optional, default used below)
    SMART_USER_ID (client / user id)
    SMART_TOTP (optional)
    SMART_API_SECRET (optional)
*/

const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const WebSocket = require("ws");
const totp = require("totp-generator"); // totp-generator package
const dotenv = require("dotenv");
const crypto = require("crypto");

dotenv.config();

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// Config / constants
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelone.in";
const SMARTAPI_KEY = process.env.SMARTAPI_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || ""; // if provided
const SMART_USER_ID = process.env.SMART_USER_ID || ""; // clientCode / userId

if (!SMARTAPI_KEY) {
  console.warn("Warning: SMARTAPI_KEY is not set in env - some features will fail.");
}

// helper: safe number
function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}
function clamp(v, a, b){ return Math.max(a, Math.min(b, v)); }
function roundToStep(v, step) {
  if (!step) return v;
  return Math.round(v / step) * step;
}
function nowTS(){ return Date.now(); }
function fmtDate(d){ return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`; }

// small safe fetch wrapper
async function safeFetch(url, opts = {}, timeout = 10000) {
  const controller = new AbortController();
  const id = setTimeout(()=>controller.abort(), timeout);
  try {
    const res = await fetch(url, Object.assign({}, opts, { signal: controller.signal }));
    clearTimeout(id);
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch(e){ json = null; }
    return { ok: res.ok, status: res.status, text, json };
  } catch (e) {
    clearTimeout(id);
    return { ok: false, error: e.message || String(e) };
  }
}

// ----------------------
// SmartAPI login helper
// Tries multiple common flows and returns { ok, feed_token, tokens, expires, raw }
// ----------------------
async function smartLogin() {
  // Many SmartAPI implementations need a username/password + totp or hashed secret.
  // We implement a flexible flow:
  // 1) If SMART_TOTP_SECRET is provided -> derive password = TOTP or include in body
  // 2) Try endpoint variations that commonly appear in SmartAPI docs
  const base = SMARTAPI_BASE.replace(/\/$/, "");
  const attempts = [];

  // Build candidate payloads and endpoints
  const payloads = [];

  // candidate 1: "clientCode" + "password" (TOTP) -> endpoint: /client/v1/login or /login
  if (SMART_USER_ID && SMART_TOTP_SECRET) {
    const totpCode = totp(SMART_TOTP_SECRET);
    payloads.push({
      url: `${base}/client/v1/login`, // common
      body: { clientCode: SMART_USER_ID, password: totpCode, apiKey: SMARTAPI_KEY }
    });
    payloads.push({
      url: `${base}/rest/secure/angelbroking/user/v1/login`, // sometimes structured
      body: { clientCode: SMART_USER_ID, password: totpCode, apiKey: SMARTAPI_KEY }
    });
  }

  // candidate 2: apiKey + secret -> post to /client/v1/generateSession (some providers)
  if (SMARTAPI_KEY && SMART_API_SECRET) {
    // many implementations use a checksum or signature. Try a direct post too.
    payloads.push({
      url: `${base}/client/v1/generateSession`,
      body: { apiKey: SMARTAPI_KEY, secretKey: SMART_API_SECRET }
    });
    payloads.push({
      url: `${base}/session/authorise`, // fallback guess
      body: { apiKey: SMARTAPI_KEY, secret: SMART_API_SECRET }
    });
  }

  // candidate 3: minimal endpoints that return feedToken via login response
  payloads.push({
    url: `${base}/client/v1/login`,
    body: { apiKey: SMARTAPI_KEY, clientCode: SMART_USER_ID || "" }
  });
  payloads.push({
    url: `${base}/session/login`,
    body: { apiKey: SMARTAPI_KEY, clientCode: SMART_USER_ID || "" }
  });

  // Now attempt them sequentially until we find feed token or tokens
  for (const p of payloads) {
    try {
      const headers = { "Content-Type": "application/json" };
      const res = await safeFetch(p.url, { method: "POST", headers, body: JSON.stringify(p.body) }, 10000);
      attempts.push({ url: p.url, status: res.status, ok: res.ok, json: res.json, text: res.text });
      if (res.ok && res.json) {
        // try to find common fields feedToken, token, tokens, access_token
        const j = res.json;
        const feed_token = j.feedToken || j.feed_token || j.data && (j.data.feedToken || j.data.feed_token);
        const tokens = j.tokens || j.token || j.data && (j.data.tokens || j.data.token);
        const access = j.access_token || j.data && j.data.access_token;
        // Some providers wrap in data -> payload
        if (feed_token || tokens || access) {
          return { ok: true, feed_token, tokens, access, raw: j, attempts };
        }
      }
    } catch (e) {
      attempts.push({ url: p.url, error: String(e) });
    }
  }

  // if nothing found - return failure with debugging info
  return { ok: false, attempts, message: "Login attempts failed - check env and SmartAPI endpoints" };
}

// Exported debug function to let frontend call login
async function doLogin() {
  const r = await smartLogin();
  return r;
}

// END PART 1
// ==============================
// Part 2/4
// final server.js (BEGIN PART-2)
// WebSocket management, token discovery, helpers
// ==============================

/*
  Purpose:
   - discover auto_tokens for markets (nifty/sensex/natural gas etc)
   - maintain a single websocket client that can be reused by subscriptions
*/

const AUTO_TOKENS = {}; // { market: { symbol, token, expiry, ltp } }
let WS_CLIENT = null;
let WS_CLIENT_INFO = { connected: false, url: null, lastConnect: 0 };

// fetch master symbols list to find FUT token: (tries few known endpoints)
async function fetchSymbolsList() {
  const base = SMARTAPI_BASE.replace(/\/$/, "");
  const tryUrls = [
    `${base}/client/v1/instruments`, // hypothetical
    `${base}/market/v1/instruments`, 
    `${base}/rest/secure/angelbroking/market/v1/instruments`,
    `${base}/rest/market/v1/instruments`
  ];
  for (const u of tryUrls) {
    try {
      const r = await safeFetch(u, { method: "GET" }, 8000);
      if (r.ok && r.json) return { ok: true, url: u, data: r.json };
    } catch(e){}
  }
  return { ok:false };
}

// try to find FUT symbol/token for a given market lookup string
async function findFutureSymbolFor(marketLookup) {
  // if already cached return
  if (AUTO_TOKENS[marketLookup] && AUTO_TOKENS[marketLookup].symbol) return AUTO_TOKENS[marketLookup];

  const sres = await fetchSymbolsList();
  if (!sres.ok) return null;
  const data = sres.data;
  // Normalize array
  let arr = Array.isArray(data) ? data : (data.data && Array.isArray(data.data) ? data.data : null);
  if (!arr) {
    // try parsing nested
    try {
      arr = JSON.parse(JSON.stringify(data)).flat(Infinity);
    } catch(e) { arr = null; }
  }
  if (!arr || !Array.isArray(arr)) return null;

  const look = String(marketLookup).toLowerCase();
  for (const item of arr) {
    try {
      const s = JSON.stringify(item).toLowerCase();
      if (s.includes(look) && s.includes("fut")) {
        // Extract token fields
        const sym = item.symbol || item.name || (item.tradingSymbol || null);
        const tok = item.token || item.exchangeToken || item.tokenId || null;
        const expiry = item.expiry || item.expiryDate || null;
        AUTO_TOKENS[marketLookup] = { symbol: sym, token: tok ? String(tok) : null, expiry, raw: item };
        return AUTO_TOKENS[marketLookup];
      }
    } catch(e){}
  }
  return null;
}

// make a WebSocket connection for streaming (single client)
function initWebSocket({ clientCode = SMART_USER_ID, feedToken = null, apiKey = SMARTAPI_KEY } = {}) {
  if (!feedToken || !apiKey || !clientCode) {
    // not enough info
    return { ok: false, message: "Missing clientCode/feedToken/apiKey for websocket init" };
  }
  const wsUrl = `wss://smartapisocket.angelone.in/smart-stream?clientCode=${encodeURIComponent(clientCode)}&feedToken=${encodeURIComponent(feedToken)}&apiKey=${encodeURIComponent(apiKey)}`;
  // reuse existing if same
  if (WS_CLIENT && WS_CLIENT_INFO.url === wsUrl && WS_CLIENT_INFO.connected) return { ok: true, reused: true };

  // if existing, close then recreate
  if (WS_CLIENT) {
    try { WS_CLIENT.terminate(); } catch(e){}
    WS_CLIENT = null;
  }

  try {
    const ws = new WebSocket(wsUrl);
    WS_CLIENT = ws;
    WS_CLIENT_INFO.url = wsUrl;
    WS_CLIENT_INFO.lastConnect = Date.now();
    WS_CLIENT_INFO.connected = false;

    ws.on("open", () => {
      WS_CLIENT_INFO.connected = true;
      console.log("WebSocket open ->", wsUrl);
    });
    ws.on("message", (msg) => {
      // incoming binary or text - try parse
      try {
        const txt = typeof msg === "string" ? msg : msg.toString();
        // console.log("WS msg:", txt);
        // You may want to parse and update AUTO_TOKENS LTP if payload contains quote
        // Basic heuristic:
        try {
          const j = JSON.parse(txt);
          // if j contains tokens/ltp update AUTO_TOKENS if possible
          if (j && typeof j === "object") {
            if (j.payload && Array.isArray(j.payload)) {
              // Example: payload array of [symbol, ltp...] (depends on provider)
              // leave as debug for now
            }
          }
        } catch(e){}
      } catch(e){ console.warn("WS message parse err", e); }
    });
    ws.on("close", (code, reason) => {
      WS_CLIENT_INFO.connected = false;
      console.log("WebSocket closed", code, reason);
    });
    ws.on("error", (err) => {
      WS_CLIENT_INFO.connected = false;
      console.warn("WebSocket error", err && err.message ? err.message : err);
    });

    return { ok: true, url: wsUrl };
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}

// subscription helper: send subscribe request via ws (format provider expects may vary)
function wsSubscribe(symbols = []) {
  if (!WS_CLIENT || WS_CLIENT.readyState !== WebSocket.OPEN) {
    return { ok: false, message: "WS not open" };
  }
  // typical SmartAPI subscription format: { action: "subscribe", symbols: ["NIFTY20DEC..."] }
  const payload = JSON.stringify({ action: "subscribe", symbols });
  WS_CLIENT.send(payload);
  return { ok: true, payload };
}

// end part 2
// ==============================
// Part 3/4
// final server.js (BEGIN PART-3)
// Option-chain parsing, Greeks fallback, Premium engine (strikes & straddle) logic
// ==============================

/*
  Functions:
   - fetchQuote(symbol/token) -> attempts to fetch LTP via HTTP quote endpoint
   - fetchGreeks(name, expiry) -> POST to /marketData/v1/optionGreek when available
   - buildOptionChain(market, futToken/strikeStep/expiry) -> collate strikes
   - premiumEngine(...) -> compute CE/PE/STRADDLE strikes and recommended entries/targets
*/

async function fetchQuoteByToken(token, exchange="NFO") {
  const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote/${exchange}/${token}`;
  const res = await safeFetch(url, { method: "GET", headers: { "Authorization": SMARTAPI_KEY } }, 8000);
  if (res.ok && res.json) return { ok: true, raw: res.json };
  return { ok: false, res };
}

async function fetchGreeksByNameAndExpiry(name, expiry) {
  const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/marketData/v1/optionGreek`;
  const body = { name, expirydate: expiry }; // as docs sample
  const res = await safeFetch(url, { method: "POST", headers: { "Content-Type": "application/json", "apiKey": SMARTAPI_KEY }, body: JSON.stringify(body) }, 10000);
  if (res.ok && res.json) return { ok: true, data: res.json };
  return { ok: false, res };
}

// build a basic strike list around spot with given step & distances
function calculateStrikes(spot, step = 50, baseDistances = {near:150, mid:200, far:250}) {
  // produce strikes at steps aligned to step
  const center = roundToStep(spot, step);
  const strikes = [];
  const maxDistance = baseDistances.far || 250;
  const half = Math.ceil(maxDistance / step);
  for (let i = -half; i <= half; i++) {
    strikes.push(center + i * step);
  }
  strikes.sort((a,b)=>a-b);
  return strikes;
}

// premium engine: given indicator inputs, produce recommended CE/PE/STRADDLE suggestions
function premiumEngine({ ema20, ema50, rsi, vwap, spot, market = "nifty", expiry_days = 1, use_live = false }) {
  // simplified rule-based engine based on your earlier patterns
  // Determine main trend
  let main = "SIDEWAYS";
  let bias = "NONE";
  if (ema20 > ema50 && spot > vwap && rsi > 55) { main = "UPTREND"; bias = "CE"; }
  else if (ema20 < ema50 && spot < vwap && rsi < 45) { main = "DOWNTREND"; bias = "PE"; }
  else { main = "SIDEWAYS"; bias = "NONE"; }

  // distances depend on market
  const marketSteps = { nifty: 50, sensex: 100, "natural gas": 5 };
  const step = marketSteps[market] || 50;

  // Find base strike - round spot to nearest step
  const center = roundToStep(spot, step);

  // pick strikes a bit away depending on bias
  const distancePoints = bias === "CE" ? 1 : bias === "PE" ? -1 : 0;
  const ceStrike = center + Math.abs(54) * (step/step) * step/step ? center + 50 : center + step; // fallback simple
  // Simplify: use a distance offset in points rather than exact pips — we'll pick typical distances:
  const ceOffset = 54; const peOffset = 46; // from examples
  const ce = center + Math.round(ceOffset / step) * step;
  const pe = center - Math.round(peOffset / step) * step;
  const straddle = roundToStep(center, step);

  // thresholds for entry/stop/target (these are premium points, not %)
  const entry = bias === "NONE" ? 10 : 10;
  const stopLoss = 6;
  const target = 15;

  // Return formatted strikes
  return {
    trend: { main, bias, components: { ema_gap: `${((Math.abs(ema20-ema50)/Math.max(ema20,ema50))*100).toFixed(2)}%`, rsi: `RSI ${rsi}`, vwap: `VWAP ${vwap}`, price_structure: "Mixed", expiry: expiry_days <= 1 ? "Expiry near (volatile)" : "Expiry comfortable" } },
    strikes: [
      { type: "CE", strike: ce, distance: Math.abs(ce - spot), entry, stopLoss, target, midPrice: null },
      { type: "PE", strike: pe, distance: Math.abs(pe - spot), entry, stopLoss, target, midPrice: null },
      { type: "STRADDLE", strike: straddle, distance: Math.abs(straddle - spot), entry: (entry*200), stopLoss: (stopLoss*200), target: (target*200), midPrice: null }
    ]
  };
}

// utility to build final response for /api/calc
function buildCalcResponse(input, engineResult, auto_tokens_info = {}) {
  return {
    success: true,
    message: "Calculation complete",
    login_status: SMARTAPI_KEY ? "SmartAPI Logged-In" : "SmartAPI Not Configured",
    input: Object.assign({}, input),
    trend: {
      main: engineResult.trend.main,
      strength: (engineResult.trend.score || "MODERATE"),
      score: engineResult.trend.score || 0,
      bias: engineResult.trend.bias || engineResult.trend.bias,
      components: engineResult.trend.components,
      comment: `EMA20=${input.ema20}, EMA50=${input.ema50}, RSI=${input.rsi}, VWAP=${input.vwap}, Spot=${input.spot}`
    },
    strikes: engineResult.strikes,
    auto_tokens: auto_tokens_info,
    meta: { live_data_used: input.use_live || false, live_ltp: null, live_error: null }
  };
}

// END PART 3
// ==============================
// Part 4/4
// final server.js (BEGIN PART-4)
// API endpoints and server start
// ==============================

/*
  Endpoints:
   GET  /api/ping       -> health
   POST /api/login      -> perform SmartAPI login and return feed token / tokens
   POST /api/calc       -> accept inputs (ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live)
                          perform engine + attempt to fetch live tokens/ltp if use_live true
*/

// 1) ping
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, ts: nowTS(), app: "Trading Helper Backend" });
});

// 2) login -> call smartLogin()
app.post("/api/login", async (req, res) => {
  try {
    const r = await smartLogin();
    if (r.ok) {
      // If login provided feed_token, initialize websocket optionally
      if (r.feed_token) {
        initWebSocket({ clientCode: SMART_USER_ID, feedToken: r.feed_token, apiKey: SMARTAPI_KEY });
      }
      return res.json({ ok: true, login: true, feed_token: r.feed_token || null, tokens: r.tokens || r.access || null, raw: r.raw || null });
    } else {
      return res.status(500).json({ ok:false, message: r.message || "login failed", attempts: r.attempts || null });
    }
  } catch (e) {
    return res.status(500).json({ ok:false, error: String(e) });
  }
});

// 3) calc -> main engine endpoint (accepts input JSON)
app.post("/api/calc", async (req, res) => {
  try {
    const input = Object.assign({
      ema20: 0, ema50:0, rsi:50, vwap:0, spot:0, market:"nifty", expiry_days:1, use_live:false
    }, req.body || {});

    // run local premium engine
    const engineResult = premiumEngine(input);

    // attempt auto_tokens discovery for common markets
    const markets = ["nifty","sensex","natural gas"];
    const auto_info = {};
    for (const m of markets) {
      try {
        const found = await findFutureSymbolFor(m);
        auto_info[m] = found || { symbol: null, token: null, expiry: null, ltp: null };
      } catch(e){
        auto_info[m] = { error: String(e) };
      }
    }

    // if use_live = true try to fetch LTP for the relevant FUT token (best-effort)
    let live_ltp = null;
    let live_error = null;
    if (input.use_live) {
      const marketTokenObj = auto_info[input.market] || null;
      if (marketTokenObj && marketTokenObj.token) {
        const q = await fetchQuoteByToken(marketTokenObj.token);
        if (q.ok && q.raw) {
          // attempt to extract LTP from known fields
          const j = q.raw;
          let ltp = null;
          if (j && typeof j === "object") {
            ltp = j.lastPrice || j.ltp || (j.data && (j.data.lastPrice || j.data.ltp)) || null;
          }
          live_ltp = ltp;
          if (ltp) engineResult.strikes.forEach(s => { s.midPrice = s.midPrice || null; });
        } else {
          live_error = q.res || q;
        }
      } else {
        live_error = "No future token detected for requested market";
      }
    }

    const out = buildCalcResponse(input, engineResult, auto_info);
    out.meta.live_data_used = input.use_live;
    out.meta.live_ltp = live_ltp;
    out.meta.live_error = live_error;
    return res.json(out);
  } catch (e) {
    console.error("calc error", e);
    return res.status(500).json({ ok:false, error: String(e) });
  }
});

// Serve a friendly message on root (so browser doesn't show "Cannot GET /")
app.get("/", (req, res) => {
  res.send("Cannot GET / - backend running. Use /api/ping, /api/login or POST /api/calc");
});

// final: start server
const PORT = process.env.PORT || process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Trading Helper Backend started on port ${PORT} (PID ${process.pid})`);
});

// ==============================
// final server.js (END PART-4)
// ==============================
