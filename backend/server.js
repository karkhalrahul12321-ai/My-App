// ==============================
// Part 1 / 4
// Final server.js (BEGIN PART-1)
// Trading Helper Backend - FINAL (Part 1)
// - imports, config, app init, SmartAPI login (TOTP-safe), single WebSocket import
// - robust env/fallback handling
// ==============================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const fetch = require("node-fetch"); // if node >=18 you can use global fetch; keep node-fetch for compatibility
const WebSocket = require("ws"); // <- single import only (do NOT re-declare later)
require("dotenv").config();

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(bodyParser.urlencoded({ extended: true }));

const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;
function nowTS(){ return new Date().toISOString(); }

// Environment keys & safe fallbacks
const SMART_API_KEY = process.env.SMART_API_KEY || process.env.SMART_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || process.env.SMART_SECRET || "";
const SMART_TOTP = process.env.SMART_TOTP || process.env.SMART_TOTP_SECRET || "";
const SMART_USER_ID = process.env.SMART_USER_ID || process.env.SMART_USER || "";

// Basic verification
const missingEnv = [];
if (!SMART_API_KEY) missingEnv.push("SMART_API_KEY");
if (!SMART_API_SECRET) missingEnv.push("SMART_API_SECRET");
if (!SMART_USER_ID) missingEnv.push("SMART_USER_ID");
// TOTP can be optional for some flows, but warn if missing for TOTP login:
if (!SMART_TOTP) console.warn("[WARN] SMART_TOTP not set - TOTP login may fail for TOTP-required accounts.");

// In-memory runtime store (safe for single-instance; persistent store advisable for prod)
const runtime = {
  session: null,           // SmartAPI session object { access_token, refresh_token, expires_at ... }
  feed_token: null,        // feed_token from SmartAPI (for websocket)
  auto_tokens: {},         // auto instrument tokens per market (nifty/sensex/natural gas)
  last_login_ts: null,
  last_login_resp: null,
};

// Utility helpers
function safeNum(v, d=0){ const n = Number(v); return Number.isFinite(n) ? n : d; }
function clamp(v, min, max){ return Math.max(min, Math.min(max, v)); }
function roundToStep(v, step){ if (!step) return v; return Math.round(v/step)*step; }
function fmtDate(d){ return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`; }

function debugLog(...args){ if (process.env.DEBUG && process.env.DEBUG !== "0") console.log(...args); }

// SmartAPI endpoints (these may vary by broker; adjust if you have custom baseURL)
const SMART_BASE = process.env.SMART_BASE_URL || "https://developerapi.smith.ai/smartapi"; // fallback placeholder — replace with actual SmartAPI base if needed

// ------- Safe fetch wrapper with JSON parse & timeouts
async function httpFetch(url, opts = {}, timeout = 15000) {
  const controller = new AbortController();
  const id = setTimeout(()=>controller.abort(), timeout);
  try {
    const res = await fetch(url, { signal: controller.signal, ...opts });
    clearTimeout(id);
    const text = await res.text();
    try { return { ok: res.ok, status: res.status, json: JSON.parse(text), text }; }
    catch(e){ return { ok: res.ok, status: res.status, json: null, text }; }
  } catch (err) {
    clearTimeout(id);
    return { ok: false, status: 0, error: err.message || String(err) };
  }
}

// Helper: compute TOTP if needed (if SMART_TOTP is secret key, user probably provided base32 secret)
function computeTotp(secret) {
  // Basic TOTP using SHA1, 6 digits, 30s step, secret in base32.
  // Minimal implementation; if secret already numeric TOTP provided, return it.
  if (!secret) return null;
  if (/^\d+$/.test(secret) && secret.length >= 4 && secret.length <= 8) return secret; // already a code
  // else assume base32 secret -> convert
  const base32 = (s) => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    let output = "";
    for (let i=0;i<s.length;i++){
      const val = alphabet.indexOf(s[i].toUpperCase());
      if (val < 0) continue;
      bits += val.toString(2).padStart(5,"0");
      while (bits.length >= 8){
        output += String.fromCharCode(parseInt(bits.slice(0,8),2));
        bits = bits.slice(8);
      }
    }
    return output;
  };
  try {
    // Simple approach: if it's base32 -> HMAC-SHA1 with timecounter
    // Note: This is lightweight; for production use a proven TOTP library.
    const secretBytes = base32(secret);
    const epoch = Math.floor(Date.now() / 1000.0);
    const time = Math.floor(epoch / 30);
    const timeBuf = Buffer.alloc(8);
    timeBuf.writeUInt32BE(Math.floor(time / Math.pow(2,32)), 0);
    timeBuf.writeUInt32BE(time >>> 0, 4);
    const hmac = crypto.createHmac("sha1", secretBytes).update(timeBuf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
    return String(code).padStart(6, "0");
  } catch (e) {
    return null;
  }
}

// SmartAPI login (TOTP) - robust with multiple fallback field names handling
async function smartLogin() {
  // If we have cached session and not expired, return it
  if (runtime.session && runtime.session.access_token && runtime.session.expires_at) {
    if (Date.now() < runtime.session.expires_at - 30*1000) {
      return { ok: true, cached: true, session: runtime.session };
    }
  }

  // Build login body — many SmartAPI variants accept different fields; try common ones
  const totpCode = computeTotp(SMART_TOTP) || process.env.SMART_TOTP_CODE || "";
  const body = {
    apiKey: SMART_API_KEY,
    secretKey: SMART_API_SECRET,
    userId: SMART_USER_ID,
  };
  // include totp if available
  if (totpCode) body.totp = totpCode;

  // try a couple of likely endpoints
  const candidateUrls = [
    (process.env.SMART_BASE_URL || SMART_BASE).replace(/\/$/,'') + "/session/login",
    (process.env.SMART_BASE_URL || SMART_BASE).replace(/\/$/,'') + "/login",
    (process.env.SMART_BASE_URL || SMART_BASE).replace(/\/$/,'') + "/smartapi/session"
  ];

  let lastErr = null;
  for (const url of candidateUrls) {
    try {
      const r = await httpFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      }, 20000);
      if (!r.ok) { lastErr = r; continue; }
      const json = r.json || null;
      if (!json) { lastErr = r; continue; }

      // Normalize common response shapes:
      // e.g. { data: { access_token: '...', expires_in: 3600, feedToken: '...' }, status: true }
      // or { access_token: ..., refresh_token: ... }
      let session = {};
      if (json.data && typeof json.data === "object") session = json.data;
      else session = json;

      // Map fields to our runtime.session
      const access_token = session.access_token || session.token || session.authToken || session.session || session["accessToken"];
      const refresh_token = session.refresh_token || session.refreshToken || session.refresh;
      const expires_in = safeNum(session.expires_in || session.expires || session.ttl, 3600);
      const feedToken = (session.feed_token || session.feedToken || session.feed) || null;
      if (!access_token) {
        lastErr = { ok: false, detail: "no_access_token", url, session };
        continue;
      }

      const expires_at = Date.now() + (expires_in * 1000);
      runtime.session = {
        access_token, refresh_token, expires_in, expires_at, raw: session
      };
      runtime.feed_token = feedToken || runtime.feed_token || null;
      runtime.last_login_ts = Date.now();
      runtime.last_login_resp = { url, raw: json };
      debugLog("[smartLogin] success", { access_token: !!access_token, feedToken: !!feedToken });
      return { ok: true, session: runtime.session, feed_token: runtime.feed_token };
    } catch (err) {
      lastErr = err;
    }
  }

  return { ok: false, error: "LOGIN_FAILED", detail: lastErr };
}

// Expose a ping for health checks
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, ts: nowTS(), app: "Trading Helper Backend" });
});

// Expose settings for frontend to show which envs are present (safe: do not print secrets)
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY ? "SET" : "",
    userId: SMART_USER_ID ? "SET" : "",
    totp: SMART_TOTP ? "SET" : ""
  });
});

// END PART-1
// ==============================
// Part 2 / 4
// server.js (BEGIN PART-2)
// - auto future token discovery (robust parsing of instrument lists)
// - getAutoFutureLTP via HTTP (safe, returns tokens & optionally ltp if available)
// ==============================

// Function: fetch instruments or market snapshot to auto-resolve FUT symbols and tokens
// This function tries a few common SmartAPI endpoints and parses possible shapes.
async function discoverAutoTokenForMarket(market) {
  // market: 'nifty', 'sensex', 'natural gas' (string)
  const name = String(market || "").toLowerCase();
  const tryUrls = [
    (process.env.SMART_BASE_URL || SMART_BASE) + "/instruments",
    (process.env.SMART_BASE_URL || SMART_BASE) + "/market/instruments",
    (process.env.SMART_BASE_URL || SMART_BASE) + "/reference/instruments"
  ];
  let found = null;
  for (const url of tryUrls) {
    const r = await httpFetch(url, { method: "GET" }, 15000);
    if (!r.ok || !r.json) continue;
    const data = r.json;
    // Support arrays at top-level or .data arrays
    const arr = Array.isArray(data) ? data : (Array.isArray(data.data) ? data.data : null);
    if (!arr) continue;
    // try to match by symbol or name
    try {
      const lowerLookup = name;
      const fut = arr.find(x => {
        try {
          const s = (String(x.symbol || x.name || x.displaySymbol || x.tradingsymbol || x.instrumentName || "")).toLowerCase();
          const joined = JSON.stringify(x).toLowerCase();
          return (s.includes(lowerLookup) || joined.includes(lowerLookup)) && (s.includes("fut") || joined.includes("fut"));
        } catch(e){ return false; }
      });
      if (fut) {
        // extract token if available (token, exchangeToken, tokenId etc.)
        let sym = fut.symbol || fut.tradingsymbol || fut.name || (fut.instrumentName) || String(fut);
        let tok = fut.token || fut.exchangeToken || fut.tokenId || fut.instrumentToken || fut.instrument_token || null;
        found = { raw: fut, symbol: sym, token: tok ? String(tok) : null };
        break;
      }
    } catch (e) { continue; }
  }
  return found;
}

// getAutoFutureLTP: tries to get token+symbol for each default market
async function getAutoFutureLTP() {
  const markets = ["nifty","sensex","natural gas"];
  const result = {};
  for (const m of markets) {
    try {
      const existing = runtime.auto_tokens[m];
      if (existing && existing.symbol && existing.token) {
        result[m] = existing;
        continue;
      }
      const found = await discoverAutoTokenForMarket(m);
      if (found) {
        runtime.auto_tokens[m] = { symbol: found.symbol || null, token: found.token || null, expiry: null, ltp: null };
        result[m] = runtime.auto_tokens[m];
      } else {
        runtime.auto_tokens[m] = { symbol: null, token: null, expiry: null, ltp: null };
        result[m] = runtime.auto_tokens[m];
      }
    } catch (e) {
      runtime.auto_tokens[m] = { symbol: null, token: null, expiry: null, ltp: null };
      result[m] = runtime.auto_tokens[m];
    }
  }
  return result;
}

// get live LTP for a token via SmartAPI HTTP (not websocket). Robust parse.
async function getLTPForToken(token, marketInfo = {}) {
  if (!token) return { ok: false, error: "NO_TOKEN" };
  const urlCandidates = [
    (process.env.SMART_BASE_URL || SMART_BASE) + `/market/ltp/${token}`,
    (process.env.SMART_BASE_URL || SMART_BASE) + `/ltp/${token}`,
    (process.env.SMART_BASE_URL || SMART_BASE) + `/marketdata/ltp?token=${token}`
  ];
  for (const url of urlCandidates) {
    const r = await httpFetch(url, { method: "GET" }, 10000);
    if (!r.ok) continue;
    const j = r.json || null;
    if (!j) continue;
    // Look for LTP values in multiple possible fields
    const candidateVals = [];
    if (typeof j === "object") {
      const addIf = (v) => { if (v!==null && v!==undefined && v!=="") candidateVals.push(v); };
      addIf(j.ltp || j.lastPrice || j.lp || j.last_traded_price || (j.data && j.data.ltp));
      // deep search few fields
      try {
        const s = JSON.stringify(j).toLowerCase();
        const m = s.match(/"ltp"\s*:\s*([\d.]+)/);
        if (m) addIf(Number(m[1]));
      } catch(e){}
    }
    if (candidateVals.length) return { ok:true, ltp: safeNum(candidateVals[0], null), raw: j };
    // fallback if text contains number
    try {
      const txt = (r.text || "");
      const m = txt.match(/"lastPrice"\s*:\s*([\d.]+)/) || txt.match(/"ltp"\s*:\s*([\d.]+)/);
      if (m) return { ok:true, ltp: safeNum(Number(m[1]), null), raw: j };
    } catch(e){}
  }
  return { ok:false, error: "LTP_NOT_FOUND" };
}

// Endpoint: /api/autofetch -> run discovery + LTP fetch
app.get("/api/autofetch", async (req, res) => {
  try {
    // Ensure logged in (try login but don't crash if fails)
    const loginResp = await smartLogin();
    if (!loginResp.ok) debugLog("[autofetch] login failed or not ok", loginResp);

    const tokens = await getAutoFutureLTP();
    // Try fetch LTP for each token
    for (const k of Object.keys(tokens)) {
      const t = tokens[k];
      if (t && t.token) {
        const l = await getLTPForToken(t.token);
        if (l.ok) {
          t.ltp = l.ltp;
          t.raw_ltp = l.raw;
        } else {
          t.ltp = null;
        }
      } else {
        t.ltp = null;
      }
    }
    res.json({ ok: true, auto_tokens: runtime.auto_tokens, login: !!runtime.session });
  } catch (e) {
    res.json({ ok: false, error: "AUTOFETCH_FAILED", detail: String(e) });
  }
});

// END PART-2
// ==============================
// Part 3 / 4
// server.js (BEGIN PART-3)
// - Premium engine: option-chain minimal parser + strikes calculation
// - Endpoints: /api/ltp (single), /api/calc (main calculation using input or live LTP)
// - All functions async/await safe; no blocking placeholders
// ==============================

// DEFAULT MARKET RULES (strike step, expiry heuristics)
const FUTURE_RULES = {
  nifty: { searchSymbol: "NIFTY", exchange: "NFO", instrumentType: "FUTIDX", strikeStep: 50, baseDistances: { far: 250, mid: 200, near: 150 }, expiryDay: 4 },
  sensex: { searchSymbol: "SENSEX", exchange: "BFO", instrumentType: "FUTIDX", strikeStep: 100, baseDistances: { far: 500, mid: 400, near: 300 }, expiryDay: 4 },
  "natural gas": { searchSymbol: "NATURAL GAS", exchange: "MCX", instrumentType: "FUT", strikeStep: 5, baseDistances: { far: 80, mid: 60, near: 50 } }
};

// Minimal premium engine: calculate trend components and choose strikes
function calculateTrendAndStrikes(input) {
  // input should contain: ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live
  const ema20 = safeNum(input.ema20, 0);
  const ema50 = safeNum(input.ema50, 0);
  const rsi = safeNum(input.rsi, 50);
  const vwap = safeNum(input.vwap, 0);
  const spot = safeNum(input.spot, 0);
  const market = String(input.market || "nifty").toLowerCase();
  const expiry_days = safeNum(input.expiry_days, 3);

  // Basic trend scoring (toy engine — replace with your full logic if needed)
  let score = 50;
  let bias = "NONE";
  // ema gap
  const gapPct = ema20 && ema50 ? ( (ema20 - ema50) / ema50 ) * 100 : 0;
  if (gapPct > 0.5) { score += 20; bias = "CE"; }
  else if (gapPct < -0.5) { score -= 20; bias = "PE"; }
  // rsi
  if (rsi > 60) { score += 10; bias = bias || "CE"; }
  if (rsi < 40) { score -= 10; bias = bias || "PE"; }
  // vwap proximity
  const nearVwap = Math.abs((spot - vwap) / (vwap || 1)) * 100;
  if (nearVwap < 0.1) score += 5;

  // Normalize score
  score = clamp(Math.round(score), 0, 100);
  let strength = "RANGE";
  if (score > 65) strength = "TREND";
  else if (score < 30) strength = "WEAK";

  const main = (score > 55) ? (bias === "CE" ? "UPTREND" : "DOWNTREND") : "SIDEWAYS";

  // strikes selection
  const rule = FUTURE_RULES[market] || FUTURE_RULES["nifty"];
  const step = rule.strikeStep || 50;
  // choose ATM based on spot rounded to step
  const atm = roundToStep(spot, step);
  // distances: pick sensible distances using rule.baseDistances
  const baseD = rule.baseDistances || { near: 150, mid:200, far:250 };
  // choose strikes
  const ceStrike = atm + Math.round(baseD.mid/ step) * step;
  const peStrike = atm - Math.round(baseD.mid/ step) * step;
  const straddleStrike = atm;

  const strikes = [
    { type: "CE", strike: ceStrike, distance: Math.abs(ceStrike - spot), entry: 10, stopLoss: 6, target: 15, midPrice: null },
    { type: "PE", strike: peStrike, distance: Math.abs(peStrike - spot), entry: 10, stopLoss: 6, target: 15, midPrice: null },
    { type: "STRADDLE", strike: straddleStrike, distance: Math.abs(straddleStrike - spot), entry: 2000, stopLoss: 1200, target: 3000, midPrice: null }
  ];

  const meta = { live_data_used: !!input.use_live, live_ltp: null, live_error: null };

  return {
    ok: true,
    input: { ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live: !!input.use_live },
    trend: { main, strength, score, bias, components: { ema_gap: `${gapPct.toFixed(2)}%`, rsi: `RSI ${rsi}`, vwap: `Near VWAP`, price_structure: "Mixed structure", expiry: "Expiry mid" }, comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}` },
    strikes,
    auto_tokens: runtime.auto_tokens,
    meta
  };
}

// Endpoint: /api/ltp (for single token) - simple wrapper
app.post("/api/ltp", async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.json({ ok: false, error: "NO_TOKEN" });
  const r = await getLTPForToken(token);
  res.json(r);
});

// Endpoint: /api/calc - main entry (accepts body or uses live LTPs + autofetch)
app.post("/api/calc", async (req, res) => {
  try {
    const body = req.body || {};
    // If user wants live LTP, ensure autofetch run
    if (body.use_live) {
      // ensure logged in and tokens discovered
      await smartLogin().catch(e=>console.warn("[calc] login fail", e));
      await getAutoFutureLTP().catch(e=>console.warn("[calc] autofetch fail", e));
      // try to assign spot from auto token if provided market
      const market = (body.market || "nifty").toLowerCase();
      const tok = runtime.auto_tokens[market];
      if (tok && tok.token) {
        const l = await getLTPForToken(tok.token);
        if (l.ok) {
          body.spot = l.ltp;
          // also annotate meta
        } else {
          // leave body.spot as provided
        }
      }
    }
    // If spot still missing, require a spot input; if not present, error
    if (!("spot" in body) || body.spot === null || body.spot === undefined) {
      return res.json({ success: false, message: "Missing spot value; set spot in request or enable use_live with valid tokens."});
    }
    // Run engine
    const out = calculateTrendAndStrikes(body);
    // attach live error/meta
    out.meta = out.meta || {};
    out.meta.live_data_used = !!body.use_live;
    res.json({ success: true, message: "Calculation complete", login_status: runtime.session ? "SmartAPI Logged-In" : "SmartAPI Not Logged-In", input: out.input, trend: out.trend, strikes: out.strikes, auto_tokens: runtime.auto_tokens, meta: out.meta });
  } catch (e) {
    res.json({ success: false, error: String(e) });
  }
});

// END PART-3
// ==============================
// Part 4 / 4
// server.js (BEGIN PART-4)
// - WebSocket-ready: single connect function (uses runtime.feed_token when present)
// - SPA fallback (serve static if needed) and server start
// - Careful to not redeclare modules/vars
// ==============================

let wsClient = null;
let wsConnected = false;

// Build websocket URL from feed token (SmartAPI specific — adjust to your provider)
function buildFeedWSUrl(feedToken) {
  // NOTE: provider-specific. Example placeholder:
  if (!feedToken) return null;
  // Example: wss://feed.smartapi.com?feed_token=...
  const baseWS = process.env.SMART_FEED_WS || "wss://feed.smartapi.example/ws";
  return `${baseWS}?feed_token=${encodeURIComponent(feedToken)}`;
}

// Connect to websocket feed (non-blocking)
async function connectFeedWebSocket() {
  if (wsConnected) return { ok: true, message: "already_connected" };
  try {
    if (!runtime.feed_token) {
      debugLog("[connectFeedWebSocket] no feed token available");
      return { ok: false, error: "NO_FEED_TOKEN" };
    }
    const url = buildFeedWSUrl(runtime.feed_token);
    if (!url) return { ok: false, error: "NO_WS_URL" };

    wsClient = new WebSocket(url, { handshakeTimeout: 15000 });

    wsClient.on("open", () => {
      wsConnected = true;
      console.log("[feed] ws open");
    });

    wsClient.on("message", (data) => {
      try {
        // Many providers send gzipped payloads — handle basic zlib inflate/gunzip
        let msg = data;
        if (Buffer.isBuffer(msg)) {
          // try to gunzip or use as utf8
          try {
            msg = zlib.gunzipSync(msg).toString("utf8");
          } catch(e) {
            try { msg = zlib.inflateSync(msg).toString("utf8"); } catch(e2) { msg = msg.toString("utf8"); }
          }
        }
        let parsed = null;
        try { parsed = JSON.parse(msg); } catch(e){ parsed = msg; }
        debugLog("[feed msg]", parsed);
        // TODO: decode feed messages to update runtime.auto_tokens LTPs or option chain cache
        // Example: if parsed contains token & ltp, update runtime.auto_tokens
        try {
          if (parsed && parsed.token && parsed.ltp) {
            for (const mk of Object.keys(runtime.auto_tokens)) {
              if (runtime.auto_tokens[mk] && runtime.auto_tokens[mk].token === String(parsed.token)) {
                runtime.auto_tokens[mk].ltp = parsed.ltp;
              }
            }
          }
        } catch(e){}
      } catch (e) {
        console.warn("[feed message error]", e);
      }
    });

    wsClient.on("close", (code, reason) => {
      wsConnected = false;
      console.log(`[feed] ws closed ${code} ${String(reason).slice(0,80)}`);
      // auto reconnect after delay
      setTimeout(()=>{ connectFeedWebSocket().catch(()=>{}); }, 5000);
    });

    wsClient.on("error", (err) => {
      wsConnected = false;
      console.warn("[feed] ws error", err && err.message ? err.message : String(err));
      try { wsClient.close(); } catch(e){}
    });

    return { ok: true, url };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

// Endpoint to start feed ws (manual trigger)
app.post("/api/feed/connect", async (req, res) => {
  const r = await smartLogin().catch(e=>({ok:false,err:e}));
  if (!r.ok && !runtime.feed_token) {
    // attempt: maybe login provided feed token in runtime
    console.log("[feed connect] login not ok:", r);
  }
  const started = await connectFeedWebSocket();
  res.json(started);
});

// Endpoint: return runtime status (for debugging)
app.get("/api/status", (req, res) => {
  res.json({
    ok: true,
    session: !!runtime.session,
    feed_token: !!runtime.feed_token,
    auto_tokens: runtime.auto_tokens,
    ws: { connected: wsConnected }
  });
});

// SPA fallback (serve static build if exists)
const staticDir = path.join(__dirname, "public");
app.use(express.static(staticDir));
app.get("/", (req, res, next) => {
  // if index.html present serve it, else show basic info
  const indexFile = path.join(staticDir, "index.html");
  if (require("fs").existsSync(indexFile)) return res.sendFile(indexFile);
  res.json({ ok: true, message: "Trading Helper Backend running", ts: nowTS() });
});

// Graceful error handler
app.use((err, req, res, next) => {
  console.error("[server error]", err && err.stack ? err.stack : err);
  res.status(500).json({ ok:false, error: String(err) });
});

// Start server
app.listen(PORT, async () => {
  console.log(`Server started on port ${PORT} @ ${nowTS()}`);
  // Try initial auto fetch and login (non-blocking)
  try {
    const L = await smartLogin();
    debugLog("[startup] login", L && L.ok);
    await getAutoFutureLTP();
    // if feed token exists try WS connect (non-blocking)
    if (runtime.feed_token) {
      setTimeout(()=>connectFeedWebSocket().catch(e=>console.warn("[startup feed connect err]", e)), 500);
    }
  } catch(e){ console.warn("[startup] init failed", e); }
});

// END PART-4
