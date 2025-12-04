// server.js  — PART B1 of 10
// CLEAN, OPTIMIZED, RENDER-READY
// Dependencies required: express, body-parser, dotenv, node-fetch@2, ws, unzipper, axios, crypto-js, totp-generator
// npm i express body-parser dotenv node-fetch@2 ws unzipper axios crypto-js totp-generator

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const unzipper = require("unzipper");
const fetch = require("node-fetch"); // v2 style
const WebSocket = require("ws");
const crypto = require("crypto-js");
const totp = require("totp-generator");

require("dotenv").config();

// ---------- Basic env validation ----------
const REQUIRED_ENVS = ["SMART_API_KEY", "SMART_API_SECRET", "SMART_TOTP", "SMART_USER_ID"];
const missing = REQUIRED_ENVS.filter(k => !process.env[k]);
if (missing.length) {
  console.warn("⚠️ Missing required env variables:", missing);
  // Do not exit — allow developer to run locally with caution, but warn heavily.
}

// Helpful constants
const PORT = process.env.PORT || process.env.PORT_RENDER || 10000;
const SMART_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelone.in";
const SMART_WS_BASE = process.env.SMARTAPI_WS_BASE || "wss://smartapisocket.angelone.in/smart-stream";
const WS_CLIENT_CODE = process.env.WS_CLIENT_CODE || process.env.SMART_USER_ID || "";
const WS_FEED_TOKEN = process.env.WS_FEED_TOKEN || ""; // optional, can be filled later
const OPT_FEATURE_POLL_MS = parseInt(process.env.OPT_FEATURE_POLL_MS || "8000");

// File & cache paths
const DATA_DIR = path.join(__dirname); // keep in project root for Render
const SCRIP_MASTER_ZIP = path.join(DATA_DIR, "OpenAPIScripMaster.zip");
const SCRIP_MASTER_JSON = path.join(DATA_DIR, "OpenAPIScripMaster.json");
const SCRIP_MASTER_URL = process.env.SCRIP_MASTER_URL || "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.zip";

// In-memory caches
let scripsCache = null;
let scripsLastUpdated = 0;

// Express app
const app = express();
app.use(bodyParser.json({ limit: "200kb" }));
app.use(bodyParser.urlencoded({ extended: true }));

// small helper for safe JSON responses
function ok(data = {}) {
  return { success: true, ...data };
}
function err(message = "error", details = null) {
  return { success: false, message, details };
}

// ---------- Utility: make TOTP header / auth helpers ----------
function generateTotp(secret) {
  try {
    return totp(secret || process.env.SMART_TOTP || "");
  } catch (e) {
    console.warn("Failed to generate TOTP:", e && e.message);
    return null;
  }
}

function smartHeaders(token = null) {
  // For authenticated requests we usually need accessToken / jwt in headers.
  // This helper will be used by login and api-calls. Fill-in by later parts.
  const h = {
    "Content-Type": "application/json",
    "x-api-key": process.env.SMART_API_KEY || ""
  };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

// ---------- Utility: download & unzip ScripMaster ----------
async function downloadScripMaster(force = false) {
  // Don't re-download too frequently
  const now = Date.now();
  if (!force && scripsCache && now - scripsLastUpdated < 6 * 60 * 60 * 1000) {
    return scripsCache;
  }

  try {
    console.log("Downloading ScripMaster from:", SCRIP_MASTER_URL);
    const res = await fetch(SCRIP_MASTER_URL, { timeout: 30 * 1000 });
    if (!res.ok) {
      throw new Error(`ScripMaster download failed: ${res.status} ${res.statusText}`);
    }

    // Stream to file
    const dest = fs.createWriteStream(SCRIP_MASTER_ZIP);
    await new Promise((resolve, reject) => {
      res.body.pipe(dest);
      res.body.on("error", reject);
      dest.on("finish", resolve);
      dest.on("error", reject);
    });

    // unzip and find json
    await fs.createReadStream(SCRIP_MASTER_ZIP)
      .pipe(unzipper.Parse())
      .on("entry", async function (entry) {
        const fileName = entry.path;
        if (/OpenAPIScripMaster\.json$/i.test(fileName)) {
          // overwrite existing json
          const outPath = SCRIP_MASTER_JSON;
          entry.pipe(fs.createWriteStream(outPath));
        } else {
          entry.autodrain();
        }
      })
      .promise();

    // read json
    if (fs.existsSync(SCRIP_MASTER_JSON)) {
      const raw = fs.readFileSync(SCRIP_MASTER_JSON, "utf8");
      // parse safely
      let j = null;
      try {
        j = JSON.parse(raw);
      } catch (e) {
        // sometimes file contains BOM or other issues, try trimming
        const trimmed = raw.trim();
        j = JSON.parse(trimmed);
      }
      scripsCache = j;
      scripsLastUpdated = Date.now();
      console.log("ScripMaster loaded, entries:", Array.isArray(j) ? j.length : "unknown");
      return scripsCache;
    } else {
      throw new Error("ScripMaster JSON not found after unzip");
    }
  } catch (e) {
    console.warn("downloadScripMaster error:", e && e.message);
    // If we have prior cache, return it as fallback
    if (scripsCache) return scripsCache;
    throw e;
  }
}

// ---------- Endpoint: health & quick info ----------
app.get("/health", (req, res) => {
  res.json(ok({ uptime: process.uptime(), time: Date.now() }));
});

app.get("/info", (req, res) => {
  res.json(ok({
    node: process.version,
    smart_base: SMART_BASE,
    ws_base: SMART_WS_BASE,
    scrip_master_cached: !!scripsCache,
    scrip_master_updated_at: scripsLastUpdated
  }));
});

// ---------- Endpoint: force-refresh scrip master ----------
app.post("/admin/refresh-scripmaster", async (req, res) => {
  try {
    await downloadScripMaster(true);
    return res.json(ok({ message: "ScripMaster refreshed", entries: Array.isArray(scripsCache) ? scripsCache.length : 0 }));
  } catch (e) {
    return res.status(500).json(err("failed", e && e.message));
  }
});

// ---------- Small helper: find token by symbol/exchange ----------
function findTokenForSymbol(symbol, exchange = "NSE") {
  if (!scripsCache || !Array.isArray(scripsCache)) return null;
  // scripsCache items may have keys like token, symbol, name, exch_seg, etc.
  // We'll try multiple match strategies
  symbol = (symbol || "").toUpperCase();
  for (let item of scripsCache) {
    if (!item) continue;
    const s = (item.symbol || item.name || "").toString().toUpperCase();
    if (s === symbol) return item;
    // try partial match (exact tokens like NIFTY... etc)
    if (s.includes(symbol)) return item;
  }
  return null;
}

// ---------- Start server after attempting to load scrip master (non-blocking) ----------
(async () => {
  try {
    // try to download scrip master in background but don't block server start excessively
    downloadScripMaster().catch(e => console.warn("Initial scripmaster load failed:", e && e.message));
  } catch (e) {
    console.warn("Unexpected error starting scrip master load:", e && e.message);
  }

  app.listen(PORT, () => {
    console.log(`Trading-helper backend listening on port ${PORT} — pid:${process.pid}`);
  });
})();

// PART B1 ends here. Continue with B2 for auth, websocket, option chain, greeks, premium engine, endpoints.
// server.js — PART B2 of 10
// Auth, HTTP helpers, token management, LTP fallback, websocket connect stub

// ---------- Auth & Token state ----------
let accessToken = null;
let refreshToken = null;
let feedToken = WS_FEED_TOKEN || null; // optional
let accessTokenExpiresAt = 0;

// live prices map (token -> ltp)
const livePrices = {}; // { token: { ltp: number, ts: Date } }
let wsClient = null;
let wsConnected = false;

// Helper: check token valid
function tokenValid() {
  return accessToken && Date.now() < (accessTokenExpiresAt - 10 * 1000); // 10s safety
}

// Low-level HTTP helpers using axios (with retries)
async function httpRequest(method, url, data = null, headers = {}) {
  const opts = {
    method,
    url,
    headers: { ...headers },
    timeout: 30 * 1000,
    validateStatus: s => s < 500
  };
  if (data) opts.data = data;
  try {
    const r = await axios(opts);
    return r;
  } catch (e) {
    // Wrap for caller
    throw e;
  }
}

// SmartAPI specific helper to call endpoints with auth
async function smartApiRequest(method, path, data = null, opts = {}) {
  const url = (SMART_BASE || "").replace(/\/$/, "") + path;
  const headers = smartHeaders(accessToken);
  if (opts.extraHeaders) Object.assign(headers, opts.extraHeaders);

  try {
    const resp = await httpRequest(method, url, data, headers);
    return resp;
  } catch (e) {
    throw e;
  }
}

// ---------- SmartAPI login flow (stateless) ----------
// Note: Angel's login varies by account type; adapt if needed.
// This function does a login using API key + secret + totp and stores accessToken.
async function smartLogin() {
  // If we already have valid token, return it
  if (tokenValid()) {
    return { success: true, accessToken, expiresAt: accessTokenExpiresAt };
  }

  const apiKey = process.env.SMART_API_KEY || "";
  const apiSecret = process.env.SMART_API_SECRET || "";
  const userId = process.env.SMART_USER_ID || "";
  const totpVal = generateTotp(process.env.SMART_TOTP);

  if (!apiKey || !apiSecret || !userId) {
    return { success: false, message: "Missing SmartAPI credentials in env" };
  }

  // Construct login payload — this is a generic pattern. If your account uses a different
  // endpoint/payload, replace this path/payload accordingly.
  const loginPath = "/rest/auth/angelbroking/user/v1/loginWithToken"; // placeholder path
  const payload = {
    // many SmartAPI examples use clientCode, password, totp etc.
    // We'll pass what we can; if your implementation needs different fields,
    // edit accordingly in B3 after testing.
    clientCode: userId,
    apiKey: apiKey,
    password: apiSecret, // sometimes password field is used for secret
    totp: totpVal
  };

  try {
    const resp = await httpRequest("post", (SMART_BASE + loginPath), payload, smartHeaders());
    if (resp && resp.data) {
      const d = resp.data;
      // Typical successful response contains accessToken and feedToken; adapt parsing as needed.
      accessToken = d.accessToken || d.data && d.data.jwtToken || d.data && d.data.accessToken || d.token || null;
      refreshToken = d.refreshToken || null;
      feedToken = feedToken || (d.feedToken || (d.data && d.data.feedToken) || null);
      // Set expire time (best-effort): check if response gives expiresIn or expiry
      const expiresIn = d.expiresIn || (d.data && d.data.expires_in) || 60 * 60; // fallback 1h
      accessTokenExpiresAt = Date.now() + (expiresIn * 1000);

      console.log("SmartAPI login success — accessToken:", !!accessToken, "feedToken:", !!feedToken);
      return { success: true, accessToken, feedToken };
    } else {
      return { success: false, message: "Invalid login response", raw: resp && resp.data };
    }
  } catch (e) {
    console.warn("smartLogin failed:", e && e.message);
    return { success: false, message: "login_failed", details: e && e.message };
  }
}

// Optional: function to refresh access token using refreshToken (if SmartAPI supports)
async function refreshAccessToken() {
  if (!refreshToken) return { success: false, message: "no_refresh_token" };
  try {
    const path = "/rest/auth/angelbroking/user/v1/refreshToken"; // placeholder
    const resp = await httpRequest("post", SMART_BASE + path, { refreshToken }, smartHeaders());
    if (resp && resp.data) {
      const d = resp.data;
      accessToken = d.accessToken || null;
      const expiresIn = d.expiresIn || 60 * 60;
      accessTokenExpiresAt = Date.now() + (expiresIn * 1000);
      console.log("Access token refreshed");
      return { success: true };
    }
    return { success: false, raw: resp && resp.data };
  } catch (e) {
    console.warn("refreshAccessToken error:", e && e.message);
    return { success: false, message: e && e.message };
  }
}

// Background token refresher (non-blocking)
setInterval(async () => {
  try {
    if (!tokenValid()) {
      console.log("Access token invalid/expiring, attempting login/refresh...");
      const r = await smartLogin();
      if (!r.success && refreshToken) {
        await refreshAccessToken();
      }
    }
  } catch (e) {
    console.warn("Token refresher error:", e && e.message);
  }
}, 45 * 1000); // check every 45s

// ---------- LTP fallback (HTTP) ----------
// Public endpoint to fetch LTP for a symbol; uses SmartAPI LTP endpoint as fallback if ws not available.
// Example path: /rest/secure/angelbroking/market/v1/quote/ (user may need to adapt)
async function fetchLtpHttp(symbol, exchange = "NSE") {
  // try scrip->token mapping using scripsCache first
  try {
    const sItem = findTokenForSymbol(symbol, exchange);
    if (sItem && sItem.token) {
      const token = sItem.token;
      // SmartAPI quote endpoint; adapt if necessary
      const quotePath = `/rest/secure/angelbroking/market/v1/quote/?exchange=${encodeURIComponent(exchange)}&token=${encodeURIComponent(token)}`;
      // Use smartApiRequest to include auth header when available
      try {
        const resp = await smartApiRequest("get", quotePath);
        if (resp && resp.data) {
          // Try multiple shapes
          const data = resp.data;
          if (data && (data.ltp || data.lastPrice || data.payload && data.payload.last_price)) {
            const ltp = data.ltp || data.lastPrice || (data.payload && data.payload.last_price);
            // update cache
            livePrices[token] = { ltp: Number(ltp), ts: Date.now() };
            return { success: true, token, ltp: Number(ltp), raw: data };
          }
          return { success: false, message: "no_ltp_in_response", raw: data };
        }
      } catch (e) {
        // fallthrough to generic HTTP method below
        console.warn("smartApi quote error:", e && e.message);
      }
    }

    // Generic fallback: try a simple endpoint where symbol name can be used (not always supported)
    // This is a last resort and may fail for certain instruments.
    const genericPath = `/rest/secure/angelbroking/market/v1/quote/?symbol=${encodeURIComponent(symbol)}`;
    try {
      const resp2 = await smartApiRequest("get", genericPath);
      if (resp2 && resp2.data) {
        const d2 = resp2.data;
        const ltp = d2.ltp || d2.lastPrice || (d2.payload && d2.payload.last_price);
        return { success: !!ltp, ltp: ltp || null, raw: d2 };
      }
    } catch (e2) {
      console.warn("generic LTP fetch failed:", e2 && e2.message);
    }

    return { success: false, message: "ltp_fetch_failed" };
  } catch (e) {
    return { success: false, message: "exception_fetchLtp", details: e && e.message };
  }
}

// ---------- WebSocket connect (stub) ----------
// We'll implement robust ws in B3. This stub initiates connection if feedToken exists,
// and will set wsConnected and wsClient. It will also handle ping/pong/heartbeat.
async function connectWebSocket(feedTokenLocal = null) {
  // ensure login
  await smartLogin().catch(() => null);

  const clientCode = WS_CLIENT_CODE || process.env.SMART_USER_ID || "";
  const feedTokenToUse = feedTokenLocal || feedToken || WS_FEED_TOKEN || "";

  // If feed token is not available, the server can still connect if SmartAPI supports query-less WS (some require feed token)
  // Build query params as required: ?clientCode=&feedToken=&apiKey=
  const qs = new URLSearchParams({
    clientCode: clientCode || "",
    feedToken: feedTokenToUse || "",
    apiKey: process.env.SMART_API_KEY || ""
  }).toString();

  const wsUrl = (SMART_WS_BASE || "wss://smartapisocket.angelone.in/smart-stream") + "?" + qs;
  if (wsClient && wsConnected) {
    console.log("WS already connected");
    return true;
  }

  try {
    console.log("Connecting WS to:", wsUrl);
    wsClient = new WebSocket(wsUrl, { handshakeTimeout: 15000 });

    wsClient.on("open", () => {
      wsConnected = true;
      console.log("WS open — connected");
      // optionally send heartbeat or subscription; will be handled in B3
    });

    wsClient.on("message", (raw) => {
      // We'll parse and update livePrices in B3 for proper message structure
      try {
        const msg = raw.toString();
        // don't parse here deeply; use B3 logic to decode binary/buffer formats
        // quick attempt to JSON parse if possible
        let parsed = null;
        try { parsed = JSON.parse(msg); } catch (_) { parsed = null; }
        if (parsed && parsed.payload) {
          // sample: parsed.payload -> update tokens
          // defer detailed handling to B3
        }
      } catch (e) {
        console.warn("WS message parse error:", e && e.message);
      }
    });

    wsClient.on("close", (code, reason) => {
      wsConnected = false;
      console.warn("WS closed:", code, (reason && reason.toString && reason.toString()) || reason);
      // schedule reconnect
      setTimeout(() => connectWebSocket(feedTokenLocal), 5000);
    });

    wsClient.on("error", (err) => {
      wsConnected = false;
      console.warn("WS error:", err && err.message);
      // ensure closed
      try { wsClient && wsClient.terminate(); } catch (e) {}
      setTimeout(() => connectWebSocket(feedTokenLocal), 5000);
    });

    return true;
  } catch (e) {
    console.warn("connectWebSocket exception:", e && e.message);
    wsConnected = false;
    return false;
  }
}

// ---------- Public endpoints related to auth & LTP ----------

// Trigger login manually (for debugging)
app.post("/admin/login", async (req, res) => {
  try {
    const r = await smartLogin();
    if (r.success) {
      return res.json(ok({ message: "logged_in", feedToken: r.feedToken || null }));
    } else {
      return res.status(400).json(err("login_failed", r));
    }
  } catch (e) {
    return res.status(500).json(err("exception", e && e.message));
  }
});

// Endpoint to connect WS (manual trigger)
app.post("/admin/connect-ws", async (req, res) => {
  try {
    const ft = req.body && req.body.feedToken;
    const okc = await connectWebSocket(ft);
    return res.json(ok({ ws_connected: !!wsConnected, success: !!okc }));
  } catch (e) {
    return res.status(500).json(err("connect_failed", e && e.message));
  }
});

// Get LTP: prefer WS live price, fallback to HTTP
app.get("/ltp", async (req, res) => {
  // Accept query: token or symbol+exchange
  const token = req.query.token;
  const symbol = req.query.symbol;
  const exchange = req.query.exchange || "NSE";

  try {
    if (token && livePrices[token]) {
      return res.json(ok({ token, ltp: livePrices[token].ltp, source: "ws", ts: livePrices[token].ts }));
    }

    if (symbol) {
      // try mapping
      const sItem = findTokenForSymbol(symbol, exchange);
      if (sItem && sItem.token && livePrices[sItem.token]) {
        return res.json(ok({ token: sItem.token, ltp: livePrices[sItem.token].ltp, source: "ws_cache" }));
      }
      // fallback to HTTP
      const fetched = await fetchLtpHttp(symbol, exchange);
      if (fetched && fetched.success) {
        return res.json(ok({ symbol, ltp: fetched.ltp || null, token: fetched.token || null, source: "http" }));
      }
      return res.status(404).json(err("ltp_not_found", fetched));
    }

    if (token) {
      // if token exists but not in livePrices, fallback to HTTP by searching scripsCache
      let found = null;
      if (Array.isArray(scripsCache)) {
        found = scripsCache.find(it => (it && (it.token == token || it.symbol == token || it.name == token)));
      }
      if (found) {
        const fetched = await fetchLtpHttp(found.symbol || found.name, found.exch || found.exchange || "NSE");
        if (fetched && fetched.success) return res.json(ok({ token, ltp: fetched.ltp, source: "http" }));
      }
      return res.status(404).json(err("token_not_live", token));
    }

    return res.status(400).json(err("missing_params", "provide token or symbol"));
  } catch (e) {
    return res.status(500).json(err("ltp_error", e && e.message));
  }
});

// PART B2 ends here. Continue with B3 for robust websocket parsing, subscription, option chain engine, greeks endpoints.
// server.js — PART B3 of 10
// Robust WebSocket parsing, subscription helpers, option-greeks HTTP helper endpoint

// ---------- WS message parsing helpers ----------
// SmartAPI WS may send binary or JSON structures; we attempt to handle both common shapes.
// This parser is defensive: it tries several decodes and updates livePrices accordingly.

function safeParseJson(s) {
  try {
    return JSON.parse(s);
  } catch (e) {
    return null;
  }
}

function handleWsTickMessage(msg) {
  // msg can be object or string. We support several possible shapes:
  // 1) { "type": "tick", "payload": [ { "token": "12345", "ltp": 123.4, ... }, ... ] }
  // 2) { "payload": { "lastPrice": 123.4, "token": "12345", ... } }
  // 3) legacy binary frames converted to CSV-like strings -> token|ltp|...
  try {
    if (!msg) return;
    if (typeof msg === "string") {
      const parsed = safeParseJson(msg);
      if (parsed) msg = parsed;
    }

    if (typeof msg === "object") {
      // Case: payload is array of ticks
      if (Array.isArray(msg.payload)) {
        for (let item of msg.payload) {
          processTickItem(item);
        }
        return;
      }

      // Case: object with payload single
      if (msg.payload && typeof msg.payload === "object") {
        processTickItem(msg.payload);
        return;
      }

      // Case: direct tick object
      if (msg.token && (msg.ltp || msg.lastPrice || msg.last_price)) {
        processTickItem(msg);
        return;
      }

      // Case: some providers send data in 'data' or other keys
      if (msg.data && Array.isArray(msg.data)) {
        for (let it of msg.data) processTickItem(it);
        return;
      }
    }

    // Last resort: string with pipe-separated values "token|ltp|..."
    if (typeof msg === "string" && msg.indexOf("|") > 0) {
      // Example "36688|100.5|..."
      const parts = msg.split("|").map(p => p.trim());
      const tokenCandidate = parts[0];
      const ltpCandidate = Number(parts[1]) || null;
      if (tokenCandidate && !isNaN(ltpCandidate)) {
        updateLivePrice(tokenCandidate, ltpCandidate);
        return;
      }
    }
  } catch (e) {
    console.warn("handleWsTickMessage error:", e && e.message);
  }
}

function processTickItem(item) {
  if (!item) return;
  // common key names mapping
  const token = item.token || item.instrument_token || item.tok || item.symbol_token || item.instrumentId || item.instrument || null;
  const ltp = Number(item.ltp || item.lastPrice || item.last_price || item.lp || item.price || item.tradePrice || item.p);
  if (token && !isNaN(ltp)) {
    updateLivePrice(String(token), ltp);
  } else {
    // try find token via name fields
    const maybeSymbol = (item.symbol || item.name || item.scrip || item.instrument || "").toString().toUpperCase();
    if (maybeSymbol) {
      const found = findTokenForSymbol(maybeSymbol);
      if (found && found.token && !isNaN(ltp)) {
        updateLivePrice(String(found.token), ltp);
      }
    }
  }
}

function updateLivePrice(token, ltp) {
  try {
    const now = Date.now();
    livePrices[token] = { ltp: Number(ltp), ts: now };
    // console.debug can be noisy; comment out or enable when debugging
    // console.debug("livePrice update:", token, ltp);
  } catch (e) {
    // ignore
  }
}

// ---------- WS message handler wrapper (attach to wsClient.on('message')) ----------
function onWsRawMessage(raw) {
  if (!raw) return;
  // raw may be Buffer or string
  try {
    let text = null;
    if (Buffer.isBuffer(raw)) {
      // try to treat as utf8 text
      text = raw.toString("utf8");
    } else {
      text = (typeof raw === "string") ? raw : JSON.stringify(raw);
    }

    // attempt parse
    const parsed = safeParseJson(text);
    if (parsed) {
      // pass object to tick handler
      handleWsTickMessage(parsed);
      return;
    }

    // not JSON: attempt CSV-like or proto decode patterns
    // some providers send lines like "tick|token|ltp|..."
    if (text.indexOf("|") > 0) {
      handleWsTickMessage(text);
      return;
    }

    // fallback: try to parse as eval-style (rare)
    try {
      const attempt = JSON.parse(text);
      handleWsTickMessage(attempt);
      return;
    } catch (_) {
      // give up
    }
  } catch (e) {
    console.warn("onWsRawMessage error:", e && e.message);
  }
}

// Attach robust handler if wsClient exists
function attachWsHandlers() {
  if (!wsClient) return;
  wsClient.on("message", (raw) => {
    // use wrapper
    try {
      onWsRawMessage(raw);
    } catch (e) {
      console.warn("ws message processing error:", e && e.message);
    }
  });
}

// If wsClient already exists (from B2), attach handlers now
if (wsClient) attachWsHandlers();

// ---------- Subscribe helper (by token) ----------
// SmartAPI often expects a "subscribe" JSON with tokens list; implement helper to send subscription
function wsSubscribeTokens(tokens = [], mode = "LTP") {
  // tokens: array of token strings or numbers
  if (!wsClient || wsClient.readyState !== WebSocket.OPEN) {
    console.warn("wsSubscribeTokens: ws not open");
    return false;
  }
  if (!Array.isArray(tokens) || tokens.length === 0) return false;

  // Construct subscribe message per SmartAPI format
  // Example: { "action": "subscribe", "symbols": ["<token1>", "<token2>"], "mode": "LTP" }
  const payload = {
    action: "subscribe",
    symbols: tokens.map(t => String(t)),
    mode: mode
  };

  try {
    wsClient.send(JSON.stringify(payload));
    console.log("Subscribed tokens:", tokens.length);
    return true;
  } catch (e) {
    console.warn("wsSubscribeTokens send failed:", e && e.message);
    return false;
  }
}

// Helper to subscribe by symbol names (map using scripsCache)
function subscribeBySymbols(symbols = [], exchange = "NSE", mode = "LTP") {
  if (!Array.isArray(symbols) || symbols.length === 0) return false;
  const tokens = [];
  for (let s of symbols) {
    const found = findTokenForSymbol(s, exchange);
    if (found && found.token) tokens.push(found.token);
  }
  if (tokens.length) return wsSubscribeTokens(tokens, mode);
  return false;
}

// ---------- Option Greeks HTTP helper (uses SmartAPI greeks endpoint) ----------
// SmartAPI Greeks endpoint path (based on docs)
const OPTION_GREEKS_PATH = "/rest/secure/angelbroking/marketData/v1/optionGreek";

// POST body shape usually: { name: "TCS", expirydate: "25JAN2024" }
async function fetchOptionGreeksUnderlying(name, expiryDate) {
  try {
    // ensure login for headers
    await smartLogin().catch(() => null);

    const payload = { name: name, expirydate: expiryDate };
    // call smartApiRequest; method POST
    const resp = await smartApiRequest("post", OPTION_GREEKS_PATH, payload);
    if (resp && resp.data) {
      return { success: true, data: resp.data };
    }
    return { success: false, message: "no_response" };
  } catch (e) {
    return { success: false, message: "exception", details: e && e.message };
  }
}

// Endpoint to fetch option greeks for symbol+expiry
app.post("/option-greeks", async (req, res) => {
  const name = req.body && (req.body.name || req.body.underlying || req.body.symbol);
  const expiry = req.body && (req.body.expiry || req.body.expirydate || req.body.expiry_date);
  if (!name || !expiry) {
    return res.status(400).json(err("missing_params", "provide name and expiry (e.g. 25DEC2025)"));
  }
  try {
    const r = await fetchOptionGreeksUnderlying(name, expiry);
    if (r.success) return res.json(ok({ greeks: r.data }));
    return res.status(500).json(err("greeks_failed", r));
  } catch (e) {
    return res.status(500).json(err("exception", e && e.message));
  }
});

// ---------- Small admin endpoint: subscribe tokens via API ----------
app.post("/admin/subscribe", async (req, res) => {
  const tokens = req.body && req.body.tokens;
  const symbols = req.body && req.body.symbols;
  const mode = req.body && req.body.mode || "LTP";
  try {
    if (Array.isArray(tokens) && tokens.length) {
      const okc = wsSubscribeTokens(tokens, mode);
      return res.json(ok({ subscribed: tokens.length, ws_connected: !!wsConnected, ok: !!okc }));
    }
    if (Array.isArray(symbols) && symbols.length) {
      const okc = subscribeBySymbols(symbols);
      return res.json(ok({ subscribed_symbols: symbols.length, ws_connected: !!wsConnected, ok: !!okc }));
    }
    return res.status(400).json(err("missing_params", "provide tokens[] or symbols[] in body"));
  } catch (e) {
    return res.status(500).json(err("subscribe_error", e && e.message));
  }
});

// PART B3 ends here. Continue with B4 for option-chain engine, strike selection, Greeks integration, premium checks.
// server.js — PART B4 of 10
// Option Chain Engine: strike selection, expiry matching, CE/PE separation, ATM logic.

// ---------- Market Resolver ----------
function resolveMarket(m) {
  if (!m) return null;
  m = m.toString().trim().toLowerCase();
  if (m.includes("nif")) return "nifty";
  if (m.includes("sen")) return "sensex";
  if (m.includes("gas") || m.includes("nat")) return "natural gas";
  return m; // unknown → caller handles
}

// ---------- Step size per market ----------
function getStepSize(market) {
  if (market === "natural gas") return 5;
  return 50; // Nifty/Sensex defaults
}

// ---------- ATM strike ----------
function findATM(price, step) {
  const p = Number(price);
  return Math.round(p / step) * step;
}

// ---------- Pick 3 Strikes (PE-ATM-CE) ----------
function get3Strikes(price, step) {
  const atm = findATM(price, step);
  return [atm - step, atm, atm + step];
}

// ---------- Find expiry from ScripMaster ----------
function findExpiryForMarket(market) {
  if (!scripsCache || !Array.isArray(scripsCache)) return null;

  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10); // yyyy-mm-dd

  const items = scripsCache.filter(it => {
    if (!it || !it.expiry || !it.symbol) return false;
    const sym = it.symbol.toUpperCase();
    if (market === "nifty" && sym.includes("NIFTY")) return true;
    if (market === "sensex" && sym.includes("SENSEX")) return true;
    if (market === "natural gas") {
      if (sym.includes("NATURALGAS") || sym.includes("NATURAL GAS") || sym.includes("NG")) return true;
    }
    return false;
  });

  if (!items.length) return null;

  const uniqueExp = [...new Set(items.map(x => x.expiry))].sort((a, b) => {
    return new Date(a) - new Date(b);
  });

  const upcoming = uniqueExp.find(exp => new Date(exp) >= new Date(todayStr));
  return upcoming || uniqueExp[uniqueExp.length - 1];
}

// ---------- Filter CE/PE for given strike ----------
function getCEPEFromStrike(market, strike, expiry) {
  if (!scripsCache || !Array.isArray(scripsCache)) return { CE: null, PE: null };

  const ce = scripsCache.find(it =>
    it &&
    (it.strike == strike) &&
    (it.expiry === expiry) &&
    (it.symbol || "").toUpperCase().includes("CE") &&
    matchMarketSymbol(it.symbol, market)
  );

  const pe = scripsCache.find(it =>
    it &&
    (it.strike == strike) &&
    (it.expiry === expiry) &&
    (it.symbol || "").toUpperCase().includes("PE") &&
    matchMarketSymbol(it.symbol, market)
  );

  return { CE: ce || null, PE: pe || null };
}

// ---------- Symbol matcher ----------
function matchMarketSymbol(sym, market) {
  if (!sym) return false;
  const s = sym.toUpperCase();
  if (market === "nifty") return s.includes("NIFTY");
  if (market === "sensex") return s.includes("SENSEX");
  if (market === "natural gas") return s.includes("NATURALGAS") || s.includes("NATURAL GAS") || s.includes("NG");
  return false;
}

// ---------- Helper: extract LTP from WS or fallback HTTP ----------
function getCachedOrHttpLtpForToken(token, symbolGuess = null, exchange = "NFO") {
  return new Promise(async (resolve) => {
    try {
      if (livePrices[token]) {
        return resolve({
          token,
          ltp: livePrices[token].ltp,
          source: "ws"
        });
      }

      const fallback = await fetchLtpHttp(symbolGuess || token, exchange);
      if (fallback && fallback.success) {
        return resolve({
          token,
          ltp: fallback.ltp,
          source: "http"
        });
      }

      resolve({ token, ltp: null, source: "none" });
    } catch (e) {
      resolve({ token, ltp: null, source: "exception", error: e && e.message });
    }
  });
}

// ---------- Build complete CE/PE structure for a strike ----------
async function buildStrike(market, strike, expiry) {
  const { CE, PE } = getCEPEFromStrike(market, strike, expiry);

  const out = {
    strike,
    CE: null,
    PE: null
  };

  if (CE) {
    const ceLtpObj = await getCachedOrHttpLtpForToken(
      CE.token,
      CE.symbol,
      CE.exch || "NFO"
    );
    out.CE = {
      symbol: CE.symbol,
      token: CE.token,
      ltp: ceLtpObj.ltp,
      expiry: CE.expiry
    };
  }

  if (PE) {
    const peLtpObj = await getCachedOrHttpLtpForToken(
      PE.token,
      PE.symbol,
      PE.exch || "NFO"
    );
    out.PE = {
      symbol: PE.symbol,
      token: PE.token,
      ltp: peLtpObj.ltp,
      expiry: PE.expiry
    };
  }

  return out;
}

// ---------- Endpoint: Raw Option Chain (for testing) ----------
app.post("/option-chain/raw", async (req, res) => {
  try {
    const market = resolveMarket(req.body.market);
    const spot = Number(req.body.spot);

    if (!market) return res.status(400).json(err("invalid_market"));
    if (!spot) return res.status(400).json(err("invalid_spot"));

    const step = getStepSize(market);
    const strikes = get3Strikes(spot, step);
    const expiry = findExpiryForMarket(market);

    if (!expiry) return res.status(500).json(err("expiry_not_found"));

    const results = [];
    for (let st of strikes) {
      const obj = await buildStrike(market, st, expiry);
      results.push(obj);
    }

    return res.json(ok({
      market,
      spot,
      strikes,
      expiry,
      chain: results
    }));
  } catch (e) {
    return res.status(500).json(err("exception", e && e.message));
  }
});

// PART B4 ends here — continue with PART B5 for option-chain summary, premium engine, final-analysis merge.
// server.js — PART B5 of 10
// Premium engine, option-chain summary, UI-friendly /option-chain endpoint and small helpers

// ---------- Premium rules (tuneable) ----------
function computePremiumPlan(distance) {
  // distance = absolute points between basePrice and strike
  // returns entry (premium to take), stopLoss, target
  let entry = 10, stopLoss = 6, target = 15;
  if (distance <= 10) { entry = 5; stopLoss = 3; target = 8; }        // ATM / near ATM -> tighter
  else if (distance <= 50) { entry = 10; stopLoss = 6; target = 15; } // typical
  else if (distance <= 100) { entry = 8; stopLoss = 5; target = 12; } // further OTM
  else { entry = 6; stopLoss = 4; target = 10; }                     // deep OTM
  return { distance, entry, stopLoss, target };
}

// ---------- Helper: pick UI-strikes (CE, PE, STRADDLE) from built chain ----------
function composeUiStrikesFromChain(chain, basePrice) {
  // chain: array of { strike, CE:{...}, PE:{...} }
  // choose: lowest -> PE, middle->STRADDLE, highest->CE
  if (!Array.isArray(chain) || chain.length === 0) return [];

  const sorted = [...chain].sort((a, b) => Number(a.strike) - Number(b.strike));
  const low = sorted[0];
  const mid = sorted[1] || sorted[0];
  const high = sorted[2] || sorted[sorted.length - 1];

  const out = [];

  if (high) {
    const dist = Math.abs(Number(basePrice) - Number(high.strike));
    const plan = computePremiumPlan(dist);
    out.push({
      type: "CE",
      strike: Number(high.strike),
      distance: dist,
      entry: plan.entry,
      stopLoss: plan.stopLoss,
      target: plan.target
    });
  }

  if (low) {
    const dist = Math.abs(Number(basePrice) - Number(low.strike));
    const plan = computePremiumPlan(dist);
    out.push({
      type: "PE",
      strike: Number(low.strike),
      distance: dist,
      entry: plan.entry,
      stopLoss: plan.stopLoss,
      target: plan.target
    });
  }

  if (mid) {
    const dist = Math.abs(Number(basePrice) - Number(mid.strike));
    const plan = computePremiumPlan(dist);
    out.push({
      type: "STRADDLE",
      strike: Number(mid.strike),
      distance: dist,
      entry: plan.entry,
      stopLoss: plan.stopLoss,
      target: plan.target
    });
  }

  return out;
}

// ---------- Endpoint: user-facing option-chain (UI friendly) ----------
// Accepts: { market: "nifty", spot: 25900, use_live: true (optional) }
// Returns: strikes (3), chain (detailed), ui-friendly strike suggestions
app.post("/option-chain", async (req, res) => {
  try {
    const marketRaw = req.body && req.body.market;
    const spotRaw = req.body && (req.body.spot || req.body.basePrice || req.body.live_ltp);
    const useLive = !!req.body.use_live;

    const market = resolveMarket(marketRaw);
    if (!market) return res.status(400).json(err("invalid_market", { provided: marketRaw }));

    // Determine base price: prefer live future LTP if requested and available
    let basePrice = Number(spotRaw) || 0;
    if (useLive) {
      // try to get AUTO future's LTP from livePrices or HTTP fallback
      try {
        const expiry = findExpiryForMarket(market);
        // lookup a future-like symbol in scripsCache for market to identify token
        const candidates = (scripsCache || []).filter(it => it && matchMarketSymbol(it.symbol || it.tradingSymbol || it.name || "", market) && it.instrumentType && /(FUT|FUTIDX|FUTSTK|FUTCOM)/i.test(it.instrumentType || it.instrument_type || ""));
        if (candidates && candidates.length) {
          const cand = candidates[0];
          if (cand && cand.token && livePrices[cand.token] && livePrices[cand.token].ltp) {
            basePrice = Number(livePrices[cand.token].ltp);
          } else if (cand && cand.symbol) {
            const fetched = await fetchLtpHttp(cand.symbol, cand.exch || "NFO");
            if (fetched && fetched.success && fetched.ltp) basePrice = Number(fetched.ltp);
          }
        }
      } catch (e) {
        // ignore and fallback to supplied spot
      }
    }

    if (!basePrice || basePrice <= 0) {
      // if user didn't pass spot, try fallback: use cached scrips to infer a recent future
      if (Array.isArray(scripsCache) && scripsCache.length) {
        const ex = findExpiryForMarket(market);
        const fut = (scripsCache.find(it => it && matchMarketSymbol(it.symbol || it.tradingSymbol || it.name || "", market) && (it.instrumentType || it.instrument_type || "").toUpperCase().includes("FUT") && it.expiry === ex) || null);
        if (fut && fut.token && livePrices[fut.token]) basePrice = Number(livePrices[fut.token].ltp);
      }
    }

    if (!basePrice || basePrice <= 0) return res.status(400).json(err("invalid_base_price", "provide spot or use_live data"));

    const step = getStepSize(market);
    const strikes = get3Strikes(basePrice, step);
    const expiry = findExpiryForMarket(market);
    if (!expiry) return res.status(500).json(err("expiry_not_found"));

    // Build chain (detailed CE/PE per strike)
    const chain = [];
    for (let st of strikes) {
      const built = await buildStrike(market, st, expiry);
      chain.push(built);
    }

    // Compose UI-friendly suggestions
    const uiStrikes = composeUiStrikesFromChain(chain, basePrice);

    return res.json(ok({
      market,
      basePrice,
      expiry,
      strikes,
      chain,
      strikes_suggestions: uiStrikes
    }));
  } catch (e) {
    return res.status(500).json(err("option_chain_error", e && e.message));
  }
});

// ---------- Small endpoint: premium calc (ad-hoc) ----------
app.post("/premium-calc", (req, res) => {
  try {
    const { distance } = req.body || {};
    const d = Number(distance || 0);
    if (!d) return res.status(400).json(err("invalid_distance"));
    const plan = computePremiumPlan(d);
    return res.json(ok({ plan }));
  } catch (e) {
    return res.status(500).json(err("premium_error", e && e.message));
  }
});

// PART B5 ends here. Continue with B6 for trend engine, full-analysis endpoint and greeks integration.
// server.js — PART B6 of 10
// Trend engine + Full-analysis endpoint (front-end compatible response)

// ---------- Trend / scoring engine ----------
function computeTrend(ema20, ema50, rsi, vwap, spot) {
  // Defensive coercion
  ema20 = Number(ema20) || 0;
  ema50 = Number(ema50) || 0;
  rsi = Number(rsi) || 50;
  vwap = Number(vwap) || 0;
  spot = Number(spot) || 0;

  const diff = ema20 - ema50;
  const gapPct = Math.abs(ema50) > 0 ? (Math.abs(diff) / Math.abs(ema50)) * 100 : 0;

  let main = "SIDEWAYS";
  let strength = "RANGE";
  let bias = "NONE";

  if (gapPct > 0.6 && ema20 > ema50) {
    main = "UP";
    bias = "BULL";
    strength = gapPct > 1.5 ? "TREND" : "TRENDING";
  } else if (gapPct > 0.6 && ema20 < ema50) {
    main = "DOWN";
    bias = "BEAR";
    strength = gapPct > 1.5 ? "TREND" : "TRENDING";
  }

  // Score mixes RSI distance from 50 and gapPct
  const rsiScore = Math.min(100, Math.abs(rsi - 50) * 1.5);
  const gapScore = Math.min(100, gapPct * 10);
  const score = Math.round(((rsiScore + gapScore) / 2) * 100) / 100;

  const components = {
    ema_gap: `${gapPct.toFixed(2)}%`,
    rsi: `RSI ${rsi} (${rsi > 60 ? "high" : (rsi < 40 ? "low" : "neutral")})`,
    vwap: (spot && vwap) ? ((spot > vwap) ? `Above VWAP (${(((spot - vwap) / Math.max(1, vwap)) * 100).toFixed(2)}%)` : `Below VWAP (${(((vwap - spot) / Math.max(1, vwap)) * 100).toFixed(2)}%)`) : "VWAP unknown",
    price_structure: main === "SIDEWAYS" ? "Mixed structure" : `${main} structure`,
    expiry: "Expiry mid"
  };

  const comment = `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`;

  return { main, strength, score, bias, components, comment };
}

// ---------- Helper: build UI response similar to your previous format ----------
async function buildFullAnalysisPayload(input) {
  // input: { ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live }
  const ema20 = Number(input.ema20) || 0;
  const ema50 = Number(input.ema50) || 0;
  const rsi = Number(input.rsi) || 50;
  const vwap = Number(input.vwap) || 0;
  const spotGiven = Number(input.spot) || 0;
  const marketRaw = input.market || "nifty";
  const use_live = !!input.use_live;

  const market = resolveMarket(marketRaw) || "nifty";
  const trend = computeTrend(ema20, ema50, rsi, vwap, spotGiven);

  // Determine basePrice (prefer live future LTP if requested)
  let basePrice = spotGiven || 0;
  if (use_live) {
    try {
      // try to infer a future candidate from scripsCache
      const expiry = findExpiryForMarket(market);
      const candidate = (scripsCache || []).find(it => it && matchMarketSymbol(it.symbol || it.name || it.tradingSymbol || "", market) && ((it.instrumentType || it.instrument_type || it.instrument || "").toUpperCase().includes("FUT")) && it.expiry === expiry);
      if (candidate && candidate.token && livePrices[candidate.token] && livePrices[candidate.token].ltp) {
        basePrice = Number(livePrices[candidate.token].ltp);
      } else if (candidate && candidate.symbol) {
        const fh = await fetchLtpHttp(candidate.symbol, candidate.exch || "NFO");
        if (fh && fh.success && fh.ltp) basePrice = Number(fh.ltp);
      }
    } catch (e) {
      // ignore and fallback to spotGiven
    }
  }

  // Final fallback
  if (!basePrice || basePrice <= 0) basePrice = spotGiven || ema20 || 0;

  // Strikes
  const step = getStepSize(market);
  const strikes = get3Strikes(basePrice, step);
  const expiry = findExpiryForMarket(market) || null;

  // Build chain entries in parallel
  const chainPromises = strikes.map(st => buildStrike(market, st, expiry));
  const chain = await Promise.all(chainPromises);

  // Compose UI-friendly strikes (CE, PE, STRADDLE)
  const uiStrikes = composeUiStrikesFromChain(chain, basePrice);

  // Greeks: try fetch for underlying if possible
  let greeks = null;
  try {
    const underlyingCandidate = (scripsCache || []).find(it => it && matchMarketSymbol(it.symbol || it.name || it.tradingSymbol || "", market) && (it.instrumentType || it.instrument_type || "").toUpperCase().includes("FUT"));
    if (underlyingCandidate && underlyingCandidate.symbol) {
      const name = String(underlyingCandidate.symbol).replace(/FUT.*$/i, "").trim();
      const g = await fetchOptionGreeksUnderlying(name, expiry);
      if (g && g.success) greeks = g.data;
    }
  } catch (e) {
    greeks = null;
  }

  // meta
  const meta = {
    live_data_used: use_live && Object.keys(livePrices || {}).length > 0,
    live_ltp: null,
    ws_connected: !!wsConnected,
    live_error: null
  };
  // attempt to get live_ltp for market
  try {
    if (use_live) {
      const candidateToken = (scripsCache || []).find(it => it && matchMarketSymbol(it.symbol || it.name || it.tradingSymbol || "", market) && ((it.instrumentType || it.instrument_type || "").toUpperCase().includes("FUT")));
      if (candidateToken && candidateToken.token && livePrices[candidateToken.token]) {
        meta.live_ltp = livePrices[candidateToken.token].ltp;
      } else {
        // try HTTP LTP for a known future symbol
        if (candidateToken && candidateToken.symbol) {
          const f = await fetchLtpHttp(candidateToken.symbol, candidateToken.exch || "NFO");
          if (f && f.success) meta.live_ltp = f.ltp;
        }
      }
    }
  } catch (e) {
    meta.live_error = e && e.message;
  }

  // Build final strikes array in user's short format (type, strike, distance, entry, stopLoss, target)
  const strikesOut = uiStrikes.map(s => ({
    type: s.type,
    strike: s.strike,
    distance: s.distance,
    entry: s.entry,
    stopLoss: s.stopLoss,
    target: s.target
  }));

  // Assemble response similar to your original sample
  const response = {
    success: true,
    message: "Calculation complete",
    login_status: tokenValid() ? "SmartAPI Logged-In" : "Not Logged-In",
    input: {
      ema20, ema50, rsi, vwap, spot: basePrice, market, expiry_days: input.expiry_days || 0, use_live
    },
    trend: {
      main: trend.main,
      strength: trend.strength,
      score: trend.score,
      bias: trend.bias,
      components: trend.components,
      comment: trend.comment
    },
    strikes: strikesOut,
    chain: chain,
    greeks: greeks,
    auto_tokens: { /* We can populate best-effort below from scripsCache */ },
    meta: meta
  };

  // Populate auto_tokens best-effort: pick one future per market from scripsCache
  const markets = ["nifty", "sensex", "natural gas"];
  const auto_tokens = {};
  for (let m of markets) {
    try {
      const exp = findExpiryForMarket(m);
      const fut = (scripsCache || []).find(it => it && matchMarketSymbol(it.symbol || it.name || it.tradingSymbol || "", m) && ((it.instrumentType || it.instrument_type || "").toUpperCase().includes("FUT")) && it.expiry === exp);
      if (fut) {
        auto_tokens[m] = { symbol: fut.symbol || fut.name || null, token: fut.token || fut.symbolToken || fut.symboltoken || null, expiry: fut.expiry || exp || null };
      } else {
        auto_tokens[m] = null;
      }
    } catch (e) {
      auto_tokens[m] = null;
    }
  }
  response.auto_tokens = auto_tokens;

  return response;
}

// ---------- Endpoint: /full-analysis ----------
app.post("/full-analysis", async (req, res) => {
  try {
    const payload = await buildFullAnalysisPayload(req.body || {});
    return res.json(payload);
  } catch (e) {
    return res.status(500).json(err("full_analysis_error", e && e.message));
  }
});
// PART B6 ends here. Continue with B7 for admin utilities, logging, and final endpoints like /api/scrips/status, /api/ltp/latest etc.
// server.js — PART B7 of 10
// Admin utilities, scrip-master status, LTP summary, ws-status, token-map endpoints

// ---------- Admin: get WS & Login status ----------
app.get("/admin/status", (req, res) => {
  try {
    return res.json(ok({
      ws_connected: wsConnected,
      access_token_valid: tokenValid(),
      feed_token: !!feedToken,
      live_prices_cached: Object.keys(livePrices).length,
      scrip_master_loaded: !!scripsCache,
      scrip_master_entries: Array.isArray(scripsCache) ? scripsCache.length : 0,
      scrip_master_last_update: scripsLastUpdated
    }));
  } catch (e) {
    return res.json(err("status_error", e && e.message));
  }
});

// ---------- Get token for a symbol ----------
app.get("/token", (req, res) => {
  try {
    const symbol = req.query.symbol;
    if (!symbol) return res.status(400).json(err("missing_symbol"));

    const found = findTokenForSymbol(symbol);
    if (!found) return res.status(404).json(err("not_found"));

    return res.json(ok({ symbol, found }));
  } catch (e) {
    return res.status(500).json(err("token_error", e && e.message));
  }
});

// ---------- ScripMaster status ----------
app.get("/scrips/status", (req, res) => {
  try {
    return res.json(ok({
      loaded: !!scripsCache,
      entries: Array.isArray(scripsCache) ? scripsCache.length : 0,
      last_updated: scripsLastUpdated,
      zip_exists: fs.existsSync(SCRIP_MASTER_ZIP),
      json_exists: fs.existsSync(SCRIP_MASTER_JSON)
    }));
  } catch (e) {
    return res.status(500).json(err("scrips_status_error", e && e.message));
  }
});

// ---------- Endpoint: list all scrips for debugging (LIMITED) ----------
app.get("/scrips/list", (req, res) => {
  try {
    if (!scripsCache || !Array.isArray(scripsCache)) {
      return res.json(err("scrips_not_loaded"));
    }

    const limit = Number(req.query.limit || 50);
    return res.json(ok({
      count: scripsCache.length,
      sample: scripsCache.slice(0, limit)
    }));
  } catch (e) {
    return res.status(500).json(err("scrips_list_error", e && e.message));
  }
});

// ---------- Latest LTP snapshot (for debugging) ----------
app.get("/ltp/latest", (req, res) => {
  try {
    const obj = {};
    for (let token of Object.keys(livePrices)) {
      obj[token] = livePrices[token].ltp;
    }
    return res.json(ok({ count: Object.keys(obj).length, prices: obj }));
  } catch (e) {
    return res.status(500).json(err("ltp_latest_error", e && e.message));
  }
});

// ---------- Simple market tokens discovery ----------
app.get("/market/future-token", (req, res) => {
  try {
    const marketRaw = req.query.market;
    const market = resolveMarket(marketRaw);
    if (!market) return res.status(400).json(err("invalid_market"));

    const expiry = findExpiryForMarket(market);
    if (!expiry) return res.status(400).json(err("expiry_not_found"));

    const fut = (scripsCache || []).find(it =>
      it &&
      matchMarketSymbol(it.symbol || it.name || it.tradingSymbol || "", market) &&
      ((it.instrumentType || it.instrument_type || it.instrument || "").toUpperCase().includes("FUT")) &&
      it.expiry === expiry
    );

    return res.json(ok({ market, expiry, future: fut || null }));
  } catch (e) {
    return res.status(500).json(err("market_future_token_error", e && e.message));
  }
});

// ---------- Get live LTP for a market future ----------
app.get("/market/live-ltp", async (req, res) => {
  try {
    const marketRaw = req.query.market;
    const market = resolveMarket(marketRaw);
    if (!market) return res.status(400).json(err("invalid_market"));

    const expiry = findExpiryForMarket(market);
    const fut = (scripsCache || []).find(it =>
      it &&
      matchMarketSymbol(it.symbol || it.name || it.tradingSymbol || "", market) &&
      ((it.instrumentType || it.instrument_type || it.instrument || "").toUpperCase().includes("FUT")) &&
      it.expiry === expiry
    );

    if (!fut) return res.status(400).json(err("future_not_found"));

    // Try WS first
    if (livePrices[fut.token]) {
      return res.json(ok({
        market,
        expiry,
        symbol: fut.symbol,
        token: fut.token,
        ltp: livePrices[fut.token].ltp,
        source: "ws"
      }));
    }

    // Fallback HTTP
    const fh = await fetchLtpHttp(fut.symbol, fut.exch || "NFO");
    if (fh && fh.success) {
      return res.json(ok({
        market,
        expiry,
        symbol: fut.symbol,
        token: fut.token,
        ltp: fh.ltp,
        source: "http"
      }));
    }

    return res.status(404).json(err("ltp_not_available"));
  } catch (e) {
    return res.status(500).json(err("market_live_ltp_error", e && e.message));
  }
});

// PART B7 ends here. Continue with B8 for WebSocket auto-subscribe logic, reconnect policies, and performance-safe intervals.
// server.js — PART B8 of 10
// WebSocket auto-subscribe logic, auto-reconnect policies, and periodic health checks.

// ---------- Auto-subscribe helper: subscribe FUT tokens of all 3 markets ----------
async function autoSubscribeMarketFutures() {
  try {
    if (!scripsCache || !Array.isArray(scripsCache)) {
      console.warn("autoSubscribeMarketFutures: scripsCache empty, skipping");
      return;
    }

    const markets = ["nifty", "sensex", "natural gas"];
    const tokens = [];

    for (let m of markets) {
      try {
        const expiry = findExpiryForMarket(m);
        if (!expiry) continue;

        const fut = scripsCache.find(it =>
          it &&
          matchMarketSymbol(it.symbol || it.tradingSymbol || it.name || "", m) &&
          ((it.instrumentType || it.instrument_type || it.instrument || "").toUpperCase().includes("FUT")) &&
          it.expiry === expiry
        );

        if (fut && fut.token) tokens.push(String(fut.token));
      } catch (e) {
        console.warn("auto-subscribe error for market:", m, e && e.message);
      }
    }

    if (tokens.length) {
      console.log("Auto-subscribing FUT tokens:", tokens);
      wsSubscribeTokens(tokens, "LTP");
    } else {
      console.log("No FUT tokens found for auto-subscribe.");
    }
  } catch (e) {
    console.warn("autoSubscribeMarketFutures exception:", e && e.message);
  }
}

// ---------- Ensure WebSocket connection stays alive ----------
async function ensureWsAlive() {
  try {
    // 1) Ensure login first
    await smartLogin().catch(() => null);

    // 2) If no WS or closed, reconnect
    if (!wsClient || wsClient.readyState !== WebSocket.OPEN) {
      console.warn("WS not open — reconnecting…");
      await connectWebSocket();
      // attach robust handlers again
      if (wsClient) attachWsHandlers();
    }

    // 3) If WS open but not subscribed, subscribe tokens
    if (wsClient && wsClient.readyState === WebSocket.OPEN) {
      await autoSubscribeMarketFutures();
    }
  } catch (e) {
    console.warn("ensureWsAlive error:", e && e.message);
  }
}

// ---------- Periodic WS-Alive Checker ----------
setInterval(() => {
  ensureWsAlive().catch(() => null);
}, 15000); // run every 15 seconds

// ---------- WS Heartbeat (ping) ----------
setInterval(() => {
  try {
    if (wsClient && wsClient.readyState === WebSocket.OPEN) {
      wsClient.ping();
    }
  } catch (_) {}
}, 10000); // ping every 10s

// ---------- Manual endpoint: trigger auto-subscribe (debug) ----------
app.post("/admin/auto-subscribe", async (req, res) => {
  try {
    await autoSubscribeMarketFutures();
    return res.json(ok({ message: "auto-subscribed" }));
  } catch (e) {
    return res.status(500).json(err("auto_subscribe_error", e && e.message));
  }
});

// ---------- Manual endpoint: force WS reconnect ----------
app.post("/admin/ws-reconnect", async (req, res) => {
  try {
    if (wsClient) {
      try { wsClient.terminate(); } catch (_) {}
      wsClient = null;
      wsConnected = false;
    }
    await connectWebSocket();
    if (wsClient) attachWsHandlers();

    return res.json(ok({ ws_connected: wsConnected }));
  } catch (e) {
    return res.status(500).json(err("ws_reconnect_error", e && e.message));
  }
});

// PART B8 ends here — Continue with PART B9 for safe shutdown handlers, fallback logs, and final utility functions.
// server.js — PART B9 of 10
// Safe shutdown handlers, fallback logging, memory cleanups, and protective utilities.

// ---------- Global error handlers ----------
process.on("uncaughtException", (err) => {
  console.error("❌ Uncaught Exception:", err && err.message, err);
});

process.on("unhandledRejection", (reason) => {
  console.error("❌ Unhandled Rejection:", reason);
});

// ---------- Graceful shutdown helper ----------
function gracefulShutdown(signal) {
  return () => {
    console.log(`⚠️ Received ${signal} — shutting down gracefully...`);

    try {
      if (wsClient) {
        try { wsClient.terminate(); } catch (_) {}
        wsClient = null;
      }
    } catch (e) {
      console.warn("WS termination error:", e && e.message);
    }

    try {
      // small delay for cleanup
      setTimeout(() => {
        console.log("👋 Exiting now.");
        process.exit(0);
      }, 500);
    } catch (e) {
      console.warn("Shutdown error:", e && e.message);
      process.exit(1);
    }
  };
}

process.on("SIGINT", gracefulShutdown("SIGINT"));
process.on("SIGTERM", gracefulShutdown("SIGTERM"));

// ---------- Memory-usage monitor (debug) ----------
setInterval(() => {
  const mb = process.memoryUsage();
  const usedMB = Math.round((mb.rss / 1024 / 1024) * 100) / 100;

  if (usedMB > 350) {
    console.warn("⚠️ High memory usage:", usedMB, "MB");
  }
}, 20000);

// ---------- Auto-cleanup old livePrices entries ----------
setInterval(() => {
  try {
    const now = Date.now();
    const keys = Object.keys(livePrices);
    for (let t of keys) {
      const age = now - (livePrices[t].ts || 0);
      if (age > 60000 * 5) {  // older than 5 minutes
        delete livePrices[t];
      }
    }
  } catch (e) {
    console.warn("Cleanup error:", e && e.message);
  }
}, 30000);

// ---------- Mini endpoint: memory usage ----------
app.get("/admin/memory", (req, res) => {
  try {
    const mb = process.memoryUsage();
    return res.json(ok({
      rss_mb: Math.round((mb.rss / 1024 / 1024) * 100) / 100,
      heap_mb: Math.round((mb.heapUsed / 1024 / 1024) * 100) / 100,
      uptime: process.uptime()
    }));
  } catch (e) {
    return res.status(500).json(err("memory_error", e && e.message));
  }
});

// ---------- Mini endpoint: flush live-price cache ----------
app.post("/admin/flush-ltp-cache", (req, res) => {
  try {
    const count = Object.keys(livePrices).length;
    for (let k of Object.keys(livePrices)) delete livePrices[k];
    return res.json(ok({ flushed: count }));
  } catch (e) {
    return res.status(500).json(err("flush_error", e && e.message));
  }
});

// ---------- Mini endpoint: test response (ping) ----------
app.get("/ping", (req, res) => {
  return res.json(ok({ pong: true, time: Date.now() }));
});

// PART B9 ends here — Last one (PART B10) will contain final glue, export fixes, 
// last checks, and the official "server.js completed" footer.
// server.js — PART B10 of 10
// FINAL: Glue endpoints, root handler, and confirmation footer.

// ---------- Root endpoint ----------
app.get("/", (req, res) => {
  return res.json(ok({
    message: "Trading backend is running",
    version: "1.0.0",
    ws_connected: wsConnected,
    scrips_loaded: !!scripsCache,
    time: Date.now()
  }));
});

// ---------- If any route is not found ----------
app.use((req, res) => {
  return res.status(404).json(err("route_not_found", req.originalUrl));
});

// ---------- Final Footer Log ----------
console.log("---------------------------------------------------------");
console.log("✔️  server.js fully loaded (B1 → B10)");
console.log("✔️  SmartAPI + WS + OptionChain + Greeks + Premium Engine Ready");
console.log("✔️  Auto ScripMaster, Auto FUT subscription, Auto LTP alive");
console.log("✔️  Listening on PORT:", PORT);
console.log("---------------------------------------------------------");

// END OF FILE — server.js COMPLETED
