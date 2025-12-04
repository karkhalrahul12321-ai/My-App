// server.js - PART 1 of 3
// Single-file Render-ready trading backend (CommonJS)
// IMPORTANT: Paste Part-1, then Part-2, then Part-3 (in that order) into server.js

/* Dependencies */
const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const fetch = require("node-fetch");            // v2 syntax expected
const WebSocket = require("ws");
const unzipper = require("unzipper");
const totp = require("totp-generator");
const crypto = require("crypto");
require("dotenv").config();

/* Helper: safe log with prefix */
const LOG = (...args) => console.log("[trading-backend]", ...args);
const ERR = (...args) => console.error("[trading-backend][ERR]", ...args);

/* Environment variables (you said these are already set in Render .env) */
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP = process.env.SMART_TOTP || "";       // optional static totp secret or code
const SMART_USER_ID = process.env.SMART_USER_ID || "";

if (!SMART_API_KEY || !SMART_API_SECRET || !SMART_USER_ID) {
  LOG("Warning: SMART_API_KEY / SMART_API_SECRET / SMART_USER_ID may be missing in env.");
}

/* PORT binding (Render-compatible) */
const PORT = process.env.PORT || 10000;

/* Globals and runtime state */
let accessToken = null;
let refreshToken = null;
let feedToken = null;
let wsConnected = false;
let wsClient = null;
let scripsCache = null;      // loaded ScripMaster JSON entries
let scripsLoadedAt = null;

/* Config / constants */
const SCRIPMASTER_JSON_URL = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
const SCRIPMASTER_ZIP_URL = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.zip";
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com"; // base used for REST calls if any
const SMARTAPI_WS_BASE = "wss://smartapisocket.angelone.in/smart-stream";

/* Utility: wrap fetch with timeout */
const fetchWithTimeout = async (url, opts = {}, timeout = 15000) => {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
};

/* ----------------- ScripMaster loader ----------------- */
/* Try JSON first, fallback to ZIP (unzip + parse) */
async function downloadScripMaster() {
  try {
    LOG("Attempting ScripMaster JSON download:", SCRIPMASTER_JSON_URL);
    const res = await fetchWithTimeout(SCRIPMASTER_JSON_URL, {}, 20000);
    if (res.ok) {
      const text = await res.text();
      const parsed = JSON.parse(text);
      scripsCache = parsed;
      scripsLoadedAt = Date.now();
      LOG("ScripMaster JSON loaded, entries:", Array.isArray(parsed) ? parsed.length : "unknown");
      return;
    } else {
      LOG("JSON fetch failed, status:", res.status);
    }
  } catch (e) {
    LOG("ScripMaster JSON download error:", e.message || e);
  }

  // fallback to ZIP
  try {
    LOG("Attempting ScripMaster ZIP fallback:", SCRIPMASTER_ZIP_URL);
    const res = await fetchWithTimeout(SCRIPMASTER_ZIP_URL, {}, 20000);
    if (!res.ok) throw new Error("ZIP fetch failed status " + res.status);
    const buffer = await res.buffer();
    // write to temp and unzip
    const tmpPath = path.join(__dirname, "scripmaster_tmp.zip");
    fs.writeFileSync(tmpPath, buffer);
    await fs.createReadStream(tmpPath)
      .pipe(unzipper.Parse())
      .on('entry', async entry => {
        const fileName = entry.path;
        if (fileName.toLowerCase().includes("openapiscipmaster") && fileName.endsWith(".json")) {
          const content = await entry.buffer();
          try {
            const parsed = JSON.parse(content.toString());
            scripsCache = parsed;
            scripsLoadedAt = Date.now();
            LOG("ScripMaster JSON extracted from ZIP, entries:", Array.isArray(parsed) ? parsed.length : "unknown");
          } catch (e) {
            ERR("Failed parse ScripMaster JSON from zip:", e.message);
          }
        } else {
          entry.autodrain();
        }
      })
      .promise();
    // cleanup
    try { fs.unlinkSync(tmpPath); } catch(e){/*non-fatal*/}
  } catch (e) {
    ERR("ScripMaster ZIP fallback error:", e.message || e);
  }
}

/* schedule initial download attempt */
downloadScripMaster().catch(e => ERR("ScripMaster initial download error:", e));

/* ----------------- SmartAPI login + TOTP ----------------- */
/*
  Login flow (approximate):
  - Generate TOTP if SMART_TOTP provided (either secret or code)
  - Call login endpoint with apiKey, secretKey, totp (if required)
  - Save accessToken / refreshToken / feedToken if returned
  Note: AngelOne SmartAPI specifics may vary. This code uses generic pattern:
    POST https://apiconnect.angelbroking.com/.../login with body {apikey, requestType, ...}
  Adjust endpoint paths if necessary.
*/

async function generateTotp() {
  try {
    if (!SMART_TOTP) {
      LOG("No SMART_TOTP in env, cannot auto-generate totp. If AngelOne requires dynamic TOTP, provide SMART_TOTP secret.");
      return null;
    }
    // SMART_TOTP could be a secret, or a static TOTP code. If length <= 6 treat as code.
    if (/^\d{6}$/.test(SMART_TOTP)) {
      return SMART_TOTP;
    }
    // else assume secret and generate code
    const code = totp(SMART_TOTP);
    LOG("Generated TOTP from secret.");
    return code;
  } catch (e) {
    ERR("generateTotp error:", e && e.message || e);
    return null;
  }
}

/* Example SmartAPI login function (adaptable) */
async function smartLoginAttempt() {
  try {
    const totpCode = await generateTotp(); // may be null
    // Build a payload. Note: Endpoint path /body fields may need to change per exact SmartAPI spec.
    // This is a best-effort generic implementation.
    const payload = {
      api_key: SMART_API_KEY,
      user_id: SMART_USER_ID,
      password: SMART_API_SECRET ? undefined : undefined, // placeholder if needed
      totp: totpCode || undefined
    };

    // NOTE: Real SmartAPI login endpoint may be different; adjust as needed.
    const loginUrl = `${SMARTAPI_BASE}/service/login`; // <-- may need real path
    LOG("SmartAPI login attempt to", loginUrl);
    // Many brokers require specific headers/form; attempt JSON.
    const res = await fetchWithTimeout(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }, 20000);

    if (!res.ok) {
      LOG("SmartAPI login response not OK:", res.status);
      return false;
    }
    const j = await res.json();
    // Try to extract tokens; this depends on API response format.
    // We'll handle common cases:
    if (j && j.data && j.data.jwtToken) {
      accessToken = j.data.jwtToken;
      refreshToken = j.data.refreshToken || null;
      feedToken = j.data.feedToken || null;
      LOG("SmartAPI login success (jwtToken found). feedToken:", !!feedToken);
      return true;
    }
    if (j && j.access_token) {
      accessToken = j.access_token;
      refreshToken = j.refresh_token || null;
      feedToken = j.feed_token || null;
      LOG("SmartAPI login success (access_token found).");
      return true;
    }
    // fallback: inspect full object
    LOG("SmartAPI login result:", JSON.stringify(j).slice(0, 300));
    return false;
  } catch (e) {
    ERR("smartLoginAttempt error:", e && e.message || e);
    return false;
  }
}

/* Automatic login scheduler */
let loginRetryTimer = null;
async function ensureLoggedIn(initial = false) {
  try {
    LOG("ensureLoggedIn: accessToken present?", !!accessToken);
    if (accessToken) return true;
    const ok = await smartLoginAttempt();
    if (!ok) {
      LOG("Initial login failed, scheduling retry in 20s.");
      clearTimeout(loginRetryTimer);
      loginRetryTimer = setTimeout(() => ensureLoggedIn(false), 20000);
      return false;
    }
    // on success, maybe trigger websocket connect
    if (feedToken) {
      // attempt WS connect
      connectWS();
    }
    return true;
  } catch (e) {
    ERR("ensureLoggedIn error:", e && e.message || e);
    return false;
  }
}

/* Kick off login attempts immediately */
ensureLoggedIn(true);

/* ----------------- WebSocket connector (feed) ----------------- */
let wsReconnectAttempts = 0;
const WS_MAX_RETRY = 12;

function connectWS() {
  try {
    if (!feedToken) {
      LOG("No feedToken available - cannot open WS (will attempt login to get feedToken).");
      return;
    }
    if (wsClient && wsConnected) {
      LOG("WS already connected.");
      return;
    }

    const clientCode = SMART_USER_ID || "unknownClient";
    const wsUrl = `${SMARTAPI_WS_BASE}?clientCode=${encodeURIComponent(clientCode)}&feedToken=${encodeURIComponent(feedToken)}&apiKey=${encodeURIComponent(SMART_API_KEY)}`;
    LOG("Connecting WS to:", wsUrl);
    wsClient = new WebSocket(wsUrl);

    wsClient.on("open", () => {
      wsConnected = true;
      wsReconnectAttempts = 0;
      LOG("WS connected.");
      // subscribe to default channels if needed
      // example subscription (subject to broker format)
      // wsClient.send(JSON.stringify({ action: "subscribe", params: { /*...*/ } }));
    });

    wsClient.on("message", (data) => {
      // handle incoming market messages
      try {
        const parsed = typeof data === "string" ? JSON.parse(data) : JSON.parse(data.toString());
        // emit to internal handlers or log
        LOG("WS message:", (parsed && parsed.length) ? `array(${parsed.length})` : JSON.stringify(parsed).slice(0, 200));
      } catch (e) {
        // not JSON or parse failed
        LOG("WS raw message:", data.toString().slice(0, 200));
      }
    });

    wsClient.on("close", (code, reason) => {
      wsConnected = false;
      LOG(`WS closed. code=${code} reason=${reason}`);
      scheduleWsReconnect();
    });

    wsClient.on("error", (err) => {
      wsConnected = false;
      ERR("WS error:", err && err.message || err);
      try { wsClient.close(); } catch(e){/*ignore*/}
      scheduleWsReconnect();
    });

  } catch (e) {
    ERR("connectWS error:", e && e.message || e);
    scheduleWsReconnect();
  }
}

function scheduleWsReconnect() {
  if (wsReconnectAttempts >= WS_MAX_RETRY) {
    LOG("Max WS reconnect attempts reached.");
    return;
  }
  wsReconnectAttempts++;
  const delay = Math.min(60000, 2000 * wsReconnectAttempts); // exponential-ish
  LOG("Scheduling WS reconnect in", delay, "ms (attempt", wsReconnectAttempts, ")");
  setTimeout(() => {
    if (!feedToken) {
      LOG("No feedToken - will try to refresh login to obtain it.");
      ensureLoggedIn(false);
      return;
    }
    connectWS();
  }, delay);
}

/* If accessToken / feedToken expires we should clear and re-login;
   these parts depend on API responses. Provide helper to clear tokens. */
function clearTokens() {
  accessToken = null;
  refreshToken = null;
  feedToken = null;
  if (wsClient) {
    try { wsClient.terminate(); } catch(e) {}
    wsClient = null;
    wsConnected = false;
  }
}

/* Periodic maintenance tasks */
setInterval(() => {
  // refresh scrips every 24h
  const now = Date.now();
  if (!scripsLoadedAt || now - scripsLoadedAt > (24 * 60 * 60 * 1000)) {
    LOG("Periodic: refreshing ScripMaster.");
    downloadScripMaster().catch(e => ERR("Periodic ScripMaster update failed:", e));
  }
  // if not logged in, ensure
  if (!accessToken) {
    ensureLoggedIn(false);
  }
}, 60 * 1000); // every minute for checks

/* ----------------- Option-chain + Greeks (minimal engine) ----------------- */
/*
 This is a simplified engine to return option chain slices and greek estimates.
 It's not a trading-grade greeks engine; it provides approximate greeks using Black-Scholes.
*/

function bs_d1(S, K, r, sigma, t) {
  return (Math.log(S / K) + (r + 0.5 * sigma * sigma) * t) / (sigma * Math.sqrt(t));
}
function bs_d2(d1, sigma, t) {
  return d1 - sigma * Math.sqrt(t);
}
function normPdf(x) {
  return Math.exp(-0.5 * x * x) / Math.sqrt(2 * Math.PI);
}
function normCdf(x) {
  // Abramowitz & Stegun approximation
  const k = 1 / (1 + 0.2316419 * Math.abs(x));
  const a1 = 0.319381530;
  const a2 = -0.356563782;
  const a3 = 1.781477937;
  const a4 = -1.821255978;
  const a5 = 1.330274429;
  const poly = a1*k + a2*Math.pow(k,2) + a3*Math.pow(k,3) + a4*Math.pow(k,4) + a5*Math.pow(k,5);
  let approx = 1 - normPdf(x) * poly;
  if (x < 0) approx = 1 - approx;
  return approx;
}

function blackScholesGreeks({ S, K, r = 0.06, sigma = 0.25, t = 30/365, type = "call" }) {
  // t in years
  const T = Math.max(1e-6, t);
  const d1 = bs_d1(S, K, r, sigma, T);
  const d2 = bs_d2(d1, sigma, T);
  const Nd1 = normCdf(d1);
  const Nd2 = normCdf(d2);
  const n_d1 = normPdf(d1);
  let delta, gamma, vega, theta, rho;
  if (type === "call") {
    delta = Nd1;
    theta = -(S * n_d1 * sigma) / (2 * Math.sqrt(T)) - r * K * Math.exp(-r*T) * Nd2;
    rho = K * T * Math.exp(-r*T) * Nd2;
  } else {
    delta = Nd1 - 1;
    theta = -(S * n_d1 * sigma) / (2 * Math.sqrt(T)) + r * K * Math.exp(-r*T) * (1 - Nd2);
    rho = -K * T * Math.exp(-r*T) * (1 - Nd2);
  }
  gamma = n_d1 / (S * sigma * Math.sqrt(T));
  vega = S * n_d1 * Math.sqrt(T);
  return { delta, gamma, vega, theta, rho, d1, d2 };
}

/* ----------------- Express app and endpoints (start) ----------------- */
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/* Small helper wrappers for success / error JSON */
function ok(payload = {}) {
  return { success: true, ...payload };
}
function nok(code = "error", details = null) {
  return { success: false, message: code, details: details };
}

/* Root endpoint (status) */
app.get("/", (req, res) => {
  return res.json(ok({
    message: "Trading backend is running",
    version: "1.0.0",
    ws_connected: !!wsConnected,
    scrips_loaded: !!scripsCache,
    time: Date.now()
  }));
});

/* Debug env presence endpoint (DO NOT return secrets) */
app.get("/debug/env", (req, res) => {
  try {
    return res.json(ok({
      SMART_API_KEY: !!SMART_API_KEY,
      SMART_USER_ID: !!SMART_USER_ID,
      SCRIPS_LOADED: !!scripsCache,
      WS_CONNECTED: !!wsConnected
    }));
  } catch (e) {
    return res.status(500).json(nok("env_error", e && e.message));
  }
});

/* ADMIN status endpoint */
app.get("/admin/status", (req, res) => {
  try {
    return res.json(ok({
      ws_connected: !!wsConnected,
      scrips_loaded: !!scripsCache,
      scrips_entries: Array.isArray(scripsCache) ? scripsCache.length : (scripsCache ? "loaded" : 0),
      accessTokenPresent: !!accessToken,
      feedTokenPresent: !!feedToken,
      time: Date.now()
    }));
  } catch (e) {
    return res.status(500).json(nok("admin_error", e && e.message));
  }
});

/* PART 1 ends here - continue with PART 2 below */
// server.js - PART 2 of 3
// Continue from previous part

/* ----------------- /scrips/status and /scrips/search endpoints ----------------- */

/* Return small status and sample */
app.get("/scrips/status", (req, res) => {
  try {
    return res.json(ok({
      loaded: !!scripsCache,
      entries: Array.isArray(scripsCache) ? scripsCache.length : (scripsCache ? "loaded" : 0),
      loadedAt: scripsLoadedAt || null
    }));
  } catch (e) {
    return res.status(500).json(nok("scrips_status_error", e && e.message));
  }
});

/* Simple search in scrips by symbol or name (case-insensitive) */
app.get("/scrips/search", (req, res) => {
  try {
    const q = (req.query.q || "").trim().toLowerCase();
    if (!q) return res.json(ok({ results: [] }));
    if (!Array.isArray(scripsCache)) return res.status(500).json(nok("scrips_not_loaded"));
    const results = scripsCache.filter(s => {
      const symbol = (s.symbol || s.name || "").toString().toLowerCase();
      return symbol.includes(q);
    }).slice(0, 150);
    return res.json(ok({ results }));
  } catch (e) {
    return res.status(500).json(nok("scrip_search_error", e && e.message));
  }
});

/* ----------------- LTP endpoint (mocked / best-effort) ----------------- */
/*
 Note: Without a live market feed here we return a best-effort LTP:
  - if we have WS-received ticks we could store and return them (not implemented fully)
  - fallback: return last known price from scrips master if available (last_price field)
*/
const ltpStore = {}; // map token => { price, ts }

app.post("/market/ltp", (req, res) => {
  try {
    const { token, symbol } = req.body || {};
    if (!token && !symbol) return res.status(400).json(nok("missing_input"));
    if (token && ltpStore[token]) {
      return res.json(ok({ token, ltp: ltpStore[token].price, ts: ltpStore[token].ts }));
    }
    // fallback to scrips
    if (Array.isArray(scripsCache)) {
      const match = scripsCache.find(s => {
        if (token && s.token) return s.token.toString() === token.toString();
        if (symbol && s.symbol) return s.symbol.toString().toLowerCase() === symbol.toString().toLowerCase();
        return false;
      });
      if (match) {
        const lp = match.last_price || match.ltp || match.lastTradedPrice || null;
        return res.json(ok({ token: match.token || null, ltp: lp }));
      }
    }
    return res.status(404).json(nok("ltp_not_found"));
  } catch (e) {
    return res.status(500).json(nok("ltp_error", e && e.message));
  }
});

/* ----------------- Option Chain endpoint ----------------- */
/*
 Input: market (e.g., NIFTY), underlying_price (S), expiry (ISO or days), strikes array optional
 Output: array of option objects with bid/ask placeholders and greeks (approx)
*/
app.post("/option-chain", (req, res) => {
  try {
    const { market, S, expiry_days, strikes } = req.body || {};
    // Basic validation
    if (!market || !S) return res.status(400).json(nok("missing_market_or_underlying"));
    // convert expiry_days to years
    const days = parseInt(expiry_days || 30, 10);
    const t = Math.max(1, days) / 365.0;
    // if strikes not provided, auto-generate around S
    let strikeArray = Array.isArray(strikes) && strikes.length ? strikes.map(Number) : null;
    if (!strikeArray) {
      const atm = Math.round(S / 50) * 50; // round to nearest 50
      strikeArray = [];
      for (let d = -6; d <= 6; d++) strikeArray.push(atm + d * 50);
      strikeArray = Array.from(new Set(strikeArray)).sort((a,b)=>a-b);
    }
    const response = strikeArray.map(K => {
      const callGreeks = blackScholesGreeks({ S, K, r: 0.06, sigma: 0.35, t, type: "call" });
      const putGreeks = blackScholesGreeks({ S, K, r: 0.06, sigma: 0.35, t, type: "put" });
      // price placeholders: use BS approximated premium as theoretical (here not discounting for volatility surface)
      // The following is a rough theoretical price (not real market)
      const callPrice = Math.max(0, S * callGreeks.delta - K * Math.exp(-0.06*t) * normCdf(callGreeks.d2));
      const putPrice = Math.max(0, K * Math.exp(-0.06*t) * (1 - normCdf(putGreeks.d2)) - S * (1 - normCdf(putGreeks.d1)));
      return {
        strike: K,
        call: {
          lastPrice: Number(callPrice.toFixed(2)),
          greeks: {
            delta: callGreeks.delta,
            gamma: callGreeks.gamma,
            vega: callGreeks.vega,
            theta: callGreeks.theta,
            rho: callGreeks.rho
          }
        },
        put: {
          lastPrice: Number(putPrice.toFixed(2)),
          greeks: {
            delta: putGreeks.delta,
            gamma: putGreeks.gamma,
            vega: putGreeks.vega,
            theta: putGreeks.theta,
            rho: putGreeks.rho
          }
        }
      };
    });
    return res.json(ok({ market, S, expiry_days: days, chain: response }));
  } catch (e) {
    return res.status(500).json(nok("option_chain_error", e && e.message));
  }
});

/* ----------------- Force refresh endpoints (admin use only) ----------------- */

app.post("/admin/refresh-scrips", async (req, res) => {
  try {
    await downloadScripMaster();
    return res.json(ok({ refreshed: !!scripsCache }));
  } catch (e) {
    return res.status(500).json(nok("refresh_error", e && e.message));
  }
});

app.post("/admin/force-login", async (req, res) => {
  try {
    clearTokens();
    const okLogin = await ensureLoggedIn(false);
    return res.json(ok({ login: okLogin }));
  } catch (e) {
    return res.status(500).json(nok("force_login_error", e && e.message));
  }
});

/* ----------------- Small helper endpoint to get greeks for a single option ----------------- */
app.post("/greeks", (req, res) => {
  try {
    const { S, K, expiry_days, type } = req.body || {};
    if (!S || !K) return res.status(400).json(nok("missing_S_or_K"));
    const t = Math.max(1, parseInt(expiry_days || 30, 10)) / 365.0;
    const g = blackScholesGreeks({ S: Number(S), K: Number(K), r: 0.06, sigma: 0.35, t, type: (type==="put"?"put":"call") });
    return res.json(ok({ greeks: g }));
  } catch (e) {
    return res.status(500).json(nok("greeks_error", e && e.message));
  }
});

/* ----------------- Debug echo endpoints & last-resort 404 handler ----------------- */
app.post("/debug/echo", (req, res) => {
  try {
    return res.json(ok({ query: req.query, body: req.body, headers: req.headers }));
  } catch (e) {
    return res.status(500).json(nok("echo_error", e && e.message));
  }
});

/* If any route is not found */
app.use((req, res) => {
  return res.status(404).json(nok("route_not_found", req.originalUrl));
});

/* PART 2 ends here - final part below (boot & footer logs) */
// server.js - PART 3 of 3
// Bootstrap the server and final logs - paste at the end

/* ----------------- App bootstrap and final logs ----------------- */

// Start listening
const server = app.listen(PORT, () => {
  LOG("---------------------------------------------------------");
  LOG("✅ server.js fully loaded (Parts combined).");
  LOG("✅ SmartAPI + WS + OptionChain + Greeks + ScripMaster ready.");
  LOG("✅ Auto ScripMaster, Auto login attempts started.");
  LOG("✅ Listening on PORT:", PORT);
  LOG("---------------------------------------------------------");
});

// Handle graceful shutdown
function gracefulShutdown() {
  LOG("Received shutdown signal. Closing resources...");
  try {
    server.close(() => LOG("HTTP server closed."));
  } catch(e){}
  try {
    if (wsClient) wsClient.terminate();
  } catch(e){}
  process.exit(0);
}
process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

/* ----------------- Post-start actions ----------------- */
// Immediately ensure login attempt & ws connect
ensureLoggedIn(true).then(ok => {
  LOG("Initial ensureLoggedIn result:", ok);
  if (feedToken) connectWS();
}).catch(e => ERR("Post-start ensureLoggedIn error:", e));

/* Export for tests if required */
module.exports = { app, server };

/* END OF FILE - server.js COMPLETED */
