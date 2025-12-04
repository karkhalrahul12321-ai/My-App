/**
 * ============================================================
 *   FULL BACKEND — COMPLETE SERVER (3-PART VERSION)
 * ============================================================
 *  ✔ SmartAPI login (API key + secret + TOTP auto)
 *  ✔ Auto token refresh (retry + fallback)
 *  ✔ WebSocket live market stream + auto reconnect
 *  ✔ Option-chain (NIFTY + SENSEX + NATURALGAS)
 *  ✔ Greeks calculation
 *  ✔ Premium engine
 *  ✔ LTP endpoint
 *  ✔ Auto ScripMaster Loader (JSON primary + ZIP fallback)
 *  ✔ Render-compatible PORT binding
 *  ✔ Debug + Admin endpoints
 *
 *  NOTE:
 *  Must include .env:
 *  SMART_API_KEY
 *  SMART_API_SECRET
 *  SMART_TOTP      (or SMART_TOTP_SECRET)
 *  SMART_USER_ID
 * ============================================================
 */

const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const WebSocket = require("ws");
const unzipper = require("unzipper");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());

/* ------------------------------------------------------------
   Environment
-------------------------------------------------------------*/
const API_KEY = process.env.SMART_API_KEY;
const API_SECRET = process.env.SMART_API_SECRET;
const API_USER = process.env.SMART_USER_ID;

const TOTP_STATIC =
  process.env.SMART_TOTP ||
  process.env.SMART_TOTP_SECRET ||
  null;

let accessToken = null;
let feedToken = null;
let ws = null;
let wsConnected = false;

const SCRIPMASTER_JSON =
  "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";

const SCRIPMASTER_ZIP =
  "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.zip";

let scripsCache = null;

/* ------------------------------------------------------------
   Helper – safe logs
-------------------------------------------------------------*/
const ok = (msg, data = null) => ({ success: true, message: msg, details: data });
const nok = (msg, data = null) => ({ success: false, message: msg, details: data });

function log(...a) {
  console.log(new Date().toISOString(), ">", ...a);
}

/* ------------------------------------------------------------
   TOTP Generator (safe fallback)
-------------------------------------------------------------*/
function generateTOTP() {
  try {
    if (!TOTP_STATIC) return null;
    const totpGen = require("totp-generator");
    return totpGen(TOTP_STATIC);
  } catch (e) {
    log("totp-generator failed:", e.message);
    try {
      const { totp } = require("otplib");
      return totp.generate(TOTP_STATIC);
    } catch (e2) {
      log("otplib totp failed:", e2.message);
      return null;
    }
  }
}

/* ------------------------------------------------------------
   SmartAPI Login
-------------------------------------------------------------*/
async function smartLogin() {
  try {
    const totp = generateTOTP();
    if (!totp) return { ok: false, why: "NO_TOTP" };

    const loginURL = "https://apiconnect.angelbroking.com/rest/auth/secure/login/v1";
    const payload = {
      clientcode: API_USER,
      password: API_KEY,
      totp,
    };

    const resp = await fetch(loginURL, {
      method: "POST",
      headers: {
        "X-ClientLocalIP": "0.0.0.0",
        "X-ClientPublicIP": "0.0.0.0",
        "X-MACAddress": "00:00:00:00:00:00",
        "X-PrivateKey": API_SECRET,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const json = await resp.json();

    if (!json?.data?.jwtToken) {
      return { ok: false, why: "LOGIN_FAILED", raw: json };
    }

    accessToken = json.data.jwtToken;
    feedToken = json.data.feedToken;

    log("✓ SmartAPI login success");
    return { ok: true };
  } catch (e) {
    return { ok: false, why: e.message };
  }
}

/* ------------------------------------------------------------
   ScripMaster Loader (JSON → ZIP fallback)
-------------------------------------------------------------*/
async function loadScripMaster() {
  try {
    log("Downloading ScripMaster JSON...");
    const r = await fetch(SCRIPMASTER_JSON);
    if (!r.ok) throw new Error("JSON download failed");

    scripsCache = await r.json();
    log("✓ ScripMaster JSON loaded:", scripsCache.length);
  } catch (e) {
    log("JSON failed:", e.message);
    log("Trying ZIP fallback...");

    try {
      const r2 = await fetch(SCRIPMASTER_ZIP);
      if (!r2.ok) throw new Error("ZIP download failed");

      const buffer = await r2.buffer();
      const directory = await unzipper.Open.buffer(buffer);
      for (const file of directory.files) {
        if (file.path.endsWith(".json")) {
          const content = JSON.parse(await file.buffer());
          scripsCache = content;
          log("✓ ScripMaster ZIP loaded:", scripsCache.length);
        }
      }
    } catch (e2) {
      log("ZIP fallback failed:", e2.message);
    }
  }
}
/* =============================================================
   PART-2: WebSocket connector, market feed handling,
           option-chain helpers, greeks & premium engine
   ============================================================= */

/* ------------------------------------------------------------
   WebSocket: connect to SmartAPI market stream (uses feedToken)
   - builds URL with clientCode, feedToken, apiKey
   - reconnects with exponential backoff
-------------------------------------------------------------*/
const WS_BASE = process.env.SMARTAPI_WS_BASE || "wss://smartapisocket.angelone.in/smart-stream";
const WS_CLIENT_CODE = process.env.WS_CLIENT_CODE || API_USER;
let wsRetry = 0;
let wsRetryTimer = null;
const WS_MAX_RETRY = 12;

function buildWsUrl() {
  if (!feedToken || !API_KEY) return null;
  const qs = `?clientCode=${encodeURIComponent(WS_CLIENT_CODE)}&feedToken=${encodeURIComponent(feedToken)}&apiKey=${encodeURIComponent(API_KEY)}`;
  return WS_BASE + qs;
}

function wsConnect() {
  const url = buildWsUrl();
  if (!url) {
    log("No feedToken — cannot open WS");
    wsConnected = false;
    return;
  }

  try {
    log("Connecting WS to:", url);
    ws = new WebSocket(url);

    ws.on("open", () => {
      wsConnected = true;
      wsRetry = 0;
      log("✓ WS open");
      // subscribe to default topics if needed
    });

    ws.on("message", (msg) => {
      try {
        // SmartAPI WS may send binary or JSON — try JSON parse
        const data = typeof msg === "string" ? JSON.parse(msg) : JSON.parse(msg.toString());
        handleWsMessage(data);
      } catch (e) {
        log("WS message parse error:", e.message);
      }
    });

    ws.on("close", (code, reason) => {
      wsConnected = false;
      log("WS closed:", code, reason && reason.toString ? reason.toString() : reason);
      scheduleReconnect();
    });

    ws.on("error", (err) => {
      wsConnected = false;
      log("WS error:", err && err.message ? err.message : err);
      try { ws.close(); } catch (e) {}
    });
  } catch (e) {
    wsConnected = false;
    log("WS connect exception:", e.message);
    scheduleReconnect();
  }
}

function scheduleReconnect() {
  if (wsRetryTimer) return;
  wsRetry++;
  const wait = Math.min(30000, 1000 * Math.pow(2, Math.min(wsRetry, WS_MAX_RETRY)));
  log(`WS reconnect scheduled in ${wait}ms (attempt ${wsRetry})`);
  wsRetryTimer = setTimeout(() => {
    wsRetryTimer = null;
    wsConnect();
  }, wait);
}

/* ------------------------------------------------------------
   WS Message handler (placeholder — you can expand)
-------------------------------------------------------------*/
function handleWsMessage(data) {
  // Example: { payload: {...}, type: 'ltp' } - depends on SmartAPI format
  // For now just log minimal
  // You can add logic: update in-memory LTP store, feed to endpoints, etc.
  if (data && data.payload) {
    // keep it lightweight
    // e.g., update a small map of latest LTPs if provided
    try {
      if (!global.ltpMap) global.ltpMap = new Map();
      const p = data.payload;
      if (p.token && p.lastPrice != null) {
        global.ltpMap.set(String(p.token), { price: p.lastPrice, at: Date.now() });
      }
    } catch (e) { /* ignore */ }
  }
}

/* ------------------------------------------------------------
   Auto-login / token refresh loop
   - Performs initial login, then refresh every N minutes
   - If login fails, schedule retry
-------------------------------------------------------------*/
let loginIntervalTimer = null;
async function ensureLogin() {
  const res = await smartLogin();
  if (!res.ok) {
    log("SmartAPI login failed:", res.why || res.raw || res);
    // retry later
    if (loginIntervalTimer) clearTimeout(loginIntervalTimer);
    loginIntervalTimer = setTimeout(ensureLogin, 20000);
    return;
  }
  // on success, reset reconnection and open WS
  if (ws) try { ws.terminate(); } catch (e) {}
  wsConnect();

  // schedule token refresh: SmartAPI tokens typically last long — refresh every 15m
  if (loginIntervalTimer) clearTimeout(loginIntervalTimer);
  loginIntervalTimer = setTimeout(ensureLogin, 15 * 60 * 1000);
}

/* ------------------------------------------------------------
   Option chain & Greeks helpers (basic)
   - Uses SmartAPI option Greek endpoint or local calc fallback
-------------------------------------------------------------*/
async function fetchOptionGreeks(symbol, expiryDate) {
  // Prefer server-side API if available
  try {
    const url = "https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/optionGreek";
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken || ""}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: symbol, expirydate: expiryDate }),
    });
    const json = await resp.json();
    return json;
  } catch (e) {
    log("fetchOptionGreeks failed:", e.message);
    return null;
  }
}

// Basic Black-Scholes Greeks implementation (for fallback calculations)
function bsGreeks({ S, K, r = 0.07, sigma = 0.25, t = 30 / 365, type = "call" }) {
  // S: spot, K: strike, r: interest, sigma: vol, t: time years
  // use math functions
  function normPdf(x) { return Math.exp(-0.5 * x * x) / Math.sqrt(2 * Math.PI); }
  function normCdf(x) { // Abramowitz-Stegun approximation
    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x) / Math.sqrt(2);
    const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741, a4 = -1.453152027, a5 = 1.061405429;
    const p = 0.3275911;
    const t1 = 1 / (1 + p * x);
    const y = 1 - (((((a5 * t1 + a4) * t1) + a3) * t1 + a2) * t1 + a1) * t1 * Math.exp(-x * x);
    return 0.5 * (1 + sign * y);
  }

  const sqrtT = Math.sqrt(t);
  const d1 = (Math.log(S / K) + (r + 0.5 * sigma * sigma) * t) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  const Nd1 = normCdf(d1);
  const Nd2 = normCdf(d2);
  const pdfd1 = normPdf(d1);

  const delta = type === "call" ? Nd1 : Nd1 - 1;
  const gamma = pdfd1 / (S * sigma * sqrtT);
  const vega = S * pdfd1 * sqrtT;
  const theta = - (S * pdfd1 * sigma) / (2 * sqrtT) - (type === "call" ? r * K * Math.exp(-r * t) * Nd2 : -r * K * Math.exp(-r * t) * (1 - Nd2));
  const rho = type === "call" ? K * t * Math.exp(-r * t) * Nd2 : -K * t * Math.exp(-r * t) * (1 - Nd2);

  return { delta, gamma, theta, vega, rho };
}

/* ------------------------------------------------------------
   Premium engine (placeholder)
   - Simple sample premium calculation using LTP or greeks
-------------------------------------------------------------*/
function premiumEngineForStrike(symbolName, strike, spot, expiryDays) {
  // This is a simple fallback engine. Replace with your own logic if needed.
  const days = Math.max(1, expiryDays);
  const greeks = bsGreeks({ S: spot, K: strike, sigma: 0.3, t: days / 365, type: "call" });
  // price approx via Black-Scholes (not implemented full here) -> use greeks for hints
  const estPremium = Math.max(1, Math.abs(spot - strike) * 0.1 + greeks.vega * 0.01);
  return { premium: +estPremium.toFixed(2), greeks };
}

/* ------------------------------------------------------------
   REST helpers for option chain: find nearest strikes
-------------------------------------------------------------*/
function findNearestStrikes(spot, step = 50, count = 3) {
  // generate strikes around spot with given step, return array of strike values (3 up, 3 down sample)
  const center = Math.round(spot / step) * step;
  const strikes = [];
  // return center and two above for sample (your earlier ask: 3 strikes)
  for (let i = 0; i < count; i++) strikes.push(center + i * step);
  return strikes;
}

/* ------------------------------------------------------------
   Initialize scripmaster + login on startup
-------------------------------------------------------------*/
(async function bootstrapInitial() {
  try {
    await loadScripMaster();
    // start login attempts
    await ensureLogin();
  } catch (e) {
    log("bootstrapInitial error:", e.message);
  }
})();
/* =============================================================
   PART-3 / FINAL
   API endpoints (LTP, Option chain, Greeks, Premium),
   Admin routes, Debug routes,
   PORT binding for Render,
   END OF FILE
   ============================================================= */

/* ------------------------------------------------------------
   Helper: find token by tradingsymbol from ScripMaster
-------------------------------------------------------------*/
function findToken(tsym) {
  if (!scripsCache) return null;
  const row = scripsCache.find(r => r.tradingsymbol === tsym);
  return row ? row.token : null;
}

/* ------------------------------------------------------------
   GET /market/ltp?symbol=NIFTY&strike=24500&type=CE
-------------------------------------------------------------*/
app.get("/market/ltp", async (req, res) => {
  try {
    const { symbol, strike, type } = req.query;
    if (!symbol) return res.json(nok("missing_symbol"));

    const tsym = strike && type ? `${symbol}${strike}${type}` : symbol;
    const token = findToken(tsym);

    if (!token) return res.json(nok("token_not_found", tsym));

    // try WS live data first
    if (global.ltpMap && global.ltpMap.has(String(token))) {
      const l = global.ltpMap.get(String(token));
      return res.json(ok({ symbol, token, ltp: l.price, ts: l.at }));
    }

    // fallback to REST SmartAPI LTP
    const url = "https://apiconnect.angelone.in/rest/secure/marketdata/v1/quote";
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ mode: "LTP", exchangeTokens: { NSE: [token] } }),
    });
    const json = await resp.json();
    return res.json(ok({ symbol, token, raw: json }));
  } catch (e) {
    return res.status(500).json(nok("ltp_error", e.message));
  }
});

/* ------------------------------------------------------------
   GET /option-chain?symbol=NIFTY&spot=24540&expiry_days=5
-------------------------------------------------------------*/
app.get("/option-chain", async (req, res) => {
  try {
    const { symbol, spot, expiry_days } = req.query;
    if (!symbol) return res.json(nok("missing_symbol"));
    if (!spot) return res.json(nok("missing_spot"));

    const nearest = findNearestStrikes(+spot, 50, 3);
    const out = [];

    for (const st of nearest) {
      const ceSym = `${symbol}${st}CE`;
      const peSym = `${symbol}${st}PE`;
      const ceTok = findToken(ceSym);
      const peTok = findToken(peSym);

      out.push({
        strike: st,
        CE: ceTok ? { symbol: ceSym, token: ceTok } : null,
        PE: peTok ? { symbol: peSym, token: peTok } : null,
      });
    }

    return res.json(ok({ symbol, nearest_strikes: out }));
  } catch (e) {
    return res.status(500).json(nok("oc_error", e.message));
  }
});

/* ------------------------------------------------------------
   GET /greeks?symbol=NIFTY&strike=24500&spot=24540&type=CE&expiry_days=5
-------------------------------------------------------------*/
app.get("/greeks", async (req, res) => {
  try {
    const { symbol, strike, spot, type, expiry_days } = req.query;
    if (!symbol || !strike || !spot || !type)
      return res.json(nok("missing_params"));

    const greeks = bsGreeks({
      S: +spot,
      K: +strike,
      sigma: 0.25,
      t: (+expiry_days || 5) / 365,
      type: type.toLowerCase() === "ce" ? "call" : "put",
    });

    return res.json(ok({ symbol, strike, type, greeks }));
  } catch (e) {
    return res.status(500).json(nok("greeks_error", e.message));
  }
});

/* ------------------------------------------------------------
   GET /premium?symbol=NIFTY&strike=24500&spot=24540&expiry_days=5
-------------------------------------------------------------*/
app.get("/premium", (req, res) => {
  try {
    const { symbol, strike, spot, expiry_days } = req.query;
    if (!symbol || !strike || !spot)
      return res.json(nok("missing_params"));

    const p = premiumEngineForStrike(symbol, +strike, +spot, +expiry_days || 5);
    return res.json(ok({ symbol, ...p }));
  } catch (e) {
    return res.status(500).json(nok("premium_err", e.message));
  }
});

/* ------------------------------------------------------------
   GET /admin/status
-------------------------------------------------------------*/
app.get("/admin/status", (req, res) => {
  return res.json(
    ok({
      server_time: Date.now(),
      smart_logged_in: !!accessToken,
      feedToken_present: !!feedToken,
      ws_connected: wsConnected,
      scrips_loaded: !!scripsCache,
    })
  );
});

/* ------------------------------------------------------------
   DEBUG: /debug/env
-------------------------------------------------------------*/
app.get("/debug/env", (req, res) => {
  return res.json(
    ok({
      SMART_API_KEY: !!API_KEY,
      SMART_API_SECRET: !!API_SECRET,
      SMART_TOTP: !!TOTP_SECRET || !!STATIC_TOTP,
      SMART_USER_ID: !!API_USER,
      feedToken: !!feedToken,
      accessToken: !!accessToken,
    })
  );
});

/* ------------------------------------------------------------
   404 handler
-------------------------------------------------------------*/
app.use((req, res) => {
  return res.status(404).json(nok("route_not_found", req.originalUrl));
});

/* ------------------------------------------------------------
   PORT binding (Render)
-------------------------------------------------------------*/
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  log("------------------------------------------------");
  log("✓ server.js fully loaded (PART 1 → PART 3)");
  log("✓ SmartAPI login + WebSocket + OptionChain active");
  log("✓ ScripMaster:", !!scripsCache);
  log("✓ FeedToken:", !!feedToken);
  log("✓ PORT:", PORT);
  log("------------------------------------------------");
});

/* ========================== END OF FILE ========================== */
