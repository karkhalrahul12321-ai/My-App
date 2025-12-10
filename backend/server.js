/* ============================================================
   TENGO BACKEND - FINAL FIXED CommonJS VERSION (NO IMPORTS)
   SmartAPI Login (Password + TOTP) + SmartStream V2 WebSocket
   ============================================================ */

const express = require("express");
const crypto = require("node:crypto");
const fetch = (...args) => import("node-fetch").then(mod => mod.default(...args));
const WebSocket = require("ws");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

/* ----------------------------
   ENV VARIABLES (REQUIRED)
----------------------------- */

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP_SECRET || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

const SMARTAPI_BASE = "https://smartapi.angelone.in";
const PORT = process.env.PORT || 10000;

/* ----------------------------
   INTERNAL SESSION STORE
----------------------------- */

let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0
};

/* ----------------------------
   TOTP GENERATOR
----------------------------- */

function generateTOTP(secret) {
  try {
    const clean = secret.replace(/[^A-Z2-7=]/gi, "");
    const buffer = Buffer.from(clean, "base32");
    const time = Math.floor(Date.now() / 30000);
    const msg = Buffer.alloc(8);

    msg.writeUInt32BE(0, 0);
    msg.writeUInt32BE(time, 4);

    const hmac = crypto.createHmac("sha1", buffer).update(msg).digest();
    const offset = hmac[19] & 0xf;

    const code =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    return (code % 1000000).toString().padStart(6, "0");
  } catch (e) {
    return null;
  }
}

/* ----------------------------
   SAFE FETCH JSON
----------------------------- */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

module.exports = { app }; // (Just exporting if needed externally)

/* ----------------------------
   END OF PART 1
----------------------------- */
/* ----------------------------
   server.js - PART 2 of 6
   SmartAPI Login + FeedToken Fetch + WS v2 bootstrap const
   ---------------------------- */

const WS_V2_URL = "wss://smartapisocket.angelone.in/smart-stream"; // URL base (we'll append query if needed)

// SMARTAPI: login using password + TOTP
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);
    if (!totp) return { ok: false, reason: "TOTP_FAILED" };

    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: totp
        })
      }
    );

    const data = await resp.json().catch(() => null);
    console.log("LOGIN RAW:", JSON.stringify(data || null, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // ~20 hours

    console.log("DEBUG: After Login SESSION =>", {
      access_token_set: !!session.access_token,
      feed_token_set: !!session.feed_token,
      expires_at: session.expires_at
    });

    return { ok: true };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// Express login route
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
  const r = await smartApiLogin(password);
  console.log("After Login SESSION:", session);

  if (!r.ok) {
    return res.json({
      success: false,
      error:
        r.reason === "ENV_MISSING"
          ? "SmartAPI ENV missing"
          : r.reason === "PASSWORD_MISSING"
          ? "Password missing"
          : r.reason === "LOGIN_FAILED"
          ? "SmartAPI login failed"
          : "Login error: " + (r.error || "Unknown"),
      raw: r.raw || null
    });
  }

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at
    }
  });
});

// Login status route (for quick URL tests)
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null
  });
});

/* ----------------------------
   END OF PART 2
---------------------------- */
/* ----------------------------
   server.js - PART 3 of 6
   Smart Stream WebSocket v2 (URL Auth Mode)
---------------------------- */

let wsClient = null;
let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subs: []
};

// Build full Smart Stream URL (clientCode + feedToken + apiKey)
function buildWsV2Url() {
  if (!session.feed_token || !session.access_token) return null;

  return (
    WS_V2_URL +
    `?clientCode=${SMART_USER_ID}` +
    `&feedToken=${session.feed_token}` +
    `&apiKey=${SMART_API_KEY}`
  );
}

// Start SmartAPI V2 WebSocket
async function startWebsocketV2() {
  console.log("DEBUG: V2 Start Check =>", {
    access_token_set: !!session.access_token,
    feed_token_set: !!session.feed_token,
    expires_at: session.expires_at
  });

  if (!session.access_token || !session.feed_token) {
    console.log("WSv2 WAIT: token missing");
    return;
  }

  const fullUrl = buildWsV2Url();
  if (!fullUrl) {
    console.log("WSv2 ERROR: Missing URL build fields");
    return;
  }

  // Clean old WS
  if (wsClient) {
    try {
      wsClient.close();
    } catch (_) {}
    wsClient = null;
    wsStatus.connected = false;
  }

  console.log("WSv2 → CONNECTING:", fullUrl);

  wsClient = new WebSocket(fullUrl, { perMessageDeflate: false });

  // When connected
  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.lastError = null;
    wsStatus.reconnectAttempts = 0;

    console.log("WSv2 → CONNECTED");
  });

  // When message arrives (LTP etc.)
  wsClient.on("message", (msg) => {
    wsStatus.lastMsgAt = Date.now();

    try {
      const parsed = JSON.parse(msg.toString());
      // console.log("WSv2 MSG:", parsed);
    } catch (err) {
      console.log("WSv2 PARSE ERR:", err.message);
    }
  });

  // On error
  wsClient.on("error", (err) => {
    wsStatus.lastError = err?.message || "WS ERROR";
    console.log("WSv2 ERROR:", wsStatus.lastError);
  });

  // On close → auto reconnect
  wsClient.on("close", () => {
    console.log("WSv2 CLOSED");
    wsStatus.connected = false;

    setTimeout(() => {
      wsStatus.reconnectAttempts++;
      console.log("WSv2 → RECONNECT Attempt:", wsStatus.reconnectAttempts);
      startWebsocketV2();
    }, 2000);
  });
}

// Auto WebSocket Starter
setInterval(() => {
  const exp = session.expires_at || 0;
  const now = Date.now();

  if (!session.access_token || now >= exp) {
    wsStatus.connected = false;
    return;
  }

  if (!wsStatus.connected) startWebsocketV2();
}, 3000);

// API: WebSocket status
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subs
  });
});

/* ----------------------------
   END OF PART 3
---------------------------- */
/* ----------------------------
   server.js — PART 4 of 6
   Smart Stream v2 LTP Subscribe / Unsubscribe System
---------------------------- */

// Build Subscription Payload for Smart Stream V2
function buildSubPayload(tokens) {
  return {
    action: "subscribe",
    params: {
      mode: "ltp",
      tokenList: tokens
    }
  };
}

// Build Unsubscribe Payload
function buildUnsubPayload(tokens) {
  return {
    action: "unsubscribe",
    params: {
      mode: "ltp",
      tokenList: tokens
    }
  };
}

// Send data safely to WS
function wsSendSafe(obj) {
  if (!wsClient || wsClient.readyState !== 1) {
    console.log("WSv2 SEND FAIL → not connected");
    return false;
  }

  try {
    wsClient.send(JSON.stringify(obj));
    return true;
  } catch (err) {
    console.log("WSv2 SEND ERROR:", err.message);
    return false;
  }
}

// Subscribe function
async function subscribeTokens(tokens) {
  if (!tokens || !Array.isArray(tokens) || tokens.length === 0) {
    return { ok: false, error: "NO_TOKENS" };
  }

  const payload = buildSubPayload(tokens);
  const ok = wsSendSafe(payload);

  if (ok) {
    wsStatus.subs.push(...tokens);
    wsStatus.subs = [...new Set(wsStatus.subs)]; // make unique
    console.log("WSv2 SUB:", tokens);
  }

  return { ok };
}

// Unsubscribe
async function unsubscribeTokens(tokens) {
  if (!tokens || !Array.isArray(tokens) || tokens.length === 0) {
    return { ok: false, error: "NO_TOKENS" };
  }

  const payload = buildUnsubPayload(tokens);
  const ok = wsSendSafe(payload);

  if (ok) {
    wsStatus.subs = wsStatus.subs.filter((t) => !tokens.includes(t));
    console.log("WSv2 UNSUB:", tokens);
  }

  return { ok };
}

// API: Subscribe
app.post("/api/ws/subscribe", async (req, res) => {
  const { tokens } = req.body || {};
  const out = await subscribeTokens(tokens);
  res.json(out);
});

// API: Unsubscribe
app.post("/api/ws/unsubscribe", async (req, res) => {
  const { tokens } = req.body || {};
  const out = await unsubscribeTokens(tokens);
  res.json(out);
});

/* ----------------------------
   END OF PART 4
---------------------------- */
/* ----------------------------
   server.js — PART 5 of 6
   Trading Engine: Spot LTP, Futures LTP, Options LTP,
   Strike Generator, Trend, computeEntry()
---------------------------- */

// --------------------------------------------------
// WEEKLY EXPIRY DETECTOR (THURSDAY)
// --------------------------------------------------
function detectExpiry() {
  const t = new Date();
  const d = t.getDay(); // 4 = Thursday
  const expiry = new Date(t);

  if (d <= 4) expiry.setDate(t.getDate() + (4 - d));
  else expiry.setDate(t.getDate() + (7 - (d - 4)));

  const yyyy = expiry.getFullYear();
  const mm = String(expiry.getMonth() + 1).padStart(2, "0");
  const dd = String(expiry.getDate()).padStart(2, "0");

  return `${yyyy}-${mm}-${dd}`;
}

// --------------------------------------------------
// SPOT LTP FETCH
// --------------------------------------------------
async function fetchSpotLTP(symbol) {
  try {
    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
        method: "POST",
        headers: {
          Authorization: session.access_token,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB"
        },
        body: JSON.stringify({
          exchange: "NSE",
          tradingsymbol: symbol,
          symboltoken: ""
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp =
      Number(j?.data?.ltp) ||
      Number(j?.data?.lastPrice) ||
      Number(j?.data?.ltpValue);

    return isFinite(ltp) ? ltp : null;
  } catch (_) {
    return null;
  }
}

// --------------------------------------------------
// OPTION LTP FETCH (CE/PE)
// --------------------------------------------------
async function fetchOption(symbol, strike, type) {
  try {
    const exch = "NFO";
    const ts = `${symbol}${strike}${type}00`;

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
        method: "POST",
        headers: {
          Authorization: session.access_token,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          exchange: exch,
          tradingsymbol: ts,
          symboltoken: ""
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice);
    return isFinite(ltp) ? ltp : null;
  } catch (_) {
    return null;
  }
}

// --------------------------------------------------
// STRIKES (ATM, CE, PE)
// --------------------------------------------------
function getStrikes(spot) {
  spot = Number(spot) || 0;
  const atm = Math.round(spot / 50) * 50;
  return {
    atm,
    ce: atm + 50,
    pe: atm - 50
  };
}

// --------------------------------------------------
// SIMPLE TREND ENGINE
// --------------------------------------------------
function getTrend({ ema20, ema50, rsi, vwap, spot }) {
  let direction = "NEUTRAL";

  if (ema20 > ema50) direction = "UP";
  if (ema20 < ema50) direction = "DOWN";

  return {
    direction,
    note: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
  };
}

// --------------------------------------------------
// FINAL ENTRY COMPUTE
// --------------------------------------------------
async function computeEntry({ symbol, spot, ema20, ema50, rsi, vwap }) {
  const trend = getTrend({ ema20, ema50, rsi, vwap, spot });
  const strikes = getStrikes(spot);

  const ce = await fetchOption(symbol, strikes.ce, "CE");
  const pe = await fetchOption(symbol, strikes.pe, "PE");

  return {
    trend,
    strikes,
    ce_ltp: ce,
    pe_ltp: pe
  };
}

// --------------------------------------------------
// /api/compute Route
// --------------------------------------------------
app.post("/api/compute", async (req, res) => {
  try {
    const b = req.body || {};
    const symbol = (b.market || "NIFTY").toUpperCase();

    let spot = Number(b.spot) || null;

    // WS Live LTP override
    if (b.use_live && wsStatus.connected && wsStatus.lastMsgAt > 0) {
      // no tick parser yet, so fallback to stored:
      spot = spot || null;
    }

    // fallback → API LTP
    if (!spot) {
      spot = await fetchSpotLTP(symbol);
    }

    const ema20 = Number(b.ema20 || 0);
    const ema50 = Number(b.ema50 || 0);
    const rsi = Number(b.rsi || 0);
    const vwap = Number(b.vwap || 0);

    const result = await computeEntry({
      symbol,
      spot,
      ema20,
      ema50,
      rsi,
      vwap
    });

    res.json({
      success: true,
      message: "Compute OK",
      input: {
        symbol,
        spot,
        ema20,
        ema50,
        rsi,
        vwap
      },
      result
    });
  } catch (err) {
    res.json({
      success: false,
      error: err.message || "Compute Failed"
    });
  }
});

/* ----------------------------
   END OF PART 5
---------------------------- */
/* ----------------------------
   server.js — PART 6 of 6 (FINAL)
   Server Listen + Auto WS Start + Health Route
---------------------------- */

// HEALTH CHECK
app.get("/", (req, res) => {
  res.send("TENGO Backend is running — Smart Stream V2 Active");
});

// AUTO START SMART-STREAM WS (every 3 seconds check in Part 3)
setTimeout(() => {
  console.log("WSv2 AUTO-START Triggered...");
  startWebsocketV2();
}, 1500);

// START EXPRESS SERVER
app.listen(PORT, () => {
  console.log(`SERVER LIVE on PORT ${PORT}`);
});

/* ============================================================
   END OF FULL server.js — FINAL VERSION (CommonJS + SmartStream)
   ============================================================ */
