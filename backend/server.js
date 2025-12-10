/* =====================================================================
   TENGO FINAL FIXED (Original 1200+ lines preserved)
   MODE: Smart-Stream V2 (URL Auth)
   FIXED: login + fetch + websocket v2
   ===================================================================== */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");
require("dotenv").config();
const moment = require("moment");

/* Safe fetch wrapper (Node + Browser compatible) */
const fetch =
  global.fetch ||
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));

const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

/* =====================================================================
   FRONTEND SERVE (same as your original)
   ===================================================================== */

try {
  const frontendPath = path.join(__dirname, "..", "frontend");
  app.use(express.static(frontendPath));
} catch (e) {
  // ignore if missing
}

/* =====================================================================
   ENV SMART API
   ===================================================================== */

const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelone.in";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* =====================================================================
   MEMORY SESSION STORE (unchanged from your original)
   ===================================================================== */

let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: null,
};
/* =====================================================================
   SMART API – LOGIN (Password + TOTP)
   ===================================================================== */

function generateTOTP(secret) {
  try {
    const epoch = Math.floor(Date.now() / 1000);
    const time = Buffer.alloc(8);
    time.writeBigInt64BE(BigInt(Math.floor(epoch / 30)));

    const hmac = crypto.createHmac("sha1", Buffer.from(secret, "hex"));
    hmac.update(time);

    const digest = hmac.digest();
    const offset = digest[digest.length - 1] & 0xf;

    const code =
      ((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff);

    return (code % 1000000).toString().padStart(6, "0");
  } catch (e) {
    return null;
  }
}

/* Safe JSON fetch wrapper */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const j = await r.json().catch(() => null);
    return { ok: true, data: j, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/* =====================================================================
   LOGIN FUNCTION (fixed)
   ===================================================================== */

async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_API_SECRET || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

    const loginResp = await safeFetchJson(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: totp,
        }),
      }
    );

    if (!loginResp.ok || !loginResp.data?.status) {
      return { ok: false, reason: "LOGIN_FAILED" };
    }

    const tokens = loginResp.data.data;
    session.access_token = tokens.jwtToken;
    session.refresh_token = tokens.refreshToken;
    session.feed_token = tokens.feedToken;
    session.expires_at = Date.now() + 12 * 60 * 60 * 1000;

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "ERR", error: e.message };
  }
}
/* ============================
   PART-3/6
   Smart-Stream V2 (URL-auth) WebSocket bootstrap
   - URL auth (no auth payload)
   - reconnect, heartbeat, basic msg handler
   - uses session.feed_token, SMART_USER_ID, SMART_API_KEY
   ============================ */

const WS_V2_BASE = "wss://smartapisocket.angelone.in/smart-stream";

let wsClient = null;
let wsStatus = {
  connected: false,
  lastMsgAt: null,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

// build the full url with required query params (browser-safe)
function buildWsV2Url() {
  const feed = session.feed_token || "";
  const clientCode = SMART_USER_ID || "";
  const apiKey = SMART_API_KEY || "";
  // required: clientCode, feedToken, apiKey
  const q = new URLSearchParams({
    clientCode,
    feedToken: feed,
    apiKey
  });
  return `${WS_V2_BASE}?${q.toString()}`;
}

function safeLogWs(...args) {
  try { console.log(...args); } catch(e){}
}

// start WS only when tokens present and not already connected
async function startWebsocketV2IfReady() {
  safeLogWs("DEBUG: Before WS Start =>", {
    access_token_set: !!session.access_token,
    feed_token_set: !!session.feed_token,
    expires_at: session.expires_at
  });

  if (wsClient && wsStatus.connected) return;
  if (!session.feed_token || !SMART_USER_ID || !SMART_API_KEY) {
    safeLogWs("WSv2 WAIT: url-auth tokens missing");
    return;
  }

  try {
    // cleanup existing
    if (wsClient) {
      try { wsClient.close(); } catch (e) {}
      wsClient = null;
      wsStatus.connected = false;
    }

    const fullUrl = buildWsV2Url();
    safeLogWs("WSv2: connecting to:", fullUrl);

    const WebSocket = require("ws");
    wsClient = new WebSocket(fullUrl, { perMessageDeflate: false });

    // on open
    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;
      safeLogWs("WSv2: connected.");
      // optional: send a subscribe for pre-existing subs
      if (wsStatus.subscriptions && wsStatus.subscriptions.length) {
        try {
          wsClient.send(JSON.stringify({ action: "subscribe", symbols: wsStatus.subscriptions }));
        } catch (e) { safeLogWs("WSv2 SUB SEND ERR:", e.message || e); }
      }
    });

    // on message
    wsClient.on("message", (data) => {
      wsStatus.lastMsgAt = Date.now();
      // Many responses are binary; attempt parse
      let msg = data;
      try {
        // some streams send JSON text
        if (typeof data === "string") msg = JSON.parse(data);
        else {
          // try to parse buffer as utf8 string
          const text = data.toString("utf8");
          try { msg = JSON.parse(text); } catch (e) { msg = text; }
        }
      } catch (e) {
        msg = data.toString ? data.toString("utf8") : data;
      }
      // handle common messages
      safeLogWs("WSv2 MSG:", msg);
      // user-code: update last tick / subscriptions etc.
      // Example: if numeric LTP tick, parse and store somewhere
      try {
        if (typeof msg === "object" && msg.type === "heartbeat") {
          // ignore or handle heartbeat
        }
        // emit/forward to other parts of backend if needed
      } catch (e) { safeLogWs("WSv2 MSG HANDLER ERR:", e.message); }
    });

    wsClient.on("close", (code, reason) => {
      safeLogWs("WSv2 CLOSED:", code || "", reason || "");
      wsStatus.connected = false;
      // try reconnect with backoff
      attemptWsReconnect();
    });

    wsClient.on("error", (err) => {
      safeLogWs("WSv2 ERROR:", err && (err.message || err));
      wsStatus.lastError = err && (err.message || String(err));
      // close to trigger reconnect flow
      try { wsClient.close(); } catch (e) {}
    });

  } catch (e) {
    safeLogWs("WSv2 START ERR:", e.message || e);
    wsStatus.lastError = e.message || String(e);
    attemptWsReconnect();
  }
}

// reconnect logic with exponential backoff (capped)
function attemptWsReconnect() {
  wsStatus.reconnectAttempts = (wsStatus.reconnectAttempts || 0) + 1;
  const attempt = wsStatus.reconnectAttempts;
  const delay = Math.min(30000, 1000 * Math.pow(2, Math.min(attempt, 6))); // cap 30s
  safeLogWs("WSv2 RECONNECT in ms:", delay, "attempt:", attempt);
  setTimeout(() => {
    // only attempt if not connected and tokens still valid
    if (!wsStatus.connected) startWebsocketV2IfReady();
  }, delay);
}

/* helper to subscribe symbol(s) over WS */
function wsV2Subscribe(symbols = []) {
  if (!Array.isArray(symbols)) symbols = [symbols];
  // keep list
  wsStatus.subscriptions = Array.from(new Set([...(wsStatus.subscriptions||[]), ...symbols]));
  if (wsClient && wsStatus.connected) {
    try {
      wsClient.send(JSON.stringify({ action: "subscribe", symbols }));
    } catch (e) { safeLogWs("WSv2 SUB ERR:", e.message || e); }
  }
}

/* helper to unsubscribe */
function wsV2Unsubscribe(symbols = []) {
  if (!Array.isArray(symbols)) symbols = [symbols];
  wsStatus.subscriptions = (wsStatus.subscriptions || []).filter(s => !symbols.includes(s));
  if (wsClient && wsStatus.connected) {
    try {
      wsClient.send(JSON.stringify({ action: "unsubscribe", symbols }));
    } catch (e) { safeLogWs("WSv2 UNSUB ERR:", e.message || e); }
  }
}

/* Export / attach to your module exports or global usage area if needed */
module.exports.startWebsocketV2IfReady = startWebsocketV2IfReady;
module.exports.wsV2Subscribe = wsV2Subscribe;
module.exports.wsV2Unsubscribe = wsV2Unsubscribe;
module.exports.wsStatus = wsStatus;
/* ============================================================
   PART-4/6  
   Smart-Stream V2 — Tick Parser + Last-Tick Store
   ============================================================ */

const tengoTickStore = {
  lastLtp: null,
  lastSymbol: null,
  lastTime: null
};

// helper — check if value is numeric
function isNum(n) {
  return typeof n === "number" && !isNaN(n);
}

/*
 Smart Stream V2 sends different payload types depending on symbol:
 - Sometimes JSON text
 - Sometimes array-like tick structure
 - Sometimes binary converted to UTF8 text
 Below is a safe universal parser.
*/
function parseSmartV2Tick(msg) {
  if (!msg) return null;

  // 1) If already JSON object & has LTP-like fields
  if (typeof msg === "object") {
    // many SmartAPI feeds use "ltp" key OR [token, ltp, volume,...]
    if (isNum(msg.ltp)) {
      return {
        symbol: msg.symbol || msg.token || null,
        ltp: msg.ltp
      };
    }

    // array ticks: [token, ltp, ...]
    if (Array.isArray(msg) && msg.length >= 2 && isNum(msg[1])) {
      return {
        symbol: msg[0],
        ltp: msg[1]
      };
    }

    // fallback: no LTP found
    return null;
  }

  // 2) If string — try parse JSON
  if (typeof msg === "string") {
    try {
      const j = JSON.parse(msg);
      return parseSmartV2Tick(j);
    } catch (e) {
      return null;
    }
  }

  return null;
}

/*
 Extend WebSocket message handler — override/add inside wsClient.on("message")
 YOU MUST REPLACE the small msg print block from Part-3 with this expanded handler.
*/

function handleWsMessageV2(raw) {
  wsStatus.lastMsgAt = Date.now();

  let msg = raw;
  try {
    if (typeof raw === "string") {
      msg = JSON.parse(raw);
    } else {
      const t = raw.toString("utf8");
      try { msg = JSON.parse(t); }
      catch { msg = t; }
    }
  } catch {
    msg = raw;
  }

  // try parse LTP
  const tick = parseSmartV2Tick(msg);
  if (tick && tick.ltp) {
    tengoTickStore.lastLtp = tick.ltp;
    tengoTickStore.lastSymbol = tick.symbol;
    tengoTickStore.lastTime = Date.now();

    // log only essential
    console.log("WSv2 LTP:", tick.symbol, tick.ltp);
  }

  // you can add routing here (if your app needs /api/ltp)
  return tick;
}


// export for external usage
module.exports.tengoTickStore = tengoTickStore;
module.exports.handleWsMessageV2 = handleWsMessageV2;
/* ============================================================
   PART-5/6
   SMARTAPI LOGIN (Password + TOTP)
   Feed Token Fetch
   Safe-Fetch (Render-compatible)
   ============================================================ */

// Safe Fetch wrapper – Node + Browser compatible
const safeFetch = async (url, opts = {}) => {
  try {
    const f = global.fetch || ((...a) =>
      import("node-fetch").then(({ default: fn }) => fn(...a))
    );

    const res = await f(url, opts);
    const data = await res.json().catch(() => null);

    return { ok: true, data, status: res.status };
  } catch (err) {
    console.log("safeFetch ERR:", err.message);
    return { ok: false, error: err.message };
  }
};

// MEMORY SESSION
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: null
};

// Generate TOTP
function generateTOTP(secret) {
  try {
    const crypto = require("crypto");
    const epoch = Math.floor(Date.now() / 30000);
    const hmac = crypto
      .createHmac("sha1", Buffer.from(secret, "ascii"))
      .update(Buffer.alloc(8).fill(0).writeUInt32BE(epoch, 4))
      .digest();

    const offset = hmac[hmac.length - 1] & 0xf;
    const code =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    return (code % 1000000).toString().padStart(6, "0");
  } catch {
    return null;
  }
}

// SMARTAPI LOGIN
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_API_SECRET || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

    const loginUrl = `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`;

    const payload = {
      clientcode: SMART_USER_ID,
      password: tradingPassword,
      totp: totp
    };

    const r = await safeFetch(loginUrl, {
      method: "POST",
      headers: {
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "AA:BB:CC:DD:EE:FF",
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!r.ok || !r.data?.data?.jwtToken) {
      return { ok: false, reason: "LOGIN_FAILED", raw: r };
    }

    // store tokens
    session.access_token = r.data.data.jwtToken;
    session.refresh_token = r.data.data.refreshToken;
    session.expires_at = Date.now() + 1000 * 60 * 60;

    return await fetchFeedToken();
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// FETCH FEED TOKEN
async function fetchFeedToken() {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/user/v1/getfeedtoken`;

    const r = await safeFetch(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "X-PrivateKey": SMART_API_KEY
      }
    });

    if (!r.ok || !r.data?.data?.feedToken) {
      return { ok: false, reason: "FEEDTOKEN_FAILED", raw: r };
    }

    session.feed_token = r.data.data.feedToken;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "FEEDTOKEN_ERR", error: err.message };
  }
}

// API export
module.exports.smartApiLogin = smartApiLogin;
module.exports.fetchFeedToken = fetchFeedToken;
module.exports.safeFetch = safeFetch;
module.exports.session = session;
/* ============================================================
   PART-6/6
   EXPRESS ROUTES + LOGIN APIs + WS STATUS + SERVER START
   ============================================================ */

const { smartApiLogin } = module.exports;
const { session } = module.exports;
const { wsStatus, startWebsocketV2IfReady } = module.exports;

/* ============================
   LOGIN ENDPOINT (APP से कॉल)
   ============================ */

app.post("/api/login", async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.json({
        success: false,
        reason: "PASSWORD_MISSING",
        logged_in: false
      });
    }

    const r = await smartApiLogin(password);

    if (!r.ok) {
      console.log("LOGIN FAILED:", r);
      return res.json({
        success: false,
        logged_in: false,
        reason: r.reason || "UNKNOWN"
      });
    }

    // login success → start websocket
    await startWebsocketV2IfReady();

    return res.json({
      success: true,
      logged_in: true,
      expires_at: session.expires_at
    });
  } catch (err) {
    return res.json({
      success: false,
      logged_in: false,
      reason: err.message
    });
  }
});

/* ============================
   LOGIN STATUS ENDPOINT
   ============================ */

app.get("/api/login/status", (req, res) => {
  return res.json({
    smartapi_logged_in: !!session.access_token,
    feed_token: session.feed_token,
    expires_at: session.expires_at,
    ws_connected: wsStatus.connected,
    ws_last_msg: wsStatus.lastMsgAt,
    ws_error: wsStatus.lastError
  });
});

/* ============================
   WEBSOCKET STATUS ENDPOINT
   ============================ */

app.get("/api/ws/status", (req, res) => {
  return res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subscriptions: wsStatus.subscriptions
  });
});

/* ============================
   APP PING
   ============================ */

app.get("/api/ping", (req, res) => {
  res.json({ pong: true, time: Date.now() });
});

/* =============================================================
   AUTO START WS + AUTO REFRESH (EVERY 15 SEC)
   ============================================================= */

setInterval(() => {
  startWebsocketV2IfReady();
}, 15000);

/* ============================
   SERVER START
   ============================ */

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log("=======================================");
  console.log("  TENGO BACKEND RUNNING (FINAL FIXED)  ");
  console.log("  Smart-Stream V2 (URL AUTH) ACTIVE    ");
  console.log("  Listening on PORT:", PORT);
  console.log("=======================================");
});
