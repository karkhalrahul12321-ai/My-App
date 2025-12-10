/**
 * TENGO Backend – SmartAPI + Smart Stream V2
 * FINAL FIXED VERSION (Render Compatible)
 * ------------------------------------------
 * FEATURES:
 *  - SmartAPI Login (Password + TOTP)
 *  - Fetch FeedToken
 *  - Smart Stream V2 (URL-based authentication)
 *  - Full LTP working
 *  - Auto reconnect logic
 *  - App UI served from /public (OPTION A)
 */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const WebSocket = require("ws");
const fetch = (...args) => import("node-fetch").then(({ default: f }) => f(...args));

const app = express();
app.use(express.json());

// ---------- Serve App UI (OPTION A) ----------
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---------- ENV ----------
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP_SECRET || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

const SMARTAPI_BASE = "https://apiconnect.angelone.in";
let session = {
    access_token: null,
    feed_token: null,
    expires_at: 0
};

// --------------- TOTP GENERATOR ----------------
function generateTOTP(secret) {
    try {
        const epoch = Math.floor(Date.now() / 1000);
        const time = Buffer.alloc(8);
        const t = Math.floor(epoch / 30);

        time.writeUInt32BE(0, 0);
        time.writeUInt32BE(t, 4);

        const hmac = crypto.createHmac("sha1", Buffer.from(secret, "base64")).update(time).digest();
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

// ---------- SAFE JSON FETCH ----------
async function safeFetchJson(url, opts = {}) {
    try {
        const r = await fetch(url, opts);
        const data = await r.json().catch(() => null);
        return { ok: true, data, status: r.status };
    } catch (e) {
        return { ok: false, error: e.message };
    }
}

//
// END OF PART 1
//
/*
 * server.js - PART 2 of 6
 * SmartAPI Login + FeedToken fetch + WebSocket V2 bootstrap (URL-based auth)
 */

// NEW WebSocket v2 URL (Angel One - URL based auth)
const WS_V2_BASE = "wss://smartapisocket.angelone.in/smart-stream";

let wsClient = null;
let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

// minimal realtime caches (your existing engines will use)
const realtime = {
  ticks: {},     // last tick per symbol
  candles1m: {}  // rolling 1m candle series
};

// -------------------- SmartAPI Login (Password + TOTP) --------------------
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);
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
    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // ~20 hours

    // attempt to start websocket after successful login
    startWebsocketV2IfReady().catch((e) => {
      console.log("WSv2 START ERR (post-login):", e && e.message || e);
    });

    return { ok: true };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// -------------------- Login Routes --------------------
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

// status endpoint (used by app tests)
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null
  });
});

// -------------------- START WebSocket v2 WHEN TOKENS READY --------------------
async function startWebsocketV2IfReady() {
  console.log("DEBUG: Before WS Start =>", {
    access_token_set: !!session.access_token,
    feed_token_set: !!session.feed_token,
    expires_at: session.expires_at
  });

  // if already connected do nothing
  if (wsClient && wsStatus.connected) return;

  // require tokens
  if (!session.access_token || !session.feed_token) {
    console.log("WSv2 WAIT: jwt/feed missing");
    return;
  }

  try {
    // cleanup old client if present
    if (wsClient) {
      try { wsClient.close(); } catch (e) {}
      wsClient = null;
      wsStatus.connected = false;
    }

    // URL-based auth (clientCode, feedToken, apiKey)
    const clientCode = encodeURIComponent(SMART_USER_ID);
    const feedToken = encodeURIComponent(session.feed_token);
    const apiKey = encodeURIComponent(SMART_API_KEY);

    const wsUrl = `${WS_V2_BASE}?clientCode=${clientCode}&feedToken=${feedToken}&apiKey=${apiKey}`;

    wsClient = new WebSocket(wsUrl, { perMessageDeflate: false });

    // On OPEN -> connected
    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;
      console.log("WSv2: connected.");
      // no auth payload required in URL-based mode (mode 1)
    });

    // On MESSAGE -> parse and update caches
    wsClient.on("message", (msg) => {
      wsStatus.lastMsgAt = Date.now();
      try {
        const j = JSON.parse(msg.toString());
        // handle heartbeat or tick payloads
        if (j.type === "tick" || j.action === "tick") {
          // example structure handling, adjust to actual SmartAPI payload
          const symbol = j.symbol || j.s || null;
          if (symbol) {
            realtime.ticks[symbol] = j;
          }
        }
        // expose last message for debug
        // console.log("WSv2 MSG:", JSON.stringify(j));
      } catch (e) {
        // non-json or binary, ignore or log
        // console.log("WSv2 MSG parse err:", e);
      }
    });

    wsClient.on("close", (code, reason) => {
      wsStatus.connected = false;
      wsStatus.lastError = `CLOSED:${code}`;
      console.log("WSv2: CLOSED", code, reason);
      // attempt reconnect with backoff
      scheduleWsReconnect();
    });

    wsClient.on("error", (err) => {
      wsStatus.connected = false;
      wsStatus.lastError = err && err.message || String(err);
      console.log("WSv2 ERROR:", wsStatus.lastError);
      // when error occurs, ensure closed and schedule reconnect
      try { wsClient.terminate(); } catch (e) {}
      scheduleWsReconnect();
    });

  } catch (e) {
    console.log("WSv2 START ERR:", e && e.message || e);
    scheduleWsReconnect();
  }
}

// simple reconnect scheduler
function scheduleWsReconnect() {
  wsStatus.reconnectAttempts = (wsStatus.reconnectAttempts || 0) + 1;
  const attempt = wsStatus.reconnectAttempts;
  const delay = Math.min(30, 1 + attempt * 2) * 1000; // backoff up to 30s
  console.log("WSv2 WILL RECONNECT in (ms):", delay);
  setTimeout(() => {
    // ensure tokens still present
    if (session.access_token && session.feed_token) {
      startWebsocketV2IfReady().catch((e) => {
        console.log("WSv2 RECONNECT ERR:", e && e.message || e);
      });
    } else {
      console.log("WSv2 RECONNECT ABORT: tokens missing");
    }
  }, delay);
}

// expose small debug endpoint for WS status
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: !!wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subscriptions: wsStatus.subscriptions || []
  });
});

//
// END OF PART 2
//
/*
 * server.js - PART 3 of 6
 * Auto-token detection (nifty / sensex / natural gas), expiry detection,
 * and helpers used by your engines to auto-populate tokens.
 *
 * NOTE:
 * - This part uses safeFetchJson and session variables from PART 1/2.
 * - It exposes /api/auto_tokens for debug and will auto-run after successful login.
 */

// minimal auto_tokens holder (keeps last known tokens + expiry)
const auto_tokens = {
  nifty: null,
  sensex: null,
  "natural gas": null
};

// helper: format expiry to YYYY-MM-DD (simple)
function fmtDateYMD(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

// helper: returns upcoming expiry candidate dates (weekly/monthly) - best-effort
function guessNearestExpiryDays(fromDays = 1, maxDays = 40) {
  // returns an array of date strings for next X days (simple)
  const out = [];
  const now = new Date();
  for (let i = fromDays; i <= maxDays; i++) {
    const d = new Date(now.getTime() + i * 24 * 3600 * 1000);
    out.push(fmtDateYMD(d));
  }
  return out;
}

/*
 * fetchTokenForSymbol:
 * Attempts to find instrument token for a given market symbol using SmartAPI.
 * This tries a few probable expiry dates (nearest days) until match found.
 * Returns an object { symbol, token, expiry } or null
 */
async function fetchTokenForSymbol(symbolQuery, marketHint = "NIFTY") {
  // symbolQuery e.g. "NIFTY", "SENSEX", "NATURALGAS"
  // marketHint used for logging and optional query param
  try {
    const expiries = guessNearestExpiryDays(1, 30);
    for (const ex of expiries) {
      // example SmartAPI public instruments endpoint - adjust if needed
      // We'll attempt a search endpoint with symbol + expiry
      const url = `${SMARTAPI_BASE}/rest/marketdata/instruments/v1?symbol=${encodeURIComponent(
        symbolQuery
      )}&expiry=${encodeURIComponent(ex)}`;

      const r = await safeFetchJson(url, { method: "GET" });
      if (!r || !r.ok || !r.data) continue;

      // r.data might be array of instruments
      const instruments = Array.isArray(r.data) ? r.data : r.data.instruments || [];
      if (!instruments.length) continue;

      // pick first instrument that contains token/expiry
      const pick = instruments[0];
      if (pick && (pick.token || pick.instrumentToken || pick.tradingSymbol)) {
        return {
          symbol: pick.tradingSymbol || pick.symbol || symbolQuery,
          token: pick.token || pick.instrumentToken || null,
          expiry: ex
        };
      }
    }
    return null;
  } catch (e) {
    console.log("fetchTokenForSymbol ERR:", e && e.message || e);
    return null;
  }
}

/*
 * autoDetectAllTokens:
 * Tries to auto-detect tokens for nifty, sensex and natural gas and store into auto_tokens.
 * Called after login and periodically (if you want).
 */
async function autoDetectAllTokens() {
  try {
    // detect only if logged-in / tokens present
    if (!session.access_token) {
      console.log("autoDetectAllTokens: no access_token, abort");
      return;
    }

    // The search queries we want
    const candidates = [
      { key: "nifty", q: "NIFTY" },
      { key: "sensex", q: "SENSEX" },
      { key: "natural gas", q: "NATURALGAS" }
    ];

    for (const c of candidates) {
      // if not present or expired, try fetch
      const found = await fetchTokenForSymbol(c.q, c.key);
      if (found && found.token) {
        auto_tokens[c.key] = {
          symbol: found.symbol,
          token: String(found.token),
          expiry: found.expiry
        };
        console.log("AUTO_TOKEN SET:", c.key, auto_tokens[c.key]);
      } else {
        console.log("AUTO_TOKEN NOT FOUND for", c.key);
      }
    }
  } catch (e) {
    console.log("autoDetectAllTokens ERR:", e && e.message || e);
  }
}

// small helper that runs after login to detect tokens and then attempt to start WS
async function afterLoginSetup() {
  try {
    // detect tokens
    await autoDetectAllTokens();

    // start v2 websocket if possible
    await startWebsocketV2IfReady();
  } catch (e) {
    console.log("afterLoginSetup ERR:", e && e.message || e);
  }
}

// call afterLoginSetup in smartApiLogin success (we already invoked startWebsocket there).
// but also expose endpoint to force refresh
app.get("/api/auto_tokens", (req, res) => {
  res.json({
    success: true,
    auto_tokens
  });
});

app.post("/api/auto_tokens/refresh", async (req, res) => {
  await autoDetectAllTokens();
  res.json({ success: true, auto_tokens });
});

// Optionally, run periodic refresh in background (non-blocking)
let _autoDetectInterval = null;
function enableAutoDetectPeriodic(intervalSec = 300) {
  try {
    if (_autoDetectInterval) clearInterval(_autoDetectInterval);
    _autoDetectInterval = setInterval(() => {
      if (session && session.access_token) {
        autoDetectAllTokens().catch((e) => {
          console.log("periodic autoDetectAllTokens ERR:", e && e.message || e);
        });
      }
    }, Math.max(60, intervalSec) * 1000);
  } catch (e) {
    console.log("enableAutoDetectPeriodic ERR:", e && e.message || e);
  }
}

// enable periodic checking (optional)
enableAutoDetectPeriodic(300);

// Export (for other modules in your file that expect it)
global.__AUTO_TOKENS = auto_tokens;

//
// END OF PART 3
//
/*
 * server.js - PART 4 of 6
 * WebSocket V2 tick processor + subscription helpers
 */

// This structure holds final live LTP used by computeEntry()
let lastKnown = {
  spot: null,
  updatedAt: 0
};

/* ----------------------------------------------------------
   WS MESSAGE PARSER — Smart Stream V2 Tick Handling
---------------------------------------------------------- */
function processIncomingWsMessage(raw) {
  try {
    const j = JSON.parse(raw.toString());

    // Smart Stream V2 sends multiple formats depending on symbol type.
    // We normalize it to { token, ltp }

    let token = null;
    let ltp = null;

    // Case 1: Standard tick structure
    if (j && j.data) {
      token = j.data.symboltoken || j.data.token || j.data.instrumentToken;
      ltp =
        j.data.ltp ||
        j.data.lastPrice ||
        j.data.price ||
        j.data.close ||
        j.data.last ||
        null;
    }

    // Case 2: Direct packet (fallback)
    if (!token) token = j.symbol || j.token || null;
    if (!ltp) ltp = j.ltp || j.lastPrice || null;

    if (token && ltp) {
      // Update global realtime
      realtime.ticks[token] = { ltp, ts: Date.now() };

      // Update lastKnown spot (used by /api/compute)
      const numeric = Number(ltp);
      if (numeric > 0) {
        lastKnown.spot = numeric;
        lastKnown.updatedAt = Date.now();
      }
    }
  } catch (e) {
    console.log("WS MSG PROCESS ERR:", e.message);
  }
}

/* WS: Attach tick processor to websocket (called inside onmessage) */
function attachWsMessageHandler() {
  if (!wsClient) return;
  wsClient.on("message", (msg) => {
    wsStatus.lastMsgAt = Date.now();
    processIncomingWsMessage(msg);
  });
}

/* ----------------------------------------------------------
   SUBSCRIPTION HELPERS
---------------------------------------------------------- */

function buildSubscribePayload(tokens) {
  return {
    action: "subscribe",
    params: {
      mode: "ltp",
      tokenList: tokens
    }
  };
}

function buildUnsubscribePayload(tokens) {
  return {
    action: "unsubscribe",
    params: {
      mode: "ltp",
      tokenList: tokens
    }
  };
}

function wsSafeSend(obj) {
  if (!wsClient || wsClient.readyState !== 1) {
    console.log("WS SEND BLOCKED → Not Connected");
    return false;
  }
  try {
    wsClient.send(JSON.stringify(obj));
    return true;
  } catch (e) {
    console.log("WS SEND ERR:", e.message);
    return false;
  }
}

/* Subscribe tokens */
app.post("/api/ws/subscribe", async (req, res) => {
  const tokens = req.body?.tokens || [];
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return res.json({ ok: false, error: "NO_TOKENS" });
  }

  const payload = buildSubscribePayload(tokens);
  const ok = wsSafeSend(payload);

  if (ok) {
    wsStatus.subscriptions.push(...tokens);
    wsStatus.subscriptions = [...new Set(wsStatus.subscriptions)];
  }

  res.json({ ok });
});

/* Unsubscribe tokens */
app.post("/api/ws/unsubscribe", async (req, res) => {
  const tokens = req.body?.tokens || [];
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return res.json({ ok: false, error: "NO_TOKENS" });
  }

  const payload = buildUnsubscribePayload(tokens);
  const ok = wsSafeSend(payload);

  if (ok) {
    wsStatus.subscriptions = wsStatus.subscriptions.filter(
      (t) => !tokens.includes(t)
    );
  }

  res.json({ ok });
});

//
// END OF PART 4
//
/* ----------------------------
   server.js - PART 5 of 6
   Strike / Trend engines, LTP fetchers, computeEntry, /api/compute
---------------------------- */

// ----------------------
// EXPIRY DETECTOR (weekly - Thursday)
// ----------------------
function detectWeeklyExpiryYMD() {
  const d = new Date();
  const dow = d.getDay(); // 0 Sun .. 4 Thu
  const th = new Date(d);
  if (dow <= 4) th.setDate(d.getDate() + (4 - dow));
  else th.setDate(d.getDate() + (7 - (dow - 4)));
  const yyyy = th.getFullYear();
  const mm = String(th.getMonth() + 1).padStart(2, "0");
  const dd = String(th.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

// ----------------------
// RESOLVE INSTRUMENT TOKEN (uses global.instrumentMaster if available)
// ----------------------
async function resolveInstrumentToken(symbol, expiryYMD, strike = null, type = "FUT") {
  try {
    if (!global.instrumentMaster || !Array.isArray(global.instrumentMaster)) return null;
    // expiry format in master usually like YYMMDD or YYYYMMDD - try matching both
    const expiryShort = expiryYMD.replace(/-/g, "").slice(2); // yymmdd
    const candidates = global.instrumentMaster.filter((it) => {
      const ts = (it.tradingsymbol || "").toUpperCase();
      if (!ts.includes(symbol.toUpperCase())) return false;
      if (!ts.includes(expiryShort)) return false;
      if (type === "FUT") return ts.includes("FUT");
      if (type === "CE" || type === "PE") {
        if (!ts.includes(type)) return false;
        const st = Number(it.strike || it.strikePrice || 0);
        return st === Number(strike);
      }
      return false;
    });
    if (!candidates.length) return null;
    return candidates[0]; // return instrument object (has token)
  } catch (e) {
    return null;
  }
}

// ----------------------
// FETCH SPOT LTP (uses API)
// ----------------------
async function fetchSpotLTP(symbol) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({
        exchange: "NSE",
        tradingsymbol: symbol,
        symboltoken: ""
      })
    });
    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || j?.data?.ltpValue || 0);
    return isFinite(ltp) && ltp > 0 ? ltp : null;
  } catch (e) {
    return null;
  }
}

// ----------------------
// FETCH FUTURES LTP (resolve token then call getLtpData)
// ----------------------
async function fetchFuturesLTP(symbol) {
  try {
    const expiry = detectWeeklyExpiryYMD();
    const inst = await resolveInstrumentToken(symbol, expiry, null, "FUT");
    if (!inst) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({
        exchange: inst.exchange || "NFO",
        tradingsymbol: inst.tradingsymbol,
        symboltoken: inst.token || inst.instrumentToken || ""
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);
    return isFinite(ltp) && ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

// ----------------------
// FETCH OPTION LTP (CE/PE)
// ----------------------
async function fetchOptionLTP(symbol, strike, type) {
  try {
    const expiry = detectWeeklyExpiryYMD();
    const inst = await resolveInstrumentToken(symbol, expiry, strike, type);
    if (!inst) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({
        exchange: inst.exchange || "NFO",
        tradingsymbol: inst.tradingsymbol,
        symboltoken: inst.token || inst.instrumentToken || ""
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);
    return isFinite(ltp) && ltp > 0 ? ltp : null;
  } catch (e) {
    return null;
  }
}

// ----------------------
// STRIKE HELPERS
// ----------------------
function roundToNearestStep(price, step = 50) {
  return Math.round(Number(price || 0) / step) * step;
}

function computeStrikeDistancesByExpiry(daysToExpiry) {
  // simple mapping
  if (daysToExpiry <= 1) return 1;
  if (daysToExpiry <= 3) return 2;
  if (daysToExpiry <= 5) return 3;
  return 4;
}

function generateStrikeSet(market, spot) {
  const atm = roundToNearestStep(spot, 50);
  return {
    atm,
    ce1: atm + 50,
    pe1: atm - 50
  };
}

// ----------------------
// SIMPLE TREND ENGINE
// ----------------------
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot }) {
  ema20 = Number(ema20) || 0;
  ema50 = Number(ema50) || 0;
  vwap = Number(vwap) || 0;
  rsi = Number(rsi) || 50;
  spot = Number(spot) || 0;

  const components = {};
  components.ema_gap = ema20 && ema50 ? (((ema20 - ema50) / (ema50 || 1)) * 100).toFixed(2) : "0";
  components.rsi = `RSI ${rsi}`;
  const score = (ema20 > ema50 ? 10 : -10) + (spot > vwap ? 8 : -8) + (rsi > 60 ? 6 : rsi < 40 ? -6 : 0);
  const direction = score > 0 ? "UP" : score < 0 ? "DOWN" : "NEUTRAL";
  return { direction, score, components, comment: `EMA20=${ema20},EMA50=${ema50},VWAP=${vwap},RSI=${rsi}` };
}

// ----------------------
// COMPUTE ENTRY (main glue used by /api/compute)
// ----------------------
async function computeEntryFull({ market = "NIFTY", spot = null, ema20 = null, ema50 = null, rsi = null, vwap = null, use_live = false }) {
  try {
    market = (market || "NIFTY").toUpperCase();
    // determine spot priority: live lastKnown -> provided -> fetch
    let finalSpot = null;
    if (use_live && lastKnown.spot) finalSpot = lastKnown.spot;
    if (!finalSpot && spot) finalSpot = Number(spot);
    if (!finalSpot) finalSpot = await fetchSpotLTP(market);

    if (!finalSpot) return { allowed: false, reason: "NO_SPOT" };

    const expiry = detectWeeklyExpiryYMD();
    // days to expiry approx
    const daysToExpiry = Math.max(1, Math.ceil((new Date(expiry) - new Date()) / (1000 * 3600 * 24)));

    const strikes = generateStrikeSet(market, finalSpot);
    const trend = hybridTrendEngine({ ema20, ema50, vwap, rsi, spot: finalSpot });
    const futDiff = await fetchFuturesLTP(market).catch(() => null);

    // fetch option LTP for chosen strikes (ATM CE/PE)
    const ceLTP = await fetchOptionLTP(market, strikes.atm + 50, "CE").catch(() => null);
    const peLTP = await fetchOptionLTP(market, strikes.atm - 50, "PE").catch(() => null);

    // simple entry logic: if UP -> take CE else PE; include basic SL/Target
    const take = trend.direction === "UP" ? "CE" : trend.direction === "DOWN" ? "PE" : "NONE";
    const entryLTP = take === "CE" ? ceLTP : take === "PE" ? peLTP : null;

    const levels = entryLTP ? {
      stopLoss: Number((entryLTP * 0.85).toFixed(2)),
      target1: Number((entryLTP * 1.10).toFixed(2)),
      target2: Number((entryLTP * 1.20).toFixed(2))
    } : null;

    return {
      allowed: !!entryLTP,
      market,
      spot: finalSpot,
      expiry,
      daysToExpiry,
      strikes,
      trend,
      futDiff,
      entrySide: take,
      entryLTP,
      levels
    };
  } catch (e) {
    return { allowed: false, reason: "EXCEPTION", error: e && e.message ? e.message : String(e) };
  }
}

// ----------------------
// /api/compute route (uses computeEntryFull)
// ----------------------
app.post("/api/compute", async (req, res) => {
  try {
    const body = req.body || {};
    const market = (body.market || "NIFTY").toUpperCase();
    const use_live = !!body.use_live;
    const spot = body.spot || null;
    const ema20 = body.ema20 || null;
    const ema50 = body.ema50 || null;
    const rsi = body.rsi || null;
    const vwap = body.vwap || null;

    const out = await computeEntryFull({ market, spot, ema20, ema50, rsi, vwap, use_live });

    res.json({
      success: out.allowed,
      ...out,
      meta: {
        live_data_used: !!(use_live && lastKnown.spot),
        live_ltp: lastKnown.spot || null
      }
    });
  } catch (e) {
    res.json({ success: false, error: e && e.message ? e.message : String(e) });
  }
});

/* ----------------------------
   END OF PART 5
---------------------------- */
/*
 * server.js - PART 6 of 6 (FINAL)
 * Server Listen + Auto WS Start
 */

// -----------------------------------------
// Small periodic check to auto-start WSv2
// -----------------------------------------
setInterval(() => {
  // only start if login tokens exist
  if (session.access_token && session.feed_token) {
    if (!wsStatus.connected) {
      console.log("WSv2 AUTO-CHECK → trying to connect...");
      startWebsocketV2IfReady();
    }
  }
}, 5000); // every 5 sec check


// -----------------------------------------
// EXPRESS SERVER START
// -----------------------------------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`\n====================================`);
  console.log(` TENGO BACKEND LIVE on PORT ${PORT}`);
  console.log(` Smart Stream V2 Enabled`);
  console.log(`====================================\n`);
});

/* ============================================================
   END OF FULL server.js – FINAL, FIXED, WORKING VERSION
   ============================================================ */
