/* ---------------------------
   BASIC SETUP + EXPRESS + STATIC UI
---------------------------- */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const WebSocket = require("ws");

const app = express();
app.use(express.json());

// Serve Frontend UI
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;

/* ---------------------------
   ENV VARIABLES
---------------------------- */

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP_SECRET || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMARTAPI_BASE = "https://apiconnect.angelone.in";

/* ---------------------------
   MEMORY SESSION
---------------------------- */

let session = {
  access_token: null,
  feed_token: null,
  expires_at: 0
};

/* ---------------------------
   TOTP GENERATOR
---------------------------- */

function generateTOTP(secret) {
  try {
    const key = Buffer.from(secret, "base64");
    const time = Math.floor(Date.now() / 30000);
    const msg = Buffer.alloc(8);
    msg.writeUInt32BE(0, 0);
    msg.writeUInt32BE(time, 4);

    const hmac = crypto.createHmac("sha1", key).update(msg).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
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

/* ---------------------------
   SAFE JSON FETCH WRAPPER
---------------------------- */

async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
/* --------------------------------------
   SMARTAPI LOGIN (Password + TOTP)
--------------------------------------- */

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

    const data = await resp.json();

    if (data && data.status === true) {
      session.access_token = data.data.jwtToken;
      session.feed_token = data.data.feedToken;
      session.expires_at = Date.now() + 14 * 60 * 1000; // 14 min validity

      return { ok: true };
    } else {
      return { ok: false, reason: data?.message || "LOGIN_FAILED" };
    }
  } catch (e) {
    return { ok: false, reason: e.message || "LOGIN_ERR" };
  }
}

/* --------------------------------------
   AUTO REFRESH FEED TOKEN (IF NEEDED)
--------------------------------------- */

async function refreshFeedToken() {
  if (!session.access_token) return;

  const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/user/v1/getfeedtoken`;
  const r = await safeFetchJson(url, {
    headers: {
      "X-PrivateKey": SMART_API_KEY,
      Authorization: `Bearer ${session.access_token}`
    }
  });

  if (r.ok && r.data && r.data.status === true) {
    session.feed_token = r.data.data;
  }
}
// ---------------------------------------
// server.js - PART 3 of 6
// Smart Stream V2 URL Auth + WebSocket v2 Bootstrap
// ---------------------------------------

/**
 * NEW WebSocket v2 base URL (Angel One - Smart Stream V2)
 * Mode: URL based auth for browser/server clients:
 *   wss://smartapisocket.angelone.in/smart-stream?clientCode=<>&feedToken=<>&apiKey=<>
 */
const WS_V2_BASE = "wss://smartapisocket.angelone.in/smart-stream";

let wsV2Client = null;

let wsV2Status = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: new Set() // token strings subscribed
};

// minimal realtime caches (used by existing engines)
const realtime = {
  ticks: {},    // last tick per token -> { token, ltp, timestamp, ... }
  candles1m: {} // rolling 1-minute candle series (optional)
};

/**
 * Build WS v2 URL with required query params for URL-based auth.
 * Returns: full WSS URL string
 */
function buildWsV2Url() {
  // session.feed_token must be present
  const feed = encodeURIComponent(session.feed_token || "");
  const client = encodeURIComponent(SMART_USER_ID || "");
  const apiKey = encodeURIComponent(SMART_API_KEY || "");
  // Angel doc sample: wss://.../smart-stream?clientCode=&feedToken=&apiKey=
  return `${WS_V2_BASE}?clientCode=${client}&feedToken=${feed}&apiKey=${apiKey}`;
}

/**
 * Subscribe helper (adds token to local set and sends subscribe message).
 * token: string or numeric token id used by SmartAPI (instrument token)
 */
function wsV2Subscribe(token) {
  try {
    const t = String(token);
    if (wsV2Status.subscriptions.has(t)) return;
    wsV2Status.subscriptions.add(t);

    if (wsV2Client && wsV2Status.connected) {
      const payload = {
        action: "subscribe",       // v2 style - adjust if your account uses different action name
        params: { symbols: [t] }
      };
      wsV2Client.send(JSON.stringify(payload));
      console.log("WSv2: SUBSCRIBE SENT =>", t);
    }
  } catch (e) {
    console.log("WSv2 SUBSCRIBE ERR:", e && e.message || e);
  }
}

/**
 * Unsubscribe helper
 */
function wsV2Unsubscribe(token) {
  try {
    const t = String(token);
    if (!wsV2Status.subscriptions.has(t)) return;
    wsV2Status.subscriptions.delete(t);

    if (wsV2Client && wsV2Status.connected) {
      const payload = {
        action: "unsubscribe",
        params: { symbols: [t] }
      };
      wsV2Client.send(JSON.stringify(payload));
      console.log("WSv2: UNSUBSCRIBE SENT =>", t);
    }
  } catch (e) {
    console.log("WSv2 UNSUBSCRIBE ERR:", e && e.message || e);
  }
}

/**
 * Clean, parse incoming messages and update realtime caches.
 * messageData: string (raw)
 */
function handleWsV2Message(messageData) {
  let parsed = null;
  try {
    parsed = JSON.parse(messageData);
  } catch (e) {
    // some messages might be binary or not-json - ignore safely
    console.log("WSv2: received non-json message");
    return;
  }

  // Save last message timestamp
  wsV2Status.lastMsgAt = Date.now();

  // Typical v2 payloads vary — handle common tick format
  // Example (hypothetical):
  // { type: "tick", data: { token: "36688", ltp: 18325, o:..., h:..., l:..., t: <ts> } }
  if (parsed.type === "tick" && parsed.data) {
    const d = parsed.data;
    const token = String(d.token || d.symbol || d.instrumentToken || "");
    const ltp = Number(d.ltp || d.last || d.price || 0);
    realtime.ticks[token] = {
      token,
      ltp,
      raw: d,
      ts: Date.now()
    };
    // optional: emit or store for other parts of your app
    // console.log("WSv2 TICK:", token, ltp);
    return;
  }

  // Heartbeat or connection messages
  if (parsed.type === "heartbeat" || parsed.action === "heartbeat") {
    // ignore for now
    return;
  }

  // Auth / ack / error
  if (parsed.type === "auth" || parsed.action === "auth") {
    console.log("WSv2 AUTH RESP:", parsed);
    return;
  }

  // Generic / unknown messages - keep for debugging
  console.log("WSv2 MSG:", parsed);
}

/**
 * Start/Restart WSv2 if tokens are ready (session.feed_token required)
 */
async function startWebsocketV2IfReady() {
  console.log("DEBUG: Before WSv2 Start =>", {
    access_token_set: !!session.access_token,
    feed_token_set: !!session.feed_token,
    expires_at: session.expires_at
  });

  // Already connected?
  if (wsV2Client && wsV2Status.connected) return;

  // Need feed token for URL auth
  if (!session.feed_token) {
    console.log("WSv2 WAIT: feed token missing");
    return;
  }

  try {
    // Cleanup old client
    if (wsV2Client) {
      try { wsV2Client.close(); } catch (e) {}
      wsV2Client = null;
      wsV2Status.connected = false;
    }

    const url = buildWsV2Url();
    console.log("WSv2 CONNECT URL:", url.replace(/(feedToken=)[^&]+/, "$1<hidden>"));

    // create new WebSocket (Node's ws or browser native depending environment)
    wsV2Client = new WebSocket(url, { perMessageDeflate: false });

    // ON OPEN
    wsV2Client.onopen = () => {
      wsV2Status.connected = true;
      wsV2Status.reconnectAttempts = 0;
      wsV2Status.lastError = null;
      console.log("WSv2: connected.");

      // re-subscribe previously requested tokens
      if (wsV2Status.subscriptions.size) {
        const symbols = Array.from(wsV2Status.subscriptions);
        const payload = { action: "subscribe", params: { symbols } };
        try { wsV2Client.send(JSON.stringify(payload)); } catch (e) {
          console.log("WSv2 RESUBSCRIBE ERR:", e && e.message || e);
        }
      }
    };

    // ON MESSAGE
    wsV2Client.onmessage = (ev) => {
      // ev.data (string)
      try {
        handleWsV2Message(ev.data);
      } catch (e) {
        console.log("WSv2 MSG HANDLER ERR:", e && e.message || e);
      }
    };

    // ON ERROR
    wsV2Client.onerror = (err) => {
      wsV2Status.lastError = (err && err.message) || "WSv2 ERROR";
      console.log("WSv2 ERROR:", wsV2Status.lastError);
    };

    // ON CLOSE
    wsV2Client.onclose = (closeEvt) => {
      wsV2Status.connected = false;
      wsV2Status.lastError = `CLOSED: ${closeEvt && closeEvt.code || ""} ${closeEvt && closeEvt.reason || ""}`;
      console.log("WSv2 CLOSED:", wsV2Status.lastError);

      // reconnect with backoff
      const attempt = ++wsV2Status.reconnectAttempts;
      const backoffMs = Math.min(30_000, 1000 * Math.pow(1.8, Math.min(attempt, 8)));
      console.log(`WSv2 RECONNECT in ${backoffMs}ms (attempt ${attempt})`);
      setTimeout(() => {
        // Ensure tokens still present
        if (session.feed_token) startWebsocketV2IfReady();
      }, backoffMs);
    };

  } catch (err) {
    console.log("WSv2 START ERR:", err && err.message || err);
  }
}

/**
 * Stop WSv2 immediately and clear subscriptions
 */
function stopWebsocketV2() {
  try {
    if (wsV2Client) {
      try { wsV2Client.close(); } catch (e) {}
      wsV2Client = null;
    }
    wsV2Status.connected = false;
    wsV2Status.subscriptions.clear();
    console.log("WSv2: stopped.");
  } catch (e) {
    console.log("WSv2 STOP ERR:", e && e.message || e);
  }
}

// Expose subscribe helper to other modules / endpoints
// (If using Express routes, you can call wsV2Subscribe(token) from route handlers)

// End of PART 3
// Next: PART 4 will contain WebSocket message parsers + public endpoints to subscribe/unsubscribe
// ---------------------------------------
// server.js - PART 4 of 6
// Public Endpoints for WSv2 (Subscribe/Unsubscribe/Status)
// Auto-start WebSocket V2 after Login
// ---------------------------------------

// EXPRESS APP (already created in earlier part)
const express = require("express");
const app = express();
app.use(express.json());

// ---------------------------
// LOGIN ROUTE
// ---------------------------
app.post("/api/login", async (req, res) => {
  const tradingPassword = req.body.password || "";

  const r = await smartApiLogin(tradingPassword);

  if (!r.ok) {
    return res.json({
      success: false,
      logged_in: false,
      reason: r.reason,
      raw: r.raw || null
    });
  }

  // After successful login → Start WS V2
  setTimeout(() => startWebsocketV2IfReady(), 300);

  return res.json({
    success: true,
    logged_in: true,
    expires_at: session.expires_at
  });
});

// ---------------------------
// LOGIN STATUS ROUTE
// ---------------------------
app.get("/api/login/status", (req, res) => {
  const logged = !!session.access_token;
  return res.json({
    success: true,
    logged_in: logged,
    expires_at: session.expires_at || null
  });
});

// ---------------------------
// WSv2 STATUS ENDPOINT
// ---------------------------
app.get("/api/ws/status", (req, res) => {
  return res.json({
    connected: wsV2Status.connected,
    lastMsgAt: wsV2Status.lastMsgAt,
    lastError: wsV2Status.lastError,
    subs: Array.from(wsV2Status.subscriptions)
  });
});

// ---------------------------
// SUBSCRIBE ENDPOINT
// ---------------------------
app.post("/api/ws/subscribe", (req, res) => {
  const token = String(req.body.token || "");

  if (!token) {
    return res.json({ success: false, reason: "TOKEN_MISSING" });
  }

  wsV2Subscribe(token);

  return res.json({
    success: true,
    subscribed: Array.from(wsV2Status.subscriptions)
  });
});

// ---------------------------
// UNSUBSCRIBE ENDPOINT
// ---------------------------
app.post("/api/ws/unsubscribe", (req, res) => {
  const token = String(req.body.token || "");

  if (!token) {
    return res.json({ success: false, reason: "TOKEN_MISSING" });
  }

  wsV2Unsubscribe(token);

  return res.json({
    success: true,
    subscribed: Array.from(wsV2Status.subscriptions)
  });
});

// ---------------------------
// START WSv2 ON SERVER START (IF TOKENS ALREADY PRESENT)
// ---------------------------
setTimeout(() => {
  if (session.feed_token) startWebsocketV2IfReady();
}, 1500);

// ---------------------------
// MINI HEALTH ENDPOINT
// ---------------------------
app.get("/", (req, res) => {
  res.send(
    `TENGO Backend Running — Smart Stream V2 Active<br>` +
    `WS Connected: ${wsV2Status.connected}<br>` +
    `Subscriptions: ${Array.from(wsV2Status.subscriptions).join(", ")}`
  );
});

// ---------------------------
// END OF PART 4
// Next: Part 5 → Strike Engine, OI Engine, Trend Engine, etc.
// ---------------------------
/* ----------------------------------------
   server.js - PART 5 of 6
   Strike engine, LTP fetchers, trend engine, computeEntry, /api/compute
   ---------------------------------------- */

/**
 * Weekly expiry detector (Thursday)
 */
function detectWeeklyExpiryYMD() {
  const now = new Date();
  const dow = now.getDay(); // 0 Sun .. 4 Thu
  const th = new Date(now);
  if (dow <= 4) th.setDate(now.getDate() + (4 - dow));
  else th.setDate(now.getDate() + (7 - (dow - 4)));
  const yyyy = th.getFullYear();
  const mm = String(th.getMonth() + 1).padStart(2, "0");
  const dd = String(th.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

/**
 * Resolve instrument token from global.instrumentMaster (if available)
 * Returns instrument object or null
 */
async function resolveInstrumentToken(symbol, expiryYMD, strike = null, type = "FUT") {
  try {
    if (!global.instrumentMaster || !Array.isArray(global.instrumentMaster)) return null;
    const expiryShort = expiryYMD.replace(/-/g, "").slice(2); // yymmdd
    const list = global.instrumentMaster.filter((it) => {
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
    return list.length ? list[0] : null;
  } catch (e) {
    return null;
  }
}

/**
 * Fetch LTP via API getLtpData
 * generic wrapper - supply exchange, tradingsymbol, symboltoken
 */
async function apiGetLtp(exchange, tradingsymbol, symboltoken) {
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
        exchange: exchange || "NSE",
        tradingsymbol: tradingsymbol || "",
        symboltoken: symboltoken || ""
      })
    });
    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);
    return isFinite(ltp) && ltp > 0 ? ltp : null;
  } catch (e) {
    return null;
  }
}

/**
 * Fetch spot LTP (symbol like NIFTY, BANKNIFTY, or stock)
 */
async function fetchSpotLTP(symbol) {
  return await apiGetLtp("NSE", symbol, "");
}

/**
 * Fetch futures LTP (resolve token first)
 */
async function fetchFuturesLTP(symbol) {
  const expiry = detectWeeklyExpiryYMD();
  const inst = await resolveInstrumentToken(symbol, expiry, null, "FUT");
  if (!inst) return null;
  return await apiGetLtp(inst.exchange || "NFO", inst.tradingsymbol, inst.token || inst.instrumentToken);
}

/**
 * Fetch option LTP (CE or PE)
 */
async function fetchOptionLTP(symbol, strike, type) {
  const expiry = detectWeeklyExpiryYMD();
  const inst = await resolveInstrumentToken(symbol, expiry, strike, type);
  if (!inst) return null;
  return await apiGetLtp(inst.exchange || "NFO", inst.tradingsymbol, inst.token || inst.instrumentToken);
}

/**
 * Strike helpers
 */
function roundToNearest(price, step = 50) {
  price = Number(price || 0);
  return Math.round(price / step) * step;
}
function generateStrikeSet(spot) {
  const atm = roundToNearest(spot, 50);
  return { atm, ce: atm + 50, pe: atm - 50 };
}

/**
 * Simple hybrid trend engine (keeps your original rules)
 */
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot }) {
  ema20 = Number(ema20) || 0;
  ema50 = Number(ema50) || 0;
  vwap = Number(vwap) || 0;
  rsi = Number(rsi) || 50;
  spot = Number(spot) || 0;

  const components = {};
  const emaGapPct = ema50 ? ((ema20 - ema50) / ema50) * 100 : 0;
  components.ema_gap = Math.abs(emaGapPct) < 0.5 ? `Flat (${emaGapPct.toFixed(2)}%)` : (emaGapPct > 0 ? "EMA20>EMA50" : "EMA20<EMA50");
  components.rsi = `RSI ${rsi.toFixed(2)}`;
  const vwapRel = vwap ? ((spot - vwap) / vwap) * 100 : 0;
  components.vwap = vwapRel >= 0 ? `Above VWAP (${vwapRel.toFixed(2)}%)` : `Below VWAP (${vwapRel.toFixed(2)}%)`;

  let score = 50;
  if (ema20 > ema50) score += 10; else score -= 10;
  if (spot > vwap) score += 8; else score -= 8;
  if (rsi > 60) score += 6; if (rsi < 40) score -= 6;

  const direction = score >= 55 ? "UP" : score <= 45 ? "DOWN" : "NEUTRAL";
  return {
    main: direction === "UP" ? "UPTREND" : direction === "DOWN" ? "DOWNTREND" : "NEUTRAL",
    strength: Math.abs(score - 50) > 15 ? "STRONG" : "MODERATE",
    score,
    bias: direction === "UP" ? "CE" : direction === "DOWN" ? "PE" : "NEUTRAL",
    components,
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`
  };
}

/**
 * computeEntryFull - main glue for strikes & targets
 * Accepts: { market, spot, ema20, ema50, rsi, vwap, use_live }
 */
async function computeEntryFull({ market = "NIFTY", spot = null, ema20 = null, ema50 = null, rsi = null, vwap = null, use_live = false }) {
  try {
    market = (market || "NIFTY").toUpperCase();

    // determine spot: prefer live lastKnown tick if requested
    let finalSpot = null;
    if (use_live && typeof lastKnown === "object" && lastKnown.spot) finalSpot = lastKnown.spot;
    if (!finalSpot && spot) finalSpot = Number(spot);
    if (!finalSpot) finalSpot = await fetchSpotLTP(market);

    if (!finalSpot) return { allowed: false, reason: "NO_SPOT" };

    const expiry = detectWeeklyExpiryYMD();
    const daysToExpiry = Math.max(1, Math.ceil((new Date(expiry) - new Date()) / (1000 * 3600 * 24)));

    const strikes = generateStrikeSet(finalSpot);
    const trend = hybridTrendEngine({ ema20, ema50, vwap, rsi, spot: finalSpot });

    const futDiff = await fetchFuturesLTP(market).catch(() => null);

    const ceLTP = await fetchOptionLTP(market, strikes.ce, "CE").catch(() => null);
    const peLTP = await fetchOptionLTP(market, strikes.pe, "PE").catch(() => null);

    const side = trend.main === "UPTREND" ? "CE" : trend.main === "DOWNTREND" ? "PE" : "NONE";
    const entryLTP = side === "CE" ? ceLTP : side === "PE" ? peLTP : null;

    let levels = null;
    if (entryLTP) {
      levels = {
        stopLoss: Number((entryLTP * 0.85).toFixed(2)), // 15% SL
        target1: Number((entryLTP * 1.10).toFixed(2)),
        target2: Number((entryLTP * 1.20).toFixed(2))
      };
    }

    return {
      allowed: !!entryLTP,
      market,
      spot: finalSpot,
      expiry,
      daysToExpiry,
      strikes,
      trend,
      futDiff,
      entrySide: side,
      entryLTP,
      levels
    };
  } catch (e) {
    return { allowed: false, reason: "EXCEPTION", error: e && e.message ? e.message : String(e) };
  }
}

/**
 * /api/compute route
 * Accepts JSON body: { market, spot, ema20, ema50, rsi, vwap, use_live }
 */
app.post("/api/compute", async (req, res) => {
  try {
    const b = req.body || {};
    const out = await computeEntryFull({
      market: b.market,
      spot: b.spot,
      ema20: b.ema20,
      ema50: b.ema50,
      rsi: b.rsi,
      vwap: b.vwap,
      use_live: !!b.use_live
    });

    return res.json({
      success: out.allowed,
      ...out,
      meta: {
        live_data_used: !!(b.use_live && lastKnown && lastKnown.spot),
        live_ltp: lastKnown && lastKnown.spot ? lastKnown.spot : null
      }
    });
  } catch (err) {
    return res.json({ success: false, error: err && err.message ? err.message : String(err) });
  }
});

/* ----------------------------
   END OF PART 5
---------------------------- */
/* ----------------------------------------
   server.js - PART 6 of 6 (FINAL)
   Server Listen + WS Auto Start
----------------------------------------- */

/**
 * Periodic check → if logged in & feed token exists → ensure WSv2 runs
 */
setInterval(() => {
  if (session.access_token && session.feed_token) {
    if (!wsV2Status.connected) {
      console.log("WSv2 AUTO-CHECK → attempting reconnect…");
      startWebsocketV2IfReady();
    }
  }
}, 5000); // every 5 seconds


/**
 * START EXPRESS SERVER
 */
app.listen(PORT, () => {
  console.log("\n========================================");
  console.log("   TENGO BACKEND RUNNING (FINAL FIXED)");
  console.log("   Smart Stream V2 (URL Auth) ACTIVE");
  console.log("   Express Server Listening on PORT:", PORT);
  console.log("========================================\n");
});

/* ----------------------------------------
   END OF FULL server.js (FINAL COMPLETE)
----------------------------------------- */
