/* ============================================================
   TENGO FINAL FIXED (CommonJS, Render-compatible)
   - Based on your original Tengo.js
   - Non-invasive: compute engines untouched
   - Replaced/Patched: WebSocket -> Smart-Stream V2 (URL auth)
   ============================================================ */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = (typeof fetch === "function") ? fetch : require("node-fetch");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();
const moment = require("moment");

const app = express();
app.use(bodyParser.json({ limit: "2mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

/* ------------------------------------------------------------
   SERVE FRONTEND
------------------------------------------------------------ */
const frontendPath = path.join(__dirname, "..", "frontend");
try {
  app.use(express.static(frontendPath));
} catch (e) {
  // frontend missing is OK
}

/* ------------------------------------------------------------
   ENV SMARTAPI
------------------------------------------------------------ */
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* ------------------------------------------------------------
   MEMORY SESSION STORE
------------------------------------------------------------ */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

/* ------------------------------------------------------------
   LAST KNOWN SPOT MEMORY
------------------------------------------------------------ */
let lastKnown = {
  spot: null,
  updatedAt: 0,
};

/* ------------------------------------------------------------
   BASE32 DECODE + TOTP
------------------------------------------------------------ */
function base32Decode(input) {
  if (!input) return Buffer.from([]);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  let out = [];

  input = input.replace(/=+$/, "").toUpperCase();

  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx === -1) continue;

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateTOTP(secret) {
  try {
    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 30000);  // 30-sec step
    const buf = Buffer.alloc(8);

    buf.writeUInt32BE(0, 0);
    buf.writeUInt32BE(time, 4);

    const hmac = crypto.createHmac("sha1", key).update(buf).digest();
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

/* ------------------------------------------------------------
   SAFE FETCH WRAPPER
------------------------------------------------------------ */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}

/* ------------------------------------------------------------
   Update last known spot
------------------------------------------------------------ */
function setLastKnownSpot(v) {
  lastKnown.spot = v;
  lastKnown.updatedAt = Date.now();
}

/* ------------------------------------------------------------
   (👇 नीचे से Part-2 शुरू होगा — तुम्हारे पूरे compute engines)
------------------------------------------------------------ */
/* -------------------------------------------------------------
   SAFE NUMBER
------------------------------------------------------------- */
function safeNum(v) {
  const n = Number(v);
  return isFinite(n) ? n : 0;
}

/* -------------------------------------------------------------
   BASIC TREND METRICS
------------------------------------------------------------- */
function computeBasicTrend(ema20, ema50, vwap, spot) {
  ema20 = safeNum(ema20);
  ema50 = safeNum(ema50);
  vwap  = safeNum(vwap);
  spot  = safeNum(spot);

  const above20 = spot > ema20;
  const above50 = spot > ema50;
  const aboveVW = spot > vwap;

  const below20 = spot < ema20;
  const below50 = spot < ema50;
  const belowVW = spot < vwap;

  let score = 0;
  if (above20) score++;
  if (above50) score++;
  if (aboveVW) score++;

  if (below20) score--;
  if (below50) score--;
  if (belowVW) score--;

  let direction = "NEUTRAL";
  if (score >= 2) direction = "UP";
  if (score <= -2) direction = "DOWN";

  return { score, direction, above20, above50, aboveVW };
}

/* -------------------------------------------------------------
   MOMENTUM TREND (spot vs prev spot)
------------------------------------------------------------- */
function computeMomentumTrend(spot, prev) {
  spot = safeNum(spot);
  prev = safeNum(prev);

  const diff = spot - prev;
  if (diff > 3)  return { momentum: "UP",   slope: diff };
  if (diff < -3) return { momentum: "DOWN", slope: diff };

  return { momentum: "NEUTRAL", slope: diff };
}

/* -------------------------------------------------------------
   RSI TREND GATE (Your Final Logic)
------------------------------------------------------------- */
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);
  if (direction === "DOWN") return rsi < 40;
  if (direction === "UP")   return rsi > 50;
  return false;
}

/* -------------------------------------------------------------
   HYBRID TREND ENGINE
------------------------------------------------------------- */
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
  const base = computeBasicTrend(ema20, ema50, vwap, spot);
  const mom  = computeMomentumTrend(spot, lastSpot);
  const rsiOk = rsiTrendGate(rsi, base.direction);

  let score = base.score;

  if (mom.momentum === "UP")   score++;
  if (mom.momentum === "DOWN") score--;

  if (!rsiOk) score = Math.sign(score) * Math.max(0, Math.abs(score) - 1);

  let direction = "NEUTRAL";
  if (score >= 2) direction = "UP";
  if (score <= -2) direction = "DOWN";

  return { direction, score, base, momentum: mom, rsiOk };
}

/* -------------------------------------------------------------
   TRIPLE CONFIRMATION — TREND
------------------------------------------------------------- */
async function tripleConfirmTrend(trendObj, symbol, getCandlesFn) {
  if (!trendObj) return { trendConfirmed: false };

  if (Math.abs(trendObj.score) >= 3)
    return { trendConfirmed: true };

  try {
    const candles = (await getCandlesFn(symbol, 1, 30))
      .map(c => Number(c.close)).filter(Boolean);

    if (!candles.length) return { trendConfirmed: false };

    const sum = candles.reduce((a,b)=>a+b,0);
    const mean = sum / candles.length;
    const last = candles[candles.length-1];

    if (trendObj.direction === "UP"   && last > mean) return { trendConfirmed: true };
    if (trendObj.direction === "DOWN" && last < mean) return { trendConfirmed: true };

    return { trendConfirmed: false };
  } catch {
    return { trendConfirmed: false };
  }
}

/* -------------------------------------------------------------
   TRIPLE CONFIRMATION — MOMENTUM
------------------------------------------------------------- */
async function tripleConfirmMomentum(symbol, getCandlesFn) {
  try {
    const c = await getCandlesFn(symbol, 1, 8);   // recent 8 candles
    const closes = c.map(x => Number(x.close)).filter(Boolean);

    if (closes.length < 5) return { momentumConfirmed: false };

    const last = closes[closes.length-1];
    const mid  = closes.slice(0, -1)
                .reduce((a,b)=>a+b,0) / (closes.length - 1);

    const pct = Math.abs((last - mid) / mid);

    return { momentumConfirmed: pct > 0.0008 };
  } catch {
    return { momentumConfirmed: false };
  }
}

/* -------------------------------------------------------------
   TRIPLE CONFIRMATION — VOLUME
------------------------------------------------------------- */
async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c = await getCandlesFn(symbol, 5, 10);
    const vols = c.map(x => Number(x.volume||0)).filter(v=>v>0);

    if (!vols.length) return { volumeConfirmed: false };

    const last = vols[vols.length-1];
    const avg  = vols.reduce((a,b)=>a+b,0) / vols.length;

    return { volumeConfirmed: last >= avg*0.8 };
  } catch {
    return { volumeConfirmed: false };
  }
}

/* -------------------------------------------------------------
   FAKE BREAKOUT CHECK (Soft)
------------------------------------------------------------- */
function rejectFakeBreakout(trendObj, futDiff) {
  if (!trendObj) return true;
  if (Math.abs(trendObj.score) < 2) return true;
  if (futDiff && Math.abs(futDiff) > 200) return true;
  return false;
}

/* -------------------------------------------------------------
   FINAL ENTRY GUARD
------------------------------------------------------------- */
async function finalEntryGuard({ symbol, trendObj, futDiff, getCandlesFn }) {
  const t = await tripleConfirmTrend(trendObj, symbol, getCandlesFn);
  const m = await tripleConfirmMomentum(symbol, getCandlesFn);
  const v = await tripleConfirmVolume(symbol, getCandlesFn);

  const passed = (t.trendConfirmed?1:0) +
                 (m.momentumConfirmed?1:0) +
                 (v.volumeConfirmed?1:0);

  if (passed === 0)
    return { allowed:false, reason:"NO_CONFIRMATIONS", details:{t,m,v} };

  if (rejectFakeBreakout(trendObj, futDiff))
    return { allowed:false, reason:"FAKE_BREAKOUT_SOFT", futDiff };

  if (futDiff && Math.abs(futDiff) > 300)
    return { allowed:false, reason:"FUTURE_MISMATCH_HARD", futDiff };

  return { allowed:true, reason:"ALLOWED", passed, details:{t,m,v} };
}

/* -------------------------------------------------------------
   FUTURES DIFF
------------------------------------------------------------- */
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const f = await fetchFuturesLTP(symbol);
    if (!f) return null;
    return Number(f) - Number(spotUsed);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   STRIKE STEPS & GENERATOR
------------------------------------------------------------- */
function roundToStep(mkt, price) {
  return Math.round(Number(price||0) / 50) * 50;
}
function getStrikeSteps(mkt, days) {
  return (days >= 5 ? 50 : 25);
}
function computeStrikeDistanceByExpiry(days, minSteps=1) {
  if (days<=1) return minSteps;
  if (days<=3) return minSteps+1;
  if (days<=5) return minSteps+2;
  return minSteps+3;
}

function generateStrikes(market, spot, days) {
  const base = roundToStep(market, spot);
  const minSteps = getStrikeSteps(market, days);
  const dist = computeStrikeDistanceByExpiry(days, minSteps);

  return {
    atm: base,
    otm1: base + dist,
    otm2: base - dist
  };
}

/* -------------------------------------------------------------
   TARGETS & STOPLOSS
------------------------------------------------------------- */
function computeTargetsAndSL(ltp) {
  ltp = Number(ltp) || 0;
  return {
    stopLoss: Number((ltp * 0.85).toFixed(2)),
    target1:  Number((ltp * 1.10).toFixed(2)),
    target2:  Number((ltp * 1.20).toFixed(2))
  };
}
/* -------------------------------------------------------------
   PART 3/6 — Smart-Stream V2 (URL-auth) : CONNECT + RECONNECT
   Paste this after Part-2 (engines) and before endpoints.
------------------------------------------------------------- */

//
// Ensure single ws client/state exists
//
if (typeof wsV2Client === "undefined") var wsV2Client = null;
if (typeof wsV2Status === "undefined") {
  var wsV2Status = {
    connected: false,
    reconnectAttempts: 0,
    lastMsgAt: 0,
    lastError: null,
    subscriptions: []
  };
}

/**
 * buildWsV2Url()
 * Uses SMART_USER_ID + SMART_API_KEY (from env) + session.feed_token
 */
function buildWsV2Url() {
  const client = encodeURIComponent(String(process.env.SMART_USER_ID || SMART_USER_ID || ""));
  const apiKey = encodeURIComponent(String(process.env.SMART_API_KEY || SMART_API_KEY || ""));
  const feed = encodeURIComponent(String(session.feed_token || ""));
  return `${WS_V2_BASE}?clientCode=${client}&feedToken=${feed}&apiKey=${apiKey}`;
}

/**
 * scheduleWSReconnect()
 * Uses exponential-ish backoff but bounded.
 */
function scheduleWSReconnect() {
  try {
    wsV2Status.reconnectAttempts = (wsV2Status.reconnectAttempts || 0) + 1;
    const attempt = wsV2Status.reconnectAttempts;
    const delay = Math.min(30000, Math.round(1000 * Math.pow(1.6, Math.min(attempt, 10))));
    console.log(`WSv2 → reconnect scheduled in ${delay}ms (attempt ${attempt})`);
    setTimeout(() => {
      try { startWebsocketIfReadyV2().catch(()=>{}); } catch(e){ console.log("reconnect start err", e && e.message); }
    }, delay);
  } catch(e){ console.log("scheduleWSReconnect err", e && e.message); }
}

/**
 * startWebsocketIfReadyV2()
 * Main starter — idempotent and safe
 */
async function startWebsocketIfReadyV2() {
  try {
    console.log("WSv2: start check", { access: !!session.access_token, feed: !!session.feed_token });

    // already connected
    if (wsV2Client && wsV2Status.connected) return;

    // require both JWT and feed token for URL auth
    if (!session.access_token || !session.feed_token) {
      console.log("WSv2: token(s) missing, skipping connect");
      return;
    }

    // cleanup existing client if any
    try {
      if (wsV2Client) {
        try { wsV2Client.removeAllListeners && wsV2Client.removeAllListeners(); } catch(e){}
        try { wsV2Client.terminate ? wsV2Client.terminate() : wsV2Client.close(); } catch(e){}
      }
    } catch(e){ /* ignore */ }
    wsV2Client = null;
    wsV2Status.connected = false;

    // build url
    const url = buildWsV2Url();
    console.log("WSv2 CONNECT →", url.replace(/(feedToken=)[^&]+/, "$1[hidden]"));

    // create ws client (use ws package in node)
    const WS = require("ws");
    wsV2Client = new WS(url, { perMessageDeflate: false, handshakeTimeout: 10000 });

    // on open
    wsV2Client.on("open", () => {
      wsV2Status.connected = true;
      wsV2Status.reconnectAttempts = 0;
      wsV2Status.lastError = null;
      console.log("WSv2: connected (URL auth)");

      // re-subscribe if previously requested tokens exist
      if (Array.isArray(wsV2Status.subscriptions) && wsV2Status.subscriptions.length) {
        const payload = { action: "subscribe", params: { mode: "ltp", tokenList: wsV2Status.subscriptions } };
        try { wsV2Client.send(JSON.stringify(payload)); } catch(e){ console.log("resub send err", e && e.message); }
      }
    });

    // on message
    wsV2Client.on("message", (data) => {
      wsV2Status.lastMsgAt = Date.now();
      try {
        let text = data;
        if (Buffer.isBuffer(data)) text = data.toString("utf8");
        let parsed = null;
        try { parsed = JSON.parse(text); } catch(e) { parsed = text; }
        // Prefer user-defined handler if present (handleWsMessageGeneric),
        // otherwise fallback to light parsing here.
        if (typeof handleWsMessageGeneric === "function") {
          try { handleWsMessageGeneric(parsed); } catch(e){ console.log("handleWsMessageGeneric err", e && e.message); }
        } else {
          // basic fallback parsing:
          try {
            if (typeof parsed === "object" && parsed !== null) {
              // common V2 tick shape: { type:'tick', data:{ token/ltp/... } }
              if (parsed.type === "tick" && parsed.data) {
                const d = parsed.data;
                const token = String(d.token || d.symbol || d.instrument || "");
                const ltp = Number(d.ltp || d.lastPrice || d.price || 0);
                if (token && isFinite(ltp) && ltp > 0) {
                  global.realtime = global.realtime || {};
                  global.realtime.ticks = global.realtime.ticks || {};
                  global.realtime.ticks[token] = { token, ltp, ts: Date.now(), raw: d };
                  setLastKnownSpot(ltp);
                }
              }
            }
          } catch(e){ console.log("ws parse fallback err", e && e.message); }
        }
      } catch (e) {
        console.log("WSv2 message error", e && e.message);
      }
    });

    // on close
    wsV2Client.on("close", (code, reason) => {
      wsV2Status.connected = false;
      wsV2Status.lastError = "CLOSED:" + code;
      console.log("WSv2 CLOSED", code, reason && reason.toString ? reason.toString() : reason);
      scheduleWSReconnect();
    });

    // on error
    wsV2Client.on("error", (err) => {
      wsV2Status.connected = false;
      wsV2Status.lastError = String(err && err.message || err);
      console.log("WSv2 ERROR", wsV2Status.lastError);
      scheduleWSReconnect();
    });

  } catch (e) {
    wsV2Status.connected = false;
    wsV2Status.lastError = String(e && e.message || e);
    console.log("WSv2 start exception", e && e.message);
    scheduleWSReconnect();
  }
}

/* -------------------------------------------------------------
   END PART 3
   (Next: Part-4 -> message handler helpers + subscribe/unsubscribe endpoints)
------------------------------------------------------------- */
/* -------------------------------------------------------------
   PART 4/6 — WebSocket V2 Message Handler + Subscription APIs
------------------------------------------------------------- */

/* -------------------------------------------------------------
   GENERIC MESSAGE HANDLER (Used by V2 WebSocket)
------------------------------------------------------------- */
function handleWsMessageGeneric(obj) {
  try {
    if (!obj) return;

    // If raw string → parse
    if (typeof obj === "string") {
      try { obj = JSON.parse(obj); } catch { return; }
    }

    /* -------------------------------
       V2 TICK FORMAT:
       { type:"tick", data:{ token, ltp, ... } }
    ------------------------------- */
    if (obj.type === "tick" && obj.data) {
      const d = obj.data;
      const token = String(
        d.token ||
        d.symbol ||
        d.instrument ||
        d.instrumentToken ||
        ""
      );

      const ltp = Number(
        d.ltp ||
        d.lastPrice ||
        d.price ||
        d.last ||
        0
      );

      if (token && isFinite(ltp) && ltp > 0) {
        global.realtime = global.realtime || {};
        global.realtime.ticks = global.realtime.ticks || {};

        global.realtime.ticks[token] = {
          token,
          ltp,
          ts: Date.now(),
          raw: d
        };

        // Update last known spot
        setLastKnownSpot(ltp);
      }

      return;
    }

    /* -----------------------------------------------------
       Legacy Shape (rare):
       { payload:{ symbol, ltp } }
    ----------------------------------------------------- */
    if (obj.payload && obj.payload.symbol) {
      const d = obj.payload;

      const token = String(d.symbol || d.token || "");
      const ltp = Number(d.ltp || d.lastPrice || 0);

      if (token && ltp > 0) {
        global.realtime = global.realtime || {};
        global.realtime.ticks = global.realtime.ticks || {};

        global.realtime.ticks[token] = {
          token,
          ltp,
          ts: Date.now(),
          raw: d
        };

        setLastKnownSpot(ltp);
      }
      return;
    }

  } catch (e) {
    console.log("handleWsMessageGeneric err:", e && e.message);
  }
}

/* -------------------------------------------------------------
   SUBSCRIBE / UNSUBSCRIBE HELPERS
------------------------------------------------------------- */
function wsV2Subscribe(token) {
  try {
    const t = String(token);
    if (!t) return false;

    wsV2Status.subscriptions = wsV2Status.subscriptions || [];
    if (!wsV2Status.subscriptions.includes(t)) {
      wsV2Status.subscriptions.push(t);
    }

    // send live if connected
    if (wsV2Client && wsV2Status.connected) {
      const payload = {
        action: "subscribe",
        params: { mode: "ltp", tokenList: [t] }
      };
      try { wsV2Client.send(JSON.stringify(payload)); } catch (e) {}
    }
    return true;

  } catch { return false; }
}

function wsV2Unsubscribe(token) {
  try {
    const t = String(token);
    if (!t) return false;

    wsV2Status.subscriptions =
      (wsV2Status.subscriptions || []).filter(x => x !== t);

    if (wsV2Client && wsV2Status.connected) {
      const payload = {
        action: "unsubscribe",
        params: { mode: "ltp", tokenList: [t] }
      };
      try { wsV2Client.send(JSON.stringify(payload)); } catch (e) {}
    }
    return true;

  } catch { return false; }
}

/* --------------------------------------------------------------
   WS ENDPOINTS — /api/ws/status, subscribe, unsubscribe
-------------------------------------------------------------- */

// WS STATUS
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: !!wsV2Status.connected,
    lastMsgAt: wsV2Status.lastMsgAt || null,
    lastError: wsV2Status.lastError || null,
    subscriptions: wsV2Status.subscriptions || []
  });
});

// SUBSCRIBE
app.post("/api/ws/subscribe", (req, res) => {
  const body = req.body || {};
  const tokens = Array.isArray(body.tokens)
    ? body.tokens
    : (body.token ? [body.token] : []);

  if (!tokens.length) {
    return res.json({ success: false, reason: "NO_TOKENS" });
  }

  for (const t of tokens) wsV2Subscribe(t);

  return res.json({
    success: true,
    subscriptions: wsV2Status.subscriptions
  });
});

// UNSUBSCRIBE
app.post("/api/ws/unsubscribe", (req, res) => {
  const body = req.body || {};
  const tokens = Array.isArray(body.tokens)
    ? body.tokens
    : (body.token ? [body.token] : []);

  if (!tokens.length) {
    return res.json({ success: false, reason: "NO_TOKENS" });
  }

  for (const t of tokens) wsV2Unsubscribe(t);

  return res.json({
    success: true,
    subscriptions: wsV2Status.subscriptions
  });
});

/* -------------------------------------------------------------
   END PART 4
------------------------------------------------------------- */
/* -------------------------------------------------------------
   PART 5/6 — WebSocket Auto-Start After Login + Auto Health Checker
------------------------------------------------------------- */

/* -------------------------------------------------------------
   SMARTAPI LOGIN (PATCHED)
   - This is ONLY the WebSocket start-integration.
   - Your original login logic stays SAME.
------------------------------------------------------------- */

app.post("/api/login", async (req, res) => {
  try {
    const { password } = req.body || {};

    if (!password)
      return res.json({ success:false, message:"Password required" });

    const totp = generateTOTP(SMART_TOTP_SECRET);
    if (!totp)
      return res.json({ success:false, message:"TOTP failed" });

    const url = `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`;

    const r = await safeFetchJson(url, {
      method: "POST",
      headers: {
        "X-ClientLocalIP": "127.0.0.1",
        "X-PrivateKey": SMART_API_KEY,
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        clientcode: SMART_USER_ID,
        password,
        totp
      })
    });

    if (!r.ok)
      return res.json({ success:false, message:"Network error", detail:r.error });

    const data = r.data;
    if (!data?.data?.jwtToken)
      return res.json({ success:false, message:"Invalid login response", raw:data });

    // --------------------------
    // SAVE SESSION TOKENS
    // --------------------------
    session.access_token = String(data.data.jwtToken || "");
    session.refresh_token = String(data.data.refreshToken || "");
    session.feed_token    = String(data.data.feedToken || "");
    session.expires_at    = Date.now() + 1000 * 60 * 60; // 1 hour

    console.log("LOGIN SUCCESS", {
      access: !!session.access_token,
      feed: !!session.feed_token
    });

    // -----------------------------------------------------
    // AUTO-START WEBSOCKET — ***CRITICAL FIX HERE***
    // -----------------------------------------------------
    setTimeout(() => {
      try {
        startWebsocketIfReadyV2().catch(e =>
          console.log("WSv2 start err", e && e.message)
        );
      } catch (e) {
        console.log("WSv2 start exception", e && e.message);
      }
    }, 350);   // slight delay for session flush

    return res.json({ success:true, message:"SmartAPI Login Successful" });

  } catch (e) {
    return res.json({ success:false, message:"Internal error", error:e.message });
  }
});


/* -------------------------------------------------------------
   AUTO-CHECKER (every 5 seconds)
   Ensures:
   - If login complete → WS stays running
   - If WS drops → restart
------------------------------------------------------------- */
setInterval(() => {
  try {
    const loggedIn = !!session.access_token && !!session.feed_token;

    if (!loggedIn) return;

    if (!wsV2Status.connected) {
      console.log("WSv2 → auto-check: reconnecting...");
      startWebsocketIfReadyV2().catch(()=>{});
    }
  } catch(e) {
    console.log("WSv2 auto-check error:", e && e.message);
  }
}, 5000);

/* -------------------------------------------------------------
   END PART 5
------------------------------------------------------------- */
/* -------------------------------------------------------------
   FETCH FUTURES LTP  (supersafe)
------------------------------------------------------------- */
async function fetchFuturesLTP(symbol) {
  try {
    const exp = detectExpiryForSymbol(symbol).currentWeek;
    const tokenInfo = await resolveInstrumentToken(symbol, exp, 0, "FUT");
    if (!tokenInfo) return null;

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
        exchange: tokenInfo.instrument?.exchange || "NFO",
        tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
        symboltoken: tokenInfo.token || ""
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);
    return ltp > 0 ? ltp : null;

  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   CORE SPOT FETCHER (Auto for NIFTY / SENSEX / NG)
------------------------------------------------------------- */
async function fetchSpot(symbol) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const exchange = (symbol === "NATURALGAS") ? "MCX" : "NSE";

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
        exchange: exchange,
        tradingsymbol: symbol,
        symboltoken: "0"
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;

  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   EXPIRY DETECTOR
------------------------------------------------------------- */
function detectExpiryForSymbol(symbol) {
  const today = moment();
  const weekday = today.day();

  // weekly expiry: Thursday
  let nextThursday = today.clone().day(4); 
  if (weekday > 4) nextThursday.add(1, "week");

  return {
    currentWeek: nextThursday.format("DDMMMYYYY").toUpperCase()
  };
}

/* -------------------------------------------------------------
   TOKEN RESOLVER (Symbol + Strike + Type => Token)
------------------------------------------------------------- */
async function resolveInstrumentToken(symbol, expiryStr, strike, type) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/searchScrip`;
    const search = `${symbol}${expiryStr}${strike}${type}`.toUpperCase();

    const r = await safeFetchJson(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ search })
    });

    if (!r.ok || !r.data?.data?.length) return null;

    const i = r.data.data[0];
    return {
      token: i.symboltoken,
      instrument: i
    };

  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   CANDLE FETCHER (1m / 5m)
------------------------------------------------------------- */
async function fetchCandles(symbol, intervalMins = 1, count = 20) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;

    const now = moment().format("YYYY-MM-DD HH:mm");
    const from = moment().subtract(count * intervalMins, "minutes")
                 .format("YYYY-MM-DD HH:mm");

    const payload = {
      exchange: (symbol === "NATURALGAS" ? "MCX" : "NSE"),
      symbol: symbol,
      interval: `${intervalMins}minute`,
      fromdate: from,
      todate: now
    };

    const r = await safeFetchJson(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const raw = r.data?.data?.candles || [];
    return raw.map(c => ({
      time: c[0],
      open: c[1],
      high: c[2],
      low: c[3],
      close: c[4],
      volume: c[5]
    }));

  } catch {
    return [];
  }
}

/* -------------------------------------------------------------
   RSI CALCULATOR
------------------------------------------------------------- */
function computeRSI(closes, period = 14) {
  if (!closes || closes.length < period + 1) return null;

  let gains = 0, losses = 0;
  for (let i = closes.length - period - 1; i < closes.length - 1; i++) {
    const diff = closes[i + 1] - closes[i];
    if (diff >= 0) gains += diff;
    else losses -= diff;
  }

  const avgGain = gains / period;
  const avgLoss = losses / period;

  if (avgLoss === 0) return 100;
  const rs = avgGain / avgLoss;

  return 100 - (100 / (1 + rs));
}

/* -------------------------------------------------------------
   MAIN ENTRY COMPUTE
------------------------------------------------------------- */
async function computeEntry(symbol, ema20, ema50, rsi, vwap, spot, expiry_days) {
  const trendObj = hybridTrendEngine({
    ema20, ema50, rsi, vwap,
    spot,
    lastSpot: lastKnown.spot
  });

  const strikes = generateStrikes(symbol, spot, expiry_days);

  const ce = await fetchOptionLTP(symbol, strikes.otm1, "CE");
  const pe = await fetchOptionLTP(symbol, strikes.otm2, "PE");
  const atm = await fetchOptionLTP(symbol, strikes.atm, "CE");

  const futDiff = await detectFuturesDiff(symbol, spot);
  const guard = await finalEntryGuard({
    symbol,
    trendObj,
    futDiff,
    getCandlesFn: fetchCandles
  });

  return {
    strikes,
    optionLTP: { ce, pe, atm },
    trendObj,
    futDiff,
    guard
  };
}

/* -------------------------------------------------------------
   MAIN API — /api/calc
------------------------------------------------------------- */
app.post("/api/calc", async (req, res) => {
  try {
    const { 
      market = "NIFTY",
      ema20, ema50, rsi, vwap, spot,
      expiry_days = 1,
      use_live = true
    } = req.body || {};

    let finalSpot = Number(spot);

    if (use_live) {
      const live = await fetchSpot(market);
      if (live) finalSpot = live;
    }

    const result = await computeEntry(
      market,
      ema20, ema50, rsi, vwap,
      finalSpot,
      expiry_days
    );

    return res.json({
      success: true,
      message: "Calculation complete",
      live_used: use_live,
      spot: finalSpot,
      ...result
    });

  } catch (e) {
    return res.json({
      success:false,
      message:"Error in calc",
      error:e.message
    });
  }
});

/* -------------------------------------------------------------
   PING + ROOT
------------------------------------------------------------- */
app.get("/api/ping", (req, res) => res.json({ pong:true }));
app.get("/", (req, res) => res.send("Backend running"));

/* -------------------------------------------------------------
   SERVER START
------------------------------------------------------------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("TENGO Server running on", PORT));
