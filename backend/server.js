/* -------------------------------------------------------------
   RAHUL FINAL BACKEND — LIVE ENABLED (WITH WEBSOCKET)
   PART 1 / X — BASE IMPORTS + CONFIG + SESSION
-------------------------------------------------------------- */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");   // 

// <-- NEW: WebSocket Client (LIVE DATA)

const app = express();
app.use(cors());
app.use(bodyParser.json());

/* ------------------------------------------------------------
   SERVE FRONTEND
------------------------------------------------------------ */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* ------------------------------------------------------------
   ENV SMARTAPI
------------------------------------------------------------ */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
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
  let bits = 0;
  let value = 0;
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
    const time = Math.floor(Date.now() / 30000);
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
   SAFE JSON FETCH
------------------------------------------------------------ */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
// -----------------------------------------------------
// SmartAPI login
// -----------------------------------------------------
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
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: totp,
        }),
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
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // about 20 hours

    return { ok: true };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// -----------------------------------------------------
// Login routes
// -----------------------------------------------------
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
  const r = await smartApiLogin(password);

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
      raw: r.raw || null,
    });
  }

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at,
    },
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
  });
});

app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || "",
  });
});
/* -------------------------------------------------------------
   API: LOGIN STATUS
-------------------------------------------------------------- */
app.get("/api/login/status", (req, res) => {
  res.json({
    access_token: !!session.access_token,
    feed_token: !!session.feed_token,
    login_time: session.login_time
  });
});
/* -------------------------------------------------------------
   LIVE WEBSOCKET (Angel SmartAPI)
   - Uses session.feed_token + session.access_token
   - Auto-starts after login
   - Updates real-time spot into lastKnown.spot
   - Fully non-invasive (does not touch old logic)
-------------------------------------------------------------- */

const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";
let wsClient = null;

let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

// minimal live caches (used by your existing engines)
const realtime = {
  ticks: {},        // last tick for each symbol
  candles1m: {}     // rolling 1-minute candle series
};

/* -------------------------------------------------------------
   START WEBSOCKET WHEN TOKENS ARE READY
-------------------------------------------------------------- */
async function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;

  if (!session.feed_token || !session.access_token) {
    console.log("WS: waiting for login tokens...");
    return;
  }

  try {
    wsClient = new WebSocket(WS_URL, { perMessageDeflate: false });

    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;

      console.log("WS: connected.");

      // AUTH
      const auth = {
  task: "auth",
  channel: "websocket",
  token: session.feed_token,
  user: SMART_USER_ID,
  apikey: SMART_API_KEY,
  source: "API"
};

      try { wsClient.send(JSON.stringify(auth)); }
      catch(e){ console.log("WS AUTH SEND ERR", e); }

      // subscribe after 1 second (tokens resolve)
      setTimeout(() => subscribeCoreSymbols(), 1000);
    });

    wsClient.on("message", (raw) => {
      wsStatus.lastMsgAt = Date.now();

      let msg = null;
      try { msg = JSON.parse(raw); }
      catch { return; }

      if (!msg || !msg.data) return;

      const d = msg.data;

      const token = d.token || d.instrument_token || null;
      const ltp   = Number(d.ltp || d.lastPrice || d.price || 0) || null;
      const oi    = Number(d.oi || d.openInterest || 0) || null;

      // try to extract symbol name directly
      const sym = d.tradingsymbol || d.symbol || null;

      if (sym && ltp != null) {
        // update tick
        realtime.ticks[sym] = {
          ltp, oi,
          time: Date.now()
        };

        // update global spot for backend
        lastKnown.spot = ltp;
        lastKnown.updatedAt = Date.now();

        // ------------------------------
        // BUILD 1-MIN CANDLE
        // ------------------------------
        try {
          if (!realtime.candles1m[sym]) realtime.candles1m[sym] = [];
          const arr = realtime.candles1m[sym];

          const now = Date.now();
          const curMin = Math.floor(now / 60000) * 60000;

          let cur = arr.length ? arr[arr.length - 1] : null;

          if (!cur || cur.time !== curMin) {
            // new candle
            const newC = {
              time: curMin,
              open: ltp,
              high: ltp,
              low: ltp,
              close: ltp,
              volume: d.volume || 0
            };
            arr.push(newC);

            // memory limit
            if (arr.length > 180) arr.shift();
          } else {
            // update existing candle
            cur.high = Math.max(cur.high, ltp);
            cur.low  = Math.min(cur.low, ltp);
            cur.close = ltp;
            cur.volume = (cur.volume || 0) + (d.volumeDelta || 0);
          }
        } catch(e){}
      }
    });

    wsClient.on("close", (code) => {
      wsStatus.connected = false;
      wsStatus.lastError = "closed:" + code;
      console.log("WS CLOSED", code);
      scheduleWSReconnect();
    });

    wsClient.on("error", (e) => {
      wsStatus.connected = false;
      wsStatus.lastError = String(e);
      console.log("WS ERR", e);
      scheduleWSReconnect();
    });

  } catch (e) {
    wsStatus.connected = false;
    wsStatus.lastError = String(e);
    console.log("WS START ERR", e);
    scheduleWSReconnect();
  }
}

/* -------------------------------------------------------------
   RECONNECT LOGIC (SAFE)
-------------------------------------------------------------- */
function scheduleWSReconnect() {
  wsStatus.reconnectAttempts++;
  const backoff = Math.min(30000, 1000 * Math.pow(1.5, wsStatus.reconnectAttempts));

  setTimeout(() => {
    try { if (wsClient) wsClient.terminate(); } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, backoff);
}

/* -------------------------------------------------------------
   SUBSCRIBE TO CORE SYMBOLS
   (NIFTY, SENSEX, NATURALGAS — as per your original file)
-------------------------------------------------------------- */
async function subscribeCoreSymbols() {
  try {
    const symbols = ["NIFTY", "SENSEX", "NATURALGAS"];
    const expiry = detectExpiryForSymbol("NIFTY").currentWeek;

    const tokens = [];

    for (let s of symbols) {
      const tok = await resolveInstrumentToken(s, expiry, 0, "FUT").catch(()=>null);
      if (tok && tok.token) tokens.push(String(tok.token));
    }

    if (tokens.length > 0) {
      const sub = {
        task: "cn",
        channel: {
          instrument_tokens: tokens,
          feed_type: "ltp"
        }
      };
      wsClient.send(JSON.stringify(sub));
      wsStatus.subscriptions = tokens;
      console.log("WS SUBSCRIBED →", tokens);
    }

  } catch (e) {
    console.log("WS SUBSCRIBE ERR", e);
  }
}

/* -------------------------------------------------------------
   WS STATUS ENDPOINT
-------------------------------------------------------------- */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions
  });
});

/* -------------------------------------------------------------
   AUTO START HOOK AFTER LOGIN
-------------------------------------------------------------- */
const _origSmartLogin = smartApiLogin;

smartApiLogin = async function(pw) {
  const r = await _origSmartLogin(pw);
  if (r && r.ok) {
    setTimeout(() => startWebsocketIfReady(), 1200);
  }
  return r;
};

/* -------------------------------------------------------------
   INITIAL DELAYED WS START (if token already present)
-------------------------------------------------------------- */
setTimeout(() => startWebsocketIfReady(), 2000);
/* -------------------------------------------------------------
   FETCH LTP (SPOT)
-------------------------------------------------------------- */
async function fetchLTP(symbol) {
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
        symboltoken: "", // only for indices supported by Angel
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.ltpValue || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   FETCH FUTURES LTP
-------------------------------------------------------------- */
async function fetchFuturesLTP(symbol) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;

    const tokenInfo = await resolveInstrumentToken(symbol, expiry, 0, "FUT");
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
   RESOLVE INSTRUMENT TOKEN
-------------------------------------------------------------- */
async function resolveInstrumentToken(symbol, expiry, strike = 0, type = "FUT") {
  try {
    // This expects your instrument master file to be loaded in memory (as in original)
    if (!global.instrumentMaster) return null;

    const list = global.instrumentMaster.filter((it) => {
      const ts = it.tradingsymbol || "";
      return (
        ts.includes(symbol) &&
        ts.includes(expiry.replace(/-/g, "").slice(2)) &&
        (type === "FUT" ? ts.includes("FUT") : ts.includes(type))
      );
    });

    if (!list.length) return null;

    // FUTURES case → direct
    if (type === "FUT") return { instrument: list[0], token: list[0].token };

    // OPTION case
    const match = list.find((it) => {
      const st = Number(it.strike || it.strikePrice || 0);
      return st === Number(strike) && it.instrumenttype === type;
    });

    return match ? { instrument: match, token: match.token } : null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   EXPIRY DETECTOR (WEEKLY)
-------------------------------------------------------------- */
function detectExpiryForSymbol(symbol) {
  try {
    const today = moment();
    let currentWeek = today.clone().weekday(4); // Thursday

    if (today.weekday() > 4) {
      currentWeek = today.clone().add(1, "weeks").weekday(4);
    }

    const nextWeek = currentWeek.clone().add(1, "weeks").weekday(4);

    return {
      currentWeek: currentWeek.format("YYYY-MM-DD"),
      nextWeek: nextWeek.format("YYYY-MM-DD")
    };
  } catch {
    return {
      currentWeek: moment().format("YYYY-MM-DD"),
      nextWeek: moment().add(7, "days").format("YYYY-MM-DD")
    };
  }
}
/* -------------------------------------------------------------
   BASE TREND METRICS
-------------------------------------------------------------- */
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
   MOMENTUM TREND CHECKER
-------------------------------------------------------------- */
function computeMomentumTrend(spot, prev) {
  try {
    spot = safeNum(spot);
    prev = safeNum(prev);

    if (!prev) return { momentum: "NEUTRAL", slope: 0 };

    const diff = spot - prev;
    if (diff > 3) return { momentum: "UP", slope: diff };
    if (diff < -3) return { momentum: "DOWN", slope: diff };

    return { momentum: "NEUTRAL", slope: diff };
  } catch {
    return { momentum: "NEUTRAL", slope: 0 };
  }
}

/* -------------------------------------------------------------
   DYNAMIC RSI TREND LOGIC  (as per your final decision)
   - Downtrend → RSI < 40 passes
   - Uptrend   → RSI > 50 passes
-------------------------------------------------------------- */
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);

  if (direction === "DOWN") {
    return rsi < 40;
  }
  if (direction === "UP") {
    return rsi > 50;
  }
  return false; // neutral not allowed
}

/* -------------------------------------------------------------
   HYBRID TREND ENGINE  (your original + final merged)
   Combines:
   - Basic EMA/VWAP trend
   - RSI trend filter
   - Momentum slope
-------------------------------------------------------------- */
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
  const basic = computeBasicTrend(ema20, ema50, vwap, spot);
  const mom   = computeMomentumTrend(spot, lastSpot);
  const rsiOk = rsiTrendGate(rsi, basic.direction);

  let score = basic.score;

  if (mom.momentum === "UP") score++;
  if (mom.momentum === "DOWN") score--;

  // if RSI contradicts → reduce score
  if (!rsiOk) score = Math.sign(score) * Math.max(0, Math.abs(score) - 1);

  // final direction
  let finalDir = "NEUTRAL";
  if (score >= 2) finalDir = "UP";
  if (score <= -2) finalDir = "DOWN";

  return {
    direction: finalDir,
    base: basic,
    momentum: mom,
    rsiOk,
    score
  };
}
/* -------------------------------------------------------------
   TRIPLE CONFIRMATION (Trend + Momentum + Volume)
-------------------------------------------------------------- */

/* 1) Trend confirmation — uses hybridTrendEngine result */
async function tripleConfirmTrend(trendObj, symbol, getCandlesFn) {
  if (!trendObj) return { trendConfirmed: false };

  const score = Number(trendObj.score || 0);
  if (Math.abs(score) >= 3) return { trendConfirmed: true }; // lightweight pass for modest scores

  try {
    // fall back to recent 1m candles if provided
    const candles = (typeof getCandlesFn === "function")
      ? (await getCandlesFn(symbol, 1, 30)).map(c => Number(c.close)).filter(Boolean)
      : [];

    const localRSI = candles.length ? computeRSI(candles, 14) : null;

    if (!localRSI && Math.abs(score) >= 2) return { trendConfirmed: true };

    if (trendObj.direction === "UP") {
      if (localRSI && localRSI > 50 && score > 1) return { trendConfirmed: true };
    } else if (trendObj.direction === "DOWN") {
      if (localRSI && localRSI < 40 && score < -1) return { trendConfirmed: true };
    }

    return { trendConfirmed: false };
  } catch {
    return { trendConfirmed: Math.abs(score) >= 2 };
  }
}

/* 2) Momentum confirmation — structure based (1m + 5m)
   returns { momentumConfirmed: boolean }
*/
async function tripleConfirmMomentum(symbol, getCandlesFn) {
  try {
    const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 6) : [];

    const closes1 = c1.map(x => Number(x.close)).filter(Boolean);
    const closes5 = c5.map(x => Number(x.close)).filter(Boolean);

    if (closes1.length < 6) return { momentumConfirmed: false };

    const last = closes1[closes1.length - 1];
    const meanPrev = closes1.slice(0, -1).reduce((a,b)=>a+b,0)/Math.max(1, closes1.length-1);
    const pct = Math.abs((last - meanPrev) / Math.max(1, meanPrev));

    let momentumConfirmed = pct > 0.0008;

    const downs1 = closes1.slice(-5).every((v,i,arr)=> i===0 ? true : arr[i] < arr[i-1]);
    const ups1   = closes1.slice(-5).every((v,i,arr)=> i===0 ? true : arr[i] > arr[i-1]);

    if (!(downs1 || ups1) && closes5.length >= 3) {
      const downs5 = closes5.slice(-3).every((v,i,arr)=> i===0 ? true : arr[i] < arr[i-1]);
      const ups5 = closes5.slice(-3).every((v,i,arr)=> i===0 ? true : arr[i] > arr[i-1]);
      momentumConfirmed = momentumConfirmed && (downs5 || ups5);
    }

    return { momentumConfirmed };
  } catch {
    return { momentumConfirmed: false };
  }
}

/* 3) Volume confirmation — median/mean of recent 5m volumes
   returns { volumeConfirmed: boolean }
*/
async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 12) : [];
    const vols = c5.map(x => Number(x.volume || x.vol || 0)).filter(v=>v>0);

    if (!vols.length) {
      // fallback: ATR-based quick proxy using 1m candles
      const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
      const highs = c1.map(x=>Number(x.high)).filter(Boolean);
      const lows = c1.map(x=>Number(x.low)).filter(Boolean);

      const tr = [];
      for (let i=1;i<highs.length;i++){
        tr.push(Math.max(Math.abs(highs[i]-lows[i]), Math.abs(highs[i]-Number(c1[i-1].close)), Math.abs(lows[i]-Number(c1[i-1].close))));
      }
      const avgTR = tr.length ? tr.reduce((a,b)=>a+b,0)/tr.length : 0;
      return { volumeConfirmed: avgTR > 0 && (avgTR / Math.max(1, Number(c1[c1.length-1]?.close||1))) > 0.001 };
    }

    const latest = vols[vols.length-1];
    const sorted = [...vols].sort((a,b)=>a-b);
    const median = sorted[Math.floor(sorted.length/2)] || 0;
    const mean = vols.reduce((a,b)=>a+b,0)/vols.length;

    return { volumeConfirmed: latest >= Math.max(median*0.9, mean*0.8) };
  } catch {
    return { volumeConfirmed: false };
  }
}

/* -------------------------------------------------------------
   ULTRA-SOFT FAKE BREAKOUT CHECK
   - only blocks when truly unclear or huge futures mismatch
   - does NOT block for RSI or small volume swings
-------------------------------------------------------------- */
function rejectFakeBreakout(trendObj, futDiff) {
  if (!trendObj) return true; // no trend data -> conservative block

  const score = Number(trendObj.score || 0);

  // if market is highly unclear (very small score) -> block
  if (Math.abs(score) < 2) return true;

  // soft futures mismatch threshold (tunable)
  if (futDiff && Math.abs(futDiff) > 200) return true;

  // otherwise allow continuation
  return false;
}

/* -------------------------------------------------------------
   FINAL ENTRY GUARD
   Combines triple-confirmation + soft-breakout + futDiff
   Returns { allowed: boolean, reason: string }
-------------------------------------------------------------- */
async function finalEntryGuard({ symbol, trendObj, futDiff, getCandlesFn }) {
  // triple confirmation checks
  const t = await tripleConfirmTrend(trendObj, symbol, getCandlesFn);
  const m = await tripleConfirmMomentum(symbol, getCandlesFn);
  const v = await tripleConfirmVolume(symbol, getCandlesFn);

  const passedCount = (t.trendConfirmed?1:0) + (m.momentumConfirmed?1:0) + (v.volumeConfirmed?1:0);

  // require at least 1 pass and prefer 2
  if (passedCount === 0) return { allowed: false, reason: "NO_CONFIRMATIONS", details: { t,m,v } };

  // soft breakout reject
  const softReject = rejectFakeBreakout(trendObj, futDiff);
  if (softReject) {
    return { allowed: false, reason: "FAKE_BREAKOUT_SOFT", details: { t,m,v, futDiff } };
  }

  // hard futures mismatch block
  if (futDiff && Math.abs(futDiff) > 300) return { allowed: false, reason: "FUT_MISMATCH_HARD", futDiff };

  return { allowed: true, reason: "ALLOWED", passedCount, details: { t,m,v } };
}
/* -------------------------------------------------------------
   FUTURES DIFF DETECTION (SAFE)
-------------------------------------------------------------- */
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut) return null;
    if (!isFinite(spotUsed)) return null;

    return Number(fut) - Number(spotUsed);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   STRIKE UTILS (your original logic + stable merge)
-------------------------------------------------------------- */
function roundToStep(market, price) {
  price = Number(price) || 0;
  return Math.round(price / 50) * 50;  // your markets: NIFTY/SENSEX/NG → stable
}

function getStrikeSteps(market, daysToExpiry) {
  return (daysToExpiry >= 5 ? 50 : 25);
}

function computeStrikeDistanceByExpiry(days, minSteps = 1) {
  if (days <= 1) return minSteps;
  if (days <= 3) return minSteps + 1;
  if (days <= 5) return minSteps + 2;
  return minSteps + 3;
}

/* -------------------------------------------------------------
   STRIKE GENERATOR (ATM + 2 OTM)
-------------------------------------------------------------- */
function generateStrikes(market, spot, expiry_days) {
  const base = roundToStep(market, spot);
  const minSteps = getStrikeSteps(market, expiry_days);
  const dynamicDist = computeStrikeDistanceByExpiry(expiry_days, minSteps);

  const atm = base;
  const otm1 = base + dynamicDist;
  const otm2 = base - dynamicDist;

  return { atm, otm1, otm2 };
}

/* -------------------------------------------------------------
   TARGET & SL CALCULATOR
-------------------------------------------------------------- */
function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;

  const sl = entryLTP * 0.85;   // 15% SL
  const tgt1 = entryLTP * 1.10;
  const tgt2 = entryLTP * 1.20;

  return {
    stopLoss: Number(sl.toFixed(2)),
    target1: Number(tgt1.toFixed(2)),
    target2: Number(tgt2.toFixed(2))
  };
}

/* -------------------------------------------------------------
   FETCH OPTION LTP (SUPERSAFE)
-------------------------------------------------------------- */
async function fetchOptionLTP(symbol, strike, type) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;

    const tokenInfo = await resolveInstrumentToken(symbol, expiry, strike, type);
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
   VOLUME SPIKE (NON-BLOCKING HELPER)
-------------------------------------------------------------- */
function detectVolumeSpike(prevVol, curVol) {
  if (!prevVol || !curVol) return false;
  return curVol >= prevVol * 1.15;
}

/* -------------------------------------------------------------
   MAIN ENTRY ENGINE
-------------------------------------------------------------- */
async function computeEntry({
  market,
  spot,
  ema20,
  ema50,
  vwap,
  rsi,
  expiry_days,
  lastSpot
}) {
  // ----- basic trend -----
  const trendObj = hybridTrendEngine({
    ema20, ema50, vwap, rsi, spot, lastSpot
  });

  // ----- futures diff -----
  const futDiff = await detectFuturesDiff(market, spot);

  // ----- strike generation -----
  const strikes = generateStrikes(market, spot, expiry_days);

  // ----- triple confirm + guard -----
  const entryGate = await finalEntryGuard({
    symbol: market,
    trendObj,
    futDiff,
    getCandlesFn: fetchRecentCandles   // original function below
  });

  if (!entryGate.allowed) {
    return {
      allowed: false,
      reason: entryGate.reason,
      details: entryGate.details || {},
      trend: trendObj,
      futDiff
    };
  }

  // ----- fetch option LTPs -----
  const ceATM  = await fetchOptionLTP(market, strikes.atm, "CE");
  const peATM  = await fetchOptionLTP(market, strikes.atm, "PE");
  const ceOTM  = await fetchOptionLTP(market, strikes.otm1, "CE");
  const peOTM  = await fetchOptionLTP(market, strikes.otm1, "PE");

  // pick direction-wise
  const takeCE = trendObj.direction === "UP";
  const entryLTP = takeCE ? ceATM : peATM;

  if (!entryLTP)
    return { allowed: false, reason: "OPTION_LTP_FAIL", trend: trendObj };

  // ----- compute SL/targets -----
  const levels = computeTargetsAndSL(entryLTP);

  return {
    allowed: true,
    direction: trendObj.direction,
    strikes,
    entryLTP,
    futDiff,
    sl: levels.stopLoss,
    target1: levels.target1,
    target2: levels.target2
  };
}
/* -------------------------------------------------------------
   CANDLE FETCHERS (1m / 5m)
   - Uses your existing REST-based historical candle fetch
   - WebSocket real-time candles (realtime.candles1m) get used via fallback
-------------------------------------------------------------- */

/* BASE API CALL FOR HISTORICAL CANDLES */
async function fetchCandles(symbol, interval, count) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;

    const payload = {
      exchange: "NSE",
      symboltoken: "",
      interval: interval,
      fromdate: moment().subtract(count, "days").format("YYYY-MM-DD 09:15"),
      todate: moment().format("YYYY-MM-DD 15:30"),
      tradingsymbol: symbol
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const j = await r.json().catch(() => null);

    if (!j || !j.data || !Array.isArray(j.data)) return [];

    return j.data.map((c) => ({
      time: c[0],
      open: Number(c[1]),
      high: Number(c[2]),
      low: Number(c[3]),
      close: Number(c[4]),
      volume: Number(c[5])
    }));
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------
   fetchRecentCandles(symbol, interval, limit)
   PRIORITY:
     1) If WebSocket 1m candles exist → use those (REAL TIME)
     2) else fallback to REST historical
-------------------------------------------------------------- */
async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    // CASE 1: If interval is 1m and socket has candles → use those
    if (interval === 1 && realtime.candles1m[symbol]) {
      const arr = realtime.candles1m[symbol];
      return arr.slice(-limit);
    }

    // CASE 2: fallback to REST
    let intv = "ONE_MINUTE";
    if (interval === 5) intv = "FIVE_MINUTE";

    const candles = await fetchCandles(symbol, intv, limit);
    return candles.slice(-limit);
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------
   RSI CALCULATOR (14-period)
-------------------------------------------------------------- */
function computeRSI(closes, period = 14) {
  try {
    if (!closes || closes.length < period + 1) return null;

    let gains = 0;
    let losses = 0;

    for (let i = 1; i <= period; i++) {
      const diff = closes[i] - closes[i - 1];
      if (diff > 0) gains += diff;
      else losses -= diff;
    }

    if (losses === 0) return 100;

    let rs = gains / losses;
    return 100 - 100 / (1 + rs);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   ATR HELPER (non-blocking)
-------------------------------------------------------------- */
async function computeATR(symbol, interval = 1, limit = 14) {
  try {
    const candles = await fetchRecentCandles(symbol, interval, limit + 1);
    if (candles.length < 2) return 0;

    let trs = [];

    for (let i = 1; i < candles.length; i++) {
      const cur = candles[i];
      const prev = candles[i - 1];
      const tr = Math.max(
        cur.high - cur.low,
        Math.abs(cur.high - prev.close),
        Math.abs(cur.low - prev.close)
      );
      trs.push(tr);
    }

    if (!trs.length) return 0;

    return trs.reduce((a, b) => a + b, 0) / trs.length;
  } catch {
    return 0;
  }
}
/* -------------------------------------------------------------
   API: GET SPOT (LIVE FIRST → FALLBACK REST)
-------------------------------------------------------------- */
app.get("/api/spot", async (req, res) => {
  try {
    const market = String(req.query.market || "NIFTY").toUpperCase();

    // 1) Try websocket live
    if (lastKnown.spot && Date.now() - (lastKnown.updatedAt || 0) < 5000) {
      return res.json({
        success: true,
        source: "LIVE",
        spot: lastKnown.spot
      });
    }

    // 2) Fallback REST
    const fallback = await fetchLTP(market);
    if (fallback) {
      lastKnown.spot = fallback;
      lastKnown.updatedAt = Date.now();
      return res.json({ success: true, source: "REST", spot: fallback });
    }

    return res.json({
      success: false,
      error: "SPOT_NOT_AVAILABLE"
    });
  } catch (e) {
    return res.json({ success: false, error: "EXCEPTION" });
  }
});

/* -------------------------------------------------------------
   API: RESOLVE TOKEN (OPTION / FUT)
-------------------------------------------------------------- */
app.get("/api/token/resolve", async (req, res) => {
  try {
    const market = String(req.query.market || "");
    const strike = Number(req.query.strike || 0);
    const type   = String(req.query.type || "CE");

    const expiry = detectExpiryForSymbol(market).currentWeek;

    const tok = await resolveInstrumentToken(market, expiry, strike, type);
    if (!tok) {
      return res.json({ success: false, error: "TOKEN_NOT_FOUND" });
    }

    return res.json({ success: true, token: tok });
  } catch {
    res.json({ success: false, error: "EXCEPTION" });
  }
});

/* -------------------------------------------------------------
   API: /api/calc
   MASTER ENDPOINT THAT APP USES FOR ENTRY SIGNAL
-------------------------------------------------------------- */
app.post("/api/calc", async (req, res) => {
  try {
    const {
      market,
      ema20,
      ema50,
      vwap,
      rsi,
      spot,
      expiry_days
    } = req.body;

    // ---- LIVE SPOT PRIORITY ----
    let finalSpot = null;

    // 1) If websocket spot is fresh → use it
    if (lastKnown.spot && Date.now() - (lastKnown.updatedAt || 0) < 5000) {
      finalSpot = lastKnown.spot;
    }

    // 2) Else use user-provided spot
    else if (spot) {
      finalSpot = Number(spot);
      lastKnown.spot = finalSpot;
      lastKnown.updatedAt = Date.now();
    }

    // 3) Or last fallback REST
    else {
      const fallback = await fetchLTP(market);
      if (fallback) {
        finalSpot = fallback;
        lastKnown.spot = fallback;
        lastKnown.updatedAt = Date.now();
      }
    }

    if (!finalSpot || !isFinite(finalSpot)) {
      return res.json({
        success: false,
        error: "Spot could not be resolved",
        guardian: {
          spot_used: null,
          live_used: !!lastKnown.spot,
          fallback_used: false
        },
        meta: { live_data_used: false }
      });
    }

    // ----- RUN ENTRY ENGINE -----
    const entry = await computeEntry({
      market,
      spot: finalSpot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot: lastKnown.prevSpot || null
    });

    lastKnown.prevSpot = finalSpot;

    // ----- Response -----
    return res.json({
      success: true,
      entry
    });
  } catch (err) {
    return res.json({
      success: false,
      error: "EXCEPTION_IN_CALC",
      detail: String(err)
    });
  }
});

/* -------------------------------------------------------------
   API: PING
-------------------------------------------------------------- */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    live: wsStatus.connected,
    spot: lastKnown.spot || null
  });
});

/* -------------------------------------------------------------
   FALLBACK ROOT
-------------------------------------------------------------- */
app.get("/", (req, res) => {
  res.send("Rahul Backend OK — LIVE WebSocket Enabled 🚀");
});

/* -------------------------------------------------------------
   START SERVER
-------------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
