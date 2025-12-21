/* PART 1/6 — BASE IMPORTS + CONFIG + SESSION + TOTP + LOGIN */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

/* ONLINE MASTER AUTO-LOADER (NO NEED TO STORE IN GIT) */
global.instrumentMaster = [];

// ===== GLOBAL HELPER =====
global.tsof = function (entry) {
  return String(
    entry?.tradingsymbol ||
    entry?.symbol ||
    entry?.name ||
    ""
  ).toUpperCase();
};
const tsof = global.tsof;
async function loadMasterOnline() {
  try {
    const url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
    const r = await fetch(url);
    const j = await r.json().catch(() => []);
    if (Array.isArray(j) && j.length > 0) {
      global.instrumentMaster = j;
      console.log("MASTER LOADED ONLINE ✔ COUNT:", j.length);
    } else {
      console.log("MASTER LOAD FAILED → empty response");
    }
  } catch (e) {
    console.log("MASTER LOAD ERROR:", e);
  }
}
loadMasterOnline();
setInterval(loadMasterOnline, 60 * 60 * 1000);

const app = express();
app.use(cors());
app.use(bodyParser.json());

/* SERVE FRONTEND */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* ENV SMARTAPI */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* MEMORY SESSION STORE */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: null
};

/* LAST KNOWN SPOT MEMORY */
let lastKnown = {
  spot: null,
  updatedAt: 0,
  prevSpot: null
};

/* BASE32 DECODE + TOTP */
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

/* SAFE JSON FETCH */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
}

/* SmartAPI login */
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
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;
    session.login_time = Date.now();

    return { ok: true };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err);
    return { ok: false, reason: "EXCEPTION", error: err && err.message ? err.message : String(err) };
  }
}

/* Login routes */
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
      login_time: session.login_time
    },
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
    login_time: session.login_time || null
  });
});

app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || "",
  });
});

app.get("/healthz", (req, res) => {
  res.json({
    ok: true,
    time: Date.now(),
    env: {
      SMARTAPI_BASE: SMARTAPI_BASE ? true : false,
      SMART_API_KEY: SMART_API_KEY ? true : false,
      SMART_USER_ID: SMART_USER_ID ? true : false
    }
  });
});

/* Export (kept for testability; server actually starts in Part-6) */
module.exports = {
  app,
  session,
  lastKnown,
  SMARTAPI_BASE,
  SMART_API_KEY,
  SMART_API_SECRET,
  SMART_TOTP_SECRET,
  SMART_USER_ID,
  safeFetchJson,
  smartApiLogin,
  generateTOTP
};
/* PART 2/6 — WEBSOCKET (FULL FIXED VERSION) + HELPERS */

// ===== HELPER FUNCTIONS (DO NOT MOVE BELOW) =====

function itypeOf(entry) {
  return String(
    entry.instrumenttype ||
    entry.instrumentType ||
    entry.type ||
    ""
  ).toUpperCase();
}

function parseExpiryDate(v) {
  if (!v) return null;
  const s = String(v).trim();
  const m = moment(
    s,
    ["YYYY-MM-DD", "YYYYMMDD", "DD-MM-YYYY", "DDMMYYYY", "DDMMMYYYY"],
    true
  );
  if (m.isValid()) return m.toDate();
  const fallback = new Date(s);
  return isFinite(fallback.getTime()) ? fallback : null;
}

function isTokenSane(t) {
  if (!t && t !== 0) return false;
  const n = Number(String(t).replace(/\D/g, "")) || 0;
  return n > 0;
}
// ==============================================

/* WEBSOCKET */
const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";
let wsClient = null;
let wsHeartbeat = null;

let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

const realtime = {
  ticks: {},
  candles1m: {}
};
// ================================
// OPTION WS TOKENS (CE / PE - LIVE)
// ================================
const optionWsTokens = new Set();
let subscribedTokens = new Set();
// OPTION LTP STORE (token -> ltp)
const optionLTP = {};
/* START WEBSOCKET WHEN TOKENS ARE READY */
async function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;
  if (!session.feed_token || !session.access_token) {
    console.log("WS: waiting for login tokens...");
    return;
  }

  try {
    wsClient = new WebSocket(WS_URL, {
      perMessageDeflate: false,
      headers: {
        Authorization: session.access_token,
        "x-api-key": SMART_API_KEY,
        "x-client-code": SMART_USER_ID,
        "x-feed-token": session.feed_token
      }
    });
  } catch (e) {
    console.log("WS INIT ERR", e);
    return;
  }

  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.reconnectAttempts = 0;
    wsStatus.lastError = null;
    console.log("WS: connected.");

    const auth = {
      task: "auth",
      channel: "websocket",
      token: session.feed_token,
      user: SMART_USER_ID,
      apikey: SMART_API_KEY,
      source: "API"
    };

    try { wsClient.send(JSON.stringify(auth)); } catch (e) { console.log("WS AUTH SEND ERR", e); }

    setTimeout(() => subscribeCoreSymbols(), 1000);

    if (wsHeartbeat) clearInterval(wsHeartbeat);
    wsHeartbeat = setInterval(() => {
      try {
        if (wsClient && wsClient.readyState === WebSocket.OPEN) {
          wsClient.send("ping");
        }
      } catch (e) { console.log("HB ERR", e); }
    }, 30000);
  });

  wsClient.on("message", (raw) => {
    wsStatus.lastMsgAt = Date.now();

    let msg = null;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    console.log("🔥 RAW WS MESSAGE", msg);
const d = msg.data || msg;
if (!d) return;
    
   const token =
  d.token ||
  d.instrument_token ||
  d.instrumentToken ||
  null; 

const ltp = Number(
  d.ltp ??
  d.last_traded_price ??
  d.lastPrice ??
  d.price ??
  d.close ??
  0
) || null;

// ✅ MOVE THESE UP
const oi = Number(d.oi || d.openInterest || 0) || null;
const sym = d.tradingsymbol || d.symbol || null;

// 🟢 SAFE TO USE sym NOW
if (token && ltp != null) {
  console.log("🟢 WS TICK", {
    token,
    ltp,
    sym,
    instrumentType: d.instrumenttype || d.instrumentType
  });
}

// realtime ticks
if (sym && ltp != null) {
  realtime.ticks[sym] = {
    ltp,
    oi,
    time: Date.now()
  };
}

// OPTION LTP STORE
if (token && ltp != null) {
  optionLTP[token] = {
    ltp,
    symbol: sym,
    time: Date.now()
  };
}
    // 🔎 DEBUG: option LTP stored
console.log("📦 OPTION LTP STORED", {
  token,
  ltp,
  symbol: sym
});
const itype = String(d.instrumenttype || d.instrumentType || "").toUpperCase();
const ts = String(sym || "").toUpperCase();

if (ltp != null) {
  if (ts.includes("NIFTY")) {
    lastKnown.nifty ??= {};
    lastKnown.nifty.prevSpot = lastKnown.nifty.spot;
    lastKnown.nifty.spot = ltp;
    lastKnown.nifty.updatedAt = Date.now();
  }

  if (ts.includes("SENSEX")) {
    lastKnown.sensex ??= {};
    lastKnown.sensex.prevSpot = lastKnown.sensex.spot;
    lastKnown.sensex.spot = ltp;
    lastKnown.sensex.updatedAt = Date.now();
  }

  if (ts.includes("NATURALGAS") || ts.includes("NG")) {
    lastKnown.ng ??= {};
    lastKnown.ng.prevSpot = lastKnown.ng.spot;
    lastKnown.ng.spot = ltp;
    lastKnown.ng.updatedAt = Date.now();
  }
}
    /* BUILD 1-MIN CANDLE */
    try {
      if (sym && ltp != null) {
        if (!realtime.candles1m[sym]) realtime.candles1m[sym] = [];
        const arr = realtime.candles1m[sym];
        const now = Date.now();
        const curMin = Math.floor(now / 60000) * 60000;
        let cur = arr.length ? arr[arr.length - 1] : null;

        if (!cur || cur.time !== curMin) {
          const newC = {
            time: curMin,
            open: ltp,
            high: ltp,
            low: ltp,
            close: ltp,
            volume: d.volume || 0
          };
          arr.push(newC);
          if (arr.length > 180) arr.shift();
        } else {
          cur.high = Math.max(cur.high, ltp);
          cur.low = Math.min(cur.low, ltp);
          cur.close = ltp;
          cur.volume = (cur.volume || 0) + (d.volumeDelta || 0);
        }
      }
    } catch (e) { console.log("CANDLE ERROR", e); }
  });

  wsClient.on("error", (err) => {
    wsStatus.connected = false;
    wsStatus.lastError = String(err);
    console.log("WS ERR:", err);
    scheduleWSReconnect();
  });

  wsClient.on("close", (code) => {
    wsStatus.connected = false;
    wsStatus.lastError = "closed:" + code;
    console.log("WS CLOSED", code);
    scheduleWSReconnect();
  });
}

function scheduleWSReconnect() {
  wsStatus.reconnectAttempts++;
  const backoff = Math.min(30000, 1000 * Math.pow(1.5, wsStatus.reconnectAttempts));
  setTimeout(() => {
    try { if (wsClient) wsClient.terminate(); } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, backoff);
}
/* --- EXPIRY DETECTOR (FINAL, FIXED) --- */
function detectExpiryForSymbol(symbol, expiryDays = 0) {
  symbol = String(symbol || "").toUpperCase();

  // 1) If UI provided expiry days, use it directly
  if (Number(expiryDays) > 0) {
    const base = new Date();
    const target = new Date(base);
    target.setDate(base.getDate() + Number(expiryDays));
    target.setHours(0, 0, 0, 0);

    return {
      targetDate: target,
      currentWeek: moment(target).format("YYYY-MM-DD"),
      monthly: moment(target).format("YYYY-MM-DD")
    };
  }

  // 2) Auto expiry logic
  const today = moment();

  // Default weekly expiry = Thursday
  let weeklyExpiryDay = 4; // 0=Sun ... 4=Thu

  // Indian indices special cases
  if (symbol.includes("NIFTY")) weeklyExpiryDay = 2;   // Tuesday
  if (symbol.includes("SENSEX")) weeklyExpiryDay = 2; // Tuesday

  // Find current week expiry
  let currentWeek = today.clone().day(weeklyExpiryDay);
  if (currentWeek.isBefore(today, "day")) {
    currentWeek.add(1, "week");
  }

  // Monthly expiry = last occurrence of weeklyExpiryDay in month
  let monthly = today.clone().endOf("month");
  while (monthly.day() !== weeklyExpiryDay) {
    monthly.subtract(1, "day");
  }

  return {
    currentWeek: currentWeek.format("YYYY-MM-DD"),
    monthly: monthly.format("YYYY-MM-DD"),
    targetDate: currentWeek.toDate()
  };
}
/* --- END EXPIRY DETECTOR --- */
/* SUBSCRIBE CORE SYMBOLS — FINAL FIX */

async function subscribeCoreSymbols() {
  try {
    let tokens = [];

    // 🔥 FORCE ADD OPTION TOKENS FIRST
    if (optionWsTokens.size > 0) {
      for (const t of optionWsTokens) {
        if (isTokenSane(t)) {
          tokens.push(String(t));
        }
      }
      console.log("📡 OPTION TOKENS FOR WS:", tokens);
    }

    // ⛑️ SAFETY: अगर अब भी empty है, तो return
    if (!tokens.length) {
      console.log("WS SUB: no tokens resolved (even option)");
      return;
    }

  /* ===== NIFTY FUT ONLY (SAFE MODE) ===== */
const niftyExp = detectExpiryForSymbol("NIFTY").currentWeek;
const niftyFut = await resolveInstrumentToken("NIFTY", niftyExp, 0, "FUT");

if (niftyFut?.token) {
  tokens.push(String(niftyFut.token));
  /* ==== SENSEX ==== */
const sensexIdx = await resolveInstrumentToken("SENSEX", "", 0, "INDEX");
if (sensexIdx?.token) tokens.push(String(sensexIdx.token));

const sensexExp = detectExpiryForSymbol("SENSEX").currentWeek;
const sensexFut = await resolveInstrumentToken("SENSEX", sensexExp, 0, "FUT");
if (sensexFut?.token) tokens.push(String(sensexFut.token));
  
  /* ==== NATURAL GAS (FUT only) ==== */
const ngExp = detectExpiryForSymbol("NATURALGAS").currentWeek;
const ngFut = await resolveInstrumentToken("NATURALGAS", ngExp, 0, "FUT");
if (ngFut?.token) tokens.push(String(ngFut.token));
  
  console.log("WS SUB → NIFTY FUT:", niftyFut.token, niftyExp);
}

    if (!tokens.length) {
      console.log("WS SUB: no tokens resolved");
      return;
    }

    wsClient.send(JSON.stringify({
      task: "cn",
      channel: {
        instrument_tokens: tokens,
        feed_type: "ltp"
      }
    }));

    wsStatus.subscriptions = tokens;
    console.log("WS SUBSCRIBED (ALL MARKETS):", tokens);

  } catch (e) {
    console.log("WS SUBSCRIBE ERR", e);
  }
}

/* WS STATUS ENDPOINT */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions
  });
});

/* AUTO-START HOOK AFTER LOGIN */
const _origSmartLogin = smartApiLogin;
smartApiLogin = async function (pw) {
  const r = await _origSmartLogin(pw);
  if (r && r.ok) {
    setTimeout(() => startWebsocketIfReady(), 1200);
  }
  return r;
};

/* INITIAL DELAYED WS START */
setTimeout(() => startWebsocketIfReady(), 2000);
/* PART 3/6 — TREND + MOMENTUM + VOLUME + HYBRID ENGINE */

function safeNum(n) {
  n = Number(n);
  return isFinite(n) ? n : 0;
}

/* BASIC TREND METRICS */
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

/* MOMENTUM TREND CHECKER */
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

/* RSI TREND FILTER */
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);

  if (direction === "DOWN") return rsi < 40;
  if (direction === "UP")   return rsi > 50;

  return false;
}

/* HYBRID TREND ENGINE */
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
  const basic = computeBasicTrend(ema20, ema50, vwap, spot);
  const mom   = computeMomentumTrend(spot, lastSpot);
  const rsiOk = rsiTrendGate(rsi, basic.direction);

  let score = basic.score;

  if (mom.momentum === "UP") score++;
  if (mom.momentum === "DOWN") score--;

  if (!rsiOk) score = Math.sign(score) * Math.max(0, Math.abs(score) - 1);

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

/* TRIPLE CONFIRMATION — TREND */
async function tripleConfirmTrend(trendObj, symbol, getCandlesFn) {
  if (!trendObj) return { trendConfirmed: false };

  const score = Number(trendObj.score || 0);
  if (Math.abs(score) >= 3) return { trendConfirmed: true };

  try {
    const candles = (typeof getCandlesFn === "function")
      ? (await getCandlesFn(symbol, 1, 30)).map(c => Number(c.close)).filter(Boolean)
      : [];

    const localRSI = candles.length ? computeRSI(candles, 14) : null;

    if (!localRSI && Math.abs(score) >= 2) return { trendConfirmed: true };

    if (trendObj.direction === "UP") {
      if (localRSI && localRSI > 50 && score > 1) return { trendConfirmed: true };
    }
    else if (trendObj.direction === "DOWN") {
      if (localRSI && localRSI < 40 && score < -1) return { trendConfirmed: true };
    }

    return { trendConfirmed: false };
  } catch {
    return { trendConfirmed: Math.abs(score) >= 2 };
  }
}

/* TRIPLE CONFIRMATION — MOMENTUM */
async function tripleConfirmMomentum(symbol, getCandlesFn) {
  try {
    const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 6)  : [];

    const closes1 = c1.map(x => Number(x.close)).filter(Boolean);
    const closes5 = c5.map(x => Number(x.close)).filter(Boolean);

    if (closes1.length < 6) return { momentumConfirmed: false };

    const last = closes1[closes1.length - 1];
    const meanPrev = closes1.slice(0, -1).reduce((a,b)=>a+b,0) / Math.max(1, closes1.length-1);
    const pct = Math.abs((last - meanPrev) / Math.max(1, meanPrev));

    let momentumConfirmed = pct > 0.0008;

    const downs1 = closes1.slice(-5).every((v,i,arr)=> i===0 ? true : arr[i] < arr[i-1]);
    const ups1   = closes1.slice(-5).every((v,i,arr)=> i===0 ? true : arr[i] > arr[i-1]);

    if (!(downs1 || ups1) && closes5.length >= 3) {
      const downs5 = closes5.slice(-3).every((v,i,arr)=> i===0 ? true : arr[i] < arr[i-1]);
      const ups5   = closes5.slice(-3).every((v,i,arr)=> i===0 ? true : arr[i] > arr[i-1]);
      momentumConfirmed = momentumConfirmed && (downs5 || ups5);
    }

    return { momentumConfirmed };
  } catch {
    return { momentumConfirmed: false };
  }
}

/* TRIPLE CONFIRMATION — VOLUME */
async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 12) : [];
    const vols = c5.map(x => Number(x.volume || x.vol || 0)).filter(v => v > 0);

    if (!vols.length) {
      const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
      const highs = c1.map(x=>Number(x.high)).filter(Boolean);
      const lows  = c1.map(x=>Number(x.low)).filter(Boolean);

      const tr = [];
      for (let i = 1; i < highs.length; i++) {
        tr.push(Math.max(
          Math.abs(highs[i]-lows[i]),
          Math.abs(highs[i]-Number(c1[i-1].close)),
          Math.abs(lows[i]-Number(c1[i-1].close))
        ));
      }

      const avgTR = tr.length ? tr.reduce((a,b)=>a+b,0) / tr.length : 0;
      return {
        volumeConfirmed:
          avgTR > 0 && (avgTR / Math.max(1, Number(c1[c1.length-1]?.close || 1))) > 0.001
      };
    }

    const latest = vols[vols.length - 1];
    const sorted = [...vols].sort((a,b)=>a-b);
    const median = sorted[Math.floor(sorted.length / 2)] || 0;
    const mean = vols.reduce((a,b)=>a+b,0) / vols.length;

    return { volumeConfirmed: latest >= Math.max(median*0.9, mean*0.8) };
  } catch {
    return { volumeConfirmed: false };
  }
}

/* FAKE BREAKOUT SOFT BLOCKER */
function rejectFakeBreakout(trendObj, futDiff) {
  if (!trendObj) return true;
  const score = Number(trendObj.score || 0);
  if (Math.abs(score) < 2) return true;
  if (futDiff && Math.abs(futDiff) > 200) return true;
  return false;
}

/* STRIKE UTILS */
function roundToStep(market, price) {
  price = Number(price) || 0;
  return Math.round(price / 50) * 50;
}
function getStrikeSteps(market, daysToExpiry) {
  return daysToExpiry >= 5 ? 50 : 25;
}
function computeStrikeDistanceByExpiry(days, minSteps = 1) {
  if (days <= 1) return minSteps;
  if (days <= 3) return minSteps + 1;
  if (days <= 5) return minSteps + 2;
  return minSteps + 3;
}
function generateStrikes(market, spot, expiry_days) {
  console.log("🚨 STRIKE INPUT:", {
  market,
  spot,
  expiry_days
});
  const base = roundToStep(market, spot);
  const minSteps = getStrikeSteps(market, expiry_days);
  const dynamicDist = computeStrikeDistanceByExpiry(expiry_days, minSteps);
  const atm = base;
  const otm1 = base + dynamicDist;
  const otm2 = base - dynamicDist;
  return { atm, otm1, otm2 };
}

/* TARGET + STOPLOSS */
function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;
  const sl = entryLTP * 0.85;
  const tgt1 = entryLTP * 1.10;
  const tgt2 = entryLTP * 1.20;
  return {
    stopLoss: Number(sl.toFixed(2)),
    target1: Number(tgt1.toFixed(2)),
    target2: Number(tgt2.toFixed(2))
  };
}
/* PART 4/6 — ENTRY ENGINE + FUTURES + OPTION LTP + TOKEN RESOLVE */
function getOptionExchange(symbol) {
  const s = String(symbol).toUpperCase();

  if (s.includes("NIFTY")) return "NFO";
  if (s.includes("SENSEX")) return "BFO";
  if (s.includes("NATURAL") || s.includes("NG")) return "MCX";

  return "NFO"; // default fallback
}
/* FUTURES LTP FETCHER — FIXED */
async function fetchFuturesLTP(symbol) {
  try {
    // ✅ Auto weekly expiry (no expiry_days dependency)
    const expiry = detectExpiryForSymbol(symbol).currentWeek;

    const tokenInfo = await resolveInstrumentToken(
      symbol,
      expiry,
      0,
      "FUT"
    );

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
  } catch (e) {
    console.log("fetchFuturesLTP ERR", e);
    return null;
  }
    }

/* FUTURES DIFF DETECTOR */
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut || !isFinite(spotUsed)) return null;
    return Number(fut) - Number(spotUsed);
  } catch {
    return null;
  }
}
/* OPTION LTP FETCHER (CE/PE) — ANGEL SAFE */
async function fetchOptionLTP(symbol, strike, type, expiry_days) {
  console.log("➡️ fetchOptionLTP called", {
    symbol,
    strike,
    type,
    expiry_days
  });

  try {
    const expiryInfo = detectExpiryForSymbol(symbol, expiry_days);
    const expiry = expiryInfo.currentWeek;

    const tokenInfo = await resolveInstrumentToken(
      symbol,
      expiry,
      strike,
      type
    );

    if (!tokenInfo?.token) return null;

    /* STEP 1: REST OPTION LTP (PRIMARY) */
const ts =
  tokenInfo.instrument?.tradingsymbol ||
  tokenInfo.tradingsymbol ||
  `${symbol}${expiry}${strike}${type}`;

if (!ts) {
  console.log("❌ NO TRADINGSYMBOL RESOLVED", tokenInfo);
  return null;
}

const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`;

const ex = getOptionExchange(symbol);

const r = await fetch(url, {
  method: "POST",
  headers: {
    "X-PrivateKey": SMART_API_KEY,
    "Authorization": `Bearer ${session.access_token}`,
    "X-UserType": "USER",
    "X-SourceID": "WEB",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    mode: "LTP",
    exchangeTokens: {
      [ex]: [String(tokenInfo.token)]
    }
  })
});

const text = await r.text();
let j;

try {
  j = JSON.parse(text);
} catch {
  console.log("❌ NON-JSON OPTION QUOTE RESPONSE", text);
  return null;
}

const apiLtp = Number(
  j?.data?.fetched?.[0]?.ltp ||
  j?.data?.fetched?.[0]?.lastPrice ||
  0
);

if (apiLtp > 0) {
  console.log("🌐 OPTION API LTP", {
    token: tokenInfo.token,
    ltp: apiLtp
  });
  return apiLtp;
}

return null;

    /* STEP 2: WS OPTION LTP (SECONDARY) */
    const wsHit = optionLTP[tokenInfo.token];

    console.log("🔍 OPTION WS HIT CHECK", {
      token: tokenInfo.token,
      wsHit
    });

    if (wsHit && wsHit.ltp > 0) {
      return wsHit.ltp;
    }

    return null;

  } catch (e) {
    console.log("fetchOptionLTP ERR", e);
    return null;
  }
}
 
/* RESOLVE INSTRUMENT TOKEN — single unified implementation */

async function resolveInstrumentToken(symbol, expiry = "", strike = 0, type = "FUT") {
 console.log("### RESOLVE TOKEN – FIXED VERSION ACTIVE ###");
  try {
    // Ensure master is available
    let master = global.instrumentMaster;
    if (!master || !Array.isArray(master) || master.length === 0) {
      try {
        const url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
        const r = await fetch(url);
        master = await r.json().catch(() => null);
        if (Array.isArray(master)) global.instrumentMaster = master;
      } catch (e) {
        return null;
      }
    }

    if (!master || !Array.isArray(master) || master.length === 0) return null;

    const wantedSymbolRaw = String(symbol || "").trim();
    if (!wantedSymbolRaw) return null;
    const wantedSymbol = wantedSymbolRaw.toUpperCase();
    const wantedStrike = Number(strike || 0);
    const wantedType = String((type || "FUT")).toUpperCase();
    const normExpiry = String(expiry || "").replace(/-/g, "").trim();
let candidates = [];
    function normalize(s){ return String(s || "").toUpperCase().replace(/\s+/g, " ").trim(); }

    function matchesMarket(entry) {
      const marketCandidatesArr = [
        entry.symbol,
        entry.name,
        entry.tradingsymbol,
        entry.instrumentname,
        entry.token + ""
      ].filter(Boolean).map(normalize);

      const key = normalize(wantedSymbol);

      if (marketCandidatesArr.includes(key)) return true;

      const aliasMap = {
        "SENSEX": [
          "SENSEX","SENSEX30","SENSEX-30","SENSEX_30",
          "BSE SENSEX","BSE30","SENSEX INDEX","INDEX-SENSEX",
          "SENSEXI","SENSEX-I","SENSEX30-INDEX"
        ],
        "NIFTY": [
          "NIFTY","NIFTY50","NIFTY 50","NSE NIFTY",
          "NIFTY INDEX","NIFTY50 INDEX"
        ],
        "NATURALGAS": [
          "NATURAL GAS","NATURALGAS","NAT GAS","NG","NATGAS"
        ]
      };

      if (aliasMap[key]) {
        if (marketCandidatesArr.some(c => aliasMap[key].includes(c))) return true;
      }

      if (marketCandidatesArr.some(c => c.includes(key))) return true;

      const nospace = key.replace(/\s+/g, "");
      if (marketCandidatesArr.some(c => c.replace(/\s+/g, "").includes(nospace))) return true;

      return false;
    }

    const marketCandidates = master.filter(it => matchesMarket(it));
    if (!marketCandidates.length) return null;
candidates = marketCandidates;
    // 2) OPTION resolver (STRICT – no FUT allowed)
if (type === "CE" || type === "PE") {
  const side = type; // CE / PE
  const approxStrike = Number(strike || 0);

  const optList = candidates.filter((it) => {
    const itype = itypeOf(it);
    const ts = global.tsof(it);
    

    const isOption =
      itype === "OPTIDX" ||
      itype === "OPTSTK" ||
      itype.includes("OPT");

    if (!isOption) return false;

    const sideMatch =
  side === "CE"
    ? (ts.includes("CE"))
    : (ts.includes("PE"));

let st = Number(it.strike || it.strikePrice || 0);

// normalize Angel strike scale
if (st > 100000) {
  st = Math.round(st / 100);
} else if (st > 10000) {
  st = Math.round(st / 10);
}

// allow ATM match when strike = 0 (LIVE mode)
let strikeMatch = true;

if (approxStrike > 0) {
  const diff = Math.abs(st - approxStrike);
  strikeMatch = diff <= 100; // 1 strike tolerance
}

return sideMatch && strikeMatch;
  });

if (optList.length) {
  const withExpiry = optList
    .map(it => {
      const ex =
        parseExpiryDate(
          it.expiry ||
          it.expiryDate ||
          it.expiry_dt ||
          it.expiryDateTime
        );
      const diff = ex ? Math.abs(ex.getTime() - Date.now()) : Infinity;
      return { it, diff };
    })
    .sort((a, b) => a.diff - b.diff);

  const pick = withExpiry[0].it;

const tradingSymbol =
  pick.tradingSymbol ||
  pick.tradingsymbol ||
  pick.symbol ||
  pick.name ||
  "UNKNOWN";

console.log("✅ FINAL PICK (nearest expiry)", {
  tradingSymbol,
  expiry:
    pick.expiry ||
    pick.expiryDate ||
    pick.expiry_dt ||
    pick.expiryDateTime,
  strike: pick.strike,
  token: pick.token
});
  // STEP B: add option token for WS (LIVE CE / PE)
if (type === "CE" || type === "PE") {
  if (isTokenSane(pick.token)) {
    optionWsTokens.add(String(pick.token));
    console.log("📡 OPTION WS TOKEN ADDED:", pick.token);

    // 🔥 NEW: force WS re-subscribe when option token arrives
    if (wsClient && wsStatus.connected) {
  console.log("🔁 Re-subscribing WS after option token add");
  subscribedTokens.clear();   // 🔴 IMPORTANT
  subscribeCoreSymbols();
    }
  }
}
  return { instrument: pick, token: String(pick.token) };
}
  console.log(
    "resolveInstrumentToken: no option match",
    symbol,
    strike,
    side
  );
  return null;
}

// ================================
// MAIN token resolver logic
// ================================

symbol = String(symbol || "").trim().toUpperCase();
type   = String(type || "").trim().toUpperCase();

if (!symbol) return null;

const key = symbol.replace(/[^A-Z]/g, "");
if (!key) return null;

// ✅ MOVE THESE UP (IMPORTANT)
const expiryStr = String(expiry || "").trim();
const strikeNum = Number(strike || 0);
// --------------------------------
// 1) Filter by symbol key
// --------------------------------
 candidates = global.instrumentMaster.filter(it => {
   const ts = global.tsof(it);
   return (
     ts.startsWith(key) ||
     ts.includes(key) ||
     String(it.name || "").toUpperCase().includes(key)
   );
 });

if (!candidates.length) {
  console.log("resolveInstrumentToken: no candidates for", symbol);
  return null;
}

// --------------------------------------------------
// 2) OPTION resolver (FIXED & RELAXED)
// --------------------------------------------------
if (type === "CE" || type === "PE") {
  const side = type;
  const STRIKE_STEP = market === "NIFTY" || market === "SENSEX" ? 50 : 100;
const approxStrike = Math.round(strikeNum / STRIKE_STEP) * STRIKE_STEP;

  console.log("OPTION RESOLVER INPUT", {
    symbol,
    side,
    approxStrike
  });

  const optList = candidates.filter(it => {
    const itype = itypeOf(it);
    const ts = global.tsof(it);
    const st = Number(it.strike || it.strikePrice || 0);

    // option type check
    const isOption =
      itype === "OPTIDX" ||
      itype === "OPTSTK" ||
      itype.includes("OPT");

    if (!isOption) return false;

    // CE / PE match (relaxed)
    const sideMatch =
      ts.endsWith(side) || ts.includes(side);

    if (!sideMatch) return false;

    // strike match (relaxed tolerance)
    const strikeMatch = Math.abs(st - approxStrike) <= STRIKE_STEP;

    if (!strikeMatch) return false;

    return true;
  });

  if (!optList.length) {
    console.log(
      "resolveInstrumentToken: no option match",
      symbol,
      approxStrike,
      side
    );
    return null;
  }

  // nearest expiry preference
  optList.sort((a, b) => {
    const ea = parseExpiryDate(a.expiry || a.expirydate || a.expiryDate);
    const eb = parseExpiryDate(b.expiry || b.expirydate || b.expiryDate);

    if (!ea && !eb) return 0;
    if (!ea) return 1;
    if (!eb) return -1;
    return ea - eb;
  });

  const picked = optList[0];

  console.log("OPTION PICKED", {
    tradingsymbol: picked.tradingsymbol,
    token: picked.token,
    strike: picked.strike,
    expiry: picked.expiry
  });
console.log("✅ FINAL PICK (nearest expiry)", {
  tradingSymbol:
    picked.tradingSymbol ||
    picked.tradingsymbol ||
    picked.symbol ||
    picked.name,
  expiry:
    picked.expiry ||
    picked.expiryDate ||
    picked.expiry_dt ||
    picked.expiryDateTime,
  strike: picked.strike,
  token: picked.token
});
  return {
    token: picked.token,
    instrument: picked
  };
}
  
  return null;

      // fallback index/AMXIDX
      const spots = candidates.filter((it) => {
        const itype = itypeOf(it);
        const st = Number(it.strike || it.strikePrice || 0);
        return (
          (itype.includes("INDEX") || itype.includes("AMXIDX") || itype.includes("IND")) &&
          Math.abs(st) < 1 &&
          isTokenSane(it.token)
        );
      });

      if (spots.length) {
        const s = spots[0];
        return { instrument: s, token: String(s.token) };
      }
    
    // ================================
// FUTURES — NEAREST EXPIRY PICK (STEP-3 FIX)
// ================================
const futCandidates = candidates
  .filter(it => {
    const itype = itypeOf(it);
    return /FUT/.test(itype) && isTokenSane(it.token);
  })
  .map(it => {
    const ex = parseExpiryDate(
      it.expiry || it.expiryDate || it.expiry_dt
    );
    const diff = ex ? Math.abs(ex.getTime() - Date.now()) : Infinity;
    return { it, diff };
  })
  .sort((a, b) => a.diff - b.diff);

if (futCandidates.length) {
  const fut = futCandidates[0].it;
  return {
    instrument: fut,
    token: String(fut.token)
  };
}
    // 5) general fallback
    const general = candidates.find((it) =>
      isTokenSane(it.token) &&
      String(it.tradingsymbol || it.symbol || it.name || "").trim().length > 3
    );

    if (general) return { instrument: general, token: String(general.token) };

    // 6) last fallback
    const any = candidates.find((it) => it.token && isTokenSane(it.token));
    if (any) return { instrument: any, token: String(any.token) };

    return null;
  } catch (err) {
    console.log("resolveInstrumentToken ERROR:", err);
    return null;
  }
}

/* FINAL ENTRY GUARD */
async function finalEntryGuard({ symbol, trendObj, futDiff, getCandlesFn }) {
  const t = await tripleConfirmTrend(trendObj, symbol, getCandlesFn);
  const m = await tripleConfirmMomentum(symbol, getCandlesFn);
  const v = await tripleConfirmVolume(symbol, getCandlesFn);

  const passedCount =
    (t.trendConfirmed ? 1 : 0) +
    (m.momentumConfirmed ? 1 : 0) +
    (v.volumeConfirmed ? 1 : 0);

  if (passedCount === 0) {
    return { allowed: false, reason: "NO_CONFIRMATIONS", details: { t, m, v } };
  }

  if (rejectFakeBreakout(trendObj, futDiff)) {
    return {
      allowed: false,
      reason: "FAKE_BREAKOUT_SOFT",
      details: { t, m, v, futDiff }
    };
  }

  if (futDiff && Math.abs(futDiff) > 300) {
    return { allowed: false, reason: "FUT_MISMATCH_HARD", futDiff };
  }

  return { allowed: true, reason: "ALLOWED", passedCount, details: { t, m, v } };
}

/* MAIN ENTRY ENGINE */
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
  const trendObj = hybridTrendEngine({
    ema20, ema50, vwap, rsi, spot, lastSpot
  });

  const futDiff = await detectFuturesDiff(market, spot);
  const strikes = generateStrikes(market, spot, expiry_days);

  const entryGate = await finalEntryGuard({
    symbol: market,
    trendObj,
    futDiff,
    getCandlesFn: fetchRecentCandles
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

  const ceATM = await fetchOptionLTP(market, strikes.atm, "CE", expiry_days);
const peATM = await fetchOptionLTP(market, strikes.atm, "PE", expiry_days);

  const takeCE = trendObj.direction === "UP";
  const entryLTP = takeCE ? ceATM : peATM;

  if (!entryLTP) {
  return {
    allowed: false,
    reason: "OPTION_LTP_PENDING",
    retryAfter: 1,   // faster retry
    hint: "WS silent or REST retry",
    trend: trendObj
  };
}
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
/* PART 5/6 — CANDLES (HISTORICAL + REALTIME), RSI, ATR, LTP */

/* FETCH HISTORICAL CANDLES */
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
  } catch (e) {
    console.log("fetchCandles ERR", e);
    return [];
  }
}

/* fetchRecentCandles */
async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    if (interval === 1 && realtime.candles1m && realtime.candles1m[symbol]) {
      const arr = realtime.candles1m[symbol];
      return arr.slice(-limit);
    }

    let intv = "ONE_MINUTE";
    if (interval === 5) intv = "FIVE_MINUTE";

    const candles = await fetchCandles(symbol, intv, Math.ceil(limit / (interval === 1 ? 1 : 5)));
    return candles.slice(-limit);
  } catch (e) {
    console.log("fetchRecentCandles ERR", e);
    return [];
  }
}

/* RSI CALCULATOR (14-period default) */
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

    const rs = gains / losses;
    return 100 - 100 / (1 + rs);
  } catch (e) {
    console.log("computeRSI ERR", e);
    return null;
  }
}

/* ATR HELPER */
async function computeATR(symbol, interval = 1, limit = 14) {
  try {
    const candles = await fetchRecentCandles(symbol, interval, limit + 1);
    if (!candles || candles.length < 2) return 0;

    const trs = [];

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
  } catch (e) {
    console.log("computeATR ERR", e);
    return 0;
  }
}

/* VOLUME SPIKE DETECTOR */
function detectVolumeSpike(prevVol, curVol) {
  if (!prevVol || !curVol) return false;
  return curVol >= prevVol * 1.15;
}


/* FETCH LTP (INDEX SPOT SAFE VERSION) */
async function fetchLTP(symbol) {
  try {
    const idx = await resolveInstrumentToken(symbol, "", 0, "INDEX");
    if (!idx?.token) return null;

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
        exchange: idx.instrument.exchange || "NSE",
        tradingsymbol: idx.instrument.tradingsymbol,
        symboltoken: idx.token
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch (e) {
    console.log("fetchLTP ERR", e);
    return null;
  }
}
/* PART 6/6 — API ROUTES + SPOT + CALC + SERVER START */

/* API: GET SPOT (NIFTY / SENSEX / NATURAL GAS) */
app.get("/api/spot", async (req, res) => {
  try {
    const market = String(req.query.market || "NIFTY").toUpperCase();

    /* 1️⃣ WS SPOT (only for INDEX: NIFTY / SENSEX) */
    if (
      (market === "NIFTY" || market === "SENSEX") &&
      lastKnown.spot &&
      Date.now() - (lastKnown.updatedAt || 0) < 5000
    ) {
      return res.json({
        success: true,
        source: "WS",
        spot: lastKnown.spot
      });
    }

    /* 2️⃣ REST SPOT for INDEX (NIFTY / SENSEX) */
    if (market === "NIFTY" || market === "SENSEX") {
      const INDEX_MAP = {
        NIFTY: "NIFTY 50",
        SENSEX: "SENSEX"
      };

      const indexSymbol = INDEX_MAP[market];
      const idx = await resolveInstrumentToken(indexSymbol, "", 0, "INDEX");

      if (!idx?.token) {
        return res.json({
          success: false,
          error: "INDEX_TOKEN_NOT_FOUND"
        });
      }

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
          exchange: idx.instrument.exchange || "NSE",
          tradingsymbol: idx.instrument.tradingsymbol,
          symboltoken: idx.token
        })
      });

      const j = await r.json().catch(() => null);
      const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

      if (!ltp) {
        return res.json({
          success: false,
          error: "SPOT_NOT_AVAILABLE"
        });
      }

      lastKnown.spot = ltp;
      lastKnown.updatedAt = Date.now();

      return res.json({
        success: true,
        source: "REST",
        spot: ltp
      });
    }

    /* 3️⃣ NATURAL GAS → FUTURE LTP AS SPOT */
    if (market === "NATURAL GAS" || market === "NATURALGAS") {
      const fut = await fetchFuturesLTP("NATURALGAS");

      if (!fut) {
        return res.json({
          success: false,
          error: "FUT_LTP_NOT_AVAILABLE"
        });
      }

      return res.json({
        success: true,
        source: "FUTURE",
        spot: fut
      });
    }

    return res.json({
      success: false,
      error: "INVALID_MARKET"
    });
  } catch (e) {
    return res.json({
      success: false,
      error: "SPOT_EXCEPTION",
      detail: String(e)
    });
  }
});

/* API: RESOLVE INSTRUMENT TOKEN */
app.get("/api/token/resolve", async (req, res) => {
  try {
    const market = String(req.query.market || "");
    const strike = Number(req.query.strike || 0);
    const type   = String(req.query.type || "CE");

    const expiry = detectExpiryForSymbol(market).currentWeek;
    const tok = await resolveInstrumentToken(market, expiry, strike, type);

    if (!tok) {
      return res.json({
        success: false,
        error: "TOKEN_NOT_FOUND"
      });
    }

    return res.json({ success: true, token: tok });

  } catch (e) {
    res.json({ success: false, error: "EXCEPTION", detail: String(e) });
  }
});

/* API: /api/calc  (Master Entry Engine) */
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
console.log("CALC INPUT:", {
  market,
  spot,
  expiry_days,
  use_live: req.body.use_live
});
    let finalSpot = null;

// ✅ 1. Manual spot gets FIRST priority
if (spot != null && isFinite(Number(spot))) {
  finalSpot = Number(spot);
}
// ✅ 2. Recent WS spot
else if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) {
  finalSpot = lastKnown.spot;
}
// ✅ 3. REST fallback (index LTP)
else {
  const INDEX_MAP = {
    NIFTY: "NIFTY 50",
    SENSEX: "SENSEX"
  };

  const calcSymbol = INDEX_MAP[market] || market;
  const fb = await fetchLTP(calcSymbol);

  if (fb && isFinite(fb)) {
    finalSpot = fb;
    lastKnown.spot = fb;
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

    return res.json({
      success: true,
      entry
    });
  } catch (err) {
  console.error("❌ COMPUTE ENTRY ERROR:", err);
  return res.json({
    success: false,
    error: "EXCEPTION_IN_CALC",
    detail: err?.message || String(err)
  });
  }
});

/* API: PING */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    live: wsStatus.connected,
    spot: lastKnown.spot || null
  });
});

/* SAFE FALLBACK ROOT (keeps message simple) */
app.get("/", (req, res) => {
  res.send("Rahul Backend OK — LIVE WebSocket Enabled 🚀");
});

/* START SERVER */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
