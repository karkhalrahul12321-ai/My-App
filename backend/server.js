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

/* ===============================
   MARKET HOURS HELPER (NSE)
================================ */
function isMarketOpen() {
  const now = new Date();
  const day = now.getDay(); // 0 = Sunday
  if (day === 0 || day === 6) return false;

  const h = now.getHours();
  const m = now.getMinutes();
  const minutes = h * 60 + m;

  // NSE: 09:15 (555) → 15:30 (930)
  return minutes >= 555 && minutes <= 930;
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

/* PART 2/6 — WEBSOCKET (ANGEL ONE SMART STREAM V2 — FINAL) */

// ===== HELPERS =====
function itypeOf(entry) {
  return String(
    entry.instrumenttype ||
    entry.instrumentType ||
    entry.type ||
    ""
  ).toUpperCase();
}

function isTokenSane(t) {
  const n = Number(String(t).replace(/\D/g, ""));
  return Number.isFinite(n) && n > 0;
}

// ===== WS CONFIG =====
const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";
let wsClient = null;
let wsHeartbeat = null;

let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  reconnectAttempts: 0,
  subscriptions: []
};

const realtime = { ticks: {}, candles1m: {} };
//const optionWsTokens = new Set();
//const optionLTP = {};
const wsSubs = {
  index: false,
  options: new Set()
};

// ===== START WS =====
async function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;
  if (!session.feed_token || !session.access_token) return;

  wsClient = new WebSocket(WS_URL, {
  headers: {
    Authorization: `Bearer ${session.access_token}`,
    "x-api-key": SMART_API_KEY,
    "x-client-code": SMART_USER_ID,
    "x-feed-token": session.feed_token
  }
});

  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.reconnectAttempts = 0;

    // 🔐 AUTH (V2)
    wsClient.send(JSON.stringify({
      action: "auth",
      params: {
        token: session.feed_token,
        user: SMART_USER_ID,
        apikey: SMART_API_KEY
      }
    }));

    setTimeout(subscribeCoreSymbols, 800);

    wsHeartbeat = setInterval(() => {
      if (wsClient.readyState === WebSocket.OPEN) {
        wsClient.send(JSON.stringify({ action: "ping" }));
      }
    }, 30000);
  });

  wsClient.on("message", raw => {
    wsStatus.lastMsgAt = Date.now();

    // ✅ RAW WS LOG (Angel proof)
    console.log("RAW WS MSG", raw.toString());

    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    const payload = Array.isArray(msg.data) ? msg.data[0] : msg.data;
    if (!payload) return;

    const token = String(payload.exchangeInstrumentID).trim();
      let rawLtp =
    payload.touchline?.lastTradedPrice ??
    payload.touchline?.ltp ??
    payload.lastTradedPrice ??
    payload.ltp ??
    payload?.bestFive?.buy?.[0]?.price ??
    payload?.bestFive?.sell?.[0]?.price ??
    0;

  const ltp = rawLtp > 0 ? rawLtp / 100 : 0;
    const sym = payload.tradingsymbol || null;
    const itype = itypeOf(payload);

    if (!token) return;

    // SPOT UPDATE
    if (itype.includes("INDEX") && sym?.includes("NIFTY")) {
      lastKnown.nifty = { spot: ltp, updatedAt: Date.now() };
    }

    if (itype.includes("INDEX") && sym?.includes("SENSEX")) {
      lastKnown.sensex = { spot: ltp, updatedAt: Date.now() };
    }

    // CANDLE BUILD
    if (sym) {
      realtime.candles1m[sym] ??= [];
      const arr = realtime.candles1m[sym];
      const t = Math.floor(Date.now() / 60000) * 60000;
      const last = arr[arr.length - 1];

      if (!last || last.time !== t) {
        arr.push({ time: t, open: ltp, high: ltp, low: ltp, close: ltp, volume: 0 });
        if (arr.length > 180) arr.shift();
      } else {
        last.high = Math.max(last.high, ltp);
        last.low = Math.min(last.low, ltp);
        last.close = ltp;
      }
    }
  });

  wsClient.on("close", scheduleWSReconnect);
  wsClient.on("error", scheduleWSReconnect);
}

function scheduleWSReconnect() {
  wsStatus.connected = false;
  wsStatus.reconnectAttempts++;
  setTimeout(() => {
    try { wsClient?.terminate(); } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, Math.min(30000, 1000 * 2 ** wsStatus.reconnectAttempts));
}
    
// ===== SUBSCRIBE (V2 ONLY) =====
async function subscribeCoreSymbols(retry = 0) {
  if (!wsClient || wsClient.readyState !== WebSocket.OPEN) return;

  /* =========================
     BUILD INDEX TOKENS
  ========================== */
  const indexTokens = [
    {
      exchangeSegment: 1, // NSE
      exchangeInstrumentID: 99926000 // NIFTY
    }
  ];

  /* =========================
     BUILD OPTION TOKENS
  ========================== */
  const optionTokens = [];

  for (const t of optionWsTokens) {
    if (isTokenSane(t)) {
      optionTokens.push({
        exchangeSegment: 2, // NFO
        exchangeInstrumentID: Number(t)
      });
    }
  }

  /* =========================
     WS SUBSCRIBE — SPLIT MODE
  ========================== */
  // INDEX — FULL MODE (MODE 4)
  wsClient.send(JSON.stringify({
    action: "subscribe",
    params: {
      mode: 4,
      tokenList: indexTokens
    }
  }));
  console.log("📡 WS INDEX SUBSCRIBE (mode 4)", indexTokens);

  /* =========================
     STATUS
  ========================== */
  wsSubs.index = true;
  wsStatus.subscriptions = {
    index: indexTokens,
    options: optionTokens
  };
}

/* WAIT FOR OPTION WS TICK (SAFE PROMISE) */
function waitForOptionWSTick(token, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const start = Date.now();

    const iv = setInterval(() => {
      if (optionLTP[token]?.ltp > 0) {
        clearInterval(iv);
        return resolve(optionLTP[token].ltp);
      }

      if (Date.now() - start >= timeoutMs) {
        clearInterval(iv);
        return resolve(null);
      }
    }, 100);
  });
}

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
/* ===============================
   STRIKE UTILS (DYNAMIC, EXPIRY AWARE)
================================ */

/* STEP SIZE — EXCHANGE RULE */
function getStrikeStepByMarket(market) {
  market = String(market || "").toUpperCase();
  if (market.includes("NIFTY")) return 50;
  if (market.includes("SENSEX")) return 100;
  if (market.includes("NATURAL") || market.includes("NG")) return 5;
  return 50;
}

/* ROUND TO VALID STRIKE */
function roundToStep(market, price) {
  const step = getStrikeStepByMarket(market);
  return Math.round(Number(price) / step) * step;
}

/* ===============================
   EXPIRY AWARE GAP MATRIX
================================ */

function getStrikeGapsByMarket(market, expiry_days = 0) {
  market = String(market || "").toUpperCase();

  /* EXPIRY NEAR → SMALLER GAPS */
  const shrink =
    expiry_days <= 0 ? 1 :
    expiry_days <= 1 ? 0.8 :
    expiry_days <= 3 ? 0.6 :
    expiry_days <= 5 ? 0.5 :
    1;

  if (market.includes("NIFTY")) {
    return [
      Math.round(250 * shrink / 50) * 50,
      Math.round(150 * shrink / 50) * 50,
      Math.round(100 * shrink / 50) * 50
    ];
  }

  if (market.includes("SENSEX")) {
    return [
      Math.round(500 * shrink / 100) * 100,
      Math.round(300 * shrink / 100) * 100,
      Math.round(100 * shrink / 100) * 100
    ];
  }

  if (market.includes("NATURAL") || market.includes("NG")) {
    return [
      Math.round(80 * shrink / 5) * 5,
      Math.round(50 * shrink / 5) * 5,
      Math.round(20 * shrink / 5) * 5
    ];
  }

  return [];
}

/* ===============================
   STRIKE GENERATOR (CE + PE BOTH)
================================ */

function generateStrikes(market, spot, expiry_days = 0) {
  const atm = roundToStep(market, spot);
  const gaps = getStrikeGapsByMarket(market, expiry_days);

  const ce = [];
  const pe = [];

  for (const g of gaps) {
    if (!g) continue;
    ce.push(atm + g);
    pe.push(atm - g);
  }

  return {
    atm,
    ce, // CALL strikes (3)
    pe  // PUT strikes  (3)
  };
}

/* ===============================
   TARGET + STOPLOSS
================================ */

function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;

  const stopLoss = entryLTP * 0.85;
  const target1  = entryLTP * 1.10;
  const target2  = entryLTP * 1.20;

  return {
    stopLoss: Number(stopLoss.toFixed(2)),
    target1:  Number(target1.toFixed(2)),
    target2:  Number(target2.toFixed(2))
  };
}

/* --- EXPIRY DETECTOR (FINAL – MARKET ACCURATE) --- */

function detectExpiryForSymbol(symbol, expiryDays = 0) {
  symbol = String(symbol || "").toUpperCase();

  /* 1️⃣ UI override (manual expiry_days) */
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

  const today = moment();

  /* ===============================
     MARKET-WISE EXPIRY RULES
  ================================ */

  // 🟢 NIFTY → Weekly Tuesday
  if (symbol.includes("NIFTY")) {
    let weekly = today.clone().day(2); // Tuesday
    if (weekly.isBefore(today, "day")) weekly.add(1, "week");

    // monthly = last Tuesday of month
    let monthly = today.clone().endOf("month");
    while (monthly.day() !== 2) monthly.subtract(1, "day");

    return {
      currentWeek: weekly.format("YYYY-MM-DD"),
      monthly: monthly.format("YYYY-MM-DD"),
      targetDate: weekly.toDate()
    };
  }

  // 🟢 SENSEX → Weekly Thursday
  if (symbol.includes("SENSEX")) {
    let weekly = today.clone().day(4); // Thursday
    if (weekly.isBefore(today, "day")) weekly.add(1, "week");

    // monthly = last Thursday of month
    let monthly = today.clone().endOf("month");
    while (monthly.day() !== 4) monthly.subtract(1, "day");

    return {
      currentWeek: weekly.format("YYYY-MM-DD"),
      monthly: monthly.format("YYYY-MM-DD"),
      targetDate: weekly.toDate()
    };
  }

  // 🟢 NATURAL GAS → Monthly only (MCX)
  if (symbol.includes("NATURAL")) {
    // MCX monthly expiry = last working day (simplified: last calendar day)
    let monthly = today.clone().endOf("month");

    return {
      currentWeek: null, // ❗ NG has no weekly
      monthly: monthly.format("YYYY-MM-DD"),
      targetDate: monthly.toDate()
    };
  }

  /* Fallback (safe) */
  let fallback = today.clone().add(7, "days");
  return {
    currentWeek: fallback.format("YYYY-MM-DD"),
    monthly: fallback.format("YYYY-MM-DD"),
    targetDate: fallback.toDate()
  };
}

/* --- EXPIRY PARSER (REQUIRED HELPER) --- */
function parseExpiryDate(v) {
  if (!v) return null;

  const s = String(v).trim();

  // Angel master commonly uses these formats
  const m = moment(
    s,
    [
      "YYYY-MM-DD",
      "DD-MM-YYYY",
      "YYYYMMDD",
      "DDMMMYYYY",
      "DD-MMM-YYYY",
      "YYYY-MM-DDTHH:mm:ss"
    ],
    true
  );

  if (m.isValid()) {
    return m.toDate();
  }

  // JS fallback (last resort)
  const d = new Date(s);
  return isFinite(d.getTime()) ? d : null;
}

/* ===============================
   FUTURES LTP (ANGEL DOC SAFE)
================================ */

async function fetchFuturesLTP(symbol) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;

    const tokenInfo = await resolveInstrumentToken(
      symbol,
      expiry,
      0,
      "FUT"
    );

    if (!tokenInfo?.token) return null;

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: session.access_token,
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB"
        },
        body: JSON.stringify({
          exchange: tokenInfo.instrument.exchange,
          tradingsymbol: tokenInfo.instrument.tradingsymbol,
          symboltoken: tokenInfo.token
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || 0);

    return ltp > 0 ? ltp : null;
  } catch (e) {
    console.log("fetchFuturesLTP ERR", e);
    return null;
  }
}

/* ===============================
   FUTURES vs SPOT DIFF
================================ */
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut || !isFinite(spotUsed)) return null;
    return Number(fut) - Number(spotUsed);
  } catch {
    return null;
  }
}

/* =========================================================
   OPTION LTP FETCHER — FINAL (ANGEL DOC COMPLIANT)
   RULE (AS PER ANGEL):
   - OPTIONS (CE / PE) → REST ONLY (getLtpData)
   - WS OPTION TICKS ARE UNRELIABLE → DO NOT DEPEND
========================================================= */

async function fetchOptionLTP(symbol, strike, type, expiry_days) {
  try {
    /* ---------- 1️⃣ EXPIRY ---------- */
    const expiryInfo = detectExpiryForSymbol(symbol, expiry_days);
    const expiry = expiryInfo?.currentWeek;
    if (!expiry) return null;

    /* ---------- 2️⃣ TOKEN RESOLVE ---------- */
    const tokenInfo = await resolveInstrumentToken(
      symbol,
      expiry,
      strike,
      type
    );

    if (!tokenInfo?.token || !tokenInfo.instrument) {
      console.log("❌ OPTION TOKEN NOT FOUND", { symbol, strike, type });
      return null;
    }

    const token = String(tokenInfo.token);
    const tradingsymbol =
      tokenInfo.instrument.tradingsymbol ||
      tokenInfo.instrument.tradingSymbol ||
      tokenInfo.instrument.symbol ||
      tokenInfo.instrument.name;

    if (!tradingsymbol) {
      console.log("❌ OPTION TRADINGSYMBOL MISSING", tokenInfo.instrument);
      return null;
    }

    /* ---------- 3️⃣ FAST CACHE (REST SNAPSHOT) ---------- */
    if (
      optionLTP[token] &&
      optionLTP[token].ltp > 0 &&
      Date.now() - optionLTP[token].time < 2000
    ) {
      return optionLTP[token].ltp;
    }

    /* ---------- 4️⃣ REST LTP (AUTHORITATIVE SOURCE) ---------- */
    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: `Bearer ${session.access_token}`,
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          exchange: "NFO",
          tradingsymbol,
          symboltoken: token,
          feedtype: "LTP" // 🔥 REQUIRED AS PER DOC
        })
      }
    );

    const j = await r.json().catch(() => null);
    const restLtp = Number(
      j?.data?.ltp ??
      j?.data?.lastPrice ??
      0
    );

    if (restLtp > 0) {
      optionLTP[token] = {
        ltp: restLtp,
        time: Date.now(),
        source: "REST"
      };

      console.log("✅ OPTION LTP (REST)", {
        symbol,
        strike,
        type,
        ltp: restLtp
      });

      return restLtp;
    }
    
    /* ---------- 6️⃣ LAST KNOWN (VERY SAFE) ---------- */
    if (optionLTP[token]?.ltp > 0) {
      return optionLTP[token].ltp;
    }

    return null;

  } catch (e) {
    console.log("❌ fetchOptionLTP ERROR", e);
    return null;
  }
}

  /* =========================================================
   RESOLVE INSTRUMENT TOKEN — ANGEL ONE (MASTER CORRECT)
========================================================= */

function normalizeAngelExpiry(exp) {
  if (!exp) return "";

  // Already Angel format → 20JAN2026
  if (/^\d{2}[A-Z]{3}\d{4}$/.test(exp)) return exp;

  // ISO → Angel
  const d = new Date(exp);
  if (isNaN(d)) return "";

  const DD = String(d.getDate()).padStart(2, "0");
  const MMM = ["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"][d.getMonth()];
  const YYYY = d.getFullYear();

  return `${DD}${MMM}${YYYY}`;
}

function normalizeStrike(raw) {
  const n = Number(raw);
  if (!n) return 0;

  // Angel master strike is usually *100
  if (n < 100000) return n * 100;
  return Math.round(n);
}

async function resolveInstrumentToken(
  symbol,
  expiry = "",
  strike = 0,
  side = "FUT"   // CE | PE | FUT | INDEX
) {
  try {
    const master = global.instrumentMaster;
    if (!Array.isArray(master) || !master.length) return null;

    const SYM = String(symbol).toUpperCase();
    const SIDE = String(side).toUpperCase();
    const WANT_STRIKE = normalizeStrike(strike);
    const WANT_EXPIRY = normalizeAngelExpiry(expiry);

    // ---------- BASE FILTER (symbol match) ----------
    let rows = master.filter(it =>
      it &&
      it.symbol &&
      it.symbol.toUpperCase().includes(SYM)
    );

    if (!rows.length) return null;

    /* ===============================
       OPTION (CE / PE)
    ================================ */
    if (SIDE === "CE" || SIDE === "PE") {
      let opts = rows.filter(it => {
        if (!it.instrumenttype?.includes("OPT")) return false;
        if (!it.symbol.endsWith(SIDE)) return false;

        const st = normalizeStrike(it.strike);
        return st === WANT_STRIKE;
      });

      if (!opts.length) {
        console.log("❌ OPTION NOT FOUND IN MASTER", {
          symbol: SYM,
          strike,
          side: SIDE,
          expiry
        });
        return null;
      }

      // expiry filter (if provided)
      if (WANT_EXPIRY) {
        opts = opts.filter(it => it.expiry === WANT_EXPIRY);
        if (!opts.length) {
          console.log("❌ EXPIRY NOT FOUND IN MASTER", {
            symbol: SYM,
            strike,
            side: SIDE,
            expiry: WANT_EXPIRY
          });
          return null;
        }
      }

      // nearest expiry safety sort
      opts.sort((a, b) => {
        const ea = new Date(a.expiry.slice(2) + " " + a.expiry.slice(0,2));
        const eb = new Date(b.expiry.slice(2) + " " + b.expiry.slice(0,2));
        return ea - eb;
      });

      const pick = opts[0];

      console.log("✅ OPTION TOKEN RESOLVED (MASTER)", {
        symbol: SYM,
        strike,
        side: SIDE,
        token: pick.token,
        tradingsymbol: pick.symbol,
        expiry: pick.expiry
      });
 
      return {
        token: String(pick.token),
        instrument: pick
      };
    }

    /* ===============================
       INDEX
    ================================ */
    if (SIDE === "INDEX") {
      const idx = rows.find(it =>
        it.instrumenttype === "INDEX" &&
        it.symbol === SYM
      );

      if (!idx) return null;

      return {
        token: String(idx.token),
        instrument: idx
      };
    }

    /* ===============================
       FUTURES
    ================================ */
    const futs = rows
      .filter(it => it.instrumenttype?.includes("FUT"))
      .map(it => ({
        it,
        diff: Math.abs(new Date(it.expiry) - Date.now())
      }))
      .sort((a, b) => a.diff - b.diff);

    if (!futs.length) return null;

    return {
      token: String(futs[0].it.token),
      instrument: futs[0].it
    };

  } catch (err) {
    console.error("❌ resolveInstrumentToken ERROR", err);
    return null;
  }
}

/* ===============================
   FINAL ENTRY GUARD
================================ */

async function finalEntryGuard({ symbol, trendObj, futDiff, getCandlesFn }) {
  return { allowed: true, reason: "LTP_TEST_MODE" };
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

/* ===============================
   MAIN ENTRY ENGINE (DOC SAFE)
================================ */

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
  /* 1️⃣ TREND */
  const trendObj = hybridTrendEngine({
    ema20,
    ema50,
    vwap,
    rsi,
    spot,
    lastSpot
  });

  if (trendObj.direction === "NEUTRAL") {
    trendObj.direction = "UP";
  }

  /* 2️⃣ FUTURES DIFF */
  const futDiff = await detectFuturesDiff(market, spot);

  /* 3️⃣ STRIKES (NEW STRUCTURE) */
  const strikes = generateStrikes(market, spot, expiry_days);
  const expiry = detectExpiryForSymbol(market, expiry_days).currentWeek;
/* 🔥 PRIORITIZE ATM FIRST (CLOSEST TO SPOT) */
strikes.ce.sort((a, b) => Math.abs(a - spot) - Math.abs(b - spot));
strikes.pe.sort((a, b) => Math.abs(a - spot) - Math.abs(b - spot));

  /* 🔒 EXPIRY SAFETY — ATM ONLY */
if (Number(expiry_days) <= 1) {
  strikes.ce = strikes.ce.slice(0, 1);
  strikes.pe = strikes.pe.slice(0, 1);

  console.log("⚠️ EXPIRY MODE: ATM ONLY", {
    ce: strikes.ce,
    pe: strikes.pe
  });
}
  
  /* 4️⃣ FORCE OPTION TOKEN RESOLUTION (CE + PE, ALL STRIKES) */
  for (const s of strikes.ce) {
    await resolveInstrumentToken(market, expiry, s, "CE");
  }
  for (const s of strikes.pe) {
    await resolveInstrumentToken(market, expiry, s, "PE");
  }

  /* 6️⃣ ENTRY GATE */
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

  /* 7️⃣ OPTION LTP (WS + REST HYBRID) */
    const cePrices = [];
for (const s of strikes.ce) {
  const ltp = await fetchOptionLTP(market, s, "CE", expiry_days);
  if (ltp && ltp > 5) cePrices.push(ltp);
}

  const pePrices = [];
for (const s of strikes.pe) {
  const ltp = await fetchOptionLTP(market, s, "PE", expiry_days);
  if (ltp && ltp > 5) pePrices.push(ltp);
}

  const takeCE = trendObj.direction === "UP";
const entryLTP = takeCE
  ? cePrices.find(p => p && p > 5)
  : pePrices.find(p => p && p > 5);

if (!entryLTP) {
  return {
    allowed: false,
    reason: "NO_VALID_OPTION_LTP",
    retryAfter: 2,
    trend: trendObj
  };
}
  /* 8️⃣ SL / TARGET */
  const { stopLoss, target1, target2 } = computeTargetsAndSL(entryLTP);

  /* 9️⃣ FINAL RESPONSE */
  return {
    allowed: true,
    direction: trendObj.direction,
    strikes,
    prices: {
      ce: cePrices,
      pe: pePrices
    },
    entryLTP,
    sl: stopLoss,
    target1,
    target2,
    trend: trendObj,
    futDiff
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
/* ===============================
   PART 6/6 — API ROUTES + SERVER
================================ */

/* ---------- SPOT API ---------- */
app.get("/api/spot", async (req, res) => {
  try {
    const market = String(req.query.market || "NIFTY").toUpperCase();

    /* 1️⃣ WS SPOT (INDEX) */
    if (market === "NIFTY") {
      const n = lastKnown.nifty;
      if (n?.spot && Date.now() - n.updatedAt < 5000) {
        return res.json({ success: true, source: "WS", spot: n.spot });
      }
    }

    if (market === "SENSEX") {
      const s = lastKnown.sensex;
      if (s?.spot && Date.now() - s.updatedAt < 5000) {
        return res.json({ success: true, source: "WS", spot: s.spot });
      }
    }

    /* 2️⃣ REST INDEX SPOT */
    if (market === "NIFTY" || market === "SENSEX") {
      const INDEX_MAP = {
        NIFTY: "NIFTY 50",
        SENSEX: "SENSEX"
      };

      const idx = await resolveInstrumentToken(
        INDEX_MAP[market],
        "",
        0,
        "INDEX"
      );

      if (!idx?.token) {
        return res.json({ success: false, error: "INDEX_TOKEN_NOT_FOUND" });
      }

      const r = await fetch(
        `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
        {
          method: "POST",
          headers: {
            "X-PrivateKey": SMART_API_KEY,
            Authorization: session.access_token,
            "Content-Type": "application/json",
            "X-UserType": "USER",
            "X-SourceID": "WEB"
          },
          body: JSON.stringify({
            exchange: idx.instrument.exchange,
            tradingsymbol: idx.instrument.tradingsymbol,
            symboltoken: idx.token
          })
        }
      );

      const j = await r.json().catch(() => null);
      const ltp = Number(j?.data?.ltp || 0);

      if (!ltp) {
        return res.json({ success: false, error: "SPOT_NOT_AVAILABLE" });
      }

      if (market === "NIFTY") {
        lastKnown.nifty = { spot: ltp, updatedAt: Date.now() };
      } else {
        lastKnown.sensex = { spot: ltp, updatedAt: Date.now() };
      }

      return res.json({ success: true, source: "REST", spot: ltp });
    }

    /* 3️⃣ NATURAL GAS (FUTURE AS SPOT) */
    if (market === "NATURALGAS" || market === "NATURAL GAS") {
      const fut = await fetchFuturesLTP("NATURALGAS");
      if (!fut) {
        return res.json({ success: false, error: "FUT_LTP_NOT_AVAILABLE" });
      }
      lastKnown.ng = { spot: fut, updatedAt: Date.now() };
      return res.json({ success: true, source: "FUTURE", spot: fut });
    }

    return res.json({ success: false, error: "INVALID_MARKET" });

  } catch (e) {
    return res.json({ success: false, error: "SPOT_EXCEPTION", detail: String(e) });
  }
});

/* ---------- TOKEN RESOLVE ---------- */
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

  } catch (e) {
    res.json({ success: false, error: "EXCEPTION", detail: String(e) });
  }
});

/* ---------- CALC API ---------- */
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

    let finalSpot = null;

    /* 1️⃣ MANUAL SPOT */
    if (spot != null && isFinite(Number(spot))) {
      finalSpot = Number(spot);
    }

    /* 2️⃣ WS SPOT */
    if (!finalSpot) {
      const lk =
        market === "NIFTY" ? lastKnown.nifty :
        market === "SENSEX" ? lastKnown.sensex :
        market.includes("NATURAL") ? lastKnown.ng :
        null;

      if (lk?.spot && Date.now() - lk.updatedAt < 5000) {
        finalSpot = lk.spot;
      }
    }

    /* 3️⃣ REST SPOT */
    if (!finalSpot) {
      const INDEX_MAP = {
        NIFTY: "NIFTY 50",
        SENSEX: "SENSEX"
      };
      const sym = INDEX_MAP[market] || market;

      const idx = await resolveInstrumentToken(sym, "", 0, "INDEX");
      if (idx?.token) {
        const r = await fetch(
          `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
          {
            method: "POST",
            headers: {
              "X-PrivateKey": SMART_API_KEY,
              Authorization: session.access_token,
              "Content-Type": "application/json",
              "X-UserType": "USER",
              "X-SourceID": "WEB"
            },
            body: JSON.stringify({
              exchange: idx.instrument.exchange,
              tradingsymbol: idx.instrument.tradingsymbol,
              symboltoken: idx.token
            })
          }
        );

        const j = await r.json().catch(() => null);
        finalSpot = Number(j?.data?.ltp || 0);
      }
    }

    if (!finalSpot) {
      return res.json({ success: false, error: "SPOT_RESOLUTION_FAILED" });
    }

    const entry = await computeEntry({
      market,
      spot: finalSpot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot: null
    });

    return res.json({ success: true, entry });

  } catch (err) {
    console.error("❌ COMPUTE ENTRY ERROR:", err);
    return res.json({
      success: false,
      error: "EXCEPTION_IN_CALC",
      detail: err?.message || String(err)
    });
  }
});

app.get("/debug/ltp/:token/:ts", async (req, res) => {
  const r = await fetch(
    `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
    {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        "Authorization": `Bearer ${session.access_token}`,
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        exchange: "NFO",
        tradingsymbol: req.params.ts,
        symboltoken: req.params.token
      })
    }
  );
  res.json(await r.json());
});

/* ---------- PING ---------- */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    ws: {
      connected: wsStatus.connected,
      subs: wsStatus.subscriptions,
      lastMsgAt: wsStatus.lastMsgAt
    }
  });
});

/* ---------- ROOT ---------- */
app.get("/", (req, res) => {
  res.send("Rahul Backend OK — Angel One WS LIVE 🚀");
});

/* ---------- SERVER ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
