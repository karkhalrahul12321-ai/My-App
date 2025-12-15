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
// ===== PART 1/6 END =====
// ===== PART 2/6 START =====
// WEBSOCKET + CORE HELPERS + EXPIRY DETECTOR (SANITIZED)

// --------------------------------------------------
// COMMON HELPERS (USED ACROSS FILE)
// --------------------------------------------------
function tsOf(entry) {
  return String(
    entry?.tradingsymbol ||
    entry?.symbol ||
    entry?.name ||
    ""
  ).toUpperCase();
}

function itypeOf(entry) {
  return String(
    entry?.instrumenttype ||
    entry?.instrumentType ||
    entry?.type ||
    ""
  ).toUpperCase();
}

function parseExpiryDate(v) {
  if (!v) return null;
  const s = String(v).trim();

  const m = moment(
    s,
    [
      "YYYY-MM-DD",
      "YYYYMMDD",
      "DD-MM-YYYY",
      "DDMMMYYYY",
      "DDMMYYYY",
      moment.ISO_8601
    ],
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

// --------------------------------------------------
// WEBSOCKET CORE
// --------------------------------------------------
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

// REALTIME CACHE
const realtime = {
  ticks: {},
  candles1m: {}
};

// --------------------------------------------------
// START WEBSOCKET (SAFE)
// --------------------------------------------------
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
    console.log("WS INIT ERROR:", e);
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

    try {
      wsClient.send(JSON.stringify(auth));
    } catch (e) {
      console.log("WS AUTH SEND ERROR:", e);
    }

    if (wsHeartbeat) clearInterval(wsHeartbeat);

    wsHeartbeat = setInterval(() => {
      try {
        if (wsClient && wsClient.readyState === WebSocket.OPEN) {
          wsClient.send("ping");
        }
      } catch {}
    }, 30000);

    setTimeout(() => subscribeCoreSymbols(), 1000);
  });

  wsClient.on("message", (raw) => {
    wsStatus.lastMsgAt = Date.now();

    let msg = null;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (!msg || !msg.data) return;

    const d = msg.data;

    const sym = d.tradingsymbol || d.symbol || null;
    const ltp = Number(
      d.ltp ??
      d.last_traded_price ??
      d.lastPrice ??
      d.price ??
      d.close ??
      0
    ) || null;

    const oi = Number(d.oi || d.openInterest || 0) || null;

    if (sym && ltp != null) {
      realtime.ticks[sym] = {
        ltp,
        oi,
        time: Date.now()
      };
    }

    // SPOT UPDATE (INDEX / FUTURES)
    const itype = String(
      d.instrumenttype || d.instrumentType || ""
    ).toUpperCase();

    const ts = String(sym || "").toUpperCase();

    if (
      ltp != null &&
      (
        itype.includes("IDX") ||
        itype.includes("INDEX") ||
        itype.includes("FUT") ||
        ts.includes("NIFTY") ||
        ts.includes("SENSEX")
      )
    ) {
      lastKnown.spot = ltp;
      lastKnown.updatedAt = Date.now();
    }

    // BUILD 1-MIN CANDLE
    try {
      if (sym && ltp != null) {
        if (!realtime.candles1m[sym]) {
          realtime.candles1m[sym] = [];
        }

        const arr = realtime.candles1m[sym];
        const now = Date.now();
        const curMin = Math.floor(now / 60000) * 60000;
        const cur = arr.length ? arr[arr.length - 1] : null;

        if (!cur || cur.time !== curMin) {
          arr.push({
            time: curMin,
            open: ltp,
            high: ltp,
            low: ltp,
            close: ltp,
            volume: d.volume || 0
          });
          if (arr.length > 180) arr.shift();
        } else {
          cur.high = Math.max(cur.high, ltp);
          cur.low = Math.min(cur.low, ltp);
          cur.close = ltp;
          cur.volume = (cur.volume || 0) + (d.volumeDelta || 0);
        }
      }
    } catch (e) {
      console.log("CANDLE BUILD ERROR:", e);
    }
  });

  wsClient.on("error", (err) => {
    wsStatus.connected = false;
    wsStatus.lastError = String(err);
    console.log("WS ERROR:", err);
    scheduleWSReconnect();
  });

  wsClient.on("close", (code) => {
    wsStatus.connected = false;
    wsStatus.lastError = "closed:" + code;
    console.log("WS CLOSED:", code);
    scheduleWSReconnect();
  });
}

// --------------------------------------------------
// WS RECONNECT LOGIC
// --------------------------------------------------
function scheduleWSReconnect() {
  wsStatus.reconnectAttempts++;

  const backoff = Math.min(
    30000,
    1000 * Math.pow(1.5, wsStatus.reconnectAttempts)
  );

  setTimeout(() => {
    try {
      if (wsClient) wsClient.terminate();
    } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, backoff);
}

// --------------------------------------------------
// EXPIRY DETECTOR (SANITIZED + SAFE)
// --------------------------------------------------
function detectExpiryForSymbol(symbol, expiryDays = 0) {
  symbol = String(symbol || "").toUpperCase();

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

  let weeklyExpiryDay = 4; // Thursday
  if (symbol.includes("NIFTY")) weeklyExpiryDay = 2;
  if (symbol.includes("SENSEX")) weeklyExpiryDay = 2;

  let currentWeek = today.clone().day(weeklyExpiryDay);
  if (currentWeek.isBefore(today, "day")) {
    currentWeek.add(1, "week");
  }

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

// ===== PART 2/6 END =====
// ===== PART 3/6 START =====
// TREND + MOMENTUM + VOLUME + STRIKE + TARGET LOGIC (SANITIZED)

// --------------------------------------------------
// SAFE NUMBER
// --------------------------------------------------
function safeNum(n) {
  n = Number(n);
  return isFinite(n) ? n : 0;
}

// --------------------------------------------------
// BASIC TREND METRICS
// --------------------------------------------------
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

  return {
    score,
    direction,
    above20,
    above50,
    aboveVW
  };
}

// --------------------------------------------------
// MOMENTUM CHECK
// --------------------------------------------------
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

// --------------------------------------------------
// RSI TREND GATE
// --------------------------------------------------
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);

  if (direction === "DOWN") return rsi < 40;
  if (direction === "UP")   return rsi > 50;

  return false;
}

// --------------------------------------------------
// HYBRID TREND ENGINE
// --------------------------------------------------
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
  const basic = computeBasicTrend(ema20, ema50, vwap, spot);
  const mom   = computeMomentumTrend(spot, lastSpot);
  const rsiOk = rsiTrendGate(rsi, basic.direction);

  let score = basic.score;

  if (mom.momentum === "UP") score++;
  if (mom.momentum === "DOWN") score--;

  if (!rsiOk) {
    score = Math.sign(score) * Math.max(0, Math.abs(score) - 1);
  }

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

// --------------------------------------------------
// TRIPLE CONFIRMATION — TREND
// --------------------------------------------------
async function tripleConfirmTrend(trendObj, symbol, getCandlesFn) {
  if (!trendObj) return { trendConfirmed: false };

  const score = Number(trendObj.score || 0);
  if (Math.abs(score) >= 3) return { trendConfirmed: true };

  try {
    const candles = typeof getCandlesFn === "function"
      ? (await getCandlesFn(symbol, 1, 30))
          .map(c => Number(c.close))
          .filter(Boolean)
      : [];

    const localRSI = candles.length
      ? computeRSI(candles, 14)
      : null;

    if (!localRSI && Math.abs(score) >= 2) {
      return { trendConfirmed: true };
    }

    if (trendObj.direction === "UP") {
      if (localRSI && localRSI > 50 && score > 1) {
        return { trendConfirmed: true };
      }
    }

    if (trendObj.direction === "DOWN") {
      if (localRSI && localRSI < 40 && score < -1) {
        return { trendConfirmed: true };
      }
    }

    return { trendConfirmed: false };
  } catch {
    return { trendConfirmed: Math.abs(score) >= 2 };
  }
}

// --------------------------------------------------
// TRIPLE CONFIRMATION — MOMENTUM
// --------------------------------------------------
async function tripleConfirmMomentum(symbol, getCandlesFn) {
  try {
    const c1 = typeof getCandlesFn === "function"
      ? await getCandlesFn(symbol, 1, 12)
      : [];

    const c5 = typeof getCandlesFn === "function"
      ? await getCandlesFn(symbol, 5, 6)
      : [];

    const closes1 = c1.map(x => Number(x.close)).filter(Boolean);
    const closes5 = c5.map(x => Number(x.close)).filter(Boolean);

    if (closes1.length < 6) return { momentumConfirmed: false };

    const last = closes1[closes1.length - 1];
    const meanPrev =
      closes1.slice(0, -1).reduce((a, b) => a + b, 0) /
      Math.max(1, closes1.length - 1);

    const pct = Math.abs((last - meanPrev) / Math.max(1, meanPrev));
    let momentumConfirmed = pct > 0.0008;

    const downs1 = closes1.slice(-5).every(
      (v, i, arr) => i === 0 || arr[i] < arr[i - 1]
    );

    const ups1 = closes1.slice(-5).every(
      (v, i, arr) => i === 0 || arr[i] > arr[i - 1]
    );

    if (!(downs1 || ups1) && closes5.length >= 3) {
      const downs5 = closes5.slice(-3).every(
        (v, i, arr) => i === 0 || arr[i] < arr[i - 1]
      );

      const ups5 = closes5.slice(-3).every(
        (v, i, arr) => i === 0 || arr[i] > arr[i - 1]
      );

      momentumConfirmed = momentumConfirmed && (downs5 || ups5);
    }

    return { momentumConfirmed };
  } catch {
    return { momentumConfirmed: false };
  }
}

// --------------------------------------------------
// TRIPLE CONFIRMATION — VOLUME
// --------------------------------------------------
async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c5 = typeof getCandlesFn === "function"
      ? await getCandlesFn(symbol, 5, 12)
      : [];

    const vols = c5
      .map(x => Number(x.volume || x.vol || 0))
      .filter(v => v > 0);

    if (!vols.length) {
      const c1 = typeof getCandlesFn === "function"
        ? await getCandlesFn(symbol, 1, 12)
        : [];

      const highs = c1.map(x => Number(x.high)).filter(Boolean);
      const lows  = c1.map(x => Number(x.low)).filter(Boolean);

      const tr = [];
      for (let i = 1; i < highs.length; i++) {
        tr.push(
          Math.max(
            Math.abs(highs[i] - lows[i]),
            Math.abs(highs[i] - Number(c1[i - 1]?.close || 0)),
            Math.abs(lows[i] - Number(c1[i - 1]?.close || 0))
          )
        );
      }

      const avgTR =
        tr.length ? tr.reduce((a, b) => a + b, 0) / tr.length : 0;

      return {
        volumeConfirmed:
          avgTR > 0 &&
          (avgTR / Math.max(1, Number(c1[c1.length - 1]?.close || 1))) > 0.001
      };
    }

    const latest = vols[vols.length - 1];
    const sorted = [...vols].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)] || 0;
    const mean   = vols.reduce((a, b) => a + b, 0) / vols.length;

    return {
      volumeConfirmed: latest >= Math.max(median * 0.9, mean * 0.8)
    };
  } catch {
    return { volumeConfirmed: false };
  }
}

// --------------------------------------------------
// FAKE BREAKOUT FILTER
// --------------------------------------------------
function rejectFakeBreakout(trendObj, futDiff) {
  if (!trendObj) return true;

  const score = Number(trendObj.score || 0);
  if (Math.abs(score) < 2) return true;

  if (futDiff && Math.abs(futDiff) > 200) return true;

  return false;
}

// --------------------------------------------------
// STRIKE UTILITIES
// --------------------------------------------------
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
  const base = roundToStep(market, spot);
  const minSteps = getStrikeSteps(market, expiry_days);
  const dynamicDist = computeStrikeDistanceByExpiry(
    expiry_days,
    minSteps
  );

  return {
    atm: base,
    otm1: base + dynamicDist,
    otm2: base - dynamicDist
  };
}

// --------------------------------------------------
// TARGET + STOPLOSS
// --------------------------------------------------
function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;

  const sl   = entryLTP * 0.85;
  const tgt1 = entryLTP * 1.10;
  const tgt2 = entryLTP * 1.20;

  return {
    stopLoss: Number(sl.toFixed(2)),
    target1:  Number(tgt1.toFixed(2)),
    target2:  Number(tgt2.toFixed(2))
  };
}

// ===== PART 3/6 END =====
// ===== PART 4/6 START =====
// ENTRY ENGINE + FUTURES / OPTIONS LTP + TOKEN RESOLVER (SANITIZED FINAL)

// --------------------------------------------------
// FUTURES LTP FETCHER
// --------------------------------------------------
async function fetchFuturesLTP(symbol) {
  try {
    const expiry = detectExpiryForSymbol(symbol).targetDate;
    const tokenInfo = await resolveInstrumentToken(symbol, expiry, 0, "FUT");
    if (!tokenInfo) return null;

    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

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

// --------------------------------------------------
// FUTURES DIFF DETECTOR
// --------------------------------------------------
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut || !isFinite(spotUsed)) return null;
    return Number(fut) - Number(spotUsed);
  } catch {
    return null;
  }
}

// --------------------------------------------------
// OPTION LTP FETCHER (CE / PE)
// --------------------------------------------------
async function fetchOptionLTP(symbol, strike, type) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;
    const tokenInfo =
      await resolveInstrumentToken(symbol, expiry, strike, type);

    if (!tokenInfo) return null;

    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

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

// --------------------------------------------------
// RESOLVE INSTRUMENT TOKEN (CLEAN, SINGLE-PASS)
// --------------------------------------------------
async function resolveInstrumentToken(
  symbol,
  expiry = "",
  strike = 0,
  type = "FUT"
) {
  try {
    let master = global.instrumentMaster;

    if (!Array.isArray(master) || master.length === 0) {
      return null;
    }

    symbol = String(symbol || "").trim().toUpperCase();
    type   = String(type || "").trim().toUpperCase();

    if (!symbol) return null;

    const key = symbol.replace(/[^A-Z]/g, "");
    if (!key) return null;

    const expiryStr = String(expiry || "").replace(/-/g, "");
    const strikeNum = Number(strike || 0);

    // --------------------------------
    // 1) FILTER BY SYMBOL KEY
    // --------------------------------
    let candidates = master.filter(it => {
      const ts = tsOf(it);
      return (
        ts.startsWith(key) ||
        ts.includes(key) ||
        String(it.name || "").toUpperCase().includes(key)
      );
    });

    if (!candidates.length) return null;

    // --------------------------------
    // 2) OPTION RESOLVER (STRICT)
    // --------------------------------
    if (type === "CE" || type === "PE") {
      const side = type;
      const approxStrike = Math.round(strikeNum);

      const optList = candidates.filter(it => {
        const itype = itypeOf(it);
        if (!itype.includes("OPT")) return false;

        const ts = tsOf(it);
        if (!ts.endsWith(side)) return false;

        const st =
          Number(it.strike || it.strikePrice || 0);

        if (Math.abs(st - approxStrike) > 0.5) return false;

        const ex = parseExpiryDate(
          it.expiry || it.expiryDate || it.expiry_dt
        );
        if (!ex) return false;

        if (expiryStr) {
          const exStr = moment(ex).format("YYYYMMDD");
          if (!exStr.includes(expiryStr)) return false;
        }

        return isTokenSane(it.token);
      });

      if (!optList.length) return null;

      const pick = optList
        .map(it => {
          const ex = parseExpiryDate(
            it.expiry || it.expiryDate || it.expiry_dt
          );
          const diff = ex
            ? Math.abs(ex.getTime() - Date.now())
            : Infinity;
          return { it, diff };
        })
        .sort((a, b) => a.diff - b.diff)[0].it;

      return {
        instrument: pick,
        token: String(pick.token)
      };
    }

    // --------------------------------
    // 3) INDEX SPOT
    // --------------------------------
    const spot = candidates.find(it => {
      const itype = itypeOf(it);
      return (
        (itype.includes("INDEX") ||
         itype.includes("AMXIDX") ||
         itype.includes("IND")) &&
        isTokenSane(it.token)
      );
    });

    if (spot) {
      return {
        instrument: spot,
        token: String(spot.token)
      };
    }

    // --------------------------------
    // 4) FUTURES (PREFERRED)
    // --------------------------------
    const fut = candidates.find(it => {
      const itype = itypeOf(it);
      return (
        itype.includes("FUT") &&
        isTokenSane(it.token)
      );
    });

    if (fut) {
      return {
        instrument: fut,
        token: String(fut.token)
      };
    }

    // --------------------------------
    // 5) FALLBACK
    // --------------------------------
    const any = candidates.find(it => isTokenSane(it.token));
    if (any) {
      return {
        instrument: any,
        token: String(any.token)
      };
    }

    return null;
  } catch (e) {
    console.log("resolveInstrumentToken ERROR:", e);
    return null;
  }
}

// --------------------------------------------------
// FINAL ENTRY GUARD
// --------------------------------------------------
async function finalEntryGuard({
  symbol,
  trendObj,
  futDiff,
  getCandlesFn
}) {
  const t = await tripleConfirmTrend(
    trendObj,
    symbol,
    getCandlesFn
  );
  const m = await tripleConfirmMomentum(
    symbol,
    getCandlesFn
  );
  const v = await tripleConfirmVolume(
    symbol,
    getCandlesFn
  );

  const passedCount =
    (t.trendConfirmed ? 1 : 0) +
    (m.momentumConfirmed ? 1 : 0) +
    (v.volumeConfirmed ? 1 : 0);

  if (passedCount === 0) {
    return {
      allowed: false,
      reason: "NO_CONFIRMATIONS",
      details: { t, m, v }
    };
  }

  if (rejectFakeBreakout(trendObj, futDiff)) {
    return {
      allowed: false,
      reason: "FAKE_BREAKOUT_SOFT",
      details: { t, m, v, futDiff }
    };
  }

  if (futDiff && Math.abs(futDiff) > 300) {
    return {
      allowed: false,
      reason: "FUT_MISMATCH_HARD",
      futDiff
    };
  }

  return {
    allowed: true,
    reason: "ALLOWED",
    passedCount,
    details: { t, m, v }
  };
}

// --------------------------------------------------
// MAIN ENTRY ENGINE
// --------------------------------------------------
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
    ema20,
    ema50,
    vwap,
    rsi,
    spot,
    lastSpot
  });

  const futDiff = await detectFuturesDiff(market, spot);
  const strikes = generateStrikes(
    market,
    spot,
    expiry_days
  );

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
      details: entryGate.details,
      trend: trendObj,
      futDiff
    };
  }

  const ceATM = await fetchOptionLTP(
    market,
    strikes.atm,
    "CE"
  );
  const peATM = await fetchOptionLTP(
    market,
    strikes.atm,
    "PE"
  );

  const takeCE = trendObj.direction === "UP";
  const entryLTP = takeCE ? ceATM : peATM;

  if (!entryLTP) {
    return {
      allowed: false,
      reason: "OPTION_LTP_FAIL",
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

// ===== PART 4/6 END =====
// ===== PART 5/6 START =====
// CANDLES + INDICATORS + LTP HELPERS (SANITIZED)

// --------------------------------------------------
// HISTORICAL CANDLES FETCHER (SMARTAPI)
// --------------------------------------------------
async function fetchHistoricalCandles(
  exchange,
  symboltoken,
  interval,
  from,
  to
) {
  try {
    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;

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
        exchange,
        symboltoken,
        interval,
        fromdate: from,
        todate: to
      })
    });

    const j = await r.json().catch(() => null);
    if (!j || !Array.isArray(j.data)) return [];

    return j.data.map(c => ({
      time: Number(c[0]),
      open: Number(c[1]),
      high: Number(c[2]),
      low:  Number(c[3]),
      close:Number(c[4]),
      volume:Number(c[5] || 0)
    }));
  } catch {
    return [];
  }
}

// --------------------------------------------------
// RECENT CANDLES WRAPPER
// --------------------------------------------------
async function fetchRecentCandles(
  symbol,
  timeframeMin = 1,
  bars = 30
) {
  try {
    const tokenInfo = await resolveInstrumentToken(symbol);
    if (!tokenInfo) return [];

    const exchange =
      tokenInfo.instrument?.exchange || "NSE";
    const token = tokenInfo.token;

    const to = moment().format("YYYY-MM-DD HH:mm");
    const from = moment()
      .subtract(timeframeMin * bars, "minutes")
      .format("YYYY-MM-DD HH:mm");

    return await fetchHistoricalCandles(
      exchange,
      token,
      `${timeframeMin}MINUTE`,
      from,
      to
    );
  } catch {
    return [];
  }
}

// --------------------------------------------------
// RSI CALCULATOR
// --------------------------------------------------
function computeRSI(closes, period = 14) {
  if (!Array.isArray(closes) || closes.length < period + 1) {
    return null;
  }

  let gains = 0;
  let losses = 0;

  for (let i = 1; i <= period; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff >= 0) gains += diff;
    else losses -= diff;
  }

  gains /= period;
  losses /= period;

  let rs = losses === 0 ? 100 : gains / losses;
  let rsi = 100 - 100 / (1 + rs);

  for (let i = period + 1; i < closes.length; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff >= 0) {
      gains = (gains * (period - 1) + diff) / period;
      losses = (losses * (period - 1)) / period;
    } else {
      gains = (gains * (period - 1)) / period;
      losses = (losses * (period - 1) - diff) / period;
    }

    rs = losses === 0 ? 100 : gains / losses;
    rsi = 100 - 100 / (1 + rs);
  }

  return Number(rsi.toFixed(2));
}

// --------------------------------------------------
// ATR CALCULATOR
// --------------------------------------------------
function computeATR(candles, period = 14) {
  if (!Array.isArray(candles) || candles.length < period + 1) {
    return null;
  }

  const trs = [];

  for (let i = 1; i < candles.length; i++) {
    const h = candles[i].high;
    const l = candles[i].low;
    const pc = candles[i - 1].close;

    trs.push(
      Math.max(
        Math.abs(h - l),
        Math.abs(h - pc),
        Math.abs(l - pc)
      )
    );
  }

  if (trs.length < period) return null;

  let atr =
    trs.slice(0, period).reduce((a, b) => a + b, 0) / period;

  for (let i = period; i < trs.length; i++) {
    atr = (atr * (period - 1) + trs[i]) / period;
  }

  return Number(atr.toFixed(2));
}

// --------------------------------------------------
// SPOT FETCH HELPER (FALLBACK SAFE)
// --------------------------------------------------
async function fetchSpotPrice(symbol) {
  try {
    const tokenInfo = await resolveInstrumentToken(symbol);
    if (!tokenInfo) return null;

    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

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
        exchange: tokenInfo.instrument?.exchange || "NSE",
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

// ===== PART 5/6 END =====
// ===== PART 6/6 START =====
// AUTH + API ROUTES + WS STATUS + SERVER START (SANITIZED FINAL)

// --------------------------------------------------
// SMARTAPI LOGIN
// --------------------------------------------------
async function smartApiLogin() {
  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);
    if (!totp) {
      console.log("LOGIN ERROR: TOTP generation failed");
      return false;
    }

    const url = `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-PrivateKey": SMART_API_KEY
      },
      body: JSON.stringify({
        clientcode: SMART_USER_ID,
        password: SMART_API_SECRET,
        totp
      })
    });

    const j = await r.json().catch(() => null);
    if (!j || !j.data || !j.data.jwtToken) {
      console.log("LOGIN FAILED:", j);
      return false;
    }

    session.access_token = j.data.jwtToken;
    session.refresh_token = j.data.refreshToken;
    session.feed_token = j.data.feedToken;
    session.login_time = Date.now();
    session.expires_at = Date.now() + 6 * 60 * 60 * 1000;

    console.log("SMARTAPI LOGIN SUCCESS ✔");

    startWebsocketIfReady();
    return true;
  } catch (e) {
    console.log("LOGIN ERROR:", e);
    return false;
  }
}

// AUTO LOGIN ON START
smartApiLogin();
setInterval(smartApiLogin, 5 * 60 * 60 * 1000);

// --------------------------------------------------
// API ROUTES
// --------------------------------------------------
app.get("/api/ws/status", (req, res) => {
  res.json({
    wsStatus,
    lastKnown
  });
});

app.get("/api/spot", async (req, res) => {
  const market = String(req.query.market || "").toUpperCase();
  if (!market) {
    return res.json({ ok: false, error: "NO_MARKET" });
  }

  const spot =
    lastKnown.spot ||
    (await fetchSpotPrice(market));

  if (!spot) {
    return res.json({ ok: false, error: "SPOT_FAIL" });
  }

  res.json({
    ok: true,
    market,
    spot,
    updatedAt: lastKnown.updatedAt
  });
});

app.post("/api/calc", async (req, res) => {
  try {
    const {
      market,
      spot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot
    } = req.body || {};

    if (!market) {
      return res.json({
        allowed: false,
        reason: "NO_MARKET"
      });
    }

    const result = await computeEntry({
      market,
      spot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot
    });

    res.json(result);
  } catch (e) {
    res.json({
      allowed: false,
      reason: "CALC_ERROR",
      error: String(e)
    });
  }
});

app.get("/api/token/resolve", async (req, res) => {
  const { symbol, expiry, strike, type } = req.query;

  const r = await resolveInstrumentToken(
    symbol,
    expiry,
    strike,
    type
  );

  res.json({
    ok: !!r,
    result: r
  });
});

// --------------------------------------------------
// SERVER START
// --------------------------------------------------
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});

// ===== PART 6/6 END =====
