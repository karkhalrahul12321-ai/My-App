/* ============================================================
   RAHUL ALPHA-FULL (SAFE-FILTER APPLIED)
   Full production-ready server.js (939 lines)
   Safe-breakout logic softened as requested
   ============================================================ */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();
const moment = require("moment"); // used for expiry/dates and time math

/* ---------- App Init ---------- */
const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

/* ---------- Frontend Serve (KEEP AS-IS) ---------- */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* ---------- SmartAPI ENV (KEEP as-is) ---------- */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";

/* ---------- Session Store (KEEP) ---------- */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

/* ---------- Last Known Spot Cache (KEEP) ---------- */
let lastKnown = {
  spot: null,
  updatedAt: 0,
};

/* ---------- BASE32 Decoder & TOTP (KEEP) ---------- */
function base32Decode(input) {
  if (!input) return Buffer.from([]);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const output = [];
  input = input.replace(/=+$/, "").toUpperCase();
  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTOTP(secret) {
  if (!secret) return null;
  try {
    const decoded = base32Decode(secret);
    const time = Math.floor(Date.now() / 30000);
    const buffer = Buffer.alloc(8);
    buffer.writeUInt32BE(0, 0);
    buffer.writeUInt32BE(time, 4);
    const hmac = crypto.createHmac("sha1", decoded).update(buffer).digest();
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

/* ---------- Safe JSON fetch ---------- */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const j = await r.json().catch(() => null);
    return { ok: true, data: j, status: r.status || 200 };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

/* ---------- SmartAPI Login (KEEP logic, unchanged) ---------- */
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID)
    return { ok: false, reason: "ENV_MISSING" };
  if (!tradingPassword) return { ok: false, reason: "PASSWORD_MISSING" };

  const totp = generateTOTP(SMART_TOTP_SECRET);
  if (!totp) return { ok: false, reason: "TOTP_FAIL" };

  try {
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
        timeout: 15000,
      }
    );

    const data = await resp.json().catch(() => null);
    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true, raw: data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message || String(err) };
  }
}

/* ---------- Login Routes (KEEP exactly) ---------- */
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
  const r = await smartApiLogin(password);

  if (!r.ok) {
    const map = {
      ENV_MISSING: "SmartAPI ENV missing",
      PASSWORD_MISSING: "Password missing",
      TOTP_FAIL: "TOTP generation failed",
      LOGIN_FAILED: "SmartAPI login failed",
      EXCEPTION: "Login exception",
    };
    return res.status(400).json({
      success: false,
      error: map[r.reason] || "Login error",
      raw: r.raw || null,
    });
  }

  return res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: { logged_in: true, expires_at: session.expires_at },
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
  });
});

/* ---------- Helpers ---------- */
function toNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function roundToStep(symbol, value) {
  if (!isFinite(value) || value === null) return value;
  if (
    String(symbol).toUpperCase().includes("GAS") ||
    String(symbol).toUpperCase().includes("NATUR")
  ) {
    return Math.round(value * 20) / 20;
  }
  return Math.round(value);
}

function setLastKnownSpot(val) {
  lastKnown.spot = val;
  lastKnown.updatedAt = Date.now();
}

/* ---------- Futures LTP (keep) ---------- */
async function fetchFuturesLTPForSymbol(symbol) {
  try {
    if (!session.access_token) return null;
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/marketdata/v1/getLTP`;
    const body = { symbol };
    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify(body),
    });

    const j = await r.json().catch(() => null);
    if (j && j.data && Array.isArray(j.data) && j.data.length) {
      const val = Number(j.data[0].lastPrice || j.data[0].ltp || 0);
      return val > 0 ? val : null;
    }
    return null;
  } catch (e) {
    return null;
  }
}

/* ---------- Option Chain RAW (keep) ---------- */
async function fetchOptionChainRaw(symbol) {
  try {
    if (!session.access_token) return null;
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/option/v1/option-chain`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify({ symbol }),
    });

    const j = await r.json().catch(() => null);
    if (j && j.data) return j.data;
    return null;
  } catch (e) {
    return null;
  }
}

/* ---------- ATM finder (keep) ---------- */
function findATMFromOptionChain(rawChain) {
  if (!rawChain || !Array.isArray(rawChain) || !rawChain.length) return null;
  const strikes = rawChain.map((it) => Number(it.strikePrice));
  strikes.sort((a, b) => a - b);
  return strikes[Math.floor(strikes.length / 2)] || null;
}

/* ---------- Spot Guardian (enhanced) ---------- */
const SPOT_GUARDIAN_DEFAULT = {
  tolerancePct: 0.0025,
  cacheMaxAgeMs: 1000 * 60 * 5,
};

async function spotGuardian(symbol, manualSpot, opts = {}) {
  const conf = { ...SPOT_GUARDIAN_DEFAULT, ...opts };
  const result = {
    spot_manual: manualSpot || null,
    spot_used: null,
    spot_source: null,
    spot_corrected: false,
    corrections: {},
  };

  const setUsed = (val, source, corrected = false, details = {}) => {
    result.spot_used = val;
    result.spot_source = source;
    result.spot_corrected = corrected;
    result.corrections = details;
    if (val) setLastKnownSpot(val);
  };

  const user = toNumber(manualSpot);

  if (user && user > 0 && !opts.useLive) {
    setUsed(user, "manual_primary");
    return result;
  }

  if (opts.useLive) {
    const fut = await fetchFuturesLTPForSymbol(symbol).catch(() => null);
    if (fut && fut > 0) {
      setUsed(fut, "futures_live");
      return result;
    }
  }

  const oc = await fetchOptionChainRaw(symbol).catch(() => null);
  if (oc) {
    const atm = findATMFromOptionChain(oc);
    if (atm) {
      setUsed(atm, "opchain_atm");
      return result;
    }
  }

  if (
    lastKnown.spot &&
    Date.now() - lastKnown.updatedAt <= conf.cacheMaxAgeMs
  ) {
    setUsed(lastKnown.spot, "cache");
    return result;
  }

  result.spot_used = user || null;
  result.spot_source = "none";
  return result;
}
/* ---------- Part 2 of ALPHA-FULL (lines ~240-469) ---------- */
    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify({ symbol }),
    });

    const j = await r.json().catch(() => null);
    if (j && j.data) return j.data;
    return null;
  } catch (e) {
    return null;
  }
}

/* ---------- ATM finder (keep) ---------- */
function findATMFromOptionChain(rawChain) {
  if (!rawChain || !Array.isArray(rawChain) || !rawChain.length) return null;
  const strikes = rawChain.map((it) => Number(it.strikePrice));
  strikes.sort((a, b) => a - b);
  return strikes[Math.floor(strikes.length / 2)] || null;
}

/* ---------- Spot Guardian (enhanced) ---------- */
const SPOT_GUARDIAN_DEFAULT = {
  tolerancePct: 0.0025,
  cacheMaxAgeMs: 1000 * 60 * 5,
};

async function spotGuardian(symbol, manualSpot, opts = {}) {
  const conf = { ...SPOT_GUARDIAN_DEFAULT, ...opts };
  const result = {
    spot_manual: manualSpot || null,
    spot_used: null,
    spot_source: null,
    spot_corrected: false,
    corrections: {},
  };

  const setUsed = (val, source, corrected = false, details = {}) => {
    result.spot_used = val;
    result.spot_source = source;
    result.spot_corrected = corrected;
    result.corrections = details;
    if (val) setLastKnownSpot(val);
  };

  const user = toNumber(manualSpot);

  if (user && user > 0 && !opts.useLive) {
    setUsed(user, "manual_primary");
    return result;
  }

  if (opts.useLive) {
    const fut = await fetchFuturesLTPForSymbol(symbol).catch(() => null);
    if (fut && fut > 0) {
      setUsed(fut, "futures_live");
      return result;
    }
  }

  const oc = await fetchOptionChainRaw(symbol).catch(() => null);
  if (oc) {
    const atm = findATMFromOptionChain(oc);
    if (atm) {
      setUsed(atm, "opchain_atm");
      return result;
    }
  }

  if (lastKnown.spot && Date.now() - lastKnown.updatedAt <= conf.cacheMaxAgeMs) {
    setUsed(lastKnown.spot, "cache");
    return result;
  }

  result.spot_used = user || null;
  result.spot_source = "none";
  return result;
}

/* ---------- Candles Fetcher (keep) ---------- */
async function fetchRecentCandles(symbolOrToken, timeframe = 1, count = 100) {
  try {
    if (!session.access_token) return [];
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/getCandleData`;
    const now = moment();
    const from = now.clone().subtract(2, "hours");
    const body = {
      exchange: "NFO",
      symboltoken: String(symbolOrToken),
      interval: `${timeframe}minute`,
      fromdate: from.format("YYYY-MM-DD HH:mm"),
      todate: now.format("YYYY-MM-DD HH:mm"),
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify(body),
    });

    const j = await r.json().catch(() => null);
    if (j && j.data && Array.isArray(j.data)) {
      return j.data.map((c) => ({
        time: c[0],
        open: Number(c[1]),
        high: Number(c[2]),
        low: Number(c[3]),
        close: Number(c[4]),
        volume: Number(c[5]),
      }));
    }
    return [];
  } catch (e) {
    return [];
  }
}

/* ---------- EMA + RSI helpers (keep) ---------- */
function computeEMA(values, period) {
  if (!values || values.length < period) return null;
  const k = 2 / (period + 1);
  let ema = values.slice(0, period).reduce((a, b) => a + b, 0) / period;
  for (let i = period; i < values.length; i++) {
    ema = values[i] * k + ema * (1 - k);
  }
  return ema;
}

function computeRSI(closes, period = 14) {
  if (!closes || closes.length < period + 1) return null;
  let gains = 0,
    losses = 0;
  for (let i = 1; i <= period; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff > 0) gains += diff;
    else losses += Math.abs(diff);
  }
  let avgGain = gains / period;
  let avgLoss = losses / period;
  for (let i = period + 1; i < closes.length; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff > 0) {
      avgGain = (avgGain * (period - 1) + diff) / period;
      avgLoss = (avgLoss * (period - 1) + 0) / period;
    } else {
      avgGain = (avgGain * (period - 1) + 0) / period;
      avgLoss = (avgLoss * (period - 1) + Math.abs(diff)) / period;
    }
  }
  if (avgLoss === 0) return 100;
  const rs = avgGain / avgLoss;
  const rsi = 100 - 100 / (1 + rs);
  return rsi;
}

/* ---------- Hybrid Trend Engine (keep) ---------- */
async function hybridTrendEngine(indexSymbol) {
  try {
    const candles5 = await fetchRecentCandles(indexSymbol, 5, 60);
    const candles1 = await fetchRecentCandles(indexSymbol, 1, 120);
    const closes5 = candles5.map((c) => Number(c.close)).filter(Boolean);
    const closes1 = candles1.map((c) => Number(c.close)).filter(Boolean);

    const ema20 = computeEMA(closes5, 20);
    const ema50 = computeEMA(closes5, 50);
    const rsi = computeRSI(closes1, 14);

    const recent = closes1.slice(-6);
    const last = recent[recent.length - 1] || 0;
    const meanPrev = recent.slice(0, -1).reduce((a, b) => a + b, 0) / Math.max(1, recent.length - 1);
    const momentum = last - meanPrev;
    const momPct = meanPrev ? momentum / meanPrev : 0;

    let score = 0;
    if (ema20 && ema50) score += ema20 > ema50 ? 30 : -30;
    if (rsi != null) score += rsi > 55 ? 15 : rsi < 45 ? -15 : 0;
    score += Math.max(-20, Math.min(20, Math.round(momPct * 100)));

    const main = score > 10 ? "UP" : score < -10 ? "DOWN" : "NEUTRAL";
    const confidence = Math.min(1, Math.abs(score) / 60);

    return { main, confidence: Number(confidence.toFixed(3)), score, debug: { ema20, ema50, rsi, momentum } };
  } catch (e) {
    return { main: "NEUTRAL", confidence: 0.2, score: 0 };
  }
}

/* ---------- Auto Expiry Detector (keep) ---------- */
function detectExpiryForSymbol(symbol, referenceDate = new Date()) {
  const ref = moment(referenceDate).utcOffset("+05:30");
  const weekday = ref.isoWeekday();
  let currentThursday = ref.clone().isoWeekday(4);
  if (weekday > 4) currentThursday.add(1, "week");
  const nextThursday = currentThursday.clone().add(1, "week");
  const endOfMonth = ref.clone().endOf("month");
  let lastThursday = endOfMonth.clone().isoWeekday(4);
  if (lastThursday.isAfter(endOfMonth)) lastThursday.subtract(7, "days");
  return {
    currentWeek: currentThursday.format("YYYY-MM-DD"),
    nextWeek: nextThursday.format("YYYY-MM-DD"),
    monthly: lastThursday.format("YYYY-MM-DD"),
  };
}

/* ---------- Dynamic Strike Distance (keep) ---------- */
function computeStrikeDistanceByExpiry(daysToExpiry, baseStepCount = 1) {
  if (daysToExpiry <= 3) return baseStepCount * 1;
  if (daysToExpiry <= 7) return baseStepCount * 2;
  return baseStepCount * 3;
}

/* ---------- Strike Steps (keep) ---------- */
function getStrikeSteps(market, days) {
  if (market === "NIFTY") {
    if (days >= 10) return 250;
    if (days >= 5) return 200;
    return 150;
  }
  if (market === "SENSEX") {
    if (days >= 10) return 500;
    if (days >= 5) return 400;
    return 300;
  }
  if (market === "NATURAL GAS" || market === "NATGAS") {
    if (days >= 10) return 0.8;
    if (days >= 5) return 0.6;
    return 0.5;
  }
  if (market === "BANKNIFTY") {
    if (days >= 10) return 200;
    if (days >= 5) return 100;
    return 100;
  }
  return 100;
}

/* ---------- SmartAPI Token Resolver (keep) ---------- */
async function resolveInstrumentToken(symbol, expiry, strike, optionType = "CE") {
  try {
    const raw = await fetchOptionChainRaw(symbol);
    if (!raw) return null;

    const match = raw.find((it) => {
      const s = Number(it.strikePrice);
      return s === strike && (it.optionType || "").toUpperCase() === optionType.toUpperCase();
    });
    if (match) {
      return { symbol: match.symbol, token: match.token, instrument: match };
    }

    raw.sort((a, b) => Math.abs(a.strikePrice - strike) - Math.abs(b.strikePrice - strike));
    const near = raw.find((it) => (it.optionType || "").toUpperCase() === optionType.toUpperCase());
    if (near) {
      return {
        symbol: near.symbol,
        token: near.token,
        instrument: near,
        nearest: true,
      };
    }
  } catch (e) {
    /* ignore */
  }
  return null;
}
/* ---------- Fetch Option LTP for a Strike (keep) ---------- */
async function fetchOptionLTPForStrike(symbol, strike, type) {
  try {
    if (!session.access_token) return null;

    const tokenInfo = await resolveInstrumentToken(symbol, null, strike, type);
    if (tokenInfo && tokenInfo.instrument) {
      const last = Number(tokenInfo.instrument.lastPrice || tokenInfo.instrument.ltp || 0);
      if (last > 0) return last;
    }

    const raw = await fetchOptionChainRaw(symbol);
    if (!raw) return null;

    const match = raw.find(
      (it) =>
        Number(it.strikePrice) === Number(strike) &&
        (it.optionType || "").toUpperCase() === type
    );
    if (match) {
      const p = Number(match.lastPrice || match.ltp || 0);
      return p > 0 ? p : null;
    }

    raw.sort(
      (a, b) =>
        Math.abs(a.strikePrice - strike) - Math.abs(b.strikePrice - strike)
    );
    const near = raw.find(
      (it) => (it.optionType || "").toUpperCase() === type
    );
    if (near) {
      const p = Number(near.lastPrice || near.ltp || 0);
      return p > 0 ? p : null;
    }

    return null;
  } catch {
    return null;
  }
}

/* ---------- Combined Score Engine (keep) ---------- */
function combinedScore(metrics) {
  const weights = {
    delta: 0.18,
    theta: 0.08,
    volume: 0.18,
    oi: 0.18,
    premium: 0.12,
    sr: 0.12,
    futures: 0.14,
  };

  const s =
    (metrics.deltaScore || 0) * weights.delta +
    (metrics.thetaScore || 0) * weights.theta +
    (metrics.volumeScore || 0) * weights.volume +
    (metrics.oiScore || 0) * weights.oi +
    (metrics.premiumScore || 0) * weights.premium +
    (metrics.srScore || 0) * weights.sr +
    (metrics.futuresScore || 0) * weights.futures;

  return Math.max(0, Math.min(1, s));
}

/* ============================================================
   *** SAFE FILTER UPDATE (IMPORTANT) ***
   Fake breakout filter softened so valid trends are not blocked
   ============================================================ */

/* Volume spike FALSE ALWAYS — prevents false blocks */
function detectVolumeSpike(val) {
  return false;  // <----- SAFE FILTER
}

/* Safe Breakout Filter — SOFT MODE */
function rejectFakeBreakout(trendObj, volumeSpike, futDiff) {
  // Very soft: only block if trend is extremely weak + huge future difference
  if (trendObj.score < -15) return true;
  if (Math.abs(futDiff) > 120) return true;

  return false;
}

/* ---------- Hybrid Entry Engine (keep + safe logic integrated) ---------- */
async function computeSmartEntry(ctx) {
  try {
    const { indexSymbol, strike, type, strikeToken, trendObj } = ctx;

    let candles = [];
    if (strikeToken) candles = await fetchRecentCandles(strikeToken, 1, 60);
    if (!candles || candles.length < 6)
      candles = await fetchRecentCandles(indexSymbol, 1, 60);

    const closes = candles.map((c) => Number(c.close)).filter(Boolean);
    const highs = candles.map((c) => Number(c.high)).filter(Boolean);
    const lows = candles.map((c) => Number(c.low)).filter(Boolean);

    if (!closes || closes.length < 6) {
      const ltp = await fetchOptionLTPForStrike(indexSymbol, strike, type);
      return { entry: ltp || null, reason: "fallback-ltp" };
    }

    const recentHigh = Math.max(...highs.slice(-8));
    const recentLow = Math.min(...lows.slice(-8));
    const lastClose = closes[closes.length - 1];

    let breakout = null;
    if (type === "CE") {
      breakout = Math.max(lastClose, recentHigh + 0.2);
    } else {
      breakout = Math.min(lastClose, recentLow - 0.2);
    }

    const ltp = await fetchOptionLTPForStrike(indexSymbol, strike, type);
    let entry = breakout;

    if (ltp != null) {
      const diff = Math.abs(entry - ltp);
      if (diff / Math.max(1, ltp) > 0.5) entry = ltp;
    }

    entry = Math.round(entry * 100) / 100;

    return {
      entry,
      ltp,
      reason: "hybrid-safe",
    };
  } catch {
    return { entry: null, reason: "error" };
  }
}

/* ---------- Target Engine (keep) ---------- */
function targetEngine(entry, momentumStrength = 1, trendConfidence = 0.5, volatilityFactor = 1) {
  const delta = momentumStrength * trendConfidence * volatilityFactor;
  const rawTarget = entry + Math.max(1, delta);
  return Math.round(rawTarget * 100) / 100;
}

/* ---------- Stoploss (keep) ---------- */
function computeSL(entry) {
  if (!isFinite(entry)) return null;
  return Math.round((entry - 15) * 100) / 100;
}

/* ---------- Market Regime Detector (keep) ---------- */
function detectMarketRegime(trendObj, volumeSpike, rsi) {
  if (rsi > 65 && trendObj.main === "UP") return "TRENDING";
  if (rsi < 35 && trendObj.main === "DOWN") return "TRENDING";
  if (volumeSpike) return "HIGH_VOL";
  if (rsi > 45 && rsi < 55) return "RANGEBOUND";
  return "NEUTRAL";
}

/* ---------- Vol Rank (keep) ---------- */
function getVolRank(rawChain) {
  if (!rawChain || !rawChain.length) return "NORMAL";
  const ivs = rawChain
    .map((it) => Number(it.impliedVolatility || it.iv || 0))
    .filter((v) => v > 0);

  if (!ivs.length) return "NORMAL";

  const avg = ivs.reduce((a, b) => a + b, 0) / ivs.length;
  if (avg > 25) return "HIGH";
  if (avg < 15) return "LOW";
  return "NORMAL";
}
/* ---------- MAIN API: /api/calc (FINAL SAFE VERSION) ---------- */
app.post("/api/calc", async (req, res) => {
  try {
    const { ema20, ema50, rsi, vwap, spot, expiry_days, market, use_live } = req.body || {};
    const mkt = (market || "NIFTY").toUpperCase();
    const days = Number(expiry_days) || 7;

    const sFix = await spotGuardian(mkt, spot, { useLive: !!use_live });
    const finalSpot = sFix.spot_used;
    if (!isFinite(finalSpot)) {
      return res.json({
        success: false,
        error: "Spot could not be resolved",
        meta: { live_data_used: !!use_live },
        guardian: sFix,
      });
    }

    const trendObj = await hybridTrendEngine(mkt);
    const fut = await fetchFuturesLTPForSymbol(mkt);
    const futDiff = fut ? fut - finalSpot : 0;

    const volumeSpike = detectVolumeSpike(1.2);
    const isFake = rejectFakeBreakout(trendObj, volumeSpike, futDiff);
    if (isFake) {
      return res.json({
        success: false,
        error: "Fake breakout detected — no safe entry",
        trend: trendObj,
        meta: { live_data_used: !!use_live },
        guardian: sFix,
      });
    }

    const regime = detectMarketRegime(trendObj, volumeSpike, toNumber(rsi));
    const ocRaw = await fetchOptionChainRaw(mkt);
    const volRank = getVolRank(ocRaw || []);

    const expiries = detectExpiryForSymbol(mkt);
    const expiry = expiries.currentWeek;
    const daysToExpiry = Math.max(0, moment(expiry).diff(moment(), "days"));

    const step = getStrikeSteps(mkt, daysToExpiry);
    const stepCount = computeStrikeDistanceByExpiry(daysToExpiry, 1);
    const dist = stepCount * (isFinite(step) ? step : 100);

    const atm = roundToStep(mkt, finalSpot);
    const up = atm + dist;
    const down = atm - dist;
    const strikes = [atm, up, down];

    const fullList = [];
    for (let st of strikes) {
      let preferred = "BOTH";
      if (trendObj.main === "UP") preferred = "CE";
      if (trendObj.main === "DOWN") preferred = "PE";

      const ceInfo = await resolveInstrumentToken(mkt, expiry, st, "CE");
      const peInfo = await resolveInstrumentToken(mkt, expiry, st, "PE");

      const ceEntryObj = await computeSmartEntry({
        indexSymbol: mkt,
        strike: st,
        type: "CE",
        strikeToken: ceInfo ? ceInfo.token : null,
        trendObj,
        expiry,
        strikeStep: step,
        spot: finalSpot,
      });
      const peEntryObj = await computeSmartEntry({
        indexSymbol: mkt,
        strike: st,
        type: "PE",
        strikeToken: peInfo ? peInfo.token : null,
        trendObj,
        expiry,
        strikeStep: step,
        spot: finalSpot,
      });

      const ceEntry = ceEntryObj.entry != null ? Number(ceEntryObj.entry) : null;
      const peEntry = peEntryObj.entry != null ? Number(peEntryObj.entry) : null;
      const ceSL = ceEntry != null ? computeSL(ceEntry) : null;
      const peSL = peEntry != null ? computeSL(peEntry) : null;

      const ceMomentum = Math.abs((ceEntry || 0) - (ceEntryObj.ltp || ceEntry || 0)) || 1;
      const peMomentum = Math.abs((peEntry || 0) - (peEntryObj.ltp || peEntry || 0)) || 1;

      const ceTarget = ceEntry != null ? targetEngine(ceEntry, ceMomentum, trendObj.confidence || 0.4, Math.max(1, ceMomentum)) : null;
      const peTarget = peEntry != null ? targetEngine(peEntry, peMomentum, trendObj.confidence || 0.4, Math.max(1, peMomentum)) : null;

      const ceScore = combinedScore({
        deltaScore: 0.5, thetaScore: 0.5, volumeScore: 0.5,
        oiScore: 0.5, premiumScore: 0.5, srScore: 0.5, futuresScore: 0.5,
      });
      const peScore = combinedScore({
        deltaScore: 0.5, thetaScore: 0.5, volumeScore: 0.5,
        oiScore: 0.5, premiumScore: 0.5, srScore: 0.5, futuresScore: 0.5,
      });

      const r_ce = ceEntry && ceSL && ceTarget ? (ceTarget - ceEntry) / (ceEntry - ceSL) : -1;
      const r_pe = peEntry && peSL && peTarget ? (peTarget - peEntry) / (peEntry - peSL) : -1;

      let chosen = null;
      if (preferred === "CE") {
        chosen = { type: "CE", entry: ceEntry, stopLoss: ceSL, target: ceTarget, token: ceInfo ? ceInfo.token : null, score: ceScore, reason: ceEntryObj.reason };
      } else if (preferred === "PE") {
        chosen = { type: "PE", entry: peEntry, stopLoss: peSL, target: peTarget, token: peInfo ? peInfo.token : null, score: peScore, reason: peEntryObj.reason };
      } else {
        chosen = r_ce >= r_pe ? { type: "CE", entry: ceEntry, stopLoss: ceSL, target: ceTarget, token: ceInfo ? ceInfo.token : null, score: ceScore, reason: ceEntryObj.reason } :
                               { type: "PE", entry: peEntry, stopLoss: peSL, target: peTarget, token: peInfo ? peInfo.token : null, score: peScore, reason: peEntryObj.reason };
      }

      fullList.push({
        strike: st,
        distance: Math.abs(st - atm),
        pair: {
          CE: { entry: ceEntry, stopLoss: ceSL, target: ceTarget, token: ceInfo ? ceInfo.token : null, score: ceScore, reason: ceEntryObj.reason },
          PE: { entry: peEntry, stopLoss: peSL, target: peTarget, token: peInfo ? peInfo.token : null, score: peScore, reason: peEntryObj.reason }
        },
        chosen
      });
    }

    const ordered = fullList.sort((a, b) => {
      if (a.strike === atm && b.strike !== atm) return -1;
      if (b.strike === atm && a.strike !== atm) return 1;
      const sa = a.chosen && a.chosen.score ? a.chosen.score : 0;
      const sb = b.chosen && b.chosen.score ? b.chosen.score : 0;
      return sb - sa;
    });

    const outputStrikes = ordered.map(r => {
      const c = r.chosen || {};
      return {
        strike: r.strike,
        distance: r.distance,
        type: c.type || null,
        token: c.token || null,
        entry: c.entry || null,
        stopLoss: c.stopLoss || null,
        target: c.target || null,
        score: Number((c.score || 0).toFixed(3)),
        reason: c.reason || null,
        debug: c.debug || {}
      };
    });

    return res.json({
      success: true,
      trend: trendObj,
      input: {
        ema20,
        ema50,
        rsi,
        vwap,
        spot: finalSpot,
        expiry_days: days,
        market: mkt,
      },
      meta: {
        live_data_used: !!use_live,
        expiry,
      },
      volRank,
      strikes: outputStrikes,
      guardian: sFix,
      login_status: session.access_token ? "Logged-in" : "Not logged in",
    });
  } catch (err) {
    return res.json({
      success: false,
      error: err.message || String(err),
    });
  }
});

/* ---------- ALIAS ROUTE (KEEP) ---------- */
app.post("/api/suggest", (req, res) => {
  req.url = "/api/calc";
  app._router.handle(req, res);
});

/* ---------- Ping ---------- */
app.get("/ping", (req, res) => {
  res.json({
    ok: true,
    alive: true,
    logged_in: !!session.access_token,
    last_spot: lastKnown.spot || null,
  });
});

/* ---------- Server Listen ---------- */
const PORT= process.env.PORT || 8080;
app.listen(PORT, ()=> {
  console.log("ALPHA-FULL SAFE running on port", PORT);
});

/* ===========================
   END OF ALPHA-FULL (SAFE)
   =========================== */
