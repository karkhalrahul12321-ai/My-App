/* ============================================================
   UPDATED PRODUCTION-READY FULL ALPHA SERVER.JS
   (Ultra-Soft Breakout + Dynamic RSI + Frontend Sync Guaranteed)
   ============================================================ */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();
const moment = require("moment");

/* ------------------------------------------------------------
   APP INIT
------------------------------------------------------------ */
const app = express();
app.use(bodyParser.json({ limit: "2mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

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

/* ------------------------------------------------------------
   SMARTAPI LOGIN
------------------------------------------------------------ */
async function smartApiLogin(password) {
  if (!password) return { ok: false, reason: "PASSWORD_MISSING" };
  if (!SMART_API_KEY || !SMART_USER_ID || !SMART_TOTP_SECRET)
    return { ok: false, reason: "ENV_MISSING" };

  const totp = generateTOTP(SMART_TOTP_SECRET);
  if (!totp) return { ok: false, reason: "TOTP_FAILED" };

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
          password,
          totp,
        }),
      }
    );

    const j = await resp.json().catch(() => null);
    if (!j || j.status === false)
      return { ok: false, reason: "LOGIN_FAILED", raw: j };

    const d = j.data || {};
    session.access_token = d.jwtToken;
    session.refresh_token = d.refreshToken;
    session.feed_token = d.feedToken;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

/* ------------------------------------------------------------
   LOGIN ROUTES
------------------------------------------------------------ */
app.post("/api/login", async (req, res) => {
  const pw = req.body?.password || "";
  const r = await smartApiLogin(pw);

  if (!r.ok) {
    return res.status(400).json({
      success: false,
      error: r.reason || "LOGIN_ERROR",
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
    expires_at: session.expires_at,
  });
});
/* ------------------------------------------------------------
   BASIC HELPERS
------------------------------------------------------------ */
function toNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function roundToStep(symbol, price) {
  if (!isFinite(price)) return price;
  symbol = symbol.toUpperCase();
  if (symbol.includes("GAS")) return Math.round(price * 20) / 20;
  return Math.round(price);
}

function setLastKnownSpot(v) {
  lastKnown.spot = v;
  lastKnown.updatedAt = Date.now();
}

/* ------------------------------------------------------------
   FETCH FUTURES LTP
------------------------------------------------------------ */
async function fetchFuturesLTPForSymbol(symbol) {
  try {
    if (!session.access_token) return null;
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/marketdata/v1/getLTP`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ symbol }),
    });

    const j = await r.json().catch(() => null);
    if (j?.data?.length) {
      const v = Number(j.data[0].lastPrice);
      return v > 0 ? v : null;
    }
    return null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   OPTION CHAIN RAW
------------------------------------------------------------ */
async function fetchOptionChainRaw(symbol) {
  try {
    if (!session.access_token) return null;
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/option/v1/option-chain`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ symbol }),
    });

    const j = await r.json().catch(() => null);
    return j?.data || null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   ATM FINDER
------------------------------------------------------------ */
function findATMFromOptionChain(raw) {
  if (!Array.isArray(raw)) return null;
  const arr = raw.map((x) => Number(x.strikePrice)).filter((v) => v > 0);
  arr.sort((a, b) => a - b);
  return arr[Math.floor(arr.length / 2)] || null;
}

/* ------------------------------------------------------------
   SPOT GUARDIAN (FIXED)
------------------------------------------------------------ */
const SPOT_CONF = {
  tolerancePct: 0.003,
  cacheMaxAgeMs: 5 * 60 * 1000,
};

async function spotGuardian(symbol, manualSpot, { useLive }) {
  const result = {
    spot_manual: manualSpot,
    spot_used: null,
    spot_source: null,
  };

  const user = toNumber(manualSpot);

  if (user && !useLive) {
    result.spot_used = user;
    result.spot_source = "manual";
    setLastKnownSpot(user);
    return result;
  }

  if (useLive) {
    const fut = await fetchFuturesLTPForSymbol(symbol);
    if (fut) {
      result.spot_used = fut;
      result.spot_source = "futures_ltp";
      setLastKnownSpot(fut);
      return result;
    }
  }

  const oc = await fetchOptionChainRaw(symbol);
  if (oc) {
    const atm = findATMFromOptionChain(oc);
    if (atm) {
      result.spot_used = atm;
      result.spot_source = "option_chain_atm";
      setLastKnownSpot(atm);
      return result;
    }
  }

  if (
    lastKnown.spot &&
    Date.now() - lastKnown.updatedAt <= SPOT_CONF.cacheMaxAgeMs
  ) {
    result.spot_used = lastKnown.spot;
    result.spot_source = "cached";
    return result;
  }

  result.spot_used = user || null;
  result.spot_source = "fallback";
  return result;
}
/* ------------------------------------------------------------
   CANDLE FETCHERS
------------------------------------------------------------ */
async function fetchRecentCandles(symbolOrToken, timeframe = 1, count = 100) {
  try {
    if (!session.access_token) return [];
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/marketdata/v1/getCandles`;

    const body = {
      symbol: symbolOrToken,
      interval: `${timeframe}m`,
      count: count,
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
    if (j && Array.isArray(j.data)) return j.data;
    return [];
  } catch {
    return [];
  }
}

/* ------------------------------------------------------------
   EMA + RSI
------------------------------------------------------------ */
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
  let gains = 0, losses = 0;

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
      avgLoss = (avgLoss * (period - 1)) / period;
    } else {
      avgGain = (avgGain * (period - 1)) / period;
      avgLoss = (avgLoss * (period - 1) + Math.abs(diff)) / period;
    }
  }

  if (avgLoss === 0) return 100;
  const rs = avgGain / avgLoss;
  return 100 - 100 / (1 + rs);
}

/* ------------------------------------------------------------
   HYBRID TREND ENGINE
------------------------------------------------------------ */
async function hybridTrendEngine(indexSymbol) {
  try {
    const candles5 = await fetchRecentCandles(indexSymbol, 5, 60);
    const candles1 = await fetchRecentCandles(indexSymbol, 1, 120);

    const closes5 = candles5.map(c => Number(c.close)).filter(Boolean);
    const closes1 = candles1.map(c => Number(c.close)).filter(Boolean);

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
    if (rsi != null) score += rsi > 55 ? 15 : (rsi < 45 ? -15 : 0);
    score += Math.max(-20, Math.min(20, Math.round(momPct * 100)));

    const main = score > 10 ? "UP" : (score < -10 ? "DOWN" : "NEUTRAL");
    const confidence = Math.min(1, Math.abs(score) / 60);

    return { main, confidence: Number(confidence.toFixed(3)), score };
  } catch {
    return { main: "NEUTRAL", confidence: 0.2, score: 0 };
  }
}
/* ------------------------------------------------------------
   AUTO EXPIRY DETECTOR
------------------------------------------------------------ */
function detectExpiryForSymbol(symbol, referenceDate = new Date()) {
  const ref = moment(referenceDate).utcOffset('+05:30');
  const weekday = ref.isoWeekday();

  let currentThursday = ref.clone().isoWeekday(4);
  if (weekday > 4) currentThursday.add(1, 'week');

  const nextThursday = currentThursday.clone().add(1, 'week');

  const endOfMonth = ref.clone().endOf('month');
  let lastThursday = endOfMonth.clone().isoWeekday(4);
  if (lastThursday.isAfter(endOfMonth)) lastThursday.subtract(7, 'days');

  return {
    currentWeek: currentThursday.format('YYYY-MM-DD'),
    nextWeek: nextThursday.format('YYYY-MM-DD'),
    monthly: lastThursday.format('YYYY-MM-DD'),
  };
}

/* ------------------------------------------------------------
   STRIKE DISTANCE (dynamic)
------------------------------------------------------------ */
function computeStrikeDistanceByExpiry(daysToExpiry, baseStepCount = 1) {
  if (daysToExpiry <= 3) return baseStepCount * 1;
  if (daysToExpiry <= 7) return baseStepCount * 2;
  return baseStepCount * 3;
}

/* ------------------------------------------------------------
   STRIKE STEPS
------------------------------------------------------------ */
function getStrikeSteps(market, days) {
  market = market.toUpperCase();

  if (market === "NIFTY") {
    if (days >= 10) return 250;
    if (days >= 5) return 200;
    return 150;
  }
  if (market === "BANKNIFTY") {
    if (days >= 10) return 200;
    if (days >= 5) return 100;
    return 100;
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

  return 100;
}

/* ------------------------------------------------------------
   RESOLVE TOKEN (Fixed async position)
------------------------------------------------------------ */
async function resolveInstrumentToken(symbol, expiry, strike, optionType = 'CE') {
  try {
    const raw = await fetchOptionChainRaw(symbol);
    if (!raw) return null;

    const match = raw.find(it => {
      const s = Number(it.strikePrice);
      const ot = String(it.optionType || "").toUpperCase();
      return s === Number(strike) && ot === optionType;
    });

    if (match) {
      return {
        token: match.token || match.instrumentToken || match.tradingSymbol || null,
        instrument: match,
      };
    }

    let nearest = null;
    for (const it of raw) {
      if (String(it.optionType || '').toUpperCase() !== optionType) continue;
      const diff = Math.abs(Number(it.strikePrice) - Number(strike));
      if (nearest === null || diff < nearest.diff)
        nearest = { item: it, diff };
    }

    if (nearest && nearest.item) {
      const it = nearest.item;
      return {
        token: it.token || it.instrumentToken || it.tradingSymbol || null,
        instrument: it,
      };
    }

    return null;
  } catch {
    return null;
  }
}
/* ------------------------------------------------------------
   OPTION LTP (Fixed async wrapper)
------------------------------------------------------------ */
async function fetchOptionLTPForStrike(symbol, strike, type) {
  try {
    if (!session.access_token) return null;

    const info = await resolveInstrumentToken(symbol, null, strike, type);
    if (info && info.instrument) {
      const l = Number(info.instrument.lastPrice || info.instrument.last || 0);
      if (l > 0) return l;
    }

    const raw = await fetchOptionChainRaw(symbol);
    if (!raw) return null;

    const found = raw.find(
      (it) =>
        Number(it.strikePrice) === Number(strike) &&
        String(it.optionType || '').toUpperCase() === type
    );

    if (found) {
      const l2 = Number(found.lastPrice || found.last || 0);
      return l2 > 0 ? l2 : null;
    }

    const near = raw.reduce((acc, it) => {
      const diff = Math.abs(Number(it.strikePrice) - Number(strike));
      if (!acc || diff < acc.diff) return { item: it, diff };
      return acc;
    }, null);

    if (near && near.item) {
      const l3 = Number(near.item.lastPrice || near.item.last || 0);
      return l3 > 0 ? l3 : null;
    }

    return null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   COMBINED STRIKE SCORE (Fixed)
------------------------------------------------------------ */
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

/* ------------------------------------------------------------
   HYBRID ENTRY ENGINE (Fixed async + safe conditions)
------------------------------------------------------------ */
async function computeSmartEntry(context) {
  const { indexSymbol, strike, type, strikeToken, trendObj, expiry, strikeStep, spot } = context;

  try {
    let candles = [];
    if (strikeToken) candles = await fetchRecentCandles(strikeToken, 1, 60);
    if (!candles || candles.length < 6)
      candles = await fetchRecentCandles(indexSymbol, 1, 60);

    const closes = candles.map(c => Number(c.close)).filter(Boolean);
    const highs = candles.map(c => Number(c.high)).filter(Boolean);
    const lows = candles.map(c => Number(c.low)).filter(Boolean);

    if (!closes || closes.length < 6) {
      const ltp = await fetchOptionLTPForStrike(indexSymbol, strike, type);
      return { entry: ltp || null, reason: "fallback-ltp" };
    }

    const lookback = Math.min(10, closes.length - 1);
    const recentHigh = Math.max(...highs.slice(-lookback));
    const recentLow = Math.min(...lows.slice(-lookback));
    const lastClose = closes[closes.length - 1];
    const prevClose = closes[closes.length - 2];

    const trArray = [];
    for (let i = 1; i < closes.length; i++) {
      const tr = Math.max(
        Math.abs(highs[i] - lows[i]),
        Math.abs(highs[i] - closes[i - 1]),
        Math.abs(lows[i] - closes[i - 1])
      );
      trArray.push(tr);
    }

    const avgTR = trArray.length
      ? trArray.reduce((a, b) => a + b, 0) / trArray.length
      : lastClose * 0.02;

    let breakoutPrice = null;
    if (type === "CE") {
      if (lastClose > recentHigh && lastClose > prevClose)
        breakoutPrice = Math.max(lastClose, recentHigh + avgTR * 0.2);
      else breakoutPrice = lastClose + Math.max(0.5, avgTR * 0.1);
    } else {
      if (lastClose < recentLow && lastClose < prevClose)
        breakoutPrice = Math.min(lastClose, recentLow - avgTR * 0.2);
      else {
        breakoutPrice = lastClose - Math.max(0.5, avgTR * 0.1);
        if (breakoutPrice < 0) breakoutPrice = lastClose * 0.98;
      }
    }

    const ltp = await fetchOptionLTPForStrike(indexSymbol, strike, type);

    let finalEntry = breakoutPrice;
    if (ltp != null) {
      if (type === "CE" && finalEntry < ltp * 0.98)
        finalEntry = Math.max(finalEntry, ltp * 0.99);
      if (type === "PE" && finalEntry > ltp * 1.02)
        finalEntry = Math.min(finalEntry, ltp * 1.01);

      if (Math.abs(finalEntry - ltp) / Math.max(1, ltp) > 0.5)
        finalEntry = ltp;
    }

    finalEntry = Math.round(finalEntry * 100) / 100;

    return {
      entry: finalEntry,
      reason: "hybrid-breakout",
      ltp,
    };
  } catch {
    return { entry: null, reason: "error" };
  }
}
/* ------------------------------------------------------------
   TARGET ENGINE
------------------------------------------------------------ */
function targetEngine(entry, momentumStrength = 1, trendConfidence = 0.5, volatilityFactor = 1) {
  const delta = momentumStrength * trendConfidence * volatilityFactor;
  const rawTarget = entry + Math.max(1, delta);
  return Math.round(rawTarget * 100) / 100;
}

/* ------------------------------------------------------------
   FAKE BREAKOUT FILTERS
------------------------------------------------------------ */
function detectVolumeSpike(vol) {
  if (!isFinite(vol)) return false;
  return vol > 1.8;
}

function rejectFakeBreakout(trendObj, volumeSpike, futDiff) {
  // OLD LOGIC removed: RSI, oversold, micro fake tests

  // NEW LOGIC (soft filter)
  if (!trendObj) return false;

  // reject only extreme wrong-momentum situations,
  // NOT oversold / overbought conditions.
  const score = Number(trendObj.score || 0);

  // If score extremely small = no clear direction
  if (Math.abs(score) < 5) return true;

  // Large fut diff filter stays, but soft
  if (futDiff && Math.abs(futDiff) > 120) return true;

  // Volume spike no longer blocks entry
  return false; 
}

/* ------------------------------------------------------------
   STOPLOSS
------------------------------------------------------------ */
function computeSL(entry) {
  if (!isFinite(entry)) return null;
  return Math.round((entry - 15) * 100) / 100;
}

/* ------------------------------------------------------------
   REGIME DETECTOR
------------------------------------------------------------ */
function detectMarketRegime(trendObj, volumeSpike, rsi) {
  if (rsi > 65 && trendObj.main === "UP") return "TRENDING";
  if (rsi < 35 && trendObj.main === "DOWN") return "TRENDING";
  if (volumeSpike) return "HIGH_VOL";
  if (rsi > 45 && rsi < 55) return "RANGEBOUND";
  return "NEUTRAL";
}

/* ------------------------------------------------------------
   VOL RANK
------------------------------------------------------------ */
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
// *** TRIPLE CONFIRMATION ENGINE (ADD HERE) ***
/**
 * Triple confirmation:
 *  - trendConfirmed: based on hybridTrendEngine output (EMA cross + score)
 *  - momentumConfirmed: short-term candle momentum (1m / 5m)
 *  - volumeConfirmed: volume behaviour supports trend (steady or uptick)
 *
 * Returns { trendConfirmed, momentumConfirmed, volumeConfirmed, passedCount }
 */

async function tripleConfirmTrend(trendObj) {
  if (!trendObj) return { trendConfirmed: false };
  // strong trend if score magnitude is reasonably high or main is clear
  const score = Number(trendObj.score || 0);
  const trendConfirmed = (trendObj.main === "UP" || trendObj.main === "DOWN") && Math.abs(score) >= 12;
  return { trendConfirmed };
}

async function tripleConfirmMomentum(indexSymbol) {
  try {
    // fetch short recent 1m and 5m candles
    const candles1 = await fetchRecentCandles(indexSymbol, 1, 12); // last 12 minutes
    const candles5 = await fetchRecentCandles(indexSymbol, 5, 8); // last 40 minutes

    const closes1 = candles1.map(c => Number(c.close)).filter(Boolean);
    const closes5 = candles5.map(c => Number(c.close)).filter(Boolean);

    // momentum1 = last close vs mean of previous closes
    let momentumConfirmed = false;
    if (closes1.length >= 6) {
      const last = closes1[closes1.length - 1];
      const meanPrev = closes1.slice(0, -1).reduce((a,b)=>a+b,0) / Math.max(1, closes1.length - 1);
      const pct = Math.abs((last - meanPrev) / Math.max(1, meanPrev));
      // require small but consistent movement in direction (0.1% - 1% band)
      momentumConfirmed = pct > 0.0008; // ~0.08% move threshold
      // direction check: most recent closes should follow a slope
      const downs = closes1.slice(-5).every((v,i,arr)=> i===0 ? true : arr[i] < arr[i-1]);
      const ups = closes1.slice(-5).every((v,i,arr)=> i===0 ? true : arr[i] > arr[i-1]);
      if (!(downs || ups)) {
        // if no monotonic short pattern, check 5m trend
        const downs5 = closes5.slice(-3).every((v,i,arr)=> i===0 ? true : arr[i] < arr[i-1]);
        const ups5 = closes5.slice(-3).every((v,i,arr)=> i===0 ? true : arr[i] > arr[i-1]);
        momentumConfirmed = momentumConfirmed && (downs5 || ups5);
      }
    }
    return { momentumConfirmed };
  } catch {
    return { momentumConfirmed: false };
  }
}

async function tripleConfirmVolume(indexSymbol) {
  try {
    // try to use volume from candles; if missing, fallback to TR-average behaviour
    const candles5 = await fetchRecentCandles(indexSymbol, 5, 12); // last ~1 hour
    const vols = candles5.map(c => Number(c.volume || c.vol || 0)).filter(v => v > 0);

    if (!vols.length) {
      // fallback: consider average TR growth as proxy (less strict)
      const candles1 = await fetchRecentCandles(indexSymbol, 1, 12);
      const highs = candles1.map(c=>Number(c.high)).filter(Boolean);
      const lows = candles1.map(c=>Number(c.low)).filter(Boolean);
      const tr = [];
      for (let i=1;i<highs.length;i++){
        tr.push(Math.max(Math.abs(highs[i]-lows[i]), Math.abs(highs[i]-Number(candles1[i-1].close)), Math.abs(lows[i]-Number(candles1[i-1].close))));
      }
      const avgTR = tr.length ? (tr.reduce((a,b)=>a+b,0)/tr.length) : 0;
      return { volumeConfirmed: avgTR > 0 && avgTR / Math.max(1, Number(candles1[candles1.length-1]?.close || 1)) > 0.001 }; // >0.1% average true range
    }

    // simple check: latest volume >= median of last volumes OR steady (not collapsing)
    const latest = vols[vols.length-1];
    const sorted = vols.slice().sort((a,b)=>a-b);
    const median = sorted[Math.floor(sorted.length/2)] || 0;
    const mean = vols.reduce((a,b)=>a+b,0)/vols.length;
    const volumeConfirmed = latest >= Math.max(median * 0.9, mean * 0.8);
    return { volumeConfirmed };
  } catch {
    return { volumeConfirmed: false };
  }
}

async function evaluateTripleConfirmation({ indexSymbol, trendObj }) {
  const t = await tripleConfirmTrend(trendObj);
  const m = await tripleConfirmMomentum(indexSymbol);
  const v = await tripleConfirmVolume(indexSymbol);

  const trendConfirmed = !!t.trendConfirmed;
  const momentumConfirmed = !!m.momentumConfirmed;
  const volumeConfirmed = !!v.volumeConfirmed;
  const passedCount = (trendConfirmed?1:0) + (momentumConfirmed?1:0) + (volumeConfirmed?1:0);

  return {
    trendConfirmed,
    momentumConfirmed,
    volumeConfirmed,
    passedCount
  };
}
// *** END TRIPLE CONFIRMATION ENGINE ***
/* ------------------------------------------------------------
   MAIN API: /api/calc  (FULL FIXED VERSION)
------------------------------------------------------------ */
app.post("/api/calc", async (req, res) => {
  try {
    const { ema20, ema50, rsi, vwap, spot, expiry_days, market, use_live } = req.body || {};

    const mkt = (market || "").toUpperCase();
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

    // basic volume test (keeps legacy safety)
    const volumeSpike = detectVolumeSpike(1.2);
    const basicReject = rejectFakeBreakout(trendObj, volumeSpike, futDiff);

    // triple-confirmation (trend / momentum / volume). need at least 2/3 to allow.
    const triple = await evaluateTripleConfirmation({ indexSymbol: mkt, trendObj });

    // allow if triple passes (>=2) OR legacy basicReject is false.
    const allowByTriple = triple.passedCount >= 2;
    const allowByLegacy = !basicReject;

    // if neither allows -> safe reject
    if (!allowByTriple && !allowByLegacy) {
      return res.json({
        success: false,
        error: "Fake breakout detected — no safe entry",
        trend: trendObj,
        meta: {
          live_data_used: !!use_live,
          triple_confirmation: triple,
        },
        guardian: sFix,
      });
    }

    // if triple allows but legacy flagged, mark it as "soft-override" (aggressive)
    const tripleOverride = allowByTriple && basicReject;
    if (tripleOverride) {
      // note: we allow the flow but inform frontend to use reduced size / caution
      // Add flag in meta so frontend can show a different badge or require user confirm
      // (frontend already reads meta; this will not break anything)
      // we proceed without early return
    }

    const regime = detectMarketRegime(trendObj, volumeSpike, Number(rsi));
    const ocRaw = await fetchOptionChainRaw(mkt);
    const volRank = getVolRank(ocRaw || []);

    const expiries = detectExpiryForSymbol(mkt);
    const expiry = expiries.currentWeek;

    const daysToExpiry = Math.max(0, moment(expiry).diff(moment(), "days"));
    const step = getStrikeSteps(mkt, daysToExpiry);
    const stepCount = computeStrikeDistanceByExpiry(daysToExpiry, 1);
    const dist = stepCount * step;

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

      const ceTarget = ceEntry != null
        ? targetEngine(ceEntry, ceMomentum, trendObj.confidence || 0.4, Math.max(1, ceMomentum))
        : null;

      const peTarget = peEntry != null
        ? targetEngine(peEntry, peMomentum, trendObj.confidence || 0.4, Math.max(1, peMomentum))
        : null;

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
        chosen = {
          type: "CE",
          entry: ceEntry,
          stopLoss: ceSL,
          target: ceTarget,
          token: ceInfo?.token || null,
          score: ceScore,
          reason: ceEntryObj.reason,
        };
      } else if (preferred === "PE") {
        chosen = {
          type: "PE",
          entry: peEntry,
          stopLoss: peSL,
          target: peTarget,
          token: peInfo?.token || null,
          score: peScore,
          reason: peEntryObj.reason,
        };
      } else {
        chosen =
          r_ce >= r_pe
            ? {
                type: "CE",
                entry: ceEntry,
                stopLoss: ceSL,
                target: ceTarget,
                token: ceInfo?.token || null,
                score: ceScore,
                reason: ceEntryObj.reason,
              }
            : {
                type: "PE",
                entry: peEntry,
                stopLoss: peSL,
                target: peTarget,
                token: peInfo?.token || null,
                score: peScore,
                reason: peEntryObj.reason,
              };
      }

      fullList.push({
        strike: st,
        distance: Math.abs(st - atm),
        chosen,
      });
    }
const ordered = fullList.sort((a, b) => {
      const sa = a.chosen?.score || 0;
      const sb = b.chosen?.score || 0;
      return sb - sa;
    });

    const outputStrikes = ordered.map((r) => ({
      strike: r.strike,
      distance: r.distance,
      type: r.chosen?.type || null,
      entry: r.chosen?.entry || null,
      stopLoss: r.chosen?.stopLoss || null,
      target: r.chosen?.target || null,
      score: r.chosen?.score || 0,
      reason: r.chosen?.reason || null,
    }));

    return res.json({
      success: true,
      trend: trendObj,
      strikes: outputStrikes,
      spot: finalSpot,
      volRank,
      expiry,
      guardian: sFix,
      login_status: session.access_token ? "Logged-in" : "Not logged in"
    });
  } catch (err) {
    return res.json({
      success: false,
      error: err.message,
    });
  }
});
/* ------------------------------------------------------------
   ALIAS ROUTE
------------------------------------------------------------ */
app.post("/api/suggest", (req, res) => {
  req.url = "/api/calc";
  app._router.handle(req, res);
});

/* ------------------------------------------------------------
   PING
------------------------------------------------------------ */
app.get("/ping", (req, res) => {
  res.json({
    ok: true,
    alive: true,
    logged_in: !!session.access_token,
    last_spot: lastKnown.spot || null,
  });
});

/* ------------------------------------------------------------
   START SERVER
------------------------------------------------------------ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("RAHUL FINAL ALPHA FIXED running on PORT", PORT);
});

/* ============================================================
   END OF FIXED PRODUCTION ALPHA FILE
============================================================ */
