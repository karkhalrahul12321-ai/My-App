/* ============================================================
   UPDATED PRODUCTION-READY ALPHA SERVER.JS  
   (Ultra-Soft Filter + Dynamic RSI Integrated)
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
   SPOT GUARDIAN
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
   EMA + RSI + Dynamic RSI
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

/* DYNAMIC RSI RANGE ADJUSTMENT (48–55 auto) */
function dynamicRSIThreshold(volRank, trendScore) {
  if (volRank === "HIGH") return 48;
  if (trendScore > 25) return 50;
  if (volRank === "LOW") return 55;
  return 52;
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

    return { main, confidence: Number(confidence.toFixed(3)), score, rsi };
  } catch {
    return { main: "NEUTRAL", confidence: 0.2, score: 0, rsi: 50 };
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
   ULTRA-SOFT FAKE BREAKOUT FILTER (UPDATED)
------------------------------------------------------------ */
function ultraSoftReject(trendObj, futDiff, dynamicRsi, actualRsi) {
  if (!trendObj) return true;

  if (trendObj.main === "UP" && actualRsi > dynamicRsi) return false;
  if (trendObj.main === "DOWN" && actualRsi < dynamicRsi) return false;

  if (Math.abs(futDiff) > 150) return true;

  return trendObj.score < -20;
}

/* ------------------------------------------------------------
   STOPLOSS
------------------------------------------------------------ */
function computeSL(entry) {
  if (!isFinite(entry)) return null;
  return Math.round((entry - 15) * 100) / 100;
}

/* ------------------------------------------------------------
   MAIN API: /api/calc
------------------------------------------------------------ */
app.post("/api/calc", async (req, res) => {
  try {
    const { ema20, ema50, rsi, vwap, spot, expiry_days, market, use_live } = req.body || {};

    const mkt = (market || "").toUpperCase();
    const days = Number(expiry_days) || 7;

    const sFix = await spotGuardian(mkt, spot, { useLive: !!use_live });
    const finalSpot = sFix.spot_used;

    const trendObj = await hybridTrendEngine(mkt);
    const ocRaw = await fetchOptionChainRaw(mkt);
    const volRank = getVolRank(ocRaw || []);

    const dynamicRsiTh = dynamicRSIThreshold(volRank, trendObj.score);
    const fut = await fetchFuturesLTPForSymbol(mkt);
    const futDiff = fut ? fut - finalSpot : 0;

    const isFake = ultraSoftReject(
      trendObj,
      futDiff,
      dynamicRsiTh,
      trendObj.rsi
    );

    if (isFake) {
      return res.json({
        success: false,
        error: "Fake breakout detected — no safe entry",
        trend: trendObj,
        dynamicRSI: dynamicRsiTh,
        guardian: sFix,
      });
    }

    return res.json({
      success: true,
      trend: trendObj,
      dynamicRSI: dynamicRsiTh,
      spot: finalSpot,
      message: "Ultra-soft mode with Dynamic RSI active",
    });
  } catch (err) {
    return res.json({ success: false, error: err.message });
  }
});

/* ------------------------------------------------------------
   START SERVER
------------------------------------------------------------ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("RAHUL FINAL ULTRA-SOFT + DYNAMIC RSI running on PORT", PORT);
});

/* ============================================================
   END OF UPDATED FILE
============================================================ */
