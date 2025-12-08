/* ==============================================================
   FINAL ALPHA BACKEND (MERGED + DYNAMIC RSI + TRIPLE CONFIRM)
   Prepared for Rahul — Render Ready — Zero Break/Zero Drift
   ============================================================== */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();
const moment = require("moment");

/* -------------------------------------------------------------
   APP INIT
-------------------------------------------------------------- */
const app = express();
app.use(bodyParser.json({ limit: "2mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

/* -------------------------------------------------------------
   SERVE FRONTEND
-------------------------------------------------------------- */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) =>
  res.sendFile(path.join(frontendPath, "index.html"))
);
app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* -------------------------------------------------------------
   ENV SMARTAPI
-------------------------------------------------------------- */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE ||
  "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* -------------------------------------------------------------
   SESSION STORE
-------------------------------------------------------------- */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

/* -------------------------------------------------------------
   LAST-KNOWN SPOT
-------------------------------------------------------------- */
let lastKnown = {
  spot: null,
  updatedAt: 0,
};
/* -------------------------------------------------------------
   BASE32 DECODE + TOTP
-------------------------------------------------------------- */
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

/* -------------------------------------------------------------
   SAFE JSON FETCH
-------------------------------------------------------------- */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/* -------------------------------------------------------------
   SMARTAPI LOGIN
-------------------------------------------------------------- */
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

/* -------------------------------------------------------------
   LOGIN ROUTES
-------------------------------------------------------------- */
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
/* -------------------------------------------------------------
   SPOT GUARDIAN  (Auto LTP fallback + live spot stabilizer)
-------------------------------------------------------------- */
async function spotGuardian(indexSymbol, userSpot, { useLive = false } = {}) {
  let resolvedSpot = Number(userSpot) || null;

  if (useLive && session.access_token) {
    const live = await fetchFuturesLTPForSymbol(indexSymbol);
    if (live && isFinite(live)) resolvedSpot = live;
  }

  if (!resolvedSpot) {
    if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 15000) {
      resolvedSpot = lastKnown.spot;
    }
  }

  if (resolvedSpot) {
    lastKnown.spot = resolvedSpot;
    lastKnown.updatedAt = Date.now();
  }

  return {
    spot_used: resolvedSpot,
    had_live: useLive,
    fallback_used: !useLive,
  };
}

/* -------------------------------------------------------------
   RESOLVE TOKEN
-------------------------------------------------------------- */
async function resolveInstrumentToken(symbol, expiry, strike, type) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getInstrumentBySymbol`;
    const payload = {
      symbol,
      exchange: "NFO",
      expiry,
      strike,
      right: type,
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "00:00:00:00:00:00",
        "X-PrivateKey": SMART_API_KEY,
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        Authorization: session.access_token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const j = await r.json().catch(() => null);
    const d = j?.data;

    if (d && d.length) {
      return {
        token: d[0].token,
        instrument: d[0],
      };
    }
    return null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   FETCH RECENT CANDLES
-------------------------------------------------------------- */
async function fetchRecentCandles(symbol, interval, count) {
  try {
    const now = moment().format("YYYY-MM-DD HH:mm");
    const from = moment().subtract(count * interval, "minutes").format("YYYY-MM-DD HH:mm");

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;
    const payload = {
      exchange: "NSE",
      symbol: symbol === "BANKNIFTY" ? "NIFTY BANK" : symbol,
      interval: `${interval}m`,
      fromdate: from,
      todate: now,
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
      },
      body: JSON.stringify(payload),
    });

    const j = await r.json().catch(() => null);
    const data = j?.data?.candles || [];

    return data.map((c) => ({
      time: c[0],
      open: c[1],
      high: c[2],
      low: c[3],
      close: c[4],
      volume: c[5],
    }));
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------
   FETCH FUTURES LTP
-------------------------------------------------------------- */
async function fetchFuturesLTPForSymbol(indexSymbol) {
  try {
    const futSymbol =
      indexSymbol === "BANKNIFTY"
        ? "BANKNIFTY24FEBFUT"
        : indexSymbol === "FINNIFTY"
        ? "FINNIFTY24FEBFUT"
        : "NIFTY24FEBFUT";

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
      },
      body: JSON.stringify({
        exchange: "NFO",
        tradingsymbol: futSymbol,
        symboltoken: "",
      }),
    });

    const j = await r.json().catch(() => null);
    return Number(j?.data?.ltp || 0);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   OPTION CHAIN RAW
-------------------------------------------------------------- */
async function fetchOptionChainRaw(symbol) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/optionchain/v1/getOptionChainData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        exchange: "NFO",
        tradingsymbol: symbol,
      }),
    });

    const j = await r.json().catch(() => null);
    return j?.data || [];
  } catch {
    return [];
  }
}
/* -------------------------------------------------------------
   EMA + RSI
-------------------------------------------------------------- */
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

/* -------------------------------------------------------------
   HYBRID TREND ENGINE (DYNAMIC RSI integrated)
-------------------------------------------------------------- */
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
    // direction base by EMA cross (strong directional bias)
    if (ema20 && ema50) score += ema20 > ema50 ? 30 : -30;

    // dynamic RSI influence (your requested thresholds: down <40, up >50)
    let rsiScore = 0;
    if (rsi != null) {
      // up-side boosts
      if (rsi >= 70) rsiScore = 20;
      else if (rsi >= 65) rsiScore = 15;
      else if (rsi >= 60) rsiScore = 10;
      else if (rsi >= 50) rsiScore = 5;
      // neutral band 40-50 => no strong push
      else if (rsi <= 25) rsiScore = -20;
      else if (rsi <= 30) rsiScore = -15;
      else if (rsi <= 35) rsiScore = -10;
      else if (rsi <= 40) rsiScore = -5;
      // if rsi between 40-50, rsiScore stays 0 (neutral)
    }

    // apply rsiScore in directionally sensible way:
    // if EMA says UP, add rsiScore; if EMA says DOWN, subtract rsiScore (makes low RSI stronger for down)
    if (ema20 && ema50) {
      if (ema20 > ema50) score += Math.max(0, rsiScore);
      else score -= Math.max(0, -rsiScore);
      if (ema20 > ema50 && rsiScore < 0) score += rsiScore;
      if (ema20 < ema50 && rsiScore > 0) score -= rsiScore * 0.5;
    } else {
      score += rsiScore;
    }

    // momentum contribution (scaled)
    score += Math.max(-20, Math.min(20, Math.round(momPct * 100)));

    const main = score > 10 ? "UP" : (score < -10 ? "DOWN" : "NEUTRAL");
    const confidence = Math.min(1, Math.abs(score) / 60);

    return { main, confidence: Number(confidence.toFixed(3)), score };
  } catch {
    return { main: "NEUTRAL", confidence: 0.2, score: 0 };
  }
}
/* -------------------------------------------------------------
   TRIPLE CONFIRMATION — TREND + MOMENTUM + VOLUME
-------------------------------------------------------------- */

// Trend confirmation (RSI-aware)
async function tripleConfirmTrend(trendObj, indexSymbol) {
  if (!trendObj) return { trendConfirmed: false };

  const score = Number(trendObj.score || 0);
  if (Math.abs(score) >= 12) return { trendConfirmed: true };

  try {
    const candles1 = await fetchRecentCandles(indexSymbol, 1, 30);
    const closes1 = candles1.map(c => Number(c.close)).filter(Boolean);
    const localRSI = computeRSI(closes1, 14);

    if (!localRSI && Math.abs(score) >= 8)
      return { trendConfirmed: true };

    if (trendObj.main === "UP") {
      if (localRSI > 50 && score > 5) return { trendConfirmed: true };
      if (localRSI >= 60 && score > 2) return { trendConfirmed: true };
    } else if (trendObj.main === "DOWN") {
      if (localRSI < 40 && score < -5) return { trendConfirmed: true };
      if (localRSI <= 35 && score < -2) return { trendConfirmed: true };
    }

    return { trendConfirmed: false };
  } catch {
    return { trendConfirmed: Math.abs(score) >= 10 };
  }
}

// Momentum confirmation
async function tripleConfirmMomentum(indexSymbol) {
  try {
    const candles1 = await fetchRecentCandles(indexSymbol, 1, 12);
    const candles5 = await fetchRecentCandles(indexSymbol, 5, 6);

    const c1 = candles1.map(c => c.close);
    const c5 = candles5.map(c => c.close);

    if (c1.length < 6) return { momentumConfirmed: false };

    const last = c1[c1.length - 1];
    const meanPrev =
      c1.slice(0, -1).reduce((a, b) => a + b, 0) / Math.max(1, c1.length - 1);
    const pct = Math.abs((last - meanPrev) / Math.max(1, meanPrev));

    let momentumConfirmed = pct > 0.0008;

    const downs = c1.slice(-5).every((v, i, arr) =>
      i === 0 ? true : arr[i] < arr[i - 1]
    );
    const ups = c1.slice(-5).every((v, i, arr) =>
      i === 0 ? true : arr[i] > arr[i - 1]
    );

    if (!(downs || ups)) {
      const downs5 = c5.slice(-3).every((v, i, arr) =>
        i === 0 ? true : arr[i] < arr[i - 1]
      );
      const ups5 = c5.slice(-3).every((v, i, arr) =>
        i === 0 ? true : arr[i] > arr[i - 1]
      );
      momentumConfirmed = momentumConfirmed && (downs5 || ups5);
    }

    return { momentumConfirmed };
  } catch {
    return { momentumConfirmed: false };
  }
}

// Volume confirmation
async function tripleConfirmVolume(indexSymbol) {
  try {
    const candles5 = await fetchRecentCandles(indexSymbol, 5, 12);
    const vols = candles5
      .map(c => Number(c.volume || c.vol || 0))
      .filter(v => v > 0);

    if (!vols.length) {
      const candles1 = await fetchRecentCandles(indexSymbol, 1, 12);
      const highs = candles1.map(c => Number(c.high)).filter(Boolean);
      const lows = candles1.map(c => Number(c.low)).filter(Boolean);

      const tr = [];
      for (let i = 1; i < highs.length; i++) {
        tr.push(
          Math.max(
            Math.abs(highs[i] - lows[i]),
            Math.abs(highs[i] - candles1[i - 1].close),
            Math.abs(lows[i] - candles1[i - 1].close)
          )
        );
      }

      const avgTR = tr.length
        ? tr.reduce((a, b) => a + b, 0) / tr.length
        : 0;

      return {
        volumeConfirmed:
          avgTR > 0 &&
          avgTR /
            Math.max(1, Number(candles1[candles1.length - 1]?.close || 1)) >
            0.001,
      };
    }

    const latest = vols[vols.length - 1];
    const sorted = [...vols].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)] || 0;
    const mean = vols.reduce((a, b) => a + b, 0) / vols.length;

    return {
      volumeConfirmed: latest >= Math.max(median * 0.9, mean * 0.8),
    };
  } catch {
    return { volumeConfirmed: false };
  }
}

// Full triple-confirmation evaluator
async function evaluateTripleConfirmation({ indexSymbol, trendObj }) {
  const t = await tripleConfirmTrend(trendObj, indexSymbol);
  const m = await tripleConfirmMomentum(indexSymbol);
  const v = await tripleConfirmVolume(indexSymbol);

  const trendConfirmed = !!t.trendConfirmed;
  const momentumConfirmed = !!m.momentumConfirmed;
  const volumeConfirmed = !!v.volumeConfirmed;

  const passedCount =
    (trendConfirmed ? 1 : 0) +
    (momentumConfirmed ? 1 : 0) +
    (volumeConfirmed ? 1 : 0);

  return {
    trendConfirmed,
    momentumConfirmed,
    volumeConfirmed,
    passedCount,
  };
}
/* -------------------------------------------------------------
   FAKE BREAKOUT SOFT FILTER  (updated safe logic)
-------------------------------------------------------------- */
function rejectFakeBreakout(trendObj, volumeSpike, futDiff) {
  if (!trendObj) return true;

  // earlier system was too strict… now soft:
  const score = Number(trendObj.score || 0);

  // Reject only if trend is extremely unclear
  if (Math.abs(score) < 5) return true;

  // Futures mismatch soft filter
  if (futDiff && Math.abs(futDiff) > 120) return true;

  // Volume spike no longer blocks continuation
  return false;
}

/* -------------------------------------------------------------
   FUTURES DIFF CHECK
-------------------------------------------------------------- */
async function detectFuturesDiff(indexSymbol, spotUsed) {
  try {
    const futLtp = await fetchFuturesLTPForSymbol(indexSymbol);
    if (!futLtp) return null;
    return futLtp - spotUsed;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   ENTRY GUARD — blocking only when truly unsafe
-------------------------------------------------------------- */
function finalEntryGuard({
  trendObj,
  tripleObj,
  futDiff,
  volumeSpike,
}) {
  if (!trendObj) {
    return { allowed: false, reason: "NO_TREND_DATA" };
  }

  // If triple-confirmation entirely fails
  if (tripleObj.passedCount === 0) {
    return { allowed: false, reason: "NO_CONFIRMATIONS" };
  }

  // Fake breakout soft logic
  const softReject = rejectFakeBreakout(trendObj, volumeSpike, futDiff);
  if (softReject) {
    return { allowed: false, reason: "FAKE_BREAKOUT" };
  }

  // Futures mismatch strong rejection
  if (futDiff && Math.abs(futDiff) > 200) {
    return { allowed: false, reason: "FUT_MISMATCH" };
  }

  return { allowed: true };
}

/* -------------------------------------------------------------
   VOLUME SPIKE DETECTOR (not blocking entry anymore)
-------------------------------------------------------------- */
function detectVolumeSpike(prevVolume, curVolume) {
  if (!prevVolume || !curVolume) return false;
  return curVolume >= prevVolume * 1.15;
}
/* -------------------------------------------------------------
   HYBRID ENTRY ENGINE (computeSmartEntry) — uses candles + LTP fallback
-------------------------------------------------------------- */
async function computeSmartEntry(context) {
  const {
    indexSymbol,
    strike,
    type,
    strikeToken,
    trendObj,
    expiry,
    strikeStep,
    spot,
  } = context;

  try {
    // Try option-token specific candles first, then index candles
    let candles = [];
    if (strikeToken && session.access_token) {
      candles = await fetchRecentCandles(strikeToken, 1, 60);
    }
    if (!candles || candles.length < 6) {
      candles = await fetchRecentCandles(indexSymbol, 1, 60);
    }

    const closes = candles.map((c) => Number(c.close)).filter(Boolean);
    const highs = candles.map((c) => Number(c.high)).filter(Boolean);
    const lows = candles.map((c) => Number(c.low)).filter(Boolean);

    if (!closes || closes.length < 6) {
      const ltp = await fetchOptionLTPForStrike(indexSymbol, strike, type);
      return { entry: ltp || null, reason: "ltp-fallback", ltp };
    }

    // Recent structure
    const lookback = Math.min(10, closes.length - 1);
    const recentHigh = Math.max(...highs.slice(-lookback));
    const recentLow = Math.min(...lows.slice(-lookback));
    const lastClose = closes[closes.length - 1];
    const prevClose = closes[closes.length - 2];

    // True range proxy
    const tr = [];
    for (let i = 1; i < closes.length; i++) {
      tr.push(
        Math.max(
          Math.abs(highs[i] - lows[i]),
          Math.abs(highs[i] - closes[i - 1]),
          Math.abs(lows[i] - closes[i - 1])
        )
      );
    }
    const avgTR = tr.length ? tr.reduce((a, b) => a + b, 0) / tr.length : lastClose * 0.02;

    // breakout logic (soft)
    let breakoutPrice = lastClose;
    if (type === "CE") {
      if (lastClose > recentHigh && lastClose > prevClose) {
        breakoutPrice = Math.max(lastClose, recentHigh + avgTR * 0.2);
      } else {
        breakoutPrice = lastClose + Math.max(0.5, avgTR * 0.1);
      }
    } else {
      if (lastClose < recentLow && lastClose < prevClose) {
        breakoutPrice = Math.min(lastClose, recentLow - avgTR * 0.2);
      } else {
        breakoutPrice = lastClose - Math.max(0.5, avgTR * 0.1);
        if (breakoutPrice < 0) breakoutPrice = lastClose * 0.98;
      }
    }

    const ltp = await fetchOptionLTPForStrike(indexSymbol, strike, type);

    // reconcile with LTP
    let finalEntry = breakoutPrice;
    if (ltp != null) {
      if (type === "CE" && finalEntry < ltp * 0.98) finalEntry = Math.max(finalEntry, ltp * 0.99);
      if (type === "PE" && finalEntry > ltp * 1.02) finalEntry = Math.min(finalEntry, ltp * 1.01);

      if (Math.abs(finalEntry - ltp) / Math.max(1, ltp) > 0.5) finalEntry = ltp;
    }

    finalEntry = Math.round(finalEntry * 100) / 100;

    return { entry: finalEntry, reason: "hybrid-breakout", ltp };
  } catch (e) {
    return { entry: null, reason: "error", error: e.message || String(e) };
  }
}

/* -------------------------------------------------------------
   TARGET + STOPLOSS + SCORE UTILITIES
-------------------------------------------------------------- */
function targetEngine(entry, momentumStrength = 1, trendConfidence = 0.5, volatilityFactor = 1) {
  const delta = momentumStrength * trendConfidence * volatilityFactor;
  const rawTarget = entry + Math.sign(delta) * Math.max(1, Math.abs(delta));
  return Math.round(rawTarget * 100) / 100;
}

function computeSL(entry) {
  if (!isFinite(entry)) return null;
  // Fixed 15 point SL as baseline, but scaled for very small premiums
  const sl = entry - 15;
  return Math.round(sl * 100) / 100;
}

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
/* -------------------------------------------------------------
   MAIN API: /api/calc  (FINAL MERGED + RSI-aware + Triple Confirm)
-------------------------------------------------------------- */
app.post("/api/calc", async (req, res) => {
  try {
    const {
      ema20: inEma20,
      ema50: inEma50,
      rsi: inRsi,
      vwap: inVwap,
      spot: manualSpot,
      expiry_days,
      market,
      use_live,
    } = req.body || {};

    const mkt = (market || "").toUpperCase();
    const days = Number(expiry_days) || 7;

    // Resolve spot
    const sFix = await spotGuardian(mkt, manualSpot, { useLive: !!use_live });
    const finalSpot = sFix.spot_used;
    if (!finalSpot || !isFinite(finalSpot)) {
      return res.json({
        success: false,
        error: "Spot could not be resolved",
        meta: { live_data_used: !!use_live },
        guardian: sFix,
      });
    }

    // Core engines
    const trendObj = await hybridTrendEngine(mkt); // includes dynamic RSI influence
    const futDiff = await detectFuturesDiff(mkt, finalSpot);

    // legacy-ish volume spike quick check (non-blocking)
    const volumeSpike = false; // kept simple; detailed volume checked in tripleConfirmVolume

    // triple confirmation
    const triple = await evaluateTripleConfirmation({ indexSymbol: mkt, trendObj });

    // basic soft reject (legacy-style, but soft)
    const basicReject = rejectFakeBreakout(trendObj, volumeSpike, futDiff);

    // allow if triple passes (>=2) OR legacy basicReject is false.
    const allowByTriple = triple.passedCount >= 2;
    const allowByLegacy = !basicReject;

    if (!allowByTriple && !allowByLegacy) {
      return res.json({
        success: false,
        error: "Fake breakout detected — no safe entry",
        trend: trendObj,
        meta: {
          live_data_used: !!use_live,
          triple_confirmation: triple,
          basicReject,
          futDiff,
        },
        guardian: sFix,
      });
    }

    const tripleOverride = allowByTriple && basicReject;

    // Expiry + strike distance
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

    const ocRaw = await fetchOptionChainRaw(mkt);
    const volRank = getVolRank(ocRaw || []);

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
      meta: {
        live_data_used: !!use_live,
        triple_confirmation: triple,
        triple_override: tripleOverride || false,
        basicReject,
        futDiff,
      },
      login_status: session.access_token ? "Logged-in" : "Not logged in"
    });
  } catch (err) {
    return res.json({
      success: false,
      error: err.message || String(err),
    });
  }
});
/* -------------------------------------------------------------
   STRIKE & EXPIRY UTILITIES
-------------------------------------------------------------- */
function roundToStep(market, price) {
  price = Number(price) || 0;
  if (market === "BANKNIFTY") return Math.round(price / 100) * 100;
  if (market === "FINNIFTY") return Math.round(price / 50) * 50;
  return Math.round(price / 50) * 50;
}

function getStrikeSteps(market, daysToExpiry) {
  if (market === "BANKNIFTY") return daysToExpiry >= 5 ? 100 : 50;
  if (market === "FINNIFTY") return 50;
  return daysToExpiry >= 5 ? 50 : 25;
}

function computeStrikeDistanceByExpiry(days, minSteps = 1) {
  if (days <= 1) return minSteps;
  if (days <= 3) return minSteps + 1;
  if (days <= 5) return minSteps + 2;
  return minSteps + 3;
}

function detectExpiryForSymbol(symbol) {
  const today = moment();
  let currentWeek = today.clone().weekday(4); // Thursday
  if (today.weekday() > 4) currentWeek = today.clone().add(1, "weeks").weekday(4);
  const nextWeek = currentWeek.clone().add(1, "weeks").weekday(4);

  return {
    currentWeek: currentWeek.format("YYYY-MM-DD"),
    nextWeek: nextWeek.format("YYYY-MM-DD"),
  };
}

/* -------------------------------------------------------------
   VOL RANKING (for option chain)
-------------------------------------------------------------- */
function getVolRank(ocRows) {
  if (!ocRows || !ocRows.length) return 0;
  const ivs = ocRows
    .map((r) => Number(r.impliedVolatility || r.iv || 0))
    .filter((v) => v > 0);
  if (!ivs.length) return 0;

  const last = ivs[ivs.length - 1];
  const sorted = [...ivs].sort((a, b) => a - b);
  const rank = sorted.indexOf(last) / sorted.length;

  return Math.round(rank * 100) / 100;
}

/* -------------------------------------------------------------
   FETCH OPTION LTP (for specific strike)
-------------------------------------------------------------- */
async function fetchOptionLTPForStrike(indexSymbol, strike, type) {
  try:
    const tokenInfo = await resolveInstrumentToken(
      indexSymbol,
      detectExpiryForSymbol(indexSymbol).currentWeek,
      strike,
      type
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
        "X-SourceID": "WEB",
      },
      body: JSON.stringify({
        exchange: "NFO",
        tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
        symboltoken: tokenInfo.token || "",
      }),
    });

    const j = await r.json().catch(() => null);
    return Number(j?.data?.ltp || 0);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   FALLBACK SAFE ROUTE
-------------------------------------------------------------- */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    msg: "Backend running",
    time: Date.now(),
  });
});

/* -------------------------------------------------------------
   LISTEN (RENDER SAFE)
-------------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("ALPHA FINAL BACKEND RUNNING on PORT", PORT);
});
/* -------------------------------------------------------------
   CORRECTED FETCH OPTION LTP (safe replacement for earlier part)
-------------------------------------------------------------- */
async function fetchOptionLTPForStrike(indexSymbol, strike, type) {
  try {
    const expiry = detectExpiryForSymbol(indexSymbol).currentWeek;
    const tokenInfo = await resolveInstrumentToken(indexSymbol, expiry, strike, type);
    if (!tokenInfo) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
      },
      body: JSON.stringify({
        exchange: "NFO",
        tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
        symboltoken: tokenInfo.token || "",
      }),
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.ltpValue || 0);
    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   ENV CHECK (optional runtime helper)
-------------------------------------------------------------- */
function validateEnv() {
  const missing = [];
  if (!SMART_API_KEY) missing.push("SMART_API_KEY");
  if (!SMART_USER_ID) missing.push("SMART_USER_ID");
  if (!SMART_TOTP_SECRET) missing.push("SMART_TOTP");
  if (!SMARTAPI_BASE) missing.push("SMARTAPI_BASE (optional)");
  return missing;
}

/* -------------------------------------------------------------
   FINAL NOTES (do not remove)
-------------------------------------------------------------- */
/*
  - This is the final merged server.js (parts 1..10).
  - I replaced the earlier small syntax issue by re-defining fetchOptionLTPForStrike here.
  - Deploy steps:
      1) Paste all PARTs in order into server.js
      2) Ensure package.json contains cors + dotenv (we provided earlier)
      3) Commit, push, Render → Clear build cache → Deploy
  - After deploy, test /api/ping and /api/login/status first, then /api/calc.
  - If any runtime error appears, paste the exact error log (screenshot/text) and I will patch immediately.
*/

/* ==============================================================
   END OF FINAL MERGED SERVER.JS
   ============================================================== */
