/* ===========================================================
   RAHUL — GAMMA SERVER (UPDATED WITH SOFT FAKE BREAKOUT FILTER)
   PART 1 OF 2
=========================================================== */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();
const moment = require("moment");

/* ---------- Express Setup ---------- */
const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

/* ---------- Frontend Static Paths ---------- */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) => res.sendFile(path.join(frontendPath, "settings.html")));

/* ---------- SmartAPI ENV (KEEP as-is) ---------- */
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
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

/* ---------- BASE32 Decoder ---------- */
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

/* ---------- TOTP Generator ---------- */
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

/* ---------- SmartAPI Login ---------- */
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID)
    return { ok: false, reason: "ENV_MISSING" };
  if (!tradingPassword) return { ok: false, reason: "PASSWORD_MISSING" };

  const totp = generateTOTP(SMART_TOTP_SECRET);
  if (!totp) return { ok: false, reason: "TOTP_FAIL" };

  try {
    const url = `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`;

    const r = await fetch(url, {
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
        totp,
      }),
    });

    const j = await r.json().catch(() => null);
    if (!j || j.status === false) return { ok: false, reason: "LOGIN_FAILED", raw: j };

    const d = j.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 1000 * 60 * 60 * 20;

    return { ok: true, raw: j };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

/* ---------- Login API ---------- */
app.post("/api/login", async (req, res) => {
  const pass = req.body.password || "";
  const r = await smartApiLogin(pass);

  if (!r.ok) {
    return res.status(400).json({
      success: false,
      error: r.reason,
      raw: r.raw || null,
    });
  }

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: { logged_in: true, expires_at: session.expires_at },
  });
});

/* ---------- Number Helper ---------- */
function toNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/* ---------- Round Strike ---------- */
function roundToStep(symbol, value) {
  if (String(symbol).includes("GAS")) return Math.round(value * 20) / 20;
  return Math.round(value);
}

/* ---------- Cache Spot Setter ---------- */
function setLastKnownSpot(v) {
  lastKnown.spot = v;
  lastKnown.updatedAt = Date.now();
}

/* ---------- Fetch Futures LTP ---------- */
async function fetchFuturesLTPForSymbol(symbol) {
  try {
    if (!session.access_token) return null;
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/marketdata/v1/getLTP`;

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
    if (j && j.data && Array.isArray(j.data) && j.data.length) {
      const v = Number(j.data[0].lastPrice || j.data[0].ltp || 0);
      return v > 0 ? v : null;
    }
    return null;
  } catch {
    return null;
  }
}

/* ---------- Fetch Option Chain ---------- */
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
    return j?.data || null;
  } catch {
    return null;
  }
}

/* ---------- ATM finder ---------- */
function findATMFromOptionChain(rawChain) {
  if (!rawChain || !rawChain.length) return null;
  const strikes = rawChain.map((it) => Number(it.strikePrice));
  strikes.sort((a, b) => a - b);
  return strikes[Math.floor(strikes.length / 2)];
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

  const setUsed = (val, src, corrected = false, details = {}) => {
    result.spot_used = val;
    result.spot_source = src;
    result.spot_corrected = corrected;
    result.corrections = details;
    if (val) setLastKnownSpot(val);
  };

  const user = toNumber(manualSpot);

  if (user && !opts.useLive) {
    setUsed(user, "manual_primary");
    return result;
  }

  if (opts.useLive) {
    const fut = await fetchFuturesLTPForSymbol(symbol);
    if (fut) {
      setUsed(fut, "futures_live");
      return result;
    }
  }

  const oc = await fetchOptionChainRaw(symbol);
  if (oc) {
    const atm = findATMFromOptionChain(oc);
    if (atm) {
      setUsed(atm, "opchain_atm");
      return result;
    }
  }

  if (lastKnown.spot && Date.now() - lastKnown.updatedAt < conf.cacheMaxAgeMs) {
    setUsed(lastKnown.spot, "cache");
    return result;
  }

  setUsed(user || null, "none");
  return result;
}

/* ---------- Candle Fetcher ---------- */
async function fetchRecentCandles(symbolOrToken, timeframe = 1, count = 100) {
  try {
    if (!session.access_token) return [];
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/marketdata/v1/getCandles`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify({
        symbol: symbolOrToken,
        interval: `${timeframe}m`,
        count,
      }),
    });

    const j = await r.json().catch(() => null);
    return Array.isArray(j?.data) ? j.data : [];
  } catch {
    return [];
  }
}
/* ---------- EMA Calculation ---------- */
function computeEMA(values, period) {
  if (!values || values.length < period) return null;
  const k = 2 / (period + 1);
  let ema = values.slice(0, period).reduce((a, b) => a + b, 0) / period;
  for (let i = period; i < values.length; i++) {
    ema = values[i] * k + ema * (1 - k);
  }
  return ema;
}

/* ---------- RSI Calculation ---------- */
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
    if (diff > 0)
      avgGain = (avgGain * (period - 1) + diff) / period;
    else
      avgLoss = (avgLoss * (period - 1) + Math.abs(diff)) / period;
  }

  if (avgLoss === 0) return 100;
  const rs = avgGain / avgLoss;
  return 100 - 100 / (1 + rs);
}

/* ---------- Hybrid Trend Engine ---------- */
async function hybridTrendEngine(indexSymbol) {
  try {
    const c5 = await fetchRecentCandles(indexSymbol, 5, 60);
    const c1 = await fetchRecentCandles(indexSymbol, 1, 120);

    const closes5 = c5.map((x) => Number(x.close) || 0);
    const closes1 = c1.map((x) => Number(x.close) || 0);

    const ema20 = computeEMA(closes5, 20);
    const ema50 = computeEMA(closes5, 50);
    const rsi = computeRSI(closes1, 14);

    const recent = closes1.slice(-6);
    const last = recent.at(-1);
    const prevAvg = recent.slice(0, -1).reduce((a, b) => a + b, 0) / Math.max(1, recent.length - 1);

    const momentum = last - prevAvg;
    const momPct = prevAvg ? momentum / prevAvg : 0;

    let score = 0;
    if (ema20 && ema50) {
      score += ema20 > ema50 ? 30 : -30;
    }

    if (rsi != null) {
      score += rsi > 55 ? 15 : rsi < 45 ? -15 : 0;
    }

    score += Math.max(-20, Math.min(20, Math.round(momPct * 100)));

    const main =
      score > 10 ? "UP" : score < -10 ? "DOWN" : "NEUTRAL";

    return {
      main,
      confidence: Math.min(1, Math.abs(score) / 60),
      score,
    };
  } catch {
    return { main: "NEUTRAL", confidence: 0.2, score: 0 };
  }
}

/* ---------- Expiry Detector ---------- */
function detectExpiryForSymbol(symbol) {
  const ref = moment().utcOffset("+05:30");
  let th = ref.clone().isoWeekday(4);

  if (ref.isoWeekday() > 4) th.add(1, "week");

  return { currentWeek: th.format("YYYY-MM-DD") };
}

/* ---------- Strike Distance ---------- */
function computeStrikeDistanceByExpiry(daysToExpiry, baseStepCount = 1) {
  if (daysToExpiry <= 3) return baseStepCount * 1;
  if (daysToExpiry <= 7) return baseStepCount * 2;
  return baseStepCount * 3;
}

/* ---------- Strike Steps ---------- */
function getStrikeSteps(market, days) {
  if (market === "NIFTY") return days >= 5 ? 200 : 150;
  if (market === "BANKNIFTY") return 100;
  if (market === "SENSEX") return 300;
  if (market.includes("GAS")) return 0.5;
  return 100;
}

/* ---------- Token Resolver ---------- */
async function resolveInstrumentToken(symbol, expiry, strike, type) {
  const raw = await fetchOptionChainRaw(symbol);
  if (!raw) return null;

  const exact = raw.find(
    (x) =>
      Number(x.strikePrice) === Number(strike) &&
      String(x.optionType).toUpperCase() === type
  );

  if (exact)
    return {
      token: exact.token || exact.instrumentToken || null,
      instrument: exact,
    };

  let nearest = null;
  for (const x of raw) {
    if (String(x.optionType).toUpperCase() !== type) continue;

    const diff = Math.abs(Number(x.strikePrice) - strike);
    if (!nearest || diff < nearest.diff)
      nearest = { item: x, diff };
  }

  if (nearest?.item)
    return {
      token: nearest.item.token || nearest.item.instrumentToken || null,
      instrument: nearest.item,
    };

  return null;
}

/* ---------- Fetch Option LTP ---------- */
async function fetchOptionLTPForStrike(symbol, strike, type) {
  const info = await resolveInstrumentToken(symbol, null, strike, type);

  if (info?.instrument) {
    const p = Number(info.instrument.lastPrice || 0);
    return p > 0 ? p : null;
  }
  return null;
}

/* ---------- Soft Fake Breakout Filter (UPDATED IN GAMMA) ---------- */
function rejectFakeBreakout(trendObj, volumeSpike, futDiff) {
  if (!trendObj) return true;

  // Softened trend threshold
  if (!volumeSpike && trendObj.score < 5) return true;

  // Softened futures difference threshold
  if (futDiff && Math.abs(futDiff) > 80) return true;

  return false;
}

/* ---------- SL Calculation ---------- */
function computeSL(entry) {
  return Math.round((entry - 15) * 100) / 100;
}

/* ---------- Smart Entry Engine ---------- */
async function computeSmartEntry(ctx) {
  const { indexSymbol, strike, type, trendObj } = ctx;

  let candles = await fetchRecentCandles(indexSymbol, 1, 60);
  if (!candles || candles.length < 6) return { entry: null };

  const closes = candles.map((c) => Number(c.close));
  const highs = candles.map((c) => Number(c.high));
  const lows = candles.map((c) => Number(c.low));

  const last = closes.at(-1);
  const prev = closes.at(-2);

  const high10 = Math.max(...highs.slice(-10));
  const low10 = Math.min(...lows.slice(-10));

  let entry = last;

  if (type === "CE") {
    entry = last > high10 && last > prev ? last + 0.5 : last + 0.3;
  } else {
    entry = last < low10 && last < prev ? last - 0.5 : last - 0.3;
  }

  const ltp = await fetchOptionLTPForStrike(indexSymbol, strike, type);
  if (ltp && Math.abs(entry - ltp) / Math.max(1, ltp) > 0.50) entry = ltp;

  return { entry: Math.round(entry * 100) / 100 };
}

/* ---------- Target Engine ---------- */
function targetEngine(entry, momentumStrength = 1, trendConfidence = 0.5) {
  const raw = entry + momentumStrength * trendConfidence;
  return Math.round(raw * 100) / 100;
}

/* ---------- MAIN ENGINE /api/calc ---------- */
app.post("/api/calc", async (req, res) => {
  try {
    const { spot, expiry_days, market, use_live } = req.body;

    const mkt = String(market || "").toUpperCase();
    const days = Number(expiry_days || 7);

    const sFix = await spotGuardian(mkt, spot, { useLive: use_live });
    const finalSpot = sFix.spot_used;

    const trend = await hybridTrendEngine(mkt);
    const fut = await fetchFuturesLTPForSymbol(mkt);
    const futDiff = fut ? fut - finalSpot : 0;

    const volumeSpike = false;

    const reject = rejectFakeBreakout(trend, volumeSpike, futDiff);

    if (reject) {
      return res.json({
        success: false,
        error: "Fake breakout detected — no safe entry",
        trend,
      });
    }

    const expiry = detectExpiryForSymbol(mkt).currentWeek;

    const step = getStrikeSteps(mkt, days);
    const dist = computeStrikeDistanceByExpiry(days, 1) * step;

    const atm = roundToStep(mkt, finalSpot);
    const strikes = [atm, atm + dist, atm - dist];

    const output = [];

    for (const st of strikes) {
      const ceEntryObj = await computeSmartEntry({
        indexSymbol: mkt,
        strike: st,
        type: "CE",
        trendObj: trend,
      });

      const peEntryObj = await computeSmartEntry({
        indexSymbol: mkt,
        strike: st,
        type: "PE",
        trendObj: trend,
      });

      let chosenType =
        trend.main === "UP"
          ? "CE"
          : trend.main === "DOWN"
          ? "PE"
          : (ceEntryObj.entry || 0) > (peEntryObj.entry || 0)
          ? "CE"
          : "PE";

      const chosenEntry =
        chosenType === "CE" ? ceEntryObj.entry : peEntryObj.entry;

      const sl = computeSL(chosenEntry);
      const target = targetEngine(chosenEntry, 1, trend.confidence);

      output.push({
        strike: st,
        type: chosenType,
        entry: chosenEntry,
        stopLoss: sl,
        target,
      });
    }

    return res.json({
      success: true,
      trend,
      strikes: output,
    });
  } catch (err) {
    return res.json({
      success: false,
      error: err.message,
    });
  }
});

/* ---------- Alias ---------- */
app.post("/api/suggest", (req, res) => {
  req.url = "/api/calc";
  app._router.handle(req, res);
});

/* ---------- Ping ---------- */
app.get("/ping", (req, res) => {
  res.json({
    ok: true,
    logged_in: !!session.access_token,
    last_spot: lastKnown.spot,
  });
});

/* ---------- Start Server ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log("RAHUL — GAMMA (Soft Filter Applied) running on PORT", PORT)
);

/* ===========================
   END OF GAMMA (Part 2/2)
=========================== */
