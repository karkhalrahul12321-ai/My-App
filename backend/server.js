/* ===========================
   RAHUL FINAL ALPHA (SYNCED BUILD)
   PART 1 OF 2
   =========================== */

/* ---------- Imports & Config ---------- */
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();

/* ---------- App Init ---------- */
const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

/* ---------- Frontend Serve ---------- */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) => res.sendFile(path.join(frontendPath, "settings.html")));

/* ---------- SmartAPI ENV ---------- */
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";

/* ---------- Session Store ---------- */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

/* ---------- Last Known Spot Cache ---------- */
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
    const resp = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
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
    });

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

/* ---------- Login Routes ---------- */
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
  if (String(symbol).toUpperCase().includes("GAS") || String(symbol).toUpperCase().includes("NATUR")) {
    return Math.round(value * 20) / 20;
  }
  return Math.round(value);
}

function setLastKnownSpot(val) {
  lastKnown.spot = val;
  lastKnown.updatedAt = Date.now();
}

/* ---------- Fetch Futures LTP ---------- */
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

/* ---------- Fetch Option-Chain RAW ---------- */
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

/* ---------- ATM From Option Chain ---------- */
function findATMFromOptionChain(rawChain) {
  if (!rawChain || !Array.isArray(rawChain) || !rawChain.length) return null;
  const strikes = rawChain.map((it) => Number(it.strikePrice));
  strikes.sort((a, b) => a - b);
  return strikes[Math.floor(strikes.length / 2)] || null;
}

/* ---------- Spot Guardian ---------- */
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

  /* USER MANUAL SPOT */
  if (user && user > 0 && !opts.useLive) {
    setUsed(user, "manual_primary");
    return result;
  }

  /* LIVE FUTURES */
  if (opts.useLive) {
    const fut = await fetchFuturesLTPForSymbol(symbol).catch(() => null);
    if (fut && fut > 0) {
      setUsed(fut, "futures_live");
      return result;
    }
  }

  /* OPTION CHAIN FALLBACK */
  const oc = await fetchOptionChainRaw(symbol).catch(() => null);
  if (oc) {
    const atm = findATMFromOptionChain(oc);
    if (atm) {
      setUsed(atm, "opchain_atm");
      return result;
    }
  }

  /* LAST KNOWN */
  if (lastKnown.spot && Date.now() - lastKnown.updatedAt <= conf.cacheMaxAgeMs) {
    setUsed(lastKnown.spot, "cache");
    return result;
  }

  result.spot_used = user || null;
  result.spot_source = "none";
  return result;
}

/* ---------- Trend Simple ---------- */
function computeTrendSimple(ema20, ema50, rsi, vwap, spot) {
  let score = 0;
  if (!isFinite(ema20) || !isFinite(ema50) || !isFinite(rsi) || !isFinite(vwap) || !isFinite(spot)) {
    return { main: "NEUTRAL", bias: "Neutral", strength: 0, score: 0 };
  }

  if (ema20 > ema50) score += 25;
  if (spot > vwap) score += 20;
  if (rsi > 60) score += 20;

  const main = score > 30 ? "UP" : score < 10 ? "DOWN" : "NEUTRAL";
  const bias = main === "UP" ? "Bullish" : main === "DOWN" ? "Bearish" : "Neutral";
  const strength = Math.min(100, Math.max(0, score));

  return { main, bias, strength, score };
}

/* ---------- Health ---------- */
app.get("/ping", (req, res) => {
  res.json({
    ok: true,
    alive: true,
    logged_in: !!session.access_token,
    last_spot: lastKnown.spot || null,
  });
});

/* ===========================
   END OF PART 1 — COPY PART 2 ALSO
   =========================== */
/* ===========================
   RAHUL FINAL ALPHA (SYNCED BUILD)
   PART 2 OF 2
   =========================== */

/* ---------- Strike step sizes depending on market ---------- */
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
  return 100;
}

/* ---------- Volume Spike Detector (placeholder) ---------- */
function detectVolumeSpike(vol) {
  if (!isFinite(vol)) return false;
  return vol > 1.8;
}

/* ---------- Market Regime Detector ---------- */
function detectMarketRegime(trendObj, volumeSpike, rsi) {
  if (!trendObj) return "UNKNOWN";

  if (trendObj.main === "UP" && trendObj.score > 30 && volumeSpike) return "TRENDING";
  if (trendObj.main === "DOWN" && trendObj.score > 20 && volumeSpike) return "TRENDING";

  if (trendObj.strength < 20 && !volumeSpike) return "RANGEBOUND";

  if (rsi > 70 || rsi < 30) return "HIGH_VOL";

  return "NORMAL";
}

/* ---------- Fake Breakout Rejection ---------- */
function rejectFakeBreakout(trendObj, volumeSpike, futDiff) {
  if (!trendObj) return true;

  if (!volumeSpike && trendObj.score < 20) return true;

  if (futDiff && Math.abs(futDiff) > 40) return true;

  return false;
}

/* ---------- VolRank helper ---------- */
function getVolRank(ocData) {
  if (!ocData || !ocData.length) return "NORMAL";
  const avg = ocData.reduce((a, b) => a + (Number(b.impliedVolatility) || 0), 0) / ocData.length;
  if (avg > 22) return "HIGH";
  if (avg < 14) return "LOW";
  return "NORMAL";
}

/* ---------- Entry Calibration PRO ---------- */
function calibratedEntryPrice(baseLtp, regime, volRank) {
  if (!isFinite(baseLtp) || baseLtp <= 0) return baseLtp;

  let adj = 0;

  if (regime === "TRENDING") adj += baseLtp * 0.015;
  if (regime === "RANGEBOUND") adj -= baseLtp * 0.02;
  if (regime === "HIGH_VOL") adj += baseLtp * 0.03;

  if (volRank === "HIGH") adj += baseLtp * 0.02;
  if (volRank === "LOW") adj -= baseLtp * 0.01;

  const finalEntry = baseLtp + adj;
  return Math.max(1, Math.round(finalEntry * 100) / 100);
}

/* ---------- Stop-loss & Target ---------- */
function computeSL(entry) {
  if (!isFinite(entry)) return null;
  return Math.round((entry - 15) * 100) / 100;
}

function computeTarget(entry, strength, regime) {
  if (!isFinite(entry)) return null;

  let t = entry + 25;

  if (regime === "TRENDING") t += 12;
  if (regime === "HIGH_VOL") t += 18;
  if (regime === "RANGEBOUND") t -= 10;

  if (strength > 60) t += 10;

  return Math.round(t * 100) / 100;
}

/* ---------- Fetch Option LTP For Exact Strike ---------- */
async function fetchOptionLTPForStrike(symbol, strike, type) {
  try {
    if (!session.access_token) return null;
    const raw = await fetchOptionChainRaw(symbol);
    if (!raw) return null;

    const found = raw.find(
      (it) =>
        Number(it.strikePrice) === Number(strike) &&
        ((it.optionType === "CE" && type === "CE") ||
          (it.optionType === "PE" && type === "PE"))
    );

    if (found) {
      const l = Number(found.lastPrice || found.last || 0);
      return l > 0 ? l : null;
    }

    // fallback nearest strike
    const near = raw.reduce((acc, it) => {
      const diff = Math.abs(Number(it.strikePrice) - Number(strike));
      if (acc === null || diff < acc.diff) return { item: it, diff };
      return acc;
    }, null);

    if (near && near.item) {
      const l2 = Number(near.item.lastPrice || near.item.last || 0);
      return l2 > 0 ? l2 : null;
    }

    return null;
  } catch (e) {
    return null;
  }
}

/* ===========================================================
   FULL CALCULATION ROUTE — SYNCED WITH FRONTEND (/api/calc)
   =========================================================== */

app.post("/api/calc", async (req, res) => {
  try {
    const { ema20, ema50, rsi, vwap, spot, expiry_days, market, use_live } = req.body || {};

    const mkt = (market || "").toUpperCase();
    const days = Number(expiry_days) || 7;

    /* ----------- Spot Guardian ----------- */
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

    /* ----------- Trend Engine ----------- */
    const trendObj = computeTrendSimple(
      toNumber(ema20),
      toNumber(ema50),
      toNumber(rsi),
      toNumber(vwap),
      finalSpot
    );

    /* Fallback: If trend incomplete, still continue safely */

    /* ----------- Futures diff for fake breakout check ----------- */
    const fut = await fetchFuturesLTPForSymbol(mkt);
    const futDiff = fut ? fut - finalSpot : 0;

    /* ----------- Fake Breakout Check ----------- */
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

    /* ----------- Market Regime ----------- */
    const regime = detectMarketRegime(trendObj, volumeSpike, toNumber(rsi));

    /* ----------- OC Raw + Vol Rank ----------- */
    const ocRaw = await fetchOptionChainRaw(mkt);
    const volRank = getVolRank(ocRaw || []);

    /* ----------- Strike Steps ----------- */
    const step = getStrikeSteps(mkt, days);

    const atm = roundToStep(mkt, finalSpot);
    const s1 = atm + step;
    const s2 = atm - step;
    const s3 = atm;

    const strikes = [s1, s2, s3];

    /* ----------- Build Strike Objects ----------- */
    const fullList = [];

    for (let st of strikes) {
      let type = "CE";
      if (trendObj.main === "DOWN") type = "PE";

      const baseLtp = await fetchOptionLTPForStrike(mkt, st, type);
      const entry = calibratedEntryPrice(baseLtp || 5, regime, volRank);
      const sl = computeSL(entry);
      const target = computeTarget(entry, trendObj.strength, regime);

      fullList.push({
        strike: st,
        distance: Math.abs(st - atm),
        entry,
        stopLoss: sl,
        target,
      });
    }

    /* ----------- Final Response (Frontend Expected Format) ----------- */
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
      },

      volRank,
      strikes: fullList,
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

/* ---------- ALIAS ROUTE (OPTIONAL) ---------- */
app.post("/api/suggest", (req, res) => {
  req.url = "/api/calc";
  app._router.handle(req, res);
});

/* ---------- Start Server ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("RAHUL FINAL ALPHA (SYNCED BUILD) running on PORT", PORT);
});

/* ===========================
   END OF PART 2
   =========================== */
