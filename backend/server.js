/* ===========================
   RAHUL FINAL ALPHA - PART 1 (FIXED LTP/ENTRY/SL/TARGET)
   (Paste Part1 then Part2 to form server.js)
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

/* ---------- Frontend Serve (assumes ../frontend) ---------- */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) => res.sendFile(path.join(frontendPath, "settings.html")));

/* ---------- SmartAPI / ENV ---------- */
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || ""; // optional

/* ---------- In-memory session store & cache ---------- */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

let lastKnown = {
  spot: null,
  updatedAt: 0,
};

/* ---------- Utilities: base32 decode + TOTP ---------- */
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

/* ---------- Safe fetch wrapper ---------- */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const j = await r.json().catch(() => null);
    return { ok: true, data: j, status: r.status || 200 };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

/* ---------- SmartAPI Login Implementation ---------- */
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
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
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // ~20 hours

    return { ok: true, raw: data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message || String(err) };
  }
}

/* ---------- Routes: Login / Status / Settings ---------- */
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
    return res.status(400).json({ success: false, error: map[r.reason] || "Login error", raw: r.raw || null });
  }
  return res.json({ success: true, message: "SmartAPI Login Successful", session: { logged_in: true, expires_at: session.expires_at } });
});

app.get("/api/login/status", (req, res) => {
  res.json({ success: true, logged_in: !!session.access_token, expires_at: session.expires_at || null });
});

app.get("/api/settings", (req, res) => {
  res.json({ success: true, apiKey: SMART_API_KEY ? "*****" : "", userId: SMART_USER_ID || "" });
});

/* ---------- Helpers ---------- */
function toNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
function roundToStep(symbol, value) {
  if (!isFinite(value) || value === null) return value;
  if (String(symbol).toUpperCase().includes("GAS") || String(symbol).toUpperCase().includes("NATUR")) {
    return Math.round(value * 20) / 20; // 0.05 rounding
  }
  return Math.round(value); // integer rounding for indices
}
function clamp(v, a, b) {
  if (v === null || v === undefined) return v;
  return Math.max(a, Math.min(b, v));
}

/* ---------- Cache helpers ---------- */
function setLastKnownSpot(val) {
  lastKnown.spot = val;
  lastKnown.updatedAt = Date.now();
}

/* ---------- Option Chain / Futures Fetch Helpers (used by Spot Guardian and engines) ---------- */

/*
  Note: These functions use Angel endpoints as configured. They are defensive and return null on failure.
*/

async function fetchFuturesLTPForSymbol(symbol) {
  try {
    if (!session.access_token) return null;
    // Example Angel endpoint - adjust if your exact path differs
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/marketdata/v1/getLTP`;
    const body = { symbols: [symbol] }; // adapt if needed
    const r = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json", "X-PrivateKey": SMART_API_KEY },
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

async function fetchOptionChainRaw(symbol) {
  try {
    if (!session.access_token) return null;
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/option/v1/option-chain`;
    const r = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json", "X-PrivateKey": SMART_API_KEY },
      body: JSON.stringify({ symbol }),
    });
    const j = await r.json().catch(() => null);
    if (j && j.data && Array.isArray(j.data)) return j.data;
    // sometimes API returns {data:{...}} restructure safe
    if (j && j.data && typeof j.data === "object") {
      // flatten possible structure
      const arr = [];
      Object.keys(j.data).forEach((k) => {
        const item = j.data[k];
        if (Array.isArray(item)) arr.push(...item);
      });
      return arr.length ? arr : null;
    }
    return null;
  } catch (e) {
    return null;
  }
}

function findATMFromOptionChain(rawChain) {
  if (!rawChain || !Array.isArray(rawChain) || !rawChain.length) return null;
  // choose strike closest to median lastPrice-derived underlying if available
  const strikes = [];
  for (const it of rawChain) {
    const s = Number(it.strikePrice || it.strike || it.strike_price);
    if (isFinite(s)) strikes.push(s);
  }
  if (!strikes.length) return null;
  strikes.sort((a, b) => a - b);
  const mid = strikes[Math.floor(strikes.length / 2)];
  return mid || null;
}

/* ---------- Spot-Guardian (core) ---------- */
const SPOT_GUARDIAN_DEFAULT = {
  tolerancePct: 0.0025, // 0.25%
  cacheMaxAgeMs: 1000 * 60 * 5, // 5 min
};

async function spotGuardian(symbol, manualSpot, opts = {}) {
  const conf = Object.assign({}, SPOT_GUARDIAN_DEFAULT, opts || {});
  const result = {
    spot_manual: manualSpot || null,
    spot_used: null,
    spot_source: null,
    spot_corrected: false,
    corrections: {},
    debug: {},
  };

  const setUsed = (val, source, corrected = false, details = {}) => {
    result.spot_used = val;
    result.spot_source = source;
    result.spot_corrected = corrected;
    if (details) result.corrections = details;
    if (val) setLastKnownSpot(val);
  };

  const user = toNumber(manualSpot);

  // 1) If user provided -> verify using futures then option-chain
  if (user && user > 0) {
    const fut = await fetchFuturesLTPForSymbol(symbol).catch(() => null);
    if (fut && fut > 0) {
      const diff = Math.abs(fut - user);
      if (diff / fut <= conf.tolerancePct) {
        setUsed(user, "manual_verified", false, { manual: user, futures: fut });
        return result;
      } else {
        setUsed(fut, "futures_corrected", true, { manual: user, futures: fut });
        return result;
      }
    }
    const oc = await fetchOptionChainRaw(symbol).catch(() => null);
    if (oc) {
      const atm = findATMFromOptionChain(oc);
      if (atm) {
        const diff2 = Math.abs(atm - user);
        if (diff2 / atm <= conf.tolerancePct) {
          setUsed(user, "manual_verified_opchain", false, { manual: user, atm });
          return result;
        } else {
          setUsed(atm, "opchain_corrected", true, { manual: user, atm });
          return result;
        }
      }
    }
    setUsed(user, "manual_best_effort", false, { manual: user });
    return result;
  }

  // 2) If not provided and useLive true -> futures
  if (opts.useLive) {
    const fut2 = await fetchFuturesLTPForSymbol(symbol).catch(() => null);
    if (fut2 && fut2 > 0) {
      setUsed(fut2, "futures_live", false, { fut: fut2 });
      return result;
    }
  }

  // 3) option chain ATM
  const oc2 = await fetchOptionChainRaw(symbol).catch(() => null);
  if (oc2) {
    const atm2 = findATMFromOptionChain(oc2);
    if (atm2) {
      setUsed(atm2, "opchain_atm", false, { atm: atm2 });
      return result;
    }
  }

  // 4) lastKnown
  if (lastKnown.spot && Date.now() - lastKnown.updatedAt <= SPOT_GUARDIAN_DEFAULT.cacheMaxAgeMs) {
    setUsed(lastKnown.spot, "cache", false, { lastKnown: lastKnown.spot, updatedAt: lastKnown.updatedAt });
    return result;
  }

  result.spot_used = null;
  result.spot_source = "none";
  result.spot_corrected = false;
  return result;
}

/* ---------- Option LTP fetch helper for exact strike ---------- */
async function fetchOptionLTPForStrike(symbol, strike, type) {
  try {
    if (!session.access_token) return null;
    const raw = await fetchOptionChainRaw(symbol);
    if (!raw) return null;
    // Normalize optionType detection
    const normalizedType = (type || "").toString().toUpperCase();
    // Search exact match (strike may be number or string)
    let found = raw.find((it) => {
      const s = Number(it.strikePrice || it.strike || it.strike_price);
      const t = (it.optionType || it.option_type || it.type || "").toString().toUpperCase();
      if (!isFinite(s)) return false;
      if (s !== Number(strike)) return false;
      if (!t) return true; // if API doesn't have type, accept by strike
      if (normalizedType === "CE" && (t === "CE" || t === "CALL" || t === "C")) return true;
      if (normalizedType === "PE" && (t === "PE" || t === "PUT" || t === "P")) return true;
      return false;
    });
    if (found) {
      const l = Number(found.lastPrice || found.last || found.lastPriceRaw || 0);
      if (l > 0) return l;
    }
    // If exact not found, try nearest strike of same type
    const candidates = raw
      .map((it) => {
        return { s: Number(it.strikePrice || it.strike || it.strike_price), it };
      })
      .filter((x) => isFinite(x.s));
    if (!candidates.length) return null;
    candidates.sort((a, b) => Math.abs(a.s - Number(strike)) - Math.abs(b.s - Number(strike)));
    for (const c of candidates) {
      const t = (c.it.optionType || c.it.option_type || c.it.type || "").toString().toUpperCase();
      if (!t || normalizedType === "CE" ? (t === "CE" || t === "CALL") : (t === "PE" || t === "PUT")) {
        const l2 = Number(c.it.lastPrice || c.it.last || 0);
        if (l2 > 0) return l2;
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

/* ---------- Fallback premium estimator (sensible) ---------- */
function fallbackPremiumEstimate(symbol, strike, spot) {
  // intrinsic component
  const intrinsicCE = Math.max(0, (spot || 0) - strike);
  const intrinsicPE = Math.max(0, strike - (spot || 0));
  const intrinsic = Math.max(intrinsicCE, intrinsicPE);
  // time value baseline
  let timeValue = 5; // baseline
  // larger underlying => bigger baseline
  if (String(symbol).toUpperCase().includes("NIFTY") || String(symbol).toUpperCase().includes("SENSEX")) {
    timeValue = 5;
  } else {
    timeValue = 2;
  }
  // volatility-ish scale (rough)
  const volFactor = Math.max(1, Math.round((Math.abs(strike - (spot || strike)) / Math.max(1, (spot || strike))) * 100));
  const approx = Math.max(1, +(intrinsic * 0.2 + timeValue + volFactor * 0.05).toFixed(2));
  return approx;
}

/* ---------- Health / ping ---------- */
app.get("/ping", (req, res) => {
  res.json({ ok: true, alive: true, logged_in: !!session.access_token, last_spot: lastKnown.spot || null });
});

/* ---------- Placeholder small engine if external missing ---------- */
function computeTrendSimple(ema20, ema50, rsi, vwap, spot) {
  let score = 0;
  if (!isFinite(ema20) || !isFinite(ema50) || !isFinite(rsi) || !isFinite(vwap) || !isFinite(spot)) {
    return { main: "NEUTRAL", bias: "Neutral", strength: 50, score: 0, reasons: ["incomplete"] };
  }
  if (ema20 > ema50) score += 25;
  if (spot > vwap) score += 20;
  if (rsi > 60) score += 20;
  const main = score > 30 ? "UP" : score < 10 ? "DOWN" : "NEUTRAL";
  const bias = main === "UP" ? "Bullish" : main === "DOWN" ? "Bearish" : "Neutral";
  const strength = Math.min(100, Math.max(0, score));
  return { main, bias, strength, score, reasons: [] };
}

/* ---------- PART 1 COMPLETE - Paste Part 2 next ---------- */
/* ===========================
   RAHUL FINAL ALPHA - PART 2 (FIXED LTP/ENTRY/SL/TARGET)
   (Paste this exactly after Part1)
   =========================== */

/* ---------- Strike Selection Logic ---------- */
function getStrikeSteps(market, days) {
  const m = (market || "").toUpperCase();
  if (m.includes("NIFTY")) {
    if (days >= 10) return 250;
    if (days >= 5) return 200;
    return 150;
  }
  if (m.includes("SENSEX")) {
    if (days >= 10) return 500;
    if (days >= 5) return 400;
    return 300;
  }
  if (m.includes("GAS") || m.includes("NAT")) {
    if (days >= 10) return 0.8;
    if (days >= 5) return 0.6;
    return 0.5;
  }
  return 100;
}

/* ---------- Market Regime Detector ---------- */
function detectMarketRegime(trendObj, volumeSpike, rsi) {
  if (!trendObj) return "UNKNOWN";
  if ((trendObj.main === "UP" || trendObj.main === "DOWN") && trendObj.score > 30 && volumeSpike) return "TRENDING";
  if (trendObj.strength < 20 && !volumeSpike) return "RANGEBOUND";
  if (rsi > 70 || rsi < 30) return "HIGH_VOL";
  return "NORMAL";
}

/* ---------- Volume Spike Detector ---------- */
function detectVolumeSpike(vol) {
  if (!isFinite(vol)) return false;
  return vol > 1.8;
}

/* ---------- Fake Breakout Rejection ---------- */
function rejectFakeBreakout(trendObj, volumeSpike, futDiff) {
  if (!trendObj) return true;
  if (!volumeSpike && trendObj.score < 20) return true;
  if (futDiff && Math.abs(futDiff) > 40) return true;
  return false;
}

/* ---------- Entry Calibration PRO ---------- */
function calibratedEntryPrice(baseLtp, regime, volRank, trendStrength) {
  // baseLtp assumed numeric > 0
  if (!isFinite(baseLtp) || baseLtp <= 0) return null;
  let adj = 0;
  const b = Number(baseLtp);

  // small % adjustments based on regime
  if (regime === "TRENDING") adj += b * 0.015;
  if (regime === "RANGEBOUND") adj -= b * 0.02;
  if (regime === "HIGH_VOL") adj += b * 0.03;

  if (volRank === "HIGH") adj += b * 0.02;
  if (volRank === "LOW") adj -= b * 0.01;

  // trendStrength contribution (0-100), small factor
  adj += b * (Math.min(80, Math.max(0, trendStrength)) / 100) * 0.01;

  const finalEntry = b + adj;
  return Math.max(1, Math.round(finalEntry * 100) / 100);
}

/* ---------- Target / SL Logic ---------- */
function computeSL(entry) {
  if (!isFinite(entry) || entry <= 0) return null;
  const sl = entry - 15;
  return Math.round(Math.max(0.01, sl) * 100) / 100;
}

function computeTarget(entry, strength, regime) {
  if (!isFinite(entry) || entry <= 0) return null;
  // base target: either fixed minimal or percentage of entry
  const base = Math.max(6.13, entry * 0.12); // at least 6.13 or 12% of entry
  let extra = 0;
  if (regime === "TRENDING") extra += 0.08 * entry;
  if (regime === "HIGH_VOL") extra += 0.12 * entry;
  if (strength > 60) extra += 0.05 * entry;
  const t = entry + base + extra;
  return Math.round(t * 100) / 100;
}

/* ---------- VolRank helper ---------- */
function getVolRank(ocData) {
  if (!ocData || !ocData.length) return "NORMAL";
  const arr = ocData.map((x) => Number(x.impliedVolatility || x.iv || 0)).filter((v) => isFinite(v) && v > 0);
  const avg = arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 16;
  if (avg > 22) return "HIGH";
  if (avg < 14) return "LOW";
  return "NORMAL";
}

/* ---------- Main Suggestion Route (fixed logic) ---------- */
app.post("/api/suggest", async (req, res) => {
  try {
    const body = req.body || {};
    const ema20 = toNumber(body.ema20);
    const ema50 = toNumber(body.ema50);
    const rsi = toNumber(body.rsi);
    const vwap = toNumber(body.vwap);
    const manualSpot = toNumber(body.spot);
    const days = Number(body.expiry_days || body.expiryDays || 7);
    const market = (body.market || "NIFTY").toUpperCase();
    const useLive = !!body.useLive;

    // 1) Resolve spot
    const sFix = await spotGuardian(market, manualSpot, { useLive });
    const finalSpot = toNumber(sFix.spot_used);
    if (!isFinite(finalSpot) || finalSpot <= 0) {
      return res.json({ success: false, error: "Unable to resolve spot", guardian: sFix });
    }

    // 2) Compute trend
    const trendObj = computeTrendSimple(ema20, ema50, rsi, vwap, finalSpot);

    // 3) Volume spike & futures
    const volumeSpike = detectVolumeSpike(1.2); // placeholder; replace with real volume if available
    const fut = await fetchFuturesLTPForSymbol(market);
    const futDiff = fut ? fut - finalSpot : 0;

    // 4) Fake breakout rejection
    const isFake = rejectFakeBreakout(trendObj, volumeSpike, futDiff);
    if (isFake) {
      return res.json({
        success: false,
        error: "Fake breakout detected — no safe entry",
        trend: trendObj,
        guardian: sFix,
      });
    }

    // 5) Regime and oc raw
    const regime = detectMarketRegime(trendObj, volumeSpike, rsi);
    const ocRaw = await fetchOptionChainRaw(market);
    const volRank = getVolRank(ocRaw || []);

    // 6) strike steps & selection
    const step = getStrikeSteps(market, days);
    const atm = roundToStep(market, finalSpot);
    const strikeA = roundToStep(market, atm + step);
    const strikeB = roundToStep(market, atm - step);
    const strikeC = atm;

    const strikes = [strikeA, strikeB, strikeC];

    // 7) Build final list with correct LTP->entry->SL->target
    const finalList = [];
    for (const st of strikes) {
      // choose type by trend: UP -> CE first, DOWN -> PE first, NEUTRAL -> CE then PE
      let type = "CE";
      if (trendObj.main === "DOWN") type = "PE";
      if (trendObj.main === "NEUTRAL") type = "CE";

      // fetch actual option LTP for that strike+type
      let baseLtp = await fetchOptionLTPForStrike(market, st, type);
      if (!baseLtp) {
        // if not found for chosen type, try opposite type
        const altType = type === "CE" ? "PE" : "CE";
        baseLtp = await fetchOptionLTPForStrike(market, st, altType);
      }

      // fallback estimate if still null
      if (!baseLtp || !isFinite(baseLtp) || baseLtp <= 0) {
        baseLtp = fallbackPremiumEstimate(market, st, finalSpot);
      }

      // calibrated entry based on baseLtp and regime
      const entry = calibratedEntryPrice(baseLtp, regime, volRank, trendObj.strength) || Math.max(1, baseLtp);
      const stopLoss = computeSL(entry);
      const target = computeTarget(entry, trendObj.strength, regime);

      finalList.push({
        strike: st,
        distance: Math.abs(st - atm),
        baseLtp: Math.round(baseLtp * 100) / 100,
        entry,
        stopLoss,
        target,
      });
    }

    return res.json({
      success: true,
      trend: trendObj,
      input: { ema20, ema50, rsi, vwap, spot: finalSpot, expiry_days: days, market },
      regime,
      volRank,
      strikes: finalList,
      guardian: sFix,
      login_status: session.access_token ? "Logged-in" : "Not logged",
    });
  } catch (err) {
    return res.json({ success: false, error: err.message || String(err) });
  }
});

/* ---------- Start Server ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("RAHUL FINAL ALPHA running on PORT", PORT);
});

/* ---------- END OF ALPHA ---------- */
