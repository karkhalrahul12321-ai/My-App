/**
 * Alpha - UPDATED server.js
 * Part-1 of 3 (LRUCache Fix Applied)
 */

const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const crypto = require('crypto');
const moment = require('moment');

// 🔥 NEW FIXED LRU import
const { LRUCache } = require('lru-cache');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

const SMART_API_KEY = process.env.SMART_API_KEY || 'REPLACE_SMART_API_KEY';
const SMART_API_SECRET = process.env.SMART_API_SECRET || 'REPLACE_SMART_API_SECRET';
const SMART_TOTP = process.env.SMART_TOTP || 'REPLACE_SMART_TOTP';
const SMART_USER_ID = process.env.SMART_USER_ID || 'REPLACE_SMART_USER_ID';

/* ===========================
   FIXED — new LRUCache()
   =========================== */

const cache = new LRUCache({
  max: 500,
  ttl: 1000 * 60 * 5
});

function safeParseFloat(v, fallback = 0) {
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : fallback;
}

function roundToTick(value, tick = 1) {
  return Math.round(value / tick) * tick;
}

function nowISO() {
  return new Date().toISOString();
}

function log(...args) {
  console.log(`[${nowISO()}]`, ...args);
}

function asyncHandler(fn) {
  return function (req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/* =========================== */

function detectMarket(payload) {
  if (!payload) return 'Nifty';
  const m = (payload.market || '').toLowerCase();
  if (m.includes('nifty')) return 'Nifty';
  if (m.includes('sensex') || m.includes('bank')) return 'Sensex';
  if (m.includes('natgas') || m.includes('natural')) return 'NaturalGas';
  return 'Nifty';
}

/* ===========================
   getVolRank — already fixed version
   =========================== */

function getVolRank(symbol, optionData = []) {
  if (!Array.isArray(optionData) || optionData.length === 0) {
    return { rankMap: {}, sorted: [], scoreExplanation: 'no-data' };
  }

  let maxVol = 0, maxOI = 0, maxIV = 0;
  for (const d of optionData) {
    const v = Math.max(0, safeParseFloat(d.volume));
    const oi = Math.max(0, safeParseFloat(d.oi));
    const iv = Math.max(0, safeParseFloat(d.iv));
    if (v > maxVol) maxVol = v;
    if (oi > maxOI) maxOI = oi;
    if (iv > maxIV) maxIV = iv;
  }

  maxVol = Math.max(1, maxVol);
  maxOI = Math.max(1, maxOI);
  maxIV = Math.max(1, maxIV);

  const wVol = 0.55;
  const wOI = 0.30;
  const wIV = 0.15;

  const scored = optionData.map(d => {
    const vol = safeParseFloat(d.volume, 0);
    const oi = safeParseFloat(d.oi, 0);
    const iv = safeParseFloat(d.iv, 0);

    const nVol = vol / maxVol;
    const nOI = oi / maxOI;
    const nIV = iv / maxIV;

    const score = (nVol * wVol) + (nOI * wOI) + (nIV * wIV);

    return {
      ...d,
      vol, oi, iv, score
    };
  });

  scored.sort((a, b) => b.score - a.score);

  const rankMap = {};
  const sorted = [];
  for (let i = 0; i < scored.length; i++) {
    const s = scored[i];
    rankMap[s.strike] = i + 1;
    sorted.push({
      strike: s.strike,
      score: Number(s.score.toFixed(6)),
      vol: s.vol,
      oi: s.oi,
      iv: s.iv
    });
  }

  return {
    rankMap,
    sorted,
    scoreExplanation: `weights(vol:${wVol},oi:${wOI},iv:${wIV}) maxVol:${maxVol} maxOI:${maxOI} maxIV:${maxIV}`
  };
}

/* ===========================
   Safe Filters (unchanged)
   =========================== */

function applySafeFilters(optionBucket = [], opts = {}) {
  const minVolume = opts.minVolume ?? 10;
  const minOI = opts.minOI ?? 50;
  const maxIV = opts.maxIV ?? 200;
  const maxRank = opts.maxRank ?? 50;

  const { rankMap, sorted } = getVolRank("bulk", optionBucket);

  const filtered = optionBucket.filter(d => {
    const vol = safeParseFloat(d.volume, 0);
    const oi = safeParseFloat(d.oi, 0);
    const iv = safeParseFloat(d.iv, 0);
    const rank = rankMap[d.strike] || Number.MAX_SAFE_INTEGER;

    if (vol < minVolume) return false;
    if (oi < minOI) return false;
    if (iv > maxIV) return false;
    if (rank > maxRank) return false;

    return true;
  });

  return {
    filtered,
    debug: {
      applied: { minVolume, minOI, maxIV, maxRank },
      totalBefore: optionBucket.length,
      totalAfter: filtered.length,
      topByScore: sorted.slice(0, 10)
    }
  };
}

/* =========================== */

function calculateTrend(metrics = {}) {
  const ema20 = safeParseFloat(metrics.ema20, 0);
  const ema50 = safeParseFloat(metrics.ema50, 0);
  const rsi = safeParseFloat(metrics.rsi, 50);
  const vwap = safeParseFloat(metrics.vwap, 0);
  const spot = safeParseFloat(metrics.spot, 0);

  let score = 0;

  if (ema20 > ema50) score += 0.45;
  else score -= 0.45;

  if (spot > vwap) score += 0.25;
  else score -= 0.25;

  if (rsi > 60) score += 0.15;
  else if (rsi < 40) score -= 0.15;

  score = Math.max(-1, Math.min(1, score));

  let trend = "NEUTRAL";
  if (score >= 0.25) trend = "BULL";
  else if (score <= -0.25) trend = "BEAR";

  return {
    trend,
    confidence: Number(Math.abs(score).toFixed(3)),
    explanation: `score:${score.toFixed(3)} (ema20:${ema20},ema50:${ema50},vwap:${vwap},rsi:${rsi},spot:${spot})`
  };
}

function suggestStrikesByTrend({ spot, trend, expiryDays, strikeStep = 50, maxDistance = 1000 }) {
  const atm = roundToTick(spot, strikeStep);
  const out = [];

  out.push({ type: "ATM", strike: atm });

  if (trend === "BULL") {
    out.push({ type: "NEAR1", strike: atm + strikeStep });
    out.push({ type: "NEAR2", strike: atm + strikeStep * 2 });
  } else if (trend === "BEAR") {
    out.push({ type: "NEAR1", strike: atm - strikeStep });
    out.push({ type: "NEAR2", strike: atm - strikeStep * 2 });
  } else {
    out.push({ type: "NEAR1", strike: atm - strikeStep });
    out.push({ type: "NEAR2", strike: atm + strikeStep });
  }

  return {
    atm,
    strikes: out.filter(x => Math.abs(x.strike - atm) <= maxDistance)
  };
}

app.get("/health", (req, res) => {
  res.json({ ok: true, time: nowISO(), version: "Alpha-part1-updated" });
});

/* Part-1 Ends Here */
/**
 * Alpha - UPDATED server.js
 * Part-2 of 3 (LRUCache Fix Applied)
 */

/* ===========================
   SmartAPI: Auth/session helpers
   =========================== */

// 🔥 FIXED — new LRUCache()
const sessionCache = new LRUCache({
  max: 50,
  ttl: 1000 * 60 * 30
});

async function smartApiLogin() {
  const cached = sessionCache.get("smart_session");
  if (cached && cached.token) return cached;

  const token = "FAKE-" + Date.now();
  const session = {
    token,
    createdAt: Date.now(),
    expiresAt: Date.now() + 1000 * 60 * 25
  };

  sessionCache.set("smart_session", session);
  log("smartApiLogin: new session created");

  return session;
}

async function smartApiAuthHeaders() {
  const s = await smartApiLogin();
  return {
    "Content-Type": "application/json",
    "x-api-key": SMART_API_KEY,
    "Authorization": `Bearer ${s.token}`
  };
}

/* ===========================
   Master token detection
   =========================== */

const masterTokens = {
  "NIFTY": { exchange: "NSE", token: "256265", name: "NIFTY" },
  "SENSEX": { exchange: "BSE", token: "999999", name: "SENSEX" },
  "NATGAS": { exchange: "MCX", token: "500000", name: "NATGAS" }
};

function detectTokenFromSymbol(symbol) {
  if (!symbol) return masterTokens.NIFTY;
  const s = symbol.toUpperCase();

  if (s.includes("NIFTY")) return masterTokens.NIFTY;
  if (s.includes("SENSEX")) return masterTokens.SENSEX;
  if (s.includes("NATGAS") || s.includes("NATURAL")) return masterTokens.NATGAS;

  return masterTokens.NIFTY;
}

/* ===========================
   Option chain normalization
   =========================== */

function normalizeOptionChain(raw = []) {
  const out = [];

  for (const x of raw) {
    try {
      const strike = safeParseFloat(x.strike || x.strikePrice);
      if (!Number.isFinite(strike)) continue;

      const type = (x.type || x.optionType || "").toUpperCase().includes("P") ? "PE" : "CE";
      const bid = safeParseFloat(x.bid || x.bestBid);
      const ask = safeParseFloat(x.ask || x.bestAsk);
      const ltp = safeParseFloat(x.ltp || x.lastPrice);
      const volume = safeParseFloat(x.volume || x.totalTradedVolume);
      const oi = safeParseFloat(x.oi || x.openInterest);
      const iv = safeParseFloat(x.iv || x.impliedVolatility);

      out.push({
        strike,
        type,
        bid,
        ask,
        ltp,
        volume,
        oi,
        iv,
        timestamp: x.timestamp || Date.now()
      });
    } catch (e) {}
  }

  return out;
}

/* ===========================
   Greeks Engine
   =========================== */

function approxGreeks({ spot, strike, daysToExpiry, ivPercent, rate = 0.06 }) {
  const T = Math.max(1, daysToExpiry) / 365;
  const iv = Math.max(0.0001, ivPercent / 100);

  const sigma = iv * Math.sqrt(T);
  const d1 = (Math.log(spot / strike) + (rate + 0.5 * iv * iv) * T) / sigma;
  const d2 = d1 - sigma;

  function erf(x) {
    const sign = x >= 0 ? 1 : -1;
    x = Math.abs(x);
    const t = 1 / (1 + 0.3275911 * x);
    const y = 1 -
      (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592)
      * t * Math.exp(-x * x);
    return sign * y;
  }

  const norm = x => 0.5 * (1 + erf(x / Math.sqrt(2)));

  return {
    deltaCall: Number(norm(d1).toFixed(4)),
    deltaPut: Number((norm(d1) - 1).toFixed(4)),
    d1: Number(d1.toFixed(4)),
    d2: Number(d2.toFixed(4))
  };
}

/* ===========================
   Premium Engine
   =========================== */

function premiumScore({ spot, strike, ltp, ivPercent, daysToExpiry }) {
  const intrinsic = Math.max(0, spot - strike);
  const extrinsic = Math.max(0, ltp - intrinsic);

  const T = Math.max(1, daysToExpiry) / 365;
  const iv = Math.max(0.0001, ivPercent / 100);
  const expectedMove = spot * iv * Math.sqrt(T);

  return {
    intrinsic,
    extrinsic,
    expectedMove,
    score: Number((extrinsic / (expectedMove + 1e-9)).toFixed(4))
  };
}

/* ===========================
   Dynamic strike step
   =========================== */

function computeStrikeStep({ daysToExpiry, baseStep = 50 }) {
  const d = Math.max(1, daysToExpiry);

  if (d <= 3) return baseStep / 2;
  if (d <= 10) return baseStep;
  if (d <= 30) return baseStep * 2;
  return baseStep * 4;
}

/* ===========================
   NATGAS adjustments
   =========================== */

function handleNaturalGasAdjustments({ market, suggestedStrikes }) {
  if (market !== "NaturalGas") return suggestedStrikes;

  return suggestedStrikes.map(s => ({
    ...s,
    strike: roundToTick(s.strike, 0.5),
    note: (s.note || "") + " | NATGAS-adjust"
  }));
}

/* ===========================
   Risk SL/Target
   =========================== */

function computeSLandTarget({ entryPrice, slPercent = 15 }) {
  const slAmt = (slPercent / 100) * entryPrice;

  return {
    stopLossPrice: entryPrice - slAmt,
    targetPrice: entryPrice + slAmt * 1.5
  };
}

/* ===========================
   /suggest main engine
   =========================== */

app.post("/suggest", asyncHandler(async (req, res) => {
  const p = req.body || {};

  const raw = Array.isArray(p.optionChain) ? p.optionChain : [];
  const chain = normalizeOptionChain(raw);

  const spot = safeParseFloat(p.spot, 0);
  const market = detectMarket(p);
  const days = safeParseFloat(p.daysToExpiry, 7);

  const step = computeStrikeStep({ daysToExpiry: days, baseStep: p.baseStep || 50 });

  const trend = calculateTrend({
    ema20: p.ema20,
    ema50: p.ema50,
    rsi: p.rsi,
    vwap: p.vwap,
    spot
  });

  const trendStrikes = suggestStrikesByTrend({
    spot,
    trend: trend.trend,
    expiryDays: days,
    strikeStep: step
  });

  const combined = chain.map(c => ({
    strike: c.strike,
    volume: c.volume,
    oi: c.oi,
    iv: c.iv
  }));

  const volRank = getVolRank("bulk", combined);

  const safe = applySafeFilters(combined, {
    minVolume: p.minVolume,
    minOI: p.minOI,
    maxIV: p.maxIV,
    maxRank: p.maxRank
  });

  const finalStrikes = handleNaturalGasAdjustments({
    market,
    spot,
    suggestedStrikes: trendStrikes.strikes
  });

  return res.json({
    ok: true,
    market,
    spot,
    strikeStep: step,
    trend,
    volRankTop: volRank.sorted.slice(0, 10),
    safeFilter: safe.debug,
    finalStrikes
  });
}));

/* Part-2 Ends */
/**
 * Alpha - UPDATED server.js
 * Part-3 of 3 (LRUCache Fix Applied)
 */

/* ===========================
   Robust SmartAPI wrapper
   =========================== */

async function smartApiRequest(path, body = {}, method = "POST", opts = {}) {
  const maxRetries = opts.maxRetries ?? 3;
  const baseUrl = opts.baseUrl || "https://api.smartapi.example";
  const url = `${baseUrl}${path}`;

  const attempt = async (n) => {
    try {
      const headers = await smartApiAuthHeaders();
      const resp = await fetch(url, {
        method,
        headers,
        body: method === "GET" ? undefined : JSON.stringify(body)
      });

      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        const err = new Error(`HTTP ${resp.status}: ${text}`);
        err.status = resp.status;
        throw err;
      }

      return resp.json();
    } catch (err) {
      const status = err.status;
      const transient = !status || status >= 500;
      if (n < maxRetries && transient) {
        const wait = (n + 1) * 250;
        await new Promise(r => setTimeout(r, wait));
        return attempt(n + 1);
      }
      throw err;
    }
  };

  return attempt(0);
}

/* ===========================
   Audit Trail
   =========================== */

const auditTrail = [];
const AUDIT_MAX = 1000;

function audit(event) {
  const ev = { time: Date.now(), ...event };
  auditTrail.push(ev);
  if (auditTrail.length > AUDIT_MAX) auditTrail.shift();
}

app.get("/debug/audit", (req, res) => {
  res.json({
    ok: true,
    count: auditTrail.length,
    trail: auditTrail.slice(-200)
  });
});

/* ===========================
   Risk Rules
   =========================== */

const RISK = {
  maxExposurePerSymbol: parseFloat(process.env.MAX_EXPOSURE_PER_SYMBOL) || 100000,
  maxDailyLoss: parseFloat(process.env.MAX_DAILY_LOSS) || 200000,
  maxQtyPerOrder: parseInt(process.env.MAX_QTY_PER_ORDER) || 500,
  enforcedSLPercent: parseFloat(process.env.ENFORCED_SL_PERCENT) || 15
};

function enforceRiskRules(orders = []) {
  const violations = [];
  let exposure = 0;

  for (const o of orders) {
    const qty = Number(o.qty || 0);
    const entry = Number(o.price || o.entry || 0);

    if (qty <= 0) violations.push({ order: o, reason: "qty <= 0" });
    if (qty > RISK.maxQtyPerOrder) violations.push({ order: o, reason: "qty > maxQty" });
    if (entry < 0) violations.push({ order: o, reason: "entry < 0" });

    exposure += qty * entry;
  }

  if (exposure > RISK.maxExposurePerSymbol) {
    violations.push({ reason: "exposure too high", exposure });
  }

  return { ok: violations.length === 0, violations, exposure };
}

/* ===========================
   /execute (simulate or real)
   =========================== */

app.post("/execute", asyncHandler(async (req, res) => {
  const body = req.body || {};
  const orders = Array.isArray(body.orders) ? body.orders : [];
  const simulate = body.simulate !== undefined ? body.simulate : true;

  audit({ type: "execute_request", orders, simulate });

  const risk = enforceRiskRules(orders);
  if (!risk.ok) {
    audit({ type: "blocked", reason: "risk", risk });
    return res.json({ ok: false, error: "risk_violation", details: risk });
  }

  const results = [];

  for (const o of orders) {
    try {
      if (simulate) {
        results.push({
          ok: true,
          simulated: true,
          result: {
            orderId: "SIM-" + Date.now(),
            placedAt: Date.now(),
            details: o
          }
        });
      } else {
        const r = await smartApiRequest("/order/place", o, "POST", { maxRetries: 2 });
        results.push({ ok: true, simulated: false, result: r });
      }
    } catch (err) {
      results.push({ ok: false, error: err.message || String(err) });
    }
  }

  res.json({ ok: true, risk, results });
}));

/* ===========================
   /test endpoints
   =========================== */

app.get("/ready", asyncHandler(async (req, res) => {
  await smartApiLogin();
  res.json({ ok: true, ready: true, time: nowISO() });
}));

app.get("/test/greeks", (req, res) => {
  const q = req.query;
  const spot = safeParseFloat(q.spot, 100);
  const strike = safeParseFloat(q.strike, spot);
  const days = safeParseFloat(q.days, 7);
  const iv = safeParseFloat(q.iv, 20);

  const g = approxGreeks({ spot, strike, daysToExpiry: days, ivPercent: iv });
  res.json({ ok: true, greeks: g });
});

app.post("/test/volrank", (req, res) => {
  const data = Array.isArray(req.body.data) ? req.body.data : [];
  const r = getVolRank("TEST", data);
  res.json({ ok: true, result: r });
});

/* ===========================
   Graceful Shutdown
   =========================== */

let shuttingDown = false;

async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  log("Graceful shutdown...");
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

/* ===========================
   Final Listen
   =========================== */

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    log(`Alpha server (UPDATED, complete) running on port ${PORT}`);
  });
}
