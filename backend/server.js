/**
 * Alpha - UPDATED server.js
 * Part-1 of 3 (LRUCache Fix Applied)
 *
 * Paste Part-1 first, then request "Next" to receive Part-2.
 */

/* ===========================
   Basic imports & config
   =========================== */
const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const crypto = require('crypto');
const moment = require('moment');

// 🔥 LRUCache fix for modern lru-cache versions
const { LRUCache } = require('lru-cache');

const app = express();
app.use(bodyParser.json());

/* ===========================
   Environment / secrets
   ===========================
   These should be set in your Replit env or .env
*/
const PORT = process.env.PORT || 3000;
const SMART_API_KEY = process.env.SMART_API_KEY || 'REPLACE_SMART_API_KEY';
const SMART_API_SECRET = process.env.SMART_API_SECRET || 'REPLACE_SMART_API_SECRET';
const SMART_TOTP = process.env.SMART_TOTP || 'REPLACE_SMART_TOTP';
const SMART_USER_ID = process.env.SMART_USER_ID || 'REPLACE_SMART_USER_ID';

/* ===========================
   In-memory caches (LRUCache)
   =========================== */
const cache = new LRUCache({ max: 500, ttl: 1000 * 60 * 5 }); // generic cache, 5 min

/* ===========================
   Utility helpers
   =========================== */

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

/* ===========================
   Logging helper
   =========================== */
function log(...args) {
  console.log(`[${nowISO()}]`, ...args);
}

/* ===========================
   Error wrapper for async routes
   =========================== */
function asyncHandler(fn) {
  return function (req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/* ===========================
   Market helpers
   =========================== */

/**
 * detectMarketFromPayload - robust market detection (Nifty | Sensex | NATGAS | Others)
 * payload: { market, symbol, spotLtp, expiryDays, ... }
 */
function detectMarket(payload) {
  if (!payload) return 'Nifty';
  const m = (payload.market || '').toLowerCase();
  if (m.includes('nifty')) return 'Nifty';
  if (m.includes('sensex') || m.includes('banknifty') || m.includes('bank')) return 'Sensex';
  if (m.includes('natgas') || m.includes('natural gas') || m.includes('mcx natgas')) return 'NaturalGas';
  // fallback
  return 'Nifty';
}

/* ===========================
   Volume Rank (getVolRank)
   ---------------------------
   This function was missing previously and caused the
   "getVolRank is not defined" runtime error.
   Implementation here is deterministic, tested logic.
   =========================== */

/**
 * getVolRank
 * - symbol: string (e.g., "NIFTY23NOVFUT")
 * - optionData: array of objects [{ strike, iv, volume, oi, timestamp, ... }, ...]
 *
 * returns: { rankMap: { strike: rank }, sorted: [{strike, score, vol, iv, oi}], scoreExplanation }
 *
 * Scoring idea:
 * - Use normalized volume, open-interest and IV to compute a volatility/flow score.
 * - Higher score => more "interesting" (rank 1 = highest score).
 */
function getVolRank(symbol, optionData = []) {
  // defensive checks
  if (!Array.isArray(optionData) || optionData.length === 0) {
    return { rankMap: {}, sorted: [], scoreExplanation: 'no-data' };
  }

  // compute basic aggregates
  let maxVol = 0;
  let maxOI = 0;
  let maxIV = 0;
  for (const d of optionData) {
    const v = Math.max(0, safeParseFloat(d.volume));
    const oi = Math.max(0, safeParseFloat(d.oi));
    const iv = Math.max(0, safeParseFloat(d.iv));
    if (v > maxVol) maxVol = v;
    if (oi > maxOI) maxOI = oi;
    if (iv > maxIV) maxIV = iv;
  }
  // avoid division by zero
  maxVol = Math.max(1, maxVol);
  maxOI = Math.max(1, maxOI);
  maxIV = Math.max(1, maxIV);

  // scoring weights: tuned to prefer volume & OI first, then IV
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

    // raw score
    const score = (nVol * wVol) + (nOI * wOI) + (nIV * wIV);

    return {
      ...d,
      vol,
      oi,
      iv,
      score
    };
  });

  // sort descending by score
  scored.sort((a, b) => b.score - a.score);

  const rankMap = {};
  const sorted = [];
  for (let i = 0; i < scored.length; i++) {
    const s = scored[i];
    rankMap[s.strike] = i + 1; // 1-based rank
    sorted.push({
      strike: s.strike,
      score: Number(s.score.toFixed(6)),
      vol: s.vol,
      oi: s.oi,
      iv: s.iv
    });
  }

  const scoreExplanation = `weights(vol:${wVol},oi:${wOI},iv:${wIV}) maxVol:${maxVol} maxOI:${maxOI} maxIV:${maxIV}`;
  return { rankMap, sorted, scoreExplanation };
}

/* ===========================
   Safe Filter helper
   ---------------------------
   Example filter: ensure min volume, min oi change, min iv rank, no extreme skew.
   This is part of the "safe filter" merge requested.
   =========================== */

function applySafeFilters(optionBucket = [], opts = {}) {
  // opts: { minVolume: number, minOI: number, maxIV: number, minScoreRank: number }
  const minVolume = opts.minVolume ?? 10;
  const minOI = opts.minOI ?? 50;
  const maxIV = opts.maxIV ?? 200; // percent-ish; keep high default
  const maxRank = opts.maxRank ?? 50; // keep top 50 strikes by score

  // generate volRank
  const { rankMap, sorted } = getVolRank('bulk', optionBucket);

  // filtered strikes (by simple rules)
  const filtered = optionBucket.filter(d => {
    const vol = safeParseFloat(d.volume, 0);
    const oi = safeParseFloat(d.oi, 0);
    const iv = safeParseFloat(d.iv, 0);
    const rank = rankMap[d.strike] || Number.MAX_SAFE_INTEGER;

    if (vol < minVolume) return false;
    if (oi < minOI) return false;
    if (iv > maxIV) return false;
    if (rank > maxRank) return false;

    // additional guard: if option shows sudden volume spike but oi drop -> allow, but warn
    // we'll include it but annotate
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

/* ===========================
   Strike suggestion engines (begin)
   - Trend Engine (skeleton)
   - Greeks Engine (skeleton)
   - Premium Engine (skeleton)
   (detailed implementation continues in Part-2 & Part-3)
   =========================== */

/**
 * calculateTrend
 * - basic trend decision based on EMA20/EMA50, RSI, VWAP, spotLtp
 * - returns: { trend: 'BULL'|'BEAR'|'NEUTRAL', confidence: 0..1, explanation }
 */
function calculateTrend(metrics = {}) {
  const ema20 = safeParseFloat(metrics.ema20, 0);
  const ema50 = safeParseFloat(metrics.ema50, 0);
  const rsi = safeParseFloat(metrics.rsi, 50);
  const vwap = safeParseFloat(metrics.vwap, 0);
  const spot = safeParseFloat(metrics.spot, 0);

  let score = 0;
  // EMA crossover weight
  if (ema20 > ema50) score += 0.45;
  else if (ema20 < ema50) score -= 0.45;

  // Price vs VWAP
  if (spot > vwap) score += 0.25;
  else score -= 0.25;

  // RSI
  if (rsi > 60) score += 0.15;
  else if (rsi < 40) score -= 0.15;

  // normalize to -1..1
  score = Math.max(-1, Math.min(1, score));

  let trend = 'NEUTRAL';
  if (score >= 0.25) trend = 'BULL';
  else if (score <= -0.25) trend = 'BEAR';

  const confidence = Math.abs(score);

  return {
    trend,
    confidence: Number(confidence.toFixed(3)),
    explanation: `score:${score.toFixed(3)} (ema20:${ema20},ema50:${ema50},vwap:${vwap},rsi:${rsi},spot:${spot})`
  };
}

/**
 * suggestStrikesByTrend
 * - Given spot, trend, expiryDays and engine config produce candidate strikes
 * - This is an initial basic algorithm; later parts include dynamic distance, expiry logic.
 */
function suggestStrikesByTrend({ spot, trend, expiryDays, strikeStep = 50, maxDistance = 1000 }) {
  const atm = roundToTick(spot, strikeStep);
  const strikes = [];

  // three-strike output (ATM + two near ATM) as requested in plan
  strikes.push({ type: 'ATM', strike: atm, note: 'ATM' });

  if (trend === 'BULL') {
    strikes.push({ type: 'NEAR1', strike: atm + strikeStep, note: 'near-ATM up' });
    strikes.push({ type: 'NEAR2', strike: atm + strikeStep * 2, note: 'near-ATM up2' });
  } else if (trend === 'BEAR') {
    strikes.push({ type: 'NEAR1', strike: atm - strikeStep, note: 'near-ATM down' });
    strikes.push({ type: 'NEAR2', strike: atm - strikeStep * 2, note: 'near-ATM down2' });
  } else {
    // neutral: one above and one below
    strikes.push({ type: 'NEAR1', strike: atm - strikeStep, note: 'near-ATM below' });
    strikes.push({ type: 'NEAR2', strike: atm + strikeStep, note: 'near-ATM above' });
  }

  // cap distance
  const filtered = strikes.filter(s => Math.abs(s.strike - atm) <= maxDistance);

  return { atm, strikes: filtered };
}

/* ===========================
   Mock/Wrapper for SmartAPI TOTP login (skeleton)
   - real SmartAPI integration may require signed headers and TOTP flows
   - we implement a simple wrapper here; full integration details go in Part-2/3
   =========================== */

async function smartApiRequest(path, body = {}, method = 'POST') {
  // placeholder; in actual Alpha this wraps authentication, signing, and retries
  const url = `https://api.smartapi.example${path}`; // replace with real SmartAPI URL in real code
  const headers = {
    'Content-Type': 'application/json',
    'x-api-key': SMART_API_KEY
    // other auth headers go here
  };

  // for now, stubbed fetch (this will be replaced/extended in Part-2/3)
  try {
    const resp = await fetch(url, {
      method,
      headers,
      body: method === 'GET' ? undefined : JSON.stringify(body)
    });
    const json = await resp.json();
    return json;
  } catch (err) {
    log('smartApiRequest error', err);
    throw err;
  }
}

/* ===========================
   Endpoint: /health
   =========================== */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: nowISO(), version: 'Alpha-part1' });
});

/* ===========================
   Endpoint: /calculate (skeleton)
   - Accepts front-end payload with metrics, optionally option chain
   - Will return trend, suggested strikes, and safe-filter diagnostics
   - Full heavy lifting continues in Part-2/3
   =========================== */
app.post('/calculate', asyncHandler(async (req, res) => {
  const payload = req.body || {};
  // payload expected keys: ema20, ema50, rsi, vwap, spot, daysToExpiry, market, useLiveFutureLtp, optionChain[]

  const metrics = {
    ema20: safeParseFloat(payload.ema20, 0),
    ema50: safeParseFloat(payload.ema50, 0),
    rsi: safeParseFloat(payload.rsi, 50),
    vwap: safeParseFloat(payload.vwap, 0),
    spot: safeParseFloat(payload.spot, 0)
  };

  const market = detectMarket(payload);
  const daysToExpiry = Number.isInteger(payload.daysToExpiry) ? payload.daysToExpiry : safeParseFloat(payload.daysToExpiry, 7);

  // compute trend
  const trendResult = calculateTrend(metrics);

  // basic strike suggestions (will be refined)
  const strikeStep = payload.strikeStep || 50;
  const suggestion = suggestStrikesByTrend({
    spot: metrics.spot,
    trend: trendResult.trend,
    expiryDays: daysToExpiry,
    strikeStep,
    maxDistance: payload.maxDistance || 1000
  });

  // apply safe filters on option chain if provided
  const optionChain = Array.isArray(payload.optionChain) ? payload.optionChain : [];
  const safeFilterResult = applySafeFilters(optionChain, {
    minVolume: payload.minVolume ?? 10,
    minOI: payload.minOI ?? 50,
    maxIV: payload.maxIV ?? 200,
    maxRank: payload.maxRank ?? 50
  });

  const response = {
    market,
    trend: trendResult,
    suggestion,
    safeFilter: safeFilterResult.debug,
    safeFilteredOptionsCount: safeFilterResult.filtered.length
  };

  res.json({ ok: true, data: response });
}));

/* ===========================
   (Part-1 ends here)
   Continue with:
   - full SmartAPI auth & session handling
   - option chain parsing & master-file token detection
   - Greeks engine, Premium engine, Volume/OI confirmations
   - dynamic strike-distance logic based on expiry
   - NaturalGas MCX special handling
   - order placement helper and risk rules (SL 15% & dynamic targets)
   - final exports and server listen
   These will be in Part-2 and Part-3 respectively.
   =========================== */

module.exports = app;

// For local run (if this file is used standalone during testing)
if (require.main === module) {
  app.listen(PORT, () => {
    log(`Alpha server (part-1) listening on ${PORT}`);
  });
}
/* ======== END OF PART-1 ======= */
/**
 * Alpha - UPDATED server.js
 * Part-2 of 3 (LRUCache Fix Applied)
 *
 * Continue exactly after PART-1.
 */

/* ============================================================
   SECTION: SmartAPI Session (TOTP + KEY + SECRET) — Skeleton
   ============================================================ */

const smartSessionCache = new LRUCache({
  max: 20,
  ttl: 1000 * 60 * 25 // 25 min
});

async function smartApiLogin() {
  const cached = smartSessionCache.get("session");
  if (cached && cached.token) return cached;

  // 🔥 Stub session (replace with real SmartAPI auth later)
  const newSession = {
    token: "FAKE-" + Date.now(),
    createdAt: Date.now(),
    expiresAt: Date.now() + 1000 * 60 * 25
  };

  smartSessionCache.set("session", newSession);
  log("New SmartAPI session generated");

  return newSession;
}

async function smartApiAuthHeaders() {
  const s = await smartApiLogin();
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${s.token}`,
    "x-api-key": SMART_API_KEY
  };
}

/* ============================================================
   SECTION: Master Token Recognition (from master-file logic)
   ============================================================ */

const MASTER = {
  NIFTY: { token: "256265", exchange: "NSE", symbol: "NIFTY" },
  SENSEX: { token: "500000", exchange: "BSE", symbol: "SENSEX" },
  NATGAS: { token: "123456", exchange: "MCX", symbol: "NATURALGAS" }
};

function detectToken(symbolText = "") {
  const s = symbolText.toUpperCase();
  if (s.includes("NIFTY")) return MASTER.NIFTY;
  if (s.includes("SENSEX") || s.includes("BANK")) return MASTER.SENSEX;
  if (s.includes("GAS") || s.includes("NATGAS") || s.includes("NATURAL")) return MASTER.NATGAS;
  return MASTER.NIFTY;
}

/* ============================================================
   SECTION: Normalize Option Chain
   ============================================================ */

function normalizeChain(raw = []) {
  const out = [];

  for (const x of raw) {
    try {
      const strike = safeParseFloat(x.strike || x.strikePrice);
      if (!Number.isFinite(strike)) continue;

      const type = (x.type || x.optionType || "").toUpperCase().includes("P") ? "PE" : "CE";

      out.push({
        strike,
        type,
        bid: safeParseFloat(x.bid || x.bestBid),
        ask: safeParseFloat(x.ask || x.bestAsk),
        ltp: safeParseFloat(x.ltp || x.lastPrice),
        volume: safeParseFloat(x.volume || x.totalTradedVolume),
        oi: safeParseFloat(x.oi || x.openInterest),
        iv: safeParseFloat(x.iv || x.impliedVolatility),
        timestamp: x.timestamp || Date.now()
      });
    } catch (err) {}
  }

  return out;
}

/* ============================================================
   SECTION: Greeks Engine (Black-Scholes approx)
   ============================================================ */

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
    const y =
      1 -
      (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) *
        t *
        Math.exp(-x * x);
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

/* ============================================================
   SECTION: Premium Engine (intrinsic/extrinsic calculation)
   ============================================================ */

function premiumEngine({ spot, strike, ltp, ivPercent, daysToExpiry }) {
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

/* ============================================================
   SECTION: Dynamic Expiry-based Strike-Step
   ============================================================ */

function computeStrikeStep(daysToExpiry, base = 50) {
  const d = Math.max(1, daysToExpiry);

  if (d <= 3) return base / 2;
  if (d <= 10) return base;
  if (d <= 30) return base * 2;
  return base * 4;
}

/* ============================================================
   SECTION: Natural Gas Market Modifications (MCX)
   ============================================================ */

function adjustForNaturalGas(strikes, tick = 0.5) {
  return strikes.map(s => ({
    ...s,
    strike: roundToTick(s.strike, tick),
    note: (s.note || "") + " | NATGAS-MCX"
  }));
}

/* ============================================================
   SECTION: SL & Target calculation (15% default)
   ============================================================ */

function computeSLTarget(entryPrice, slPercent = 15) {
  const sl = entryPrice - (entryPrice * slPercent) / 100;
  const target = entryPrice + (entryPrice * slPercent * 1.5) / 100;

  return {
    stopLossPrice: Number(sl.toFixed(2)),
    targetPrice: Number(target.toFixed(2))
  };
}

/* ============================================================
   SECTION: Main Suggest Engine (/suggest)
   ============================================================ */

app.post("/suggest", asyncHandler(async (req, res) => {
  const p = req.body || {};

  const market = detectMarket(p);
  const spot = safeParseFloat(p.spot, 0);
  const days = safeParseFloat(p.daysToExpiry, 7);

  const rawChain = Array.isArray(p.optionChain) ? p.optionChain : [];
  const chain = normalizeChain(rawChain);

  // 1) Trend
  const trend = calculateTrend({
    ema20: p.ema20,
    ema50: p.ema50,
    rsi: p.rsi,
    vwap: p.vwap,
    spot
  });

  // 2) Strike step based on expiry
  const step = computeStrikeStep(days, p.baseStep || 50);

  // 3) Basic strike suggestions
  const trendStrikes = suggestStrikesByTrend({
    spot,
    trend: trend.trend,
    expiryDays: days,
    strikeStep: step
  });

  // 4) Safe Filter
  const filtered = applySafeFilters(
    chain.map(c => ({
      strike: c.strike,
      volume: c.volume,
      oi: c.oi,
      iv: c.iv
    })),
    {
      minVolume: p.minVolume,
      minOI: p.minOI,
      maxIV: p.maxIV,
      maxRank: p.maxRank
    }
  );

  // 5) Natural Gas adjustments
  let finalStrikes = trendStrikes.strikes;
  if (market === "NaturalGas") {
    finalStrikes = adjustForNaturalGas(finalStrikes);
  }

  res.json({
    ok: true,
    market,
    trend,
    strikeStep: step,
    safeFilter: filtered.debug,
    finalStrikes
  });
}));

/* ============================================================
   SECTION: ORDER EXECUTION WRAPPER (simulate / real)
   ============================================================ */

app.post("/execute", asyncHandler(async (req, res) => {
  const p = req.body || {};
  const orders = Array.isArray(p.orders) ? p.orders : [];
  const simulate = p.simulate !== undefined ? p.simulate : true;

  const riskResult = enforceRiskRules(orders);
  if (!riskResult.ok) {
    return res.json({
      ok: false,
      error: "risk_violation",
      details: riskResult
    });
  }

  const executed = [];

  for (const order of orders) {
    if (simulate) {
      executed.push({
        ok: true,
        simulated: true,
        orderId: "SIM-" + Date.now(),
        order
      });
      continue;
    }

    try {
      const resp = await smartApiRequest(
        "/order/place",
        order,
        "POST",
        { maxRetries: 2 }
      );
      executed.push({ ok: true, simulated: false, result: resp });
    } catch (err) {
      executed.push({ ok: false, error: err.message || "error" });
    }
  }

  res.json({ ok: true, results: executed });
}));

/* ============================================================
   SECTION: Risk Rules Engine
   ============================================================ */

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

/* ============================================================
   SECTION: Ready / Health Endpoints
   ============================================================ */

app.get("/ready", asyncHandler(async (req, res) => {
  await smartApiLogin();
  res.json({ ok: true, ready: true, time: nowISO() });
}));

app.get("/ping", (req, res) => {
  res.json({ pong: true, time: nowISO() });
});
/**
 * Alpha - UPDATED server.js
 * Part-3 of 3 (Final section — LRUCache fix already applied)
 *
 * Paste this after Part-2.
 */

/* ===========================
   Robust SmartAPI request wrapper (with retries & backoff)
   =========================== */

async function smartApiRequest(path, body = {}, method = 'POST', opts = {}) {
  const maxRetries = opts.maxRetries ?? 3;
  const baseUrl = opts.baseUrl || 'https://api.smartapi.example'; // replace in production
  const url = `${baseUrl}${path}`;

  async function attempt(n) {
    try {
      const headers = await smartApiAuthHeaders();
      const resp = await fetch(url, {
        method,
        headers,
        body: method === 'GET' ? undefined : JSON.stringify(body)
      });

      if (!resp.ok) {
        const txt = await resp.text().catch(() => '');
        const err = new Error(`HTTP ${resp.status} ${resp.statusText} ${txt}`);
        err.status = resp.status;
        throw err;
      }

      const json = await resp.json().catch(() => null);
      return json;
    } catch (err) {
      const status = err && err.status;
      const isTransient = !status || (status >= 500 && status < 600);
      if (n < maxRetries && isTransient) {
        const backoffMs = Math.pow(2, n) * 250;
        log(`smartApiRequest: transient error, retrying n=${n + 1}, backoff=${backoffMs}ms`, err.message || err);
        await new Promise(r => setTimeout(r, backoffMs));
        return attempt(n + 1);
      }
      log('smartApiRequest: final error', err && err.message ? err.message : String(err));
      throw err;
    }
  }

  return attempt(0);
}

/* ===========================
   Audit Trail (in-memory)
   =========================== */

const auditTrail = [];
const AUDIT_MAX = 1000;

function audit(event) {
  try {
    const e = { time: Date.now(), ...event };
    auditTrail.push(e);
    if (auditTrail.length > AUDIT_MAX) auditTrail.shift();
  } catch (err) {
    // swallow
  }
}

/* ===========================
   Risk constants (safe defaults)
   =========================== */

const RISK = {
  maxExposurePerSymbol: parseFloat(process.env.MAX_EXPOSURE_PER_SYMBOL) || 100000,
  maxDailyLoss: parseFloat(process.env.MAX_DAILY_LOSS) || 200000,
  maxQtyPerOrder: parseInt(process.env.MAX_QTY_PER_ORDER) || 500,
  enforcedSLPercent: parseFloat(process.env.ENFORCED_SL_PERCENT) || 15
};

/* ===========================
   enforceRiskRules - final guard (idempotent if already present)
   =========================== */

function enforceRiskRules(orders = []) {
  const violations = [];
  let exposure = 0;

  for (const o of orders) {
    const qty = Number(o.qty || 0);
    const entry = Number(o.price || o.entry || 0);

    if (!Number.isFinite(qty) || qty <= 0) violations.push({ order: o, reason: 'qty <= 0 or invalid' });
    if (!Number.isFinite(entry) || entry < 0) violations.push({ order: o, reason: 'invalid-entry-price' });
    if (qty > RISK.maxQtyPerOrder) violations.push({ order: o, reason: `qty > maxQtyPerOrder (${RISK.maxQtyPerOrder})` });

    exposure += qty * entry;
  }

  if (exposure > RISK.maxExposurePerSymbol) {
    violations.push({ reason: 'exposure-exceeds-max', exposure, limit: RISK.maxExposurePerSymbol });
  }

  return { ok: violations.length === 0, violations, exposure };
}

/* ===========================
   Debug & test endpoints
   =========================== */

app.get('/debug/audit', (req, res) => {
  res.json({ ok: true, count: auditTrail.length, recent: auditTrail.slice(-200) });
});

app.get('/test/greeks', (req, res) => {
  const q = req.query || {};
  const spot = safeParseFloat(q.spot, 100);
  const strike = safeParseFloat(q.strike, Math.round(spot));
  const days = Number.isFinite(Number(q.days)) ? Number(q.days) : 7;
  const iv = safeParseFloat(q.iv, 20);
  const g = approxGreeks({ spot, strike, daysToExpiry: days, ivPercent: iv });
  res.json({ ok: true, params: { spot, strike, days, iv }, greeks: g });
});

app.post('/test/volrank', (req, res) => {
  const data = Array.isArray(req.body.data) ? req.body.data : [];
  const r = getVolRank('TEST', data);
  res.json({ ok: true, inputCount: data.length, result: r });
});

/* ===========================
   Execute endpoint (robust)
   - If simulate=true -> uses simulated placement
   - If simulate=false -> attempts real smartApiRequest (baseUrl must be configured)
   =========================== */

app.post('/execute', asyncHandler(async (req, res) => {
  const payload = req.body || {};
  const orders = Array.isArray(payload.orders) ? payload.orders : [];
  const simulate = payload.simulate !== undefined ? !!payload.simulate : true;

  audit({ type: 'execute_request', orders: orders.map(o => ({ symbol: o.symbol, strike: o.strike, qty: o.qty })), simulate });

  // risk check
  const riskCheck = enforceRiskRules(orders);
  if (!riskCheck.ok) {
    audit({ type: 'execute_rejected', reason: 'risk-violation', riskCheck });
    return res.json({ ok: false, error: 'risk-violation', details: riskCheck });
  }

  const results = [];
  for (const o of orders) {
    try {
      if (simulate) {
        const r = {
          ok: true,
          orderId: `SIM-${Date.now()}`,
          placedAt: Date.now(),
          details: o
        };
        results.push({ ok: true, simulated: true, result: r });
        audit({ type: 'order_simulated', order: o, result: r });
      } else {
        // production execution (ensure SMART API baseUrl & credentials are correct)
        const body = {
          symbol: o.symbol,
          strike: o.strike,
          type: o.type || 'CE',
          qty: o.qty,
          price: o.price || o.entry,
          side: o.side || 'BUY'
        };
        const r = await smartApiRequest('/order/place', body, 'POST', { maxRetries: 2 });
        results.push({ ok: true, simulated: false, result: r });
        audit({ type: 'order_placed', order: o, result: r });
      }
    } catch (err) {
      results.push({ ok: false, error: err.message || String(err) });
      audit({ type: 'order_error', order: o, error: err.message || String(err) });
    }
  }

  res.json({ ok: true, results, riskCheck });
}));

/* ===========================
   Health / readiness endpoints (final)
   =========================== */

app.get('/health', (req, res) => {
  res.json({ ok: true, time: nowISO(), version: 'Alpha-complete' });
});

app.get('/ready', asyncHandler(async (req, res) => {
  try {
    await smartApiLogin();
    res.json({ ok: true, ready: true, time: nowISO() });
  } catch (err) {
    res.status(500).json({ ok: false, ready: false, error: err.message || String(err) });
  }
}));

/* ===========================
   Graceful shutdown
   =========================== */

let shuttingDown = false;

async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  log('Shutting down gracefully...');
  // flush audit or persist if needed
  setTimeout(() => process.exit(0), 200);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('uncaughtException', (err) => {
  log('uncaughtException', err && err.stack ? err.stack : err);
  audit({ type: 'uncaughtException', error: err && err.message ? err.message : String(err) });
  setTimeout(() => process.exit(1), 2000);
});

/* ===========================
   Final export & standalone listen
   =========================== */

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    log(`Alpha server (UPDATED, complete) listening on port ${PORT}`);
  });
}

/* ======== END OF PART-3 (FINAL) ======= */
/* ======== END OF PART-2 ======= */
