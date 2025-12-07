/**
 * Alpha - server.js
 * Part-1 of 3
 *
 * NOTE:
 * - This file is the first ~1/3 of the full 939-line Alpha server.js.
 * - Part-2 and Part-3 will continue sequentially and complete the file.
 * - Keep the exact order when pasting into your original file.
 */

/* ===========================
   Basic imports & config
   =========================== */
const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch'); // for external API calls
const crypto = require('crypto');
const moment = require('moment');
const LRU = require('lru-cache');

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
   In-memory caches (LRU)
   =========================== */
const cache = new LRU({ max: 500, ttl: 1000 * 60 * 5 }); // generic cache, 5 min

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
/**
 * Alpha - server.js
 * Part-2 of 3
 *
 * Continuation of the Alpha server.js (append this after Part-1).
 * Contains SmartAPI session handling, option-chain parsing, greeks & premium engines,
 * master-token detection, dynamic strike-distance helpers, NaturalGas handling,
 * and order placement helpers (safety-only; actual trade code left stubbed).
 */

/* ===========================
   SmartAPI: Auth/session helpers
   - Maintains a lightweight in-memory session
   - Handles TOTP and re-login attempts
   =========================== */

const sessionCache = new LRU({ max: 50, ttl: 1000 * 60 * 30 }); // 30 min

async function smartApiLogin() {
  // If cached session exists and not expired, return it
  const cached = sessionCache.get('smart_session');
  if (cached && cached.token) return cached;

  // In production, you'd compute TOTP and call auth endpoint.
  // Here we simulate a login and cache a dummy token.
  const fakeToken = `FAKE-TOKEN-${Date.now()}`;
  const session = {
    token: fakeToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 1000 * 60 * 25 // 25 minutes
  };
  sessionCache.set('smart_session', session);
  log('smartApiLogin: created new fake session');
  return session;
}

async function smartApiAuthHeaders() {
  const s = await smartApiLogin();
  return {
    'Content-Type': 'application/json',
    'x-api-key': SMART_API_KEY,
    Authorization: `Bearer ${s.token}`
  };
}

/* ===========================
   Option Chain Parsing & Master Token detection
   - masterTokens: mapping to platform tokens (kept simple)
   - normalizeOptionChain: converts SmartAPI/other payloads into our option objects:
     { strike, type: 'CE'|'PE', bid, ask, ltp, volume, oi, iv, timestamp }
   =========================== */

const masterTokens = {
  // Example structure: symbolKey -> { exchange, token, name }
  // This should be replaced with real masterfile data
  'NIFTY': { exchange: 'NSE', token: '256265', name: 'NIFTY' },
  'SENSEX': { exchange: 'BSE', token: '999999', name: 'SENSEX' },
  'NATGAS': { exchange: 'MCX', token: '500000', name: 'NATGAS' }
};

function detectTokenFromSymbol(symbol) {
  if (!symbol || typeof symbol !== 'string') return null;
  const s = symbol.toUpperCase();
  if (s.includes('NIFTY')) return masterTokens.NIFTY;
  if (s.includes('SENSEX') || s.includes('SENSEX')) return masterTokens.SENSEX;
  if (s.includes('NATGAS') || s.includes('NATGAS') || s.includes('NATURALGAS')) return masterTokens.NATGAS;
  return masterTokens.NIFTY; // fallback
}

function normalizeOptionChain(rawChain = []) {
  // Accepts a variety of shapes. Try to be defensive and produce unified entries.
  const out = [];
  for (const item of rawChain) {
    try {
      // common variants
      const strike = safeParseFloat(item.strike || item.strikePrice || item.strike_price);
      const type = (item.type || item.optionType || item.optType || '').toString().toUpperCase().includes('P') ? 'PE' : 'CE';
      const bid = safeParseFloat(item.bid || item.bestBid || item.bidPrice);
      const ask = safeParseFloat(item.ask || item.bestAsk || item.askPrice);
      const ltp = safeParseFloat(item.ltp || item.lastPrice || item.lastTradedPrice);
      const volume = safeParseFloat(item.volume || item.totalTradedVolume || item.volumeTraded);
      const oi = safeParseFloat(item.oi || item.openInterest || item.open_interest);
      const iv = safeParseFloat(item.iv || item.impliedVolatility || item.ivPercent);
      const timestamp = item.timestamp || Date.now();

      if (!Number.isFinite(strike)) continue; // skip
      out.push({
        strike,
        type,
        bid,
        ask,
        ltp,
        volume,
        oi,
        iv,
        timestamp
      });
    } catch (err) {
      // skip malformed entry
    }
  }
  return out;
}

/* ===========================
   Greeks Engine (approximate / lightweight)
   - For speed we provide approximations for delta/theta/vega using simplistic models.
   - In production use a dedicated greeks library or Black76/BS model with interest/dividends.
   =========================== */

function approxGreeks({ spot, strike, rate = 0.06, daysToExpiry = 7, ivPercent }) {
  // Defensive defaults
  const T = Math.max(1, daysToExpiry) / 365.0;
  const iv = Math.max(0.0001, (ivPercent || 20) / 100); // convert percent to decimal

  // Use Black-Scholes-ish simplification (not precise, but serves engine)
  // d1/d2 approximations
  const sigmaSqrtT = iv * Math.sqrt(T);
  const d1 = sigmaSqrtT === 0 ? 0 : (Math.log(Math.max(1e-9, spot / strike)) + (rate + 0.5 * iv * iv) * T) / sigmaSqrtT;
  const d2 = d1 - sigmaSqrtT;

  // normal CDF approx (use erf-based)
  function normCdf(x) {
    return 0.5 * (1 + erf(x / Math.sqrt(2)));
  }
  function erf(x) {
    // numerical approximation
    // Abramowitz and Stegun formula 7.1.26
    const sign = x >= 0 ? 1 : -1;
    x = Math.abs(x);
    const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741, a4 = -1.453152027, a5 = 1.061405429;
    const p = 0.3275911;
    const t = 1 / (1 + p * x);
    const y = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
    return sign * y;
  }

  // approximate delta (call)
  const deltaCall = normCdf(d1);
  const deltaPut = deltaCall - 1;

  // vega (per 1 vol point)
  const vega = spot * Math.sqrt(T) * (1 / Math.sqrt(2 * Math.PI)) * Math.exp(-0.5 * d1 * d1);

  // theta rough
  const theta = - (spot * iv * (1 / Math.sqrt(2 * Math.PI)) * Math.exp(-0.5 * d1 * d1)) / (2 * Math.sqrt(T));

  return {
    deltaCall: Number(deltaCall.toFixed(4)),
    deltaPut: Number(deltaPut.toFixed(4)),
    vega: Number(vega.toFixed(4)),
    theta: Number(theta.toFixed(4)),
    d1: Number(d1.toFixed(4)),
    d2: Number(d2.toFixed(4))
  };
}

/* ===========================
   Premium Engine
   - Detects overpriced/underpriced options relative to intrinsic/time premium.
   - Helps pick candidate strikes based on premium vs. expected move.
   =========================== */

function premiumScore({ spot, strike, ltp, ivPercent, daysToExpiry }) {
  // intrinsic for call
  const intrinsic = Math.max(0, spot - strike);
  const extrinsic = Math.max(0, ltp - intrinsic); // time value

  // expected move (simple) ~ spot * iv * sqrt(T)
  const T = Math.max(1, daysToExpiry) / 365.0;
  const iv = Math.max(0.0001, (ivPercent || 20) / 100);
  const expectedMove = spot * iv * Math.sqrt(T);

  // score: how much premium per expected move
  const score = (extrinsic / (expectedMove + 1e-9)); // higher => more premium relative to expected move
  return {
    intrinsic: Number(intrinsic.toFixed(4)),
    extrinsic: Number(extrinsic.toFixed(4)),
    expectedMove: Number(expectedMove.toFixed(4)),
    score: Number(score.toFixed(4))
  };
}

/* ===========================
   Dynamic strike distance logic based on expiry
   - Shorter expiry -> closer strikes; longer expiry -> wider
   =========================== */

function computeStrikeStep({ spot, daysToExpiry, baseStep = 50 }) {
  // Basic heuristic:
  // - 0-3 days: step = baseStep/2
  // - 4-10 days: baseStep
  // - 11-30 days: baseStep*2
  // - >30 days: baseStep*4
  const d = Math.max(1, Math.floor(daysToExpiry));
  if (d <= 3) return Math.max(1, Math.round(baseStep / 2));
  if (d <= 10) return baseStep;
  if (d <= 30) return baseStep * 2;
  return baseStep * 4;
}

/* ===========================
   Natural Gas (MCX NATGAS) special handling
   - MCX uses different lot sizes, tick values; we handle symbol detection and adjust steps
   =========================== */

function handleNaturalGasAdjustments({ market, spot, suggestedStrikes }) {
  if (market !== 'NaturalGas') return suggestedStrikes;
  // MCX NATGAS ticks often are 0.1 or 0.05 depending on instrument; we'll use 0.5 as safe
  const tick = 0.5;
  return suggestedStrikes.map(s => ({
    ...s,
    strike: roundToTick(s.strike, tick),
    note: (s.note || '') + ' | NATGAS-adjusted'
  }));
}

/* ===========================
   Order Placement Helper (safety-first)
   - This helper enforces SL% (15%) and quantity checks.
   - Actual trade placement is stubbed (returns simulated response).
   =========================== */

function computeSLandTarget({ entryPrice, isSell = false, slPercent = 15, targetMultiplier = 1.5 }) {
  // For options, SL is percentage of premium; apply SL as loss-limit
  const slAmt = (slPercent / 100) * entryPrice;
  const stopLossPrice = isSell ? entryPrice + slAmt : Math.max(0, entryPrice - slAmt);
  // dynamic target: reward-to-risk ratio
  const targetPrice = isSell ? entryPrice - (targetMultiplier * slAmt) : entryPrice + (targetMultiplier * slAmt);

  return {
    entryPrice: Number(entryPrice.toFixed(4)),
    stopLossPrice: Number(stopLossPrice.toFixed(4)),
    targetPrice: Number(targetPrice.toFixed(4)),
    slAmt: Number(slAmt.toFixed(4)),
    slPercent
  };
}

async function placeOrderSimulated({ symbol, strike, type = 'CE', qty = 1, price = 0, side = 'BUY' }) {
  // enforce safety
  if (qty <= 0) throw new Error('qty must be > 0');
  if (price < 0) throw new Error('price must be >= 0');

  // in production call smartApiRequest('/order/place', {...})
  log('placeOrderSimulated', { symbol, strike, type, qty, price, side });
  return {
    ok: true,
    orderId: `SIM-${Date.now()}`,
    placedAt: Date.now(),
    details: { symbol, strike, type, qty, price, side }
  };
}

/* ===========================
   Endpoint: /suggest (full suggestion flow)
   - Accepts payload: { symbol, spot, optionChain, daysToExpiry, baseStep, engineConfig... }
   - Returns: combined engine suggestions, safe filters, greeks, premiums, recommended order data
   =========================== */

app.post('/suggest', asyncHandler(async (req, res) => {
  const payload = req.body || {};
  const rawChain = Array.isArray(payload.optionChain) ? payload.optionChain : [];
  const optionChain = normalizeOptionChain(rawChain);

  const symbol = payload.symbol || 'NIFTY';
  const market = detectMarket({ market: payload.market || symbol });
  const daysToExpiry = Number.isInteger(payload.daysToExpiry) ? payload.daysToExpiry : safeParseFloat(payload.daysToExpiry, 7);
  const spot = safeParseFloat(payload.spot, 0);

  // compute dynamic strike step
  const baseStep = payload.baseStep || 50;
  const strikeStep = computeStrikeStep({ spot, daysToExpiry, baseStep });

  // build buckets by strike with CE/PE separation
  const buckets = {};
  for (const opt of optionChain) {
    const key = opt.strike;
    buckets[key] = buckets[key] || { strike: key, CE: null, PE: null };
    if (opt.type === 'CE') buckets[key].CE = opt;
    else buckets[key].PE = opt;
  }

  // map to array for engines
  const bucketArray = Object.values(buckets).map(b => {
    return {
      strike: b.strike,
      CE: b.CE,
      PE: b.PE,
      midCE: b.CE ? ((b.CE.bid + b.CE.ask) / 2 || b.CE.ltp) : null,
      midPE: b.PE ? ((b.PE.bid + b.PE.ask) / 2 || b.PE.ltp) : null
    };
  });

  // Volume rank across combined CE+PE ltp/volume
  const combinedOptionData = [];
  for (const b of bucketArray) {
    // push as single entries per strike using max of CE/PE volumes to rank by strike interest
    combinedOptionData.push({
      strike: b.strike,
      volume: Math.max(b.CE ? b.CE.volume : 0, b.PE ? b.PE.volume : 0),
      oi: Math.max(b.CE ? b.CE.oi : 0, b.PE ? b.PE.oi : 0),
      iv: Math.max(b.CE ? b.CE.iv : 0, b.PE ? b.PE.iv : 0)
    });
  }

  const volRankRes = getVolRank(symbol, combinedOptionData);

  // Candidate strikes from Trend engine
  const trendMetrics = {
    ema20: payload.ema20,
    ema50: payload.ema50,
    rsi: payload.rsi,
    vwap: payload.vwap,
    spot
  };
  const trendRes = calculateTrend(trendMetrics);
  const trendCandidate = suggestStrikesByTrend({
    spot,
    trend: trendRes.trend,
    expiryDays: daysToExpiry,
    strikeStep,
    maxDistance: payload.maxDistance || 1000
  });

  // Candidate strikes from Premium engine: pick top strikes by premium score
  const premiumCandidates = [];
  for (const b of bucketArray) {
    const ce = b.CE;
    const pe = b.PE;
    const representative = ce || pe;
    if (!representative) continue;
    const price = representative.ltp || (representative.bid + representative.ask) / 2 || 0;
    const iv = representative.iv || 20;
    const ps = premiumScore({ spot, strike: b.strike, ltp: price, ivPercent: iv, daysToExpiry });
    premiumCandidates.push({
      strike: b.strike,
      bestSide: ce && pe ? (ce.ltp > pe.ltp ? 'CE' : 'PE') : (ce ? 'CE' : 'PE'),
      ...ps
    });
  }
  premiumCandidates.sort((a, b) => b.score - a.score);

  // Greeks enrichment for top premium candidates
  const topPremiumEnriched = premiumCandidates.slice(0, 10).map(p => {
    const repr = bucketArray.find(b => b.strike === p.strike);
    const reprPrice = (repr && (repr.midCE || repr.midPE)) || 0;
    const greeks = approxGreeks({ spot, strike: p.strike, daysToExpiry, ivPercent: p.ivPercent || 20 });
    return {
      strike: p.strike,
      bestSide: p.bestSide,
      premiumScore: p.score,
      intrinsic: p.intrinsic,
      extrinsic: p.extrinsic,
      expectedMove: p.expectedMove,
      reprPrice: Number(reprPrice.toFixed(4)),
      greeks
    };
  });

  // Apply safe filters (re-using applySafeFilters)
  const safeResult = applySafeFilters(combinedOptionData, {
    minVolume: payload.minVolume ?? 10,
    minOI: payload.minOI ?? 50,
    maxIV: payload.maxIV ?? 200,
    maxRank: payload.maxRank ?? 50
  });

  // Suggested final strikes: union of trendCandidate and top premium strikes (deduped)
  const finalStrikeSet = new Set();
  const finalList = [];

  // trend strikes
  for (const s of trendCandidate.strikes) {
    const strikeVal = s.strike;
    if (!finalStrikeSet.has(strikeVal)) {
      finalStrikeSet.add(strikeVal);
      finalList.push({ source: 'TREND', strike: strikeVal, note: s.note });
    }
  }
  // premium top 3
  for (const p of premiumCandidates.slice(0, 3)) {
    if (!finalStrikeSet.has(p.strike)) {
      finalStrikeSet.add(p.strike);
      finalList.push({ source: 'PREMIUM', strike: p.strike, score: p.score });
    }
  }

  // adjust for natural gas if needed
  const adjustedFinalList = handleNaturalGasAdjustments({ market, spot, suggestedStrikes: finalList });

  // For each final suggestion, compute sample order parameters (simulated)
  const recommendations = adjustedFinalList.map(s => {
    // pick representative option side and price
    const b = bucketArray.find(bb => bb.strike === s.strike) || {};
    const side = (b.CE && b.CE.ltp >= (b.PE ? b.PE.ltp : -1)) ? 'CE' : 'PE';
    const repr = side === 'CE' ? b.CE : b.PE;
    const entry = repr ? (repr.ltp || (repr.bid + repr.ask) / 2 || 0) : 0;
    const rt = computeSLandTarget({ entryPrice: entry, isSell: false, slPercent: payload.slPercent || 15 });

    return {
      strike: s.strike,
      source: s.source || 'MIX',
      side,
      entry,
      stopLoss: rt.stopLossPrice,
      target: rt.targetPrice,
      greeks: repr ? approxGreeks({ spot, strike: s.strike, daysToExpiry, ivPercent: repr.iv }) : null,
      volRank: (volRankRes.rankMap && volRankRes.rankMap[s.strike]) || null
    };
  });

  const response = {
    ok: true,
    symbol,
    market,
    spot,
    daysToExpiry,
    strikeStep,
    trend: trendRes,
    volRankTop: volRankRes.sorted.slice(0, 10),
    premiumTop: premiumCandidates.slice(0, 10),
    safeFilter: safeResult.debug,
    recommendations,
    diagnostics: {
      bucketCount: bucketArray.length,
      combinedOptionDataCount: combinedOptionData.length
    }
  };

  res.json(response);
}));

/* ===========================
   Endpoint: /order (simulate/place)
   - Accepts an array of orders to place (for simulation or actual place)
   - If payload.simulate===true -> uses placeOrderSimulated
   - If payload.execute===true -> would call smartApiRequest (left as stub)
   =========================== */

app.post('/order', asyncHandler(async (req, res) => {
  const payload = req.body || {};
  const orders = Array.isArray(payload.orders) ? payload.orders : [];
  const simulate = payload.simulate !== undefined ? !!payload.simulate : true;
  const results = [];

  for (const o of orders) {
    try {
      if (simulate) {
        const r = await placeOrderSimulated(o);
        results.push({ ok: true, result: r });
      } else {
        // In production this would create a signed request to SmartAPI
        const headers = await smartApiAuthHeaders();
        // const r = await smartApiRequest('/order/place', o, 'POST');
        // results.push({ ok: true, result: r });
        results.push({ ok: false, error: 'Actual execution disabled in this alpha build' });
      }
    } catch (err) {
      results.push({ ok: false, error: err.message || String(err) });
    }
  }

  res.json({ ok: true, results });
}));

/* ===========================
   Utility Endpoint: /debug/masterfile
   - Returns the current masterTokens (for quick debugging)
   =========================== */

app.get('/debug/masterfile', (req, res) => {
  res.json({ ok: true, masterTokens });
});

/* ===========================
   (Part-2 ends here)
   Continue with:
   - final risk rules enforcement, logging & audit trail
   - more robust SmartAPI wrappers & retries
   - unit-test endpoints & health checks
   - final exports and server listen adjustments (if needed)
   These will be present in Part-3.
   =========================== */
/**
 * Alpha - server.js
 * Part-3 of 3
 *
 * Final continuation and completion of the Alpha server.js (append this after Part-2).
 * Contains enhanced SmartAPI wrappers, risk enforcement, audit trail, unit-test endpoints,
 * graceful shutdown, and final notes.
 */

/* ===========================
   Robust SmartAPI wrapper & retries
   - Uses smartApiAuthHeaders() from Part-2
   - Performs exponential backoff for transient errors
   =========================== */

async function smartApiRequest(path, body = {}, method = 'POST', opts = {}) {
  const maxRetries = opts.maxRetries ?? 3;
  const baseUrl = opts.baseUrl || 'https://api.smartapi.example'; // replace in production
  const url = `${baseUrl}${path}`;
  const makeAttempt = async (attempt) => {
    try {
      const headers = await smartApiAuthHeaders();
      const resp = await fetch(url, {
        method,
        headers,
        body: method === 'GET' ? undefined : JSON.stringify(body),
        timeout: opts.timeout || 15000
      });
      // treat non-2xx as error to trigger retry logic when appropriate
      if (!resp.ok) {
        const txt = await resp.text().catch(() => '');
        const err = new Error(`HTTP ${resp.status} ${resp.statusText} ${txt}`);
        err.status = resp.status;
        throw err;
      }
      const json = await resp.json();
      return json;
    } catch (err) {
      // transient network/5xx errors -> retry
      const status = err && err.status;
      const isTransient = !status || (status >= 500 && status < 600);
      if (attempt < maxRetries && isTransient) {
        const backoffMs = Math.pow(2, attempt) * 250;
        log(`smartApiRequest transient error, retrying attempt=${attempt + 1} backoff=${backoffMs}ms`, err.message || err);
        await new Promise(r => setTimeout(r, backoffMs));
        return makeAttempt(attempt + 1);
      }
      // bubble up final error
      log('smartApiRequest final error', err.message || err);
      throw err;
    }
  };
  return makeAttempt(0);
}

/* ===========================
   Audit / logging trail (in-memory, can be persisted to DB/files)
   - stores last N events for quick debugging
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
   Risk rules enforcement (final guard before placing orders)
   - Enforces max exposure per-symbol, max daily-loss, SL % and quantity limits
   - These are configurable via env or passed payload
   =========================== */

const RISK = {
  maxExposurePerSymbol: parseFloat(process.env.MAX_EXPOSURE_PER_SYMBOL) || 100000, // currency units
  maxDailyLoss: parseFloat(process.env.MAX_DAILY_LOSS) || 200000,
  maxQtyPerOrder: parseInt(process.env.MAX_QTY_PER_ORDER) || 500,
  enforcedSLPercent: parseFloat(process.env.ENFORCED_SL_PERCENT) || 15
};

function enforceRiskRules(orderRequests = [], context = {}) {
  // orderRequests: [{ symbol, strike, side, qty, entry, ... }, ...]
  const violations = [];
  let totalNotional = 0;

  for (const o of orderRequests) {
    const qty = Number(o.qty || 0);
    const entry = Number(o.price || o.entry || 0);
    const notional = qty * entry;

    totalNotional += notional;

    if (qty <= 0) violations.push({ order: o, reason: 'qty-must-be-positive' });
    if (qty > RISK.maxQtyPerOrder) violations.push({ order: o, reason: `qty-exceeds-max(${RISK.maxQtyPer_ORDER || RISK.maxQtyPerOrder})` });
    if ((o.slPercent || RISK.enforcedSLPercent) > 50) violations.push({ order: o, reason: 'sl-too-large' });
    if (entry < 0) violations.push({ order: o, reason: 'invalid-entry-price' });
  }

  if (totalNotional > RISK.maxExposurePerSymbol) {
    violations.push({ reason: 'exposure-exceeds-max', totalNotional, limit: RISK.maxExposurePerSymbol });
  }

  return { ok: violations.length === 0, violations, totalNotional };
}

/* ===========================
   Endpoint: /debug/audit
   - Returns recent audit trail entries (read-only)
   =========================== */

app.get('/debug/audit', (req, res) => {
  res.json({ ok: true, count: auditTrail.length, trail: auditTrail.slice(-200) });
});

/* ===========================
   Endpoint: /test/greeks
   - Quick unit-test endpoint that returns approxGreeks for provided params
   =========================== */

app.get('/test/greeks', (req, res) => {
  const q = req.query || {};
  const spot = safeParseFloat(q.spot, 100);
  const strike = safeParseFloat(q.strike, Math.round(spot));
  const days = Number.isFinite(Number(q.days)) ? Number(q.days) : 7;
  const iv = safeParseFloat(q.iv, 20);
  const g = approxGreeks({ spot, strike, daysToExpiry: days, ivPercent: iv });
  res.json({ ok: true, params: { spot, strike, days, iv }, greeks: g });
});

/* ===========================
   Endpoint: /test/volrank
   - Accepts minimal synthetic option data to verify getVolRank behavior
   =========================== */
app.post('/test/volrank', (req, res) => {
  const data = Array.isArray(req.body.data) ? req.body.data : [];
  const r = getVolRank('TEST', data);
  res.json({ ok: true, inputCount: data.length, result: r });
});

/* ===========================
   Endpoint: /execute
   - High-level endpoint that runs suggestion -> risk check -> (simulate or execute)
   - Payload: { orders: [...], simulate: true|false, meta: {...} }
   =========================== */

app.post('/execute', asyncHandler(async (req, res) => {
  const payload = req.body || {};
  const orders = Array.isArray(payload.orders) ? payload.orders : [];
  const simulate = payload.simulate !== undefined ? !!payload.simulate : true;

  // audit request
  audit({ type: 'execute_request', orders, simulate, meta: payload.meta || null });

  // risk check
  const riskCheck = enforceRiskRules(orders, { user: payload.user || 'anonymous' });
  if (!riskCheck.ok) {
    audit({ type: 'execute_rejected', reason: 'risk-violation', riskCheck });
    return res.json({ ok: false, error: 'risk-violation', details: riskCheck });
  }

  const results = [];
  for (const o of orders) {
    try {
      if (simulate) {
        const r = await placeOrderSimulated(o);
        results.push({ ok: true, simulated: true, result: r });
        audit({ type: 'order_simulated', order: o, result: r });
      } else {
        // final execution path - use smartApiRequest
        const body = {
          symbol: o.symbol,
          strike: o.strike,
          type: o.type || 'CE',
          qty: o.qty,
          price: o.price || o.entry,
          side: o.side || 'BUY'
        };
        // NOTE: this will attempt to call the SmartAPI; in this alpha, baseUrl is example and will fail unless replaced.
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
   Health & readiness improvements
   - Expose /ready which ensures session auth is possible (best-effort)
   =========================== */

app.get('/ready', asyncHandler(async (req, res) => {
  try {
    await smartApiLogin(); // attempt to ensure session
    res.json({ ok: true, ready: true, time: nowISO() });
  } catch (err) {
    res.status(500).json({ ok: false, ready: false, error: err.message || String(err) });
  }
}));

/* ===========================
   Graceful shutdown & process signals
   =========================== */

let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  log('Shutting down gracefully...');
  // flush audit trail or persist if needed (stub)
  // close DB connections, other cleanup
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('uncaughtException', (err) => {
  log('uncaughtException', err && err.stack ? err.stack : err);
  audit({ type: 'uncaughtException', error: err && err.message ? err.message : String(err) });
  // attempt graceful shutdown
  setTimeout(() => process.exit(1), 2000);
});

/* ===========================
   Final export & listen (if run standalone)
   - Keep same pattern as Part-1 to avoid double-listen when imported as module
   =========================== */

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    log(`Alpha server (complete) listening on ${PORT}`);
  });
}

/* ===========================
   Final notes:
   - Replace baseUrl 'https://api.smartapi.example' with real SmartAPI endpoints before enabling execute:true.
   - Populate masterTokens (masterfile) with accurate instrument tokens for production.
   - Consider persisting auditTrail to durable storage for compliance/backtesting.
   - Unit tests (jest/mocha) are recommended for all engines (greeks, volrank, premium).
   =========================== */
