// ---------- ALPHA (final) - server.js (PART 1 of 2) ----------
// Final-locked Alpha implementation (Part 1)
// NOTE: Merge Part 1 + Part 2 to form complete server.js

'use strict';

/**
 * Required environment variables:
 * - SMART_API_KEY
 * - SMART_API_SECRET
 * - SMART_TOTP
 * - SMART_USER_ID
 * - PORT (optional)
 *
 * This file expects to run in Node.js >= 16
 */

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { totp } = require('otplib'); // package otplib used for TOTP
const bodyParser = require('body-parser');

// Utility libs
const moment = require('moment'); // for expiry logic and times

// Config / env
const SMART_API_KEY = process.env.SMART_API_KEY || '';
const SMART_API_SECRET = process.env.SMART_API_SECRET || '';
const SMART_TOTP_SECRET = process.env.SMART_TOTP || '';
const SMART_USER_ID = process.env.SMART_USER_ID || '';
const PORT = process.env.PORT || 3000;

// SmartAPI endpoints (these are placeholders — ensure correct endpoints in your environment)
const SMART_BASE = process.env.SMART_BASE || 'https://api.angelbroking.com'; // replace if different

// Simple in-memory session storage (re-login when expired)
let session = {
  token: null,
  user_id: SMART_USER_ID,
  expires_at: 0
};

// Express app
const app = express();
app.use(bodyParser.json());

// ---------- Helper: SmartAPI Auth & Request Wrappers ----------

/**
 * generateTotp: generate TOTP using provided secret
 */
function generateTotp(secret) {
  if (!secret) return '';
  // using otplib default options (30s step)
  return totp.generate(secret);
}

/**
 * loginToSmartAPI: create a session token and store in session variable
 * This uses the typical SmartAPI TOTP login flow — adapt according to exact provider endpoints.
 */
async function loginToSmartAPI() {
  try {
    const totpCode = generateTotp(SMART_TOTP_SECRET);

    // This payload assumes Angel One SmartAPI-like flow; adapt if different
    const payload = {
      client_id: SMART_API_KEY,
      client_secret: SMART_API_SECRET,
      totp: totpCode,
      user_id: SMART_USER_ID
    };

    // Example endpoint - replace with your provider's exact login URL
    const url = `${SMART_BASE}/oauth/token`;

    const res = await axios.post(url, payload, { timeout: 10000 });
    if (res && res.data && res.data.access_token) {
      session.token = res.data.access_token;
      // if provider gives expires_in
      const ttl = res.data.expires_in || 3600;
      session.expires_at = Date.now() + ttl * 1000 - 30000; // 30s early
      session.user_id = SMART_USER_ID;
      console.log('SmartAPI login success');
      return true;
    } else {
      console.warn('SmartAPI login: unexpected response', res.data);
      return false;
    }
  } catch (err) {
    console.error('SmartAPI login error', err.message || err);
    return false;
  }
}

/**
 * ensureSession: checks and logs in if necessary
 */
async function ensureSession() {
  if (!session.token || Date.now() > session.expires_at - 10000) {
    const ok = await loginToSmartAPI();
    if (!ok) throw new Error('Unable to login to SmartAPI');
  }
}

/**
 * smartApiGet: generic GET wrapper using current session token
 */
async function smartApiGet(path, params = {}) {
  await ensureSession();
  const url = `${SMART_BASE}${path}`;
  try {
    const res = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${session.token}`,
        'Content-Type': 'application/json'
      },
      params,
      timeout: 10000
    });
    return res.data;
  } catch (err) {
    // If unauthorized, try re-login once
    if (err.response && (err.response.status === 401 || err.response.status === 403)) {
      console.warn('SmartAPI unauthorized — re-login and retry');
      await loginToSmartAPI();
      const retry = await axios.get(url, {
        headers: { Authorization: `Bearer ${session.token}` },
        params,
        timeout: 10000
      });
      return retry.data;
    }
    throw err;
  }
}

/**
 * smartApiPost: generic POST wrapper
 */
async function smartApiPost(path, body = {}) {
  await ensureSession();
  const url = `${SMART_BASE}${path}`;
  try {
    const res = await axios.post(url, body, {
      headers: {
        Authorization: `Bearer ${session.token}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    return res.data;
  } catch (err) {
    if (err.response && (err.response.status === 401 || err.response.status === 403)) {
      console.warn('SmartAPI unauthorized — re-login and retry (POST)');
      await loginToSmartAPI();
      const retry = await axios.post(url, body, {
        headers: { Authorization: `Bearer ${session.token}` },
        timeout: 10000
      });
      return retry.data;
    }
    throw err;
  }
}

// ---------- Market Utilities (Expiry detection, instruments, tokens) ----------

/**
 * detectExpiryForSymbol: returns expiry date string(s) for the given symbol.
 * Uses final-locked logic: current week -> next week -> monthly fallback.
 */
function detectExpiryForSymbol(symbol, referenceDate = new Date()) {
  // For indices (NIFTY/BANKNIFTY) weekly expiry typically Thursday (or Thursday as per exchange).
  // We'll compute next Thursday >= today, else next week, and also monthly (last Thursday).
  const ref = moment(referenceDate).utcOffset('+05:30'); // India timezone assumption
  const weekday = ref.isoWeekday(); // 1..7 (Mon..Sun)

  // find nearest Thursday of current week (4)
  let currentThursday = ref.clone().isoWeekday(4);
  if (weekday > 4) {
    // already past this week's Thursday -> next week's Thursday
    currentThursday.add(1, 'week');
  }
  // monthly - last Thursday of month
  const endOfMonth = ref.clone().endOf('month');
  // find last Thursday of month
  let lastThursday = endOfMonth.clone().isoWeekday(4);
  if (lastThursday.isAfter(endOfMonth)) lastThursday.subtract(7, 'days');

  return {
    currentWeek: currentThursday.format('YYYY-MM-DD'),
    nextWeek: currentThursday.clone().add(1, 'week').format('YYYY-MM-DD'),
    monthly: lastThursday.format('YYYY-MM-DD')
  };
}

/**
 * fetchInstrumentTokens: resolve CE/PE tokens for a given instrument and strike
 * This uses SmartAPI instrument endpoints (provider-specific). The function must be adapted
 * if your provider's instrument schema differs.
 */
async function fetchInstrumentTokens(symbol, expiry, strike, optionType = 'CE') {
  // Example placeholder endpoint; replace with actual instrument/catalog endpoint
  // We'll query SmartAPI's instruments list with filters
  const path = `/market/instruments`; // adapt path
  // Many providers provide a search or instruments endpoint that accepts symbol/expiry/strike/type
  // We'll attempt generic GET with params; adapt in real deployment.
  const params = {
    symbol,
    expiry,
    strike,
    optionType
  };
  try {
    const data = await smartApiGet(path, params);
    // data should contain array of instruments; pick best match
    if (Array.isArray(data) && data.length > 0) {
      // pick exact match if available
      const match = data.find(it => {
        const s = String(it.strike || it.strikePrice || it.strike_price || it.option_strike);
        const e = String(it.expiry || it.expiryDate || it.expiry_date);
        const t = (it.instrumentType || it.optionType || '').toUpperCase();
        return Number(s) === Number(strike) && e.startsWith(expiry) && t.startsWith(optionType);
      }) || data[0];
      return {
        token: match.token || match.tradingSymbol || match.instrument_token || match.id,
        instrument: match
      };
    } else if (data && data.result && Array.isArray(data.result) && data.result.length > 0) {
      const match = data.result[0];
      return {
        token: match.token || match.tradingSymbol || match.instrument_token || match.id,
        instrument: match
      };
    } else {
      return null;
    }
  } catch (err) {
    console.warn('fetchInstrumentTokens error', err.message || err);
    return null;
  }
}

// ---------- Market Data Fetchers: candles, ltp, oi, greeks (where possible) ----------

/**
 * fetchLTP: fetch live LTP for a token (or symbol)
 */
async function fetchLTPByToken(token) {
  try {
    // provider-specific LTP endpoint
    const path = `/market/ltp`;
    const res = await smartApiGet(path, { token });
    // return numeric LTP
    if (res && res.ltp) return Number(res.ltp);
    if (res && res.result && Array.isArray(res.result) && res.result[0] && res.result[0].ltp) {
      return Number(res.result[0].ltp);
    }
    // fallback
    return null;
  } catch (err) {
    console.warn('fetchLTPByToken error', err.message || err);
    return null;
  }
}

/**
 * fetchRecentCandles: fetch recent candle data (for momentum/EMA/RSI)
 * timeframe in minutes (e.g., 1, 5)
 */
async function fetchRecentCandles(symbolOrToken, timeframe = 5, count = 100) {
  try {
    const path = `/market/candles`;
    const res = await smartApiGet(path, { symbol: symbolOrToken, interval: `${timeframe}m`, count });
    // expect [{open,high,low,close,volume,timestamp}, ...]
    if (res && Array.isArray(res)) return res;
    if (res && res.data && Array.isArray(res.data)) return res.data;
    if (res && res.result && Array.isArray(res.result)) return res.result;
    return [];
  } catch (err) {
    console.warn('fetchRecentCandles error', err.message || err);
    return [];
  }
}

/**
 * computeEMA: simple EMA calculation, returns last EMA
 */
function computeEMA(values, period) {
  if (!values || values.length < period) return null;
  const k = 2 / (period + 1);
  let ema = values.slice(0, period).reduce((a, b) => a + b, 0) / period;
  for (let i = period; i < values.length; i++) {
    ema = values[i] * k + ema * (1 - k);
  }
  return ema;
}

/**
 * computeRSI: returns last RSI using standard 14 period
 */
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

// ---------- Trend Engine (Hybrid C) ----------

/**
 * trendEngine: returns {trend: 'UP'|'DOWN'|'NEUTRAL', confidence: 0..1}
 * Uses EMA(20), EMA(50), RSI, recent momentum
 */
async function trendEngine(indexSymbol) {
  try {
    // fetch 1m & 5m candles for more robust decision
    const candles5 = await fetchRecentCandles(indexSymbol, 5, 60); // last 5m candles
    const candles1 = await fetchRecentCandles(indexSymbol, 1, 120); // last 1m candles

    // extract closes
    const closes5 = candles5.map(c => Number(c.close)).filter(Boolean);
    const closes1 = candles1.map(c => Number(c.close)).filter(Boolean);

    // compute EMAs
    const ema20 = computeEMA(closes5, 20);
    const ema50 = computeEMA(closes5, 50);

    // rsi from 14 period on 1m
    const rsi = computeRSI(closes1, 14);

    // momentum: last close - mean of previous 5 closes
    const recent = closes1.slice(-6);
    const last = recent[recent.length - 1];
    const meanPrev = recent.slice(0, -1).reduce((a, b) => a + b, 0) / Math.max(1, recent.length - 1);
    const momentum = last - meanPrev;

    // score components
    let score = 0;
    if (ema20 && ema50) {
      if (ema20 > ema50) score += 0.4;
      else if (ema20 < ema50) score -= 0.4;
    }
    if (rsi != null) {
      if (rsi > 55) score += 0.2;
      else if (rsi < 45) score -= 0.2;
    }
    // momentum contribution (scaled)
    const momScore = Math.tanh(momentum / Math.max(1, meanPrev)) * 0.4;
    score += momScore;

    const confidence = Math.min(1, Math.abs(score));
    const trend = score > 0.08 ? 'UP' : (score < -0.08 ? 'DOWN' : 'NEUTRAL');

    return { trend, confidence: Number(confidence.toFixed(3)), debug: { ema20, ema50, rsi, momentum, score } };
  } catch (err) {
    console.warn('trendEngine error', err.message || err);
    return { trend: 'NEUTRAL', confidence: 0.2 };
  }
}

// ---------- Strike Generator (ATM + 2 near ATM) ----------

/**
 * roundToNearestStrike: depending on instrument's strike step (e.g., 100 for BANKNIFTY), round to nearest step
 * We'll use provided strikeStep (e.g., 100 for BANKNIFTY, 50 for NIFTY) — fallback 50.
 */
function roundToNearestStrike(price, strikeStep = 50) {
  const rounded = Math.round(price / strikeStep) * strikeStep;
  return rounded;
}

/**
 * computeStrikeDistanceByExpiry: dynamic distance based on days-to-expiry
 * short expiry => smaller distances; long expiry => wider distances
 */
function computeStrikeDistance(daysToExpiry, baseStep = 1) {
  // baseStep * strikeStep will be multiplied by strikeStep outside
  // simple rule: <=3 days -> 1 step, 4-7 -> 2 steps, >7 -> 3 steps
  if (daysToExpiry <= 3) return baseStep * 1;
  if (daysToExpiry <= 7) return baseStep * 2;
  return baseStep * 3;
}

/**
 * generate3Strikes: returns array of three strike numbers [ATM, ATM+X, ATM-X]
 */
function generate3Strikes(spot, expiryDateStr, strikeStep = 50) {
  const today = moment();
  const expiry = moment(expiryDateStr);
  const days = Math.max(0, expiry.diff(today, 'days'));
  const stepCount = computeStrikeDistance(days, 1);
  const atm = roundToNearestStrike(spot, strikeStep);
  const distance = stepCount * strikeStep;
  const up = atm + distance;
  const down = atm - distance;
  return { atm, up, down, distance };
}

// ---------- Entry Engine (Hybrid final logic) ----------

/**
 * entryEngine: compute smart entry price for a given strike token and context
 * Final locked logic:
 * Entry = Momentum-confirmed breakout price + Risk/Reward validation + LTP sanity-check
 * Practical implementation:
 * - Use recent candles to find breakout above local resistance (for CE) or below support (for PE)
 * - Validate that R/R with SL=entry-15 and target (momentum*trend*volatility) is acceptable (>1.2)
 * - Do not simply return LTP — return an 'ideal' entry near LTP but adjusted to avoid immediate SL hits
 */
async function computeSmartEntry(context) {
  /**
   * context: {
   *   indexSymbol, strike, type ('CE'|'PE'), strikeToken,
   *   trendObj: {trend, confidence}, expiry, strikeStep, spot
   * }
   */
  const { indexSymbol, strike, type, strikeToken, trendObj, expiry, strikeStep, spot } = context;
  try {
    // 1) get recent candles for option token (if available), else use index candles for proxy
    let candles = [];
    if (strikeToken) candles = await fetchRecentCandles(strikeToken, 1, 60);
    if (!candles || candles.length < 6) {
      // fallback to index candles as proxy for momentum
      candles = await fetchRecentCandles(indexSymbol, 1, 60);
    }
    const closes = candles.map(c => Number(c.close)).filter(Boolean);
    const highs = candles.map(c => Number(c.high)).filter(Boolean);
    const lows = candles.map(c => Number(c.low)).filter(Boolean);

    if (!closes || closes.length < 6) {
      // fallback: use LTP as entry if insufficient data
      const ltp = strikeToken ? await fetchLTPByToken(strikeToken) : null;
      return { entry: ltp || null, reason: 'fallback-ltp-or-insufficient-candles' };
    }

    // Momentum breakout detection (simple): recent max/min on last N candles
    const lookback = Math.min(10, closes.length - 1);
    const recentHigh = Math.max(...highs.slice(-lookback));
    const recentLow = Math.min(...lows.slice(-lookback));
    const lastClose = closes[closes.length - 1];
    const prevClose = closes[closes.length - 2];

    // compute volatility factor (ATR approx)
    const trArray = [];
    for (let i = 1; i < closes.length; i++) {
      const tr = Math.max(
        Math.abs(highs[i] - lows[i]),
        Math.abs(highs[i] - closes[i - 1] || 0),
        Math.abs(lows[i] - closes[i - 1] || 0)
      );
      trArray.push(tr);
    }
    const avgTR = trArray.length ? trArray.reduce((a, b) => a + b, 0) / trArray.length : 0;
    const volatilityFactor = avgTR || (lastClose * 0.02);

    // breakout threshold
    let breakoutPrice = null;
    if (type === 'CE') {
      if (lastClose > recentHigh && lastClose > prevClose) {
        // breakout above resistance
        breakoutPrice = Math.max(lastClose, recentHigh + volatilityFactor * 0.2);
      } else {
        // momentum entry: slightly above last close but not equal to LTP exactly
        breakoutPrice = lastClose + Math.max(0.5, volatilityFactor * 0.1);
      }
    } else {
      // PE -> breakdown logic
      if (lastClose < recentLow && lastClose < prevClose) {
        breakoutPrice = Math.min(lastClose, recentLow - volatilityFactor * 0.2);
      } else {
        breakoutPrice = lastClose - Math.max(0.5, volatilityFactor * 0.1);
        if (breakoutPrice < 0) breakoutPrice = Math.max(0.1, lastClose * 0.98);
      }
    }

    // LTP sanity: fetch LTP and adjust if entry dangerously below/above LTP
    const ltp = strikeToken ? await fetchLTPByToken(strikeToken) : null;
    let finalEntry = breakoutPrice;
    if (ltp != null) {
      // avoid entry that is on wrong side of LTP significantly
      if (type === 'CE') {
        // Do not return entry below LTP -  because that may be old
        if (finalEntry < ltp * 0.98) finalEntry = Math.max(finalEntry, ltp * 0.99);
        // also avoid entry that immediately makes SL hit: we apply small cushion
      } else {
        if (finalEntry > ltp * 1.02) finalEntry = Math.min(finalEntry, ltp * 1.01);
      }
      // ensure entry isn't absurdly far from LTP (> 50%)
      if (Math.abs(finalEntry - ltp) / Math.max(1, ltp) > 0.5) {
        finalEntry = ltp;
      }
    }

    // Risk-Reward validation:
    // SL = entry - 15 (locked)
    const sl = Math.max(0.01, finalEntry - 15);
    // provisional target computed below by targetEngine; but estimate rough R/R:
    const estimatedMomentum = Math.abs(lastClose - closes[closes.length - 6] || 0);
    const estimatedTarget = finalEntry + (estimatedMomentum * (trendObj.confidence || 0.5));
    const rr = (estimatedTarget - finalEntry) / Math.max(0.01, (finalEntry - sl));

    // If R/R too low (<1.1), nudge entry to improve R/R by moving entry slightly inward (reduce risk)
    if (rr < 1.1) {
      // move entry away from SL direction by volatility factor
      if (type === 'CE') finalEntry = finalEntry + Math.max(0.5, volatilityFactor * 0.1);
      else finalEntry = Math.max(0.01, finalEntry - Math.max(0.5, volatilityFactor * 0.1));
    }

    // Final rounding to 2 decimals
    finalEntry = Math.round(finalEntry * 100) / 100;

    return { entry: finalEntry, ltp, reason: 'hybrid-breakout-rr-sanity', debug: { recentHigh, recentLow, avgTR, volatilityFactor, estimatedMomentum, rr } };
  } catch (err) {
    console.warn('computeSmartEntry error', err.message || err);
    return { entry: null, reason: 'error' };
  }
}

// END OF PART 1
// ---------- ALPHA (final) - server.js (PART 2 of 2) ----------
// Continue from Part 1

// ---------- Target Engine ----------
/**
 * targetEngine: computes target based on final-locked formula:
 * Target = Entry + (momentum_strength × trend_confidence × volatility_factor)
 */
function targetEngine(entry, momentumStrength = 1, trendConfidence = 0.5, volatilityFactor = 1) {
  // momentumStrength, trendConfidence, volatilityFactor are expected to be numeric
  const delta = momentumStrength * trendConfidence * volatilityFactor;
  // ensure target at least entry + small premium
  const rawTarget = entry + Math.max(1, delta);
  // round to 2 decimals
  return Math.round(rawTarget * 100) / 100;
}

// ---------- Combined Strike Scoring (Greeks, Volume, OI, Premium, S/R, Futures) ----------
/**
 * combinedScore: given metrics, compute combined score 0..1
 * We attempt a balanced scoring using placeholder metrics fetches.
 * In production you should supply greeks/OI/volume/futures API responses.
 */
function combinedScore(metrics) {
  // metrics: {deltaScore, thetaScore, volumeScore, oiScore, premiumScore, srScore, futuresScore}
  const weights = {
    delta: 0.18,
    theta: 0.08,
    volume: 0.18,
    oi: 0.18,
    premium: 0.12,
    sr: 0.12,
    futures: 0.14
  };
  // normalize
  const s = (metrics.deltaScore || 0) * weights.delta +
            (metrics.thetaScore || 0) * weights.theta +
            (metrics.volumeScore || 0) * weights.volume +
            (metrics.oiScore || 0) * weights.oi +
            (metrics.premiumScore || 0) * weights.premium +
            (metrics.srScore || 0) * weights.sr +
            (metrics.futuresScore || 0) * weights.futures;
  return Math.max(0, Math.min(1, s));
}

// ---------- Main Strike Routine ----------
/**
 * buildAlphaStrikeSet: main function to produce 3-strike output for a given index symbol
 * Returns array of 3 strike objects in JSON format:
 * { strike, entry, stopLoss, target, distance, type, token, reason }
 */
async function buildAlphaStrikeSet(indexSymbol = 'BANKNIFTY', options = {}) {
  try {
    // 1) get spot LTP for index (master spot)
    // For indices we may have dedicated symbol tokens; here we use a provider symbol name
    // Example: 'NIFTY', 'BANKNIFTY', 'SENSEX', 'NATGAS' (MCX)
    const spotPath = `/market/ltp`;
    let spotLtp = null;
    try {
      const spotRes = await smartApiGet('/market/ltp', { symbol: indexSymbol });
      if (spotRes && spotRes.ltp) spotLtp = Number(spotRes.ltp);
      else if (spotRes && spotRes.result && Array.isArray(spotRes.result) && spotRes.result[0]) {
        spotLtp = Number(spotRes.result[0].ltp || spotRes.result[0].close);
      }
    } catch (err) {
      console.warn('spot fetch failed for', indexSymbol, err.message || err);
    }
    if (!spotLtp) {
      // fallback: try to fetch index instrument token
      // If still not found, throw
      throw new Error('Unable to fetch spot LTP for index: ' + indexSymbol);
    }

    // 2) detect expiry
    const expiries = detectExpiryForSymbol(indexSymbol);
    // choose currentWeek expiry primarily
    const expiry = expiries.currentWeek;

    // 3) compute strike step for given instrument — using conservative defaults
    let strikeStep = 50;
    if (indexSymbol.toUpperCase().includes('BANK')) strikeStep = 100;
    if (indexSymbol.toUpperCase().includes('SENSEX')) strikeStep = 100;
    if (indexSymbol.toUpperCase().includes('NATGAS')) strikeStep = 10; // MCX different tick/strike sizing; adjust as needed

    // 4) generate 3 strikes
    const { atm, up, down, distance } = generate3Strikes(spotLtp, expiry, strikeStep);

    // 5) run trend engine (final-locked Hybrid C)
    const trendObj = await trendEngine(indexSymbol);

    // 6) for each strike, resolve tokens and compute metrics, entry, target
    const strikes = [atm, up, down];
    const results = [];
    for (const s of strikes) {
      // resolve CE and PE token (primary)
      const ceInfo = await fetchInstrumentTokens(indexSymbol, expiry, s, 'CE');
      const peInfo = await fetchInstrumentTokens(indexSymbol, expiry, s, 'PE');

      // For scoring we attempt to fetch some metrics - fallback to defaults
      const metrics = {
        deltaScore: 0.5,
        thetaScore: 0.5,
        volumeScore: 0.5,
        oiScore: 0.5,
        premiumScore: 0.5,
        srScore: 0.5,
        futuresScore: 0.5
      };

      // compute CE side entry & target if trend suggests CE, else PE side; also always provide both (paired)
      // Decide side using final locked trend rules:
      let preferredType = 'CE';
      if (trendObj.trend === 'UP') preferredType = 'CE';
      else if (trendObj.trend === 'DOWN') preferredType = 'PE';
      else {
        // NEUTRAL -> pick side with better combinedScore (we compute both)
        // We'll compute both below and pick later
        preferredType = 'BOTH';
      }

      // Helper to build single side result
      async function buildSide(type) {
        const info = (type === 'CE') ? ceInfo : peInfo;
        const token = info ? (info.token || info.instrument?.token || info.instrument?.tradingSymbol) : null;

        // compute entry (hybrid)
        const entryObj = await computeSmartEntry({
          indexSymbol,
          strike: s,
          type,
          strikeToken: token,
          trendObj,
          expiry,
          strikeStep,
          spot: spotLtp
        });
        const entry = entryObj.entry != null ? Number(entryObj.entry) : null;
        // stopLoss locked rule
        const stopLoss = entry != null ? Math.round((entry - 15) * 100) / 100 : null;
        // target
        const momentumStrength = Math.abs((entry || 0) - (entryObj.ltp || entry || 0)) || 1;
        const target = entry != null ? targetEngine(entry, momentumStrength, trendObj.confidence || 0.4, Math.max(1, momentumStrength)) : null;

        // combined score (placeholder, as we didn't fetch actual greeks) - used to order strikes later
        const cscore = combinedScore(metrics);

        return {
          strike: s,
          type,
          token,
          entry,
          stopLoss,
          target,
          distance,
          score: cscore,
          debugEntryReason: entryObj.reason,
          entryDebug: entryObj.debug || {}
        };
      }

      // compute both sides
      const ceSide = await buildSide('CE');
      const peSide = await buildSide('PE');

      // choose preferred side based on final locked rule
      let chosen = null;
      if (preferredType === 'CE') chosen = ceSide;
      else if (preferredType === 'PE') chosen = peSide;
      else {
        // NEUTRAL -> choose side with better R/R (target vs sl)
        function rr(side) {
          if (!side || side.entry == null || side.stopLoss == null || side.target == null) return -1;
          const risk = side.entry - side.stopLoss;
          if (risk <= 0) return -1;
          return (side.target - side.entry) / risk;
        }
        const r_ce = rr(ceSide);
        const r_pe = rr(peSide);
        if (r_ce === r_pe) {
          // fallback to higher combined score
          chosen = ceSide.score >= peSide.score ? ceSide : peSide;
        } else {
          chosen = r_ce > r_pe ? ceSide : peSide;
        }
      }

      // Save pair with both sides too
      results.push({
        strike: s,
        distance,
        atm: s === atm,
        pair: {
          CE: ceSide,
          PE: peSide
        },
        chosen // chosen side object (CE or PE)
      });
    }

    // Order results: prefer higher chosen.score then atm first
    const ordered = results.sort((a, b) => {
      // prefer ATM in top
      if (a.atm && !b.atm) return -1;
      if (b.atm && !a.atm) return 1;
      const sa = a.chosen.score || 0;
      const sb = b.chosen.score || 0;
      return sb - sa;
    });

    // final output: three chosen sides in order ATM, up, down but with chosen side info
    const finalOutput = ordered.map(r => {
      const c = r.chosen;
      return {
        strike: r.strike,
        type: c.type,
        token: c.token,
        entry: c.entry,
        stopLoss: c.stopLoss,
        target: c.target,
        distance: r.distance,
        reason: c.debugEntryReason,
        debug: c.entryDebug,
        score: Number((c.score || 0).toFixed(3))
      };
    });

    return { index: indexSymbol, spot: spotLtp, expiry, strikes: finalOutput, trend: trendObj };
  } catch (err) {
    console.error('buildAlphaStrikeSet error', err.message || err);
    return { error: err.message || String(err) };
  }
}

// ---------- API Endpoints ----------

app.get('/health', async (req, res) => {
  try {
    // minimal health: can we ensure session?
    let ok = true;
    try {
      await ensureSession();
    } catch (e) {
      ok = false;
    }
    res.json({
      status: ok ? 'ok' : 'degraded',
      serverTime: new Date().toISOString(),
      tokenPresent: !!session.token
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message || err });
  }
});

/**
 * GET /strike?symbol=BANKNIFTY
 * Returns final locked 3-strike output for requested symbol
 */
app.get('/strike', async (req, res) => {
  try {
    const symbol = (req.query.symbol || 'BANKNIFTY').toUpperCase();
    // Validate allowed symbols if you want to restrict
    const allowed = ['BANKNIFTY', 'NIFTY', 'SENSEX', 'NATGAS'];
    if (!allowed.includes(symbol)) {
      return res.status(400).json({ error: 'Symbol not supported. Allowed: ' + allowed.join(',') });
    }

    const out = await buildAlphaStrikeSet(symbol);
    if (out.error) return res.status(500).json({ error: out.error });
    return res.json(out);
  } catch (err) {
    console.error('/strike error', err.message || err);
    res.status(500).json({ error: err.message || err });
  }
});

// ---------- Server Startup ----------
app.listen(PORT, () => {
  console.log(`Alpha server.js running on port ${PORT}`);
  console.log('Endpoints: GET /health , GET /strike?symbol=BANKNIFTY');
});

// ---------- End of server.js (Part 2) ----------
