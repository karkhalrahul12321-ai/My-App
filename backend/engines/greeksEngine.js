/**
 * greeksEngine.js
 *
 * Provides:
 *  - Black-Scholes pricing (for spot-based underlyings)
 *  - Black-76 style fallback (for futures-based underlyings) can be added later
 *  - Normal CDF via mathjs erf
 *  - augmentChainWithGreeks(chain, spot, expiry)
 *
 * Notes:
 *  - expiry is expected either as { date: 'YYYY-MM-DD', daysLeft: N } or a string 'YYYY-MM-DD'
 *  - chain is an array of { strike, call: { ltp, iv, oi, volume }, put: { ... } }
 *  - This implementation uses IV from chain if present, otherwise a default.
 *  - Greeks are approximate (sufficient for scoring & filters). For production you can replace with higher-precision libs.
 */

const { erf } = require('mathjs');

function norm_cdf(x) {
  return 0.5 * (1 + erf(x / Math.sqrt(2)));
}

function bs_price(S, K, T, r, sigma, isCall) {
  // Guard small T or zero volatility
  if (T <= 0) {
    const intrinsic = isCall ? Math.max(0, S - K) : Math.max(0, K - S);
    return intrinsic;
  }
  if (sigma <= 0) {
    const intrinsic = isCall ? Math.max(0, S - K) : Math.max(0, K - S);
    return intrinsic;
  }

  const sqrtT = Math.sqrt(T);
  const d1 = (Math.log(S / K) + 0.5 * sigma * sigma * T) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;

  const Nd1 = norm_cdf(d1);
  const Nd2 = norm_cdf(d2);

  if (isCall) {
    return S * Nd1 - K * Math.exp(-r * T) * Nd2;
  } else {
    return K * Math.exp(-r * T) * norm_cdf(-d2) - S * norm_cdf(-d1);
  }
}

function bs_greeks(S, K, T, r, sigma, isCall) {
  // Returns { delta, gamma, theta, vega, rho }
  if (T <= 0 || sigma <= 0) {
    // on expiry or zero vol - approximate greeks
    const intrinsic = isCall ? (S > K ? 1 : 0) : (S < K ? -1 : 0);
    return {
      delta: intrinsic,
      gamma: 0,
      theta: 0,
      vega: 0,
      rho: 0
    };
  }

  const sqrtT = Math.sqrt(T);
  const d1 = (Math.log(S / K) + 0.5 * sigma * sigma * T) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;

  // PDF approx using derivative of erf: pdf = exp(-0.5*x^2) / sqrt(2*pi)
  const pdf = Math.exp(-0.5 * d1 * d1) / Math.sqrt(2 * Math.PI);

  const delta = isCall ? norm_cdf(d1) : (norm_cdf(d1) - 1);
  const gamma = pdf / (S * sigma * sqrtT);
  const vega = S * pdf * sqrtT;
  const theta = - (S * pdf * sigma) / (2 * sqrtT) - r * K * Math.exp(-r * T) * (isCall ? norm_cdf(d2) : -norm_cdf(-d2));
  const rho = isCall ? K * T * Math.exp(-r * T) * norm_cdf(d2) : -K * T * Math.exp(-r * T) * norm_cdf(-d2);

  return {
    delta: parseFloat(delta.toFixed(6)),
    gamma: parseFloat(gamma.toFixed(8)),
    theta: parseFloat((theta / 365).toFixed(6)), // per-day theta approximation
    vega: parseFloat((vega / 100).toFixed(6)),   // vega per 1% vol
    rho: parseFloat((rho / 100).toFixed(6))
  };
}

function parseExpiryToYears(expiry) {
  // expiry can be {date: 'YYYY-MM-DD', daysLeft: N} or string 'YYYY-MM-DD'
  try {
    if (!expiry) return 1/365; // tiny T to avoid zero-division
    if (typeof expiry === 'object' && expiry.daysLeft != null) {
      const days = Number(expiry.daysLeft);
      return Math.max(days / 365, 1/365);
    }
    const expDate = new Date(typeof expiry === 'string' ? expiry : (expiry.date || expiry));
    const now = new Date();
    const diff = Math.max(0, (expDate - now) / (1000 * 60 * 60 * 24)); // days
    return Math.max(diff / 365, 1/365);
  } catch (e) {
    return 1/365;
  }
}

/**
 * augmentChainWithGreeks
 * Mutates chain entries to add theoretical and greeks for call/put.
 *
 * chain: [{ strike, call: { ltp, iv, oi, volume }, put: {...} }, ...]
 * spot: number
 * expiry: {date:'YYYY-MM-DD', daysLeft:N} or string
 *
 */
async function augmentChainWithGreeks(chain, spot, expiry) {
  const T = parseExpiryToYears(expiry);
  const r = 0.07; // risk-free rate assumption (configurable later)

  if (!Array.isArray(chain)) return;

  for (const row of chain) {
    const K = Number(row.strike);
    // default iv fallback
    const callIV = row.call && row.call.iv ? Number(row.call.iv) : 0.25;
    const putIV = row.put && row.put.iv ? Number(row.put.iv) : 0.25;

    // Ensure IV reasonable
    const sigmaCall = Math.max(0.01, Math.min(2, callIV));
    const sigmaPut = Math.max(0.01, Math.min(2, putIV));

    // Theoretical price
    const theoCall = bs_price(spot, K, T, r, sigmaCall, true);
    const theoPut = bs_price(spot, K, T, r, sigmaPut, false);

    // Greeks
    const gCall = bs_greeks(spot, K, T, r, sigmaCall, true);
    const gPut = bs_greeks(spot, K, T, r, sigmaPut, false);

    // Attach back (safe assignments)
    row.call = Object.assign({}, row.call, {
      theoretical: parseFloat(theoCall.toFixed(4)),
      iv: parseFloat(sigmaCall.toFixed(4)),
      delta: gCall.delta,
      gamma: gCall.gamma,
      theta: gCall.theta,
      vega: gCall.vega,
      rho: gCall.rho
    });

    row.put = Object.assign({}, row.put, {
      theoretical: parseFloat(theoPut.toFixed(4)),
      iv: parseFloat(sigmaPut.toFixed(4)),
      delta: gPut.delta,
      gamma: gPut.gamma,
      theta: gPut.theta,
      vega: gPut.vega,
      rho: gPut.rho
    });
  }
}

module.exports = { augmentChainWithGreeks };
