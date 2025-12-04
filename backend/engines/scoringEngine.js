/**
 * scoringEngine.js
 *
 * scoreCandidates(chain, trend, srData, fut, vol)
 *
 * Inputs:
 *  - chain: [{ strike, call: { ltp, iv, oi, volume, delta }, put: {...} }, ...]
 *  - trend: { isUptrend/isDowntrend/isNeutral, score, reason[] }
 *  - srData: { summary: { nearest_support, nearest_resistance }, levels: { support:[], resistance:[] } }
 *  - fut: { confirmation: 'bullish'|'bearish'|'neutral', confidence: 0..1 }
 *  - vol: { pressure: 'buying'|'selling'|'neutral', confidence: 0..1 }
 *
 * Output:
 *  - returns array of candidates with added fields:
 *      { strike, side, score, score_breakdown: {...}, ...original data... }
 *
 * Notes:
 *  - Scores are normalized into a 0..100-ish range for easy interpretation.
 *  - This is deterministic and pure JS (no external libs).
 */

function _log10(x) {
  return Math.log(Math.max(1, x)) / Math.log(10);
}

function _normalize(x, min, max) {
  if (!isFinite(x)) return 0;
  if (max === min) return 0;
  return (x - min) / (max - min);
}

function _clamp(x, a, b) {
  return Math.max(a, Math.min(b, x));
}

function scoreCandidates(chain, trend, srData, fut, vol) {
  if (!Array.isArray(chain)) return [];

  // We compute raw scores from components and then normalize.
  const scored = [];

  // Pre-calc ranges for normalization (simple heuristics)
  let maxOi = 1;
  let maxVol = 1;
  let maxIv = 0.0001;
  for (const row of chain) {
    const c = row.call || {};
    const p = row.put || {};
    maxOi = Math.max(maxOi, (c.oi || 0), (p.oi || 0));
    maxVol = Math.max(maxVol, (c.volume || 0), (p.volume || 0));
    maxIv = Math.max(maxIv, (c.iv || 0), (p.iv || 0));
  }

  // Component weights (configurable)
  const weights = {
    trend: 0.30,
    oi: 0.15,
    volume: 0.12,
    iv_sanity: 0.08,
    delta: 0.10,
    sr: 0.15,
    futures: 0.06,
    volumePressure: 0.04
  };

  for (const row of chain) {
    // decide preferred side based on trend
    let preferCall = (trend && (trend.isUptrend || trend.score > 0.2));
    let preferPut = (trend && (trend.isDowntrend || trend.score < -0.2));
    let side = 'call';
    if (preferCall && !preferPut) side = 'call';
    else if (preferPut && !preferCall) side = 'put';
    else {
      // neutral: pick side with higher premium (liquidity proxy)
      side = (row.call && row.put) ? (row.call.ltp > row.put.ltp ? 'call' : 'put') : (row.call ? 'call' : 'put');
    }

    const m = row[side] || row.call || row.put;

    // trend component: if trend aligns with side -> positive
    let trend_comp = 0;
    if (trend) {
      if (trend.isUptrend && side === 'call') trend_comp = 1;
      else if (trend.isDowntrend && side === 'put') trend_comp = 1;
      else if (trend.isNeutral) trend_comp = 0.4;
      else trend_comp = 0; // opposite side
    }

    // OI strength (log scale)
    const oi_val = Math.max(0, m.oi || 0);
    const oi_comp = _clamp(_log10(oi_val) / _log10(maxOi || 1), 0, 1);

    // Volume strength
    const vol_val = Math.max(0, m.volume || 0);
    const vol_comp = _clamp(_log10(vol_val) / _log10(maxVol || 1), 0, 1);

    // IV sanity: penalize extremely high IV (very risky) and extremely low IV (cheap but low movement)
    const iv = (m.iv != null) ? Number(m.iv) : 0.25;
    // ideal IV range [0.08, 0.45] (example)
    const iv_ideal_min = 0.08, iv_ideal_max = 0.45;
    let iv_comp = 1;
    if (iv < iv_ideal_min) iv_comp = _normalize(iv, 0.01, iv_ideal_min);
    else if (iv > iv_ideal_max) iv_comp = 1 - _normalize(iv, iv_ideal_max, Math.max(iv, iv_ideal_max * 3));
    iv_comp = _clamp(iv_comp, 0, 1);

    // Delta suitability: prefer delta around 0.3-0.6 for buying options (heuristic)
    const delta = (m.delta != null) ? Math.abs(Number(m.delta)) : 0.5;
    let delta_comp = 0;
    if (delta >= 0.3 && delta <= 0.6) delta_comp = 1;
    else if (delta >= 0.2 && delta < 0.3) delta_comp = 0.7;
    else if (delta > 0.6 && delta <= 0.8) delta_comp = 0.6;
    else delta_comp = 0.3;

    // Support/Resistance alignment
    let sr_comp = 0;
    if (srData && srData.summary) {
      const nearestRes = srData.summary.nearest_resistance || null;
      const nearestSup = srData.summary.nearest_support || null;
      const strikePrice = Number(row.strike);
      // If trend bullish and strike is below or near resistance -> good
      if (side === 'call' && nearestRes != null) {
        sr_comp = strikePrice <= nearestRes ? 1 : Math.max(0, 1 - ((strikePrice - nearestRes) / Math.max(1, nearestRes)) );
      }
      // If trend bearish and strike is above or near support -> good for puts
      if (side === 'put' && nearestSup != null) {
        sr_comp = strikePrice >= nearestSup ? 1 : Math.max(0, 1 - ((nearestSup - strikePrice) / Math.max(1, nearestSup)) );
      }
      // If neutral, small SR boost if close to either
      if (trend && trend.isNeutral) {
        let d1 = (nearestRes != null) ? Math.abs(strikePrice - nearestRes) / Math.max(1, nearestRes) : 1;
        let d2 = (nearestSup != null) ? Math.abs(strikePrice - nearestSup) / Math.max(1, nearestSup) : 1;
        const near = Math.min(d1, d2);
        sr_comp = _clamp(1 - near, 0, 1) * 0.8;
      }
    }

    // Futures confirmation & volume pressure
    let fut_comp = 0;
    if (fut) {
      if ((fut.confirmation === 'bullish' && side === 'call') || (fut.confirmation === 'bearish' && side === 'put')) {
        fut_comp = fut.confidence || 0.5;
      } else if (fut.confirmation === 'neutral') {
        fut_comp = 0.3 * (fut.confidence || 0.3);
      } else {
        fut_comp = 0; // contradicting
      }
    }
    let volPress_comp = 0;
    if (vol) {
      if ((vol.pressure === 'buying' && side === 'call') || (vol.pressure === 'selling' && side === 'put')) {
        volPress_comp = vol.confidence || 0.4;
      } else if (vol.pressure === 'neutral') {
        volPress_comp = 0.2;
      } else {
        volPress_comp = 0;
      }
    }

    // Compose weighted score
    const score_val =
      trend_comp * weights.trend +
      oi_comp * weights.oi +
      vol_comp * weights.volume +
      iv_comp * weights.iv_sanity +
      delta_comp * weights.delta +
      sr_comp * weights.sr +
      fut_comp * weights.futures +
      volPress_comp * weights.volumePressure;

    // scale to 0..100
    const normalized = Math.round(_clamp(score_val, 0, 1) * 10000) / 100;

    // build breakdown object
    const breakdown = {
      trend: parseFloat((trend_comp * weights.trend).toFixed(4)),
      oi: parseFloat((oi_comp * weights.oi).toFixed(4)),
      volume: parseFloat((vol_comp * weights.volume).toFixed(4)),
      iv_sanity: parseFloat((iv_comp * weights.iv_sanity).toFixed(4)),
      delta: parseFloat((delta_comp * weights.delta).toFixed(4)),
      sr: parseFloat((sr_comp * weights.sr).toFixed(4)),
      futures: parseFloat((fut_comp * weights.futures).toFixed(4)),
      volumePressure: parseFloat((volPress_comp * weights.volumePressure).toFixed(4))
    };

    scored.push(Object.assign({}, row, {
      side,
      score: normalized,
      score_breakdown: breakdown
    }));
  }

  // sort descending by score
  scored.sort((a, b) => b.score - a.score);
  return scored;
}

module.exports = { scoreCandidates };
