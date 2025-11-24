// =============================
//   ADVANCED TREND ENGINE HELPERS
// =============================

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

function safeNum(v, def = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}

function computeTrend(input) {
  const ema20 = safeNum(input.ema20);
  const ema50 = safeNum(input.ema50);
  const rsi = safeNum(input.rsi);
  const vwap = safeNum(input.vwap);
  const spot = safeNum(input.spot);

  // अगर basics missing हैं तो सीधे sideways
  if (!ema20 || !ema50 || !spot) {
    return {
      code: "SIDEWAYS",
      label: "SIDEWAYS / RANGE",
      direction: "NONE",
      score: 50,
      strength: "Neutral",
      comment: "Insufficient data → default sideways.",
      details: []
    };
  }

  const details = [];

  // 1) EMA gap strength
  const emaMid = (ema20 + ema50) / 2;
  const emaDiff = ema20 - ema50;               // +ve = bullish
  const emaDiffPct = (emaDiff / emaMid) * 100; // %
  let emaScore = emaDiffPct * 2;               // scale
  emaScore = clamp(emaScore, -40, 40);
  details.push(`EMA20=${ema20}, EMA50=${ema50}, gap=${emaDiffPct.toFixed(2)}%`);

  // 2) RSI strength (50 neutral)
  let rsiScore = (rsi - 50) * 1.2;             // +-60 approx
  rsiScore = clamp(rsiScore, -40, 40);
  details.push(`RSI=${rsi.toFixed(2)} → score=${rsiScore.toFixed(1)}`);

  // 3) VWAP distance
  const vwapDiff = spot - vwap;
  const vwapDiffPct = (vwapDiff / spot) * 100;
  let vwapScore = vwapDiffPct * 2;             // +-40
  vwapScore = clamp(vwapScore, -40, 40);
  details.push(`VWAP=${vwap}, Spot=${spot}, diff=${vwapDiffPct.toFixed(2)}%`);

  // 4) Position of spot vs EMA stack
  let posScore = 0;
  if (spot > ema20 && ema20 > ema50) {
    posScore = 15; // bullish stack
    details.push("Price above EMA20 > EMA50 → bullish stack.");
  } else if (spot < ema20 && ema20 < ema50) {
    posScore = -15; // bearish stack
    details.push("Price below EMA20 < EMA50 → bearish stack.");
  } else {
    details.push("Mixed EMA stack (no clean trend stack).");
  }

  // 5) Combine weighted score into 0–100
  let rawScore =
    50 +                // neutral base
    emaScore * 0.4 +
    rsiScore * 0.3 +
    vwapScore * 0.2 +
    posScore * 0.1;

  rawScore = clamp(rawScore, 0, 100);

  let code = "SIDEWAYS";
  let label = "SIDEWAYS / RANGE";
  let direction = "NONE";
  let strength = "Neutral";

  if (rawScore >= 80) {
    code = "BULLISH_STRONG";
    label = "STRONG BULLISH";
    direction = "BULLISH";
    strength = "Strong";
  } else if (rawScore >= 60) {
    code = "BULLISH";
    label = "BULLISH";
    direction = "BULLISH";
    strength = "Moderate";
  } else if (rawScore > 40) {
    code = "SIDEWAYS";
    label = "SIDEWAYS / RANGE";
    direction = "NONE";
    strength = "Neutral";
  } else if (rawScore > 20) {
    code = "BEARISH";
    label = "BEARISH";
    direction = "BEARISH";
    strength = "Moderate";
  } else {
    code = "BEARISH_STRONG";
    label = "STRONG BEARISH";
    direction = "BEARISH";
    strength = "Strong";
  }

  const comment = `Trend score = ${rawScore.toFixed(
    1
  )}/100 → ${label}.`;

  return {
    code,
    label,
    direction,
    score: Math.round(rawScore),
    strength,
    comment,
    details
  };
}

function computeStrikes(input, trend) {
  const market = (input.market || "").toLowerCase();
  const spot = safeNum(input.spot);
  const expiryDays = Math.max(1, safeNum(input.expiry_days, 7));

  // distance tuning (simple version)
  let baseDistance = 60; // default for Nifty
  if (market === "sensex") baseDistance = 400;
  if (market === "natural gas" || market === "naturalgas") baseDistance = 60;

  // expiry जितनी दूर, उतनी ज्यादा distance; नज़दीक आए तो कम
  const expiryFactor = clamp(expiryDays / 7, 0.6, 1.4);
  const distance = Math.round(baseDistance * expiryFactor);

  // strike rounding step
  let step = 50;
  if (market === "sensex") step = 100;
  if (market === "natural gas" || market === "naturalgas") step = 10;

  const roundToStep = (value) =>
    Math.round(value / step) * step;

  const ceStrike = roundToStep(spot + distance);
  const peStrike = roundToStep(spot - distance);
  const atmStrike = roundToStep(spot);

  // option price approx (trend strength के हिसाब से)
  const strengthFactor = trend.score / 100; // 0–1
  const baseEntry = 8 + 6 * strengthFactor; // 8–14 approx
  const entry = Number(baseEntry.toFixed(1));
  const stopLoss = Number((entry * 0.6).toFixed(1));
  const target = Number((entry * (1.4 + 0.3 * strengthFactor)).toFixed(1));

  // order: अगर BEARISH → पहले PE, वरना पहले CE
  const firstIsPE = trend.direction === "BEARISH";

  const ceLeg = {
    type: "CE",
    strike: ceStrike,
    distance,
    entry,
    stopLoss,
    target
  };

  const peLeg = {
    type: "PE",
    strike: peStrike,
    distance,
    entry,
    stopLoss,
    target
  };

  const ordered = firstIsPE ? [peLeg, ceLeg] : [ceLeg, peLeg];

  ordered.push({
    type: "STRADDLE",
    strike: atmStrike,
    distance: 0,
    entry,
    stopLoss,
    target
  });

  return ordered;
}

// =============================
//   API ROUTE → CALCULATE
// =============================
app.post("/api/calc", async (req, res) => {
  try {
    await ensureLogin();

    const {
      ema20,
      ema50,
      rsi,
      vwap,
      spot,
      market,
      expiry_days,
      use_live
    } = req.body || {};

    const input = {
      ema20: safeNum(ema20),
      ema50: safeNum(ema50),
      rsi: safeNum(rsi),
      vwap: safeNum(vwap),
      spot: safeNum(spot),
      market: (market || "").toLowerCase(),
      expiry_days: safeNum(expiry_days, 7),
      use_live: !!use_live
    };

    const trend = computeTrend(input);
    const strikes = computeStrikes(input, trend);

    res.json({
      success: true,
      message: "Calculation complete",
      input,
      trend,
      strikes,
      meta: {
        live_data_used: false,
        note:
          "Trend score (0–100) advanced logic से निकाला है। Option prices अभी formula-based demo हैं, बाद में live option-chain से replace कर सकते हैं."
      }
    });
  } catch (err) {
    console.error("Calc error:", err);
    res.status(500).json({
      success: false,
      error: err.message || "Internal error"
    });
  }
});
