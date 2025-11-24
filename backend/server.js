// =====================================
//  IMPORTS
// =====================================
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");

// =====================================
//  APP INIT
// =====================================
const app = express();
app.use(bodyParser.json());

// =====================================
//  SERVE FRONTEND (Render friendly)
// =====================================
const frontendPath = path.join(__dirname, "..", "frontend");

// static files (HTML, CSS, JS)
app.use(express.static(frontendPath));

// सभी routes पर index.html (SPA जैसा behaviour)
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
//  MARKET CONFIG (Nifty, Sensex, Natural Gas)
// =====================================
const MARKET_CONFIG = {
  nifty: {
    name: "Nifty",
    strikeStep: 50,
    baseDistances: {
      far: 250,
      mid: 200,
      near: 150
    },
    angelSymbol: "NIFTY"
  },
  sensex: {
    name: "Sensex",
    strikeStep: 100,
    baseDistances: {
      far: 500,
      mid: 400,
      near: 300
    },
    angelSymbol: "SENSEX"
  },
  "natural gas": {
    name: "Natural Gas",
    strikeStep: 5,
    baseDistances: {
      far: 80,
      mid: 60,
      near: 50
    },
    angelSymbol: "NATGAS" // बाद में exact SmartAPI symbol पर adjust करेंगे
  }
};

// =====================================
//  SMALL HELPERS
// =====================================
function num(v, def = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function roundToStep(value, step) {
  if (!step) return value;
  return Math.round(value / step) * step;
}

// spot range से market auto-detect
function autoDetectMarket(spot, explicitMarketRaw) {
  const m = (explicitMarketRaw || "").toString().trim().toLowerCase();

  // अगर user ने सही नाम दिया है और config में है, तो वही मान लो
  if (m && MARKET_CONFIG[m]) return m;

  const s = num(spot, 0);

  // बहुत छोटा spot → Natural Gas
  if (s > 20 && s < 2000) return "natural gas";

  // बीच range → Nifty (12k–30k approx)
  if (s >= 10000 && s < 40000) return "nifty";

  // बहुत बड़ा → Sensex (50k+)
  if (s >= 40000) return "sensex";

  // fallback
  return "nifty";
}

// =====================================
//  INPUT NORMALIZE
// =====================================
function normalizeInput(body) {
  const rawMarket = (body.market || "").toString().toLowerCase().trim();
  const spotVal = num(body.spot);

  const detectedMarketKey = autoDetectMarket(spotVal, rawMarket);

  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot: spotVal,
    market: detectedMarketKey,          // normalized (nifty / sensex / natural gas)
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live
  };
}

// =====================================
//  ADVANCED TREND ENGINE
//  (EMA gap + RSI + VWAP + price structure)
// =====================================
function computeTrend(input) {
  const ema20 = num(input.ema20);
  const ema50 = num(input.ema50);
  const rsi = num(input.rsi);
  const vwap = num(input.vwap);
  const spot = num(input.spot);

  const components = {};
  let score = 50; // base neutral
  let bias = "NONE";

  if (!ema20 || !ema50 || !spot || !vwap || !rsi) {
    components.warning = "कुछ key inputs missing हैं, trend score approx है.";
    return {
      main: "SIDEWAYS",
      strength: "NEUTRAL",
      score: 50,
      bias: "NONE",
      components,
      comment: "Data अधूरा है, इसलिए default sideways दिखाया जा रहा है."
    };
  }

  // ----- EMA gap -----
  const emaMid = (ema20 + ema50) / 2;
  const emaDiff = ema20 - ema50;               // +ve = bullish
  const emaDiffPct = (emaDiff / emaMid) * 100; // %
  let emaScore = emaDiffPct * 1.5;             // scale
  emaScore = clamp(emaScore, -25, 25);

  if (emaDiffPct > 0.3) {
    components.ema_gap = `Bullish (${emaDiffPct.toFixed(2)}%) – EMA20 ऊपर EMA50`;
  } else if (emaDiffPct < -0.3) {
    components.ema_gap = `Bearish (${emaDiffPct.toFixed(2)}%) – EMA20 नीचे EMA50`;
  } else {
    components.ema_gap = `Flat (${emaDiffPct.toFixed(2)}%) – EMA20 और EMA50 पास-पास`;
  }

  // ----- RSI contribution -----
  let rsiScore = (rsi - 50) * 1.2; // +-60 approx → clamp
  rsiScore = clamp(rsiScore, -25, 25);

  if (rsi >= 70) {
    components.rsi = `RSI ${rsi.toFixed(2)} (overbought zone) – बहुत तेज़ bullish, reversal risk भी`;
  } else if (rsi >= 60) {
    components.rsi = `RSI ${rsi.toFixed(2)} (bullish zone) – buyers active`;
  } else if (rsi <= 30) {
    components.rsi = `RSI ${rsi.toFixed(2)} (oversold zone) – बहुत तेज़ bearish, short-covering possible`;
  } else if (rsi <= 40) {
    components.rsi = `RSI ${rsi.toFixed(2)} (bearish zone) – sellers active`;
  } else {
    components.rsi = `RSI ${rsi.toFixed(2)} (neutral zone) – कोई strong RSI bias नहीं`;
  }

  // ----- VWAP contribution -----
  const vwapDiff = spot - vwap;
  const vwapDiffPct = (vwapDiff / vwap) * 100;
  let vwapScore = vwapDiffPct * 1.5; // +-30 approx
  vwapScore = clamp(vwapScore, -20, 20);

  if (vwapDiffPct > 0.1) {
    components.vwap = `Price above VWAP (${vwapDiffPct.toFixed(2)}%) – intraday strength`;
  } else if (vwapDiffPct < -0.1) {
    components.vwap = `Price below VWAP (${vwapDiffPct.toFixed(2)}%) – intraday weakness`;
  } else {
    components.vwap = `Price near VWAP (${vwapDiffPct.toFixed(2)}%) – mean-reversion zone`;
  }

  // ----- Price vs EMA structure -----
  let priceScore = 0;
  if (spot > ema20 && ema20 > ema50) {
    priceScore = 10;
    components.price_structure = "Spot > EMA20 > EMA50 – साफ़ bullish structure.";
  } else if (spot < ema20 && ema20 < ema50) {
    priceScore = -10;
    components.price_structure = "Spot < EMA20 < EMA50 – साफ़ bearish structure.";
  } else {
    components.price_structure = "EMA stack mixed है – trend उतना साफ़ नहीं.";
  }

  // ----- Expiry effect (जितनी expiry पास, उतना choppy) -----
  const d = num(input.expiry_days, 7);
  let expiryAdj = 0;
  if (d <= 2) {
    expiryAdj = -5; // expiry पास → noise ज़्यादा
    components.expiry_effect = "Expiry बहुत पास – volatility ज़्यादा, trend जल्दी बदल सकता है.";
  } else if (d >= 10) {
    expiryAdj = 3;
    components.expiry_effect = "Expiry दूर – trend ज़्यादा stable रहता है.";
  } else {
    components.expiry_effect = "Expiry मध्यम – normal volatility.";
  }

  // ----- Final score (0–100) -----
  score =
    50 +
    emaScore * 0.4 +
    rsiScore * 0.3 +
    vwapScore * 0.2 +
    priceScore * 0.2 +
    expiryAdj;

  score = clamp(score, 0, 100);

  let main = "SIDEWAYS";
  let strength = "NEUTRAL";
  if (score >= 80) {
    main = "UPTREND";
    strength = "STRONG";
    bias = "CE";
  } else if (score >= 60) {
    main = "UPTREND";
    strength = "MODERATE";
    bias = "CE";
  } else if (score <= 20) {
    main = "DOWNTREND";
    strength = "STRONG";
    bias = "PE";
  } else if (score <= 40) {
    main = "DOWNTREND";
    strength = "MODERATE";
    bias = "PE";
  } else {
    main = "SIDEWAYS";
    strength = "RANGE";
    bias = "NONE";
  }

  let comment = `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi.toFixed(
    2
  )}, VWAP=${vwap}, Spot=${spot}. `;
  if (main === "UPTREND") {
    comment += "Overall bias ऊपर की तरफ है, rule-based CE side पर काम किया जा सकता है (कोई guarantee नहीं).";
  } else if (main === "DOWNTREND") {
    comment += "Overall bias नीचे की तरफ है, rule-based PE side पर काम किया जा सकता है (कोई guarantee नहीं).";
  } else {
    comment += "Market sideways / choppy zone में है, दोनों side whipsaw risk ज़्यादा है.";
  }

  return {
    main,
    strength,
    score,
    bias,
    components,
    comment
  };
}

// =====================================
//  EXPIRY-BASED DISTANCE SCALING
//  (जैसे-जैसे expiry पास, gap कम)
// =====================================
function scaleDistancesByExpiry(expiryDays, baseDistances, strikeStep) {
  const d = Math.max(0, num(expiryDays, 7));

  // Factor 0.2 → 1.0 के बीच
  // expiry दूर → factor ~1 (पूरा gap)
  // expiry बहुत पास → factor ~0.2 (ATM के आस-पास)
  let factor = 0.2 + 0.05 * d; // d=0 → 0.2, d=10 → 0.7, d=16 → 1.0+
  if (factor > 1) factor = 1;

  const scaled = {};
  ["near", "mid", "far"].forEach((k) => {
    const raw = baseDistances[k] || 0;
    let v = raw * factor;
    // कम से कम 1 step तो रहना चाहिए
    if (v < strikeStep / 2) v = strikeStep / 2;
    scaled[k] = v;
  });

  return scaled;
}

// =====================================
//  STRIKE ENGINE (multi-market + expiry-based gap)
// =====================================
function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market] || MARKET_CONFIG["nifty"];
  const { spot, expiry_days } = input;

  const scaledDistances = scaleDistancesByExpiry(
    expiry_days,
    cfg.baseDistances,
    cfg.strikeStep
  );

  const atm = roundToStep(spot, cfg.strikeStep);

  let ceDistance, peDistance;

  if (trend.main === "UPTREND") {
    // uptrend → CE थोड़ा पास, PE दूर
    ceDistance = scaledDistances.near;
    peDistance = scaledDistances.far;
  } else if (trend.main === "DOWNTREND") {
    // downtrend → PE थोड़ा पास, CE दूर
    ceDistance = scaledDistances.far;
    peDistance = scaledDistances.near;
  } else {
    // sideways → दोनों mid
    ceDistance = scaledDistances.mid;
    peDistance = scaledDistances.mid;
  }

  const ceStrike = roundToStep(atm + ceDistance, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDistance, cfg.strikeStep);
  const straddleStrike = atm;

  function buildOption(strike, type, distanceFromSpot) {
    const steps = Math.max(1, Math.round(Math.abs(distanceFromSpot) / cfg.strikeStep));
    const basePremium = Math.max(5, steps * 5); // simple demo model
    const entry = basePremium;
    const stopLoss = Math.round(entry * 0.6);
    const target = Math.round(entry * 1.5);

    return {
      type,
      strike,
      distance: Math.round(Math.abs(distanceFromSpot)),
      entry,
      stopLoss,
      target
    };
  }

  const ce = buildOption(ceStrike, "CE", ceStrike - spot);
  const pe = buildOption(peStrike, "PE", peStrike - spot);
  const straddle = buildOption(straddleStrike, "STRADDLE", straddleStrike - spot);

  return [ce, pe, straddle];
}

// =====================================
//  API ROUTE → /api/calc
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);

    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    res.json({
      success: true,
      message: "Calculation complete",
      input,
      trend,
      strikes,
      meta: {
        live_data_used: input.use_live,
        note:
          "Trend score advanced logic से निकला है. Strike distances expiry के पास आते-आते अपने आप ATM के पास आते हैं. Option prices अभी simple formula हैं, बाद में Angel live option-chain से replace कर सकते हैं."
      }
    });
  } catch (err) {
    console.error("Error in /api/calc:", err);
    res.json({
      success: false,
      error: err.message || String(err)
    });
  }
});

// =====================================
//  START SERVER
// =====================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER running on port " + PORT);
});
