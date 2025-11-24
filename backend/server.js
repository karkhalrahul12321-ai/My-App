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
    closeGap: 150,
    mediumGap: 200,
    farGap: 250,
    angelSymbol: "NIFTY"
  },
  sensex: {
    name: "Sensex",
    strikeStep: 100,
    closeGap: 300,
    mediumGap: 400,
    farGap: 500,
    angelSymbol: "SENSEX"
  },
  "natural gas": {
    name: "Natural Gas",
    strikeStep: 5,
    closeGap: 20,
    mediumGap: 60,
    farGap: 80,
    angelSymbol: "NATGAS" // बाद में exact SmartAPI symbol पर adjust कर लेंगे
  }
};

// =====================================
//  SMALL HELPERS
// =====================================
function num(v, def = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}

// spot range से market auto-detect
function autoDetectMarket(spot, explicitMarketRaw) {
  const m = (explicitMarketRaw || "").toString().trim().toLowerCase();

  // अगर user ने सही नाम दिया है और config में है, तो वही मान लो
  if (m && MARKET_CONFIG[m]) return m;

  // spot range से अंदाज़ा
  const s = num(spot, 0);

  // बहुत छोटा spot → Natural Gas (commodity)
  if (s > 50 && s < 2000) return "natural gas";

  // बीच वाली range → Nifty (20k–30k)
  if (s >= 10000 && s < 40000) return "nifty";

  // बड़ा spot → Sensex (50k–80k+)
  if (s >= 40000) return "sensex";

  // default fallback
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
    market: detectedMarketKey,          // अब हमेशा normalized (nifty/sensex/natural gas)
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live
  };
}

// =====================================
//  TREND ENGINE (RSI + EMA + VWAP logic)
// =====================================
function trendEngine(input) {
  const { ema20, ema50, rsi, vwap, spot } = input;

  let code = "SIDEWAYS";
  let label = "SIDEWAYS / RANGE";
  let direction = "NONE";
  let commentParts = [];

  // --- RSI based bias ---
  if (rsi >= 60) {
    commentParts.push(`RSI ${rsi.toFixed(2)} → bullish bias`);
  } else if (rsi <= 40) {
    commentParts.push(`RSI ${rsi.toFixed(2)} → bearish bias`);
  } else {
    commentParts.push(`RSI ${rsi.toFixed(2)} → neutral`);
  }

  // --- EMA structure ---
  if (spot > ema20 && ema20 > ema50) {
    commentParts.push("Price > EMA20 > EMA50 → uptrend structure");
  } else if (spot < ema20 && ema20 < ema50) {
    commentParts.push("Price < EMA20 < EMA50 → downtrend structure");
  } else {
    commentParts.push("EMA20 / EMA50 mixed → no clean trend");
  }

  // --- VWAP relation ---
  if (spot > vwap) {
    commentParts.push("Price above VWAP → intraday strength");
  } else if (spot < vwap) {
    commentParts.push("Price below VWAP → intraday weakness");
  } else {
    commentParts.push("Price near VWAP → mean-reversion zone");
  }

  // --- Final decision logic ---
  const emaBull = spot > ema20 && ema20 > ema50;
  const emaBear = spot < ema20 && ema20 < ema50;
  const strongRSIUp = rsi >= 60;
  const strongRSIDown = rsi <= 40;
  const aboveVWAP = spot > vwap;
  const belowVWAP = spot < vwap;

  if (emaBull && strongRSIUp && aboveVWAP) {
    code = "UP";
    label = "UP TREND (CE bias)";
    direction = "CE";
  } else if (emaBear && strongRSIDown && belowVWAP) {
    code = "DOWN";
    label = "DOWN TREND (PE bias)";
    direction = "PE";
  } else if ((emaBull && (strongRSIUp || aboveVWAP)) || (strongRSIUp && aboveVWAP)) {
    code = "MILD_UP";
    label = "MILD UP / BUY ON DIPS";
    direction = "CE";
  } else if ((emaBear && (strongRSIDown || belowVWAP)) || (strongRSIDown && belowVWAP)) {
    code = "MILD_DOWN";
    label = "MILD DOWN / SELL ON RISES";
    direction = "PE";
  }

  const comment = [
    `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi.toFixed(2)}, VWAP=${vwap}, Spot=${spot}`,
    commentParts.join(" | ")
  ].join(" → ");

  return { code, label, direction, comment };
}

// =====================================
//  STRIKE ENGINE (multi-market)
// =====================================
function roundToStep(value, step) {
  if (!step) return value;
  return Math.round(value / step) * step;
}

function strikeEngine(input, trend) {
  const cfg = MARKET_CONFIG[input.market] || MARKET_CONFIG["nifty"];
  const { spot, expiry_days } = input;

  let gapNear = cfg.closeGap;
  let gapMid = cfg.mediumGap;
  let gapFar = cfg.farGap;

  if (expiry_days <= 2) {
    gapNear *= 0.5;
    gapMid *= 0.6;
    gapFar *= 0.7;
  } else if (expiry_days >= 10) {
    gapNear *= 1.2;
    gapMid *= 1.3;
    gapFar *= 1.4;
  }

  const atm = roundToStep(spot, cfg.strikeStep);

  let ceStrike, peStrike;

  if (trend.direction === "CE") {
    ceStrike = roundToStep(spot + gapNear, cfg.strikeStep);
    peStrike = roundToStep(spot - gapFar, cfg.strikeStep);
  } else if (trend.direction === "PE") {
    ceStrike = roundToStep(spot + gapFar, cfg.strikeStep);
    peStrike = roundToStep(spot - gapNear, cfg.strikeStep);
  } else {
    ceStrike = roundToStep(spot + gapMid, cfg.strikeStep);
    peStrike = roundToStep(spot - gapMid, cfg.strikeStep);
  }

  const straddleStrike = atm;

  function buildOption(strike, type, distance) {
    const steps = Math.max(1, Math.round(distance / cfg.strikeStep));
    const basePremium = Math.max(5, steps * 5);
    const entry = basePremium;
    const stopLoss = Math.round(entry * 0.6);
    const target = Math.round(entry * 1.5);

    return {
      type,
      strike,
      distance: Math.round(distance),
      entry,
      stopLoss,
      target
    };
  }

  const ce = buildOption(ceStrike, "CE", Math.abs(ceStrike - spot));
  const pe = buildOption(peStrike, "PE", Math.abs(peStrike - spot));
  const straddle = buildOption(
    straddleStrike,
    "STRADDLE",
    Math.abs(straddleStrike - spot)
  );

  return [ce, pe, straddle];
}

// =====================================
//  API ROUTE → /api/calc
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);

    const trend = trendEngine(input);
    const strikes = strikeEngine(input, trend);

    res.json({
      success: true,
      message: "Calculation complete",
      input,
      trend,
      strikes,
      meta: {
        live_data_used: input.use_live,
        note:
          "Market अब auto-detect हो रही है (Nifty/Sensex/Natural Gas). Option prices अभी simple हैं, बाद में Angel live chain जोड़ेंगे।"
      }
    });
  } catch (err) {
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
