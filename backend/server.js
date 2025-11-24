/* =============================
      IMPORTS
============================= */
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");

/* =============================
      APP INIT
============================= */
const app = express();
app.use(bodyParser.json());

/* =============================
      FRONTEND SERVE
============================= */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ============================================================
   TREND ENGINE (V2)
============================================================ */
function trendEngine({ ema20, ema50, rsi, vwap, spot }) {
  let code = "SIDEWAYS";
  let direction = "NONE";
  let label = "SIDEWAYS / RANGE";
  let comment = "";

  if (spot > ema20 && ema20 > ema50 && rsi > 60) {
    code = "UP";
    label = "UPTREND";
    direction = "CE";
    comment = "Strong CE bias (spot > EMA20 > EMA50 + RSI > 60)";
  }
  else if (spot < ema20 && ema20 < ema50 && rsi < 40) {
    code = "DOWN";
    label = "DOWNTREND";
    direction = "PE";
    comment = "Strong PE bias (spot < EMA20 < EMA50 + RSI < 40)";
  }
  else {
    code = "SIDEWAYS";
    label = "SIDEWAYS / RANGE";
    direction = "NONE";
    comment = "Mixed signals → sideways / choppy zone.";
  }

  return { code, label, direction, comment };
}

/* ============================================================
   STRIKE ENGINE
============================================================ */
function strikeEngine(spot, trendDirection, expiry_days) {
  const step = 60; // default NIFTY
  let ce_strike = Math.round((spot + step) / 50) * 50;
  let pe_strike = Math.round((spot - step) / 50) * 50;
  let atm_straddle = Math.round(spot / 50) * 50;

  const price = 10; // temp price until Live Chain

  return [
    {
      type: "CE",
      strike: ce_strike,
      distance: step,
      entry: price,
      stopLoss: 6,
      target: 15,
    },
    {
      type: "PE",
      strike: pe_strike,
      distance: step,
      entry: price,
      stopLoss: 6,
      target: 15,
    },
    {
      type: "STRADDLE",
      strike: atm_straddle,
      distance: 0,
      entry: price,
      stopLoss: 6,
      target: 15,
    }
  ];
}

/* ============================================================
   API ROUTE: /api/calc
============================================================ */
app.post("/api/calc", async (req, res) => {
  try {
    const input = req.body;

    const trend = trendEngine(input);
    const strikes = strikeEngine(input.spot, trend.direction, input.expiry_days);

    res.json({
      success: true,
      message: "Calculation complete",
      input,
      trend,
      strikes,
      meta: {
        live_data_used: input.use_live,
        note: "Option prices अभी simple हैं, बाद में Angel live chain जोड़ेंगे।"
      }
    });

  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

/* =============================
      START SERVER
============================= */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`SERVER READY on port ${PORT}`));
