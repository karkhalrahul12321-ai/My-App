// =============================
//   IMPORTS
// =============================
const express = require("express");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const path = require("path");

// =============================
//   APP INIT
// =============================
const app = express();
app.use(bodyParser.json());

// =============================
//   ENV CONFIG (Angel SmartAPI)
// =============================
// NOTE: अभी calculation सिर्फ तुम्हारे inputs पर होगी.
// Login / TOTP वाला हिस्सा future live-data के लिए तैयार रखा है.
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelone.in";
const API_KEY = process.env.SMART_API_KEY || "";
const API_SECRET = process.env.SMART_API_SECRET || "";
const TOTP_SECRET = process.env.SMART_TOTP || "";
const USER_ID = process.env.SMART_USER_ID || "";

// =============================
//   SESSION (ACCESS TOKEN STORAGE)
// =============================
let session = {
  access_token: null,
  refresh_token: null,
  expires_at: 0,
};

// =============================
//   BASE32 → BYTES DECODER (TOTP)
// =============================
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0,
    output = [];

  input = input.replace(/=+$/, "").toUpperCase();

  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx === -1) continue;

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

// =============================
//   GENERATE TOTP
// =============================
function generateTOTP(secret) {
  const decoded = base32Decode(secret);
  const time = Math.floor(Date.now() / 30000);
  const buffer = Buffer.alloc(8);

  buffer.writeUInt32BE(0, 0);
  buffer.writeUInt32BE(time, 4);

  const hmac = crypto.createHmac("sha1", decoded).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;

  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, "0");
}

// =============================
//   LOGIN FUNCTION (READY FOR FUTURE LIVE DATA)
// =============================
async function doLogin() {
  try {
    if (!API_KEY || !API_SECRET || !TOTP_SECRET || !USER_ID) {
      console.log("Angel env missing – skipping login");
      return false;
    }

    const totp = generateTOTP(TOTP_SECRET);

    const response = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-PrivateKey": API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          userId: USER_ID,
          password: API_SECRET, // अभी API_SECRET को password की तरह यूज़ कर रहे हैं
          totp: totp,
        }),
      }
    );

    const data = await response.json();

    if (data.status === false) {
      console.log("Login failed:", data);
      return false;
    }

    session.access_token = data.data.jwtToken;
    session.expires_at = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    console.log("Login successful!");
    return true;
  } catch (err) {
    console.log("Login Error:", err);
    return false;
  }
}

// सिर्फ future use के लिए – calculation login fail होने पर भी चलती रहेगी
async function ensureLogin() {
  if (!session.access_token || session.expires_at < Date.now()) {
    console.log("Access Token missing → Trying login (non-blocking)...");
    await doLogin();
  }
  return session.access_token;
}

// =============================
//   TRADING LOGIC HELPERS
// =============================

// Trend निकालने का simple rule-set
function analyseTrend({ ema20, ema50, rsi, vwap, spot }) {
  const emaDiff = ema20 - ema50;
  const vwapDiff = spot - vwap;

  if (emaDiff > 10 && vwapDiff > 0 && rsi >= 55) return "UP";
  if (emaDiff < -10 && vwapDiff < 0 && rsi <= 45) return "DOWN";
  return "SIDEWAYS";
}

function buildTrendComment(trend, { ema20, ema50, rsi, vwap, spot }) {
  const parts = [];
  parts.push(`EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`);

  if (trend === "UP") {
    parts.push("Price > VWAP, EMA20 > EMA50, RSI high → bullish bias.");
  } else if (trend === "DOWN") {
    parts.push("Price < VWAP, EMA20 < EMA50, RSI low → bearish bias.");
  } else {
    parts.push("Mixed signals → sideways / choppy zone.");
  }
  return parts.join(" ");
}

// Market config (distance rules तुम्हारे हिसाब से)
const MARKET_CONFIG = {
  Nifty: {
    step: 50,
    baseDistances: [250, 200, 150],
  },
  Sensex: {
    step: 100,
    baseDistances: [500, 400, 300],
  },
  "Natural Gas": {
    step: 10,
    baseDistances: [80, 60, 50],
  },
};

function scaleDistances(expiryDays, baseDistances) {
  // 30 दिन पर factor = 1, 5 दिन पर लगभग 0.3
  const rawFactor = expiryDays / 30;
  const factor = Math.min(1, Math.max(0.3, rawFactor || 0.3));
  return baseDistances.map((d) => Math.round(d * factor));
}

function roundUpToStep(value, step) {
  return Math.ceil(value / step) * step;
}
function roundDownToStep(value, step) {
  return Math.floor(value / step) * step;
}

// Strike selection
function buildStrikes({ spot, market, expiryDays, trend }) {
  const cfg = MARKET_CONFIG[market] || MARKET_CONFIG["Nifty"];
  const step = cfg.step;
  const distances = scaleDistances(expiryDays, cfg.baseDistances);

  if (trend === "UP") {
    // सिर्फ CE – ऊपर की तरफ
    return distances.map((d) => ({
      type: "CE",
      distance: d,
      strike: roundUpToStep(spot + d, step),
    }));
  }

  if (trend === "DOWN") {
    // सिर्फ PE – नीचे की तरफ
    return distances.map((d) => ({
      type: "PE",
      distance: d,
      strike: roundDownToStep(spot - d, step),
    }));
  }

  // SIDEWAYS → दोनों side + एक ATM के पास
  return [
    {
      type: "CE",
      distance: distances[1],
      strike: roundUpToStep(spot + distances[1], step),
    },
    {
      type: "PE",
      distance: distances[1],
      strike: roundDownToStep(spot - distances[1], step),
    },
    {
      type: "STRADDLE",
      distance: 0,
      strike: roundUpToStep(spot, step),
    },
  ];
}

// Simple premium / SL / Target formula (no live option-chain yet)
function buildLevels(strikeObj, spot) {
  const { strike, distance, type } = strikeObj;
  const diff = Math.abs(strike - spot);

  // distance के हिसाब से approx premium
  const basePremium = Math.max(10, Math.round(diff / 10));
  const entry = basePremium;
  const target = Math.round(entry * 1.5); // 1.5x
  const stopLoss = Math.round(entry * 0.6); // ~40% loss

  return {
    type,
    strike,
    distance,
    entry,
    stopLoss,
    target,
  };
}

// =============================
//   API ROUTE → CALCULATE
// =============================
app.post("/api/calc", async (req, res) => {
  try {
    // login कोशिश – fail होने पर भी calculation चलेगी
    await ensureLogin();

    const ema20 = Number(req.body.ema20) || 0;
    const ema50 = Number(req.body.ema50) || 0;
    const rsi = Number(req.body.rsi) || 0;
    const vwap = Number(req.body.vwap) || 0;
    const spot = Number(req.body.spot) || 0;
    const market = req.body.market || "Nifty";
    const expiry_days = Number(req.body.expiry_days) || 7;
    const use_live = !!req.body.use_live;

    const numericInputs = { ema20, ema50, rsi, vwap, spot };

    const trendCode = analyseTrend(numericInputs);
    const trendLabel =
      trendCode === "UP"
        ? "UPTREND (Bullish)"
        : trendCode === "DOWN"
        ? "DOWNTREND (Bearish)"
        : "SIDEWAYS / RANGE";

    const direction =
      trendCode === "UP" ? "CE" : trendCode === "DOWN" ? "PE" : "NONE";

    const strikesRaw = buildStrikes({
      spot,
      market,
      expiryDays: expiry_days,
      trend: trendCode,
    });

    const strikes = strikesRaw.map((s) => buildLevels(s, spot));

    const comment = buildTrendComment(trendCode, numericInputs);

    res.json({
      success: true,
      message: "Calculation complete",
      input: {
        ema20,
        ema50,
        rsi,
        vwap,
        spot,
        market,
        expiry_days,
        use_live,
      },
      trend: {
        code: trendCode, // UP / DOWN / SIDEWAYS
        label: trendLabel,
        direction, // CE / PE / NONE
        comment,
      },
      strikes, // 3 recommended strikes with entry / SL / target
      meta: {
        live_data_used: false, // अभी कोई OI / PCR / Greeks call नहीं है
        note:
          "Option price levels फिलहाल simple formula से हैं. बाद में Angel live option-chain से replace कर सकते हैं.",
      },
    });
  } catch (err) {
    console.error("Error in /api/calc:", err);
    res.status(500).json({
      success: false,
      message: "Server error in calculation",
      error: err.message,
    });
  }
});

// =============================
//   FRONTEND (STATIC FILES)
// =============================
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =============================
//   START SERVER
// =============================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
