// =====================================
//  IMPORTS
// =====================================
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const fetch = require("node-fetch");
const crypto = require("crypto");

// =====================================
//  APP INIT
// =====================================
const app = express();
app.use(bodyParser.json());

// =====================================
//  SERVE FRONTEND FILES
// =====================================
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

// Home route → send index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// Fallback routes
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
//  SMARTAPI ENV CONFIG
// =====================================
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// =====================================
//  SMARTAPI SESSION (TOKENS STORAGE)
// =====================================
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0
};

// =====================================
//  BASE32 → BYTES DECODER (FOR TOTP)
// =====================================
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, output = [];

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

// =====================================
//  GENERATE TOTP
// =====================================
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

// =====================================
//  SMARTAPI LOGIN (PASSWORD + TOTP)
// =====================================
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }

  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: totp
        })
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;

    // SmartAPI tokens expire at midnight; approx 20 hours safe
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
//  API → /api/login (Frontend Login Button)
// =====================================
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";

  if (!password) {
    return res.json({
      success: false,
      error: "Password missing"
    });
  }

  const result = await smartApiLogin(String(password));

  if (!result.ok) {
    return res.json({
      success: false,
      error:
        result.reason === "ENV_MISSING"
          ? "SmartAPI env missing"
          : result.reason === "LOGIN_FAILED"
          ? "Wrong login password / TOTP / API key"
          : "Error: " + (result.error || "Unknown")
    });
  }

  return res.json({
    success: true,
    message: "SmartAPI login successful",
    session: {
      hasToken: !!session.access_token,
      expires_at: session.expires_at
    }
  });
});

// =====================================
//  API → /api/login/status
// =====================================
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null
  });
});
// =====================================
//  HELPER FUNCTIONS
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

// =====================================
//  MARKET CONFIG (Nifty, Sensex, Natural Gas)
// =====================================
const MARKET_CONFIG = {
  nifty: {
    name: "Nifty",
    strikeStep: 50,
    baseDistances: { far: 250, mid: 200, near: 150 },
    angelSymbol: "NIFTY"
  },
  sensex: {
    name: "Sensex",
    strikeStep: 100,
    baseDistances: { far: 500, mid: 400, near: 300 },
    angelSymbol: "SENSEX"
  },
  "natural gas": {
    name: "Natural Gas",
    strikeStep: 5,
    baseDistances: { far: 80, mid: 60, near: 50 },
    angelSymbol: "NATGAS"
  }
};

// =====================================
//  AUTO DETECT MARKET
// =====================================
function autoDetectMarket(spot, explicitRaw) {
  const m = (explicitRaw || "").toString().trim().toLowerCase();

  if (m && MARKET_CONFIG[m]) return m;

  const s = num(spot);

  if (s > 20 && s < 2000) return "natural gas";
  if (s >= 10000 && s < 40000) return "nifty";
  if (s >= 40000) return "sensex";

  return "nifty";
}

// =====================================
//  NORMALIZE INPUT
// =====================================
function normalizeInput(body) {
  const rawMarket = (body.market || "").toString().toLowerCase().trim();
  const spotVal = num(body.spot);

  const detectedMarket = autoDetectMarket(spotVal, rawMarket);

  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot: spotVal,
    market: detectedMarket,
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live
  };
}

// =====================================
//  TREND ENGINE (ADVANCED)
// =====================================
function computeTrend(input) {
  const ema20 = num(input.ema20);
  const ema50 = num(input.ema50);
  const rsi = num(input.rsi);
  const vwap = num(input.vwap);
  const spot = num(input.spot);

  const comp = {};
  let score = 50;
  let bias = "NONE";

  if (!ema20 || !ema50 || !spot || !vwap || !rsi) {
    comp.warning = "Inputs missing (approx trend)";
    return {
      main: "SIDEWAYS",
      strength: "NEUTRAL",
      score: 50,
      bias: "NONE",
      components: comp,
      comment: "Data incomplete, default sideways."
    };
  }

  // EMA strength
  const emaMid = (ema20 + ema50) / 2;
  const emaDiff = ema20 - ema50;
  const emaPct = (emaDiff / emaMid) * 100;
  let emaScore = clamp(emaPct * 1.5, -25, 25);

  comp.ema_gap =
    emaPct > 0.3
      ? `Bullish (${emaPct.toFixed(2)}%)`
      : emaPct < -0.3
      ? `Bearish (${emaPct.toFixed(2)}%)`
      : `Flat (${emaPct.toFixed(2)}%)`;

  // RSI
  let rsiScore = clamp((rsi - 50) * 1.2, -25, 25);

  if (rsi >= 70) comp.rsi = `RSI ${rsi} (overbought)`;
  else if (rsi >= 60) comp.rsi = `RSI ${rsi} (bullish)`;
  else if (rsi <= 30) comp.rsi = `RSI ${rsi} (oversold)`;
  else if (rsi <= 40) comp.rsi = `RSI ${rsi} (bearish)`;
  else comp.rsi = `RSI ${rsi} (neutral)`;

  // VWAP
  const vwapDiff = spot - vwap;
  const vwapPct = (vwapDiff / vwap) * 100;
  let vwapScore = clamp(vwapPct * 1.5, -20, 20);

  comp.vwap =
    vwapPct > 0.1
      ? `Price above VWAP (${vwapPct.toFixed(2)}%)`
      : vwapPct < -0.1
      ? `Below VWAP (${vwapPct.toFixed(2)}%)`
      : `Near VWAP (${vwapPct.toFixed(2)}%)`;

  // Structure
  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) {
    structScore = 10;
    comp.price_structure = "Clean bullish";
  } else if (spot < ema20 && ema20 < ema50) {
    structScore = -10;
    comp.price_structure = "Clean bearish";
  } else {
    comp.price_structure = "Mixed structure";
  }

  // Expiry
  const d = num(input.expiry_days, 7);
  let expiryAdj = 0;
  if (d <= 2) {
    expiryAdj = -5;
    comp.expiry = "Expiry near (volatile)";
  } else if (d >= 10) {
    expiryAdj = 3;
    comp.expiry = "Expiry far (stable)";
  } else {
    comp.expiry = "Expiry mid";
  }

  // Final score
  score =
    50 +
    emaScore * 0.4 +
    rsiScore * 0.3 +
    vwapScore * 0.2 +
    structScore * 0.2 +
    expiryAdj;

  score = clamp(score, 0, 100);

  let main = "SIDEWAYS";
  let strength = "RANGE";

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

  const comment = `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`;

  return {
    main,
    strength,
    score,
    bias,
    components: comp,
    comment
  };
}

// =====================================
//  EXPIRY SCALING FOR STRIKE DISTANCES
// =====================================
function scaleDistancesByExpiry(expiryDays, baseDistances, step) {
  const d = Math.max(0, num(expiryDays));
  let factor = 0.2 + 0.05 * d;
  if (factor > 1) factor = 1;

  const out = {};
  ["near", "mid", "far"].forEach((k) => {
    let v = baseDistances[k] * factor;
    if (v < step / 2) v = step / 2;
    out[k] = v;
  });
  return out;
}

// =====================================
//  STRIKE ENGINE
// =====================================
function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const { spot, expiry_days } = input;

  const scaled = scaleDistancesByExpiry(
    expiry_days,
    cfg.baseDistances,
    cfg.strikeStep
  );

  const atm = roundToStep(spot, cfg.strikeStep);

  let ceDist, peDist;

  if (trend.main === "UPTREND") {
    ceDist = scaled.near;
    peDist = scaled.far;
  } else if (trend.main === "DOWNTREND") {
    ceDist = scaled.far;
    peDist = scaled.near;
  } else {
    ceDist = scaled.mid;
    peDist = scaled.mid;
  }

  const ceStrike = roundToStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDist, cfg.strikeStep);
  const straddleStrike = atm;

  function makeOption(strike, type, diff) {
    const steps = Math.max(1, Math.round(Math.abs(diff) / cfg.strikeStep));
    const base = Math.max(5, steps * 5);
    return {
      type,
      strike,
      distance: Math.abs(diff),
      entry: base,
      stopLoss: Math.round(base * 0.6),
      target: Math.round(base * 1.5)
    };
  }

  return [
    makeOption(ceStrike, "CE", ceStrike - spot),
    makeOption(peStrike, "PE", peStrike - spot),
    makeOption(straddleStrike, "STRADDLE", straddleStrike - spot)
  ];
}
// =====================================
//  FINAL API ROUTE → /api/calc
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    // 1) Normalize input
    const input = normalizeInput(req.body);

    // 2) Check login (ऐसे ही — अभी SmartAPI call नहीं कर रहे)
    const smartLoginOK = !!session.access_token;

    // 3) Trend engine
    const trend = computeTrend(input);

    // 4) Strike engine
    const strikes = buildStrikes(input, trend);

    // 5) Final JSON response
    res.json({
      success: true,
      message: "Calculation complete",
      login_status: smartLoginOK
        ? "SmartAPI Logged-In"
        : "Not logged-in (demo mode)",

      input,
      trend,
      strikes,

      meta: {
        note:
          "Backend fully ready. SmartAPI live LTP + option chain अगला step है."
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
