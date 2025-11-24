// =====================================
// Trading Helper Backend (FINAL)
// SmartAPI Login + Live LTP + Trend + Strikes
// =====================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const fetch = require("node-fetch");
const crypto = require("crypto");

// =====================================
// APP INIT
// =====================================
const app = express();
app.use(bodyParser.json());

// =====================================
// SERVE FRONTEND FILES
// =====================================
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
// SMARTAPI CONFIG (from ENV)
// =====================================
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// OPTIONAL: LTP tokens (अगर आप बाद में डालना चाहें)
// अभी खाली रहने दो तो भी backend fail नहीं होगा
const SMART_NIFTY_TOKEN = process.env.SMART_NIFTY_TOKEN || "";
const SMART_SENSEX_TOKEN = process.env.SMART_SENSEX_TOKEN || "";
const SMART_NATGAS_TOKEN = process.env.SMART_NATGAS_TOKEN || "";

// =====================================
// SMARTAPI SESSION STORAGE
// =====================================
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0
};

// =====================================
// BASE32 → BYTES (TOTP के लिए)
// =====================================
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const output = [];

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
// GENERATE TOTP
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
// SMARTAPI LOGIN
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
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    // approx 20 घंटे valid
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
// /api/login
// =====================================
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";

  if (!password) {
    return res.json({ success: false, error: "Password missing" });
  }

  const r = await smartApiLogin(String(password));

  if (!r.ok) {
    return res.json({
      success: false,
      error:
        r.reason === "ENV_MISSING"
          ? "SmartAPI ENV missing"
          : r.reason === "LOGIN_FAILED"
          ? "SmartAPI login failed"
          : "Login error: " + (r.error || "Unknown")
    });
  }

  res.json({
    success: true,
    message: "SmartAPI login successful",
    session: {
      hasToken: !!session.access_token,
      expires_at: session.expires_at
    }
  });
});

// =====================================
// /api/login/status
// =====================================
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null
  });
});

// =====================================
// /api/settings  (frontend settings page के लिए)
// =====================================
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || ""
  });
});

// =====================================
// HELPERS
// =====================================
function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function roundToStep(v, step) {
  if (!step) return v;
  return Math.round(v / step) * step;
}

// =====================================
// MARKET CONFIG (Nifty, Sensex, Natural Gas)
// =====================================
const MARKET_CONFIG = {
  nifty: {
    name: "Nifty",
    strikeStep: 50,
    baseDistances: { far: 250, mid: 200, near: 150 },
    angelSymbol: "NIFTY",
    exchange: "NSE",
    ltpToken: SMART_NIFTY_TOKEN || ""   // optional
  },
  sensex: {
    name: "Sensex",
    strikeStep: 100,
    baseDistances: { far: 500, mid: 400, near: 300 },
    angelSymbol: "SENSEX",
    exchange: "BSE",
    ltpToken: SMART_SENSEX_TOKEN || ""  // optional
  },
  "natural gas": {
    name: "Natural Gas",
    strikeStep: 5,
    baseDistances: { far: 80, mid: 60, near: 50 },
    angelSymbol: "NATURALGAS",
    exchange: "MCX",
    ltpToken: SMART_NATGAS_TOKEN || ""  // optional
  }
};

// =====================================
// AUTO DETECT MARKET
// =====================================
function autoDetectMarket(spot, explicitRaw) {
  const m = (explicitRaw || "").toString().trim().toLowerCase();
  if (MARKET_CONFIG[m]) return m;

  const s = num(spot, 0);

  if (s > 20 && s < 2000) return "natural gas";
  if (s >= 10000 && s < 40000) return "nifty";
  if (s >= 40000) return "sensex";

  return "nifty";
}

// =====================================
// NORMALIZE INPUT
// =====================================
function normalizeInput(body) {
  const spotVal = num(body.spot);
  const detectedMarket = autoDetectMarket(spotVal, body.market);

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

// ====================================================================
// LIVE LTP FUNCTION (SmartAPI quote)
// ====================================================================
async function getLiveLTP(symbol, exchange, symbolToken) {
  try {
    if (!session.access_token) {
      return { ok: false, error: "NOT_LOGGED_IN" };
    }

    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: `Bearer ${session.access_token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          mode: "LTP",
          exchange: exchange,
          tradingsymbol: symbol,
          symboltoken: symbolToken || ""
        })
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || data.status === false) {
      return { ok: false, error: "LTP_FETCH_FAILED", raw: data || null };
    }

    return { ok: true, ltp: data.data.ltp };
  } catch (err) {
    return { ok: false, error: "LTP_EXCEPTION", detail: err.message };
  }
}

// =====================================
// /api/ltp (optional standalone LTP)
// =====================================
app.post("/api/ltp", async (req, res) => {
  try {
    if (!session.access_token) {
      return res.json({ success: false, error: "NOT_LOGGED_IN" });
    }

    const symbol = req.body.symbol;
    const exchange = req.body.exchange || "NSE";
    const token = req.body.symboltoken || "";

    if (!symbol) {
      return res.json({ success: false, error: "Missing symbol" });
    }

    const r = await getLiveLTP(symbol, exchange, token);

    if (!r.ok) {
      return res.json({ success: false, error: "LTP error", detail: r });
    }

    res.json({ success: true, ltp: r.ltp });
  } catch (err) {
    res.json({
      success: false,
      error: "EXCEPTION in /api/ltp",
      detail: err.message
    });
  }
});

// =====================================
// ADVANCED TREND ENGINE
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
// EXPIRY SCALING FOR STRIKE DISTANCES
// =====================================
function scaleDistancesByExpiry(expiryDays, baseDistances, step) {
  const d = Math.max(0, num(expiryDays, 7));
  let factor = 0.2 + 0.05 * d;
  if (factor > 1) factor = 1;

  const out = {};
  ["near", "mid", "far"].forEach((k) => {
    const raw = baseDistances[k] || 0;
    let v = raw * factor;
    if (v < step / 2) v = step / 2;
    out[k] = v;
  });

  return out;
}

// =====================================
// STRIKE ENGINE
// =====================================
function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market] || MARKET_CONFIG["nifty"];
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
// /api/calc – MAIN API (LTP + Trend + Strikes)
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);
    const cfg = MARKET_CONFIG[input.market];

    let liveUsed = false;
    let liveError = null;
    let liveLtpValue = null;

    // Use Live Data ON + login OK + config available
    if (input.use_live && cfg && session.access_token) {
      const token = cfg.ltpToken || "";
      const r = await getLiveLTP(cfg.angelSymbol, cfg.exchange, token);

      if (r.ok && num(r.ltp) > 0) {
        input.spot = num(r.ltp);
        liveUsed = true;
        liveLtpValue = input.spot;
      } else {
        liveError = r.error || "LTP_FAILED";
      }
    }

    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token
        ? "SmartAPI Logged-In"
        : "Not logged-in (demo mode)",
      input,
      trend,
      strikes,
      meta: {
        live_data_used: liveUsed,
        live_ltp: liveLtpValue,
        live_error: liveError,
        note:
          "अगर live_data_used false है तो spot वही है जो आपने input में manually डाला था।"
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
// START SERVER
// =====================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER running on port " + PORT);
});
