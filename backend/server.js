================================================================================
             FINAL server.js  (SmartAPI Login + LTP + Calc Engine)
================================================================================
*/

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

// Home route
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// fallback for SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
//  SMARTAPI CONFIG
// =====================================
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// =====================================
//  SMARTAPI SESSION STORAGE
// =====================================
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0
};

// =====================================
//  BASE32 → BYTES DECODE  (for TOTP)
// =====================================
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
//  SMARTAPI LOGIN
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
    session.access_token = d.jwtToken;
    session.refresh_token = d.refreshToken;
    session.feed_token = d.feedToken;

    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // 20 hours

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
//  /api/login
// =====================================
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";

  if (!password) {
    return res.json({ success: false, error: "Password missing" });
  }

  const r = await smartApiLogin(password);

  if (!r.ok) {
    return res.json({
      success: false,
      error:
        r.reason === "ENV_MISSING"
          ? "SmartAPI ENV missing"
          : r.reason === "LOGIN_FAILED"
          ? "Login failed"
          : r.error
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
//  /api/login/status
// =====================================
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at
  });
});

// =====================================
//// HELPER FUNCTIONS
// =====================================
function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function roundToStep(v, step) {
  return Math.round(v / step) * step;
}

// =====================================
// MARKET CONFIG
// =====================================
const MARKET_CONFIG = {
  nifty: {
    strikeStep: 50,
    angelSymbol: "NIFTY"
  },
  sensex: {
    strikeStep: 100,
    angelSymbol: "SENSEX"
  },
  "natural gas": {
    strikeStep: 5,
    angelSymbol: "NATURALGAS"
  }
};

// =====================================
// AUTO-DETECT MARKET
// =====================================
function autoDetectMarket(spot, raw) {
  const m = (raw || "").toLowerCase().trim();
  if (MARKET_CONFIG[m]) return m;

  if (spot > 20 && spot < 2000) return "natural gas";
  if (spot >= 10000 && spot < 40000) return "nifty";
  return "sensex";
}

// =====================================
// NORMALIZE INPUT
// =====================================
function normalizeInput(body) {
  const spot = num(body.spot);
  const market = autoDetectMarket(spot, body.market);

  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot,
    market,
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live
  };
}

// ================================================================================
//                          ⭐ LIVE LTP FUNCTION ⭐
// ================================================================================
async function getLiveLTP(symbol, exchange = "NSE") {
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
          exchange,
          tradingsymbol: symbol,
          symboltoken: ""
        })
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || data.status === false)
      return { ok: false, error: "FAILED", raw: data };

    return { ok: true, ltp: data.data.ltp };
  } catch (err) {
    return { ok: false, error: "EXCEPTION", detail: err.message };
  }
}

// =====================================
//  /api/ltp
// =====================================
app.post("/api/ltp", async (req, res) => {
  if (!session.access_token) {
    return res.json({ success: false, error: "NOT_LOGGED_IN" });
  }

  const symbol = req.body.symbol;
  const exchange = req.body.exchange || "NSE";

  if (!symbol) {
    return res.json({ success: false, error: "Missing symbol" });
  }

  const r = await getLiveLTP(symbol, exchange);

  if (!r.ok) {
    return res.json({ success: false, error: "LTP error", detail: r });
  }

  res.json({ success: true, ltp: r.ltp });
});

// =====================================
// TREND ENGINE
// =====================================
function computeTrend(input) {
  const ema20 = input.ema20;
  const ema50 = input.ema50;
  const rsi = input.rsi;
  const vwap = input.vwap;
  const spot = input.spot;

  let score = 50;
  let components = {};

  // EMA
  const emaDiff = ema20 - ema50;
  const emaPct = (emaDiff / ((ema20 + ema50) / 2)) * 100;
  components.ema_gap = `EMA gap ${emaPct.toFixed(2)}%`;
  score += clamp(emaPct, -20, 20);

  // RSI
  components.rsi = `RSI ${rsi}`;
  score += clamp(rsi - 50, -20, 20);

  // VWAP
  const vw = ((spot - vwap) / vwap) * 100;
  components.vwap = `VWAP ${vw.toFixed(2)}%`;
  score += clamp(vw, -10, 10);

  score = clamp(score, 0, 100);

  let main = "SIDEWAYS";
  let bias = "NONE";

  if (score >= 60) {
    main = "UPTREND";
    bias = "CE";
  } else if (score <= 40) {
    main = "DOWNTREND";
    bias = "PE";
  }

  return {
    main,
    score,
    bias,
    components
  };
}

// =====================================
// STRIKE ENGINE
// =====================================
function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const atm = roundToStep(input.spot, cfg.strikeStep);

  const ce = atm + cfg.strikeStep;
  const pe = atm - cfg.strikeStep;

  return [
    { type: "CE", strike: ce },
    { type: "PE", strike: pe },
    { type: "STRADDLE", strike: atm }
  ];
}

// =====================================
// /api/calc
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);
    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    res.json({
      success: true,
      login_status: session.access_token
        ? "SmartAPI Logged-In"
        : "Demo Mode",
      input,
      trend,
      strikes
    });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// =====================================
// START SERVER
// =====================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER running on " + PORT);
});
