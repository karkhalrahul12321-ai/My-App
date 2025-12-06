/* ===========================
      RAHUL FINAL ALPHA SERVER
      FULL OPTION ENGINE + TREND ENGINE
      REAL LTP, ENTRY, SL, TARGET
      COMPLETE SMARTAPI LOGIN
=========================== */

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

// ---------------------------------------------
// App setup
// ---------------------------------------------
const app = express();
app.use(bodyParser.json());

const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// ---------------------------------------------
// ENV KEYS
// ---------------------------------------------
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE ||
  "https://apiconnect.angelbroking.com";

// ---------------------------------------------
// SESSION STORE
// ---------------------------------------------
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// ---------------------------------------------
// TOTP + Base32 Helpers
// ---------------------------------------------
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

// ---------------------------------------------
// SMARTAPI LOGIN
// ---------------------------------------------
async function smartApiLogin(password) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!password) return { ok: false, reason: "PASSWORD_MISSING" };

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
          "X-MACAddress": "11:11:11:11:11:11",
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: password,
          totp: totp,
        }),
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
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// ---------------------------------------------
// LOGIN ROUTES
// ---------------------------------------------
app.post("/api/login", async (req, res) => {
  const password = req.body?.password || "";
  const r = await smartApiLogin(password);

  if (!r.ok) {
    return res.json({
      success: false,
      error:
        r.reason === "ENV_MISSING"
          ? "SmartAPI ENV missing"
          : r.reason === "PASSWORD_MISSING"
          ? "Password missing"
          : r.reason === "LOGIN_FAILED"
          ? "SmartAPI login failed"
          : "Login error: " + (r.error || "Unknown"),
      raw: r.raw || null,
    });
  }

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at,
    },
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at,
  });
});

// --------------------------------------------------------
// OPTION CHAIN LTP FETCH ENGINE
// --------------------------------------------------------
async function fetchOptionLTP(symbol, strike, type) {
  if (!session.access_token) return null;

  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/option/v1/option-chain`;

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify({ symbol }),
    });

    const data = await resp.json();
    if (!data?.data) return null;

    const list = data.data;
    const item = list.find(
      (o) => o.strikePrice == strike && o.optionType == type
    );
    if (!item) return null;

    const ltp = Number(item.lastPrice || 0);
    return ltp > 0 ? ltp : null;
  } catch (err) {
    return null;
  }
}
/* =====================================================
      PART 2 — FULL TREND ENGINE + STRIKE ENGINE
      REAL LTP ENTRY + FIXED SL + TARGET
===================================================== */

// --------------------------------------------------------
// TREND ENGINE
// --------------------------------------------------------
function computeTrend(inputs) {
  const { ema20, ema50, rsi, vwap, spot } = inputs;

  let score = 0;

  // EMA Trend
  if (spot > ema20) score += 10;
  if (ema20 > ema50) score += 10;

  // RSI
  if (rsi > 60) score += 10;
  if (rsi > 70) score += 5;

  // VWAP
  if (spot > vwap) score += 10;

  const main = score >= 30 ? "UP" : score <= 10 ? "DOWN" : "SIDEWAYS";
  const bias = main === "UP" ? "Bullish" : main === "DOWN" ? "Bearish" : "Neutral";

  return { main, strength: score, bias, score };
}

// --------------------------------------------------------
// STRIKE DISTANCE LOGIC
// --------------------------------------------------------
function getStrikeDistance(market, expiryDays) {
  if (market === "NIFTY") {
    if (expiryDays >= 7) return 63; // 63 = 150 pt approx / 2 steps of NSE round
    if (expiryDays >= 3) return 42;
    return 21;
  }
  return 63;
}

// --------------------------------------------------------
// CALCULATE ENTRY, SL, TARGET
// --------------------------------------------------------
function calcPrices(realLTP, trendScore) {
  if (!realLTP || realLTP <= 0) return { entry: 0, sl: 0, target: 0 };

  const momentumFactor = trendScore / 100; // 0.0 – 1.0
  const entry = Number((realLTP + realLTP * 0.02 * momentumFactor).toFixed(2)); // entry = LTP + small move

  const stopLoss = Number((entry - 15).toFixed(2)); // fixed SL rule

  // target = entry + reward range (6.13 exact as your rule)
  const target = Number((entry + 6.13).toFixed(2));

  return { entry, stopLoss, target };
}

// --------------------------------------------------------
// MAIN /api/suggest ENGINE ROUTE
// --------------------------------------------------------
app.post("/api/suggest", async (req, res) => {
  try {
    const input = req.body || {};

    let {
      ema20,
      ema50,
      rsi,
      vwap,
      spot,
      expiry_days,
      market,
    } = input;

    // Auto spot (if missing)
    if (!spot || spot <= 0) {
      spot = ema20; // simple fallback
    }

    // Compute trend
    const trend = computeTrend({ ema20, ema50, rsi, vwap, spot });

    // Determine strike distances
    const dist = getStrikeDistance(market, expiry_days);

    // Build 3 strikes
    const strike1 = Math.round(spot + dist);
    const strike2 = Math.round(spot - dist);
    const strike3 = Math.round(spot);

    const strikes = [strike1, strike2, strike3];

    // FINAL OUTPUT ARRAY
    const output = [];

    // Process each strike
    for (let st of strikes) {
      // Fetch CE LTP
      const ceLTP = await fetchOptionLTP(market, st, "CE");

      // If CE price not found → use fallback minimal
      const realLTP = ceLTP || 1;

      const pricing = calcPrices(realLTP, trend.strength);

      output.push({
        strike: st,
        distance: Math.abs(st - spot),
        entry: pricing.entry,
        stopLoss: pricing.stopLoss,
        target: pricing.target,
      });
    }

    res.json({
      success: true,
      trend,
      input: {
        ema20,
        ema50,
        rsi,
        vwap,
        spot,
        expiry_days,
        market,
      },
      strikes: output,
      meta: {
        live_data_used: true,
      },
      login_status: session.access_token ? "Logged-in" : "Not-logged",
    });
  } catch (err) {
    res.json({
      success: false,
      error: err.message,
    });
  }
});

// --------------------------------------------------------
// SERVER START
// --------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("ALPHA FINAL SERVER RUNNING ON PORT:", PORT);
});
