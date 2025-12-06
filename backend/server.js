/* ALPHA — server.js (Part 1 of 2) */
/* Replace backend/server.js with Part1 + Part2 combined. Make sure package.json uses node-fetch v2 */

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch"); // v2 compatible require
require("dotenv").config();

const app = express();
app.use(bodyParser.json({ limit: "500kb" }));

/* ---------- Frontend serve (same as original) ---------- */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ---------- SmartAPI / env config ---------- */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || ""; // if needed elsewhere

/* ---------- Session tokens ---------- */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

/* ---------- Utilities: base32 decode + TOTP ---------- */
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const output = [];

  input = (input || "").replace(/=+$/, "").toUpperCase();

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
  if (!secret) return null;
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

/* ---------- SmartAPI Login (same as Alpha) ---------- */
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
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: totp,
        }),
        timeout: 15000,
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
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

/* ---------- Login endpoints (kept intact) ---------- */
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
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
    session: { logged_in: true, expires_at: session.expires_at },
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
  });
});

app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || "",
  });
});

/* ---------- Helper: safe fetch wrapper ---------- */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const j = await r.json().catch(() => null);
    return { ok: true, data: j, status: r.status };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

/* ---------- ENGINE: LTP / Option-chain fetch (POST /api/ltp) ---------- */
/*
  Expects:
  {
    "symbol": "NIFTY" | "SENSEX" | "NATURALGAS",
    "contract": "<optional future token or expiry>",
    "range": 1  // optional days for candle
  }
  Returns approximate LTP / helpful data.
*/
app.post("/api/ltp", async (req, res) => {
  try {
    const { symbol, contract, range } = req.body || {};
    if (!symbol) return res.status(400).json({ success: false, error: "symbol required" });

    // Example: use AngelOne historical OI or candle endpoints if available
    // We'll attempt to call API endpoints if session present or public endpoints exist.
    // For now, use safe fallback: return symbol + placeholder LTP when live fetch not possible.

    // Fallback LTP logic (simple, non-authoritative)
    const fallbackLtp = {
      NIFTY: 19800,
      SENSEX: 67200,
      NATURALGAS: 220,
    };

    // Try a simple public fetch - user may replace with correct AngelOne endpoints
    // NOTE: these calls may require auth. We keep fallback safe.
    // Example placeholder response:
    const result = {
      success: true,
      symbol,
      ltp: fallbackLtp[symbol.toUpperCase()] || null,
      info: "fallback - replace with live data fetch if API tokens available",
    };

    return res.json(result);
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message || "unknown" });
  }
});

/* ---------- ENGINE: Trend calculation (POST /api/calc) ---------- */
/*
  Accepts:
  {
    "symbol": "NIFTY"|"SENSEX"|"NATURALGAS",
    "spot": 12345,                // optional - if provided used
    "ema20": 123,                // optional - if provided used
    "ema50": 120,                // optional - if provided used
    "rsi": 45,                   // optional - if provided used
    "vwap": 121,                 // optional - if provided used
    "candles": [ {o,h,l,c,vol}, ... ] // optional
  }
  Returns:
  {
    success:true,
    trend: "UP"|"DOWN"|"NEUTRAL",
    reason: "...",
    values: { ema20, ema50, rsi, vwap, spot }
  }
*/
function simpleTrendFromInputs(vals) {
  // Very conservative rules combining EMA and RSI and VWAP
  const { ema20, ema50, rsi, vwap, spot } = vals;
  let trend = "NEUTRAL";
  let reasonParts = [];

  if (typeof ema20 === "number" && typeof ema50 === "number") {
    if (ema20 > ema50) {
      trend = "UP";
      reasonParts.push("EMA20>EMA50");
    } else if (ema20 < ema50) {
      trend = "DOWN";
      reasonParts.push("EMA20<EMA50");
    }
  }

  if (typeof vwap === "number" && typeof spot === "number") {
    if (spot > vwap) {
      trend = trend === "DOWN" ? "NEUTRAL" : "UP";
      reasonParts.push("spot>vwap");
    } else if (spot < vwap) {
      trend = trend === "UP" ? "NEUTRAL" : "DOWN";
      reasonParts.push("spot<vwap");
    }
  }

  if (typeof rsi === "number") {
    if (rsi > 60) {
      trend = "UP";
      reasonParts.push("RSI>60");
    } else if (rsi < 40) {
      trend = "DOWN";
      reasonParts.push("RSI<40");
    }
  }

  if (reasonParts.length === 0) reasonParts.push("insufficient numeric inputs - neutral");

  return { trend, reason: reasonParts.join(" | ") };
}

app.post("/api/calc", async (req, res) => {
  try {
    const payload = req.body || {};
    const symbol = (payload.symbol || "NIFTY").toUpperCase();

    // Prefer user-supplied values (you told you will supply in UI)
    const ema20 = typeof payload.ema20 === "number" ? payload.ema20 : null;
    const ema50 = typeof payload.ema50 === "number" ? payload.ema50 : null;
    const rsi = typeof payload.rsi === "number" ? payload.rsi : null;
    const vwap = typeof payload.vwap === "number" ? payload.vwap : null;
    const spot = typeof payload.spot === "number" ? payload.spot : null;

    // If candles provided, you could compute EMAs/RSI/VWAP here (not implemented fully)
    // For now use supplied values.

    const trendResult = simpleTrendFromInputs({ ema20, ema50, rsi, vwap, spot });

    return res.json({
      success: true,
      symbol,
      trend: trendResult.trend,
      reason: trendResult.reason,
      values: { ema20, ema50, rsi, vwap, spot },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message || "unknown" });
  }
});
/* ALPHA — server.js (Part 2 of 2) */
/* Continue: Strike generator + start server */

//////////////////////////////////////////////////////////////
// Strike generator
//////////////////////////////////////////////////////////////

/*
  Accepts:
  {
    "symbol": "NIFTY"|"SENSEX"|"NATURALGAS",
    "spot": 12345,        // required
    "expiryDays": 3,      // days until expiry (optional)
    "trend": "UP"|"DOWN"|"NEUTRAL" // optional - to bias CE/PE
  }

  Returns:
  {
    success:true,
    strikes: [
      { strike: 45000, type: "CE", entryPrice: 120, sl: 15, target: 200, reason: "..."},
      ...
    ],
    spot: 45000
  }
*/
function computeDistance(symbol, expiryDays) {
  // Base distances from older reqs; shrink as expiry approaches
  // Nifty: base 250/200/150 -> we'll pick base step value
  // We'll return an array of three distance offsets from spot
  expiryDays = typeof expiryDays === "number" ? expiryDays : 7;

  // Decay factor: as expiryDays->0, factor->0 (makes strikes near ATM)
  const decay = Math.max(0.2, Math.min(1, expiryDays / 30)); // between 0.2 and 1

  if (symbol === "NIFTY") {
    // want near distances: 250,200,150 scaled by decay
    return [Math.round(250 * decay), Math.round(200 * decay), Math.round(150 * decay)];
  } else if (symbol === "SENSEX") {
    return [Math.round(500 * decay), Math.round(400 * decay), Math.round(300 * decay)];
  } else if (symbol === "NATURALGAS") {
    // gas uses decimals and rounding to 0.05
    const d1 = (80 * decay);
    const d2 = (60 * decay);
    const d3 = (50 * decay);
    const round05 = x => Math.round(x * 20) / 20; // rounds to 0.05
    return [round05(d1), round05(d2), round05(d3)];
  } else {
    // default fallback
    return [100, 75, 50];
  }
}

function roundStrike(symbol, strike) {
  if (symbol === "NATURALGAS") {
    // round to nearest 0.05
    return Math.round(strike * 20) / 20;
  } else {
    // round to nearest integer (strike step assumed 1)
    return Math.round(strike);
  }
}

async function estimateEntryPrice(symbol, strikeLevel, optionType) {
  // Ideally we'd fetch option chain to get LTP; here we provide a reasonable fallback
  // If you have an endpoint to get option LTP, replace this function's logic
  // For now, return a heuristic premium:
  // premium = max(5, abs(spot - strike)/100 * volatilityFactor)
  // We cannot call real option-chain without auth; so keep small fallback values.
  return Math.max(5, Math.round(Math.abs( (strikeLevel || 0) ) / 100));
}

app.post("/api/strikes", async (req, res) => {
  try {
    const payload = req.body || {};
    const symbol = (payload.symbol || "NIFTY").toUpperCase();
    const spot = typeof payload.spot === "number" ? payload.spot : null;
    const expiryDays = typeof payload.expiryDays === "number" ? payload.expiryDays : 7;
    const trend = payload.trend || "NEUTRAL";

    if (!spot && symbol !== "NATURALGAS") {
      return res.status(400).json({ success: false, error: "spot required for this symbol" });
    }

    // compute three distances
    const dists = computeDistance(symbol, expiryDays); // array of 3 distances
    // For NIFTY/SENSEX calculate strikes spaced above/below spot
    const strikes = [];

    // pick ATM = nearest strike to spot (rounding)
    const atm = roundStrike(symbol, spot || 0);

    // Strategy: output 3 strikes: ATM, ATM +/- d1, ATM +/- d2 depending on trend direction
    // For trending UP -> recommend CE strikes; trending DOWN -> recommend PE; neutral -> both sides prefer CE for up small.
    let primarySide = "CE";
    if (trend === "DOWN") primarySide = "PE";
    if (trend === "NEUTRAL") primarySide = "CE";

    // produce three options: ATM (primarySide), near1 (primarySide), near2 (primarySide)
    // For ATM, price estimate via estimateEntryPrice
    const candidateStrikes = [
      { strike: atm, side: primarySide },
      { strike: roundStrike(symbol, (symbol === "NATURALGAS" ? atm + dists[2] : atm + dists[2])), side: primarySide },
      { strike: roundStrike(symbol, (symbol === "NATURALGAS" ? atm + dists[1] : atm + dists[1])), side: primarySide },
    ];

    // If trend is DOWN, flip signs
    if (trend === "DOWN") {
      candidateStrikes[1].strike = roundStrike(symbol, atm - dists[2]);
      candidateStrikes[2].strike = roundStrike(symbol, atm - dists[1]);
    }

    // ensure ATM is first (and if natural gas rounding handled)
    candidateStrikes[0].strike = roundStrike(symbol, atm);

    // compute entry price / sl / target for each
    for (let c of candidateStrikes) {
      const entry = await estimateEntryPrice(symbol, c.strike, c.side);
      const slAmount = +(entry * 0.15).toFixed(2); // 15% of premium
      const target = +Math.max((entry + slAmount * 1.5), entry + 5).toFixed(2); // simple dynamic target

      strikes.push({
        strike: c.strike,
        type: c.side,
        entryPrice: entry,
        stopLoss: slAmount,
        target: target,
        reason: `Auto: ${symbol} ${c.side} | dist applied`,
      });
    }

    return res.json({
      success: true,
      symbol,
      spot,
      expiryDays,
      trend,
      strikes,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message || "unknown" });
  }
});

/* ---------- Health ---------- */
app.get("/ping", (req, res) => res.json({ ok: true, msg: "Alpha Trading backend alive" }));

/* ---------- Start server ---------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("ALPHA BACKEND RUNNING ON PORT", PORT);
});
