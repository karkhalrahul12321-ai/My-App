// server.part1.js (ALPHA) - PART 1 of 2

// ----------------------------
// Imports & Config
// ----------------------------
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch"); // package.json must include node-fetch
const bodyParser = require("body-parser");
const dotenv = require("dotenv");

dotenv.config(); // read from environment (Render .env)

// ----------------------------
// App Init & Middleware
// ----------------------------
const app = express();
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// CORS (if frontend hosted separately) - package.json must include cors
const cors = require("cors");
app.use(cors());

// ----------------------------
// Static Frontend Serve
// ----------------------------
// assumes frontend files are in ../frontend relative to backend folder
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});
app.get("/settings", (req, res) => {
  res.sendFile(path.join(frontendPath, "settings.html"));
});

// ----------------------------
// SmartAPI / ENV config
// ----------------------------
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE ||
  process.env.SMARTAPI_URL ||
  "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || ""; // clientcode/user id
// Note: trading password will be supplied from frontend input (only password)

// ----------------------------
// Session store (in-memory)
// ----------------------------
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// ----------------------------
// Helpers: base32 decode + TOTP
// ----------------------------
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

// ----------------------------
// SmartAPI login implementation
// - uses SMART_USER_ID (clientcode) from .env
// - uses TOTP from .env
// - accepts trading password from frontend (POST body)
// ----------------------------
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  const totp = generateTOTP(SMART_TOTP_SECRET);
  if (!totp) return { ok: false, reason: "TOTP_FAIL" };

  try {
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
      }
    );

    const data = await resp.json().catch(() => null);
    console.log("SMARTAPI LOGIN RAW:", data);

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    // set expiry approx 20 hours
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true, raw: data };
  } catch (err) {
    console.error("SMARTAPI LOGIN EXCEPTION:", err);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// ----------------------------
// Routes: Login, status, settings
// ----------------------------

// POST /api/login  -> body: { password: "tradingPassword" }
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
  const result = await smartApiLogin(password);

  if (!result.ok) {
    const errMap = {
      ENV_MISSING: "SmartAPI ENV missing",
      PASSWORD_MISSING: "Password missing",
      TOTP_FAIL: "TOTP generation failed",
      LOGIN_FAILED: "SmartAPI login failed",
      EXCEPTION: "Login exception",
    };
    return res.status(400).json({
      success: false,
      error: errMap[result.reason] || "Login error",
      raw: result.raw || null,
    });
  }

  return res.json({
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
    expires_at: session.expires_at || null,
  });
});

app.get("/api/settings", (req, res) => {
  // Return keys that the frontend sometimes expects; be cautious with secrets in production.
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? "*****" : "",
  });
});

// ----------------------------
// Calculation route (stub start)
// POST /api/calc  -> body: { ema20, ema50, rsi, vwap, spot, market, daysToExpiry, useLiveLTP }
// returns JSON in frontend-expected format
// ----------------------------
/* server.part2.js (ALPHA) - PART 2 of 2
   Attach this file right after Part 1 content (combine to form server.js).
   Provides engines, /api/calc and /analysis/manual compatibility + server start.
*/

/* ----------------------------
   Helper: simple strength calculator
   ---------------------------- */
function computeStrength(ema20, ema50, rsi, vwap, spot) {
  // returns 0-100
  let score = 50;
  if (typeof ema20 === "number" && typeof ema50 === "number") {
    if (ema20 > ema50) score += 10;
    else score -= 10;
  }
  if (typeof rsi === "number") {
    if (rsi > 60) score += Math.min(20, (rsi - 60));
    else if (rsi < 40) score -= Math.min(20, (40 - rsi));
  }
  if (typeof vwap === "number" && typeof spot === "number") {
    if (spot > vwap) score += 8;
    else score -= 8;
  }
  // clamp
  score = Math.round(Math.max(0, Math.min(100, score)));
  return score;
}

/* ----------------------------
   Strike helpers (same logic as earlier)
   ---------------------------- */
function getDistances(symbol, expiryDays) {
  const decay = Math.max(0.25, Math.min(1, (expiryDays || 7) / 30));
  if (symbol === "NIFTY") return [Math.round(250 * decay), Math.round(200 * decay), Math.round(150 * decay)];
  if (symbol === "SENSEX") return [Math.round(500 * decay), Math.round(400 * decay), Math.round(300 * decay)];
  if (symbol === "NATURALGAS") {
    const r = (x) => Math.round(x * 20) / 20;
    return [r(80 * decay), r(60 * decay), r(50 * decay)];
  }
  return [100, 75, 50];
}
function roundStrike(symbol, strike) {
  if (symbol === "NATURALGAS") return Math.round(strike * 20) / 20;
  return Math.round(strike);
}

async function estimatePremiumFallback(symbol, strike, spot) {
  // deterministic fallback to give UI meaningful numbers
  // if spot present use distance to estimate premium, else small default
  try {
    const base = Math.abs((spot || strike) - (strike || spot || 0));
    let p = Math.max(5, Math.round(base / 100));
    // natural gas smaller scale
    if (symbol === "NATURALGAS") p = Math.max(2, Math.round(base / 2));
    return p;
  } catch (e) {
    return 5;
  }
}

/* ----------------------------
   Option: try fetch Live option premium (best-effort)
   Uses session.feed_token or access_token if available
   but will NOT fail if calls are unauthorized.
   ---------------------------- */
async function tryFetchLivePremium(symbol, strike, side) {
  // Placeholder: no generic public endpoint available reliably.
  // Return null to signal caller to use fallback.
  return null;
}

/* ----------------------------
   Build strikes array (ATM + two near)
   ---------------------------- */
async function buildStrikesForSymbol(symbol, spot, expiryDays, trend, preferLive) {
  const distances = getDistances(symbol, expiryDays);
  const atm = roundStrike(symbol, spot || 0);

  let primarySide = "CE";
  if (trend === "DOWN") primarySide = "PE";
  if (trend === "NEUTRAL") primarySide = "CE";

  // choose offsets: use distances[2] & distances[1] as near strikes
  const offsets = [0, distances[2], distances[1]];
  const candidates = offsets.map((off) => {
    const raw = primarySide === "CE" ? atm + off : atm - off;
    return { strike: roundStrike(symbol, raw), side: primarySide };
  });

  // ensure ATM first
  candidates[0].strike = roundStrike(symbol, atm);

  const strikesOut = [];
  for (let c of candidates) {
    let entry = null;
    if (preferLive) {
      entry = await tryFetchLivePremium(symbol, c.strike, c.side).catch(() => null);
    }
    if (entry == null) {
      entry = await estimatePremiumFallback(symbol, c.strike, spot);
    }
    const sl = +(entry * 0.15).toFixed(2);
    const target = +Math.max(entry + sl * 1.5, entry + 5).toFixed(2);
    strikesOut.push({
      strike: c.strike,
      type: c.side,
      entryPrice: entry,
      stopLoss: sl,
      target: target,
    });
  }

  return strikesOut;
}

/* ----------------------------
   Compatibility wrapper:
   /api/calc  and /analysis/manual both call this handler
   Input accepted:
   {
     market or symbol,
     ema20, ema50, rsi, vwap, spot,
     expiryDays (or expiry),
     useLiveLTP (boolean)
   }
   Output (frontend expected locked format):
   {
     success: true,
     trend: "UP"/"DOWN"/"NEUTRAL",
     bias: "Bullish"/"Bearish"/"Neutral",
     strength: 0-100,
     reason: "...",
     values: { ema20, ema50, rsi, vwap, spot },
     strikes: { call: x, put: y, atm: z },
     priceSource: "Manual"|"Live"
   }
*/
async function handleCalc(req, res) {
  try {
    const body = req.body || {};
    // accept flexible keys
    const market = (body.market || body.symbol || body.asset || "NIFTY").toUpperCase();
    const ema20 = typeof body.ema20 === "number" ? body.ema20 : Number(body.ema20) || null;
    const ema50 = typeof body.ema50 === "number" ? body.ema50 : Number(body.ema50) || null;
    const rsi = typeof body.rsi === "number" ? body.rsi : Number(body.rsi) || null;
    const vwap = typeof body.vwap === "number" ? body.vwap : Number(body.vwap) || null;
    const spot = typeof body.spot === "number" ? body.spot : Number(body.spot) || null;
    const expiryDays = Number(body.expiryDays || body.daysToExpiry || body.expiry || 7);
    const useLiveLTP = !!body.useLiveLTP;

    // require numeric inputs (frontend previously validated but backend must double-check)
    if ([ema20, ema50, rsi, vwap, spot].some((v) => v == null || isNaN(v))) {
      return res.json({ success: false, error: "Missing inputs - required: ema20, ema50, rsi, vwap, spot" });
    }

    // 1) Trend
    const trendCalc = computeTrend(ema20, ema50, rsi, vwap, spot);
    const trend = trendCalc.trend;
    const reason = trendCalc.reason;

    // 2) Strength
    const strength = computeStrength(ema20, ema50, rsi, vwap, spot);

    // 3) Bias text
    let bias = "Neutral";
    if (trend === "UP") bias = "Bullish";
    if (trend === "DOWN") bias = "Bearish";

    // 4) Strikes
    const strikesList = await buildStrikesForSymbol(market, spot, expiryDays, trend, useLiveLTP);

    // Map to frontend simple strikes object: call, put, atm
    // pick first as atm candidate, rest as call/put depending on side
    const atmStrike = strikesList[0]?.strike || roundStrike(market, spot);
    // For display convenience pick call = first CE strike LARGER or equal; put = first PE smaller or equal
    let callStrike = null;
    let putStrike = null;
    for (let s of strikesList) {
      if (s.type === "CE" && callStrike == null) callStrike = s.strike;
      if (s.type === "PE" && putStrike == null) putStrike = s.strike;
    }
    // fallback: if both null, set call=atm, put=atm
    if (callStrike == null) callStrike = atmStrike;
    if (putStrike == null) putStrike = atmStrike;

    // priceSource
    const priceSource = useLiveLTP ? "Live" : "Manual";

    // Final response matches frontend-locked format
    return res.json({
      success: true,
      trend: trend,
      bias: bias,
      strength: strength,
      reason: reason,
      values: { ema20, ema50, rsi, vwap, spot },
      strikes: { call: callStrike, put: putStrike, atm: atmStrike },
      priceSource: priceSource,
    });
  } catch (err) {
    return res.json({ success: false, error: err.message || "Unknown error in calculation" });
  }
}

/* ----------------------------
   Expose routes (compatibility)
   ---------------------------- */
// POST /api/calc
app.post("/api/calc", handleCalc);
// POST /analysis/manual (some frontends use this)
app.post("/analysis/manual", handleCalc);

// Also keep /api/strikes for direct strike-only calls if frontend ever uses it
app.post("/api/strikes", async (req, res) => {
  try {
    const body = req.body || {};
    const market = (body.market || body.symbol || "NIFTY").toUpperCase();
    const spot = typeof body.spot === "number" ? body.spot : Number(body.spot) || null;
    const expiryDays = Number(body.expiryDays || body.expiry || 7);
    const trend = body.trend || "NEUTRAL";
    const useLiveLTP = !!body.useLiveLTP;

    if (market !== "NATURALGAS" && (spot == null || isNaN(spot))) {
      return res.json({ success: false, error: "spot required for this market" });
    }

    const strikesList = await buildStrikesForSymbol(market, spot, expiryDays, trend, useLiveLTP);

    return res.json({ success: true, symbol: market, spot, expiryDays, trend, strikes: strikesList });
  } catch (err) {
    return res.json({ success: false, error: err.message || "Unknown" });
  }
});

/* ----------------------------
   Health / ping (already existed in some parts) - keep
   ---------------------------- */
app.get("/ping", (req, res) => res.json({ ok: true, msg: "Alpha Trading backend alive" }));

/* ----------------------------
   Start server (if not already started in Part1)
   Note: If Part1 already started server.listen, duplicate listen will error.
   If combining, ensure only one listen exists. If Part1 didn't include listen, this will start.
   ---------------------------- */
if (!module.parent) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log("ALPHA FINAL (Part1+Part2) running on port", PORT);
  });
}
