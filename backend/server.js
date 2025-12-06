// ===========================
// ALPHA - FINAL (Part 1 of 2)
// Save as server.js (paste Part1 then Part2)
// ===========================

/* ---------- Imports & Config ---------- */
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch"); // v2
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();

/* ---------- App Init ---------- */
const app = express();
app.use(bodyParser.json({ limit: "700kb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

/* ---------- Frontend Serve (unchanged) ---------- */
// assumes frontend folder at ../frontend relative to backend
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) => res.sendFile(path.join(frontendPath, "settings.html")));

/* ---------- SmartAPI / ENV ---------- */
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* ---------- In-memory session store ---------- */
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
  try {
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
  } catch (e) {
    return null;
  }
}

/* ---------- Safe fetch wrapper ---------- */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const j = await r.json().catch(() => null);
    return { ok: true, data: j, status: r.status };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

/* ---------- SmartAPI Login Implementation ---------- */
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) return { ok: false, reason: "PASSWORD_MISSING" };

  const totp = generateTOTP(SMART_TOTP_SECRET);
  if (!totp) return { ok: false, reason: "TOTP_FAIL" };

  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
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
    });

    const data = await resp.json().catch(() => null);
    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // ~20 hours

    return { ok: true, raw: data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message || String(err) };
  }
}

/* ---------- Routes: Login / Status / Settings ---------- */

// POST /api/login  -> { password }
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
  const r = await smartApiLogin(password);
  if (!r.ok) {
    const map = {
      ENV_MISSING: "SmartAPI ENV missing",
      PASSWORD_MISSING: "Password missing",
      TOTP_FAIL: "TOTP generation failed",
      LOGIN_FAILED: "SmartAPI login failed",
      EXCEPTION: "Login exception",
    };
    return res.status(400).json({ success: false, error: map[r.reason] || "Login error", raw: r.raw || null });
  }
  return res.json({ success: true, message: "SmartAPI Login Successful", session: { logged_in: true, expires_at: session.expires_at } });
});

// GET /api/login/status
app.get("/api/login/status", (req, res) => {
  res.json({ success: true, logged_in: !!session.access_token, expires_at: session.expires_at || null });
});

// GET /api/settings
app.get("/api/settings", (req, res) => {
  res.json({ success: true, apiKey: SMART_API_KEY ? "*****" : "", userId: SMART_USER_ID || "" });
});

/* ---------- Small helpers (used by Part 2) ---------- */
/* These are intentionally included in Part1 so Part2 can directly use them. */

function roundToStep(symbol, value) {
  if (!isFinite(value)) return value;
  if (symbol === "NATURALGAS") return Math.round(value * 20) / 20; // 0.05 step
  return Math.round(value); // integer steps for indices
}

/* safe numeric parse */
function toNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/* ---------- Placeholder health route ---------- */
app.get("/ping", (req, res) => {
  res.json({ ok: true, msg: "Alpha backend alive" });
});

/* ---------- NOTE ----------
 Part1 ends here. Part2 will include:
  - computeTrend, computeStrength, strike generation,
  - /api/calc and /analysis/manual handlers returning the exact frontend-expected format:
    { success:true, trend:{main,strength,bias,score}, input:{...}, strikes:[...], meta:{...}, login_status:..., auto_tokens:{...} }
  - server listen() if not already started.
 Do NOT start editing Part1 — ask for Part2 when ready.
*/

/* PART 1 COMPLETE */
// ===========================
// ALPHA - FINAL (Part 2 of 2)
// Paste immediately after Part 1
// ===========================

/* ---------- Trend Engine ---------- */
function computeTrend(ema20, ema50, rsi, vwap, spot) {
  let score = 0;
  const reasons = [];

  if (ema20 > ema50) { score += 25; reasons.push("EMA20 > EMA50"); }
  else { score -= 25; reasons.push("EMA20 < EMA50"); }

  if (spot > vwap) { score += 20; reasons.push("Spot > VWAP"); }
  else { score -= 20; reasons.push("Spot < VWAP"); }

  if (rsi > 60) { score += 20; reasons.push("RSI > 60"); }
  else if (rsi < 40) { score -= 20; reasons.push("RSI < 40"); }
  else { reasons.push("RSI Neutral"); }

  let main = "NEUTRAL";
  let bias = "Neutral";
  if (score > 10) { main = "UP"; bias = "Bullish"; }
  else if (score < -10) { main = "DOWN"; bias = "Bearish"; }

  let strength = Math.min(100, Math.max(0, Math.round(score + 50)));

  return { main, bias, strength, score, reasons };
}

/* ---------- Strike Distance Rules ---------- */
function getDistances(symbol, expiryDays) {
  const decay = Math.max(0.25, Math.min(1, (expiryDays || 7) / 30));

  if (symbol === "NIFTY") return [
    Math.round(250 * decay),
    Math.round(200 * decay),
    Math.round(150 * decay)
  ];

  if (symbol === "SENSEX") return [
    Math.round(500 * decay),
    Math.round(400 * decay),
    Math.round(300 * decay)
  ];

  if (symbol === "NATURALGAS") {
    const r = (x) => Math.round(x * 20) / 20;
    return [r(80 * decay), r(60 * decay), r(50 * decay)];
  }

  return [100, 75, 50];
}

/* ---------- Basic Fallback Premium ---------- */
function fallbackPremium(symbol, strike, spot) {
  const base = Math.abs((spot || strike) - strike);
  let p = Math.max(5, Math.round(base / 80));
  if (symbol === "NATURALGAS") p = Math.max(2, Math.round(base / 2));
  return p;
}

/* ---------- Strike Builder (CE, PE, ATM) ---------- */
function buildStrikes(symbol, spot, expiryDays, trendSide) {
  const atm = roundToStep(symbol, spot);
  const distances = getDistances(symbol, expiryDays);

  const ceStrike = roundToStep(symbol, atm + distances[0]);
  const peStrike = roundToStep(symbol, atm - distances[0]);
  const nearCE   = roundToStep(symbol, atm + distances[1]);
  const nearPE   = roundToStep(symbol, atm - distances[1]);

  const build = (strike) => {
    const entry = fallbackPremium(symbol, strike, spot);
    const sl = +(entry * 0.15).toFixed(2);
    const target = +(entry + sl * 1.5).toFixed(2);
    return {
      strike,
      distance: +(Math.abs(strike - atm)).toFixed(2),
      entry,
      stopLoss: sl,
      target
    };
  };

  // UI order: CE, PE, ATM
  return [
    build(ceStrike),
    build(peStrike),
    build(atm)
  ];
}

/* ---------- /api/calc (main engine route) ---------- */
app.post("/api/calc", async (req, res) => {
  try {
    const b = req.body || {};

    const market = (b.market || "NIFTY").toUpperCase();
    const ema20 = toNumber(b.ema20);
    const ema50 = toNumber(b.ema50);
    const rsi   = toNumber(b.rsi);
    const vwap  = toNumber(b.vwap);
    const spot  = toNumber(b.spot);
    const expiryDays = toNumber(b.expiryDays || b.daysToExpiry || 7);

    if ([ema20, ema50, rsi, vwap, spot].some((v) => v === null)) {
      return res.json({ success: false, error: "Invalid inputs" });
    }

    const trendObj = computeTrend(ema20, ema50, rsi, vwap, spot);

    const strikes = buildStrikes(market, spot, expiryDays, trendObj.main);

    const finalResponse = {
      success: true,

      trend: {
        main: trendObj.main,
        strength: trendObj.strength,
        bias: trendObj.bias,
        score: trendObj.score
      },

      input: {
        ema20,
        ema50,
        rsi,
        vwap,
        spot,
        expiry_days: expiryDays,
        market
      },

      strikes: strikes,  // UI expects array in this exact shape

      meta: {
        live_data_used: false
      },

      login_status: session.access_token ? "Logged-in" : "Demo Mode",

      auto_tokens: {
        access: session.access_token || "",
        refresh: session.refresh_token || "",
        feed: session.feed_token || ""
      }
    };

    return res.json(finalResponse);

  } catch (err) {
    return res.json({ success: false, error: err.message });
  }
});

/* ---------- /analysis/manual (UI compatibility) ---------- */
app.post("/analysis/manual", async (req, res) => {
  req.body = req.body || {};
  return app._router.handle(req, res, () => {}, "post", "/api/calc");
});

/* ---------- Start Server ---------- */
if (!module.parent) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log("ALPHA FINAL fully synced running on", PORT));
}

// ===========================
// PART 2 COMPLETE — ALPHA FULLY SYNCED
// ===========================
