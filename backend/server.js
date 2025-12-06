/* ============================
      FINAL ALPHA - PART 1
   ============================ */

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(bodyParser.json({ limit: "500kb" }));

/* ------------------------------
   Frontend Serve (No Change)
------------------------------ */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ------------------------------
   SmartAPI Config
------------------------------ */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* ------------------------------
   Session Storage
------------------------------ */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

/* ------------------------------
   Base32 + TOTP Generator
------------------------------ */
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0;
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

/* ------------------------------
      SmartAPI Login
------------------------------ */
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
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: password,
          totp: totp,
        }),
      }
    );

    const data = await resp.json();

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

/* ------------------------------
   Login Endpoints
------------------------------ */
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
    session: { logged_in: true, expires_at: session.expires_at },
  });
});

/* ------------------------------
   GET /api/login/status
------------------------------ */
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at,
  });
});
/* ============================================
      FINAL ALPHA - PART 2 (FULLY SYNCED)
   ============================================ */

/* --------------------------------------------------
   TREND ENGINE (Sync with frontend expected output)
-------------------------------------------------- */

function computeTrend(ema20, ema50, rsi, vwap, spot) {
  let trend = "NEUTRAL";
  let parts = [];

  if (ema20 > ema50) {
    trend = "UP";
    parts.push("EMA20 > EMA50");
  } else if (ema20 < ema50) {
    trend = "DOWN";
    parts.push("EMA20 < EMA50");
  }

  if (spot > vwap) {
    if (trend === "DOWN") trend = "NEUTRAL";
    else trend = "UP";
    parts.push("Spot > VWAP");
  } else if (spot < vwap) {
    if (trend === "UP") trend = "NEUTRAL";
    else trend = "DOWN";
    parts.push("Spot < VWAP");
  }

  if (rsi > 60) {
    trend = "UP";
    parts.push("RSI > 60");
  } else if (rsi < 40) {
    trend = "DOWN";
    parts.push("RSI < 40");
  }

  if (parts.length === 0) parts.push("Not enough data — Neutral");

  return {
    trend,
    reason: parts.join(" | "),
  };
}

/* --------------------------------------------------
   STRIKE DISTANCE SYSTEM (as per Rahul Trading Plan)
-------------------------------------------------- */

function getDistances(symbol, expiryDays) {
  const decay = Math.max(0.25, Math.min(1, expiryDays / 30));

  if (symbol === "NIFTY")
    return [250 * decay, 200 * decay, 150 * decay];

  if (symbol === "SENSEX")
    return [500 * decay, 400 * decay, 300 * decay];

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

async function estimatePremium(strike) {
  let p = Math.abs(strike / 100);
  if (p < 5) p = 5;
  return Math.round(p);
}

/* --------------------------------------------------
   MASTER API — /analysis/manual
   THIS IS WHAT YOUR FRONTEND CALLS
-------------------------------------------------- */

app.post("/analysis/manual", async (req, res) => {
  try {
    const {
      market = "NIFTY",
      expiry = 7,
      ema20,
      ema50,
      rsi,
      vwap,
      spot,
    } = req.body;

    if (
      ema20 == null ||
      ema50 == null ||
      rsi == null ||
      vwap == null ||
      spot == null
    ) {
      return res.json({ success: false, error: "Missing inputs" });
    }

    const symbol = market.toUpperCase();

    /* -------------------------
         1) TREND ENGINE
    ------------------------- */
    const T = computeTrend(ema20, ema50, rsi, vwap, spot);

    /* -------------------------
         2) STRIKE ENGINE
    ------------------------- */
    const atm = roundStrike(symbol, spot);
    const distances = getDistances(symbol, expiry);

    let side = "CE";
    if (T.trend === "DOWN") side = "PE";

    const s1 = atm;
    const s2 = roundStrike(symbol, side === "CE" ? atm + distances[2] : atm - distances[2]);
    const s3 = roundStrike(symbol, side === "CE" ? atm + distances[1] : atm - distances[1]);

    const entry1 = await estimatePremium(s1);
    const entry2 = await estimatePremium(s2);
    const entry3 = await estimatePremium(s3);

    const mkSL = (e) => +(e * 0.15).toFixed(2);
    const mkTG = (e, sl) => +(e + sl * 1.5).toFixed(2);

    const strikes = [
      {
        strike: s1,
        type: side,
        entry: entry1,
        sl: mkSL(entry1),
        target: mkTG(entry1, mkSL(entry1)),
      },
      {
        strike: s2,
        type: side,
        entry: entry2,
        sl: mkSL(entry2),
        target: mkTG(entry2, mkSL(entry2)),
      },
      {
        strike: s3,
        type: side,
        entry: entry3,
        sl: mkSL(entry3),
        target: mkTG(entry3, mkSL(entry3)),
      },
    ];

    /* -------------------------
         3) SEND EXACT FORMAT THAT
            YOUR FRONTEND EXPECTS
    ------------------------- */
    return res.json({
      success: true,
      trend: T.trend,
      reason: T.reason,
      values: { ema20, ema50, rsi, vwap, spot },
      strikes,
    });

  } catch (err) {
    return res.json({
      success: false,
      error: err.message || "Unknown",
    });
  }
});

/* --------------------------------------------------
   Server Start
-------------------------------------------------- */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("ALPHA BACKEND RUNNING ON PORT", PORT);
});
