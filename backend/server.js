// =============================
//   IMPORTS
// =============================
const express = require("express");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(bodyParser.json());

// =============================
//   FRONTEND PATH FIX FOR RENDER
// =============================
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// अगर कोई भी unknown route हो तो index.html दो
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =============================
//   ENV CONFIG
// =============================
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelone.in";
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
  expires_at: 0
};

// =============================
//   BASE32 → BYTES DECODER (TOTP)
// =============================
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
//   LOGIN FUNCTION
// =============================
async function doLogin() {
  try {
    const totp = generateTOTP(TOTP_SECRET);

    const response = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
      method: "POST",
      headers: {
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "00:00:00:00:00:00",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-PrivateKey": API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        userId: USER_ID,
        password: API_SECRET,
        totp: totp
      })
    });

    const data = await response.json();

    if (data.status === false) {
      console.log("Login failed:", data);
      return false;
    }

    session.access_token = data.data.jwtToken;
    session.expires_at = Date.now() + 24 * 60 * 60 * 1000;
    console.log("Login successful!");

    return true;

  } catch (err) {
    console.log("Login Error:", err);
    return false;
  }
}

// =============================
//   TOKEN CHECK
// =============================
async function ensureLogin() {
  if (!session.access_token || session.expires_at < Date.now()) {
    console.log("Access Token missing → Logging in again...");
    await doLogin();
  }
  return session.access_token;
}

// ==========================================================
//   TREND + STRIKE SUGGESTION (YOUR ADVANCED LOGIC)
// ==========================================================
function calculateTrend(ema20, ema50, rsi, vwap, spot) {
  // --- Trend logic ---
  if (spot > ema20 && ema20 > ema50 && rsi > 60) {
    return {
      code: "UP",
      label: "BULLISH TREND",
      direction: "CE",
      comment: `Strong bullish — Spot=${spot} > EMA20=${ema20} > EMA50=${ema50}, RSI=${rsi}`
    };
  }

  if (spot < ema20 && ema20 < ema50 && rsi < 40) {
    return {
      code: "DOWN",
      label: "BEARISH TREND",
      direction: "PE",
      comment: `Strong bearish — Spot=${spot} < EMA20=${ema20} < EMA50=${ema50}, RSI=${rsi}`
    };
  }

  return {
    code: "SIDEWAYS",
    label: "SIDEWAYS / RANGE",
    direction: "NONE",
    comment: `Mixed signals → sideways zone`
  };
}

function strikesForMarket(market, spot) {
  let gapCE = 60;
  let gapPE = 60;

  if (market === "sensex") {
    gapCE = 400;
    gapPE = 400;
  }

  if (market === "naturalgas") {
    gapCE = 60;
    gapPE = 60;
  }

  return [
    {
      type: "CE",
      strike: spot + gapCE,
      distance: gapCE,
      entry: 10,
      stopLoss: 6,
      target: 15,
    },
    {
      type: "PE",
      strike: spot - gapPE,
      distance: gapPE,
      entry: 10,
      stopLoss: 6,
      target: 15,
    },
    {
      type: "STRADDLE",
      strike: Math.round(spot / 50) * 50,
      distance: 0,
      entry: 10,
      stopLoss: 6,
      target: 15,
    }
  ];
}

// =============================
//   API ROUTE → CALCULATE
// =============================
app.post("/api/calc", async (req, res) => {
  try {
    await ensureLogin();

    const { ema20, ema50, rsi, vwap, spot, market } = req.body;

    const trend = calculateTrend(ema20, ema50, rsi, vwap, spot);
    const strikes = strikesForMarket(market, spot);

    res.json({
      success: true,
      message: "Calculation complete",
      input: req.body,
      trend,
      strikes,
      meta: {
        live_data_used: req.body.use_live,
        note: "Option prices फिलहाल simple हैं, बाद में Angel live chain जोड़ेंगे।"
      }
    });

  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// =============================
//   START SERVER  ✔✔✔
// =============================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
