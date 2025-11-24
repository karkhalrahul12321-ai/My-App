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
//   LOGIN FUNCTION (FUTURE LIVE DATA)
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
          password: API_SECRET, // बाद में यहाँ password यूज़ कर सकते हैं
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
    session.expires_at = Date.now() + 24 * 60 * 60 * 1000;
    console.log("Login successful!");
    return true;
  } catch (err) {
    console.log("Login Error:", err);
    return false;
  }
}

async function ensureLogin() {
  if (!session.access_token || session.expires_at < Date.now()) {
    console.log("Access Token missing → Trying login (non-blocking)...");
    await doLogin();
  }
  return session.access_token;
}

// =============================
//   TREND ENGINE V2 HELPERS
// =============================

function analyseTrendDetailed({ ema20, ema50, rsi, vwap, spot }, expiryDays) {
  const components = {};
  let score = 0;

  // EMA gap %
  let emaGapPct = 0;
  if (ema50 !== 0) {
    emaGapPct = ((ema20 - ema50) / ema50) * 100;
  }

  if (emaGapPct > 0.3) {
    score += 4;
    components.ema_gap = `Bullish (${emaGapPct.toFixed(2)}%) – EMA20 काफी ऊपर EMA50`;
  } else if (emaGapPct > 0.1) {
    score += 2;
    components.ema_gap = `Mild bullish (${emaGapPct.toFixed(2)}%) – EMA20 थोड़ा ऊपर EMA50`;
  } else if (emaGapPct < -0.3) {
    score -= 4;
    components.ema_gap = `Bearish (${emaGapPct.toFixed(2)}%) – EMA20 काफी नीचे EMA50`;
  } else if (emaGapPct < -0.1) {
    score -= 2;
    components.ema_gap = `Mild bearish (${emaGapPct.toFixed(2)}%) – EMA20 थोड़ा नीचे EMA50`;
  } else {
    components.ema_gap = `Flat (${emaGapPct.toFixed(2)}%) – EMA20 और EMA50 काफ़ी पास`;
  }

  // VWAP position
  const vwapDiff = spot - vwap;
  if (vwap !== 0) {
    const vwapPct = (vwapDiff / vwap) * 100;
    if (vwapPct > 0.1) {
      score += 2;
      components.vwap = `Price above VWAP (${vwapPct.toFixed(
        2
      )}%) – intraday bullish bias`;
    } else if (vwapPct < -0.1) {
      score -= 2;
      components.vwap = `Price below VWAP (${vwapPct.toFixed(
        2
      )}%) – intraday bearish bias`;
    } else {
      components.vwap = `Price near VWAP (${vwapPct.toFixed(
        2
      )}%) – कोई clear bias नहीं`;
    }
  } else {
    components.vwap = "VWAP 0 है – डेटा अधूरा";
  }

  // RSI
  if (rsi >= 70) {
    score += 3;
    components.rsi = `Overbought zone (${rsi.toFixed(
      2
    )}) – strong bullish momentum (सावधान)`;
  } else if (rsi >= 60) {
    score += 2;
    components.rsi = `Bullish zone (${rsi.toFixed(2)}) – buyers strong`;
  } else if (rsi <= 30) {
    score -= 3;
    components.rsi = `Oversold zone (${rsi.toFixed(
      2
    )}) – strong bearish momentum (reversal possible)`;
  } else if (rsi <= 40) {
    score -= 2;
    components.rsi = `Bearish zone (${rsi.toFixed(2)}) – sellers active`;
  } else {
    components.rsi = `Neutral zone (${rsi.toFixed(
      2
    )}) – RSI से कोई clear दिशा नहीं`;
  }

  // Price vs EMA20
  if (spot > ema20) {
    score += 1;
    components.price_structure = `Spot EMA20 के ऊपर – short term buyers active`;
  } else if (spot < ema20) {
    score -= 1;
    components.price_structure = `Spot EMA20 के नीचे – short term sellers active`;
  } else {
    components.price_structure = `Spot EMA20 के आस-पास – कोई big edge नहीं`;
  }

  // Expiry effect
  let expiryEffect = "";
  if (expiryDays <= 2) {
    // expiry बहुत पास – थोड़ा sideways bias बढ़ा देंगे
    if (score > 3) score -= 1;
    if (score < -3) score += 1;
    expiryEffect =
      "Expiry बहुत पास – volatility high, trend जल्दी बदल सकता है (extra सावधानी)";
    components.expiry_effect = expiryEffect;
  } else if (expiryDays >= 6) {
    expiryEffect = "Expiry दूर – trend ज़्यादा साफ़ और stable रहता है";
    components.expiry_effect = expiryEffect;
  } else {
    expiryEffect = "Expiry मध्यम – normal volatility";
    components.expiry_effect = expiryEffect;
  }

  // Final classification
  let main = "SIDEWAYS";
  let strength = "RANGE";
  let bias = "NONE";

  if (score >= 6) {
    main = "UPTREND";
    strength = "STRONG";
    bias = "CE";
  } else if (score >= 3) {
    main = "UPTREND";
    strength = "MODERATE";
    bias = "CE";
  } else if (score <= -6) {
    main = "DOWNTREND";
    strength = "STRONG";
    bias = "PE";
  } else if (score <= -3) {
    main = "DOWNTREND";
    strength = "MODERATE";
    bias = "PE";
  } else {
    main = "SIDEWAYS";
    strength = "RANGE";
    bias = "NONE";
  }

  const commentParts = [];
  commentParts.push(
    `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi.toFixed(
      2
    )}, VWAP=${vwap}, Spot=${spot}`
  );
  if (main === "UPTREND") {
    commentParts.push(
      "Overall bias ऊपर की तरफ है, dips पर CE side पर काम किया जा सकता है (rule-based, कोई guarantee नहीं)."
    );
  } else if (main === "DOWNTREND") {
    commentParts.push(
      "Overall bias नीचे की तरफ है, bounces पर PE side पर काम किया जा सकता है (rule-based, कोई guarantee नहीं)."
    );
  } else {
    commentParts.push(
      "Market sideways / choppy zone में है, दोनों side whipsaw होने का risk ज़्यादा है."
    );
  }

  return {
    main, // UPTREND / DOWNTREND / SIDEWAYS
    strength,
    score,
    bias, // CE / PE / NONE
    components,
    comment: commentParts.join(" "),
  };
}

// =============================
//   MARKET CONFIG
// =============================
const MARKET_CONFIG = {
  nifty: {
    step: 50,
    baseDistances: [250, 200, 150],
  },
  sensex: {
    step: 100,
    baseDistances: [500, 400, 300],
  },
  "natural gas": {
    step: 10,
    baseDistances: [80, 60, 50],
  },
};

function scaleDistances(expiryDays, baseDistances) {
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

function buildStrikes({ spot, market, expiryDays, trendMain, bias }) {
  const key = (market || "nifty").toLowerCase();
  const cfg = MARKET_CONFIG[key] || MARKET_CONFIG["nifty"];
  const step = cfg.step;
  const distances = scaleDistances(expiryDays, cfg.baseDistances);

  if (trendMain === "UPTREND") {
    return distances.map((d) => ({
      type: "CE",
      distance: d,
      strike: roundUpToStep(spot + d, step),
    }));
  }

  if (trendMain === "DOWNTREND") {
    return distances.map((d) => ({
      type: "PE",
      distance: d,
      strike: roundDownToStep(spot - d, step),
    }));
  }

  // SIDEWAYS
  return [
    {
      type: "CE",
      distance: distances[1],
      strike: roundUpToStep(spot + distances[1], step),
    },
          {
