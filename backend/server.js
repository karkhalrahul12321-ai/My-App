// =====================================
// Trading Helper Backend (FINAL STABLE VERSION)
// SmartAPI Login + searchScrip FIX + Auto Token + LTP + Trend + Strikes
// =====================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

// =====================================
// APP INIT
// =====================================
const app = express();
app.use(bodyParser.json());

// FRONTEND SERVE
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
// SMARTAPI CONFIG
// =====================================
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// SESSION STORE
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// =====================================
// BASE32 DECODE + TOTP
// =====================================
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
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

// =====================================
// LOGIN FUNCTION
// =====================================
async function smartApiLogin(password) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID)
    return { ok: false, reason: "ENV_MISSING" };

  if (!password) return { ok: false, reason: "PASSWORD_MISSING" };

  try {
    const otp = generateTOTP(SMART_TOTP_SECRET);

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
          password,
          totp: otp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false)
      return { ok: false, reason: "LOGIN_FAILED", raw: data };

    const d = data.data;
    session.access_token = d.jwtToken;
    session.refresh_token = d.refreshToken;
    session.feed_token = d.feedToken;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
// LOGIN ROUTES
// =====================================
app.post("/api/login", async (req, res) => {
  const password = req.body.password || "";
  const r = await smartApiLogin(password);

  if (!r.ok)
    return res.json({
      success: false,
      error: r.reason,
      raw: r.raw || null,
    });

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
    expires_at: session.expires_at || null,
  });
});

// =====================================
// SEARCH SCRIP (OFFICIAL FORMAT)
// =====================================
async function smartSearch(keyword) {
  if (!session.access_token) {
    console.log("SEARCH: NO TOKEN");
    return [];
  }

  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/searchScrip`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.access_token}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          searchtext: keyword, // Official param
        }),
      }
    );

    const raw = await resp.text();
    console.log("SEARCH RAW:", raw);

    let data = null;
    try {
      data = JSON.parse(raw);
    } catch {
      data = null;
    }

    if (!data || !data.data) return [];

    return data.data;
  } catch (err) {
    console.log("SEARCH EXCEPTION:", err.message);
    return [];
  }
}

// =====================================
// AUTO FUTURE TOKEN SYSTEM
// =====================================
const FUTURE_RULES = {
  nifty: { searchSymbol: "NIFTY", exchange: "NFO", type: "FUTIDX" },
  sensex: { searchSymbol: "SENSEX", exchange: "BFO", type: "FUTIDX" },
  "natural gas": {
    searchSymbol: "NATURALGAS",
    exchange: "MCX",
    type: "FUTCOM",
  },
};

let AUTO = {
  nifty: { symbol: null, token: null, expiry: null },
  sensex: { symbol: null, token: null, expiry: null },
  "natural gas": { symbol: null, token: null, expiry: null },
};

function fmt(d) {
  return d.toISOString().slice(0, 10);
}

function nextExpiries() {
  const arr = [];
  const now = new Date();
  for (let i = 1; i <= 40; i++) {
    const d = new Date();
    d.setDate(now.getDate() + i);
    if (d.getDay() === 4) arr.push(fmt(d));
  }
  return arr;
}

async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const expiries = nextExpiries();
  const all = await smartSearch(rule.searchSymbol);
  if (!all.length) return null;

  for (const exp of expiries) {
    const found = all.find(
      (x) =>
        x.exch_seg === rule.exchange &&
        x.instrumenttype === rule.type &&
        x.expirydate?.includes(exp)
    );

    if (found) {
      AUTO[market] = {
        symbol: found.tradingsymbol,
        token: found.symboltoken,
        expiry: found.expirydate,
      };
      return AUTO[market];
    }
  }

  return null;
}

app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token)
    return res.json({ success: false, error: "NOT_LOGGED_IN" });

  const out = {};
  for (const m of Object.keys(FUTURE_RULES)) {
    const r = await autoFetchFuture(m);
    out[m] = r || AUTO[m];
  }

  res.json({ success: true, auto: out });
});

// =====================================
// LTP FETCH
// =====================================
async function getAutoLTP(market) {
  const m = AUTO[market];
  if (!m || !m.symbol)
    return { ok: false, reason: "TOKEN_NOT_FOUND" };

  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.access_token}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          mode: "LTP",
          exchange: FUTURE_RULES[market].exchange,
          tradingsymbol: m.symbol,
          symboltoken: m.token,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    console.log("LTP RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false)
      return { ok: false, reason: "LTP_FAILED" };

    return { ok: true, ltp: data.data.ltp };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

// =====================================
// TREND + STRIKES (same as last stable version)
// =====================================

function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function computeTrend(i) {
  return {
    main: "SIDEWAYS",
    strength: "RANGE",
    score: 46,
    bias: "NONE",
    components: {
      ema: "OK",
      rsi: "OK",
      vwap: "OK",
    },
    comment: "Stable version trend (demo)",
  };
}

function buildStrikes(spot) {
  return [
    { type: "CE", strike: spot + 100, distance: 100, entry: 10, stopLoss: 6, target: 15 },
    { type: "PE", strike: spot - 100, distance: 100, entry: 10, stopLoss: 6, target: 15 },
    { type: "STRADDLE", strike: spot, distance: 0, entry: 5, stopLoss: 3, target: 8 },
  ];
}

// =====================================
// CALC ROUTE
// =====================================
app.post("/api/calc", async (req, res) => {
  const input = req.body;
  const spot = num(input.spot);

  const trend = computeTrend(input);
  const strikes = buildStrikes(spot);

  res.json({
    success: true,
    login_status: session.access_token ? "SmartAPI Logged-In" : "Not logged-in",
    input,
    trend,
    strikes,
    auto_tokens: AUTO,
    meta: {
      live_data_used: false,
    },
  });
});

// =====================================
// FALLBACK ROUTE
// =====================================
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
// START SERVER
// =====================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER RUNNING on", PORT);
});
