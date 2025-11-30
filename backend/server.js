// =====================================
// Trading Helper Backend – DEBUG VERSION
// SmartAPI Login + Auto Futures + V2 Debug Search
// =====================================

const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const path = require("path");
const CryptoJS = require("crypto-js");
const totp = require("totp-generator");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());

// FRONTEND PATH
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
// CONFIG
// =====================================
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// SESSION
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// =====================================
// TOTP
// =====================================
function generateTOTP(secret) {
  return totp(secret);
}

// =====================================
// LOGIN
// =====================================
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) return { ok: false, reason: "PASSWORD_MISSING" };

  try {
    const otp = generateTOTP(SMART_TOTP_SECRET);

    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-PrivateKey": SMART_API_KEY,
          "X-UserType": "USER",
          "X-SourceID": "WEB",
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: otp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    session.access_token = data.data.jwtToken;
    session.refresh_token = data.data.refreshToken;
    session.feed_token = data.data.feedToken;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// ROUTES
app.post("/api/login", async (req, res) => {
  const password = req.body?.password || "";
  const r = await smartApiLogin(password);

  if (!r.ok) {
    return res.json({
      success: false,
      error: r.reason || "ERROR",
      raw: r.raw || null,
    });
  }

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: { logged_in: true, expires_at: session.expires_at },
  });
});

// =====================================
// DEBUG SEARCH – FULL RAW LOGGING
// =====================================
async function smartSearch(keyword) {
  if (!session.access_token) {
    console.log("SEARCH ERROR: NO TOKEN");
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
          searchtext: keyword,
        }),
      }
    );

    const raw = await resp.text();

    console.log("=====================================");
    console.log("SEARCH HTTP STATUS:", resp.status);
    console.log("SEARCH RAW TEXT:", raw);
    console.log("=====================================");

    let data = null;
    try {
      data = JSON.parse(raw);
    } catch {
      return [];
    }

    console.log("SEARCH RAW JSON:", data);

    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    console.log("SEARCH EXCEPTION:", err.message);
    return [];
  }
}

// =====================================
// FUTURE RULES
// =====================================
const FUTURE_RULES = {
  nifty: { searchSymbol: "NIFTY", exchange: "NFO" },
  sensex: { searchSymbol: "SENSEX", exchange: "BFO" },
  "natural gas": { searchSymbol: "NATURALGAS", exchange: "MCX" },
};

function getNextExpiries() {
  const t = new Date();
  const list = [];
  for (let i = 1; i < 40; i++) {
    const d = new Date();
    d.setDate(t.getDate() + i);
    if (d.getDay() === 4) list.push(d.toISOString().slice(0, 10));
  }
  return list.slice(0, 4);
}

// =====================================
// AUTO FUTURE FINDER
// =====================================
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const expiries = getNextExpiries();
  const all = await smartSearch(rule.searchSymbol);
  if (!all.length) return null;

  for (const exp of expiries) {
    const found = all.find((x) => {
      const ex = (x.exch_seg || "").toUpperCase();
      const ed = (x.expirydate || "").slice(0, 10);

      return ex === rule.exchange && ed === exp;
    });
    if (found) return found;
  }

  return null;
}

// =====================================
// AUTO FETCH ROUTE
// =====================================
app.get("/api/autofetch", async (req, res) => {
  const out = {
    nifty: await autoFetchFuture("nifty"),
    sensex: await autoFetchFuture("sensex"),
    "natural gas": await autoFetchFuture("natural gas"),
  };

  res.json({ success: true, auto: out });
});

// =====================================
// TREND + STRIKES (same as your old code)
// =====================================
function analyzeTrend(i) {
  return {
    main: "SIDEWAYS",
    strength: "RANGE",
    score: 46.4,
    components: {
      ema: "Bearish (-0.61%)",
      rsi: `RSI ${i.rsi}`,
      vwap: "0.57%",
    },
    comment: `EMA20=${i.ema20}, EMA50=${i.ema50}`,
  };
}

function buildStrikes(spot) {
  return [
    { type: "CE", strike: spot + 110, distance: 110, entry: 10, stopLoss: 6, target: 15 },
    { type: "PE", strike: spot - 90, distance: 90, entry: 10, stopLoss: 6, target: 15 },
    { type: "STRADDLE", strike: spot + 10, distance: 10, entry: 5, stopLoss: 3, target: 8 },
  ];
}

// =====================================
// CALC
// =====================================
app.post("/api/calc", async (req, res) => {
  const input = req.body;
  const trend = analyzeTrend(input);
  const strikes = buildStrikes(input.spot);

  res.json({
    success: true,
    login_status: "SmartAPI Logged-In",
    input,
    trend,
    strikes,
    auto_tokens: {
      nifty: null,
      sensex: null,
      "natural gas": null,
    },
    meta: {
      live_data_used: false,
      live_ltp: null,
      live_error: { ok: false, reason: "TOKEN_NOT_FOUND" },
    },
  });
});

// =====================================
// FALLBACK
// =====================================
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
// START SERVER
// =====================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER RUNNING:", PORT);
});
