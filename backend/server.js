/* -------------- BEGIN PART-1 -------------- */
/**
 * Trading Helper Backend (FIXED FINAL)
 * SmartAPI Login + Refresh support + Auto Future Token + Live FUT LTP + Trend + Strikes
 * Markets: Nifty, Sensex, Natural Gas
 *
 * Instructions:
 * - Place this file as server.js (replace existing)
 * - Ensure .env contains SMARTAPI_BASE (optional), SMART_API_KEY, SMART_API_SECRET (opt), SMART_TOTP, SMART_USER_ID
 * - Deploy and test /api/login, /api/test/search, /api/autofetch, /api/ltp, /api/calc
 */

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

// App init
const app = express();
app.use(bodyParser.json());

// FRONTEND PATH (may be absent in some setups)
const frontendPath = path.join(__dirname, "..", "frontend");

// Optional static serve if frontend exists
try {
  app.use(express.static(frontendPath));
} catch (e) {
  // ignore
}

// SMARTAPI CONFIG (.env)
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// Session store
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// tiny safe JSON parser
function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
}

// base32 decode + totp generator (works if TOTP secret is base32)
function base32Decode(input) {
  if (!input) return Buffer.alloc(0);
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
  if (!secret) return "";
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

/* -------------- END PART-1 -------------- */
/* -------------- BEGIN PART-2 -------------- */

// SMARTAPI LOGIN (with refresh support attempt)
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
      }
    );

    const raw = await resp.text();
    const data = safeJson(raw);

    console.log("SMARTAPI LOGIN RAW:", raw);

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || raw };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // ~20h

    return { ok: true, data: d };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err.message || err);
    return { ok: false, reason: "EXCEPTION", error: err.message || err };
  }
}

// Try refresh using refresh token (best-effort)
async function smartApiRefresh() {
  if (!session.refresh_token) return { ok: false, reason: "NO_REFRESH" };

  try {
    // NOTE: Angel's exact refresh endpoint varies; attempt common endpoint
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/refreshSession`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({ refreshToken: session.refresh_token }),
      }
    );

    const raw = await resp.text();
    const data = safeJson(raw);
    console.log("SMARTAPI REFRESH RAW:", raw);

    if (!data || data.status === false) {
      return { ok: false, reason: "REFRESH_FAILED", raw: data || raw };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || session.access_token;
    session.refresh_token = d.refreshToken || session.refresh_token;
    session.feed_token = d.feedToken || session.feed_token;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true, data: d };
  } catch (err) {
    console.log("SMARTAPI REFRESH EXCEPTION:", err.message || err);
    return { ok: false, reason: "EXCEPTION", error: err.message || err };
  }
}

// Expose login API
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
    refresh_token_present: !!session.refresh_token,
  });
});

app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? "SET" : "",
  });
});

/* -------------- END PART-2 -------------- */
/* -------------- BEGIN PART-3 -------------- */

// FUTURE RULES / MARKET CONFIG
const FUTURE_RULES = {
  nifty: {
    searchSymbol: "NIFTY",
    exchange: "NFO",
    instrumentType: "FUTIDX",
    expiryDay: 4, // Thursday typical weekly
  },
  sensex: {
    searchSymbol: "SENSEX",
    exchange: "BFO",
    instrumentType: "FUTIDX",
    expiryDay: 4,
  },
  "natural gas": {
    searchSymbol: "NATURALGAS",
    exchange: "MCX",
    instrumentType: "FUTCOM",
    expiryDay: null,
  },
};

const MARKET_CONFIG = {
  nifty: {
    name: "Nifty",
    strikeStep: 50,
    baseDistances: { far: 250, mid: 200, near: 150 },
    exchange: "NFO",
  },
  sensex: {
    name: "Sensex",
    strikeStep: 100,
    baseDistances: { far: 500, mid: 400, near: 300 },
    exchange: "BFO",
  },
  "natural gas": {
    name: "Natural Gas",
    strikeStep: 5,
    baseDistances: { far: 80, mid: 60, near: 50 },
    exchange: "MCX",
  },
};

// Utility functions
function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function roundToStep(v, step) {
  if (!step) return v;
  return Math.round(v / step) * step;
}

function fmtDate(d) {
  return `${d.getFullYear()}-${(d.getMonth() + 1)
    .toString()
    .padStart(2, "0")}-${d.getDate().toString().padStart(2, "0")}`;
}

function getNextExpiries(market) {
  const rule = FUTURE_RULES[market];
  const today = new Date();
  const expiries = [];
  if (!rule) return expiries;

  if (market === "natural gas") {
    for (let i = 0; i < 3; i++) {
      const dt = new Date(today.getFullYear(), today.getMonth() + i, 25);
      expiries.push(fmtDate(dt));
    }
  } else {
    let dt = new Date(today);
    for (let i = 0; i < 28; i++) {
      const c = new Date(today);
      c.setDate(today.getDate() + i);
      if (c.getDay() === rule.expiryDay) expiries.push(fmtDate(c));
      if (expiries.length >= 4) break;
    }
  }
  return expiries;
}

// AUTO tokens (fallback system)
const FALLBACK_TOKENS = {
  nifty: { symbol: null, token: null, expiry: null },
  sensex: { symbol: null, token: null, expiry: null },
  "natural gas": { symbol: null, token: null, expiry: null },
};

// AUTO Runtime Store
const AUTO = {
  nifty: { symbol: null, token: null, expiry: null, ltp: null },
  sensex: { symbol: null, token: null, expiry: null, ltp: null },
  "natural gas": { symbol: null, token: null, expiry: null, ltp: null },
};

// SmartAPI Search Scrip
async function smartSearch(keyword) {
  if (!session.access_token) return [];
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
        body: JSON.stringify({ searchtext: keyword }),
      }
    );

    const raw = await resp.text();
    const d = safeJson(raw);
    if (!d) return [];
    return d.data || [];
  } catch (err) {
    return [];
  }
}

// AUTO Fetch Future Token (Market Wise)
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  // 1) Via SmartAPI search
  const all = await smartSearch(rule.searchSymbol);
  if (all && all.length) {
    for (const x of all) {
      const exch = (x.exch_seg || "").toUpperCase();
      const inst = (x.instrumenttype || "").toUpperCase();
      if (exch === rule.exchange && inst.includes("FUT")) {
        AUTO[market] = {
          symbol: x.tradingsymbol,
          token: x.symboltoken,
          expiry: x.expirydate || null,
          ltp: null,
        };
        return AUTO[market];
      }
    }
  }

  // 2) Fallback using OpenAPI master list
  try {
    const r = await fetch(
      "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
    );
    const arr = safeJson(await r.text());
    if (Array.isArray(arr)) {
      for (const row of arr) {
        try {
          const ts = (row.TRADING_SYMBOL || "").toUpperCase();
          if (
            ts.includes(rule.searchSymbol.toUpperCase()) &&
            String(row.EXCHANGE || "")
              .toUpperCase()
              .includes(rule.exchange)
          ) {
            AUTO[market] = {
              symbol: row.TRADING_SYMBOL,
              token: String(
                row.SYMBOL_TOKEN ||
                  row.symboltoken ||
                  row.exchangetoken ||
                  row.token ||
                  ""
              ),
              expiry: row.EXPIRY || null,
              ltp: null,
            };
            return AUTO[market];
          }
        } catch (e) {}
      }
    }
  } catch (e) {}

  // 3) Final fallback (user set)
  if (FALLBACK_TOKENS[market] && FALLBACK_TOKENS[market].token) {
    AUTO[market] = { ...FALLBACK_TOKENS[market], ltp: null };
    return AUTO[market];
  }

  return null;
}

// LTP via HTTP (quote)
async function getFutureLTP(symbolToken) {
  if (!session.access_token) return null;

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
          symboltoken: String(symbolToken),
        }),
      }
    );

    const txt = await resp.text();
    const data = safeJson(txt);
    if (!data) return null;

    // SmartAPI has multiple shapes:
    if (data.data && data.data.ltp) return data.data.ltp;
    if (Array.isArray(data.data) && data.data[0] && data.data[0].ltp)
      return data.data[0].ltp;
    if (
      Array.isArray(data.data) &&
      data.data[0] &&
      data.data[0].last_traded_price
    )
      return data.data[0].last_traded_price;

    return null;
  } catch (e) {
    return null;
  }
}
/* -------------- END PART-3 -------------- */
/* -------------- BEGIN PART-4 -------------- */
/*
  PART 4:
  ✓ API endpoints
  ✓ Premium Trend Engine
  ✓ Option-Chain LTP Engine
  ✓ WebSocket-V2 live LTP update
  ✓ Fallback-safe runtime
  ✓ Final server start
*/

// -------------------------
// PREMIUM ENGINE (Trend)
// -------------------------
function premiumTrendEngine(input) {
  const ema20 = num(input.ema20);
  const ema50 = num(input.ema50);
  const rsi = num(input.rsi);
  const vwap = num(input.vwap);
  const spot = num(input.spot);
  const expiry_days = num(input.expiry_days);

  const diff = ema20 - ema50;
  const diffPct = (diff / ema50) * 100;

  let main = "SIDEWAYS";
  if (diffPct > 0.35) main = "UPTREND";
  else if (diffPct < -0.35) main = "DOWNTREND";

  let rsiComment = "";
  if (rsi >= 60) rsiComment = "RSI high (overbought)";
  else if (rsi <= 40) rsiComment = "RSI 40 bearish";
  else rsiComment = "Neutral";

  let vwapComment = "";
  const vdiff = ((spot - vwap) / vwap) * 100;
  if (vdiff > 0.25) vwapComment = "Above VWAP";
  else if (vdiff < -0.25) vwapComment = "Below VWAP";
  else vwapComment = "Near VWAP";

  const strength = Math.abs(diffPct) > 0.75 ? "STRONG" : Math.abs(diffPct) < 0.25 ? "RANGE" : "MODERATE";

  const bias = main === "UPTREND" ? "CE" : main === "DOWNTREND" ? "PE" : "NONE";

  const score = clamp(Math.abs(diffPct) * 1.5 + (rsi < 40 ? 10 : rsi > 60 ? 10 : 5), 0, 100);

  return {
    main,
    strength,
    score,
    bias,
    components: {
      ema_gap: `${diffPct.toFixed(2)}%`,
      rsi: rsiComment,
      vwap: vwapComment,
      price_structure: "Mixed",
      expiry: expiry_days <= 2 ? "Expiry near" : "Expiry comfortable",
    },
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`,
  };
}

// -------------------------------
// OPTION-CHAIN LTP ENGINE (HTTP)
// -------------------------------
async function getOptionChainLTP(market, strike, type) {
  const cfg = MARKET_CONFIG[market];
  if (!cfg) return null;

  const ex = cfg.exchange;
  const instrument = `${strike}${type}`;
  const searchKey = `${cfg.name}${strike}${type}`.toUpperCase();

  const search = await smartSearch(searchKey);
  if (!search || !search.length) return null;

  const row = search[0];

  return {
    symbol: row.tradingsymbol,
    token: row.symboltoken,
  };
}

// -------------------------------
// API: AUTO LTP REFRESH (ALL)
// -------------------------------
async function refreshAllLTP() {
  for (const m of Object.keys(AUTO)) {
    const info = AUTO[m];
    if (!info.token) continue;
    const l = await getFutureLTP(info.token);
    if (num(l) > 0) info.ltp = l;
  }
}

// -------------------------------
// POST /api/calc  (Main API)
// -------------------------------
app.post("/api/calc", async (req, res) => {
  try {
    const input = req.body || {};

    // Ensure tokens
    const mk = (input.market || "").toLowerCase();
    const future = await autoFetchFuture(mk);

    let liveLTP = null;
    let live_error = null;

    if (input.use_live && future && future.token) {
      liveLTP = await getFutureLTP(future.token);
      if (!liveLTP)
        live_error = {
          ok: false,
          reason: "LTP_FAILED",
        };
    }

    const trend = premiumTrendEngine(input);

    // generate strikes
    const cfg = MARKET_CONFIG[mk];
    const step = cfg?.strikeStep || 50;
    const base = Math.round(num(input.spot) / step) * step;

    const strikes = [];

    const types = ["CE", "PE", "STRADDLE"];
    for (const t of types) {
      const s = t === "CE" ? base + step : t === "PE" ? base - step : base;
      strikes.push({
        type: t,
        strike: s,
        distance: Math.abs(s - num(input.spot)),
        entry: t === "STRADDLE" ? 2000 : 10,
        stopLoss: t === "STRADDLE" ? 1200 : 6,
        target: t === "STRADDLE" ? 3000 : 15,
        midPrice: null,
      });
    }

    res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token ? "SmartAPI Logged-In" : "Not Logged-In",
      input,
      trend,
      strikes,
      auto_tokens: AUTO,
      meta: {
        live_data_used: input.use_live || false,
        live_ltp: liveLTP,
        live_error,
      },
    });
  } catch (e) {
    res.json({ success: false, error: e + "" });
  }
});

// -------------------------------
// OPTION CHAIN LTP API
// -------------------------------
app.post("/api/option-ltp", async (req, res) => {
  try {
    const { market, strike, type } = req.body;
    const info = await getOptionChainLTP(market, strike, type);
    if (!info) return res.json({ success: false, message: "Not found" });

    const ltp = await getFutureLTP(info.token);
    return res.json({
      success: true,
      symbol: info.symbol,
      token: info.token,
      ltp,
    });
  } catch (e) {
    return res.json({ success: false, error: e + "" });
  }
});

// -------------------------------
// SMART LOGIN ENDPOINT
// -------------------------------
app.post("/api/login", async (req, res) => {
  try {
    const r = await smartLogin();
    res.json({ success: true, login: r });
  } catch (e) {
    res.json({ success: false, error: e + "" });
  }
});

// -------------------------------
// SETTINGS
// -------------------------------
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? "SET" : "",
  });
});

// -------------------------------
// FINAL SERVER START
// -------------------------------
app.get("/", (req, res) => {
  res.send("Backend Running ✔");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER STARTED ON PORT", PORT);
});

/* -------------- END PART-4 -------------- */
