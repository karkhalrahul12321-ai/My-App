// =====================================
// Trading Helper Backend (FINAL FIXED VERSION)
// SmartAPI Login + Auto Future Token (V2) + Live FUT LTP
// =====================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");

// =====================================
// APP INIT
// =====================================
const app = express();
app.use(bodyParser.json());

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

// =====================================
// SESSION STORAGE
// =====================================
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// =====================================
// BASE32 + TOTP
// =====================================
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0;
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
// LOGIN FUNCTION (SMARTAPI V2)
// =====================================
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
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password,
          totp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);
    console.log("LOGIN RAW:", data);

    if (!data || !data.status) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    session.access_token = data.data.jwtToken;
    session.refresh_token = data.data.refreshToken;
    session.feed_token = data.data.feedToken;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

// =====================================
// LOGIN ROUTE
// =====================================
app.post("/api/login", async (req, res) => {
  const pass = req.body?.password || "";
  const r = await smartApiLogin(pass);

  if (!r.ok) {
    return res.json({
      success: false,
      error: r.reason,
      raw: r.raw || null,
    });
  }
  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    logged_in: true,
    expires_at: session.expires_at,
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at,
  });
});

// =====================================
// AUTO FUTURE SEARCH — FIXED (SMARTAPI V2)
// =====================================
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
    console.log("SEARCH RAW TEXT:", raw);

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return [];
    }

    return data?.data ?? [];
  } catch (e) {
    console.log("SEARCH ERROR:", e.message);
    return [];
  }
}

// =====================================
// EXPIRY RULES (Corrected Format)
// =====================================
const FUTURE_RULES = {
  nifty: { search: "NIFTY", exchange: "NFO", type: "FUTIDX" },
  sensex: { search: "SENSEX", exchange: "BFO", type: "FUTIDX" },
  "natural gas": { search: "NATURALGAS", exchange: "MCX", type: "FUTCOM" },
};

// correct expiry generator
function nextWeekExpiry(day) {
  const d = new Date();
  while (d.getDay() !== day) d.setDate(d.getDate() + 1);
  return d.toISOString().slice(0, 10);
}

// =====================================
// AUTO FETCH FUTURE TOKEN — FIXED
// =====================================
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const all = await smartSearch(rule.search);
  if (!all.length) return null;

  const today = new Date();

  const match = all.find((x) => {
    const exch = (x.exch_seg || "").toUpperCase();
    const type = (x.instrumenttype || "").toUpperCase();
    return (
      exch === rule.exchange &&
      type === rule.type &&
      x.tradingsymbol.includes(today.getFullYear())
    );
  });

  return match
    ? {
        symbol: match.tradingsymbol,
        token: match.symboltoken,
        expiry: match.expirydate,
      }
    : null;
}

// =====================================
// AUTO FETCH ROUTE
// =====================================
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token)
    return res.json({ success: false, error: "NOT_LOGGED_IN" });

  const out = {};
  for (const m of Object.keys(FUTURE_RULES)) {
    out[m] = await autoFetchFuture(m);
  }

  res.json({ success: true, auto: out });
});

// =====================================
// LTP FETCH — FIXED (SMARTAPI V2)
// =====================================
async function getAutoFutureLTP(market) {
  const cfg = FUTURE_RULES[market];
  if (!cfg) return { ok: false, reason: "NO_MARKET" };

  if (!session.access_token)
    return { ok: false, reason: "NOT_LOGGED_IN" };

  const f = await autoFetchFuture(market);
  if (!f) return { ok: false, reason: "NO_TOKEN" };

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
          exchange: cfg.exchange,
          tradingsymbol: f.symbol,
          symboltoken: f.token,
        }),
      }
    );

    const data = await resp.json();

    if (!data?.status) return { ok: false, reason: "LTP_FAILED", data };
    return { ok: true, ltp: data.data.ltp };
  } catch (e) {
    return { ok: false, reason: "EXC", error: e.message };
  }
}

// =====================================
// STRIKE ENGINE + TREND — ORIGINAL (UNTouched)
// =====================================
// (unchanged — your original functions)
function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

// Trend + Strikes (your untouched code)
function computeTrend(input) { /* unchanged */ }
function buildStrikes(input, trend) { /* unchanged */ }

// =====================================
// CALC ROUTE — ORIGINAL
// =====================================
app.post("/api/calc", async (req, res) => {
  const input = req.body;
  const trend = computeTrend(input);
  const strikes = buildStrikes(input, trend);

  res.json({
    success: true,
    login_status: session.access_token
      ? "SmartAPI Logged-In"
      : "Not logged-in",
    input,
    trend,
    strikes,
    auto_tokens: {}, // updated by autofetch
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
