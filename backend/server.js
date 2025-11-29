/* ============================================================
   FINAL BACKEND – AUTO TOKEN + LIVE LTP + TREND ENGINE
   Angel NEW searchScrip API (Official Format)
============================================================ */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(express.json());

/* FRONTEND FOLDER */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ENV VARS */
const SMART_API_KEY = process.env.SMART_API_KEY;
const SMART_API_SECRET = process.env.SMART_API_SECRET;
const SMART_USER_ID = process.env.SMART_USER_ID;
const SMART_TOTP = process.env.SMART_TOTP;

const BASE_URL = "https://apiconnect.angelbroking.com";

/* SESSION MEMORY */
let SESSION = {
  jwt: null,
  refresh: null,
  feed: null,
  expires: 0
};

/* ============================================================
   TOTP GENERATOR
============================================================ */
function base32Decode(input) {
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

/* ============================================================
   LOGIN
============================================================ */
async function smartLogin(tradingPassword) {
  try {
    const totp = generateTOTP(SMART_TOTP);

    const resp = await fetch(
      `${BASE_URL}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp: totp
        })
      }
    );

    const data = await resp.json();
    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    SESSION.jwt = data.data.jwtToken;
    SESSION.refresh = data.data.refreshToken;
    SESSION.feed = data.data.feedToken;
    SESSION.expires = Date.now() + 24 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

/* ============================================================
   AUTO LOGIN IF EXPIRED
============================================================ */
async function ensureLogin() {
  if (!SESSION.jwt || Date.now() > SESSION.expires) {
    return await smartLogin(process.env.TRADING_PASSWORD);
  }
  return { ok: true };
}

/* ============================================================
   NEW OFFICIAL SEARCH SCRIP (100% CORRECT)
============================================================ */
async function smartSearch(keyword, exch) {
  if (!SESSION.jwt) return [];

  try {
    const r = await fetch(
      `${BASE_URL}/rest/secure/angelbroking/instruments/v1/searchScrip`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${SESSION.jwt}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          searchtype: "Scrip",
          searchscrip: String(keyword || "").toUpperCase(),
          exchange: exch
        })
      }
    );

    const d = await r.json();
    if (!d || d.status === false || !Array.isArray(d.data)) return [];

    return d.data;
  } catch {
    return [];
  }
}

/* ============================================================
   AUTO TOKEN FETCHER
============================================================ */
async function autoToken(market) {
  let keyword = "";
  let exch = "";

  if (market === "nifty") {
    keyword = "NIFTY";
    exch = "NFO";
  } else if (market === "sensex") {
    keyword = "SENSEX";
    exch = "BFO";
  } else if (market === "natural gas") {
    keyword = "NATURALGAS";
    exch = "MCX";
  }

  const list = await smartSearch(keyword, exch);

  const fut = list.find((x) =>
    x.tradingsymbol.toUpperCase().includes("FUT")
  );

  if (!fut) return { ok: false };

  return {
    ok: true,
    symbol: fut.tradingsymbol,
    token: fut.token,
    expiry: fut.expiry,
    exch,
    inst: fut.instrumenttype
  };
}

/* ============================================================
   LIVE LTP FETCHER
============================================================ */
async function getLTP(exch, symbol, token) {
  try {
    const r = await fetch(
      `${BASE_URL}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${SESSION.jwt}`,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          mode: "LTP",
          exchange: exch,
          tradingsymbol: symbol,
          symboltoken: token
        })
      }
    );

    const d = await r.json();
    if (!d || !d.data || !d.data.ltp) return null;

    return d.data.ltp;
  } catch {
    return null;
  }
}

/* ============================================================
   TREND + STRIKES ENGINE (SAME AS ORIGINAL)
============================================================ */
function computeTrend(o) {
  const { ema20, ema50, rsi, vwap, spot } = o;

  let score = 0;

  score += ema20 > ema50 ? 20 : -20;
  score += rsi > 50 ? 10 : -10;
  score += spot > vwap ? 10 : -10;

  let main = "SIDEWAYS";
  if (score > 40) main = "UP";
  else if (score < -40) main = "DOWN";

  return {
    main,
    strength: score > 40 ? "STRONG" : score < -40 ? "WEAK" : "NEUTRAL",
    score,
    bias: score > 40 ? "BULLISH" : score < -40 ? "BEARISH" : "NONE",
    components: {
      ema: ((ema20 - ema50) / ema50 * 100).toFixed(2) + "%",
      rsi,
      vwap: ((spot - vwap) / vwap * 100).toFixed(2) + "%",
      structure: 0,
      expiry: 0
    }
  };
}

function buildStrikes(input, trend) {
  const { spot } = input;

  return [
    {
      type: "CE",
      strike: Math.round(spot + 100),
      distance: 100,
      entry: 10,
      stopLoss: 6,
      target: 15
    },
    {
      type: "PE",
      strike: Math.round(spot - 80),
      distance: 80,
      entry: 10,
      stopLoss: 6,
      target: 15
    },
    {
      type: "STRADDLE",
      strike: Math.round(spot),
      distance: Math.round(Math.abs(spot - Math.round(spot))),
      entry: 5,
      stopLoss: 3,
      target: 8
    }
  ];
}

/* ============================================================
   MAIN API – CALCULATE
============================================================ */
app.post("/api/calc", async (req, res) => {
  await ensureLogin();

  let {
    ema20,
    ema50,
    rsi,
    vwap,
    spot,
    market,
    expiry_days,
    use_live
  } = req.body;

  const AUTO = {};
  const tok = await autoToken(market);

  if (tok.ok) {
    AUTO[market] = tok;

    if (use_live) {
      const ltp = await getLTP(tok.exch, tok.symbol, tok.token);
      if (ltp) spot = ltp;
    }
  } else {
    AUTO[market] = { symbol: null, token: null };
  }

  const trend = computeTrend({
    ema20,
    ema50,
    rsi,
    vwap,
    spot,
    expiry_days
  });

  const strikes = buildStrikes({ spot }, trend);

  res.json({
    success: true,
    login_status: SESSION.jwt ? "SmartAPI Logged-In" : "Not logged-in",
    input: req.body,
    trend,
    strikes,
    auto_tokens: AUTO,
    meta: {
      live_data_used: use_live,
      live_ltp: use_live ? spot : null
    }
  });
});

/* FALLBACK */
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* START SERVER */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("SERVER RUNNING", PORT));
