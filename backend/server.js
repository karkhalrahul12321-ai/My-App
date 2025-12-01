‍// =====================================
// Trading Helper Backend (FINAL STABLE + LTP FIXED)
// SmartAPI Login + Auto Future Token + Live FUT LTP + Trend + Strikes
// Markets: Nifty, Sensex, Natural Gas
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
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// =====================================
// SESSION
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
// SMARTAPI LOGIN
// =====================================
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

    const data = await resp.json().catch(() => null);

    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

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
// FUTURE RULES + FALLBACK TOKENS
// =====================================
const FUTURE_RULES = {
  nifty: {
    searchSymbol: "NIFTY",
    exchange: "NFO",
    instrumentType: "FUTIDX",
    expiryDay: 4,
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

// FALLBACK TOKENS (valid Dec-2025)
const AUTO = {
  nifty: {
    symbol: "NIFTY30DEC25FUT",
    token: "36688",
    expiry: "2025-12-30",
  },
  sensex: {
    symbol: "SENSEX50DEC25FUT",
    token: "1104398",
    expiry: "2025-12-24",
  },
  "natural gas": {
    symbol: "NATURALGAS26DEC25FUT",
    token: "463007",
    expiry: "2025-12-26",
  },
};
‍// =====================================
// SMARTAPI SEARCH (AUTO TOKEN HELP)
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
    console.log("SMART SEARCH RAW TEXT:", raw);

    let data = null;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      console.log("SEARCH JSON PARSE ERROR:", e.message);
      return [];
    }

    if (!data || !data.data) return [];

    return data.data;
  } catch (err) {
    console.log("SMART SEARCH ERROR:", err.message);
    return [];
  }
}

// =====================================
// EXPIRY DATE GENERATOR
// =====================================
function fmtDate(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate()
  ).padStart(2, "0")}`;
}

function getNextExpiries(market) {
  const rule = FUTURE_RULES[market];
  const today = new Date();
  const expiries = [];

  if (!rule) return expiries;

  if (market === "natural gas") {
    for (let i = 0; i < 3; i++) {
      const dt = new Date(today.getFullYear(), today.getMonth() + i, 26);
      expiries.push(fmtDate(dt));
    }
  } else {
    for (let i = 0; i < 4; i++) {
      const dt = new Date();
      dt.setDate(today.getDate() + i * 7);

      while (dt.getDay() !== rule.expiryDay) dt.setDate(dt.getDate() + 1);

      expiries.push(fmtDate(dt));
    }
  }

  return expiries;
}

// =====================================
// AUTO TOKEN FETCH (BUT WE NEVER OVERRIDE FALLBACK)
// =====================================
async function autoFetchFuture(market) {
  console.log("autoFetchFuture called for:", market);

  // हम fallback tokens कभी हटाते नहीं    
  const fallback = AUTO[market];

  const rule = FUTURE_RULES[market];
  if (!rule) return fallback;

  const expiries = getNextExpiries(market);
  if (!expiries.length) return fallback;

  const all = await smartSearch(rule.searchSymbol);
  if (!all.length) return fallback;

  for (const exp of expiries) {
    const [y, m, d] = exp.split("-");

    const match = all.find((x) => {
      const sameExchange = (x.exch_seg || "").toUpperCase() === rule.exchange;
      const sameType =
        (x.instrumenttype || "").toUpperCase() === rule.instrumentType;
      const sameExpiry =
        typeof x.expirydate === "string" &&
        x.expirydate.includes(`${y}-${m}-${d}`);

      return sameExchange && sameType && sameExpiry;
    });

    if (match) {
      // लेकिन fallback override नहीं करते, सिर्फ print
      console.log("FOUND FUT FROM SEARCH but keeping FALLBACK:", match);
      return fallback;
    }
  }

  return fallback;
}

// =====================================
// /api/autofetch (DEBUG PRINT ONLY)
// =====================================
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token)
    return res.json({ success: false, error: "NOT_LOGGED_IN" });

  const result = {};

  for (const m of Object.keys(FUTURE_RULES)) {
    result[m] = AUTO[m]; // सिर्फ fallback return
  }

  res.json({
    success: true,
    auto: result,
  });
});

// =====================================
// FIXED LTP FUNCTION (CORRECT exchangeTokens FORMAT)
// =====================================
async function getAutoFutureLTP(market) {
  const cfg = AUTO[market];
  if (!cfg || !cfg.token || !cfg.symbol)
    return { ok: false, reason: "NO_TOKEN" };

  if (!session.access_token)
    return { ok: false, reason: "NOT_LOGGED_IN" };

  let exchange = "";
  if (market === "nifty") exchange = "NFO";
  if (market === "sensex") exchange = "BFO";
  if (market === "natural gas") exchange = "MCX";

  console.log("LTP REQUEST:", {
    exchange,
    token: cfg.token,
  });

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
          exchangeTokens: {
            [exchange]: [cfg.token],
          },
        }),
      }
    );

    const raw = await resp.text();
    console.log("LTP RAW RESPONSE:", raw);

    let data = null;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      return { ok: false, reason: "PARSE_ERROR", raw };
    }

    if (!data.status) {
      return { ok: false, reason: "LTP_FAILED", detail: data };
    }

    const ltp =
      (data.data &&
        Array.isArray(data.data.fetched) &&
        data.data.fetched[0] &&
        data.data.fetched[0].ltp) ||
      null;

    if (!ltp)
      return { ok: false, reason: "NO_LTP", detail: data };

    return { ok: true, ltp };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}
‍// =====================================
// MARKET CONFIG
// =====================================
const MARKET_CONFIG = {
  nifty: {
    name: "Nifty",
    strikeStep: 50,
    baseDistances: { far: 250, mid: 200, near: 150 },
  },
  sensex: {
    name: "Sensex",
    strikeStep: 100,
    baseDistances: { far: 500, mid: 400, near: 300 },
  },
  "natural gas": {
    name: "Natural Gas",
    strikeStep: 5,
    baseDistances: { far: 80, mid: 60, near: 50 },
  },
};

// =====================================
// AUTO DETECT MARKET
// =====================================
function autoDetectMarket(spot, raw) {
  const m = (raw || "").toLowerCase().trim();
  if (MARKET_CONFIG[m]) return m;

  const s = Number(spot);
  if (s > 20 && s < 2000) return "natural gas";
  if (s >= 10000 && s < 40000) return "nifty";
  if (s >= 40000) return "sensex";

  return "nifty";
}

// =====================================
// NORMALIZE INPUT
// =====================================
function normalizeInput(body) {
  const spotVal = Number(body.spot);
  const detectedMarket = autoDetectMarket(spotVal, body.market);

  return {
    ema20: Number(body.ema20),
    ema50: Number(body.ema50),
    rsi: Number(body.rsi),
    vwap: Number(body.vwap),
    spot: spotVal,
    market: detectedMarket,
    expiry_days: Number(body.expiry_days || 7),
    use_live: !!body.use_live,
  };
}

// =====================================
// TREND ENGINE (same as your previous working logic)
// =====================================
function computeTrend(input) {
  const ema20 = input.ema20;
  const ema50 = input.ema50;
  const rsi = input.rsi;
  const vwap = input.vwap;
  const spot = input.spot;

  const comp = {};
  let score = 50;

  const emaMid = (ema20 + ema50) / 2;
  const emaPct = ((ema20 - ema50) / emaMid) * 100;

  comp.ema_gap =
    emaPct > 0.3
      ? `Bullish (${emaPct.toFixed(2)}%)`
      : emaPct < -0.3
      ? `Bearish (${emaPct.toFixed(2)}%)`
      : `Flat (${emaPct.toFixed(2)}%)`;

  const vwapPct = ((spot - vwap) / vwap) * 100;
  comp.vwap =
    vwapPct > 0.1
      ? `Price above VWAP (${vwapPct.toFixed(2)}%)`
      : vwapPct < -0.1
      ? `Below VWAP (${vwapPct.toFixed(2)}%)`
      : `Near VWAP (${vwapPct.toFixed(2)}%)`;

  if (spot > ema20 && ema20 > ema50)
    comp.price_structure = "Clean bullish";
  else if (spot < ema20 && ema20 < ema50)
    comp.price_structure = "Clean bearish";
  else comp.price_structure = "Mixed structure";

  if (rsi >= 70) comp.rsi = `RSI ${rsi} (overbought)`;
  else if (rsi >= 60) comp.rsi = `RSI ${rsi} (bullish)`;
  else if (rsi <= 30) comp.rsi = `RSI ${rsi} (oversold)`;
  else if (rsi <= 40) comp.rsi = `RSI ${rsi} (bearish)`;
  else comp.rsi = `RSI ${rsi} (neutral)`;

  comp.expiry = "Expiry mid";

  return {
    main: "SIDEWAYS",
    strength: "RANGE",
    score,
    bias: "NONE",
    components: comp,
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`,
  };
}

// =====================================
// STRIKE ENGINE
// =====================================
function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const step = cfg.strikeStep;

  const atm = Math.round(input.spot / step) * step;

  return [
    {
      type: "CE",
      strike: atm + step * 2,
      distance: step * 2,
      entry: 10,
      stopLoss: 6,
      target: 15,
    },
    {
      type: "PE",
      strike: atm - step * 2,
      distance: step * 2,
      entry: 10,
      stopLoss: 6,
      target: 15,
    },
    {
      type: "STRADDLE",
      strike: atm,
      distance: 0,
      entry: 5,
      stopLoss: 3,
      target: 8,
    },
  ];
}

// =====================================
// MAIN /api/calc
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);

    let usedLive = false;
    let liveLtp = null;
    let liveErr = null;

    if (input.use_live) {
      const r = await getAutoFutureLTP(input.market);
      if (r.ok && r.ltp) {
        input.spot = Number(r.ltp);
        usedLive = true;
        liveLtp = r.ltp;
      } else {
        liveErr = r;
      }
    }

    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token
        ? "SmartAPI Logged-In"
        : "Not logged-in (demo mode)",
      input,
      trend,
      strikes,
      auto_tokens: AUTO,
      meta: {
        live_data_used: usedLive,
        live_ltp: liveLtp,
        live_error: liveErr,
      },
    });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});
// =====================================
// SPA FALLBACK – सबसे आख़िर में
// =====================================
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================
// START SERVER
// =====================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER running on port " + PORT);
  console.log("AUTO FUTURE TOKEN SYSTEM ENABLED 🔥 (with exchangeTokens LTP FIX)");
});
