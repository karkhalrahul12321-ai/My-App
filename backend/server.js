// =====================================
// Trading Helper Backend (FINAL VERSION)
// ORIGINAL + REFRESH TOKEN + SMARTAPI V2 + searchText FIX
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
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
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
// TOTP HELPERS
// =====================================
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

// =====================================
// SAFE REFRESH TOKEN (SMARTAPI V2)
// =====================================
async function safeRefreshToken() {
  if (!session.refresh_token) {
    return { ok: false, reason: "NO_REFRESH" };
  }

  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/jwt/v1/generateTokens`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          refreshToken: session.refresh_token,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || !data.data || data.status === false) {
      console.log("SAFE REFRESH FAILED:", data);
      return { ok: false, reason: "REFRESH_FAIL" };
    }

    const d = data.data;
    session.access_token = d.jwtToken || session.access_token;
    session.refresh_token = d.refreshToken || session.refresh_token;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    console.log("REFRESH ERROR:", err.message);
    return { ok: false };
  }
}

// =====================================
// SMARTAPI LOGIN (V1)
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

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    const d = data.data || {};

    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
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
// GENERIC HELPERS
// =====================================
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

// =====================================
// FUTURE RULES
// =====================================
const FUTURE_RULES = {
  nifty: {
    searchSymbol: "NIFTY",
    exchange: "NFO",
    instrumentType: "FUTIDX",
    expiryDay: 2,
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

function fmtDate(d) {
  return `${d.getFullYear()}-${(d.getMonth() + 1)
    .toString()
    .padStart(2, "0")}-${d.getDate().toString().padStart(2, "0")}`;
}

function getNextExpiries(market) {
  const rule = FUTURE_RULES[market];
  const today = new Date();
  const expiries = [];

  if (market === "natural gas") {
    for (let i = 0; i < 3; i++) {
      const dt = new Date(today.getFullYear(), today.getMonth() + i, 25);
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
// AUTO TOKEN STORAGE
// =====================================
const AUTO = {
  nifty: { symbol: null, token: null, expiry: null },
  sensex: { symbol: null, token: null, expiry: null },
  "natural gas": { symbol: null, token: null, expiry: null },
};

// =====================================
// SMARTAPI SEARCH (FIXED: searchText)
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
        body: JSON.stringify({
          searchText: keyword, 
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    return [];
  }
}

// =====================================
// UNIVERSAL MATCHING
// =====================================
function isMatchingContract(x, rule, exp) {
  const sameExchange = x.exch_seg === rule.exchange;

  const type = (x.instrumenttype || "").toUpperCase();
  const sameType = ["FUTIDX", "FUT", "FUTSTK", "FUTCOM"].includes(type);

  const expiry = (x.expirydate || "")
    .replace("T00:00:00+05:30", "")
    .replace(/-/g, "")
    .toLowerCase();

  const target = exp.replace(/-/g, "").toLowerCase();

  return sameExchange && sameType && expiry.includes(target);
}

// =====================================
// AUTO FETCH FUTURE
// =====================================
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const expiries = getNextExpiries(market);
  const all = await smartSearch(rule.searchSymbol);

  if (!all.length) return null;

  for (const exp of expiries) {
    const match = all.find((x) => isMatchingContract(x, rule, exp));
    if (match) {
      AUTO[market] = {
        symbol: match.tradingsymbol,
        token: match.symboltoken,
        expiry: match.expirydate,
      };
      return AUTO[market];
    }
  }
  return null;
}

// =====================================
// FORCE AUTO FETCH API
// =====================================
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token) {
    return res.json({ success: false, error: "NOT_LOGGED_IN" });
  }

  const result = {};
  for (const m of Object.keys(FUTURE_RULES)) {
    const r = await autoFetchFuture(m);
    result[m] = r || AUTO[m];
  }

  res.json({ success: true, auto: result });
});

// =====================================
// MARKET / LTP / TREND / STRIKES
// =====================================
const MARKET_CONFIG = {
  nifty: {
    strikeStep: 50,
    baseDistances: { far: 250, mid: 200, near: 150 },
    exchange: "NFO",
  },
  sensex: {
    strikeStep: 100,
    baseDistances: { far: 500, mid: 400, near: 300 },
    exchange: "BFO",
  },
  "natural gas": {
    strikeStep: 5,
    baseDistances: { far: 80, mid: 60, near: 50 },
    exchange: "MCX",
  },
};

function autoDetectMarket(spot, given) {
  const m = (given || "").toLowerCase();
  if (MARKET_CONFIG[m]) return m;

  if (spot < 2000) return "natural gas";
  if (spot < 40000) return "nifty";
  return "sensex";
}

function normalizeInput(body) {
  const spot = num(body.spot);
  const detected = autoDetectMarket(spot, body.market);

  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot,
    market: detected,
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live,
  };
}

async function getAutoFutureLTP(market) {
  if (session.expires_at < Date.now()) await safeRefreshToken();

  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };

  const cfg = MARKET_CONFIG[market];
  if (!cfg) return { ok: false, reason: "NO_CFG" };

  let auto = AUTO[market];
  if (!auto.symbol || !auto.token) {
    auto = await autoFetchFuture(market);
    if (!auto) return { ok: false, reason: "TOKEN_NOT_FOUND" };
  }

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
          tradingsymbol: auto.symbol,
          symboltoken: auto.token,
        }),
      }
    );

    const data = await resp.json().catch(() => null);
    if (!data || data.status === false)
      return { ok: false, reason: "LTP_FAILED" };

    return { ok: true, ltp: data.data.ltp };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
// TREND ENGINE
// =====================================
function computeTrend(input) {
  const ema20 = num(input.ema20);
  const ema50 = num(input.ema50);
  const rsi = num(input.rsi);
  const vwap = num(input.vwap);
  const spot = num(input.spot);

  const comp = {};
  let score = 50;
  let bias = "NONE";

  if (!ema20 || !ema50 || !spot || !vwap || !rsi) {
    comp.warning = "Inputs missing";
    return {
      main: "SIDEWAYS",
      strength: "NEUTRAL",
      score: 50,
      bias: "NONE",
      components: comp,
      comment: "Incomplete data",
    };
  }

  const emaMid = (ema20 + ema50) / 2;
  const emaPct = ((ema20 - ema50) / emaMid) * 100;
  const emaScore = clamp(emaPct * 1.5, -25, 25);

  comp.ema =
    emaPct > 0.3
      ? `Bullish (${emaPct.toFixed(2)}%)`
      : emaPct < -0.3
      ? `Bearish (${emaPct.toFixed(2)}%)`
      : `Flat (${emaPct.toFixed(2)}%)`;

  const rsiScore = clamp((rsi - 50) * 1.2, -25, 25);
  comp.rsi = `RSI ${rsi}`;

  const vwapPct = ((spot - vwap) / vwap) * 100;
  const vwapScore = clamp(vwapPct * 1.5, -20, 20);
  comp.vwap = `VWAP ${vwapPct.toFixed(2)}%`;

  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) structScore = 10;
  else if (spot < ema20 && ema20 < ema50) structScore = -10;

  let expiryAdj = 0;
  if (input.expiry_days <= 2) expiryAdj = -5;
  else if (input.expiry_days >= 10) expiryAdj = 3;

  score =
    50 +
    emaScore * 0.4 +
    rsiScore * 0.3 +
    vwapScore * 0.2 +
    structScore * 0.2 +
    expiryAdj;

  score = clamp(score, 0, 100);

  let main = "SIDEWAYS",
    strength = "RANGE";

  if (score >= 80) (main = "UPTREND"), (strength = "STRONG"), (bias = "CE");
  else if (score >= 60) (main = "UPTREND"), (strength = "MODERATE"), (bias = "CE");
  else if (score <= 20) (main = "DOWNTREND"), (strength = "STRONG"), (bias = "PE");
  else if (score <= 40) (main = "DOWNTREND"), (strength = "MODERATE"), (bias = "PE");

  return {
    main,
    strength,
    score,
    bias,
    components: comp,
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`,
  };
}

// =====================================
// STRIKE ENGINE
// =====================================
function scaleDistances(expiry, base, step) {
  let f = 0.2 + 0.05 * expiry;
  if (f > 1) f = 1;

  return {
    near: Math.max(step / 2, base.near * f),
    mid: Math.max(step / 2, base.mid * f),
    far: Math.max(step / 2, base.far * f),
  };
}

function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const atm = roundToStep(input.spot, cfg.strikeStep);

  const scaled = scaleDistances(input.expiry_days, cfg.baseDistances, cfg.strikeStep);

  let ceDist, peDist;

  if (trend.main === "UPTREND") {
    ceDist = scaled.near;
    peDist = scaled.far;
  } else if (trend.main === "DOWNTREND") {
    ceDist = scaled.far;
    peDist = scaled.near;
  } else {
    ceDist = peDist = scaled.mid;
  }

  const ceStrike = roundToStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDist, cfg.strikeStep);

  function makeOption(strike, type, diff) {
    const steps = Math.max(1, Math.round(Math.abs(diff) / cfg.strikeStep));
    const base = Math.max(5, steps * 5);
    return {
      type,
      strike,
      distance: Math.abs(diff),
      entry: base,
      stopLoss: Math.round(base * 0.6),
      target: Math.round(base * 1.5),
    };
  }

  return [
    makeOption(ceStrike, "CE", ceStrike - input.spot),
    makeOption(peStrike, "PE", peStrike - input.spot),
    makeOption(atm, "STRADDLE", atm - input.spot),
  ];
}

// =====================================
// MAIN API /api/calc
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);

    let usedLive = false;
    let liveLtp = null;
    let liveError = null;

    if (input.use_live) {
      const r = await getAutoFutureLTP(input.market);
      if (r.ok) {
        input.spot = r.ltp;
        usedLive = true;
        liveLtp = r.ltp;
      } else {
        liveError = r;
      }
    }

    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    res.json({
      success: true,
      login_status: session.access_token ? "SmartAPI Logged-In" : "Not logged-in",
      input,
      trend,
      strikes,
      auto_tokens: AUTO,
      meta: {
        live_data_used: usedLive,
        live_ltp: liveLtp,
        live_error: liveError,
      },
    });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// =====================================
// SPA FALLBACK
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
  console.log("SMARTAPI v2 + REFRESH + searchText FIXED");
});
