// ======================
// server.js — PART 1/4
// Imports, init, helpers, TOTP, SmartAPI login, searchScrip
// ======================

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(express.json());

// Frontend static (adjust path as your repo)
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

// Simple root
app.get("/", (req, res) => {
  try {
    res.sendFile(path.join(frontendPath, "index.html"));
  } catch (e) {
    res.send("Backend running");
  }
});

// ========== CONFIG ==========
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMARTAPI_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// ========== SESSION ==========
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// ========== HELPERS ==========
function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function clamp(v, a, b) {
  return Math.max(a, Math.min(b, v));
}

function roundToStep(v, step) {
  if (!step) return v;
  return Math.round(v / step) * step;
}

// Base32 decode (for TOTP)
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
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
  try {
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
  } catch (e) {
    console.log("TOTP gen error:", e.message);
    return null;
  }
}

// ========== SMARTAPI LOGIN ==========
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
    console.log("LOGIN RAW:", JSON.stringify(data || {}, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    console.log("LOGIN EXC:", err.message);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// LOGIN route
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

// login status
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
  });
});

// Basic settings endpoint
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? "SET" : "",
  });
});

// ========== SEARCH SCRIP HELPER ==========
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
    console.log("SMART SEARCH RAW:", raw);

    let data = null;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      console.log("SMART SEARCH JSON PARSE ERROR:", e.message);
      return [];
    }

    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    console.log("SMART SEARCH ERROR:", err.message);
    return [];
  }
}
// ======================
// server.js — PART 2/4
// Auto-token logic, FUTURE rules, LTP (V3 first, fallback), market config
// ======================

// FUTURE RULES
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
    for (let i = 0; i < 4; i++) {
      const dt = new Date();
      dt.setDate(today.getDate() + i * 7);
      while (dt.getDay() !== rule.expiryDay) {
        dt.setDate(dt.getDate() + 1);
      }
      expiries.push(fmtDate(dt));
    }
  }
  return expiries;
}

// FALLBACK TOKENS (your provided fallback)
const FALLBACK_TOKENS = {
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

// AUTO storage (mutable)
const AUTO = {
  nifty: { ...FALLBACK_TOKENS.nifty },
  sensex: { ...FALLBACK_TOKENS.sensex },
  "natural gas": { ...FALLBACK_TOKENS["natural gas"] },
};

// Market config for strike steps & distances
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

// AUTO_FETCH FUTURE token
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const expiries = getNextExpiries(market);
  if (!expiries.length) {
    AUTO[market] = { ...FALLBACK_TOKENS[market] };
    return AUTO[market];
  }

  const all = await smartSearch(rule.searchSymbol);
  if (!all.length) {
    AUTO[market] = { ...FALLBACK_TOKENS[market] };
    return AUTO[market];
  }

  for (const exp of expiries) {
    const [y, m, d] = exp.split("-");
    const match = all.find((x) => {
      const sameExchange =
        (x.exch_seg || "").toUpperCase() === rule.exchange.toUpperCase();
      const sameType =
        (x.instrumenttype || "").toUpperCase() ===
        (rule.instrumentType || "").toUpperCase();
      const expStr = (x.expirydate || "").toString();
      const sameExpiry = expStr.includes(`${y}-${m}-${d}`);
      return sameExchange && sameType && sameExpiry;
    });

    if (match) {
      AUTO[market] = {
        symbol: match.tradingsymbol,
        token: match.symboltoken,
        expiry: match.expirydate,
      };
      console.log("autoFetchFuture found:", market, AUTO[market]);
      return AUTO[market];
    }
  }

  AUTO[market] = { ...FALLBACK_TOKENS[market] };
  return AUTO[market];
}

// /api/autofetch route
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token)
    return res.json({ success: false, error: "NOT_LOGGED_IN" });

  const result = {};
  for (const m of Object.keys(FUTURE_RULES)) {
    const r = await autoFetchFuture(m);
    result[m] = r || AUTO[m];
  }
  res.json({ success: true, auto: result });
});

// getAutoFutureLTP (V3 try first, fallback to v1-style)
async function getAutoFutureLTP(market) {
  const cfg = MARKET_CONFIG[market];
  if (!cfg) return { ok: false, reason: "NO_MARKET_CFG" };

  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };

  let auto = AUTO[market];
  if (!auto || !auto.token) {
    auto = await autoFetchFuture(market);
    if (!auto || !auto.token) {
      return { ok: false, reason: "TOKEN_NOT_FOUND", auto: auto || null };
    }
  }

  // V3 body
  try {
    const v3Body = {
      mode: "LTP",
      exchangeTokens: {
        [cfg.exchange]: [auto.token],
      },
    };

    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v3/quote`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: `Bearer ${session.access_token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(v3Body),
      }
    );

    const raw = await resp.text();
    console.log("V3 LTP RAW:", raw);

    let data = null;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      data = null;
    }

    if (data && data.status === true && data.data) {
      // various possible shapes
      if (Array.isArray(data.data)) {
        const item = data.data.find(
          (it) =>
            String(it.symbolToken) === String(auto.token) ||
            String(it.symboltoken) === String(auto.token)
        );
        const ltp = item && (item.ltp || item.last_traded_price || item.last_price);
        if (ltp != null) return { ok: true, ltp };
      } else if (data.data.fetched && Array.isArray(data.data.fetched)) {
        const item = data.data.fetched.find(
          (it) =>
            String(it.symbolToken) === String(auto.token) ||
            String(it.symboltoken) === String(auto.token)
        );
        const ltp = item && (item.ltp || item.last_traded_price || item.last_price);
        if (ltp != null) return { ok: true, ltp };
      } else {
        const values = Object.values(data.data || {});
        for (const v of values) {
          if (!v) continue;
          if (Array.isArray(v)) {
            const itm = v.find(
              (it) =>
                String(it.symbolToken) === String(auto.token) ||
                String(it.symboltoken) === String(auto.token)
            );
            const ltp = itm && (itm.ltp || itm.last_traded_price || itm.last_price);
            if (ltp != null) return { ok: true, ltp };
          }
        }
      }
    }

    if (data && data.status === false) {
      console.log("V3 LTP returned status false:", JSON.stringify(data, null, 2));
    }
  } catch (err) {
    console.log("V3 LTP exception:", err.message);
  }

  // fallback v1/v2 style
  try {
    const bodyV1 = {
      mode: "LTP",
      exchange: cfg.exchange,
      tradingsymbol: AUTO[market].symbol,
      symboltoken: AUTO[market].token,
    };

    const resp2 = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: `Bearer ${session.access_token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(bodyV1),
      }
    );

    const data2 = await resp2.json().catch(() => null);
    console.log("Fallback LTP RAW:", JSON.stringify(data2 || {}, null, 2));

    if (data2 && data2.status === true && data2.data) {
      const ltp =
        (data2.data && data2.data.ltp) ||
        (Array.isArray(data2.data) && data2.data[0] && (data2.data[0].ltp || data2.data[0].last_traded_price)) ||
        null;
      if (ltp != null) return { ok: true, ltp };
    }

    return { ok: false, reason: "LTP_FAILED", detail: data2 || null };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}
// ======================
// server.js — PART 3/4
// Normalize input, computeTrend, strike engine
// ======================

function autoDetectMarket(spot, explicitRaw) {
  const m = (explicitRaw || "").toString().trim().toLowerCase();
  if (MARKET_CONFIG[m]) return m;

  const s = num(spot, 0);
  if (s > 20 && s < 2000) return "natural gas";
  if (s >= 10000 && s < 40000) return "nifty";
  if (s >= 40000) return "sensex";
  return "nifty";
}

function normalizeInput(body) {
  const spotVal = num(body.spot);
  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot: spotVal,
    market: autoDetectMarket(spotVal, body.market),
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live,
  };
}

// TREND ENGINE
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
    comp.warning = "Inputs missing (approx trend)";
    return {
      main: "SIDEWAYS",
      strength: "NEUTRAL",
      score: 50,
      bias: "NONE",
      components: comp,
      comment: "Data incomplete, default sideways.",
    };
  }

  const emaMid = (ema20 + ema50) / 2;
  const emaDiff = ema20 - ema50;
  const emaPct = (emaDiff / (Math.abs(emaMid) || 1)) * 100;
  let emaScore = clamp(emaPct * 1.5, -25, 25);
  comp.ema_gap =
    emaPct > 0.3
      ? `Bullish (${emaPct.toFixed(2)}%)`
      : emaPct < -0.3
      ? `Bearish (${emaPct.toFixed(2)}%)`
      : `Flat (${emaPct.toFixed(2)}%)`;

  let rsiScore = clamp((rsi - 50) * 1.2, -25, 25);
  if (rsi >= 70) comp.rsi = `RSI ${rsi} (overbought)`;
  else if (rsi >= 60) comp.rsi = `RSI ${rsi} (bullish)`;
  else if (rsi <= 30) comp.rsi = `RSI ${rsi} (oversold)`;
  else if (rsi <= 40) comp.rsi = `RSI ${rsi} (bearish)`;
  else comp.rsi = `RSI ${rsi} (neutral)`;

  const vwapDiff = spot - vwap;
  const vwapPct = (vwapDiff / (Math.abs(vwap) || 1)) * 100;
  let vwapScore = clamp(vwapPct * 1.5, -20, 20);
  comp.vwap =
    vwapPct > 0.1
      ? `Price above VWAP (${vwapPct.toFixed(2)}%)`
      : vwapPct < -0.1
      ? `Below VWAP (${vwapPct.toFixed(2)}%)`
      : `Near VWAP (${vwapPct.toFixed(2)}%)`;

  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) {
    structScore = 10;
    comp.price_structure = "Clean bullish";
  } else if (spot < ema20 && ema20 < ema50) {
    structScore = -10;
    comp.price_structure = "Clean bearish";
  } else {
    comp.price_structure = "Mixed structure";
  }

  const d = num(input.expiry_days, 7);
  let expiryAdj = 0;
  if (d <= 2) {
    expiryAdj = -5;
    comp.expiry = "Expiry near (volatile)";
  } else if (d >= 10) {
    expiryAdj = 3;
    comp.expiry = "Expiry far (stable)";
  } else {
    comp.expiry = "Expiry mid";
  }

  score =
    50 +
    emaScore * 0.4 +
    rsiScore * 0.3 +
    vwapScore * 0.2 +
    structScore * 0.2 +
    expiryAdj;

  score = clamp(score, 0, 100);

  let main = "SIDEWAYS";
  let strength = "RANGE";

  if (score >= 80) {
    main = "UPTREND";
    strength = "STRONG";
    bias = "CE";
  } else if (score >= 60) {
    main = "UPTREND";
    strength = "MODERATE";
    bias = "CE";
  } else if (score <= 20) {
    main = "DOWNTREND";
    strength = "STRONG";
    bias = "PE";
  } else if (score <= 40) {
    main = "DOWNTREND";
    strength = "MODERATE";
    bias = "PE";
  }

  const comment = `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`;

  return {
    main,
    strength,
    score,
    bias,
    components: comp,
    comment,
  };
}

// scaleDistancesByExpiry (final corrected)
function scaleDistancesByExpiry(expiryDays, baseDistances, step) {
  const d = Math.max(0, num(expiryDays, 7));
  let factor = 0.2 + 0.05 * d;
  if (factor > 1) factor = 1;

  const out = {};
  ["near", "mid", "far"].forEach((k) => {
    const raw = baseDistances[k] || 0;
    let v = raw * factor;
    if (v < step / 2) v = step / 2;
    out[k] = v;
  });

  return out;
}

// Strike builder
function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market] || MARKET_CONFIG["nifty"];
  const { spot, expiry_days } = input;

  const scaled = scaleDistancesByExpiry(expiry_days, cfg.baseDistances, cfg.strikeStep);
  const atm = roundToStep(spot, cfg.strikeStep);

  let ceDist, peDist;
  if (trend.main === "UPTREND") {
    ceDist = scaled.near;
    peDist = scaled.far;
  } else if (trend.main === "DOWNTREND") {
    ceDist = scaled.far;
    peDist = scaled.near;
  } else {
    ceDist = scaled.mid;
    peDist = scaled.mid;
  }

  const ceStrike = roundToStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDist, cfg.strikeStep);
  const straddleStrike = atm;

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
    makeOption(ceStrike, "CE", ceStrike - spot),
    makeOption(peStrike, "PE", peStrike - spot),
    makeOption(straddleStrike, "STRADDLE", straddleStrike - spot),
  ];
}
// ======================
// server.js — PART 4/4
// API endpoints (calc), test routes, fallback, start server
// ======================

// Test route to view raw search response for debugging
app.get("/api/test/search", async (req, res) => {
  if (!session.access_token) return res.json({ success: false, error: "NOT_LOGGED_IN" });

  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/searchScrip`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ searchtext: "NIFTY" }),
    });

    const raw = await resp.text();
    console.log("===== /api/test/search RAW =====");
    console.log(raw);
    console.log("================================");
    res.type("application/json").send(raw);
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// /api/calc main endpoint
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);

    let usedLive = false;
    let liveLtp = null;
    let liveErr = null;

    if (input.use_live) {
      const r = await getAutoFutureLTP(input.market);
      if (r.ok && r.ltp != null) {
        input.spot = num(r.ltp);
        usedLive = true;
        liveLtp = input.spot;
      } else {
        liveErr = r;
      }
    }

    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token ? "SmartAPI Logged-In" : "Not logged-in (demo)",
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
    res.json({
      success: false,
      error: err.message || String(err),
    });
  }
});

// SPA fallback (keep at bottom)
app.get("*", (req, res) => {
  try {
    res.sendFile(path.join(frontendPath, "index.html"));
  } catch (e) {
    res.status(200).send("Backend running");
  }
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER running on port " + PORT);
  console.log("AUTO FUTURE TOKEN SYSTEM ENABLED");
});
