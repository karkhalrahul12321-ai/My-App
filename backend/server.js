// =====================================================
// Trading Helper Backend - Clean Stable Version
// SmartAPI Login + Auto Future Tokens + LTP + Trend + Strikes
// (MODIFIED: OptionChain, Greeks, PremiumEngine, WS LTP + HTTP fallback added)
// Reference original upload: 1
// =====================================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

// -----------------------------------------------------
// App init
// -----------------------------------------------------
const app = express();
app.use(bodyParser.json());

// Serve frontend
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// -----------------------------------------------------
// SmartAPI config
// -----------------------------------------------------
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// -----------------------------------------------------
// Session (tokens)
// -----------------------------------------------------
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// -----------------------------------------------------
// Helpers: base32 + TOTP
// -----------------------------------------------------
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

// -----------------------------------------------------
// SmartAPI login
// -----------------------------------------------------
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
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // about 20 hours

    return { ok: true };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// -----------------------------------------------------
// Login routes
// -----------------------------------------------------
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

app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || "",
  });
});
// -----------------------------------------------------
// Generic helpers
// -----------------------------------------------------
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

// -----------------------------------------------------
// Future rules (expiry logic)
// -----------------------------------------------------
const FUTURE_RULES = {
  nifty: {
    searchSymbol: "NIFTY",
    exchange: "NFO",
    instrumentType: "FUTIDX",
    expiryDay: 4, // Thursday
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
    expiryDay: null, // monthly
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

// -----------------------------------------------------
// Fallback tokens (from instrument master)
// -----------------------------------------------------
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

// -----------------------------------------------------
// Auto token storage
// -----------------------------------------------------
const AUTO = {
  nifty: { ...FALLBACK_TOKENS.nifty },
  sensex: { ...FALLBACK_TOKENS.sensex },
  "natural gas": { ...FALLBACK_TOKENS["natural gas"] },
};

// -----------------------------------------------------
// SmartAPI searchScrip helper
// -----------------------------------------------------
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

    const text = await resp.text();
    console.log("SEARCH RAW TEXT:", text);

    let data = null;
    try {
      data = JSON.parse(text);
    } catch (e) {
      console.log("SEARCH JSON PARSE ERROR:", e.message);
      return [];
    }

    console.log("SEARCH JSON:", JSON.stringify(data, null, 2));
    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    console.log("SMART SEARCH ERROR:", err.message);
    return [];
  }
}

// -----------------------------------------------------
// Auto fetch future (via searchScrip, with fallback)
// -----------------------------------------------------
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const expiries = getNextExpiries(market);
  if (!expiries.length) {
    console.log("autoFetchFuture: no expiries, using FALLBACK for", market);
    AUTO[market] = { ...FALLBACK_TOKENS[market] };
    return AUTO[market];
  }

  const all = await smartSearch(rule.searchSymbol);
  if (!all.length) {
    console.log("autoFetchFuture: empty search, using FALLBACK for", market);
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
        rule.instrumentType.toUpperCase();
      const expStr = typeof x.expirydate === "string" ? x.expirydate : "";
      const sameExpiry = expStr.includes(`${y}-${m}-${d}`);
      return sameExchange && sameType && sameExpiry;
    });

    if (match) {
      AUTO[market] = {
        symbol: match.tradingsymbol,
        token: match.symboltoken,
        expiry: match.expirydate,
      };
      console.log("autoFetchFuture: FOUND for", market, AUTO[market]);
      return AUTO[market];
    }
  }

  console.log("autoFetchFuture: no match, using FALLBACK for", market);
  AUTO[market] = { ...FALLBACK_TOKENS[market] };
  return AUTO[market];
}

// Manual trigger for auto tokens
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token) {
    return res.json({ success: false, error: "NOT_LOGGED_IN" });
  }

  const result = {};
  for (const m of Object.keys(FUTURE_RULES)) {
    const r = await autoFetchFuture(m);
    result[m] = r || AUTO[m];
  }

  res.json({
    success: true,
    auto: result,
  });
});

// Debug: raw search route
app.get("/api/test/search", async (req, res) => {
  if (!session.access_token) {
    return res.json({ success: false, error: "NOT_LOGGED_IN" });
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
        body: JSON.stringify({ searchtext: "NIFTY" }),
      }
    );

    const raw = await resp.text();
    console.log("==== /api/test/search RAW ====");
    console.log(raw);
    console.log("================================");

    res.type("application/json").send(raw);
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});
// -----------------------------------------------------
// Market config (for strikes and LTP)
// -----------------------------------------------------
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

// -----------------------------------------------------
// Market detection and input normalization
// -----------------------------------------------------
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
  const detectedMarket = autoDetectMarket(spotVal, body.market);

  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot: spotVal,
    market: detectedMarket,
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live,
  };
}

// -----------------------------------------------------
// LTP fetch using exchangeTokens format
// -----------------------------------------------------
async function getAutoFutureLTP(market) {
  const cfg = MARKET_CONFIG[market];
  if (!cfg) {
    return { ok: false, reason: "NO_MARKET_CFG" };
  }
  if (!session.access_token) {
    return { ok: false, reason: "NOT_LOGGED_IN" };
  }

  let auto = AUTO[market];
  if (!auto.symbol || !auto.token) {
    auto = await autoFetchFuture(market);
    if (!auto || !auto.symbol || !auto.token) {
      return { ok: false, reason: "TOKEN_NOT_FOUND", auto: auto || null };
    }
  }

  const exchangeTokens = {};
  exchangeTokens[cfg.exchange] = [auto.token];

  const body = {
    mode: "FULL",
    exchangeTokens: exchangeTokens,
  };

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
        body: JSON.stringify(body),
      }
    );

    const text = await resp.text();
    console.log("LTP RAW TEXT:", text);

    let data = null;
    try {
      data = JSON.parse(text);
    } catch (e) {
      return {
        ok: false,
        reason: "JSON_PARSE_ERROR",
        raw: text,
        error: e.message,
      };
    }

    console.log("LTP JSON:", JSON.stringify(data, null, 2));

    if (!data || data.status === false) {
      return {
        ok: false,
        reason: "LTP_FAILED",
        detail: data || null,
        requestBody: body,
      };
    }

    // New format: data.data.fetched[0].ltp
    let ltpVal = null;

    if (data.data) {
      if (Array.isArray(data.data.fetched) && data.data.fetched[0]) {
        ltpVal =
          data.data.fetched[0].ltp ||
          data.data.fetched[0].last_traded_price ||
          null;
      } else if (Array.isArray(data.data) && data.data[0]) {
        ltpVal =
          data.data[0].ltp || data.data[0].last_traded_price || null;
      } else if (data.data.ltp) {
        ltpVal = data.data.ltp;
      }
    }

    if (!ltpVal) {
      return {
        ok: false,
        reason: "NO_LTP",
        detail: data,
        requestBody: body,
      };
    }

    return { ok: true, ltp: ltpVal, requestBody: body, response: data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message, requestBody: body };
  }
}

// -----------------------------------------------------
// LTP debug route
// -----------------------------------------------------
app.get("/api/ltp/test", async (req, res) => {
  const market = (req.query.market || "nifty").toLowerCase();
  const r = await getAutoFutureLTP(market);
  res.json({
    success: r.ok,
    result: r,
    auto_tokens: AUTO,
    market,
  });
});
// -----------------------------------------------------
// Trend engine
// -----------------------------------------------------
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
  const emaPct = (emaDiff / emaMid) * 100;
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
  const vwapPct = (vwapDiff / vwap) * 100;
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
  } else {
    main = "SIDEWAYS";
    strength = "RANGE";
    bias = "NONE";
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

// -----------------------------------------------------
// Strike engine
// -----------------------------------------------------
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

function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market] || MARKET_CONFIG.nifty;
  const { spot, expiry_days } = input;

  const scaled = scaleDistancesByExpiry(
    expiry_days,
    cfg.baseDistances,
    cfg.strikeStep
  );

  const atm = roundToStep(spot, cfg.strikeStep);

  let ceDist;
  let peDist;
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
      type: type,
      strike: strike,
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
// -----------------------------------------------------
// Option Chain + Greeks + PremiumEngine + WS LTP + Fallback
// All code here is self-contained and safe-guarded so that if
// SmartAPI is not configured the endpoints still work in demo mode.
// -----------------------------------------------------

// --- Utility: Normal distribution functions for Greeks ---
function normPdf(x) {
  return (1 / Math.sqrt(2 * Math.PI)) * Math.exp(-0.5 * x * x);
}
function normCdf(x) {
  // Abramowitz and Stegun approximation
  const t = 1 / (1 + 0.2316419 * Math.abs(x));
  const d = 0.3989423 * Math.exp((-x * x) / 2);
  let prob =
    d *
    t *
    (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
  if (x > 0) prob = 1 - prob;
  return prob;
}

// --- Black-Scholes implementation (European) ---
function blackScholesPrice(S, K, r, sigma, t, optionType) {
  // S: spot, K: strike, r: risk-free rate (decimal), sigma: vol (decimal), t: time in years
  if (t <= 0 || sigma <= 0) {
    // intrinsic fallback
    if (optionType === "call") return Math.max(0, S - K);
    return Math.max(0, K - S);
  }
  const sqrtT = Math.sqrt(t);
  const d1 = (Math.log(S / K) + (r + (sigma * sigma) / 2) * t) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  if (optionType === "call") {
    return S * normCdf(d1) - K * Math.exp(-r * t) * normCdf(d2);
  } else {
    return K * Math.exp(-r * t) * normCdf(-d2) - S * normCdf(-d1);
  }
}

function blackScholesGreeks(S, K, r, sigma, t, optionType) {
  const sqrtT = Math.sqrt(Math.max(t, 1e-10));
  const d1 = (Math.log(S / K) + (r + (sigma * sigma) / 2) * t) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  const delta =
    optionType === "call" ? normCdf(d1) : normCdf(d1) - 1;
  const gamma = normPdf(d1) / (S * sigma * sqrtT);
  const vega = S * normPdf(d1) * sqrtT; // per 1 vol point (percentage 1 = 100%)
  const theta =
    -(
      (S * normPdf(d1) * sigma) /
      (2 * sqrtT)
    ) - r * K * Math.exp(-r * t) * (optionType === "call" ? normCdf(d2) : normCdf(-d2));
  const rho = optionType === "call" ? K * t * Math.exp(-r * t) * normCdf(d2) : -K * t * Math.exp(-r * t) * normCdf(-d2);

  return {
    delta,
    gamma,
    vega: vega / 100, // often quoted per 1% change, so divide by 100
    theta,
    rho,
  };
}

// --- Implied volatility (Newton-Raphson) ---
function impliedVol(marketPrice, S, K, r, t, optionType) {
  if (marketPrice <= 0) return 0;
  let sigma = 0.25; // initial guess
  for (let i = 0; i < 60; i++) {
    const price = blackScholesPrice(S, K, r, sigma, t, optionType);
    const diff = price - marketPrice;
    if (Math.abs(diff) < 1e-6) return sigma;
    // Vega (derivative of price wrt sigma)
    const sqrtT = Math.sqrt(Math.max(t, 1e-10));
    const d1 = (Math.log(S / K) + (r + (sigma * sigma) / 2) * t) / (sigma * sqrtT);
    const vega = S * normPdf(d1) * sqrtT;
    if (vega === 0) break;
    sigma = sigma - diff / vega;
    if (sigma <= 0) sigma = 1e-4;
    if (sigma > 5) sigma = 5;
  }
  return sigma;
}

// --- Option chain builder (best-effort using searchScrip) ---
// Note: Angel SmartAPI does not expose a documented single 'optionChain' REST in every account;
// here we do a best-effort: use smartSearch to fetch instrument master and filter option symbols.
// This is safe and non-destructive. If your environment exposes a direct option chain endpoint, you can
// replace this easily by adjusting SMARTAPI_BASE and endpoint.
async function getOptionChain(market, expiryDateStr) {
  // returns array of { tradingsymbol, instrumenttype, strike, optionType, symboltoken, expirydate }
  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };

  const cfg = FUTURE_RULES[market] ? FUTURE_RULES[market].searchSymbol : market.toUpperCase();
  const all = await smartSearch(cfg);
  if (!all || !all.length) return { ok: false, reason: "NO_INSTRUMENTS" };

  // filter option instruments with expiry matching (if given)
  const out = [];
  for (const it of all) {
    const sym = (it.tradingsymbol || "").toString();
    const instType = (it.instrumenttype || "").toUpperCase();
    const expiry = it.expirydate || "";
    // Heuristic: options often have CE/PE in symbol; instrumenttype may contain 'OPT'
    if (!sym) continue;
    if (!instType.includes("OPT") && !/CE|PE/.test(sym.toUpperCase())) continue;
    if (expiryDateStr && !expiry.includes(expiryDateStr)) continue;
    // try parse strike and type
    const match = sym.match(/(\d+)(CE|PE)$/i);
    let strike = null;
    let optionType = null;
    if (match) {
      strike = Number(match[1]);
      optionType = match[2].toUpperCase() === "CE" ? "call" : "put";
    } else {
      // fallback: if tradingsymbol ends with C/P convention or contains CE/PE
      if (sym.toUpperCase().includes("CE")) optionType = "call";
      if (sym.toUpperCase().includes("PE")) optionType = "put";
    }
    out.push({
      tradingsymbol: sym,
      instrumenttype: instType,
      strike: strike,
      optionType,
      symboltoken: it.symboltoken,
      expirydate: expiry,
    });
  }

  if (!out.length) return { ok: false, reason: "NO_OPTIONS_FOUND" };
  return { ok: true, chain: out };
}

// --- Premium engine: given legs, compute cost, P/L matrix at price points ---
/*
 legs = [
   { type: 'call'|'put', strike: 18200, qty: 1, side: 'buy'|'sell', price: 120 },
   ...
 ]
 options: quantity positive for buy, negative for sell (or use side)
*/
function computePremiumEngine(legs, spotRangeArray, r = 0.06, daysToExpiry = 7) {
  const t = Math.max(1e-6, daysToExpiry / 365);
  const out = {
    legs: [],
    totalCost: 0,
    payoff: [], // array aligned with spotRangeArray
  };

  // cost
  let total = 0;
  for (const L of legs) {
    const lcost = (L.price || 0) * (L.qty || 1) * (L.side === "sell" ? -1 : 1);
    total += lcost;
    out.legs.push(Object.assign({}, L, { cost: lcost }));
  }
  out.totalCost = total;

  // payoff per spot
  for (const S of spotRangeArray) {
    let val = 0;
    for (const L of legs) {
      const sign = L.side === "sell" ? -1 : 1;
      if (L.type === "call") {
        val += sign * Math.max(0, S - L.strike) * (L.qty || 1);
      } else if (L.type === "put") {
        val += sign * Math.max(0, L.strike - S) * (L.qty || 1);
      } else {
        // if it's already a premium-only leg like "STRADDLE" use price-based payoff (approx)
        val += sign * ((L.price || 0) * (L.qty || 1));
      }
    }
    // subtract premium paid
    out.payoff.push({ spot: S, pnl: Math.round((val - total) * 100) / 100 });
  }

  return out;
}

// --- WS LTP + HTTP fallback ---
// Safe init: uses process.env.SMARTAPI_WS_URL if provided; otherwise runs only HTTP poll fallback.
// The WS implementation is optional and non-blocking.
const WebSocket = require("ws");
let wsClient = null;
let wsConnected = false;
let latestLtp = null;
let wsReconnectTimer = null;

function startWsLtp(market = "nifty", pollIntervalMs = 5000) {
  // If feed token exists and WS URL provided, attempt WS connect
  const wsUrl = process.env.SMARTAPI_WS_URL || ""; // set this in env if you have a WS endpoint
  if (!wsUrl || !session.feed_token) {
    console.log("WS LTP: WS URL or feed token not provided - using HTTP polling fallback");
    // start HTTP poll fallback only
    startHttpPollFallback(market, pollIntervalMs);
    return;
  }

  try {
    wsClient = new WebSocket(wsUrl, {
      headers: {
        "Authorization": `Bearer ${session.access_token}`,
        "X-Client-FeedToken": session.feed_token,
        "X-PrivateKey": SMART_API_KEY,
      },
    });

    wsClient.on("open", () => {
      wsConnected = true;
      console.log("WS LTP: Connected to feed");
      // Subscribe format depends on provider. We will try a safe subscribe if feed requires.
      // If your SmartAPI feed requires a specific subscribe payload, set env SMARTAPI_WS_SUBSCRIBE_JSON
      const sub = process.env.SMARTAPI_WS_SUBSCRIBE_JSON;
      if (sub) {
        try {
          const payload = JSON.parse(sub);
          wsClient.send(JSON.stringify(payload));
        } catch (e) {
          console.log("WS LTP: invalid SMARTAPI_WS_SUBSCRIBE_JSON", e.message);
        }
      }
    });

    wsClient.on("message", (data) => {
      try {
        const msg = typeof data === "string" ? JSON.parse(data) : data;
        // Best-effort: try to extract LTP
        if (msg && msg.data) {
          // msg.data could be array or object
          if (Array.isArray(msg.data) && msg.data[0] && msg.data[0].ltp) {
            latestLtp = num(msg.data[0].ltp);
          } else if (msg.data.ltp) {
            latestLtp = num(msg.data.ltp);
          }
        } else if (msg && msg.ltp) {
          latestLtp = num(msg.ltp);
        }
      } catch (e) {
        // ignore parse errors
      }
    });

    wsClient.on("close", () => {
      wsConnected = false;
      console.log("WS LTP: Disconnected. Falling back to HTTP poll");
      // fallback
      startHttpPollFallback(market, pollIntervalMs);
      // try reconnect with backoff
      if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
      wsReconnectTimer = setTimeout(() => startWsLtp(market, pollIntervalMs), 5000);
    });

    wsClient.on("error", (err) => {
      console.log("WS LTP: error", err.message || err);
      wsClient.close();
    });
  } catch (err) {
    console.log("WS LTP: exception starting WS:", err.message);
    startHttpPollFallback(market, pollIntervalMs);
  }
}

let pollIntervalHandle = null;
function startHttpPollFallback(market = "nifty", pollIntervalMs = 5000) {
  if (pollIntervalHandle) return;
  // immediate fetch once
  (async () => {
    const r = await getAutoFutureLTP(market);
    if (r && r.ok && r.ltp) {
      latestLtp = num(r.ltp);
    }
  })();

  pollIntervalHandle = setInterval(async () => {
    const r = await getAutoFutureLTP(market);
    if (r && r.ok && r.ltp) {
      latestLtp = num(r.ltp);
    }
  }, pollIntervalMs);
}

// --- Public helper: getLatestLtp safely ---
function getLatestLtp() {
  return latestLtp;
}

// --- API endpoints for new features ---

// Option chain route
app.get("/api/option/chain", async (req, res) => {
  const market = (req.query.market || "nifty").toLowerCase();
  const expiry = req.query.expiry || ""; // format yyyy-mm-dd optionally
  const r = await getOptionChain(market, expiry);
  if (!r.ok) {
    return res.json({ success: false, error: r.reason || "NO_DATA", detail: r });
  }
  res.json({ success: true, chain: r.chain });
});

// Greeks route: expects JSON body { spot, strike, type: 'call'|'put', days_to_expiry, premium(optional) }
app.post("/api/option/greeks", express.json(), (req, res) => {
  try {
    const body = req.body || {};
    const S = num(body.spot, 0);
    const K = num(body.strike, 0);
    const type = (body.type || "call").toLowerCase();
    const days = Math.max(0, num(body.days_to_expiry, 7));
    const t = Math.max(1e-6, days / 365);
    const r = num(body.risk_free_rate, 0.06);
    const premium = body.premium != null ? num(body.premium, 0) : null;

    let iv = null;
    let bsPrice = null;
    if (premium && premium > 0) {
      iv = impliedVol(premium, S, K, r, t, type);
      bsPrice = blackScholesPrice(S, K, r, iv, t, type);
    } else {
      // fallback iv guess
      iv = 0.25;
      bsPrice = blackScholesPrice(S, K, r, iv, t, type);
    }

    const greeks = blackScholesGreeks(S, K, r, iv, t, type);

    res.json({
      success: true,
      input: { S, K, type, days, r, premium },
      bs: { price: bsPrice, iv },
      greeks,
    });
  } catch (err) {
    res.json({ success: false, error: err.message || String(err) });
  }
});
// Premium engine endpoint
app.post("/api/option/premium", express.json(), (req, res) => {
  try {
    // legs: array of { type:'call'|'put', strike, qty, side:'buy'|'sell', price }
    const legs = Array.isArray(req.body.legs) ? req.body.legs : [];
    const spots = Array.isArray(req.body.spots) && req.body.spots.length
      ? req.body.spots
      : (() => {
          // default spot range around current latestLtp or provided spot
          const base = num(req.body.spot, getLatestLtp() || 0);
          const step = Math.max(10, Math.round(base * 0.01));
          const arr = [];
          for (let i = -5; i <= 5; i++) arr.push(Math.max(0, base + i * step));
          return arr;
        })();

    const days = Math.max(0, num(req.body.days_to_expiry, 7));
    const r = num(req.body.risk_free_rate, 0.06);

    const out = computePremiumEngine(legs, spots, r, days);
    res.json({ success: true, result: out });
  } catch (err) {
    res.json({ success: false, error: err.message || String(err) });
  }
});

// LTP latest route (gives best known LTP from WS or HTTP fallback)
app.get("/api/ltp/latest", (req, res) => {
  res.json({ success: true, ltp: getLatestLtp(), ws_connected: wsConnected });
});

// -----------------------------------------------------
// Main /api/calc (existing) - unchanged but left here for continuity
// -----------------------------------------------------
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body || {});

    let usedLive = false;
    let liveLtp = null;
    let liveErr = null;

    if (input.use_live) {
      const r = await getAutoFutureLTP(input.market);
      if (r.ok && r.ltp) {
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
    res.json({
      success: false,
      error: err.message || String(err),
    });
  }
});

// -----------------------------------------------------
// SPA fallback
// -----------------------------------------------------
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// -----------------------------------------------------
// Init function to start optional features without breaking existing flow
// -----------------------------------------------------
function initOptionFeatures(appRef) {
  // Start HTTP polling fallback (safe) if configured
  // Use MARKET 'nifty' by default; can be overridden by env OPT_FEATURE_MARKET
  const optMarket = (process.env.OPT_FEATURE_MARKET || "nifty").toLowerCase();
  const pollMs = Math.max(2000, parseInt(process.env.OPT_FEATURE_POLL_MS || "5000"));
  startWsLtp(optMarket, pollMs);
  console.log("Option features initialized (market:", optMarket, "pollMs:", pollMs, ")");
}

// -----------------------------------------------------
// Start server
// -----------------------------------------------------
const PORT = process.env.PORT || 10000;

// initialize option features (safe - won't throw if env missing)
initOptionFeatures(app);

app.listen(PORT, () => {
  console.log("SERVER running on port " + PORT);
});
