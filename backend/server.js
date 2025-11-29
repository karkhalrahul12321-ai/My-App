// =====================================
// Trading Helper Backend (STABLE VERSION)
// SmartAPI Login V2 + Refresh Token + Auto Future Token + Trend Engine
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

// SESSION TOKENS
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// =====================================
// HELPERS — TOTP
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
// REFRESH TOKEN FUNCTION (NEWLY ADDED)
// =====================================
async function refreshAccessToken() {
  if (!session.refresh_token) {
    return { ok: false, reason: "NO_REFRESH_TOKEN" };
  }

  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/refreshToken`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-PrivateKey": SMART_API_KEY,
        },
        body: JSON.stringify({
          refreshToken: session.refresh_token,
          clientcode: SMART_USER_ID,
        }),
      }
    );

    const data = await resp.json();
    if (!data || data.status === false) {
      return { ok: false, reason: "REFRESH_FAILED", raw: data };
    }

    session.access_token = data.data.jwtToken;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
// SMARTAPI LOGIN (NOW v2)
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
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v2/loginByPassword`,
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

    const data = await resp.json();

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
  const password = req.body?.password || "";
  const r = await smartApiLogin(password);

  if (!r.ok) {
    return res.json({
      success: false,
      error: r.reason || "Login failed",
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

// SETTINGS
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || "",
  });
});

// =====================================
// UTIL
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
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(
    2,
    "0"
  )}-${String(d.getDate()).padStart(2, "0")}`;
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

// =====================================
// AUTO FUTURE TOKEN STORE
// =====================================
const AUTO = {
  nifty: { symbol: null, token: null, expiry: null },
  sensex: { symbol: null, token: null, expiry: null },
  "natural gas": { symbol: null, token: null, expiry: null },
};

// =====================================
// SMARTAPI SEARCH (with auto-refresh)
// =====================================
async function smartSearch(keyword) {
  if (!session.access_token) return [];

  if (session.expires_at < Date.now()) {
    await refreshAccessToken();
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
        body: JSON.stringify({ searchtext: keyword }),
      }
    );

    const data = await resp.json();
    return data?.data || [];
  } catch {
    return [];
  }
}

// =====================================
// AUTO FETCH FUTURE TOKEN
// =====================================
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  const expiries = getNextExpiries(market);
  const all = await smartSearch(rule.searchSymbol);
  if (!all.length) return null;

  for (const exp of expiries) {
    const [y, m, d] = exp.split("-");
    const match = all.find((x) => {
      return (
        x.exch_seg === rule.exchange &&
        x.instrumenttype === rule.instrumentType &&
        typeof x.expirydate === "string" &&
        x.expirydate.includes(`${y}-${m}-${d}`)
      );
    });

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
// LTP FETCH WITH AUTO REFRESH
// =====================================
async function getAutoFutureLTP(market) {
  if (session.expires_at < Date.now()) {
    await refreshAccessToken();
  }

  let auto = AUTO[market];
  if (!auto.symbol || !auto.token) {
    auto = await autoFetchFuture(market);
    if (!auto) {
      return { ok: false, reason: "TOKEN_NOT_FOUND" };
    }
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
          exchange: FUTURE_RULES[market].exchange,
          tradingsymbol: auto.symbol,
          symboltoken: auto.token,
        }),
      }
    );

    const data = await resp.json();
    if (!data || data.status === false) {
      return { ok: false, reason: "LTP_FAILED", detail: data };
    }

    return { ok: true, ltp: data.data.ltp };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
// AUTO DETECT MARKET
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

function autoDetectMarket(spot, raw) {
  const m = (raw || "").toLowerCase();
  if (MARKET_CONFIG[m]) return m;

  spot = num(spot);
  if (spot > 20 && spot < 2000) return "natural gas";
  if (spot >= 10000 && spot < 40000) return "nifty";
  if (spot >= 40000) return "sensex";
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

  const emaMid = (ema20 + ema50) / 2;
  const emaDiff = ema20 - ema50;
  const emaPct = (emaDiff / emaMid) * 100;
  let emaScore = clamp(emaPct * 1.5, -25, 25);

  let rsiScore = clamp((rsi - 50) * 1.2, -25, 25);

  const vwapDiff = spot - vwap;
  const vwapPct = (vwapDiff / vwap) * 100;
  let vwapScore = clamp(vwapPct * 1.5, -20, 20);

  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) structScore = 10;
  else if (spot < ema20 && ema20 < ema50) structScore = -10;

  const d = num(input.expiry_days);
  let expiryAdj = 0;
  if (d <= 2) expiryAdj = -5;
  else if (d >= 10) expiryAdj = 3;

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
  if (score >= 60) {
    main = "UPTREND";
    bias = "CE";
  }
  if (score <= 40) {
    main = "DOWNTREND";
    bias = "PE";
  }

  return {
    main,
    strength,
    score,
    bias,
    components: comp,
  };
}

// =====================================
// STRIKE ENGINE
// =====================================
function scaleDistancesByExpiry(expiryDays, baseDistances, step) {
  const d = Math.max(0, num(expiryDays, 7));
  let factor = 0.2 + 0.05 * d;
  if (factor > 1) factor = 1;

  const out = {};
  for (const k in baseDistances) {
    let v = baseDistances[k] * factor;
    if (v < step / 2) v = step / 2;
    out[k] = v;
  }
  return out;
}

function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const atm = roundToStep(input.spot, cfg.strikeStep);

  const scaled = scaleDistancesByExpiry(
    input.expiry_days,
    cfg.baseDistances,
    cfg.strikeStep
  );

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

  function make(strike, type, diff) {
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
    make(ceStrike, "CE", ceStrike - input.spot),
    make(peStrike, "PE", peStrike - input.spot),
    make(atm, "STRADDLE", atm - input.spot),
  ];
}

// =====================================
// MAIN /api/calc
// =====================================
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);

    let usedLive = false;

    if (input.use_live) {
      const r = await getAutoFutureLTP(input.market);
      if (r.ok) {
        input.spot = num(r.ltp);
        usedLive = true;
      }
    }

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
      auto_tokens: AUTO,
      meta: {
        live_data_used: usedLive,
      },
    });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
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
  console.log("SERVER running on port " + PORT);
});
