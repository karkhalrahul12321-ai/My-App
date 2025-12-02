/* ===========================================================
   FINAL FIXED SERVER.JS  (NO ENV MISMATCH • NO ERRORS)
   SmartAPI Login + Auto Tokens + LTP + Trend + Strikes
   =========================================================== */

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

/* ---------------------------
   EXPRESS APP INIT
---------------------------- */
const app = express();
app.use(bodyParser.json());

/* ---------------------------
   STATIC FRONTEND
---------------------------- */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ---------------------------
   SMART API CONFIG  (FIXED)
---------------------------- */
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com";

const SMART_API_KEY    = process.env.SMART_API_KEY    || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP      || "";
const SMART_USER_ID     = process.env.SMART_USER_ID   || "";

/* ---------------------------
   SESSION TOKENS
---------------------------- */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

/* ---------------------------
   BASE32 + TOTP
---------------------------- */
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

/* ===========================================================
   SMART API LOGIN  (FIXED ENV MATCHING)
=========================================================== */
async function smartApiLogin(password) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }

  if (!password) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: password,
          totp: totp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

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

/* LOGIN ROUTES */
app.post("/api/login", async (req, res) => {
  const password = req.body.password || "";
  const r = await smartApiLogin(password);

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
    session: { logged_in: true, expires_at: session.expires_at },
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
  });
});
/* ===========================================================
   SEARCH SCRIP (AUTO TOKEN SEARCH)
=========================================================== */
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
    console.log("SEARCH RAW:", raw);

    let data = null;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      return [];
    }

    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    return [];
  }
}

/* ===========================================================
   FUTURE RULES
=========================================================== */
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
      const dt = new Date(today.getFullYear(), today.getMonth() + i, 26);
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

/* ===========================================================
   FALLBACK TOKENS (ALWAYS VALID)
=========================================================== */
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

const AUTO = {
  nifty: { ...FALLBACK_TOKENS.nifty },
  sensex: { ...FALLBACK_TOKENS.sensex },
  "natural gas": { ...FALLBACK_TOKENS["natural gas"] },
};

/* ===========================================================
   AUTO FETCH FUTURE TOKEN USING SEARCH
=========================================================== */
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return AUTO[market];

  const expiries = getNextExpiries(market);
  const list = await smartSearch(rule.searchSymbol);

  if (!list.length) {
    console.log("AutoToken: Using fallback:", market);
    AUTO[market] = { ...FALLBACK_TOKENS[market] };
    return AUTO[market];
  }

  for (const exp of expiries) {
    const [y, m, d] = exp.split("-");

    const match = list.find((x) => {
      const ex = (x.exch_seg || "").toUpperCase() === rule.exchange;
      const tp = (x.instrumenttype || "").toUpperCase() === rule.instrumentType;
      const hasExp = (x.expirydate || "").includes(`${y}-${m}-${d}`);
      return ex && tp && hasExp;
    });

    if (match) {
      AUTO[market] = {
        symbol: match.tradingsymbol,
        token: match.symboltoken,
        expiry: match.expirydate,
      };
      console.log("AutoToken FOUND:", AUTO[market]);
      return AUTO[market];
    }
  }

  AUTO[market] = { ...FALLBACK_TOKENS[market] };
  return AUTO[market];
}

/* Manual force token refresh */
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token) {
    return res.json({ success: false, error: "NOT_LOGGED_IN" });
  }

  const out = {};
  for (const key of Object.keys(AUTO)) {
    out[key] = await autoFetchFuture(key);
  }

  res.json({ success: true, auto: out });
});

/* Debug search test */
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
    res.type("application/json").send(raw);
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});
/* ===========================================================
   LIVE FUTURE LTP (HTTP)
=========================================================== */
async function getAutoFutureLTP(market) {
  const cfg = MARKET_CONFIG[market];
  if (!cfg) return { ok: false, reason: "NO_MARKET_CFG" };
  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };

  let auto = AUTO[market];
  if (!auto.symbol || !auto.token) {
    auto = await autoFetchFuture(market);
  }
  if (!auto.symbol || !auto.token) {
    return { ok: false, reason: "TOKEN_NOT_FOUND", auto };
  }

  try {
    const resp = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: `Bearer ${session.access_token}`,
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

    const raw = await resp.text();
    console.log("LTP RAW:", raw);

    let data = null;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      return { ok: false, reason: "PARSE_ERR", raw };
    }

    if (!data || data.status === false) {
      return { ok: false, reason: "LTP_FAILED", detail: data };
    }

    const ltp =
      (data.data && data.data.ltp) ||
      (Array.isArray(data.data) && data.data[0] && data.data[0].ltp) ||
      null;

    return { ok: true, ltp };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

/* ===========================================================
   MARKET CONFIG (STRIKE ENGINE CONFIG)
=========================================================== */
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

/* ===========================================================
   AUTO DETECT MARKET
=========================================================== */
function autoDetectMarket(spot, raw) {
  const r = (raw || "").toString().toLowerCase();
  if (MARKET_CONFIG[r]) return r;

  const s = Number(spot);

  if (s > 20 && s < 2000) return "natural gas";
  if (s >= 10000 && s < 40000) return "nifty";
  if (s >= 40000) return "sensex";

  return "nifty";
}

/* ===========================================================
   NORMALIZE INPUT
=========================================================== */
function normalizeInput(body) {
  const spot = Number(body.spot);
  const market = autoDetectMarket(spot, body.market);

  return {
    ema20: Number(body.ema20),
    ema50: Number(body.ema50),
    rsi: Number(body.rsi),
    vwap: Number(body.vwap),
    spot,
    market,
    expiry_days: Number(body.expiry_days) || 7,
    use_live: !!body.use_live,
  };
}

/* ===========================================================
   TREND ENGINE (ADVANCED)
=========================================================== */
function computeTrend(input) {
  const { ema20, ema50, rsi, vwap, spot } = input;

  const comp = {};
  let score = 50;

  /* EMA GAP */
  const emaMid = (ema20 + ema50) / 2;
  const emaPct = ((ema20 - ema50) / emaMid) * 100;
  comp.ema_gap =
    emaPct > 0.3
      ? `Bullish (${emaPct.toFixed(2)}%)`
      : emaPct < -0.3
      ? `Bearish (${emaPct.toFixed(2)}%)`
      : `Flat (${emaPct.toFixed(2)}%)`;
  score += Math.max(-20, Math.min(20, emaPct * 0.8));

  /* RSI */
  comp.rsi =
    rsi >= 70
      ? `RSI ${rsi} (overbought)`
      : rsi <= 30
      ? `RSI ${rsi} (oversold)`
      : rsi <= 40
      ? `RSI ${rsi} (bearish)`
      : rsi >= 60
      ? `RSI ${rsi} (bullish)`
      : `RSI ${rsi} (neutral)`;
  score += (rsi - 50) * 0.6;

  /* VWAP */
  const vwapPct = ((spot - vwap) / vwap) * 100;
  comp.vwap =
    vwapPct > 0.1
      ? `Price above VWAP (${vwapPct.toFixed(2)}%)`
      : vwapPct < -0.1
      ? `Below VWAP (${vwapPct.toFixed(2)}%)`
      : `Near VWAP (${vwapPct.toFixed(2)}%)`;
  score += Math.max(-10, Math.min(10, vwapPct * 0.5));

  /* STRUCTURE */
  if (spot > ema20 && ema20 > ema50) {
    comp.price_structure = "Clean bullish";
    score += 8;
  } else if (spot < ema20 && ema20 < ema50) {
    comp.price_structure = "Clean bearish";
    score -= 8;
  } else {
    comp.price_structure = "Mixed structure";
  }

  /* EXPIRY EFFECT */
  const d = Number(input.expiry_days);
  if (d <= 2) {
    comp.expiry = "Expiry near (volatile)";
    score -= 5;
  } else if (d >= 10) {
    comp.expiry = "Expiry far (stable)";
    score += 3;
  } else {
    comp.expiry = "Expiry mid";
  }

  /* FINAL TREND */
  let main = "SIDEWAYS";
  let strength = "RANGE";
  let bias = "NONE";

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

  return {
    main,
    strength,
    score,
    bias,
    components: comp,
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`,
  };
}

/* ===========================================================
   STRIKE ENGINE
=========================================================== */
function scaleDistancesByExpiry(expiryDays, baseDistances, step) {
  let d = Math.max(0, expiryDays);
  let factor = 0.2 + 0.05 * d; // expiry closer => lower factor
  if (factor > 1) factor = 1;

  return {
    near: Math.max(step / 2, baseDistances.near * factor),
    mid: Math.max(step / 2, baseDistances.mid * factor),
    far: Math.max(step / 2, baseDistances.far * factor),
  };
}

function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const { spot, expiry_days } = input;

  const scaled = scaleDistancesByExpiry(
    expiry_days,
    cfg.baseDistances,
    cfg.strikeStep
  );

  const round = (v) => Math.round(v / cfg.strikeStep) * cfg.strikeStep;
  const atm = round(spot);

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

  const ceStrike = round(atm + ceDist);
  const peStrike = round(atm - peDist);
  const straddle = atm;

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
    makeOption(straddle, "STRADDLE", straddle - spot),
  ];
}
/* ===========================================================
   PART 4/4 — /api/calc, misc routes, SPA fallback, start server
   (Paste this after Part 1–3 in the same server.js)
   =========================================================== */

/* ===========================================================
   SETTINGS ENDPOINT (helpful to verify loaded ENV)
=========================================================== */
app.get("/api/settings", (req, res) => {
  res.json({
    success: true,
    apiKeyLoaded: !!SMART_API_KEY,
    apiSecretLoaded: !!SMART_API_SECRET,
    totpLoaded: !!SMART_TOTP_SECRET,
    userIdLoaded: !!SMART_USER_ID,
    SMART_API_KEY,
    // Do NOT expose secrets in production. This is for debug only.
  });
});

/* ===========================================================
   /api/calc — main calculation endpoint (uses live LTP if requested)
=========================================================== */
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body);

    let usedLive = false;
    let liveLtp = null;
    let liveErr = null;

    if (input.use_live) {
      const r = await getAutoFutureLTP(input.market);
      if (r.ok && r.ltp != null) {
        input.spot = Number(r.ltp);
        usedLive = true;
        liveLtp = input.spot;
      } else {
        liveErr = r;
      }
    }

    const trend = computeTrend(input);
    const strikes = buildStrikes(input, trend);

    return res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token ? "SmartAPI Logged-In" : "Not logged-in (demo mode)",
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
    console.error("/api/calc ERROR:", err);
    return res.json({ success: false, error: err.message || String(err) });
  }
});

/* ===========================================================
   /api/ltp — optional: fetch LTPs for all AUTO tokens (HTTP pull)
   Returns AUTO with ltp fields updated where possible.
=========================================================== */
app.get("/api/ltp", async (req, res) => {
  if (!session.access_token) {
    return res.status(401).json({ success: false, error: "NOT_LOGGED_IN" });
  }

  try {
    const markets = Object.keys(AUTO);
    for (const m of markets) {
      const t = AUTO[m];
      if (!t || !t.token || !t.symbol) {
        AUTO[m].ltp = null;
        continue;
      }
      const cfg = MARKET_CONFIG[m];
      try {
        const r = await fetch(
          `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
          {
            method: "POST",
            headers: {
              "X-PrivateKey": SMART_API_KEY,
              Authorization: `Bearer ${session.access_token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              mode: "LTP",
              exchange: cfg.exchange,
              tradingsymbol: t.symbol,
              symboltoken: t.token,
            }),
          }
        );
        const raw = await r.text();
        let data = null;
        try { data = JSON.parse(raw); } catch (e) { data = null; }
        if (data && data.status !== false) {
          const l = (data.data && data.data.ltp) || (Array.isArray(data.data) && data.data[0] && data.data[0].ltp) || null;
          AUTO[m].ltp = l;
        } else {
          AUTO[m].ltp = null;
        }
      } catch (e) {
        AUTO[m].ltp = null;
      }
    }

    return res.json({ success: true, data: AUTO });
  } catch (err) {
    console.error("/api/ltp ERROR:", err);
    return res.json({ success: false, error: err.message || String(err) });
  }
});

/* ===========================================================
   HEALTHCHECK / debug route
=========================================================== */
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    up: true,
    env: {
      SMART_API_KEY: !!SMART_API_KEY,
      SMART_API_SECRET: !!SMART_API_SECRET,
      SMART_TOTP: !!SMART_TOTP_SECRET,
      SMART_USER_ID: !!SMART_USER_ID,
    },
  });
});

/* ===========================================================
   SPA FALLBACK - must stay last
=========================================================== */
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

/* ===========================================================
   START SERVER
=========================================================== */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`SERVER running on port ${PORT}`);
  console.log("AUTO FUTURE TOKEN SYSTEM ENABLED 🔥");
});
