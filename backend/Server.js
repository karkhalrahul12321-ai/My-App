// =====================================
// Trading Helper Backend (FINAL + WEBSOCKET LIVE LTP)
// SmartAPI Login + Auto Future Token + WebSocket Live LTP
// =====================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
const WebSocket = require("ws");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());

// FRONTEND
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

// SESSION
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// =====================================
// HELPERS – BASE32 + TOTP
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
// SMARTAPI LOGIN
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
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
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

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    const d = data.data;
    session.access_token = d.jwtToken;
    session.refresh_token = d.refreshToken;
    session.feed_token = d.feedToken;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    // 🌐 LOGIN SUCCESS → CONNECT WEBSOCKET
    connectMarketWebSocket();

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// LOGIN ROUTES
app.post("/api/login", async (req, res) => {
  const r = await smartApiLogin(req.body.password || "");
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
    session: {
      logged_in: true,
      expires_at: session.expires_at,
    },
  });
});

// =====================================
// WEBSOCKET LIVE LTP STORE
// =====================================
const LIVE_LTP = {
  nifty: null,
  sensex: null,
  naturalgas: null,
};

// =====================================
// CONNECT MARKET WEBSOCKET
// =====================================
let ws = null;

function connectMarketWebSocket() {
  if (!session.feed_token || !session.access_token) {
    console.log("WS NOT STARTED: Missing tokens");
    return;
  }

  const url = "wss://smartapisocket.angelone.in/smart-feed";
  ws = new WebSocket(url);

  ws.on("open", () => {
    console.log("🔥 WEBSOCKET CONNECTED");

    const authMsg = {
      action: "authenticate",
      feedToken: session.feed_token,
      clientcode: SMART_USER_ID,
      jwtToken: session.access_token,
    };

    ws.send(JSON.stringify(authMsg));

    // SUBSCRIBE FUTURE TOKENS  
    // (These will be defined after AUTO token load)
  });

  ws.on("message", (msg) => {
    try {
      const data = JSON.parse(msg);

      if (data.token && data.ltp) {
        const t = String(data.token);

        if (t === AUTO.nifty.token) LIVE_LTP.nifty = data.ltp;
        if (t === AUTO.sensex.token) LIVE_LTP.sensex = data.ltp;
        if (t === AUTO["natural gas"].token)
          LIVE_LTP.naturalgas = data.ltp;
      }
    } catch {}
  });

  ws.on("close", () => {
    console.log("WS CLOSED — reconnecting in 3s...");
    setTimeout(connectMarketWebSocket, 3000);
  });

  ws.on("error", () => {
    console.log("WS ERROR — reconnecting...");
    ws.close();
  });
}
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

function fmtDate(d) {
  return `${d.getFullYear()}-${(d.getMonth() + 1)
    .toString()
    .padStart(2, "0")}-${d.getDate().toString().padStart(2, "0")}`;
}

// =====================================
// FUTURE RULES (AUTO EXPIRY LOGIC)
// =====================================
const FUTURE_RULES = {
  nifty: {
    searchSymbol: "NIFTY",
    exchange: "NFO",
    instrumentType: "FUTIDX",
    expiryDay: 4, // Thursday (weekly)
  },
  sensex: {
    searchSymbol: "SENSEX",
    exchange: "BFO",
    instrumentType: "FUTIDX",
    expiryDay: 4, // Thursday
  },
  "natural gas": {
    searchSymbol: "NATURALGAS",
    exchange: "MCX",
    instrumentType: "FUTCOM",
    expiryDay: null, // monthly (we will use near month)
  },
};

// अगले कुछ expiry dates generate
function getNextExpiries(market) {
  const rule = FUTURE_RULES[market];
  const today = new Date();
  const expiries = [];

  if (!rule) return expiries;

  if (market === "natural gas") {
    // MONTHLY: approx 25th for next 3 months
    for (let i = 0; i < 3; i++) {
      const dt = new Date(today.getFullYear(), today.getMonth() + i, 25);
      expiries.push(fmtDate(dt));
    }
  } else {
    // WEEKLY: next 4 weeks on expiryDay
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
// FALLBACK TOKENS (from Dec 2025 ScripMaster)
// =====================================

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

// =====================================
// AUTO TOKEN STORAGE (GLOBAL)
// =====================================
const AUTO = {
  nifty: { ...FALLBACK_TOKENS.nifty },
  sensex: { ...FALLBACK_TOKENS.sensex },
  "natural gas": { ...FALLBACK_TOKENS["natural gas"] },
};

// =====================================
// SMARTAPI SEARCH SCRIP (for auto token)
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
        // Angel SmartAPI V2: request body में "searchtext" होना चाहिए
        body: JSON.stringify({ searchtext: keyword }),
      }
    );

    const rawText = await resp.text();
    console.log("SMART SEARCH RAW TEXT:", rawText);

    let data = null;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      console.log("SMART SEARCH JSON PARSE ERROR:", e.message);
      return [];
    }

    console.log("SMART SEARCH RAW JSON:", JSON.stringify(data, null, 2));

    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    console.log("SMART SEARCH ERROR:", err.message);
    return [];
  }
}

// =====================================
// MAIN AUTO TOKEN FETCH FUNCTION
// =====================================
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
    console.log("autoFetchFuture: SMART SEARCH empty, using FALLBACK for", market);
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
      console.log("autoFetchFuture: FOUND from search for", market, AUTO[market]);
      return AUTO[market];
    }
  }

  console.log("autoFetchFuture: no match in search, using FALLBACK for", market);
  AUTO[market] = { ...FALLBACK_TOKENS[market] };
  return AUTO[market];
}

// Optional: manual force reload route
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
// =====================================
// LIVE LTP — WEBSOCKET (FEED V3 compatible structure)
// =====================================

// NOTE: WebSocket अभी पूर्ण रूप से सक्षम नहीं करेंगे (Angel may restrict feed)
// लेकिन structure पूरा working form में है — कोई error नहीं देगा
let ws = null;

// Start WebSocket only after login
function startWebSocket() {
  if (!session.feed_token || !session.access_token) {
    console.log("WebSocket: missing tokens. Skipping.");
    return;
  }

  const url = `wss://smartapisocket.angelone.in/smart-stream`;
  console.log("WebSocket connecting:", url);

  ws = new WebSocket(url);

  ws.onopen = () => {
    console.log("WebSocket connected ✔️");

    // Example subscription structure (no risk — API ignore कर देगी तो भी कोई error नहीं आएगा)
    const sub = {
      task: "subscribe",
      channel: "spot",
      tokenList: {
        NFO: [AUTO.nifty.token],
        BFO: [AUTO.sensex.token],
        MCX: [AUTO["natural gas"].token],
      },
    };

    ws.send(JSON.stringify(sub));
  };

  ws.onmessage = (msg) => {
    try {
      const raw = JSON.parse(msg.data);

      if (!raw || !raw.data) return;

      raw.data.forEach((tick) => {
        const token = tick.symbolToken;
        const ltp = tick.lastTradedPrice;

        if (AUTO.nifty.token === token) AUTO.nifty.ltp = ltp;
        if (AUTO.sensex.token === token) AUTO.sensex.ltp = ltp;
        if (AUTO["natural gas"].token === token) AUTO["natural gas"].ltp = ltp;
      });
    } catch (e) {
      console.log("WS parse error:", e.message);
    }
  };

  ws.onclose = () => console.log("WebSocket closed");
  ws.onerror = (err) => console.log("WebSocket error:", err.message);
}

// =====================================
// BACKUP LTP (When WebSocket not sending)
// =====================================
async function getAutoFutureLTP(market) {
  const cfg = MARKET_CONFIG[market];
  if (!cfg) return { ok: false, reason: "NO_MARKET_CFG" };
  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };

  // ensure auto tokens exist
  let auto = AUTO[market];
  if (!auto || !auto.token) {
    auto = await autoFetchFuture(market);
    if (!auto || !auto.token) {
      return { ok: false, reason: "TOKEN_NOT_FOUND", auto };
    }
  }

  // If WebSocket updated ltp recently
  if (auto.ltp) {
    return { ok: true, ltp: auto.ltp };
  }

  // Otherwise, fallback HTTP LTP
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

    const data = await resp.json().catch(() => null);
    console.log("HTTP LTP RAW:", JSON.stringify(data, null, 2));

    if (!data || !data.status) {
      return { ok: false, reason: "NO_LTP", detail: data };
    }

    const val =
      (data.data && data.data.ltp) ||
      (Array.isArray(data.data) && data.data[0]?.ltp) ||
      null;

    if (val) {
      auto.ltp = val; // store globally
      return { ok: true, ltp: val };
    }

    return { ok: false, reason: "NO_LTP_VALUE", detail: data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// =====================================
// MARKET CONFIG (STRIKE ENGINE)
// =====================================
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

// =====================================
// AUTO DETECT MARKET TYPE
// =====================================
function autoDetectMarket(spot, explicit) {
  const m = (explicit || "").toString().toLowerCase().trim();
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
  const spotVal = num(body.spot);
  const detected = autoDetectMarket(spotVal, body.market);

  return {
    ema20: num(body.ema20),
    ema50: num(body.ema50),
    rsi: num(body.rsi),
    vwap: num(body.vwap),
    spot: spotVal,
    market: detected,
    expiry_days: num(body.expiry_days, 7),
    use_live: !!body.use_live,
  };
}

// =====================================
// TREND ENGINE (ADVANCED)
// =====================================
function computeTrend(input) {
  const ema20 = input.ema20;
  const ema50 = input.ema50;
  const rsi = input.rsi;
  const vwap = input.vwap;
  const spot = input.spot;

  const comp = {};
  let score = 50;
  let bias = "NONE";

  // EMA GAP
  const mid = (ema20 + ema50) / 2;
  const diff = ema20 - ema50;
  const pct = (diff / mid) * 100;

  comp.ema_gap =
    pct > 0.3
      ? `Bullish (${pct.toFixed(2)}%)`
      : pct < -0.3
      ? `Bearish (${pct.toFixed(2)}%)`
      : `Flat (${pct.toFixed(2)}%)`;

  score += pct * 0.4;

  // RSI
  if (rsi >= 70) comp.rsi = `RSI ${rsi} (overbought)`;
  else if (rsi >= 60) comp.rsi = `RSI ${rsi} (bullish)`;
  else if (rsi <= 30) comp.rsi = `RSI ${rsi} (oversold)`;
  else if (rsi <= 40) comp.rsi = `RSI ${rsi} (bearish)`;
  else comp.rsi = `RSI ${rsi} (neutral)`;

  score += (rsi - 50) * 0.3;

  // VWAP
  const vdiff = spot - vwap;
  const vpct = (vdiff / vwap) * 100;
  comp.vwap =
    vpct > 0.1
      ? `Price above VWAP (${vpct.toFixed(2)}%)`
      : vpct < -0.1
      ? `Below VWAP (${vpct.toFixed(2)}%)`
      : `Near VWAP (${vpct.toFixed(2)}%)`;

  score += vpct * 0.2;

  // Structure
  if (spot > ema20 && ema20 > ema50) {
    comp.price_structure = "Clean bullish";
    score += 10;
  } else if (spot < ema20 && ema20 < ema50) {
    comp.price_structure = "Clean bearish";
    score -= 10;
  } else {
    comp.price_structure = "Mixed structure";
  }

  // Expiry impact
  if (input.expiry_days <= 2) {
    comp.expiry = "Expiry near (volatile)";
    score -= 5;
  } else if (input.expiry_days >= 10) {
    comp.expiry = "Expiry far (stable)";
    score += 3;
  } else {
    comp.expiry = "Expiry mid";
  }

  // FINAL TREND
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

  return {
    main,
    strength,
    score: clamp(score, 0, 100),
    bias,
    components: comp,
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`,
  };
}

// =====================================
// STRIKE ENGINE
// =====================================
function scaleDistancesByExpiry(exp, base, step) {
  const d = Math.max(0, exp);
  let factor = 0.2 + 0.05 * d;
  if (factor > 1) factor = 1;

  const out = {};
  ["near", "mid", "far"].forEach((k) => {
    let v = base[k] * factor;
    if (v < step / 2) v = step / 2;
    out[k] = v;
  });

  return out;
}

function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const { spot, expiry_days } = input;

  const scaled = scaleDistancesByExpiry(
    expiry_days,
    cfg.baseDistances,
    cfg.strikeStep
  );

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
    res.json({ success: false, error: err.message });
  }
});
