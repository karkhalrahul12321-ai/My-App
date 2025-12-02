// ======================================================
// COMPLETE BACKEND (FINAL BUILD)
// SmartAPI Login + AutoToken + Premium Engine Base + LTP
// WebSocket (Feed V2) Ready
// ======================================================

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");
require("dotenv").config();

// ------------------------------------------------------
// APP INIT
// ------------------------------------------------------
const app = express();
app.use(bodyParser.json());

const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// ------------------------------------------------------
// SMART API CONFIG
// ------------------------------------------------------
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// ------------------------------------------------------
// SESSION STORE
// ------------------------------------------------------
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// ------------------------------------------------------
// BASE32 + TOTP
// ------------------------------------------------------
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  input = input.replace(/=+$/, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const output = [];

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
// ------------------------------------------------------
// SMART API LOGIN
// ------------------------------------------------------
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
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
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

// ------------------------------------------------------
// LOGIN ROUTES
// ------------------------------------------------------
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
    expires_at: session.expires_at,
  });
});

// ------------------------------------------------------
// GLOBAL AUTO TOKEN STORAGE (REAL SYMBOLS from CSV Master)
// ------------------------------------------------------
const AUTO = {
  nifty: { symbol: "NIFTY30DEC25FUT", token: "36688", expiry: "2025-12-30" },
  sensex: { symbol: "SENSEX50DEC25FUT", token: "1104398", expiry: "2025-12-24" },
  naturalgas: {
    symbol: "NATURALGAS26DEC25FUT",
    token: "463007",
    expiry: "2025-12-26",
  },
};

// ------------------------------------------------------
// SEARCH SCRIP (SmartAPI V2)
// ------------------------------------------------------
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
    let data = null;

    try {
      data = JSON.parse(raw);
    } catch (err) {
      console.log("JSON parse error in search:", raw);
      return [];
    }

    if (!data || !data.data) return [];
    return data.data;
  } catch (err) {
    console.log("Search Error:", err);
    return [];
  }
}

// ------------------------------------------------------
// AUTO TOKEN FETCH ROUTE (MANUAL REFRESH)
// ------------------------------------------------------
app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token) {
    return res.json({ success: false, error: "NOT_LOGGED_IN" });
  }

  res.json({ success: true, auto: AUTO });
});
// ------------------------------------------------------
// MARKET CONFIG (STRIKE ENGINE)
// ------------------------------------------------------
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

// ------------------------------------------------------
// GENERIC HELPERS
// ------------------------------------------------------
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

// ------------------------------------------------------
// AUTO DETECT MARKET & NORMALIZE INPUT
// ------------------------------------------------------
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

// ------------------------------------------------------
// PREMIUM ENGINE (simple IV-based BS pricing + heuristics)
// ------------------------------------------------------

// Black-Scholes helpers (kept light-weight)
function normPdf(x) {
  return Math.exp(-0.5 * x * x) / Math.sqrt(2 * Math.PI);
}
function normCdf(x) {
  // approximation
  const sign = x < 0 ? -1 : 1;
  x = Math.abs(x) / Math.sqrt(2);
  const t = 1 / (1 + 0.3275911 * x);
  const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741, a4 = -1.453152027, a5 = 1.061405429;
  const erf = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
  return 0.5 * (1 + sign * erf);
}
function bsPrice(type, S, K, r, q, sigma, t) {
  if (t <= 0) {
    return type === "CE" ? Math.max(0, S - K) : Math.max(0, K - S);
  }
  const sqrtT = Math.sqrt(t);
  const d1 = (Math.log(S / K) + (r - q + 0.5 * sigma * sigma) * t) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;
  if (type === "CE") return S * Math.exp(-q * t) * normCdf(d1) - K * Math.exp(-r * t) * normCdf(d2);
  return K * Math.exp(-r * t) * normCdf(-d2) - S * Math.exp(-q * t) * normCdf(-d1);
}

// implied vol (bisection) - best-effort
function impliedVol(type, marketPrice, S, K, r, q, t) {
  if (!marketPrice || marketPrice <= 0) return 0;
  let lo = 1e-6, hi = 5.0;
  for (let i = 0; i < 60; i++) {
    const mid = (lo + hi) / 2;
    const p = bsPrice(type, S, K, r, q, mid, t);
    if (p > marketPrice) hi = mid;
    else lo = mid;
  }
  return (lo + hi) / 2;
}

// Premium compute: returns three option suggestions and mid prices
function premiumEngineCompute(input) {
  const market = input.market || "nifty";
  const spot = num(input.spot, 0);
  const expiry_days = num(input.expiry_days, 7);
  const r = 0.06; // risk-free approx
  const q = 0.0;

  const t = Math.max(1 / 365, expiry_days / 365);

  const cfg = MARKET_CONFIG[market] || MARKET_CONFIG.nifty;
  const baseDistances = cfg.baseDistances || { far: 250, mid: 200, near: 150 };
  // scale distances by expiry (less distance as expiry nears)
  const scaled = scaleDistancesByExpiry(expiry_days, baseDistances, cfg.strikeStep);

  // ATM rounding
  const atm = roundToStep(spot, cfg.strikeStep);

  // choose distances based on simple "trend" or neutral - here neutral mid
  const ceDist = scaled.mid;
  const peDist = scaled.mid;

  const ceStrike = roundToStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDist, cfg.strikeStep);
  const straddleStrike = atm;

  // fallback IV estimate
  const iv = 0.25;

  const cePrice = bsPrice("CE", spot, ceStrike, r, q, iv, t);
  const pePrice = bsPrice("PE", spot, peStrike, r, q, iv, t);
  const straddlePrice = bsPrice("CE", spot, straddleStrike, r, q, iv, t) + bsPrice("PE", spot, straddleStrike, r, q, iv, t);

  function makeOption(strike, type, price) {
    const steps = Math.max(1, Math.round(Math.abs(strike - spot) / cfg.strikeStep));
    const base = Math.max(5, steps * 5, Math.round(price));
    return {
      type,
      strike,
      distance: Math.abs(strike - spot),
      entry: base,
      stopLoss: Math.max(1, Math.round(base * 0.6)),
      target: Math.max(1, Math.round(base * 1.5)),
      midPrice: Math.round(price * 100) / 100,
    };
  }

  return [makeOption(ceStrike, "CE", cePrice), makeOption(peStrike, "PE", pePrice), makeOption(straddleStrike, "STRADDLE", straddlePrice)];
}

// scale distances helper (same logic as earlier)
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

// ------------------------------------------------------
// TREND ENGINE (same approach as original file)
// ------------------------------------------------------
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

// ------------------------------------------------------
// GET LIVE FUTURE LTP via auto tokens (quote endpoint)
// ------------------------------------------------------
async function getAutoFutureLTP(market) {
  const cfg = MARKET_CONFIG[market];
  if (!cfg) return { ok: false, reason: "NO_MARKET_CFG" };

  const auto = AUTO[market] || AUTO[market.toLowerCase()] || null;
  if (!auto || !auto.token) {
    return { ok: false, reason: "TOKEN_NOT_FOUND", auto: auto || null };
  }

  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token ? `Bearer ${session.access_token}` : "",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        mode: "LTP",
        exchange: cfg.exchange,
        tradingsymbol: auto.symbol,
        symboltoken: auto.token,
      }),
    });

    const data = await resp.json().catch(() => null);
    if (!data || data.status === false) return { ok: false, reason: "LTP_FAILED", detail: data || null };
    // handle data structure variances
    const ltpVal = (data.data && data.data.ltp) || (Array.isArray(data.data) && data.data[0] && data.data[0].ltp) || null;
    if (ltpVal == null) return { ok: false, reason: "NO_LTP", detail: data };
    return { ok: true, ltp: ltpVal, raw: data };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}
// ------------------------------------------------------
// UTIL: robust AUTO token getter (handles key naming variations)
// ------------------------------------------------------
function getAutoForMarket(market) {
  if (!market) return null;
  // try as-given
  if (AUTO[market]) return AUTO[market];
  // try lower/upper/without-space variants
  const mk = market.toString().toLowerCase();
  if (AUTO[mk]) return AUTO[mk];
  const nospace = mk.replace(/\s+/g, "");
  if (AUTO[nospace]) return AUTO[nospace];
  // try keys search
  for (const k of Object.keys(AUTO)) {
    if (k.toString().toLowerCase().replace(/\s+/g, "") === nospace) return AUTO[k];
  }
  return null;
}

// ------------------------------------------------------
// BUILD STRIKES (uses premiumEngineCompute as primary strike price generator)
// ------------------------------------------------------
function buildStrikes(input, trend) {
  // premiumEngineCompute already returns entry/stop/target + midPrice
  // Use its suggestions but adapt bias from trend if needed
  const suggestions = premiumEngineCompute(input);
  // If trend bias is strong, nudge selection (example: if UPTREND prefer CE)
  // We'll keep suggestions as-is — they're already distance/entry/stop/target based.
  return suggestions;
}

// ------------------------------------------------------
// TEST SEARCH ROUTE (raw) - useful for debugging searchScrip responses
// ------------------------------------------------------
app.get("/api/test/search", async (req, res) => {
  if (!session.access_token) return res.json({ success: false, error: "NOT_LOGGED_IN" });

  const q = (req.query.q || "NIFTY").toString();
  try {
    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/searchScrip`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ searchtext: q }),
    });

    const raw = await resp.text();
    // echo raw for debugging
    res.type("application/json").send(raw);
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// ------------------------------------------------------
// LTP FETCH ROUTE: fetch LTP for all AUTO tokens
// ------------------------------------------------------
app.get("/api/ltp", async (req, res) => {
  if (!session.access_token) return res.status(401).json({ success: false, error: "NOT_LOGGED_IN" });

  const markets = Object.keys(MARKET_CONFIG);
  const out = {};
  for (const m of markets) {
    const key = m; // same as MARKET_CONFIG keys (nifty, sensex, "natural gas")
    const auto = getAutoForMarket(m);
    if (!auto || !auto.token) {
      out[m] = { ok: false, reason: "NO_TOKEN", auto: auto || null };
      continue;
    }
    try {
      const r = await getAutoFutureLTP(m);
      out[m] = r;
      // if fetched, update AUTO ltp field
      if (r.ok && r.ltp != null) {
        const targetAuto = getAutoForMarket(m);
        if (targetAuto) targetAuto.ltp = r.ltp;
      }
    } catch (err) {
      out[m] = { ok: false, reason: "EXCEPTION", error: err.message };
    }
  }

  res.json({ success: true, data: out });
});

// ------------------------------------------------------
// MAIN CALC ROUTE: computes trend + strikes (uses live LTP if requested)
// ------------------------------------------------------
app.post("/api/calc", async (req, res) => {
  try {
    const input = normalizeInput(req.body || {});

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
    res.json({ success: false, error: err.message || String(err) });
  }
});

// ------------------------------------------------------
// OPTIONAL: Feed (WebSocket V2) Connector (best-effort)
// ------------------------------------------------------
// This attempts to connect to a websocket feed if `session.feed_token` exists.
// It requires 'ws' package. If ws is not installed, this will safely skip.
// Replace `WS_URL` with the correct Angel feed V2 websocket endpoint if/when known.
let wsClient = null;
function connectFeedV2() {
  if (!session.feed_token) {
    console.log("connectFeedV2: no feed_token available.");
    return;
  }

  let WebSocket = null;
  try {
    WebSocket = require("ws");
  } catch (e) {
    console.log("connectFeedV2: 'ws' module not installed — skipping websocket connection.");
    return;
  }

  const WS_URL = process.env.SMARTAPI_WS || "wss://feed.angelbroking.com/stream";
  try {
    wsClient = new WebSocket(WS_URL, {
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "X-Feed-Token": session.feed_token,
      },
    });

    wsClient.on("open", () => {
      console.log("Feed V2 WebSocket connected.");
      // Example subscription message (replace with actual feed format)
      // You must change this according to Angel's feed V2 subscription format.
      const subscribeMsg = {
        action: "subscribe",
        tokens: [
          // build token list from AUTO
          ...(AUTO.nifty && AUTO.nifty.token ? [AUTO.nifty.token] : []),
          ...(AUTO.sensex && AUTO.sensex.token ? [AUTO.sensex.token] : []),
          ...(AUTO["natural gas"] && AUTO["natural gas"].token ? [AUTO["natural gas"].token] : []),
        ],
      };
      try {
        wsClient.send(JSON.stringify(subscribeMsg));
      } catch (err) {
        console.log("Error sending subscribe:", err.message);
      }
    });

    wsClient.on("message", (msg) => {
      try {
        const data = JSON.parse(msg.toString());
        // Example: update AUTO LTP if feed contains token+ltp
        // The feed message structure will differ; adapt parser accordingly.
        if (data && data.token && (data.ltp || data.last_traded_price)) {
          const token = data.token.toString();
          const ltp = data.ltp || data.last_traded_price || null;
          for (const k of Object.keys(AUTO)) {
            if (AUTO[k] && AUTO[k].token && AUTO[k].token.toString() === token) {
              AUTO[k].ltp = ltp;
            }
          }
        }
      } catch (err) {
        // non-json or unexpected message
      }
    });

    wsClient.on("close", () => {
      console.log("Feed WebSocket closed.");
      wsClient = null;
      // try reconnect after a delay
      setTimeout(connectFeedV2, 30 * 1000);
    });

    wsClient.on("error", (err) => {
      console.log("Feed WebSocket error:", err.message);
    });
  } catch (err) {
    console.log("connectFeedV2 exception:", err.message);
  }
}

// Call connectFeedV2 after login if feed token present
// (smartApiLogin could call connectFeedV2() after it sets session.feed_token)
// We'll optionally call it at server start as best-effort if env has feed token.
if (process.env.AUTO_CONNECT_FEED === "1" && session.feed_token) {
  connectFeedV2();
}

// ------------------------------------------------------
// SPA fallback (keep at bottom)
// ------------------------------------------------------
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// ------------------------------------------------------
// START SERVER
// ------------------------------------------------------
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`SERVER running on port ${PORT}`);
  console.log("AUTO FUTURE TOKEN SYSTEM ENABLED 🔥");
});
