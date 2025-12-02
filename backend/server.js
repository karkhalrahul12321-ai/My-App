// ======================================================
// COMPLETE BACKEND (LTP NEW-FORMAT FIX)
// SmartAPI Login + AutoToken + Premium Engine Base + LTP (exchangeTokens)
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
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

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
  input = (input || "").replace(/=+$/, "").toUpperCase();
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
    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false)
      return { ok: false, reason: "LOGIN_FAILED", raw: data };

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

// ------------------------------------------------------
// LOGIN ROUTES
// ------------------------------------------------------
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
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
    expires_at: session.expires_at || null,
  });
});

// ------------------------------------------------------
// SEARCH SCRIP (Angel requirement: searchtext)
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
        body: JSON.stringify({
          searchtext: keyword, // FIXED
        }),
      }
    );

    const raw = await resp.text();
    let json = null;
    try {
      json = JSON.parse(raw);
    } catch {
      console.log("SEARCH JSON PARSE FAIL:", raw);
      return [];
    }

    console.log("SEARCH RESULT:", JSON.stringify(json, null, 2));
    return (json.data || []);
  } catch (err) {
    console.log("SEARCH ERROR:", err.message);
    return [];
  }
}

// ------------------------------------------------------
// FUTURE RULES
// ------------------------------------------------------
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
  naturalgas: {
    searchSymbol: "NATURALGAS",
    exchange: "MCX",
    instrumentType: "FUTCOM",
    expiryDay: null, // monthly
  },
};

// ------------------------------------------------------
function fmtDate(d) {
  return `${d.getFullYear()}-${(d.getMonth() + 1)
    .toString()
    .padStart(2, "0")}-${d.getDate().toString().padStart(2, "0")}`;
}

function getNextExpiries(market) {
  const rule = FUTURE_RULES[market];
  const today = new Date();
  const arr = [];

  if (!rule) return arr;

  if (market === "naturalgas") {
    for (let i = 0; i < 3; i++) {
      const dt = new Date(today.getFullYear(), today.getMonth() + i, 25);
      arr.push(fmtDate(dt));
    }
  } else {
    for (let i = 0; i < 4; i++) {
      const dt = new Date();
      dt.setDate(today.getDate() + i * 7);
      while (dt.getDay() !== rule.expiryDay) dt.setDate(dt.getDate() + 1);
      arr.push(fmtDate(dt));
    }
  }

  return arr;
}

// ------------------------------------------------------
// AUTO TOKEN STORAGE + FALLBACK
// ------------------------------------------------------
const FALLBACK = {
  nifty: { symbol: "NIFTY30DEC25FUT", token: "36688", expiry: "2025-12-30" },
  sensex: { symbol: "SENSEX50DEC25FUT", token: "1104398", expiry: "2025-12-24" },
  naturalgas: { symbol: "NATURALGAS26DEC25FUT", token: "463007", expiry: "2025-12-26" },
};

const AUTO = {
  nifty: { ...FALLBACK.nifty },
  sensex: { ...FALLBACK.sensex },
  naturalgas: { ...FALLBACK.naturalgas },
};

// ------------------------------------------------------
// AUTO TOKEN FETCHER
// ------------------------------------------------------
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return AUTO[market];

  const expiries = getNextExpiries(market);
  const all = await smartSearch(rule.searchSymbol);

  if (!all.length) return AUTO[market] = { ...FALLBACK[market] };

  for (const exp of expiries) {
    const [y, m, d] = exp.split("-");
    const found = all.find((x) => {
      const seg = (x.exch_seg || "").toUpperCase();
      const type = (x.instrumenttype || "").toUpperCase();
      const e = (x.expirydate || "");
      return (
        seg === rule.exchange &&
        type === rule.instrumentType &&
        e.includes(`${y}-${m}-${d}`)
      );
    });

    if (found) {
      AUTO[market] = {
        symbol: found.tradingsymbol,
        token: found.symboltoken,
        expiry: found.expirydate,
      };
      return AUTO[market];
    }
  }

  return (AUTO[market] = { ...FALLBACK[market] });
}

app.get("/api/autofetch", async (req, res) => {
  if (!session.access_token) {
    return res.json({ success: false, error: "NOT_LOGGED_IN" });
  }

  for (const m of Object.keys(FUTURE_RULES)) {
    await autoFetchFuture(m);
  }

  res.json({ success: true, auto: AUTO });
});
// ------------------------------------------------------
// MID PRICE ENGINE (Premium Calculator)
// ------------------------------------------------------
async function fetchOptionPremium(exchange, symbol, token) {
  if (!session.access_token) return null;

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
          mode: "FULL",
          exchange: exchange,
          tradingsymbol: symbol,
          symboltoken: token,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || data.status === false) return null;

    const d = data.data || {};
    const bestBuy = d.best_buy_price || d.bidprice || null;
    const bestSell = d.best_sell_price || d.askprice || null;

    if (!bestBuy || !bestSell) return null;

    return (bestBuy + bestSell) / 2; // mid price
  } catch (err) {
    return null;
  }
}

// ------------------------------------------------------
// FUTURE LTP — NEW FORMAT FIX
// ------------------------------------------------------
async function getFutureLTP(market) {
  const cfg = FUTURE_RULES[market];
  if (!cfg) return { ok: false, reason: "NO_CFG" };

  const auto = AUTO[market];
  if (!auto || !auto.symbol || !auto.token)
    return { ok: false, reason: "NO_TOKEN" };

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

    const raw = await resp.json().catch(() => null);
    console.log("LTP RAW:", JSON.stringify(raw, null, 2));

    if (!raw || raw.status === false) {
      return { ok: false, reason: "LTP_FAILED", detail: raw };
    }

    const d = raw.data;
    const ltp =
      (d && d.ltp) ||
      (Array.isArray(d) && d[0] && d[0].ltp) ||
      null;

    if (!ltp) return { ok: false, reason: "NO_LTP", detail: raw };

    return { ok: true, ltp };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// ------------------------------------------------------
// TREND ENGINE
// ------------------------------------------------------
function computeTrend(input) {
  const ema20 = Number(input.ema20);
  const ema50 = Number(input.ema50);
  const rsi = Number(input.rsi);
  const vwap = Number(input.vwap);
  const spot = Number(input.spot);

  const comp = {};
  let score = 50;
  let bias = "NONE";

  // EMA Spread
  const emaMid = (ema20 + ema50) / 2;
  const emaPct = ((ema20 - ema50) / emaMid) * 100;
  comp.ema_gap =
    emaPct > 0.3
      ? `Bullish (${emaPct.toFixed(2)}%)`
      : emaPct < -0.3
      ? `Bearish (${emaPct.toFixed(2)}%)`
      : `Flat (${emaPct.toFixed(2)}%)`;
  score += emaPct * 0.3;

  // RSI
  if (rsi >= 70) comp.rsi = `RSI ${rsi} (overbought)`;
  else if (rsi <= 30) comp.rsi = `RSI ${rsi} (oversold)`;
  else if (rsi < 40) comp.rsi = `RSI ${rsi} (bearish)`;
  else comp.rsi = `RSI ${rsi} (neutral)`;
  score += (rsi - 50) * 0.2;

  // VWAP
  const vwapPct = ((spot - vwap) / vwap) * 100;
  comp.vwap =
    vwapPct > 0.1
      ? `Above VWAP (${vwapPct.toFixed(2)}%)`
      : vwapPct < -0.1
      ? `Below VWAP (${vwapPct.toFixed(2)}%)`
      : `Near VWAP (${vwapPct.toFixed(2)}%)`;
  score += vwapPct * 0.2;

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

  // Expiry effect
  const d = Number(input.expiry_days);
  if (d <= 2) {
    comp.expiry = "Expiry near (volatile)";
    score -= 7;
  } else if (d >= 10) {
    comp.expiry = "Expiry far (stable)";
    score += 4;
  } else {
    comp.expiry = "Expiry mid";
  }

  score = Math.max(0, Math.min(100, score));

  let main = "SIDEWAYS";
  let strength = "RANGE";

  if (score >= 75) {
    main = "UPTREND";
    strength = "STRONG";
    bias = "CE";
  } else if (score >= 60) {
    main = "UPTREND";
    strength = "MODERATE";
    bias = "CE";
  } else if (score <= 25) {
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

// ------------------------------------------------------
// STRIKE ENGINE (with Premium Engine midPrice)
// ------------------------------------------------------
const MARKET_CONFIG = {
  nifty: { strikeStep: 50, base: { far: 250, mid: 200, near: 150 }, exchange: "NFO" },
  sensex: { strikeStep: 100, base: { far: 500, mid: 400, near: 300 }, exchange: "BFO" },
  naturalgas: { strikeStep: 5, base: { far: 80, mid: 60, near: 50 }, exchange: "MCX" },
};

function roundStep(v, step) {
  return Math.round(v / step) * step;
}

function dynamicDistance(days, dist) {
  let factor = 0.2 + days * 0.05;
  if (factor > 1) factor = 1;
  return dist * factor;
}

async function buildStrikes(input, trend) {
  const cfg = MARKET_CONFIG[input.market];
  const spot = input.spot;
  const d = input.expiry_days;

  const scaled = {
    near: dynamicDistance(d, cfg.base.near),
    mid: dynamicDistance(d, cfg.base.mid),
    far: dynamicDistance(d, cfg.base.far),
  };

  const atm = roundStep(spot, cfg.strikeStep);

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

  const ceStrike = roundStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundStep(atm - peDist, cfg.strikeStep);

  const straddleStrike = atm;

  async function makeOption(strike, type) {
    const symbol = `${input.market.toUpperCase()}${strike}${type}`;
    const token = "0"; // Placeholder logic — your real token mapping here

    const mid = await fetchOptionPremium(cfg.exchange, symbol, token);

    const entry = mid ? Number(mid.toFixed(2)) : type === "STRADDLE" ? 2000 : 10;

    return {
      type,
      strike,
      distance: Math.abs(strike - spot),
      entry,
      stopLoss: Number((entry * 0.6).toFixed(2)),
      target: Number((entry * 1.5).toFixed(2)),
      midPrice: mid || null,
    };
  }

  const ce = await makeOption(ceStrike, "CE");
  const pe = await makeOption(peStrike, "PE");
  const straddle = await makeOption(straddleStrike, "STRADDLE");

  return [ce, pe, straddle];
}
// ------------------------------------------------------
// Helper: build exchangeTokens payload for multiple markets
// ------------------------------------------------------
function buildExchangeTokensPayload() {
  // returns object like { NFO: ["36688"], BFO: ["1104398"], MCX: ["463007"] }
  const out = {};
  for (const k of Object.keys(AUTO)) {
    const a = AUTO[k];
    if (!a || !a.token || !a.token.toString().trim()) continue;
    const exch = (MARKET_CONFIG[k] && MARKET_CONFIG[k].exchange) || (() => {
      // fallback mapping
      if (k.includes("nifty")) return "NFO";
      if (k.includes("sensex")) return "BFO";
      if (k.includes("natural")) return "MCX";
      return null;
    })();
    if (!exch) continue;
    if (!out[exch]) out[exch] = [];
    out[exch].push(a.token.toString());
  }
  return out;
}

// ------------------------------------------------------
// NEW-FORMAT LTP: call with exchangeTokens object
// ------------------------------------------------------
async function fetchLTPExchangeTokens(exchangeTokens) {
  if (!session.access_token) return { ok: false, reason: "NOT_LOGGED_IN" };
  if (!exchangeTokens || Object.keys(exchangeTokens).length === 0)
    return { ok: false, reason: "NO_EXCHANGE_TOKENS" };

  try {
    const body = {
      mode: "LTP",
      exchangeTokens: exchangeTokens, // new format
    };

    const resp = await fetch(`${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    const raw = await resp.json().catch(() => null);
    console.log("LTP (exchangeTokens) RAW:", JSON.stringify(raw, null, 2));

    if (!raw || raw.status === false) return { ok: false, reason: "LTP_FAILED", detail: raw };

    // raw.data may be array or object; normalize into map token->ltp
    const map = {};
    if (Array.isArray(raw.data)) {
      for (const item of raw.data) {
        if (!item) continue;
        // common fields could be token, symboltoken, ltp, last_traded_price
        const token = (item.symbolToken || item.token || item.symboltoken || item.symboltoken) + "";
        const ltp = item.ltp || item.last_traded_price || item.ltpPrice || null;
        if (token) map[token] = ltp;
      }
    } else if (typeof raw.data === "object") {
      // sometimes data is object keyed by exchange
      for (const exch of Object.keys(raw.data)) {
        const entries = raw.data[exch];
        if (Array.isArray(entries)) {
          for (const it of entries) {
            const token = (it.symbolToken || it.token || it.symboltoken || "") + "";
            const ltp = it.ltp || it.last_traded_price || null;
            if (token) map[token] = ltp;
          }
        }
      }
    }

    return { ok: true, map, raw };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// ------------------------------------------------------
// /api/ltp route — fetch LTP using exchangeTokens format
// ------------------------------------------------------
app.get("/api/ltp", async (req, res) => {
  if (!session.access_token) return res.status(401).json({ success: false, error: "NOT_LOGGED_IN" });

  // build exchangeTokens from AUTO (or FALLBACK)
  const exchangeTokens = buildExchangeTokensPayload();
  if (Object.keys(exchangeTokens).length === 0) {
    return res.json({ success: false, reason: "NO_TOKENS_AVAILABLE", auto: AUTO });
  }

  const r = await fetchLTPExchangeTokens(exchangeTokens);
  if (!r.ok) {
    return res.json({ success: false, error: r });
  }

  // attach ltp values into AUTO
  for (const mk of Object.keys(AUTO)) {
    const token = (AUTO[mk] && AUTO[mk].token) ? AUTO[mk].token.toString() : null;
    if (token && r.map && Object.prototype.hasOwnProperty.call(r.map, token)) {
      AUTO[mk].ltp = r.map[token];
    }
  }

  res.json({ success: true, data: AUTO, raw: r.raw || null });
});

// ------------------------------------------------------
// Debug test route (raw search) - keep for troubleshooting
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
    res.type("application/json").send(raw);
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// ------------------------------------------------------
// MAIN /api/calc (awaits buildStrikes which may call fetchOptionPremium)
// ------------------------------------------------------
app.post("/api/calc", async (req, res) => {
  try {
    const body = req.body || {};
    // normalize input (simple)
    const input = {
      ema20: Number(body.ema20 || 0),
      ema50: Number(body.ema50 || 0),
      rsi: Number(body.rsi || 0),
      vwap: Number(body.vwap || 0),
      spot: Number(body.spot || 0),
      market: (body.market || "nifty").toString().toLowerCase().replace(/\s+/g, ""),
      expiry_days: Number(body.expiry_days || 7),
      use_live: !!body.use_live,
    };

    let usedLive = false;
    let liveLtp = null;
    let liveErr = null;

    if (input.use_live) {
      // try to fetch via exchangeTokens new format
      const exchangeTokens = buildExchangeTokensPayload();
      const r = await fetchLTPExchangeTokens(exchangeTokens);
      if (r.ok && r.map) {
        const token = (AUTO[input.market] && AUTO[input.market].token) ? AUTO[input.market].token.toString() : null;
        if (token && r.map[token] != null) {
          input.spot = Number(r.map[token]);
          usedLive = true;
          liveLtp = input.spot;
        } else {
          liveErr = { ok: false, reason: "TOKEN_NO_LTP", raw: r.raw || null };
        }
      } else {
        liveErr = r;
      }
    }

    const trend = computeTrend(input);
    const strikes = await buildStrikes(input, trend); // buildStrikes is async

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
    res.json({ success: false, error: err.message || String(err) });
  }
});

// ------------------------------------------------------
// WebSocket Feed V2 connector (reconnect, update AUTO.ltp)
// ------------------------------------------------------
let wsClient = null;
function connectFeedV2() {
  if (!session.feed_token || !session.access_token) {
    console.log("connectFeedV2: missing feed_token or access_token");
    return;
  }

  let WebSocket;
  try {
    WebSocket = require("ws");
  } catch (e) {
    console.log("connectFeedV2: 'ws' not installed — skip websocket (install ws to enable).");
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
      console.log("Feed V2 WS connected.");
      // subscribe tokens if required by feed protocol
      const tokens = [];
      for (const k of Object.keys(AUTO)) {
        if (AUTO[k] && AUTO[k].token) tokens.push(AUTO[k].token.toString());
      }
      if (tokens.length) {
        const subMsg = { action: "subscribe", tokens };
        try { wsClient.send(JSON.stringify(subMsg)); } catch (e) {}
      }
    });

    wsClient.on("message", (m) => {
      try {
        const data = JSON.parse(m.toString());
        // adapt based on actual feed message structure
        // if message contains symbolToken/token + ltp, update AUTO
        const tok = data.symbolToken || data.token || data.symboltoken || null;
        const ltp = data.ltp || data.last_traded_price || null;
        if (tok && ltp != null) {
          for (const k of Object.keys(AUTO)) {
            if (AUTO[k] && AUTO[k].token && AUTO[k].token.toString() === tok.toString()) {
              AUTO[k].ltp = Number(ltp);
            }
          }
        }
      } catch (e) {}
    });

    wsClient.on("close", () => {
      console.log("Feed WS closed, reconnect in 20s.");
      wsClient = null;
      setTimeout(connectFeedV2, 20 * 1000);
    });

    wsClient.on("error", (err) => {
      console.log("Feed WS error:", err && err.message);
    });
  } catch (err) {
    console.log("connectFeedV2 exception:", err.message);
  }
}

// call connectFeedV2 after successful login somewhere in code (smartApiLogin)
const originalSmartApiLogin = smartApiLogin;
smartApiLogin = async function (tradingPassword) {
  const r = await originalSmartApiLogin(tradingPassword);
  if (r.ok) {
    // try connecting feed
    setTimeout(() => {
      try { connectFeedV2(); } catch (e) {}
    }, 1000);
  }
  return r;
};

// ------------------------------------------------------
// SPA fallback and server start
// ------------------------------------------------------
app.get("*", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("SERVER running on port", PORT);
});
