// -----------------------------
// FINAL SERVER.JS (PART 1 / 4)
// Clean, Stable, No experimental code
// -----------------------------

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");

// -----------------------------
// ENV VARIABLES (FIXED)
// -----------------------------
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// -----------------------------
// BASIC VALIDATION
// -----------------------------
function checkEnv() {
  return (
    SMART_API_KEY &&
    SMART_API_SECRET &&
    SMART_TOTP &&
    SMART_USER_ID
  );
}

// -----------------------------
// EXPRESS APP INIT
// -----------------------------
const app = express();
app.use(bodyParser.json());

// -----------------------------
// STATIC FRONTEND (IMPORTANT FIX)
// -----------------------------
app.use(express.static(path.join(__dirname, "..", "frontend")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "frontend", "index.html"));
});

// -----------------------------
// PING
// -----------------------------
app.get("/api/ping", (req, res) => {
  res.json({ status: "ok" });
});

// -----------------------------
// SMARTAPI LOGIN (FIXED)
// -----------------------------
app.post("/api/login", async (req, res) => {
  try {
    if (!checkEnv()) {
      return res.json({
        success: false,
        error: "ENV_MISSING",
      });
    }

    const totp = require("totp-generator")(SMART_TOTP);
    const axios = require("axios");

    const loginResp = await axios.post(
      "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/loginByPassword",
      {
        clientcode: SMART_USER_ID,
        password: SMART_API_SECRET,
        totp: totp,
      },
      {
        headers: {
          "X-ClientLocalIP": "127.0.0.1",
          "X-ClientPublicIP": "127.0.0.1",
          "X-MACAddress": "00:00:00:00:00:00",
          "X-PrivateKey": SMART_API_KEY,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      }
    );

    if (!loginResp.data || loginResp.data.status !== true) {
      return res.json({
        success: false,
        error: "LOGIN_FAILED",
      });
    }

    const token = loginResp.data.data.jwtToken;
    const refreshToken = loginResp.data.data.refreshToken;
    const feedToken = loginResp.data.data.feedToken;

    session.jwtToken = token;
    session.refreshToken = refreshToken;
    session.feedToken = feedToken;

    res.json({
      success: true,
      jwt: token,
      refreshToken,
      feedToken,
    });
  } catch (err) {
    return res.json({
      success: false,
      error: "LOGIN_ERROR",
      details: err.message,
    });
  }
});

// -----------------------------
// SESSION STORE
// -----------------------------
const session = {
  jwtToken: "",
  refreshToken: "",
  feedToken: "",
};
// -----------------------------
// REFRESH TOKEN API (STABLE)
// -----------------------------
app.get("/api/refresh", async (req, res) => {
  try {
    if (!session.refreshToken) {
      return res.json({
        success: false,
        error: "NO_REFRESH_TOKEN",
      });
    }

    const axios = require("axios");

    const resp = await axios.post(
      "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/refreshTokens",
      {
        refreshToken: session.refreshToken,
      },
      {
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      }
    );

    if (!resp.data || resp.data.status !== true) {
      return res.json({
        success: false,
        error: "REFRESH_FAILED",
      });
    }

    session.jwtToken = resp.data.data.jwtToken;
    session.refreshToken = resp.data.data.refreshToken;

    res.json({
      success: true,
      jwt: session.jwtToken,
      refreshToken: session.refreshToken,
    });
  } catch (err) {
    return res.json({
      success: false,
      error: "REFRESH_ERROR",
      details: err.message,
    });
  }
});

// -------------------------------------------------
// FULL QUOTE (HTTP fallback LTP / OHLC / FULL mode)
// -------------------------------------------------
app.post("/api/quote", async (req, res) => {
  try {
    const { exchange, tradingsymbol } = req.body;

    if (!session.jwtToken) {
      return res.json({ success: false, error: "NO_JWT" });
    }

    const axios = require("axios");

    const response = await axios.post(
      "https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote/",
      {
        mode: "FULL",
        exchange,
        tradingsymbol,
      },
      {
        headers: {
          Authorization: "Bearer " + session.jwtToken,
          "X-PrivateKey": SMART_API_KEY,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      }
    );

    res.json({
      success: true,
      data: response.data,
    });
  } catch (err) {
    res.json({
      success: false,
      error: "QUOTE_ERROR",
      details: err.message,
    });
  }
});

// -----------------------------
// OPTION GREEKS (OFFICIAL API)
// -----------------------------
app.post("/api/greeks", async (req, res) => {
  try {
    const { name, expirydate } = req.body;

    if (!session.jwtToken) {
      return res.json({ success: false, error: "NO_JWT" });
    }

    const axios = require("axios");

    const greeksResp = await axios.post(
      "https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/optionGreek",
      {
        name,
        expirydate,
      },
      {
        headers: {
          Authorization: "Bearer " + session.jwtToken,
          "X-PrivateKey": SMART_API_KEY,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      }
    );

    res.json({
      success: true,
      data: greeksResp.data,
    });
  } catch (err) {
    res.json({
      success: false,
      error: "GREEKS_ERROR",
      details: err.message,
    });
  }
});
// -------------------------------------------
// OPTION CHAIN (STRIKE BUILDER + QUOTE + IV)
// -------------------------------------------
app.post("/api/option-chain", async (req, res) => {
  try {
    const { symbol, expiry, strikes } = req.body;

    if (!session.jwtToken) {
      return res.json({ success: false, error: "NO_JWT" });
    }

    if (!Array.isArray(strikes) || strikes.length === 0) {
      return res.json({ success: false, error: "NO_STRIKES" });
    }

    const axios = require("axios");

    const results = [];

    for (const strike of strikes) {
      const ceSymbol = `${symbol}${strike}CE`;
      const peSymbol = `${symbol}${strike}PE`;

      const ceQuote = axios.post(
        "https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote/",
        {
          mode: "FULL",
          exchange: "NFO",
          tradingsymbol: ceSymbol,
        },
        {
          headers: {
            Authorization: "Bearer " + session.jwtToken,
            "X-PrivateKey": SMART_API_KEY,
            Accept: "application/json",
            "Content-Type": "application/json",
          },
        }
      );

      const peQuote = axios.post(
        "https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote/",
        {
          mode: "FULL",
          exchange: "NFO",
          tradingsymbol: peSymbol,
        },
        {
          headers: {
            Authorization: "Bearer " + session.jwtToken,
            "X-PrivateKey": SMART_API_KEY,
            Accept: "application/json",
            "Content-Type": "application/json",
          },
        }
      );

      const [ceRes, peRes] = await Promise.allSettled([ceQuote, peQuote]);

      results.push({
        strike,
        ce: ceRes.status === "fulfilled" ? ceRes.value.data : null,
        pe: peRes.status === "fulfilled" ? peRes.value.data : null,
      });
    }

    res.json({
      success: true,
      data: results,
    });
  } catch (err) {
    res.json({
      success: false,
      error: "OPTION_CHAIN_ERROR",
      details: err.message,
    });
  }
});

// ------------------------------------
// WEBSOCKET LIVE LTP (SMART-STREAM v2)
// ------------------------------------
let ws = null;
let wsConnected = false;

// start websocket
function startWebsocket() {
  if (wsConnected) return;

  const WebSocket = require("ws");

  const url = `wss://smartapisocket.angelone.in/smart-stream?clientCode=${SMART_USER_ID}&feedToken=${session.feedToken}&apiKey=${SMART_API_KEY}`;

  ws = new WebSocket(url);

  ws.on("open", () => {
    wsConnected = true;
    console.log("📡 WebSocket Connected");
  });

  ws.on("close", () => {
    wsConnected = false;
    console.log("❌ WebSocket Closed. Reconnecting...");
    setTimeout(startWebsocket, 2000);
  });

  ws.on("error", (e) => {
    console.log("WS ERROR:", e.message);
  });

  ws.on("message", (data) => {
    try {
      liveBroadcast(JSON.parse(data.toString()));
    } catch (e) {}
  });
}

// storage of subscribers
const subscribers = new Map(); // clientID → ws

function liveBroadcast(msg) {
  for (const client of subscribers.values()) {
    try {
      client.send(JSON.stringify(msg));
    } catch (_) {}
  }
}
// -----------------------------
// FINAL SERVER.JS (PART 4 / 4)
// -----------------------------

const http = require("http");
const axios = require("axios");
const WebSocket = require("ws");

// -----------------------------
// HELPERS (num, clamp, round)
// -----------------------------
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

// -----------------------------
// MARKET RULES + CONFIG
// -----------------------------
const FUTURE_RULES = {
  nifty: { searchSymbol: "NIFTY", exchange: "NFO", instrumentType: "FUTIDX", expiryDay: 4 },
  sensex: { searchSymbol: "SENSEX", exchange: "BFO", instrumentType: "FUTIDX", expiryDay: 4 },
  "natural gas": { searchSymbol: "NATURALGAS", exchange: "MCX", instrumentType: "FUTCOM", expiryDay: null },
};

const MARKET_CONFIG = {
  nifty: { name: "Nifty", strikeStep: 50, baseDistances: { far: 250, mid: 200, near: 150 }, exchange: "NFO" },
  sensex: { name: "Sensex", strikeStep: 100, baseDistances: { far: 500, mid: 400, near: 300 }, exchange: "BFO" },
  "natural gas": { name: "Natural Gas", strikeStep: 5, baseDistances: { far: 80, mid: 60, near: 50 }, exchange: "MCX" },
};

// AUTO tokens store (may be populated from search or fallback)
const AUTO = {
  nifty: { symbol: null, token: null, expiry: null, ltp: null },
  sensex: { symbol: null, token: null, expiry: null, ltp: null },
  "natural gas": { symbol: null, token: null, expiry: null, ltp: null },
};

// -----------------------------
// SMART SEARCH (searchScrip)
// -----------------------------
async function smartSearch(keyword) {
  if (!session.jwtToken) return [];
  try {
    const resp = await axios.post(
      "https://apiconnect.angelone.in/rest/secure/angelbroking/order/v1/searchScrip",
      { searchtext: keyword },
      {
        headers: {
          Authorization: "Bearer " + session.jwtToken,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );
    if (!resp.data || !resp.data.data) return [];
    return resp.data.data;
  } catch (err) {
    console.log("smartSearch error:", err?.response?.data || err.message);
    return [];
  }
}

// -----------------------------
// EXPIRY HELPERS
// -----------------------------
function fmtDate(d) {
  return `${d.getFullYear()}-${(d.getMonth() + 1).toString().padStart(2, "0")}-${d.getDate().toString().padStart(2, "0")}`;
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
    // weekly next 4 occurrences of expiryDay
    for (let i = 0; expiries.length < 4 && i < 28; i++) {
      const dt = new Date();
      dt.setDate(today.getDate() + i);
      if (dt.getDay() === rule.expiryDay) expiries.push(fmtDate(dt));
    }
  }
  return expiries;
}

// -----------------------------
// AUTO FETCH FUTURE (uses smartSearch)
// -----------------------------
async function autoFetchFuture(market) {
  const rule = FUTURE_RULES[market];
  if (!rule) return null;

  try {
    const expiries = getNextExpiries(market);
    const all = await smartSearch(rule.searchSymbol);
    if (!all.length) return null;

    for (const exp of expiries) {
      const [y, m, d] = exp.split("-");
      const match = all.find((x) => {
        const sameExchange = (x.exch_seg || "").toUpperCase() === rule.exchange.toUpperCase();
        const sameType = (x.instrumenttype || "").toUpperCase() === rule.instrumentType.toUpperCase();
        const expStr = typeof x.expirydate === "string" ? x.expirydate : "";
        const sameExpiry = expStr.includes(`${y}-${m}-${d}`);
        return sameExchange && sameType && sameExpiry;
      });
      if (match) {
        AUTO[market] = { symbol: match.tradingsymbol, token: match.symboltoken, expiry: match.expirydate, ltp: null };
        return AUTO[market];
      }
    }

    return null;
  } catch (err) {
    console.log("autoFetchFuture err:", err.message);
    return null;
  }
}

// -----------------------------
// GET LTP (HTTP via market/v1/quote) — single symbol
// -----------------------------
async function fetchLTPForToken(exchange, symboltoken, tradingsymbol) {
  if (!session.jwtToken) return null;
  try {
    // some APIs expect exchangeTokens object, some expect tradingsymbol; try tradingsymbol first
    const resp = await axios.post(
      "https://apiconnect.angelone.in/rest/secure/angelbroking/market/v1/quote/",
      {
        mode: "LTP",
        exchange: exchange,
        tradingsymbol: tradingsymbol,
        symboltoken: symboltoken,
      },
      {
        headers: {
          Authorization: "Bearer " + session.jwtToken,
          "X-PrivateKey": SMART_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    const data = resp.data;
    if (!data || data.status === false) return null;
    // many variants: data.data.ltp or data.data[0].ltp
    const ltp =
      (data.data && data.data.ltp) ||
      (Array.isArray(data.data) && data.data[0] && data.data[0].ltp) ||
      null;
    return ltp;
  } catch (err) {
    // log but return null so caller can fallback
    console.log("fetchLTPForToken err:", err?.response?.data || err.message);
    return null;
  }
}

// -----------------------------
// GET AUTO FUTURE LTP (uses AUTO tokens or autoFetchFuture+fetchLTPForToken)
// -----------------------------
async function getAutoFutureLTP(market) {
  const cfg = MARKET_CONFIG[market];
  if (!cfg) return { ok: false, reason: "NO_MARKET_CFG" };

  if (!session.jwtToken) return { ok: false, reason: "NOT_LOGGED_IN" };

  let auto = AUTO[market];
  // try to autoFetch if token not present or expired
  if (!auto || !auto.token) {
    const fetched = await autoFetchFuture(market);
    if (fetched) auto = fetched;
    else {
      // no search match — leave AUTO as-is (maybe user provided fallback)
      if (!AUTO[market] || !AUTO[market].token) {
        return { ok: false, reason: "TOKEN_NOT_FOUND", auto: auto || null };
      }
      auto = AUTO[market];
    }
  }

  // try fetch LTP
  const ltp = await fetchLTPForToken(cfg.exchange, auto.token, auto.symbol);
  if (ltp === null) {
    return { ok: false, reason: "LTP_FAILED", detail: "Unable to fetch LTP" };
  }
  // update store
  AUTO[market].ltp = ltp;
  return { ok: true, ltp };
}

// -----------------------------
// TREND ENGINE + STRIKE ENGINE (compact, deterministic)
// -----------------------------
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
    return { main: "SIDEWAYS", strength: "NEUTRAL", score: 50, bias: "NONE", components: comp, comment: "Data incomplete" };
  }

  const emaMid = (ema20 + ema50) / 2;
  const emaDiff = ema20 - ema50;
  const emaPct = (emaDiff / emaMid) * 100;
  let emaScore = clamp(emaPct * 1.5, -25, 25);

  comp.ema_gap = emaPct > 0.3 ? `Bullish (${emaPct.toFixed(2)}%)` : emaPct < -0.3 ? `Bearish (${emaPct.toFixed(2)}%)` : `Flat (${emaPct.toFixed(2)}%)`;

  let rsiScore = clamp((rsi - 50) * 1.2, -25, 25);
  comp.rsi = `RSI ${rsi}${rsi <= 40 ? rsi <= 30 ? " (oversold)" : " (bearish)" : ""}`;

  const vwapDiff = spot - vwap;
  const vwapPct = (vwapDiff / vwap) * 100;
  let vwapScore = clamp(vwapPct * 1.5, -20, 20);
  comp.vwap = vwapPct > 0.1 ? `Price above VWAP (${vwapPct.toFixed(2)}%)` : vwapPct < -0.1 ? `Below VWAP (${vwapPct.toFixed(2)}%)` : `Near VWAP (${vwapPct.toFixed(2)}%)`;

  let structScore = 0;
  if (spot > ema20 && ema20 > ema50) { structScore = 10; comp.price_structure = "Clean bullish"; }
  else if (spot < ema20 && ema20 < ema50) { structScore = -10; comp.price_structure = "Clean bearish"; }
  else comp.price_structure = "Mixed structure";

  const d = num(input.expiry_days, 7);
  let expiryAdj = 0;
  if (d <= 2) { expiryAdj = -5; comp.expiry = "Expiry near (volatile)"; }
  else if (d >= 10) { expiryAdj = 3; comp.expiry = "Expiry far (stable)"; }
  else comp.expiry = "Expiry mid";

  score = 50 + emaScore * 0.4 + rsiScore * 0.3 + vwapScore * 0.2 + structScore * 0.2 + expiryAdj;
  score = clamp(score, 0, 100);

  let main = "SIDEWAYS", strength = "RANGE";
  if (score >= 80) { main = "UPTREND"; strength = "STRONG"; bias = "CE"; }
  else if (score >= 60) { main = "UPTREND"; strength = "MODERATE"; bias = "CE"; }
  else if (score <= 20) { main = "DOWNTREND"; strength = "STRONG"; bias = "PE"; }
  else if (score <= 40) { main = "DOWNTREND"; strength = "MODERATE"; bias = "PE"; }

  return { main, strength, score, bias, components: comp, comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}` };
}

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
  const cfg = MARKET_CONFIG[input.market] || MARKET_CONFIG["nifty"];
  const { spot, expiry_days } = input;
  const scaled = scaleDistancesByExpiry(expiry_days, cfg.baseDistances, cfg.strikeStep);
  const atm = roundToStep(spot, cfg.strikeStep);

  let ceDist, peDist;
  if (trend.main === "UPTREND") { ceDist = scaled.near; peDist = scaled.far; }
  else if (trend.main === "DOWNTREND") { ceDist = scaled.far; peDist = scaled.near; }
  else { ceDist = scaled.mid; peDist = scaled.mid; }

  const ceStrike = roundToStep(atm + ceDist, cfg.strikeStep);
  const peStrike = roundToStep(atm - peDist, cfg.strikeStep);
  const straddleStrike = atm;

  function makeOption(strike, type, diff) {
    const steps = Math.max(1, Math.round(Math.abs(diff) / cfg.strikeStep));
    const base = Math.max(5, steps * 5);
    return { type, strike, distance: Math.abs(diff), entry: base, stopLoss: Math.round(base * 0.6), target: Math.round(base * 1.5) };
  }

  return [ makeOption(ceStrike, "CE", ceStrike - spot), makeOption(peStrike, "PE", peStrike - spot), makeOption(straddleStrike, "STRADDLE", straddleStrike - spot) ];
}

// -----------------------------
// WEBSOCKET SERVER FOR CLIENTS (/ws)
// -----------------------------
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/ws" });

wss.on("connection", (client, req) => {
  console.log("Client connected to /ws");
  client.on("message", (msg) => {
    // client can send subscription message: {"type":"subscribe","market":"nifty"}
    try {
      const o = JSON.parse(msg.toString());
      client._subs = client._subs || {};
      if (o.type === "subscribe" && o.market) {
        client._subs[o.market] = true;
        client.send(JSON.stringify({ ok: true, subscribed: o.market }));
      } else if (o.type === "unsubscribe" && o.market) {
        delete client._subs[o.market];
        client.send(JSON.stringify({ ok: true, unsubscribed: o.market }));
      }
    } catch (e) {}
  });
  client.on("close", () => console.log("Client disconnected from /ws"));
});

// Broadcast from Angel feed to connected clients selectively
function broadcastToClients(msg) {
  // msg expected to have token or tradingsymbol -> we do a simple broadcast
  const payload = JSON.stringify(msg);
  wss.clients.forEach((c) => {
    if (c.readyState === WebSocket.OPEN) {
      try { c.send(payload); } catch (e) {}
    }
  });
}

// -----------------------------
// Angel WebSocket (feed client) — start once feedToken exists
// -----------------------------
let wsClient = null;
function startAngelFeed() {
  if (!session.feedToken || !session.jwtToken) return;
  if (wsClient && wsClient.readyState === WebSocket.OPEN) return;

  const feedUrl = `wss://smartapisocket.angelone.in/smart-stream?clientCode=${SMART_USER_ID}&feedToken=${session.feedToken}&apiKey=${SMART_API_KEY}`;
  wsClient = new WebSocket(feedUrl);

  wsClient.on("open", () => console.log("Connected to Angel feed (v2 smart-stream)"));
  wsClient.on("message", (data) => {
    try {
      const parsed = JSON.parse(data.toString());
      // update AUTO.ltp if token matches
      if (parsed && parsed.data && parsed.data.length) {
        parsed.data.forEach((d) => {
          const token = d.instrumentToken || d.symbolToken || d.token;
          // update any AUTO matching token
          Object.keys(AUTO).forEach((k) => {
            if (AUTO[k].token && String(AUTO[k].token) === String(token)) {
              // common LTP fields might be 'ltp' or 'last_traded_price'
              const l = d.ltp || d.last_traded_price || d.lastPrice || null;
              if (l !== null) AUTO[k].ltp = l;
            }
          });
        });
      }
      // broadcast raw message to connected clients
      broadcastToClients(parsed);
    } catch (e) {
      // ignore parse errors
    }
  });
  wsClient.on("close", () => {
    console.log("Angel feed closed, reconnect in 2s");
    setTimeout(startAngelFeed, 2000);
  });
  wsClient.on("error", (e) => {
    console.log("Angel feed error:", e.message);
  });
}

// try start feed every 5s if feedToken gets set later
setInterval(() => {
  if (session.feedToken && !wsClient) startAngelFeed();
}, 5000);

// -----------------------------
// SUBSCRIBE / UNSUBSCRIBE (simple HTTP helpers for clients)
// -----------------------------
app.post("/api/ws/subscribe", (req, res) => {
  // clients normally should connect via websocket; this is a helper to confirm intent
  const { market } = req.body;
  if (!market) return res.json({ success: false, error: "NO_MARKET" });
  return res.json({ success: true, message: `Use WS connection to subscribe to ${market}` });
});

// -----------------------------
// HEALTH
// -----------------------------
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    jwt: !!session.jwtToken,
    feed: !!session.feedToken,
    wsClient: wsClient ? wsClient.readyState === WebSocket.OPEN : false,
  });
});

// -----------------------------
// CALC ROUTE (trend + strikes + optional live LTP)
// -----------------------------
app.post("/api/calc", async (req, res) => {
  try {
    const body = req.body || {};
    // normalize
    const input = {
      ema20: num(body.ema20),
      ema50: num(body.ema50),
      rsi: num(body.rsi),
      vwap: num(body.vwap),
      spot: num(body.spot),
      market: (body.market || "nifty").toString().toLowerCase(),
      expiry_days: num(body.expiry_days, 7),
      use_live: !!body.use_live,
    };

    let usedLive = false, liveLtp = null, liveErr = null;
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
      login_status: session.jwtToken ? "SmartAPI Logged-In" : "Not logged-in (demo mode)",
      input,
      trend,
      strikes,
      auto_tokens: AUTO,
      meta: { live_data_used: usedLive, live_ltp: liveLtp, live_error: liveErr },
    });
  } catch (err) {
    res.json({ success: false, error: err.message || String(err) });
  }
});

// -----------------------------
// START SERVER
// -----------------------------
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log("FINAL SERVER running on port", PORT);
});
