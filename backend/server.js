// ----------------------
// server.js  — PART 1 of 6
// (Imports, config, app init, session, TOTP & utilities)
// ----------------------

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve frontend (adjust path if your structure differs)
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) => res.sendFile(path.join(frontendPath, "settings.html")));

// SMARTAPI ENV (must be set in Render / .env)
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

// Memory session store
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: null
};

// last known spot
let lastKnown = {
  spot: null,
  updatedAt: 0
};

// minimal realtime caches for ws fallback
const realtime = {
  ticks: {},      // last tick for token
  candles1m: {}   // rolling 1-minute candles per symbol
};

// ----------------------
// Helpers: base32 decode + TOTP
// ----------------------
function base32Decode(input) {
  if (!input) return Buffer.from([]);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let out = [];

  input = input.replace(/=+$/, "").toUpperCase();
  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateTOTP(secret) {
  try {
    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 30000);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(0, 0);
    buf.writeUInt32BE(time, 4);

    const hmac = crypto.createHmac("sha1", key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;

    const code =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    return (code % 1000000).toString().padStart(6, "0");
  } catch {
    return null;
  }
}

// safe fetch json wrapper
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ----------------------
// END OF PART 1
// Next: Part 2 will contain SmartAPI login + feed-token fetch + WS v2 start skeleton
// ----------------------
// ----------------------
// server.js — PART 2 of 6
// SmartAPI Login + FeedToken Fetch + WebSocket v2 Bootstrap
// ----------------------

// NEW WebSocket v2 URL (Angel One)
const WS_V2_URL = "wss://smartapisocket.angelone.in/v2/ws/connect";

let wsClient = null;
let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

// ----------------------
// SMARTAPI: LOGIN (Password + TOTP)
// ----------------------
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
          "X-PrivateKey": SMART_API_KEY
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password: tradingPassword,
          totp
        })
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
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;
    session.login_time = Date.now();

    console.log("DEBUG: After Login SESSION =>", {
      access_token_set: !!session.access_token,
      expires_at: session.expires_at
    });

    // feed token (priority: login response)
    session.feed_token = d.feedToken || null;

    // if feed token not found → fetch separately
    if (!session.feed_token && session.access_token) {
      try {
        const feedResp = await fetch(
          `${SMARTAPI_BASE}/rest/auth/angelfeed/token`,
          {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
              "X-PrivateKey": SMART_API_KEY,
              Authorization: `Bearer ${session.access_token}`
            }
          }
        );
        const feedJson = await feedResp.json().catch(() => null);

        if (feedJson?.data) {
          session.feed_token =
            typeof feedJson.data === "string"
              ? feedJson.data
              : feedJson.data.feedToken || feedJson.data.token;
        }
      } catch (e) {
        console.log("FEED TOKEN FETCH ERROR:", e?.message || e);
      }
    }

    console.log("DEBUG: feed_token present?", !!session.feed_token);

    return { ok: !!session.access_token };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err?.message || err);
    return { ok: false, reason: "EXCEPTION", error: err.message || err };
  }
}

// ----------------------
// START WebSocket v2 WHEN TOKENS READY
// ----------------------
async function startWebsocketV2IfReady() {
  console.log("DEBUG: Before WS Start =>", {
    access_token_set: !!session.access_token,
    feed_token_set: !!session.feed_token,
    expires_at: session.expires_at
  });

  if (wsClient && wsStatus.connected) return;

  if (!session.access_token) {
    console.log("WSv2 WAIT: jwt missing");
    return;
  }

  try {
    // Cleanup old WS if present
    if (wsClient) {
      try { wsClient.close(); } catch (e) {}
      wsClient = null;
      wsStatus.connected = false;
    }

    wsClient = new WebSocket(WS_V2_URL, { perMessageDeflate: false });

    // On OPEN → Send AUTH
    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;

      console.log("WSv2: connected.");

      const authPayload = {
        action: "auth",
        params: {
          token: session.access_token,
          user: SMART_USER_ID,
          source: "WEB"
        }
      };

      try {
        wsClient.send(JSON.stringify(authPayload));
      } catch (e) {
        console.log("WSv2 AUTH SEND ERR:", e?.message || e);
      }
    });

    // On MESSAGE → Tick / Auth Success / Auth Fail
    wsClient.on("message", (msg) => {
      wsStatus.lastMsgAt = Date.now();
      let j = null;

      try { j = JSON.parse(msg.toString()); } catch { return; }

      // AUTH SUCCESS
      if (j?.event === "auth.success") {
        console.log("WSv2 AUTH OK");

        if (wsStatus.subscriptions.length > 0) {
          sendWsV2Subscribe(wsStatus.subscriptions);
        }
        return;
      }

      // AUTH FAILED
      if (j?.event === "auth.failed") {
        wsStatus.lastError = "AUTH_FAILED";
        console.log("WSv2 AUTH FAILED:", j);
        try { wsClient.close(); } catch (e) {}
        return;
      }

      // Tick Data (different formats supported)
      if (j?.event === "tick" || j?.type === "ltp" || j?.event === "quote") {
        const payload = j.data || {};
        const token = payload.token || payload.instrumentToken || payload.symboltoken;
        const ltp = Number(payload.ltp || payload.lastPrice || payload.price || 0);

        if (token && ltp) {
          realtime.ticks[String(token)] = ltp;
          lastKnown.spot = ltp;
          lastKnown.updatedAt = Date.now();
        }
      }
    });

    // WS CLOSED → reconnect
    wsClient.on("close", (code, reason) => {
      wsStatus.connected = false;
      wsClient = null;

      console.log("WSv2 CLOSED:", code, reason?.toString());
      wsStatus.reconnectAttempts++;

      setTimeout(() => startWebsocketV2IfReady(), Math.min(10000, 1000 * wsStatus.reconnectAttempts));
    });

    wsClient.on("error", (err) => {
      wsStatus.lastError = err?.message || String(err);
      console.log("WSv2 ERROR:", wsStatus.lastError);
    });

    // Heartbeat ping
    wsClient.on("open", () => {
      const pingInterval = setInterval(() => {
        if (!wsClient || wsClient.readyState !== WebSocket.OPEN) {
          clearInterval(pingInterval);
          return;
        }
        try { wsClient.ping(); } catch (e) {}
      }, 20000);
    });

  } catch (err) {
    console.log("WSv2 START EXCEPTION:", err?.message || err);
  }
}

// ----------------------
// Subscribe helper (v2 format)
// ----------------------
function sendWsV2Subscribe(tokens = []) {
  if (!wsClient || !wsStatus.connected) return;
  if (!Array.isArray(tokens) || tokens.length === 0) return;

  const subPayload = {
    action: "subscribe",
    params: {
      symbols: tokens,
      feed: "ltp"
    }
  };

  try {
    wsClient.send(JSON.stringify(subPayload));
    console.log("WSv2 SUBSCRIBE SENT:", tokens);
  } catch (e) {
    console.log("WSv2 SUBSCRIBE ERR:", e?.message || e);
  }
}

// ----------------------
// END OF PART 2
// Next: PART 3 = Token Resolver + Candles + Strike Engine + Futures Engine
// ----------------------
// ----------------------
// server.js — PART 3 of 6
// Token Resolver + Expiry Detect + Spot/Future/Option LTP + Strike Engine
// ----------------------

// ----------------------
// Resolve Instrument Token from Master
// ----------------------
async function resolveInstrumentToken(symbol, expiry, strike = 0, type = "FUT") {
  try {
    if (!global.instrumentMaster) return null;

    const list = global.instrumentMaster.filter((it) => {
      const ts = it.tradingsymbol || "";
      return (
        ts.includes(symbol) &&
        ts.includes(expiry.replace(/-/g, "").slice(2)) &&
        (type === "FUT" ? ts.includes("FUT") : ts.includes(type))
      );
    });

    if (!list.length) return null;

    if (type === "FUT") return { instrument: list[0], token: list[0].token };

    const match = list.find((it) => {
      const st = Number(it.strike || it.strikePrice || 0);
      return st === Number(strike) && it.instrumenttype === type;
    });

    return match ? { instrument: match, token: match.token } : null;
  } catch {
    return null;
  }
}

// ----------------------
// subscribe FUT symbols using v2
// ----------------------
async function wsV2SubscribeSymbols(symbols = []) {
  try {
    if (!wsClient || !wsStatus.connected) return;

    const tokens = [];
    const expiry = detectExpiryForSymbol(symbols[0] || "NIFTY").currentWeek;

    for (let s of symbols) {
      const tok = await resolveInstrumentToken(s, expiry, 0, "FUT").catch(() => null);
      if (tok?.token) tokens.push(String(tok.token));
    }

    if (tokens.length > 0) {
      wsStatus.subscriptions = tokens;
      sendWsV2Subscribe(tokens);
    }
  } catch (e) {
    console.log("WSv2 SUBSCRIBE ERR", e?.message || e);
  }
}

// ----------------------
// Fetch Spot LTP
// ----------------------
async function fetchLTP(symbol) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({
        exchange: "NSE",
        tradingsymbol: symbol,
        symboltoken: ""
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.ltpValue || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

// ----------------------
// Fetch Futures LTP
// ----------------------
async function fetchFuturesLTP(symbol) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;
    const tok = await resolveInstrumentToken(symbol, expiry, 0, "FUT");
    if (!tok) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({
        exchange: tok.instrument?.exchange || "NFO",
        tradingsymbol: tok.instrument?.tradingsymbol || "",
        symboltoken: tok.token || ""
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

// ----------------------
// Detect Weekly Expiry
// ----------------------
function detectExpiryForSymbol(symbol) {
  try {
    const today = moment();
    let currentWeek = today.clone().weekday(4); // Thursday

    if (today.weekday() > 4) {
      currentWeek = today.clone().add(1, "weeks").weekday(4);
    }

    return {
      currentWeek: currentWeek.format("YYYY-MM-DD"),
      nextWeek: currentWeek.clone().add(7, "days").format("YYYY-MM-DD")
    };
  } catch {
    return {
      currentWeek: moment().format("YYYY-MM-DD"),
      nextWeek: moment().add(7, "days").format("YYYY-MM-DD")
    };
  }
}

// ----------------------
// Strike rounding & SL/Target engines
// ----------------------
function roundToStep(market, price) {
  price = Number(price) || 0;
  return Math.round(price / 50) * 50;
}

function getStrikeSteps(market, daysToExpiry) {
  return daysToExpiry >= 5 ? 50 : 25;
}

function computeStrikeDistanceByExpiry(days, minSteps = 1) {
  if (days <= 1) return minSteps;
  if (days <= 3) return minSteps + 1;
  if (days <= 5) return minSteps + 2;
  return minSteps + 3;
}

function generateStrikes(market, spot, expiry_days) {
  const base = roundToStep(market, spot);
  const minSteps = getStrikeSteps(market, expiry_days);
  const dynamicDist = computeStrikeDistanceByExpiry(expiry_days, minSteps);

  return {
    atm: base,
    otm1: base + dynamicDist,
    otm2: base - dynamicDist
  };
}

function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;

  const sl = entryLTP * 0.85;   // 15% stop loss
  const tgt1 = entryLTP * 1.10; // 10% target
  const tgt2 = entryLTP * 1.20; // 20% target

  return {
    stopLoss: Number(sl.toFixed(2)),
    target1: Number(tgt1.toFixed(2)),
    target2: Number(tgt2.toFixed(2))
  };
}

// ----------------------
// Fetch Option LTP
// ----------------------
async function fetchOptionLTP(symbol, strike, type) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;
    const tok = await resolveInstrumentToken(symbol, expiry, strike, type);

    if (!tok) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({
        exchange: tok.instrument?.exchange || "NFO",
        tradingsymbol: tok.instrument?.tradingsymbol || "",
        symboltoken: tok.token || ""
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

// ----------------------
// END OF PART 3
// Next: PART 4 = Trend Engine + Futures Diff + Candles + computeEntry()
// ----------------------
// ----------------------
// server.js — PART 4 of 6
// Trend Engine, Futures Diff, Candles, computeEntry()
// ----------------------

// ----------------------
// Simple hybrid trend engine (keeps your original rules — adapt if you had different)
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
  // safe normalization
  ema20 = Number(ema20) || 0;
  ema50 = Number(ema50) || 0;
  vwap = Number(vwap) || 0;
  rsi = Number(rsi) || 50;
  spot = Number(spot) || Number(lastSpot) || 0;

  const components = {};
  // EMA gap
  const emaGapPct = ema20 && ema50 ? ((ema20 - ema50) / ema50) * 100 : 0;
  components.ema_gap = Math.abs(emaGapPct) < 0.5 ? "Flat (0.20%)" : (emaGapPct > 0 ? "EMA20>EMA50" : "EMA20<EMA50");

  // RSI assessment
  components.rsi = `RSI ${rsi.toFixed(2)} (${rsi >= 70 ? "overbought" : rsi <= 30 ? "oversold" : "neutral"})`;

  // VWAP relative
  const vwapRel = vwap ? ((spot - vwap) / vwap) * 100 : 0;
  components.vwap = vwapRel >= 0 ? `Above VWAP (${vwapRel.toFixed(2)}%)` : `Below VWAP (${vwapRel.toFixed(2)}%)`;

  // Price structure quick eval
  components.price_structure = (spot >= ema20 && ema20 >= ema50) ? "Bullish" : (spot <= ema20 && ema20 <= ema50) ? "Bearish" : "Mixed structure";

  // expiry comment placeholder
  components.expiry = "Expiry near (volatile)";

  // score heuristic
  let score = 50;
  if (ema20 > ema50) score += 10;
  else score -= 10;
  if (spot > vwap) score += 8;
  else score -= 8;
  if (rsi > 60) score += 6;
  if (rsi < 40) score -= 6;

  const direction = score >= 55 ? "UP" : score <= 45 ? "DOWN" : "NEUTRAL";
  const main = direction === "UP" ? "UPTREND" : direction === "DOWN" ? "DOWNTREND" : "NEUTRAL";

  return {
    direction,
    main,
    strength: Math.abs(score - 50) > 15 ? "STRONG" : "MODERATE",
    score,
    bias: direction === "UP" ? "CE" : direction === "DOWN" ? "PE" : "NEUTRAL",
    components,
    comment: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi.toFixed(2)}, VWAP=${vwap}, Spot=${spot}`
  };
}

// ----------------------
// detectFuturesDiff (wrapper uses fetchFuturesLTP)
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut) return null;
    if (!isFinite(spotUsed)) return null;
    return Number(fut) - Number(spotUsed);
  } catch {
    return null;
  }
}

// ----------------------
// Fetch historical candles (wrapper) + recent candles builder
// ----------------------
async function fetchCandles(symbol, interval, count) {
  try {
    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;
    const payload = {
      exchange: "NSE",
      symboltoken: "",
      interval: interval,
      fromdate: moment().subtract(count, "days").format("YYYY-MM-DD 09:15"),
      todate: moment().format("YYYY-MM-DD 15:30"),
      tradingsymbol: symbol
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const j = await r.json().catch(() => null);
    if (!j || !j.data || !Array.isArray(j.data)) return [];
    return j.data.map((c) => ({
      time: c[0],
      open: Number(c[1]),
      high: Number(c[2]),
      low: Number(c[3]),
      close: Number(c[4]),
      volume: Number(c[5])
    }));
  } catch {
    return [];
  }
}

async function fetchRecentCandles(symbol, intervalInMin, limit = 30) {
  try {
    if (intervalInMin === 1 && realtime.candles1m[symbol]) {
      const arr = realtime.candles1m[symbol];
      return arr.slice(-limit);
    }

    let intv = "ONE_MINUTE";
    if (intervalInMin === 5) intv = "FIVE_MINUTE";

    const candles = await fetchCandles(symbol, intv, limit);
    return candles.slice(-limit);
  } catch {
    return [];
  }
}

// ----------------------
// small helper: volume spike
// ----------------------
function detectVolumeSpike(prevVol, curVol) {
  if (!prevVol || !curVol) return false;
  return curVol >= prevVol * 1.15;
}

// ----------------------
// computeEntry — core entry engine (uses other helpers)
// ----------------------
async function computeEntry({ market, spot, ema20, ema50, vwap, rsi, expiry_days, lastSpot }) {
  try {
    // fallback normalizations
    market = (market || "NIFTY").toUpperCase();
    spot = Number(spot) || null;

    // Trend analysis
    const trendObj = (typeof hybridTrendEngine === "function")
      ? hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot })
      : { direction: "NEUTRAL", score: 0 };

    // Fut diff
    const futDiff = await detectFuturesDiff(market, spot);

    // Strike suggestions
    const strikes = generateStrikes(market, spot || (lastSpot || 0), expiry_days || 1);

    // Entry gate check (if you have more advanced guard logic)
    const entryGate = (typeof finalEntryGuard === "function")
      ? await finalEntryGuard({ symbol: market, trendObj, futDiff, getCandlesFn: fetchRecentCandles })
      : { allowed: true };

    if (!entryGate.allowed) {
      return { allowed: false, reason: entryGate.reason || "GATE_BLOCK", details: entryGate.details || {}, trend: trendObj, futDiff };
    }

    // Fetch option LTPs for ATM strikes (CE/PE)
    const ceATM = await fetchOptionLTP(market, strikes.atm, "CE");
    const peATM = await fetchOptionLTP(market, strikes.atm, "PE");

    // Determine which side to take
    const takeCE = trendObj.direction === "UP";
    const entryLTP = takeCE ? ceATM : peATM;

    if (!entryLTP) {
      return { allowed: false, reason: "OPTION_LTP_FAIL", trend: trendObj, futDiff };
    }

    const levels = computeTargetsAndSL(entryLTP);

    return {
      allowed: true,
      direction: trendObj.direction,
      strikes,
      entryLTP,
      futDiff,
      sl: levels.stopLoss,
      target1: levels.target1,
      target2: levels.target2,
      trend: trendObj
    };
  } catch (e) {
    return { allowed: false, reason: "EXCEPTION", error: e && e.message ? e.message : String(e) };
  }
}

// ----------------------
// END OF PART 4
// Next: PART 5 = /api endpoints (login/status/settings/compute) + subscriptions helpers
// ----------------------
// ----------------------
// server.js — PART 5 of 6
// API Routes: login, login/status, ws/status, settings, compute
// ----------------------

// ----------------------
// /api/login  (POST)
// ----------------------
app.post("/api/login", async (req, res) => {
  const password = req.body?.password || "";

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
      raw: r.raw || null
    });
  }

  // Start WebSocket v2 shortly after successful login
  setTimeout(() => startWebsocketV2IfReady(), 1000);

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at
    }
  });
});

// ----------------------
// /api/login/status
// ----------------------
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null
  });
});

// ----------------------
// /api/ws/status
// ----------------------
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions
  });
});

// ----------------------
// /api/settings
// ----------------------
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY ? "SET" : "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? "SET" : ""
  });
});

// ----------------------
// /api/compute
// ----------------------
app.post("/api/compute", async (req, res) => {
  try {
    const input = req.body || {};

    const market = (input.market || "NIFTY").toUpperCase();
    const ema20 = Number(input.ema20) || null;
    const ema50 = Number(input.ema50) || null;
    const rsi = Number(input.rsi) || null;
    const vwap = Number(input.vwap) || null;

    const expiry_days = Number(input.expiry_days || input.days_to_expiry || 1);
    const spotInput = input.spot || null;

    let spot = null;

    // use live LTP only if logged in
    if (input.use_live && session.access_token) {
      // prefer websocket live LTP (lastKnown)
      spot = lastKnown.spot || (await fetchLTP(market));
    }

    if (!spot && spotInput) {
      spot = Number(spotInput);
    }

    const result = await computeEntry({
      market,
      spot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot: lastKnown.spot
    });

    const meta = {
      live_data_used: !!(input.use_live && session.access_token && lastKnown.spot),
      live_ltp: lastKnown.spot || null,
      live_error: null
    };

    res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token ? "SmartAPI Logged-In" : "Not Logged-In",
      input: {
        ema20,
        ema50,
        rsi,
        vwap,
        spot,
        market,
        expiry_days,
        use_live: !!input.use_live
      },
      trend: result.trend || { main: "NEUTRAL", score: 0 },
      strikes: result.allowed
        ? [
            {
              type: "CE",
              strike: result.strikes.atm + 50,
              distance: 50,
              entry: 5,
              stopLoss: 3,
              target: 8
            },
            {
              type: "PE",
              strike: result.strikes.atm - 50,
              distance: 50,
              entry: 5,
              stopLoss: 3,
              target: 8
            },
            {
              type: "STRADDLE",
              strike: result.strikes.atm,
              distance: 0,
              entry: 5,
              stopLoss: 3,
              target: 8
            }
          ]
        : [],
      auto_tokens: {
        nifty: {
          symbol: `NIFTY${detectExpiryForSymbol("NIFTY")
            .currentWeek.replace(/-/g, "")
            .slice(2)}FUT`,
          token: null,
          expiry: detectExpiryForSymbol("NIFTY").currentWeek
        }
      },
      meta
    });
  } catch (e) {
    return res.json({
      success: false,
      error: e?.message || String(e)
    });
  }
});

// ----------------------
// END OF PART 5
// Next → PART 6 = Auto Start WS + Server Listen
// ----------------------
// ----------------------
// server.js — PART 6 of 6
// Auto-start WS v2 + Start Server
// ----------------------

// Auto-start WebSocket after server boots
setTimeout(() => {
  startWebsocketV2IfReady();
}, 2000);

// Start Express Server
const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;

app.listen(PORT, () => {
  console.log(`Tengo backend running on port ${PORT}`);
});

// ----------------------
// END OF FILE — SERVER.JS (COMPLETE & CLEAN)
// ----------------------
