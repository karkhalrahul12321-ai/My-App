/* -------------------------------------------------------------
   FIXED server.js (PART 1/6)
   — Imports + Master Loader + Express Setup + SmartAPI Login
-------------------------------------------------------------- */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

/* ------------------------------------------------------------
   ONLINE MASTER AUTO-LOADER
------------------------------------------------------------ */
global.instrumentMaster = [];

async function loadMasterOnline() {
  try {
    const url =
      "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";

    const r = await fetch(url);
    const j = await r.json().catch(() => []);

    if (Array.isArray(j) && j.length > 0) {
      global.instrumentMaster = j;
      console.log("MASTER LOADED ONLINE ✔ COUNT:", j.length);
    } else {
      console.log("MASTER LOAD FAILED → empty response");
    }
  } catch (e) {
    console.log("MASTER LOAD ERROR:", e);
  }
}

// Load once on startup
loadMasterOnline();

// Refresh every 1 hour automatically
setInterval(loadMasterOnline, 60 * 60 * 1000);

/* ------------------------------------------------------------
   EXPRESS SETUP
------------------------------------------------------------ */
const app = express();
app.use(cors());
app.use(bodyParser.json());

/* SERVE FRONTEND */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) =>
  res.sendFile(path.join(frontendPath, "index.html"))
);

app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* ------------------------------------------------------------
   SMARTAPI ENV
------------------------------------------------------------ */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* ------------------------------------------------------------
   SESSION MEMORY
------------------------------------------------------------ */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: null,
};

/* ------------------------------------------------------------
   TOTP GENERATOR
------------------------------------------------------------ */
function base32Decode(input) {
  if (!input) return Buffer.from([]);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0;
  let output = [];

  input = input.replace(/=+$/, "").toUpperCase();

  for (let char of input) {
    let idx = alphabet.indexOf(char);
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
    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 30000);

    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(0, 0);
    buf.writeUInt32BE(time, 4);

    const h = crypto.createHmac("sha1", key).update(buf).digest();
    const offset = h[h.length - 1] & 0xf;

    const code =
      ((h[offset] & 0x7f) << 24) |
      ((h[offset + 1] & 0xff) << 16) |
      ((h[offset + 2] & 0xff) << 8) |
      (h[offset + 3] & 0xff);

    return (code % 1000000).toString().padStart(6, "0");
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   SAFE JSON FETCH
------------------------------------------------------------ */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}

/* ------------------------------------------------------------
   SMARTAPI LOGIN
------------------------------------------------------------ */
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
          totp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    const d = data.data || {};

    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;
    session.login_time = Date.now();

    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      reason: "EXCEPTION",
      error: err.message || String(err),
    };
  }
}

/* ------------------------------------------------------------
   LOGIN ROUTES
------------------------------------------------------------ */
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
      raw: r.raw || null,
    });
  }

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at,
      login_time: session.login_time,
    },
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at,
    login_time: session.login_time,
  });
});
/* -------------------------------------------------------------
   PART 2/6 — WEBSOCKET (FULL FIXED VERSION)
-------------------------------------------------------------- */

const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";

let wsClient = null;
let wsHeartbeat = null;

let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

/* REALTIME MEMORY */
const realtime = {
  ticks: {},
  candles1m: {}
};

/* START WEBSOCKET IF READY */
async function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;

  if (!session.feed_token || !session.access_token) {
    console.log("WS: waiting for login tokens...");
    return;
  }

  try {
    wsClient = new WebSocket(WS_URL, {
      perMessageDeflate: false,
      headers: {
        Authorization: session.access_token,
        "x-api-key": SMART_API_KEY,
        "x-client-code": SMART_USER_ID,
        "x-feed-token": session.feed_token,
      },
    });
  } catch (e) {
    console.log("WS INIT ERR", e);
    return;
  }

  /* WS OPEN */
  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.reconnectAttempts = 0;
    wsStatus.lastError = null;

    console.log("WS: connected.");

    const auth = {
      task: "auth",
      channel: "websocket",
      token: session.feed_token,
      user: SMART_USER_ID,
      apikey: SMART_API_KEY,
      source: "API",
    };

    try {
      wsClient.send(JSON.stringify(auth));
    } catch (e) {
      console.log("WS AUTH SEND ERR", e);
    }

    setTimeout(() => subscribeCoreSymbols(), 1000);

    if (wsHeartbeat) clearInterval(wsHeartbeat);
    wsHeartbeat = setInterval(() => {
      try {
        if (wsClient && wsClient.readyState === WebSocket.OPEN) {
          wsClient.send("ping");
        }
      } catch (e) {
        console.log("HB ERR", e);
      }
    }, 30000);
  });

  /* WS MESSAGE HANDLER */
  wsClient.on("message", (raw) => {
    wsStatus.lastMsgAt = Date.now();

    let msg = null;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (!msg || !msg.data) return;

    const d = msg.data;
    const token = d.token || d.instrument_token || null;
    const ltp = Number(d.ltp || d.lastPrice || d.price || 0) || null;
    const oi = Number(d.oi || d.openInterest || 0) || null;
    const sym = d.tradingsymbol || d.symbol || null;

    if (sym && ltp != null) {
      realtime.ticks[sym] = {
        ltp,
        oi,
        time: Date.now(),
      };
    }

    if (ltp != null) {
      lastKnown.spot = ltp;
      lastKnown.updatedAt = Date.now();
    }

    /* BUILD 1-MIN CANDLE */
    try {
      if (sym && ltp != null) {
        if (!realtime.candles1m[sym]) realtime.candles1m[sym] = [];
        const arr = realtime.candles1m[sym];

        const now = Date.now();
        const curMin = Math.floor(now / 60000) * 60000;

        let cur = arr[arr.length - 1];

        if (!cur || cur.time !== curMin) {
          arr.push({
            time: curMin,
            open: ltp,
            high: ltp,
            low: ltp,
            close: ltp,
            volume: d.volume || 0,
          });

          if (arr.length > 180) arr.shift();
        } else {
          cur.high = Math.max(cur.high, ltp);
          cur.low = Math.min(cur.low, ltp);
          cur.close = ltp;
          cur.volume = (cur.volume || 0) + (d.volumeDelta || 0);
        }
      }
    } catch (e) {
      console.log("CANDLE ERROR", e);
    }
  });

  /* WS ERROR */
  wsClient.on("error", (err) => {
    wsStatus.connected = false;
    wsStatus.lastError = String(err);
    console.log("WS ERR:", err);
    scheduleWSReconnect();
  });

  /* WS CLOSE */
  wsClient.on("close", (code) => {
    wsStatus.connected = false;
    wsStatus.lastError = "closed:" + code;
    console.log("WS CLOSED", code);
    scheduleWSReconnect();
  });
}

/* SAFE RECONNECT LOGIC */
function scheduleWSReconnect() {
  wsStatus.reconnectAttempts++;

  const backoff = Math.min(
    30000,
    1000 * Math.pow(1.5, wsStatus.reconnectAttempts)
  );

  setTimeout(() => {
    try {
      if (wsClient) wsClient.terminate();
    } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, backoff);
}

/* SUBSCRIBE CORE SYMBOLS */
async function subscribeCoreSymbols() {
  try {
    const symbols = ["NIFTY", "SENSEX", "NATURALGAS"];
    const expiry = detectExpiryForSymbol("NIFTY").currentWeek;

    const tokens = [];

    for (let s of symbols) {
      const tok = await resolveInstrumentToken(s, expiry, 0, "FUT").catch(
        () => null
      );

      if (tok && tok.token) {
        const tstr = String(tok.token).replace(/\D/g, "");

        if (tstr.length >= 5 && tstr.length <= 8) {
          tokens.push(String(tok.token));
        } else {
          console.log("SUBSCRIBE SKIP (bad token length):", s, tok.token);
        }
      } else {
        console.log("SUBSCRIBE SKIP (no token):", s);
      }
    }

    if (
      tokens.length > 0 &&
      wsClient &&
      wsClient.readyState === WebSocket.OPEN
    ) {
      const sub = {
        task: "cn",
        channel: {
          instrument_tokens: tokens,
          feed_type: "ltp",
        },
      };

      try {
        wsClient.send(JSON.stringify(sub));
        wsStatus.subscriptions = tokens;
        console.log("WS SUBSCRIBED →", tokens);
      } catch (e) {
        console.log("WS SEND SUBSCRIBE ERR", e);
      }
    } else {
      console.log("WS: no valid tokens to subscribe", tokens);
    }
  } catch (e) {
    console.log("WS SUBSCRIBE ERR", e);
  }
}

/* WS STATUS ENDPOINT */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions,
  });
});

/* AUTO-START HOOK AFTER LOGIN */
const _origSmartLogin = smartApiLogin;
smartApiLogin = async function (pw) {
  const r = await _origSmartLogin(pw);
  if (r && r.ok) {
    setTimeout(() => startWebsocketIfReady(), 1200);
  }
  return r;
};

/* INITIAL WS START */
setTimeout(() => startWebsocketIfReady(), 2000);
/* -------------------------------------------------------------
   PART 3/6 — TREND + MOMENTUM + VOLUME + HYBRID ENGINE
-------------------------------------------------------------- */

/* SAFE NUMBER */
function safeNum(n) {
  n = Number(n);
  return isFinite(n) ? n : 0;
}

/* BASE TREND METRICS */
function computeBasicTrend(ema20, ema50, vwap, spot) {
  ema20 = safeNum(ema20);
  ema50 = safeNum(ema50);
  vwap  = safeNum(vwap);
  spot  = safeNum(spot);

  const above20 = spot > ema20;
  const above50 = spot > ema50;
  const aboveVW = spot > vwap;

  const below20 = spot < ema20;
  const below50 = spot < ema50;
  const belowVW = spot < vwap;

  let score = 0;
  if (above20) score++;
  if (above50) score++;
  if (aboveVW) score++;

  if (below20) score--;
  if (below50) score--;
  if (belowVW) score--;

  let direction = "NEUTRAL";
  if (score >= 2) direction = "UP";
  if (score <= -2) direction = "DOWN";

  return { score, direction, above20, above50, aboveVW };
}

/* MOMENTUM TREND CHECKER */
function computeMomentumTrend(spot, prev) {
  try {
    spot = safeNum(spot);
    prev = safeNum(prev);

    if (!prev) return { momentum: "NEUTRAL", slope: 0 };

    const diff = spot - prev;
    if (diff > 3) return { momentum: "UP", slope: diff };
    if (diff < -3) return { momentum: "DOWN", slope: diff };

    return { momentum: "NEUTRAL", slope: diff };
  } catch {
    return { momentum: "NEUTRAL", slope: 0 };
  }
}

/* RSI TREND FILTER */
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);

  if (direction === "DOWN") return rsi < 40;
  if (direction === "UP")   return rsi > 50;

  return false;
}

/* HYBRID TREND ENGINE */
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
  const basic = computeBasicTrend(ema20, ema50, vwap, spot);
  const mom   = computeMomentumTrend(spot, lastSpot);
  const rsiOk = rsiTrendGate(rsi, basic.direction);

  let score = basic.score;

  if (mom.momentum === "UP") score++;
  if (mom.momentum === "DOWN") score--;

  if (!rsiOk) score = Math.sign(score) * Math.max(0, Math.abs(score) - 1);

  let finalDir = "NEUTRAL";
  if (score >= 2) finalDir = "UP";
  if (score <= -2) finalDir = "DOWN";

  return {
    direction: finalDir,
    base: basic,
    momentum: mom,
    rsiOk,
    score
  };
}

/* TRIPLE CONFIRMATION — TREND CONFIRM */
async function tripleConfirmTrend(trendObj, symbol, getCandlesFn) {
  if (!trendObj) return { trendConfirmed: false };

  const score = Number(trendObj.score || 0);
  if (Math.abs(score) >= 3) return { trendConfirmed: true };

  try {
    const candles = (typeof getCandlesFn === "function")
      ? (await getCandlesFn(symbol, 1, 30)).map(c => Number(c.close)).filter(Boolean)
      : [];

    const localRSI = candles.length ? computeRSI(candles, 14) : null;

    if (!localRSI && Math.abs(score) >= 2) return { trendConfirmed: true };

    if (trendObj.direction === "UP") {
      if (localRSI && localRSI > 50 && score > 1) return { trendConfirmed: true };
    }
    else if (trendObj.direction === "DOWN") {
      if (localRSI && localRSI < 40 && score < -1) return { trendConfirmed: true };
    }

    return { trendConfirmed: false };
  } catch {
    return { trendConfirmed: Math.abs(score) >= 2 };
  }
}

/* TRIPLE CONFIRMATION — MOMENTUM */
async function tripleConfirmMomentum(symbol, getCandlesFn) {
  try {
    const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 6)  : [];

    const closes1 = c1.map(x => Number(x.close)).filter(Boolean);
    const closes5 = c5.map(x => Number(x.close)).filter(Boolean);

    if (closes1.length < 6) return { momentumConfirmed: false };

    const last = closes1[closes1.length - 1];
    const meanPrev = closes1.slice(0, -1).reduce((a,b)=>a+b,0) / Math.max(1, closes1.length-1);
    const pct = Math.abs((last - meanPrev) / Math.max(1, meanPrev));

    let momentumConfirmed = pct > 0.0008;

    const downs1 = closes1.slice(-5).every((v,i,arr)=> i===0 ? true : arr[i] < arr[i-1]);
    const ups1   = closes1.slice(-5).every((v,i,arr)=> i===0 ? true : arr[i] > arr[i-1]);

    if (!(downs1 || ups1) && closes5.length >= 3) {
      const downs5 = closes5.slice(-3).every((v,i,arr)=> i===0 ? true : arr[i] < arr[i-1]);
      const ups5   = closes5.slice(-3).every((v,i,arr)=> i===0 ? true : arr[i] > arr[i-1]);
      momentumConfirmed = momentumConfirmed && (downs5 || ups5);
    }

    return { momentumConfirmed };
  } catch {
    return { momentumConfirmed: false };
  }
}

/* TRIPLE CONFIRMATION — VOLUME */
async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 12) : [];
    const vols = c5.map(x => Number(x.volume || x.vol || 0)).filter(v => v > 0);

    if (!vols.length) {
      const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
      const highs = c1.map(x=>Number(x.high)).filter(Boolean);
      const lows  = c1.map(x=>Number(x.low)).filter(Boolean);

      const tr = [];
      for (let i = 1; i < highs.length; i++) {
        tr.push(Math.max(
          Math.abs(highs[i]-lows[i]),
          Math.abs(highs[i]-Number(c1[i-1].close)),
          Math.abs(lows[i]-Number(c1[i-1].close))
        ));
      }

      const avgTR = tr.length ? tr.reduce((a,b)=>a+b,0) / tr.length : 0;
      return {
        volumeConfirmed:
          avgTR > 0 && (avgTR / Math.max(1, Number(c1[c1.length-1]?.close || 1))) > 0.001
      };
    }

    const latest = vols[vols.length - 1];
    const sorted = [...vols].sort((a,b)=>a-b);
    const median = sorted[Math.floor(sorted.length / 2)] || 0;
    const mean = vols.reduce((a,b)=>a+b,0) / vols.length;

    return { volumeConfirmed: latest >= Math.max(median*0.9, mean*0.8) };
  } catch {
    return { volumeConfirmed: false };
  }
}

/* FAKE BREAKOUT SOFT BLOCKER */
function rejectFakeBreakout(trendObj, futDiff) {
  if (!trendObj) return true;

  const score = Number(trendObj.score || 0);
  if (Math.abs(score) < 2) return true;

  if (futDiff && Math.abs(futDiff) > 200) return true;

  return false;
}

/* STRIKE UTILS */
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

/* STRIKE GENERATOR */
function generateStrikes(market, spot, expiry_days) {
  const base = roundToStep(market, spot);
  const minSteps = getStrikeSteps(market, expiry_days);
  const dynamicDist = computeStrikeDistanceByExpiry(expiry_days, minSteps);

  const atm = base;
  const otm1 = base + dynamicDist;
  const otm2 = base - dynamicDist;

  return { atm, otm1, otm2 };
}

/* TARGET + STOPLOSS */
function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;

  const sl = entryLTP * 0.85;
  const tgt1 = entryLTP * 1.10;
  const tgt2 = entryLTP * 1.20;

  return {
    stopLoss: Number(sl.toFixed(2)),
    target1: Number(tgt1.toFixed(2)),
    target2: Number(tgt2.toFixed(2))
  };
}
/* -------------------------------------------------------------
   PART 4/6 — ENTRY ENGINE + FUTURES + OPTION LTP + TOKEN RESOLVE
-------------------------------------------------------------- */

/* FUTURES LTP FETCHER */
async function fetchFuturesLTP(symbol) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;

    const tokenInfo = await resolveInstrumentToken(symbol, expiry, 0, "FUT");
    if (!tokenInfo) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
      },
      body: JSON.stringify({
        exchange: tokenInfo.instrument?.exchange || "NFO",
        tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
        symboltoken: tokenInfo.token || "",
      }),
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* FUTURES DIFF DETECTOR */
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut || !isFinite(spotUsed)) return null;
    return Number(fut) - Number(spotUsed);
  } catch {
    return null;
  }
}

/* OPTION LTP FETCHER */
async function fetchOptionLTP(symbol, strike, type) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;

    const tokenInfo = await resolveInstrumentToken(symbol, expiry, strike, type);
    if (!tokenInfo) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
      },
      body: JSON.stringify({
        exchange: tokenInfo.instrument?.exchange || "NFO",
        tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
        symboltoken: tokenInfo.token || "",
      }),
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   ULTRA-ACCURATE RESOLVE INSTRUMENT TOKEN (REWRITTEN)
-------------------------------------------------------------- */
async function resolveInstrumentToken(symbol, expiry = "", strike = 0, type = "FUT") {
  try {
    /* --- MASTER AVAILABILITY CHECK --- */
    let master = global.instrumentMaster;
    if (!master || !Array.isArray(master) || master.length === 0) {
      try {
        const url =
          "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
        const r = await fetch(url);
        master = await r.json().catch(() => null);
        if (Array.isArray(master)) global.instrumentMaster = master;
      } catch {
        return null;
      }
    }
    if (!master || !Array.isArray(master) || master.length === 0) return null;

    /* --- NORMALIZE INPUTS --- */
    const wantedSymbolRaw = String(symbol || "").trim();
    if (!wantedSymbolRaw) return null;

    const wantedSymbol = wantedSymbolRaw.toUpperCase();
    const wantedStrike = Number(strike || 0);
    const wantedType = String(type || "FUT").toUpperCase();
    const normExpiry = String(expiry || "").replace(/-/g, "").trim();

    function normalize(s) {
      return String(s || "").toUpperCase().replace(/\s+/g, " ").trim();
    }

    const key = normalize(wantedSymbol);

    /* --- ALIAS MAP --- */
    const aliasMap = {
      SENSEX: [
        "SENSEX",
        "SENSEX30",
        "BSE SENSEX",
        "BSE30",
        "INDEX-SENSEX",
        "SENSEX-30",
        "SENSEX_I",
        "SENSEXINDEX",
      ],
      NIFTY: [
        "NIFTY",
        "NIFTY50",
        "NIFTY 50",
        "NSE NIFTY",
        "NIFTY INDEX",
        "NIFTY50 INDEX",
        "NIFTYI",
        "NIFTY-I",
      ],
      NATURALGAS: [
        "NATURAL GAS",
        "NATURALGAS",
        "NAT GAS",
        "NATGAS",
        "NG",
        "NATGAS-1",
      ],
    };

    /* --- TOKEN SANITY CHECK (HARDENED) --- */
function isTokenSane(tok) {
  if (!tok) return false;
  const s = String(tok).replace(/\D/g, "");
  if (!s) return false;

  // valid Angel tokens are typically 5–6 digits
  if (s.length < 5 || s.length > 6) return false;

  // block garbage like 999xxxx
  if (s.startsWith("999")) return false;

  return true;
}

    /* --- MARKET CANDIDATE MATCHING --- */
    function matchesMarket(entry) {
      const candidates = [
        entry.symbol,
        entry.name,
        entry.tradingsymbol,
        entry.instrumentname,
      ]
        .filter(Boolean)
        .map(normalize);

      if (aliasMap[key]) {
        for (const a of aliasMap[key]) {
          const na = normalize(a);
          if (candidates.some((c) => c === na || c.includes(na))) return true;
        }
      }

      if (candidates.some((c) => c === key || c.includes(key))) return true;

      const nospace = key.replace(/\s+/g, "");
      if (candidates.some((c) => c.replace(/\s+/g, "").includes(nospace)))
        return true;

      return false;
    }

    function entryExpiryStr(e) {
      return String(e || "").replace(/-/g, "");
    }

    const marketCandidates = master.filter((it) => matchesMarket(it));
    if (!marketCandidates.length) return null;

    function itypeOf(it) {
      return String(it.instrumenttype || "").toUpperCase();
    }
    function tsOf(it) {
      return String(
        it.tradingsymbol || it.symbol || it.name || ""
      ).toUpperCase();
    }

    /* ---- OPTIONS (CE/PE) ---- */
    if (["CE", "PE", "OPT", "OPTION"].includes(wantedType)) {
      const opts = marketCandidates.filter((it) => {
        const st = Number(it.strike || it.strikePrice || 0);
        const itype = itypeOf(it);
        const ts = tsOf(it);

        const typeMatches =
          itype.includes(wantedType) ||
          ts.includes(wantedType) ||
          itype.includes("OPT") ||
          /CE|PE/.test(ts);

        return (
          Math.abs(st - wantedStrike) < 0.6 &&
          typeMatches &&
          isTokenSane(it.token)
        );
      });

      if (opts.length) {
        opts.sort((a, b) => {
          const ea = entryExpiryStr(a.expiry || a.expiryDate || a.expiry_dt);
          const eb = entryExpiryStr(b.expiry || b.expiryDate || b.expiry_dt);
          return ea.localeCompare(eb);
        });

        const pick = opts[0];
        return { instrument: pick, token: String(pick.token) };
      }
    }

    /* ---- FUTURES ---- */
    if (wantedType === "FUT") {
      /* 1) FUT with matching expiry */
      if (normExpiry) {
        const byExpiry = marketCandidates
          .filter((it) => {
            const e = entryExpiryStr(
              it.expiry || it.expiryDate || it.expiry_dt
            );
            const itype = itypeOf(it);
            const ts = tsOf(it);

            const isFut =
              itype.includes("FUT") ||
              ts.includes("FUT") ||
              itype.includes("FUTIDX") ||
              itype.includes("FUTSTK") ||
              itype.includes("AMXIDX");

            if (!isFut) return false;

            if (!e) return false;

            return (
              e === normExpiry ||
              e.includes(normExpiry) ||
              normExpiry.includes(e) ||
              e.endsWith(normExpiry) ||
              e.includes(normExpiry.slice(-4))
            );
          })
          .filter((it) => isTokenSane(it.token));

        if (byExpiry.length) {
          const pick0 =
            byExpiry.find(
              (it) =>
                Math.abs(Number(it.strike || it.strikePrice || 0)) < 0.5
            ) || byExpiry[0];

          if (pick0 && pick0.token)
            return { instrument: pick0, token: String(pick0.token) };
        }
      }

      /* 2) FUT auto detect (nearest expiry, strike≈0) */
      const futs = marketCandidates.filter((it) => {
        const st = Number(it.strike || it.strikePrice || 0);
        const itype = itypeOf(it);
        const ts = tsOf(it);

        const isFut =
          itype.includes("FUT") ||
          ts.includes("FUT") ||
          itype.includes("FUTIDX") ||
          itype.includes("FUTSTK") ||
          itype.includes("AMXIDX");

        return isFut && Math.abs(st) < 0.5 && isTokenSane(it.token);
      });

      if (futs.length) {
        const now = new Date();

        function expiryDateOf(it) {
          const ex = String(
            it.expiry || it.expiryDate || it.expiry_dt || ""
          );

          let d = null;

          const m1 = ex.match(/^(\d{4})[-\/](\d{2})[-\/](\d{2})$/);
          if (m1)
            d = new Date(
              Number(m1[1]),
              Number(m1[2]) - 1,
              Number(m1[3])
            );

          const m2 = ex.match(/^(\d{4})(\d{2})(\d{2})$/);
          if (!d && m2)
            d = new Date(
              Number(m2[1]),
              Number(m2[2]) - 1,
              Number(m2[3])
            );

          const m3 = ex.match(/^(\d{1,2})[- ]([A-Za-z]+)[- ](\d{4})$/);
          if (!d && m3) {
            const dd = Number(m3[1]);
            const mm = [
              "JAN",
              "FEB",
              "MAR",
              "APR",
              "MAY",
              "JUN",
              "JUL",
              "AUG",
              "SEP",
              "OCT",
              "NOV",
              "DEC",
            ].indexOf(m3[2].toUpperCase());
            if (mm >= 0) d = new Date(Number(m3[3]), mm, dd);
          }

          if (!d && ex) {
            const maybe = Date.parse(ex);
            if (!isNaN(maybe)) d = new Date(maybe);
          }

          return d;
        }

        const futsWithDates = futs
          .map((it) => {
            const d = expiryDateOf(it);
            const diff = d ? d.getTime() - now.getTime() : Infinity;
            return { it, d, diff: Math.abs(diff) };
          })
          .sort((a, b) => a.diff - b.diff);

        const pick = futsWithDates[0]?.it || futs[0];
        if (pick && pick.token)
          return { instrument: pick, token: String(pick.token) };
      }

      /* 3) FALLBACK INDEX / AMXIDX */
      const spots = marketCandidates.filter((it) => {
        const itype = itypeOf(it);
        return (
          (itype.includes("AMXIDX") ||
            itype.includes("INDEX") ||
            itype.includes("IND")) &&
          Math.abs(Number(it.strike || it.strikePrice || 0)) < 0.5 &&
          isTokenSane(it.token)
        );
      });

      if (spots.length) {
        const pick = spots[0];
        if (pick && pick.token)
          return { instrument: pick, token: String(pick.token) };
      }
    }

    /* ---- GENERAL FALLBACK (prefer exact FUT tradingsymbols first) ---- */
const pref = marketCandidates.find((it) => {
  try {
    const ts = tsOf(it);
    const itype = itypeOf(it);

    const exact = ts === key || ts === `${key}FUT` || ts === `${key} FUT`;
    const starts = ts.startsWith(key) || (ts.includes(key) && ts.indexOf(key) < 4);

    const isFut = /FUT|FUTIDX|FUTSTK|AMXIDX/.test(itype);

    return isTokenSane(it.token) && isFut && (exact || starts);
  } catch {
    return false;
  }
});

if (pref) {
  console.log("resolveInstrumentToken: preferred FUT picked:", pref.tradingsymbol || pref.symbol, pref.token);
  return { instrument: pref, token: String(pref.token) };
}

const general = marketCandidates.find((it) =>
  isTokenSane(it.token) &&
  String(it.tradingsymbol || it.symbol || it.name || "").trim().length > 3
);

if (general) {
  console.log("resolveInstrumentToken: general fallback picked:", general.tradingsymbol || general.symbol, general.token);
  return { instrument: general, token: String(general.token) };
}

const anyWithToken = marketCandidates.find((it) => it.token && isTokenSane(it.token));
if (anyWithToken) {
  console.log("resolveInstrumentToken: anyWithToken picked (last):", anyWithToken.tradingsymbol || anyWithToken.symbol, anyWithToken.token);
  return { instrument: anyWithToken, token: String(anyWithToken.token) };
}

return null;
  });

/* DETECT WEEKLY EXPIRY FOR INDEX */
function detectExpiryForSymbol(symbol) {
  try {
    const today = moment();

    let currentWeek = today.clone().weekday(4);
    if (today.weekday() > 4)
      currentWeek = today.clone().add(1, "weeks").weekday(4);

    const nextWeek = currentWeek.clone().add(1, "weeks").weekday(4);

    return {
      currentWeek: currentWeek.format("YYYY-MM-DD"),
      nextWeek: nextWeek.format("YYYY-MM-DD"),
    };
  } catch {
    return {
      currentWeek: moment().format("YYYY-MM-DD"),
      nextWeek: moment().add(7, "days").format("YYYY-MM-DD"),
    };
  }
}

/* FINAL ENTRY GUARD */
async function finalEntryGuard({ symbol, trendObj, futDiff, getCandlesFn }) {
  const t = await tripleConfirmTrend(trendObj, symbol, getCandlesFn);
  const m = await tripleConfirmMomentum(symbol, getCandlesFn);
  const v = await tripleConfirmVolume(symbol, getCandlesFn);

  const passedCount =
    (t.trendConfirmed ? 1 : 0) +
    (m.momentumConfirmed ? 1 : 0) +
    (v.volumeConfirmed ? 1 : 0);

  if (passedCount === 0) {
    return {
      allowed: false,
      reason: "NO_CONFIRMATIONS",
      details: { t, m, v },
    };
  }

  if (rejectFakeBreakout(trendObj, futDiff)) {
    return {
      allowed: false,
      reason: "FAKE_BREAKOUT_SOFT",
      details: { t, m, v, futDiff },
    };
  }

  if (futDiff && Math.abs(futDiff) > 300) {
    return { allowed: false, reason: "FUT_MISMATCH_HARD", futDiff };
  }

  return {
    allowed: true,
    reason: "ALLOWED",
    passedCount,
    details: { t, m, v },
  };
}

/* MAIN ENTRY ENGINE */
async function computeEntry({
  market,
  spot,
  ema20,
  ema50,
  vwap,
  rsi,
  expiry_days,
  lastSpot,
}) {
  const trendObj = hybridTrendEngine({
    ema20,
    ema50,
    vwap,
    rsi,
    spot,
    lastSpot,
  });

  const futDiff = await detectFuturesDiff(market, spot);

  const strikes = generateStrikes(market, spot, expiry_days);

  const entryGate = await finalEntryGuard({
    symbol: market,
    trendObj,
    futDiff,
    getCandlesFn: fetchRecentCandles,
  });

  if (!entryGate.allowed) {
    return {
      allowed: false,
      reason: entryGate.reason,
      details: entryGate.details || {},
      trend: trendObj,
      futDiff,
    };
  }

  const ceATM = await fetchOptionLTP(market, strikes.atm, "CE");
  const peATM = await fetchOptionLTP(market, strikes.atm, "PE");

  const takeCE = trendObj.direction === "UP";
  const entryLTP = takeCE ? ceATM : peATM;

  if (!entryLTP)
    return { allowed: false, reason: "OPTION_LTP_FAIL", trend: trendObj };

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
  };
}
/* -------------------------------------------------------------
   PART 5/6 — CANDLES + RSI + ATR + SAFE LTP + SPOT RESOLVER
-------------------------------------------------------------- */

/* SAFE-FETCH CANDLES — from AngelOne API */
async function safeFetchCandles(symbol, intervalMinutes = 1, count = 30) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;
    const tok = await resolveInstrumentToken(symbol, expiry, 0, "FUT");
    if (!tok) return [];

    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: session.access_token,
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify({
        symboltoken: tok.token,
        interval: `${intervalMinutes}minute`,
        fromdate: moment().subtract(count * intervalMinutes, "minutes").format("YYYY-MM-DD HH:mm"),
        todate: moment().format("YYYY-MM-DD HH:mm"),
      }),
    });

    const j = await r.json().catch(() => null);
    const arr = j?.data?.candles || [];

    return arr.map((c) => ({
      time: c[0],
      open: Number(c[1]),
      high: Number(c[2]),
      low: Number(c[3]),
      close: Number(c[4]),
      volume: Number(c[5] || 0),
    }));
  } catch {
    return [];
  }
}

/* FETCH RECENT CANDLES (WS + REST fallback) */
async function fetchRecentCandles(symbol, intervalMinutes = 1, count = 30) {
  try {
    const key = symbol.toUpperCase();
    const arr = realtime.candles1m[key] || [];

    if (intervalMinutes === 1) {
      if (arr.length >= count) {
        return arr.slice(-count).map((x) => ({ ...x }));
      }
    }

    return await safeFetchCandles(symbol, intervalMinutes, count);
  } catch {
    return [];
  }
}

/* RSI CALCULATOR */
function computeRSI(values, period = 14) {
  try {
    if (!values || values.length < period + 1) return null;

    let gains = 0,
      losses = 0;

    for (let i = 1; i <= period; i++) {
      const diff = values[i] - values[i - 1];
      if (diff >= 0) gains += diff;
      else losses -= diff;
    }

    gains /= period;
    losses /= period;

    if (losses === 0) return 100;

    const rs = gains / losses;
    return Number((100 - 100 / (1 + rs)).toFixed(2));
  } catch {
    return null;
  }
}

/* ATR CALCULATOR */
function computeATR(candles) {
  try {
    if (!candles || candles.length < 2) return null;

    const trs = [];
    for (let i = 1; i < candles.length; i++) {
      const prev = candles[i - 1];
      const curr = candles[i];

      const tr = Math.max(
        Math.abs(curr.high - curr.low),
        Math.abs(curr.high - prev.close),
        Math.abs(curr.low - prev.close)
      );

      trs.push(tr);
    }

    return trs.reduce((a, b) => a + b, 0) / trs.length;
  } catch {
    return null;
  }
}

/* SAFE LTP (WS → REST fallback) */
async function safeGetLTP(symbol) {
  try {
    if (realtime.ticks[symbol]?.ltp) {
      return realtime.ticks[symbol].ltp;
    }

    const expiry = detectExpiryForSymbol(symbol).currentWeek;

    const tok = await resolveInstrumentToken(symbol, expiry, 0, "FUT");
    if (!tok) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
      },
      body: JSON.stringify({
        exchange: tok.instrument?.exchange || "NFO",
        tradingsymbol: tok.instrument?.tradingsymbol || "",
        symboltoken: tok.token,
      }),
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp || null;
  } catch {
    return null;
  }
}

/* SPOT RESOLVER (WS → REST fallback) */
async function resolveSpot(symbol, manualSpot, forceManual = false) {
  try {
    if (forceManual && isFinite(manualSpot)) {
      return Number(manualSpot);
    }

    const sy = symbol.toUpperCase();
    const rt = realtime.ticks[sy];

    if (rt && rt.ltp && Date.now() - rt.time < 5000) {
      return rt.ltp;
    }

    if (isFinite(manualSpot) && manualSpot > 0) return Number(manualSpot);

    const fut = await fetchFuturesLTP(symbol);
    if (fut) return fut;

    return null;
  } catch {
    return null;
  }
}
/* -------------------------------------------------------------
   PART 6/6 — FINAL ROUTES + /api/calc + SERVER START
-------------------------------------------------------------- */

/* MEMORY FOR LAST SPOT */
let lastKnown = {
  spot: null,
  updatedAt: 0,
};

/* /api/calc — MAIN CALCULATION ENGINE */
app.post("/api/calc", async (req, res) => {
  try {
    const {
      market = "",
      ema20 = 0,
      ema50 = 0,
      vwap = 0,
      rsi = 0,
      manualSpot = null,
      forceManualSpot = false,
    } = req.body || {};

    const marketU = String(market).toUpperCase();
    if (!marketU) {
      return res.json({ success: false, error: "MARKET_MISSING" });
    }

    /* SPOT RESOLUTION */
    const spot = await resolveSpot(marketU, manualSpot, forceManualSpot);

    if (!spot || !isFinite(spot)) {
      return res.json({
        success: false,
        error: "SPOT_NOT_RESOLVED",
        detail: {
          lastKnown,
          manual: manualSpot,
          force: forceManualSpot,
        },
      });
    }

    lastKnown.spot = spot;
    lastKnown.updatedAt = Date.now();

    /* DETECT EXPIRY DAYS */
    const expiry = detectExpiryForSymbol(marketU).currentWeek;
    const expiry_days = Math.max(
      0,
      moment(expiry).diff(moment(), "days")
    );

    /* ENTRY ENGINE */
    const entry = await computeEntry({
      market: marketU,
      spot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot: lastKnown.spot,
    });

    return res.json({
      success: true,
      entry,
      spotUsed: spot,
      expiry_days,
    });
  } catch (err) {
    return res.json({
      success: false,
      error: "EXCEPTION",
      detail: String(err),
    });
  }
});

/* MASTER DEBUG ROUTE */
app.get("/api/master/debug", (req, res) => {
  res.json({
    count: global.instrumentMaster?.length || 0,
    sample: global.instrumentMaster?.slice(0, 5) || [],
  });
});

/* GENERIC LTP ROUTE */
app.post("/api/ltp", async (req, res) => {
  try {
    const { symbol = "" } = req.body || {};
    if (!symbol) return res.json({ success: false });

    const ltp = await safeGetLTP(symbol);
    res.json({ success: true, ltp });
  } catch {
    res.json({ success: false });
  }
});

/* SERVER START */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("SERVER RUNNING ON PORT", PORT));
