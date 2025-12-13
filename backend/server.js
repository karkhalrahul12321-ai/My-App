/* PART 1/6 — BASE IMPORTS + CONFIG + SESSION + TOTP + LOGIN (FIXED) */
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

/* SERVE FRONTEND */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* ENV SMARTAPI */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelone.in";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* MEMORY SESSION STORE */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: null
};

/* LAST KNOWN SPOT MEMORY */
let lastKnown = {
  spot: null,
  updatedAt: 0,
  prevSpot: null
};

/* ===============================
   ONLINE MASTER AUTO LOADER
   =============================== */
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
loadMasterOnline();
setInterval(loadMasterOnline, 60 * 60 * 1000);

/* ===============================
   BASE32 + TOTP
   =============================== */
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

/* SAFE JSON FETCH */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e?.message || String(e) };
  }
}

/* ===============================
   SMARTAPI LOGIN
   =============================== */
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
          totp: totp
        })
      }
    );

    const data = await resp.json().catch(() => null);

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
    return { ok: false, reason: "EXCEPTION", error: err?.message };
  }
}

/* LOGIN ROUTES */
app.post("/api/login", async (req, res) => {
  const password = req.body?.password || "";
  const r = await smartApiLogin(password);

  if (!r.ok) {
    return res.json({
      success: false,
      error: r.reason
    });
  }

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at,
      login_time: session.login_time
    }
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at || null,
    login_time: session.login_time || null
  });
});

/* HEALTH */
app.get("/healthz", (req, res) => {
  res.json({
    ok: true,
    time: Date.now(),
    env: {
      SMARTAPI_BASE: !!SMARTAPI_BASE,
      SMART_API_KEY: !!SMART_API_KEY,
      SMART_USER_ID: !!SMART_USER_ID
    }
  });
});

/* EXPORTS (for next parts) */
module.exports = {
  app,
  session,
  lastKnown,
  SMARTAPI_BASE,
  SMART_API_KEY,
  SMART_TOTP_SECRET,
  SMART_USER_ID,
  safeFetchJson,
  smartApiLogin,
  generateTOTP
};
/* PART 2/6 — WEBSOCKET (SAFE VERSION, NO BREAK) */

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

const realtime = {
  ticks: {},
  candles1m: {}
};

/* ===============================
   HELPER UTILS
   =============================== */
function tsOf(entry) {
  return String(entry.tradingsymbol || entry.symbol || entry.name || "").toUpperCase();
}
function itypeOf(entry) {
  return String(entry.instrumenttype || entry.instrumentType || entry.type || "").toUpperCase();
}
function isTokenSane(t) {
  const n = Number(String(t || "").replace(/\D/g, ""));
  return n > 0;
}

/* ===============================
   START WEBSOCKET
   =============================== */
async function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;
  if (!session.feed_token || !session.access_token) return;

  wsClient = new WebSocket(WS_URL, {
    perMessageDeflate: false,
    headers: {
      Authorization: session.access_token,
      "x-api-key": SMART_API_KEY,
      "x-client-code": SMART_USER_ID,
      "x-feed-token": session.feed_token
    }
  });

  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.lastError = null;
    wsStatus.reconnectAttempts = 0;

    const auth = {
      task: "auth",
      channel: "websocket",
      token: session.feed_token,
      user: SMART_USER_ID,
      apikey: SMART_API_KEY,
      source: "API"
    };

    wsClient.send(JSON.stringify(auth));

    setTimeout(() => subscribeCoreSymbols(), 1000);

    wsHeartbeat = setInterval(() => {
      try {
        wsClient.send("ping");
      } catch {}
    }, 30000);
  });

  wsClient.on("message", (raw) => {
    wsStatus.lastMsgAt = Date.now();

    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (!msg?.data) return;
    const d = msg.data;

    const sym =
      d.tradingsymbol ||
      d.symbol ||
      d.tradingSymbol ||
      null;

    const ltp =
      Number(
        d.ltp ||
        d.last_traded_price ||
        d.lastPrice ||
        d.price ||
        0
      ) || null;

    if (sym && ltp) {
      realtime.ticks[sym] = { ltp, time: Date.now() };
    }

    /* SAFE SPOT UPDATE (no assumption) */
    if (ltp) {
      lastKnown.spot = ltp;
      lastKnown.updatedAt = Date.now();
    }

    /* BUILD 1 MIN CANDLE */
    try {
      if (sym && ltp) {
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
            volume: d.volume || 0
          });
          if (arr.length > 180) arr.shift();
        } else {
          cur.high = Math.max(cur.high, ltp);
          cur.low = Math.min(cur.low, ltp);
          cur.close = ltp;
        }
      }
    } catch {}
  });

  wsClient.on("close", () => {
    wsStatus.connected = false;
    scheduleWSReconnect();
  });

  wsClient.on("error", (e) => {
    wsStatus.connected = false;
    wsStatus.lastError = String(e);
    scheduleWSReconnect();
  });
}

function scheduleWSReconnect() {
  wsStatus.reconnectAttempts++;
  setTimeout(() => {
    try { wsClient?.terminate(); } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, Math.min(30000, 1000 * wsStatus.reconnectAttempts));
}

/* ===============================
   CORE SUBSCRIPTIONS
   =============================== */
async function subscribeCoreSymbols() {
  try {
    const symbols = ["NIFTY", "SENSEX", "NATURALGAS"];
    const tokens = [];

    for (let s of symbols) {
      const tok = await resolveInstrumentToken(s, "", 0, "FUT");
      if (tok?.token) tokens.push(String(tok.token));
    }

    if (tokens.length) {
      wsClient.send(JSON.stringify({
        task: "cn",
        channel: { instrument_tokens: tokens, feed_type: "ltp" }
      }));
      wsStatus.subscriptions = tokens;
    }
  } catch {}
}

/* WS STATUS */
app.get("/api/ws/status", (req, res) => {
  res.json(wsStatus);
});

/* AUTO START AFTER LOGIN */
const _origLogin = smartApiLogin;
smartApiLogin = async function (pw) {
  const r = await _origLogin(pw);
  if (r?.ok) setTimeout(startWebsocketIfReady, 1500);
  return r;
};

/* DELAYED START */
setTimeout(startWebsocketIfReady, 2000);
/* PART 3/6 — TREND + MOMENTUM + VOLUME + HYBRID ENGINE */

function safeNum(n) {
  n = Number(n);
  return isFinite(n) ? n : 0;
}

/* BASIC TREND METRICS */
function computeBasicTrend(ema20, ema50, vwap, spot) {
  ema20 = safeNum(ema20);
  ema50 = safeNum(ema50);
  vwap  = safeNum(vwap);
  spot  = safeNum(spot);

  let score = 0;
  if (spot > ema20) score++;
  if (spot > ema50) score++;
  if (spot > vwap)  score++;

  if (spot < ema20) score--;
  if (spot < ema50) score--;
  if (spot < vwap)  score--;

  let direction = "NEUTRAL";
  if (score >= 2) direction = "UP";
  if (score <= -2) direction = "DOWN";

  return { score, direction };
}

/* MOMENTUM CHECK */
function computeMomentumTrend(spot, prev) {
  spot = safeNum(spot);
  prev = safeNum(prev);

  if (!prev) return { momentum: "NEUTRAL", slope: 0 };

  const diff = spot - prev;
  if (diff > 3) return { momentum: "UP", slope: diff };
  if (diff < -3) return { momentum: "DOWN", slope: diff };

  return { momentum: "NEUTRAL", slope: diff };
}

/* RSI GATE */
function rsiTrendGate(rsi, dir) {
  rsi = safeNum(rsi);
  if (dir === "UP") return rsi > 50;
  if (dir === "DOWN") return rsi < 40;
  return false;
}

/* HYBRID TREND ENGINE */
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
  const base = computeBasicTrend(ema20, ema50, vwap, spot);
  const mom  = computeMomentumTrend(spot, lastSpot);
  const rsiOk = rsiTrendGate(rsi, base.direction);

  let score = base.score;
  if (mom.momentum === "UP") score++;
  if (mom.momentum === "DOWN") score--;

  if (!rsiOk) score = Math.sign(score) * Math.max(0, Math.abs(score) - 1);

  let direction = "NEUTRAL";
  if (score >= 2) direction = "UP";
  if (score <= -2) direction = "DOWN";

  return {
    direction,
    score,
    base,
    momentum: mom,
    rsiOk
  };
}

/* TRIPLE CONFIRM — TREND */
async function tripleConfirmTrend(trendObj) {
  if (!trendObj) return { trendConfirmed: false };
  return { trendConfirmed: Math.abs(trendObj.score) >= 2 };
}

/* TRIPLE CONFIRM — MOMENTUM */
async function tripleConfirmMomentum(symbol, getCandlesFn) {
  try {
    const c = await getCandlesFn(symbol, 1, 12);
    const closes = c.map(x => Number(x.close)).filter(Boolean);
    if (closes.length < 6) return { momentumConfirmed: false };

    const last = closes[closes.length - 1];
    const mean =
      closes.slice(0, -1).reduce((a, b) => a + b, 0) /
      Math.max(1, closes.length - 1);

    const pct = Math.abs((last - mean) / mean);
    return { momentumConfirmed: pct > 0.0008 };
  } catch {
    return { momentumConfirmed: false };
  }
}

/* TRIPLE CONFIRM — VOLUME */
async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c = await getCandlesFn(symbol, 5, 12);
    const vols = c.map(x => Number(x.volume || 0)).filter(v => v > 0);
    if (!vols.length) return { volumeConfirmed: false };

    const last = vols[vols.length - 1];
    const avg = vols.reduce((a, b) => a + b, 0) / vols.length;
    return { volumeConfirmed: last >= avg * 0.8 };
  } catch {
    return { volumeConfirmed: false };
  }
}

/* FAKE BREAKOUT FILTER */
function rejectFakeBreakout(trendObj, futDiff) {
  if (!trendObj) return true;
  if (Math.abs(trendObj.score) < 2) return true;
  if (futDiff && Math.abs(futDiff) > 200) return true;
  return false;
}
/* PART 4/6 — ENTRY ENGINE + FUTURES + OPTION LTP + TOKEN RESOLVE */

/* ROUND + STRIKE UTILS */
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
  const dist = computeStrikeDistanceByExpiry(expiry_days, minSteps);
  return {
    atm: base,
    otm1: base + dist,
    otm2: base - dist
  };
}

/* TARGET + SL */
function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;
  return {
    stopLoss: Number((entryLTP * 0.85).toFixed(2)),
    target1: Number((entryLTP * 1.10).toFixed(2)),
    target2: Number((entryLTP * 1.20).toFixed(2))
  };
}

/* FUTURES LTP */
async function fetchFuturesLTP(symbol) {
  try {
    const tok = await resolveInstrumentToken(symbol, "", 0, "FUT");
    if (!tok) return null;

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
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
          symboltoken: tok.token
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);
    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* FUTURES DIFF */
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut || !spotUsed) return null;
    return fut - spotUsed;
  } catch {
    return null;
  }
}

/* OPTION LTP */
async function fetchOptionLTP(symbol, strike, type) {
  try {
    const tok = await resolveInstrumentToken(symbol, "", strike, type);
    if (!tok) return null;

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
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
          symboltoken: tok.token
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);
    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* ===============================
   MAIN ENTRY ENGINE
   =============================== */
async function computeEntry({
  market,
  spot,
  ema20,
  ema50,
  vwap,
  rsi,
  expiry_days,
  lastSpot
}) {
  const trendObj = hybridTrendEngine({
    ema20,
    ema50,
    vwap,
    rsi,
    spot,
    lastSpot
  });

  const futDiff = await detectFuturesDiff(market, spot);
  const strikes = generateStrikes(market, spot, expiry_days);

  if (rejectFakeBreakout(trendObj, futDiff)) {
    return {
      allowed: false,
      reason: "FAKE_BREAKOUT",
      trend: trendObj,
      futDiff
    };
  }

  const ceATM = await fetchOptionLTP(market, strikes.atm, "CE");
  const peATM = await fetchOptionLTP(market, strikes.atm, "PE");

  const takeCE = trendObj.direction === "UP";
  const entryLTP = takeCE ? ceATM : peATM;

  if (!entryLTP) {
    return {
      allowed: false,
      reason: "OPTION_LTP_FAIL",
      trend: trendObj
    };
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
    target2: levels.target2
  };
}
/* PART 5/6 — CANDLES + RSI + ATR + LTP HELPERS */

/* FETCH HISTORICAL CANDLES */
async function fetchCandles(symbol, interval, count) {
  try {
    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;

    const payload = {
      exchange: "NSE",
      symboltoken: "",
      interval,
      fromdate: moment()
        .subtract(count, "days")
        .format("YYYY-MM-DD 09:15"),
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
    if (!j?.data || !Array.isArray(j.data)) return [];

    return j.data.map(c => ({
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

/* FETCH RECENT CANDLES (REALTIME FIRST) */
async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    if (interval === 1 && realtime.candles1m[symbol]) {
      return realtime.candles1m[symbol].slice(-limit);
    }

    let intv = "ONE_MINUTE";
    if (interval === 5) intv = "FIVE_MINUTE";

    const c = await fetchCandles(
      symbol,
      intv,
      Math.ceil(limit / (interval === 1 ? 1 : 5))
    );
    return c.slice(-limit);
  } catch {
    return [];
  }
}

/* RSI */
function computeRSI(closes, period = 14) {
  if (!closes || closes.length < period + 1) return null;

  let gains = 0;
  let losses = 0;

  for (let i = 1; i <= period; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff > 0) gains += diff;
    else losses -= diff;
  }

  if (losses === 0) return 100;

  const rs = gains / losses;
  return 100 - 100 / (1 + rs);
}

/* ATR */
async function computeATR(symbol, interval = 1, limit = 14) {
  try {
    const candles = await fetchRecentCandles(symbol, interval, limit + 1);
    if (candles.length < 2) return 0;

    const trs = [];
    for (let i = 1; i < candles.length; i++) {
      const c = candles[i];
      const p = candles[i - 1];
      trs.push(
        Math.max(
          c.high - c.low,
          Math.abs(c.high - p.close),
          Math.abs(c.low - p.close)
        )
      );
    }

    return trs.reduce((a, b) => a + b, 0) / trs.length;
  } catch {
    return 0;
  }
}

/* VOLUME SPIKE */
function detectVolumeSpike(prevVol, curVol) {
  if (!prevVol || !curVol) return false;
  return curVol >= prevVol * 1.15;
}

/* REST LTP (LEGACY FALLBACK — NOT PRIMARY) */
async function fetchLTP(symbol) {
  try {
    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
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
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);
    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}
/* PART 6/6 — QUOTE API SPOT FIX + ROUTES + SERVER START */

/* ===============================
   NEW: SPOT VIA MARKET QUOTE API
   =============================== */
async function fetchSpotViaQuoteAPI(market) {
  try {
    if (!global.instrumentMaster || !global.instrumentMaster.length) return null;

    const key = String(market || "").toUpperCase();

    const match = global.instrumentMaster.find(it => {
      const ts = String(it.tradingsymbol || it.symbol || it.name || "").toUpperCase();
      const itype = String(it.instrumenttype || "").toUpperCase();
      return (
        isTokenSane(it.token) &&
        (itype.includes("INDEX") || itype.includes("AMXIDX")) &&
        ts.includes(key)
      );
    });

    if (!match) return null;

    const payload = {
      mode: "LTP",
      exchangeTokens: {
        [match.exchange || "NSE"]: [String(match.token)]
      }
    };

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: `Bearer ${session.access_token}`,
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB"
        },
        body: JSON.stringify(payload)
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.fetched?.[0]?.ltp || 0);

    if (ltp > 0) {
      lastKnown.spot = ltp;
      lastKnown.updatedAt = Date.now();
      return ltp;
    }

    return null;
  } catch {
    return null;
  }
}

/* ===============================
   API: GET SPOT (AUTO)
   =============================== */
app.get("/api/spot", async (req, res) => {
  const market = String(req.query.market || "NIFTY").toUpperCase();

  if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) {
    return res.json({ success: true, source: "WS", spot: lastKnown.spot });
  }

  const quoteSpot = await fetchSpotViaQuoteAPI(market);
  if (quoteSpot) {
    return res.json({ success: true, source: "QUOTE", spot: quoteSpot });
  }

  const legacy = await fetchLTP(market);
  if (legacy) {
    lastKnown.spot = legacy;
    lastKnown.updatedAt = Date.now();
    return res.json({ success: true, source: "REST", spot: legacy });
  }

  res.json({ success: false, error: "SPOT_NOT_AVAILABLE" });
});

/* ===============================
   API: /api/calc (AUTO SPOT)
   =============================== */
app.post("/api/calc", async (req, res) => {
  try {
    const {
      market,
      ema20,
      ema50,
      vwap,
      rsi,
      spot,
      expiry_days
    } = req.body;

    let finalSpot = null;

    if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) {
      finalSpot = lastKnown.spot;
    } else if (spot) {
      finalSpot = Number(spot);
      lastKnown.spot = finalSpot;
      lastKnown.updatedAt = Date.now();
    } else {
      finalSpot = await fetchSpotViaQuoteAPI(market);
    }

    if (!finalSpot || !isFinite(finalSpot)) {
      return res.json({
        success: false,
        error: "Spot could not be resolved"
      });
    }

    const entry = await computeEntry({
      market,
      spot: finalSpot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot: lastKnown.prevSpot || null
    });

    lastKnown.prevSpot = finalSpot;

    res.json({ success: true, entry });
  } catch (e) {
    res.json({
      success: false,
      error: "EXCEPTION_IN_CALC",
      detail: String(e)
    });
  }
});

/* ===============================
   API: PING
   =============================== */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    live: wsStatus.connected,
    spot: lastKnown.spot || null,
    time: Date.now()
  });
});

/* ===============================
   SERVER START
   =============================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
