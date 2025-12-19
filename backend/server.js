/* ===============================
   PART 1/6 — BASE + AUTH + SESSION
   =============================== */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

/* ===============================
   GLOBAL MASTER (ONLINE LOAD)
   =============================== */
global.instrumentMaster = [];

global.tsof = function (entry) {
  return String(
    entry?.tradingsymbol ||
    entry?.symbol ||
    entry?.name ||
    ""
  ).toUpperCase();
};

/* ===============================
   LOAD MASTER ONLINE
   =============================== */
async function loadMasterOnline() {
  try {
    const url =
      "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
    const r = await fetch(url);
    const j = await r.json().catch(() => []);

    if (Array.isArray(j) && j.length) {
      global.instrumentMaster = j;
      console.log("✅ MASTER LOADED:", j.length);
    } else {
      console.log("⚠️ MASTER EMPTY");
    }
  } catch (e) {
    console.log("❌ MASTER LOAD ERROR:", e.message);
  }
}

loadMasterOnline();
setInterval(loadMasterOnline, 60 * 60 * 1000);

/* ===============================
   EXPRESS APP
   =============================== */
const app = express();
app.use(cors());
app.use(bodyParser.json());

/* ===============================
   FRONTEND
   =============================== */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) =>
  res.sendFile(path.join(frontendPath, "index.html"))
);

app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* ===============================
   SMART API ENV
   =============================== */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* ===============================
   SESSION MEMORY
   =============================== */
const session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: null
};

const lastKnown = {
  spot: null,
  prevSpot: null,
  updatedAt: 0
};

/* ===============================
   TOTP HELPERS
   =============================== */
function base32Decode(input) {
  if (!input) return Buffer.from([]);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out = [];

  input = input.replace(/=+$/, "").toUpperCase();
  for (const ch of input) {
    const idx = alphabet.indexOf(ch);
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

/* ===============================
   SAFE FETCH JSON
   =============================== */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/* ===============================
   SMART API LOGIN
   =============================== */
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
          password,
          totp
        })
      }
    );

    const data = await resp.json().catch(() => null);
    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    session.access_token = data.data?.jwtToken || null;
    session.refresh_token = data.data?.refreshToken || null;
    session.feed_token = data.data?.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;
    session.login_time = Date.now();

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

/* ===============================
   LOGIN ROUTES
   =============================== */
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
    session: {
      expires_at: session.expires_at,
      login_time: session.login_time
    }
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({
    logged_in: !!session.access_token,
    expires_at: session.expires_at
  });
});

/* ===============================
   HEALTH
   =============================== */
app.get("/healthz", (req, res) => {
  res.json({
    ok: true,
    time: Date.now(),
    env: {
      SMART_API_KEY: !!SMART_API_KEY,
      SMART_USER_ID: !!SMART_USER_ID
    }
  });
});

/* ===============================
   EXPORTS
   =============================== */
module.exports = {
  app,
  session,
  lastKnown,
  smartApiLogin,
  safeFetchJson,
  generateTOTP
};
/* =========================================
   PART 2/6 — WEBSOCKET (STABLE & RENDER SAFE)
   ========================================= */

const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";

let wsClient = null;
let wsHeartbeat = null;

const wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: {}
};

const realtime = {
  ticks: {},
  candles1m: {}
};

/* ===============================
   WS TOKEN GROUPS
   =============================== */
const wsTokenGroups = {
  NFO: [],
  BFO: [],
  MCX: []
};

function isTokenSane(token) {
  if (!token && token !== 0) return false;
  const n = Number(String(token).replace(/\D/g, ""));
  return n > 0;
}

function addWsToken(token, exchange) {
  if (!wsTokenGroups[exchange]) return;
  const t = String(token);
  if (!wsTokenGroups[exchange].includes(t)) {
    wsTokenGroups[exchange].push(t);
  }
}

/* ===============================
   START WS
   =============================== */
async function startWebsocketIfReady() {
  if (wsClient || !session.feed_token || !session.access_token) {
    return;
  }

  try {
    wsClient = new WebSocket(WS_URL, {
      perMessageDeflate: false,
      headers: {
        Authorization: session.access_token,
        "x-api-key": SMART_API_KEY,
        "x-client-code": SMART_USER_ID,
        "x-feed-token": session.feed_token
      }
    });
  } catch (e) {
    console.log("❌ WS INIT ERROR", e.message);
    wsClient = null;
    return;
  }

  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.reconnectAttempts = 0;
    wsStatus.lastError = null;
    console.log("✅ WS CONNECTED");

    const auth = {
      task: "auth",
      channel: "websocket",
      token: session.feed_token,
      user: SMART_USER_ID,
      apikey: SMART_API_KEY,
      source: "API"
    };

    try {
      wsClient.send(JSON.stringify(auth));
    } catch {}

    if (wsHeartbeat) clearInterval(wsHeartbeat);
    wsHeartbeat = setInterval(() => {
      try {
        if (wsClient?.readyState === WebSocket.OPEN) {
          wsClient.send("ping");
        }
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

    const d = msg?.data;
    if (!d) return;

    const sym = d.tradingsymbol || d.symbol;
    const ltp = Number(
      d.ltp ??
      d.last_traded_price ??
      d.lastPrice ??
      d.price ??
      0
    );

    if (!sym || !ltp) return;

    realtime.ticks[sym] = {
      ltp,
      oi: Number(d.oi || d.openInterest || 0),
      time: Date.now()
    };

    /* 1m Candle Builder */
    if (!realtime.candles1m[sym]) realtime.candles1m[sym] = [];
    const arr = realtime.candles1m[sym];

    const now = Date.now();
    const bucket = Math.floor(now / 60000) * 60000;
    let cur = arr[arr.length - 1];

    if (!cur || cur.time !== bucket) {
      arr.push({
        time: bucket,
        open: ltp,
        high: ltp,
        low: ltp,
        close: ltp,
        volume: Number(d.volume || 0)
      });
      if (arr.length > 180) arr.shift();
    } else {
      cur.high = Math.max(cur.high, ltp);
      cur.low = Math.min(cur.low, ltp);
      cur.close = ltp;
      cur.volume += Number(d.volumeDelta || 0);
    }
  });

  wsClient.on("error", (err) => {
    wsStatus.connected = false;
    wsStatus.lastError = err.message;
    console.log("❌ WS ERROR", err.message);
    scheduleWSReconnect();
  });

  wsClient.on("close", (code) => {
    wsStatus.connected = false;
    wsStatus.lastError = `closed:${code}`;
    console.log("⚠️ WS CLOSED", code);
    scheduleWSReconnect();
  });
}

/* ===============================
   RECONNECT LOGIC
   =============================== */
function scheduleWSReconnect() {
  if (wsClient) {
    try { wsClient.terminate(); } catch {}
  }
  wsClient = null;

  wsStatus.reconnectAttempts++;
  const delay = Math.min(
    30000,
    1000 * Math.pow(1.5, wsStatus.reconnectAttempts)
  );

  setTimeout(() => {
    startWebsocketIfReady();
  }, delay);
}

/* ===============================
   WS STATUS API
   =============================== */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    error: wsStatus.lastError,
    subs: wsTokenGroups
  });
});

/* ===============================
   AUTO START AFTER LOGIN
   =============================== */
const _origLogin = smartApiLogin;
smartApiLogin = async function (pw) {
  const r = await _origLogin(pw);
  if (r.ok) {
    setTimeout(startWebsocketIfReady, 1500);
  }
  return r;
};

setTimeout(startWebsocketIfReady, 3000);
/* =========================================
   PART 3/6 — TREND + MOMENTUM + STRIKE ENGINE
   ========================================= */

/* ===============================
   SAFE NUMBER
   =============================== */
function safeNum(v) {
  const n = Number(v);
  return isFinite(n) ? n : 0;
}

/* ===============================
   BASIC TREND
   =============================== */
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

/* ===============================
   MOMENTUM CHECK
   =============================== */
function computeMomentumTrend(spot, prevSpot) {
  spot = safeNum(spot);
  prevSpot = safeNum(prevSpot);

  if (!prevSpot) return { momentum: "NEUTRAL", slope: 0 };

  const diff = spot - prevSpot;
  if (diff > 3) return { momentum: "UP", slope: diff };
  if (diff < -3) return { momentum: "DOWN", slope: diff };

  return { momentum: "NEUTRAL", slope: diff };
}

/* ===============================
   RSI FILTER
   =============================== */
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);
  if (direction === "UP") return rsi > 50;
  if (direction === "DOWN") return rsi < 40;
  return false;
}

/* ===============================
   HYBRID ENGINE
   =============================== */
function hybridTrendEngine({
  ema20,
  ema50,
  vwap,
  rsi,
  spot,
  lastSpot
}) {
  const base = computeBasicTrend(ema20, ema50, vwap, spot);
  const mom = computeMomentumTrend(spot, lastSpot);
  const rsiOk = rsiTrendGate(rsi, base.direction);

  let score = base.score;
  if (mom.momentum === "UP") score++;
  if (mom.momentum === "DOWN") score--;

  if (!rsiOk && score !== 0) {
    score = Math.sign(score) * Math.max(0, Math.abs(score) - 1);
  }

  let direction = "NEUTRAL";
  if (score >= 2) direction = "UP";
  if (score <= -2) direction = "DOWN";

  return {
    direction,
    score,
    momentum: mom,
    rsiOk
  };
}

/* ===============================
   STRIKE HELPERS
   =============================== */
function roundToStep(price, step = 50) {
  price = safeNum(price);
  return Math.round(price / step) * step;
}

function getStrikeStep(market) {
  return market === "NIFTY" || market === "SENSEX" ? 50 : 100;
}

function generateStrikes(market, spot, expiryDays = 0) {
  const step = getStrikeStep(market);
  const atm = roundToStep(spot, step);

  let distance = step;
  if (expiryDays <= 1) distance = step;
  else if (expiryDays <= 3) distance = step * 2;
  else distance = step * 3;

  return {
    atm,
    otm1: atm + distance,
    otm2: atm - distance
  };
}

/* ===============================
   TARGET + SL
   =============================== */
function computeTargetsAndSL(entryLTP) {
  entryLTP = safeNum(entryLTP);

  const stopLoss = entryLTP * 0.85;
  const target1 = entryLTP * 1.10;
  const target2 = entryLTP * 1.20;

  return {
    stopLoss: Number(stopLoss.toFixed(2)),
    target1: Number(target1.toFixed(2)),
    target2: Number(target2.toFixed(2))
  };
}

/* ===============================
   EXPORTS (LOCAL USE)
   =============================== */
module.exports = {
  hybridTrendEngine,
  generateStrikes,
  computeTargetsAndSL
};
/* =========================================
   PART 4/6 — EXPIRY + TOKEN RESOLVER + LTP
   ========================================= */

/* ===============================
   EXPIRY DETECTOR
   =============================== */
function detectExpiryForSymbol(symbol, expiryDays = 0) {
  symbol = String(symbol || "").toUpperCase();

  if (expiryDays > 0) {
    const d = moment().add(expiryDays, "days").startOf("day");
    return {
      currentWeek: d.format("YYYY-MM-DD"),
      targetDate: d.toDate()
    };
  }

  let weeklyDay = 4; // Thu
  if (symbol.includes("NIFTY")) weeklyDay = 2;
  if (symbol.includes("SENSEX")) weeklyDay = 2;

  let week = moment().day(weeklyDay);
  if (week.isBefore(moment(), "day")) week.add(1, "week");

  return {
    currentWeek: week.format("YYYY-MM-DD"),
    targetDate: week.toDate()
  };
}

/* ===============================
   PARSE EXPIRY
   =============================== */
function parseExpiryDate(v) {
  if (!v) return null;
  const m = moment(
    String(v),
    ["YYYY-MM-DD", "YYYYMMDD", "DD-MM-YYYY", "DDMMMYYYY"],
    true
  );
  if (m.isValid()) return m.toDate();
  const d = new Date(v);
  return isFinite(d.getTime()) ? d : null;
}

/* ===============================
   RESOLVE TOKEN (SAFE VERSION)
   =============================== */
async function resolveInstrumentToken(
  symbol,
  expiry = "",
  strike = 0,
  type = "FUT"
) {
  try {
    if (!global.instrumentMaster?.length) return null;

    symbol = String(symbol).toUpperCase();
    type = String(type).toUpperCase();
    strike = Number(strike || 0);

    const key = symbol.replace(/[^A-Z]/g, "");
    const list = global.instrumentMaster.filter((it) =>
      String(it.tradingsymbol || it.symbol || it.name || "")
        .toUpperCase()
        .includes(key)
    );

    if (!list.length) return null;

    /* ---------- OPTIONS ---------- */
    if (type === "CE" || type === "PE") {
      const opt = list
        .filter((it) => {
          const ts = global.tsof(it);
          const st = Number(it.strike || it.strikePrice || 0);
          return (
            ts.includes(type) &&
            Math.abs(st - strike) <= 100 &&
            String(it.instrumenttype || "").includes("OPT")
          );
        })
        .map((it) => ({
          it,
          exp: parseExpiryDate(it.expiry)
        }))
        .sort((a, b) => (a.exp || 0) - (b.exp || 0))[0];

      if (!opt?.it?.token) return null;

      addWsToken(opt.it.token, "NFO");
      return { token: String(opt.it.token), instrument: opt.it };
    }

    /* ---------- INDEX ---------- */
    if (type === "INDEX") {
      const idx = list.find((it) =>
        String(it.instrumenttype || "").includes("INDEX")
      );
      if (idx?.token) {
        return { token: String(idx.token), instrument: idx };
      }
    }

    /* ---------- FUTURES ---------- */
    const fut = list
      .filter((it) => String(it.instrumenttype || "").includes("FUT"))
      .map((it) => ({
        it,
        exp: parseExpiryDate(it.expiry)
      }))
      .sort((a, b) => (a.exp || 0) - (b.exp || 0))[0];

    if (fut?.it?.token) {
      addWsToken(fut.it.token, "NFO");
      return { token: String(fut.it.token), instrument: fut.it };
    }

    return null;
  } catch (e) {
    console.log("❌ resolveInstrumentToken ERROR", e.message);
    return null;
  }
}

/* ===============================
   FUTURES LTP
   =============================== */
async function fetchFuturesLTP(symbol) {
  try {
    const exp = detectExpiryForSymbol(symbol).currentWeek;
    const tok = await resolveInstrumentToken(symbol, exp, 0, "FUT");
    if (!tok?.token) return null;

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: session.access_token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          exchange: tok.instrument.exchange || "NFO",
          tradingsymbol: tok.instrument.tradingsymbol,
          symboltoken: tok.token
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || 0);
    return ltp || null;
  } catch {
    return null;
  }
}

/* ===============================
   OPTION LTP
   =============================== */
async function fetchOptionLTP(symbol, strike, type, expiryDays) {
  try {
    const exp = detectExpiryForSymbol(symbol, expiryDays).currentWeek;
    const tok = await resolveInstrumentToken(symbol, exp, strike, type);
    if (!tok?.token) return null;

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: session.access_token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          exchange: tok.instrument.exchange || "NFO",
          tradingsymbol: tok.instrument.tradingsymbol,
          symboltoken: tok.token
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || 0);
    return ltp || null;
  } catch {
    return null;
  }
}

/* ===============================
   EXPORTS
   =============================== */
module.exports = {
  detectExpiryForSymbol,
  resolveInstrumentToken,
  fetchFuturesLTP,
  fetchOptionLTP
};
/* =========================================
   PART 5/6 — CANDLES + RSI + ATR + LTP
   ========================================= */

/* ===============================
   HISTORICAL CANDLES
   =============================== */
async function fetchCandles(symbol, interval, days = 1) {
  try {
    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;

    const payload = {
      exchange: "NSE",
      tradingsymbol: symbol,
      symboltoken: "",
      interval,
      fromdate: moment()
        .subtract(days, "days")
        .format("YYYY-MM-DD 09:15"),
      todate: moment().format("YYYY-MM-DD 15:30")
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const j = await r.json().catch(() => null);
    if (!Array.isArray(j?.data)) return [];

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

/* ===============================
   RECENT CANDLES (WS + REST)
   =============================== */
async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    if (interval === 1 && realtime.candles1m?.[symbol]) {
      return realtime.candles1m[symbol].slice(-limit);
    }

    const map = {
      1: "ONE_MINUTE",
      5: "FIVE_MINUTE"
    };

    const candles = await fetchCandles(
      symbol,
      map[interval] || "ONE_MINUTE",
      Math.ceil(limit / interval)
    );

    return candles.slice(-limit);
  } catch {
    return [];
  }
}

/* ===============================
   RSI
   =============================== */
function computeRSI(closes, period = 14) {
  try {
    if (!Array.isArray(closes) || closes.length <= period) return null;

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
  } catch {
    return null;
  }
}

/* ===============================
   ATR
   =============================== */
async function computeATR(symbol, interval = 1, period = 14) {
  try {
    const candles = await fetchRecentCandles(symbol, interval, period + 1);
    if (candles.length < 2) return 0;

    let sum = 0;
    for (let i = 1; i < candles.length; i++) {
      const c = candles[i];
      const p = candles[i - 1];
      sum += Math.max(
        c.high - c.low,
        Math.abs(c.high - p.close),
        Math.abs(c.low - p.close)
      );
    }
    return sum / (candles.length - 1);
  } catch {
    return 0;
  }
}

/* ===============================
   INDEX SPOT LTP
   =============================== */
async function fetchLTP(symbol) {
  try {
    const tok = await resolveInstrumentToken(symbol, "", 0, "INDEX");
    if (!tok?.token) return null;

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": SMART_API_KEY,
          Authorization: session.access_token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          exchange: tok.instrument.exchange || "NSE",
          tradingsymbol: tok.instrument.tradingsymbol,
          symboltoken: tok.token
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || 0);
    return ltp || null;
  } catch {
    return null;
  }
}

/* ===============================
   EXPORTS
   =============================== */
module.exports = {
  fetchCandles,
  fetchRecentCandles,
  computeRSI,
  computeATR,
  fetchLTP
};
/* =========================================
   PART 6/6 — API + ENTRY ENGINE + SERVER
   ========================================= */

/* ===============================
   ENTRY ENGINE
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
  const trend = hybridTrendEngine({
    ema20,
    ema50,
    vwap,
    rsi,
    spot,
    lastSpot
  });

  if (trend.direction === "NEUTRAL") {
    return {
      allowed: false,
      reason: "NO_CLEAR_TREND",
      trend
    };
  }

  const strikes = generateStrikes(market, spot, expiry_days);
  const type = trend.direction === "UP" ? "CE" : "PE";

  const entryLTP = await fetchOptionLTP(
    market,
    strikes.atm,
    type,
    expiry_days
  );

  if (!entryLTP) {
    return {
      allowed: false,
      reason: "OPTION_LTP_NOT_AVAILABLE",
      retryAfter: 1
    };
  }

  const levels = computeTargetsAndSL(entryLTP);

  return {
    allowed: true,
    direction: trend.direction,
    optionType: type,
    strike: strikes.atm,
    entryLTP,
    stopLoss: levels.stopLoss,
    target1: levels.target1,
    target2: levels.target2,
    trend
  };
}

/* ===============================
   API: SPOT
   =============================== */
app.get("/api/spot", async (req, res) => {
  try {
    const market = String(req.query.market || "NIFTY").toUpperCase();

    if (
      lastKnown.spot &&
      Date.now() - lastKnown.updatedAt < 5000
    ) {
      return res.json({
        success: true,
        source: "CACHE",
        spot: lastKnown.spot
      });
    }

    let spot = null;

    if (market === "NATURALGAS") {
      spot = await fetchFuturesLTP("NATURALGAS");
    } else {
      const map = {
        NIFTY: "NIFTY 50",
        SENSEX: "SENSEX"
      };
      spot = await fetchLTP(map[market] || market);
    }

    if (!spot) {
      return res.json({
        success: false,
        error: "SPOT_NOT_AVAILABLE"
      });
    }

    lastKnown.prevSpot = lastKnown.spot;
    lastKnown.spot = spot;
    lastKnown.updatedAt = Date.now();

    res.json({
      success: true,
      source: "LIVE",
      spot
    });
  } catch (e) {
    res.json({
      success: false,
      error: "SPOT_EXCEPTION",
      detail: e.message
    });
  }
});

/* ===============================
   API: TOKEN RESOLVE
   =============================== */
app.get("/api/token/resolve", async (req, res) => {
  try {
    const market = String(req.query.market || "");
    const strike = Number(req.query.strike || 0);
    const type = String(req.query.type || "CE");

    const exp = detectExpiryForSymbol(market).currentWeek;
    const tok = await resolveInstrumentToken(
      market,
      exp,
      strike,
      type
    );

    if (!tok) {
      return res.json({
        success: false,
        error: "TOKEN_NOT_FOUND"
      });
    }

    res.json({
      success: true,
      token: tok
    });
  } catch (e) {
    res.json({
      success: false,
      error: "EXCEPTION",
      detail: e.message
    });
  }
});

/* ===============================
   API: CALC (MAIN ENTRY)
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
    } = req.body || {};

    let finalSpot = Number(spot);

    if (!finalSpot || !isFinite(finalSpot)) {
      const fb = await fetchLTP(market);
      if (!fb) {
        return res.json({
          success: false,
          error: "SPOT_UNAVAILABLE"
        });
      }
      finalSpot = fb;
    }

    const entry = await computeEntry({
      market,
      spot: finalSpot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot: lastKnown.prevSpot
    });

    lastKnown.prevSpot = finalSpot;

    res.json({
      success: true,
      entry
    });
  } catch (e) {
    console.error("❌ CALC ERROR", e);
    res.json({
      success: false,
      error: "CALC_EXCEPTION",
      detail: e.message
    });
  }
});

/* ===============================
   API: PING
   =============================== */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    ws: wsStatus.connected,
    spot: lastKnown.spot
  });
});

/* ===============================
   FALLBACK ROOT
   =============================== */
app.get("*", (req, res) => {
  res.send("Rahul Backend OK — Render Safe 🚀");
});

/* ===============================
   START SERVER
   =============================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("✅ SERVER RUNNING ON PORT", PORT);
});
