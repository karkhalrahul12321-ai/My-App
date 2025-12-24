/* ================================
   PART 1/6 — BASE + CONFIG + LOGIN
================================ */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

/* ================================
   GLOBAL MASTER (ONLINE)
================================ */
global.instrumentMaster = [];

/* ===== GLOBAL HELPERS ===== */
global.tsof = function (entry) {
  return String(
    entry?.tradingsymbol ||
    entry?.symbol ||
    entry?.name ||
    ""
  ).toUpperCase();
};

function isTokenSane(t) {
  if (!t && t !== 0) return false;
  const n = Number(String(t).replace(/\D/g, ""));
  return n > 0;
}

/* ================================
   LOAD INSTRUMENT MASTER
================================ */
async function loadMasterOnline() {
  try {
    const url =
      "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
    const r = await fetch(url);
    const j = await r.json().catch(() => []);
    if (Array.isArray(j) && j.length) {
      global.instrumentMaster = j;
      console.log("✅ MASTER LOADED:", j.length);
    }
  } catch (e) {
    console.log("❌ MASTER LOAD ERROR:", e.message);
  }
}

loadMasterOnline();
setInterval(loadMasterOnline, 60 * 60 * 1000);

/* ================================
   EXPRESS APP
================================ */
const app = express();
app.use(cors());
app.use(bodyParser.json());

/* ================================
   STATIC FRONTEND
================================ */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (_, res) =>
  res.sendFile(path.join(frontendPath, "index.html"))
);

/* ================================
   SMARTAPI ENV
================================ */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE ||
  "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* ================================
   SESSION MEMORY (CLEAN)
================================ */
const session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: 0
};

/* ================================
   SPOT MEMORY (FIXED STRUCTURE)
================================ */
const lastKnown = {
  spot: null,          // common (calc fallback)
  prevSpot: null,
  updatedAt: 0,

  nifty: {},
  sensex: {},
  ng: {}
};

/* ================================
   BASE32 + TOTP
================================ */
function base32Decode(input) {
  if (!input) return Buffer.from([]);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, out = [];

  input = input.replace(/=+$/, "").toUpperCase();
  for (let c of input) {
    const idx = alphabet.indexOf(c);
    if (idx < 0) continue;
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

    return String(code % 1000000).padStart(6, "0");
  } catch {
    return null;
  }
}

/* ================================
   SMARTAPI LOGIN
================================ */
async function smartApiLogin(password) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!password) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

    const r = await fetch(
      `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-UserType": "USER",
          "X-SourceID": "WEB",
          "X-PrivateKey": SMART_API_KEY
        },
        body: JSON.stringify({
          clientcode: SMART_USER_ID,
          password,
          totp
        })
      }
    );

    const j = await r.json().catch(() => null);
    if (!j || j.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: j };
    }

    const d = j.data || {};
    session.access_token = d.jwtToken;
    session.refresh_token = d.refreshToken;
    session.feed_token = d.feedToken;
    session.login_time = Date.now();
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "EXCEPTION", error: e.message };
  }
}

/* ================================
   LOGIN ROUTES
================================ */
app.post("/api/login", async (req, res) => {
  const r = await smartApiLogin(req.body?.password || "");
  res.json(r.ok ? { success: true } : { success: false, error: r.reason });
});

app.get("/api/login/status", (_, res) => {
  res.json({
    logged_in: !!session.access_token,
    expires_at: session.expires_at
  });
});

/* ================================
   EXPORT (FOR NEXT PARTS)
================================ */
module.exports = {
  app,
  session,
  lastKnown,
  smartApiLogin,
  generateTOTP,
  isTokenSane
};
/* ================================
   PART 2/6 — WEBSOCKET + SPOT
================================ */

const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";

let wsClient = null;
let wsHeartbeat = null;

const wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

/* ================================
   REALTIME STORES
================================ */
const realtime = {
  ticks: {},
  candles1m: {}
};

// OPTION WS
const optionWsTokens = new Set();
const optionLTP = {};
let optionWsReady = false;

/* ================================
   START WS
================================ */
function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;
  if (!session.access_token || !session.feed_token) {
    console.log("⏳ WS waiting for login...");
    return;
  }

  wsClient = new WebSocket(WS_URL, {
    headers: {
      Authorization: session.access_token,
      "x-api-key": process.env.SMART_API_KEY,
      "x-client-code": process.env.SMART_USER_ID,
      "x-feed-token": session.feed_token
    }
  });

  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.reconnectAttempts = 0;
    wsStatus.lastError = null;
    console.log("🟢 WS CONNECTED");

    wsClient.send(JSON.stringify({
      task: "auth",
      channel: "websocket",
      token: session.feed_token,
      user: process.env.SMART_USER_ID,
      apikey: process.env.SMART_API_KEY,
      source: "API"
    }));

    setTimeout(subscribeCoreTokens, 1000);

    if (wsHeartbeat) clearInterval(wsHeartbeat);
    wsHeartbeat = setInterval(() => {
      try {
        wsClient.send("ping");
      } catch {}
    }, 30000);
  });

  wsClient.on("message", handleWsMessage);
  wsClient.on("error", handleWsError);
  wsClient.on("close", handleWsClose);
}

/* ================================
   WS MESSAGE HANDLER
================================ */
function handleWsMessage(raw) {
  wsStatus.lastMsgAt = Date.now();
  let msg;

  try {
    msg = JSON.parse(raw);
  } catch {
    return;
  }

  const d = msg.data || msg;
  if (!d) return;

  const token =
    d.token ||
    d.instrument_token ||
    d.instrumentToken;

  const ltp = Number(
    d.ltp ??
    d.last_traded_price ??
    d.lastPrice ??
    d.price ??
    0
  );

  const symbol =
    d.tradingsymbol ||
    d.symbol ||
    "";

  if (!token || !ltp) return;

  /* ================================
     OPTION LTP STORE
  ================================ */
  optionLTP[token] = {
    ltp,
    symbol,
    time: Date.now()
  };
  optionWsReady = true;

  /* ================================
     TICKS
  ================================ */
  if (symbol) {
    realtime.ticks[symbol] = {
      ltp,
      time: Date.now()
    };
  }

  /* ================================
     SPOT UPDATE (FIXED)
  ================================ */
  const ts = symbol.toUpperCase();
  const itype = String(d.instrumenttype || d.instrumentType || "").toUpperCase();

  if (itype.includes("INDEX") && ltp) {
    lastKnown.spot = ltp;
    lastKnown.updatedAt = Date.now();

    if (ts.includes("NIFTY")) {
      lastKnown.nifty.spot = ltp;
      lastKnown.nifty.updatedAt = Date.now();
    }

    if (ts.includes("SENSEX")) {
      lastKnown.sensex.spot = ltp;
      lastKnown.sensex.updatedAt = Date.now();
    }
  }

  if (itype.includes("FUT") && ts.includes("NATURAL")) {
    lastKnown.ng.spot = ltp;
    lastKnown.ng.updatedAt = Date.now();
    lastKnown.spot = ltp;
    lastKnown.updatedAt = Date.now();
  }

  /* ================================
     1-MIN CANDLES
  ================================ */
  if (!symbol) return;

  if (!realtime.candles1m[symbol]) {
    realtime.candles1m[symbol] = [];
  }

  const arr = realtime.candles1m[symbol];
  const now = Date.now();
  const minute = Math.floor(now / 60000) * 60000;
  let cur = arr[arr.length - 1];

  if (!cur || cur.time !== minute) {
    arr.push({
      time: minute,
      open: ltp,
      high: ltp,
      low: ltp,
      close: ltp,
      volume: d.volume || 0
    });
    if (arr.length > 200) arr.shift();
  } else {
    cur.high = Math.max(cur.high, ltp);
    cur.low = Math.min(cur.low, ltp);
    cur.close = ltp;
  }
}

/* ================================
   WS ERROR / CLOSE
================================ */
function handleWsError(err) {
  wsStatus.connected = false;
  wsStatus.lastError = String(err);
  scheduleReconnect();
}

function handleWsClose(code) {
  wsStatus.connected = false;
  wsStatus.lastError = "CLOSED:" + code;
  scheduleReconnect();
}

function scheduleReconnect() {
  wsStatus.reconnectAttempts++;
  const delay = Math.min(
    30000,
    1000 * Math.pow(1.5, wsStatus.reconnectAttempts)
  );

  setTimeout(() => {
    try { wsClient?.terminate(); } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, delay);
}

/* ================================
   SUBSCRIBE TOKENS
================================ */
function subscribeCoreTokens() {
  if (!wsClient || !wsStatus.connected) return;

  const tokens = [];

  for (const t of optionWsTokens) {
    if (isTokenSane(t)) tokens.push(String(t));
  }

  if (!tokens.length) return;

  wsClient.send(JSON.stringify({
    task: "cn",
    channel: {
      instrument_tokens: tokens,
      feed_type: "ltp"
    }
  }));

  wsStatus.subscriptions = tokens;
  console.log("📡 WS SUBSCRIBED:", tokens.length);
}

/* ================================
   AUTO START AFTER LOGIN
================================ */
const _origLogin = smartApiLogin;
smartApiLogin = async function (pw) {
  const r = await _origLogin(pw);
  if (r?.ok) setTimeout(startWebsocketIfReady, 1200);
  return r;
};

/* ================================
   EXPORTS
================================ */
module.exports.ws = {
  startWebsocketIfReady,
  optionWsTokens,
  optionLTP,
  wsStatus,
  realtime
};
/* ================================
   PART 3/6 — TREND ENGINE
================================ */

/* ================================
   SAFE NUMBER
================================ */
function safeNum(n) {
  n = Number(n);
  return Number.isFinite(n) ? n : 0;
}

/* ================================
   BASIC TREND (EMA / VWAP)
================================ */
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

/* ================================
   MOMENTUM (SPOT VS PREV)
================================ */
function computeMomentumTrend(spot, prevSpot) {
  spot = safeNum(spot);
  prevSpot = safeNum(prevSpot);

  if (!prevSpot) return { momentum: "NEUTRAL", slope: 0 };

  const diff = spot - prevSpot;

  if (diff > 3) return { momentum: "UP", slope: diff };
  if (diff < -3) return { momentum: "DOWN", slope: diff };

  return { momentum: "NEUTRAL", slope: diff };
}

/* ================================
   RSI GATE
================================ */
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);

  if (direction === "UP") return rsi > 50;
  if (direction === "DOWN") return rsi < 40;

  return false;
}

/* ================================
   HYBRID TREND ENGINE
================================ */
function hybridTrendEngine({
  ema20,
  ema50,
  vwap,
  rsi,
  spot,
  lastSpot
}) {
  const base = computeBasicTrend(ema20, ema50, vwap, spot);
  const momentum = computeMomentumTrend(spot, lastSpot);
  const rsiOk = rsiTrendGate(rsi, base.direction);

  let score = base.score;

  if (momentum.momentum === "UP") score++;
  if (momentum.momentum === "DOWN") score--;

  // RSI soft penalty
  if (!rsiOk && Math.abs(score) > 0) {
    score = Math.sign(score) * (Math.abs(score) - 1);
  }

  let direction = "NEUTRAL";
  if (score >= 2) direction = "UP";
  if (score <= -2) direction = "DOWN";

  return {
    direction,
    score,
    base,
    momentum,
    rsiOk
  };
}

/* ================================
   TRIPLE CONFIRM — TREND
================================ */
async function tripleConfirmTrend(trendObj, symbol, getCandlesFn) {
  const score = Math.abs(trendObj.score || 0);
  if (score >= 3) return { trendConfirmed: true };

  try {
    const candles =
      typeof getCandlesFn === "function"
        ? await getCandlesFn(symbol, 1, 30)
        : [];

    const closes = candles.map(c => Number(c.close)).filter(Boolean);
    if (closes.length < 15) {
      return { trendConfirmed: score >= 2 };
    }

    const rsi = computeRSI(closes, 14);

    if (trendObj.direction === "UP" && rsi > 50 && score >= 2)
      return { trendConfirmed: true };

    if (trendObj.direction === "DOWN" && rsi < 40 && score >= 2)
      return { trendConfirmed: true };

    return { trendConfirmed: false };
  } catch {
    return { trendConfirmed: score >= 2 };
  }
}

/* ================================
   TRIPLE CONFIRM — MOMENTUM
================================ */
async function tripleConfirmMomentum(symbol, getCandlesFn) {
  try {
    const c1 = await getCandlesFn(symbol, 1, 12);
    if (!c1 || c1.length < 6) return { momentumConfirmed: false };

    const closes = c1.map(c => Number(c.close)).filter(Boolean);
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

/* ================================
   TRIPLE CONFIRM — VOLUME
================================ */
async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c5 = await getCandlesFn(symbol, 5, 12);
    const vols = c5.map(c => Number(c.volume || 0)).filter(v => v > 0);

    if (!vols.length) return { volumeConfirmed: false };

    const latest = vols[vols.length - 1];
    const avg = vols.reduce((a, b) => a + b, 0) / vols.length;

    return { volumeConfirmed: latest >= avg * 0.8 };
  } catch {
    return { volumeConfirmed: false };
  }
}

/* ================================
   FAKE BREAKOUT FILTER (FIXED)
================================ */
function rejectFakeBreakout(trendObj, futDiff) {
  if (!trendObj) return false;

  const strength = Math.abs(trendObj.score || 0);

  // weak trend → don't block
  if (strength < 2) return false;

  // future mismatch → block
  if (futDiff && Math.abs(futDiff) > 200) return true;

  return false;
}

/* ================================
   FINAL ENTRY GUARD
================================ */
async function finalEntryGuard({
  symbol,
  trendObj,
  futDiff,
  getCandlesFn
}) {
  const t = await tripleConfirmTrend(trendObj, symbol, getCandlesFn);
  const m = await tripleConfirmMomentum(symbol, getCandlesFn);
  const v = await tripleConfirmVolume(symbol, getCandlesFn);

  const pass =
    (t.trendConfirmed ? 1 : 0) +
    (m.momentumConfirmed ? 1 : 0) +
    (v.volumeConfirmed ? 1 : 0);

  if (pass === 0) {
    return { allowed: false, reason: "NO_CONFIRMATION", details: { t, m, v } };
  }

  if (rejectFakeBreakout(trendObj, futDiff)) {
    return { allowed: false, reason: "FAKE_BREAKOUT", futDiff };
  }

  return {
    allowed: true,
    confirmations: pass,
    details: { t, m, v }
  };
}

/* ================================
   EXPORTS
================================ */
module.exports.trendEngine = {
  hybridTrendEngine,
  finalEntryGuard
};
/* ================================
   PART 4/6 — TOKEN + LTP
================================ */

function itypeOf(entry) {
  return String(
    entry.instrumenttype ||
    entry.instrumentType ||
    entry.type ||
    ""
  ).toUpperCase();
}

function parseExpiryDate(v) {
  if (!v) return null;
  const d = new Date(v);
  return isFinite(d.getTime()) ? d : null;
}

/* ================================
   EXPIRY DETECTOR
================================ */
function detectExpiryForSymbol(symbol) {
  symbol = String(symbol || "").toUpperCase();
  const today = moment();

  let weeklyDay = 4; // Thu
  if (symbol.includes("NIFTY")) weeklyDay = 2;
  if (symbol.includes("SENSEX")) weeklyDay = 2;

  let weekly = today.clone().day(weeklyDay);
  if (weekly.isBefore(today, "day")) weekly.add(1, "week");

  let monthly = today.clone().endOf("month");
  while (monthly.day() !== weeklyDay) monthly.subtract(1, "day");

  return {
    currentWeek: weekly.format("YYYY-MM-DD"),
    monthly: monthly.format("YYYY-MM-DD")
  };
}

/* ================================
   STRIKE STEP
================================ */
function getStrikeStep(market) {
  market = String(market).toUpperCase();
  if (market.includes("NIFTY")) return 50;
  if (market.includes("SENSEX")) return 100;
  if (market.includes("NATURAL")) return 5;
  return 50;
}

/* ================================
   TOKEN RESOLVER (SINGLE SOURCE)
================================ */
async function resolveInstrumentToken(
  symbol,
  expiry = "",
  strike = 0,
  type = "INDEX"
) {
  if (!Array.isArray(global.instrumentMaster) || !global.instrumentMaster.length)
    return null;

  symbol = String(symbol).toUpperCase();
  type = String(type).toUpperCase();
  strike = Number(strike || 0);

  const key = symbol.replace(/\s+/g, "");
  let list = global.instrumentMaster.filter(it =>
    global.tsof(it).includes(key)
  );

  if (!list.length) return null;

  /* ================================
     INDEX
  ================================ */
  if (type === "INDEX") {
    const idx = list.find(it =>
      itypeOf(it).includes("INDEX") && isTokenSane(it.token)
    );
    return idx ? { instrument: idx, token: String(idx.token) } : null;
  }

  /* ================================
     FUTURES (NEAREST EXPIRY)
  ================================ */
  if (type === "FUT") {
    const futs = list
      .filter(it => itypeOf(it).includes("FUT") && isTokenSane(it.token))
      .map(it => ({
        it,
        diff: Math.abs(
          (parseExpiryDate(it.expiry) || 0) - Date.now()
        )
      }))
      .sort((a, b) => a.diff - b.diff);

    if (!futs.length) return null;
    return { instrument: futs[0].it, token: String(futs[0].it.token) };
  }

  /* ================================
     OPTIONS (CE / PE)
  ================================ */
  if (type === "CE" || type === "PE") {
    const step = getStrikeStep(symbol);
    const approxStrike = Math.round(strike / step) * step;

    const opts = list.filter(it => {
      const itype = itypeOf(it);
      const ts = global.tsof(it);
      let st = Number(it.strike || it.strikePrice || 0);

      // normalize Angel strike scale
      if (st > 100000) st = Math.round(st / 100);

      return (
        itype.includes("OPT") &&
        ts.includes(type) &&
        Math.abs(st - approxStrike) <= step &&
        isTokenSane(it.token)
      );
    });

    if (!opts.length) return null;

    opts.sort((a, b) => {
      const ea = parseExpiryDate(a.expiry) || 0;
      const eb = parseExpiryDate(b.expiry) || 0;
      return ea - eb;
    });

    const pick = opts[0];

    // WS subscribe
    optionWsTokens.add(String(pick.token));
    if (wsStatus.connected) subscribeCoreTokens();

    return { instrument: pick, token: String(pick.token) };
  }

  return null;
}

/* ================================
   FUTURE LTP
================================ */
async function fetchFuturesLTP(symbol) {
  const exp = detectExpiryForSymbol(symbol).currentWeek;
  const tok = await resolveInstrumentToken(symbol, exp, 0, "FUT");
  if (!tok) return null;

  const r = await fetch(
    `${process.env.SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
    {
      method: "POST",
      headers: {
        "X-PrivateKey": process.env.SMART_API_KEY,
        Authorization: session.access_token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        exchange: tok.instrument.exchange,
        tradingsymbol: tok.instrument.tradingsymbol,
        symboltoken: tok.token
      })
    }
  );

  const j = await r.json().catch(() => null);
  const ltp = Number(j?.data?.ltp || 0);
  return ltp > 0 ? ltp : null;
}

/* ================================
   OPTION LTP (WS → REST)
================================ */
async function fetchOptionLTP(symbol, strike, type) {
  const exp = detectExpiryForSymbol(symbol).currentWeek;
  const tok = await resolveInstrumentToken(symbol, exp, strike, type);
  if (!tok) return null;

  const wsHit = optionLTP[tok.token];
  if (wsHit?.ltp > 0) return wsHit.ltp;

  const r = await fetch(
    `${process.env.SMARTAPI_BASE}/rest/secure/angelbroking/market/v1/quote`,
    {
      method: "POST",
      headers: {
        "X-PrivateKey": process.env.SMART_API_KEY,
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        mode: "LTP",
        exchangeTokens: {
          [tok.instrument.exchange]: [tok.token]
        }
      })
    }
  );

  const j = await r.json().catch(() => null);
  const ltp = Number(j?.data?.fetched?.[0]?.ltp || 0);
  return ltp > 0 ? ltp : null;
}

/* ================================
   EXPORTS
================================ */
module.exports.marketData = {
  resolveInstrumentToken,
  fetchFuturesLTP,
  fetchOptionLTP,
  detectExpiryForSymbol
};
/* ================================
   PART 5/6 — CANDLES + INDICATORS
================================ */

/* ================================
   FETCH HISTORICAL CANDLES
================================ */
async function fetchCandles(symbol, interval, days = 1) {
  try {
    const url =
      `${process.env.SMARTAPI_BASE}/rest/secure/angelbroking/historical/v1/getCandleData`;

    const payload = {
      exchange: "NSE",
      symboltoken: "",
      interval,
      fromdate: moment()
        .subtract(days, "days")
        .format("YYYY-MM-DD 09:15"),
      todate: moment().format("YYYY-MM-DD 15:30"),
      tradingsymbol: symbol
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "X-PrivateKey": process.env.SMART_API_KEY,
        Authorization: session.access_token,
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

/* ================================
   FETCH RECENT CANDLES (WS + REST)
================================ */
async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    if (
      interval === 1 &&
      realtime.candles1m &&
      realtime.candles1m[symbol]
    ) {
      return realtime.candles1m[symbol].slice(-limit);
    }

    const intv =
      interval === 1
        ? "ONE_MINUTE"
        : interval === 5
        ? "FIVE_MINUTE"
        : "FIFTEEN_MINUTE";

    const days = Math.ceil(limit / (interval === 1 ? 300 : 60));
    const data = await fetchCandles(symbol, intv, days);
    return data.slice(-limit);
  } catch {
    return [];
  }
}

/* ================================
   RSI (14)
================================ */
function computeRSI(closes, period = 14) {
  if (!closes || closes.length < period + 1) return null;

  let gains = 0;
  let losses = 0;

  for (let i = 1; i <= period; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff > 0) gains += diff;
    else losses -= diff;
  }

  if (!losses) return 100;

  const rs = gains / losses;
  return 100 - 100 / (1 + rs);
}

/* ================================
   ATR
================================ */
async function computeATR(symbol, interval = 1, period = 14) {
  const candles = await fetchRecentCandles(
    symbol,
    interval,
    period + 1
  );

  if (!candles || candles.length < 2) return 0;

  const trs = [];

  for (let i = 1; i < candles.length; i++) {
    const c = candles[i];
    const p = candles[i - 1];

    const tr = Math.max(
      c.high - c.low,
      Math.abs(c.high - p.close),
      Math.abs(c.low - p.close)
    );

    trs.push(tr);
  }

  if (!trs.length) return 0;
  return trs.reduce((a, b) => a + b, 0) / trs.length;
}

/* ================================
   EXPORTS
================================ */
module.exports.indicators = {
  fetchCandles,
  fetchRecentCandles,
  computeRSI,
  computeATR
};
/* ================================
   PART 6/6 — API + ENTRY + SERVER
================================ */

const {
  hybridTrendEngine,
  finalEntryGuard
} = require("./trendEngine")?.trendEngine || module.exports.trendEngine;

const {
  resolveInstrumentToken,
  fetchFuturesLTP,
  fetchOptionLTP,
  detectExpiryForSymbol
} = require("./marketData")?.marketData || module.exports.marketData;

const {
  fetchRecentCandles,
  computeRSI,
  computeATR
} = require("./indicators")?.indicators || module.exports.indicators;

/* ================================
   SPOT API
================================ */
app.get("/api/spot", async (req, res) => {
  const market = String(req.query.market || "NIFTY").toUpperCase();

  // WS priority
  if (
    lastKnown.spot &&
    Date.now() - lastKnown.updatedAt < 5000
  ) {
    return res.json({
      success: true,
      source: "WS",
      spot: lastKnown.spot
    });
  }

  // REST fallback (INDEX)
  try {
    const idx = await resolveInstrumentToken(market, "", 0, "INDEX");
    if (!idx) {
      return res.json({ success: false, error: "TOKEN_NOT_FOUND" });
    }

    const r = await fetch(
      `${process.env.SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`,
      {
        method: "POST",
        headers: {
          "X-PrivateKey": process.env.SMART_API_KEY,
          Authorization: session.access_token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          exchange: idx.instrument.exchange,
          tradingsymbol: idx.instrument.tradingsymbol,
          symboltoken: idx.token
        })
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || 0);

    if (!ltp) {
      return res.json({ success: false, error: "SPOT_NOT_AVAILABLE" });
    }

    lastKnown.spot = ltp;
    lastKnown.updatedAt = Date.now();

    return res.json({
      success: true,
      source: "REST",
      spot: ltp
    });
  } catch (e) {
    return res.json({
      success: false,
      error: "SPOT_EXCEPTION",
      detail: e.message
    });
  }
});

/* ================================
   TOKEN RESOLVE API
================================ */
app.get("/api/token/resolve", async (req, res) => {
  const market = String(req.query.market || "");
  const strike = Number(req.query.strike || 0);
  const type = String(req.query.type || "CE");

  const expiry = detectExpiryForSymbol(market).currentWeek;
  const tok = await resolveInstrumentToken(market, expiry, strike, type);

  if (!tok) {
    return res.json({ success: false, error: "TOKEN_NOT_FOUND" });
  }

  res.json({ success: true, token: tok });
});

/* ================================
   MAIN ENTRY ENGINE
================================ */
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

  const futLTP = await fetchFuturesLTP(market);
  const futDiff =
    futLTP && spot ? Number(futLTP) - Number(spot) : null;

  const guard = await finalEntryGuard({
    symbol: market,
    trendObj,
    futDiff,
    getCandlesFn: fetchRecentCandles
  });

  if (!guard.allowed) {
    return {
      allowed: false,
      reason: guard.reason,
      trend: trendObj,
      futDiff,
      details: guard.details || {}
    };
  }

  const step =
    market.includes("NIFTY") ? 50 :
    market.includes("SENSEX") ? 100 : 50;

  const atm = Math.round(spot / step) * step;

  const ceATM = await fetchOptionLTP(market, atm, "CE");
  const peATM = await fetchOptionLTP(market, atm, "PE");

  const direction = trendObj.direction;
  const entryLTP =
    direction === "UP" ? ceATM :
    direction === "DOWN" ? peATM :
    null;

  if (!entryLTP) {
    return {
      allowed: false,
      reason: "OPTION_LTP_PENDING",
      trend: trendObj
    };
  }

  const stopLoss = Number((entryLTP * 0.85).toFixed(2));
  const target1  = Number((entryLTP * 1.10).toFixed(2));
  const target2  = Number((entryLTP * 1.20).toFixed(2));

  return {
    allowed: true,
    direction,
    strike: atm,
    option: direction === "UP" ? "CE" : "PE",
    entryLTP,
    stopLoss,
    target1,
    target2,
    trend: trendObj,
    confirmations: guard.confirmations
  };
}

/* ================================
   CALC API
================================ */
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

    let finalSpot = Number(spot);

    if (!finalSpot || !isFinite(finalSpot)) {
      if (lastKnown.spot) {
        finalSpot = lastKnown.spot;
      } else {
        return res.json({
          success: false,
          error: "SPOT_NOT_AVAILABLE"
        });
      }
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

    res.json({ success: true, entry });
  } catch (e) {
    res.json({
      success: false,
      error: "CALC_EXCEPTION",
      detail: e.message
    });
  }
});

/* ================================
   HEALTH / PING
================================ */
app.get("/api/ping", (_, res) => {
  res.json({
    success: true,
    time: Date.now(),
    ws: wsStatus.connected,
    spot: lastKnown.spot || null
  });
});

/* ================================
   SERVER START
================================ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 SERVER LIVE ON PORT", PORT);
});
