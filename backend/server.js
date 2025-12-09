/* -------------------------------------------------------------
   RAHUL FINAL BACKEND — LIVE ENABLED (WITH WEBSOCKET)
   PART 1 / X — BASE IMPORTS + CONFIG + SESSION
-------------------------------------------------------------- */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");

/* ------------------------------------------------------------
   SERVE FRONTEND
------------------------------------------------------------ */
const app = express();
app.use(cors());
app.use(bodyParser.json());

const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")));
app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* -------------------------------------------------------------
   SMARTAPI ENV + GLOBAL SESSION
-------------------------------------------------------------- */
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP_SECRET || "";

const SMARTAPI_BASE = "https://apiconnect.angelone.in";

/* ------------ SESSION (ACCESS + FEED TOKEN) ----------------- */
const session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  login_time: null
};

/* ------------ LAST KNOWN LIVE VALUES ------------------------ */
const lastKnown = {
  spot: null,
  updatedAt: null,
  future: null,
  futureUpdatedAt: null
};

/* ------------ BASIC SAFE HELPERS ---------------------------- */
function safeNum(v, def = 0) {
  v = Number(v);
  return isFinite(v) ? v : def;
}

/* -------------------------------------------------------------
   TOTP GENERATOR (FIXED — using correct base32 method)
-------------------------------------------------------------- */
const { generateTOTP } = require("./totp");   // ✅ FIXED (अब सही base32 OTP बनेगा)
/* -------------------------------------------------------------
   SMARTAPI LOGIN FUNCTION
-------------------------------------------------------------- */
async function smartApiLogin(password) {
  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);
    if (!totp) {
      return { ok: false, error: "TOTP generation failed" };
    }

    const url = `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-PrivateKey": SMART_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        clientcode: SMART_USER_ID,
        password,
        totp
      })
    });

    const j = await response.json().catch(() => null);

    if (!j || !j.status || !j.data) {
      return { ok: false, error: "Invalid login response" };
    }

    session.access_token = j.data.jwtToken;
    session.refresh_token = j.data.refreshToken;
    session.feed_token = j.data.feedToken;
    session.login_time = Date.now();

    console.log("LOGIN OK — FEED TOKEN READY");
    return { ok: true, tokens: j.data };

  } catch (e) {
    console.log("LOGIN FAIL", e);
    return { ok: false, error: String(e) };
  }
}

/* -------------------------------------------------------------
   API: LOGIN ENDPOINT
-------------------------------------------------------------- */
app.post("/api/login", async (req, res) => {
  try {
    const pw = req.body.password || "";
    const r = await smartApiLogin(pw);

    if (!r.ok) {
      return res.json({
        success: false,
        error: r.error || "LOGIN_FAILED"
      });
    }

    return res.json({
      success: true,
      tokens: r.tokens
    });

  } catch (e) {
    res.json({ success: false, error: "LOGIN_EXCEPTION" });
  }
});

/* -------------------------------------------------------------
   API: LOGIN STATUS
-------------------------------------------------------------- */
app.get("/api/login/status", (req, res) => {
  res.json({
    logged_in: !!session.access_token,
    feed_token: !!session.feed_token,
    login_time: session.login_time
  });
});
/* -------------------------------------------------------------
   LIVE WEBSOCKET (Angel SmartAPI)
   - Uses session.feed_token + session.access_token
   - Auto-starts after login
   - Updates real-time spot into lastKnown.spot
-------------------------------------------------------------- */

const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";
let wsClient = null;

let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

// minimal live caches
const realtime = {
  ticks: {},
  candles1m: {}
};

/* -------------------------------------------------------------
   START WEBSOCKET WHEN TOKENS ARE READY
-------------------------------------------------------------- */
async function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;

  if (!session.feed_token || !session.access_token) {
    console.log("WS: waiting for login tokens...");
    return;
  }

  try {
    wsClient = new WebSocket(WS_URL, { perMessageDeflate: false });

    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;

      console.log("WS: connected.");

      // AUTH
      const auth = {
        task: "auth",
        token: session.feed_token,
        jwt: session.access_token
      };

      try { wsClient.send(JSON.stringify(auth)); }
      catch(e){ console.log("WS AUTH SEND ERR", e); }

      // subscribe after 1 second
      setTimeout(() => subscribeCoreSymbols(), 1000);
    });

    wsClient.on("message", (raw) => {
      wsStatus.lastMsgAt = Date.now();
      let msg = null;

      try { msg = JSON.parse(raw); }
      catch { return; }

      if (!msg || !msg.data) return;

      const d = msg.data;

      const token = d.token || d.instrument_token || null;
      const ltp   = Number(d.ltp || d.lastPrice || d.price || 0) || null;

      if (ltp != null) {
        const sym = d.tradingsymbol || d.symbol || null;

        if (sym) {
          realtime.ticks[sym] = { ltp, oi: d.oi || 0, time: Date.now() };

          lastKnown.spot = ltp;
          lastKnown.updatedAt = Date.now();
        }
      }

      /* --------- 1-MIN CANDLE BUILDER ---------- */
      try {
        const sym = d.tradingsymbol || d.symbol;
        if (!sym || ltp == null) return;

        if (!realtime.candles1m[sym]) realtime.candles1m[sym] = [];

        const arr = realtime.candles1m[sym];
        const now = Date.now();
        const curMin = Math.floor(now / 60000) * 60000;

        let cur = arr.length ? arr[arr.length - 1] : null;

        if (!cur || cur.time !== curMin) {
          const newC = {
            time: curMin,
            open: ltp,
            high: ltp,
            low: ltp,
            close: ltp,
            volume: d.volume || 0
          };
          arr.push(newC);
          if (arr.length > 180) arr.shift();
        } else {
          cur.high = Math.max(cur.high, ltp);
          cur.low  = Math.min(cur.low, ltp);
          cur.close = ltp;
        }
      } catch {}
    });

    wsClient.on("close", (code) => {
      wsStatus.connected = false;
      wsStatus.lastError = "closed:" + code;
      console.log("WS CLOSED", code);
      scheduleWSReconnect();
    });

    wsClient.on("error", (e) => {
      wsStatus.connected = false;
      wsStatus.lastError = String(e);
      console.log("WS ERR", e);
      scheduleWSReconnect();
    });

  } catch (e) {
    wsStatus.connected = false;
    wsStatus.lastError = String(e);
    console.log("WS START ERR", e);
    scheduleWSReconnect();
  }
}

/* -------------------------------------------------------------
   RECONNECT LOGIC (SAFE)
-------------------------------------------------------------- */
function scheduleWSReconnect() {
  wsStatus.reconnectAttempts++;
  const backoff = Math.min(30000, 1000 * Math.pow(1.5, wsStatus.reconnectAttempts));

  setTimeout(() => {
    try { if (wsClient) wsClient.terminate(); } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, backoff);
}

/* -------------------------------------------------------------
   SUBSCRIBE TO CORE SYMBOLS
-------------------------------------------------------------- */
async function subscribeCoreSymbols() {
  try {
    const symbols = ["NIFTY", "SENSEX", "NATURALGAS"];
    const expiry = detectExpiryForSymbol("NIFTY").currentWeek;

    const tokens = [];

    for (let s of symbols) {
      const tok = await resolveInstrumentToken(s, expiry, 0, "FUT").catch(()=>null);
      if (tok && tok.token) tokens.push(String(tok.token));
    }

    if (tokens.length > 0) {
      const sub = {
        task: "cn",
        channel: { instrument_tokens: tokens, feed_type: "ltp" }
      };
      wsClient.send(JSON.stringify(sub));
      wsStatus.subscriptions = tokens;
      console.log("WS SUBSCRIBED →", tokens);
    }
  } catch (e) {
    console.log("WS SUBSCRIBE ERR", e);
  }
}

/* -------------------------------------------------------------
   WS STATUS ENDPOINT
-------------------------------------------------------------- */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions
  });
});

/* -------------------------------------------------------------
   AUTO START HOOK AFTER LOGIN
-------------------------------------------------------------- */
const _origSmartLogin = smartApiLogin;

smartApiLogin = async function(pw) {
  const r = await _origSmartLogin(pw);
  if (r && r.ok) {
    setTimeout(() => startWebsocketIfReady(), 1200);
  }
  return r;
};

/* -------------------------------------------------------------
   INITIAL DELAYED WS START
-------------------------------------------------------------- */
setTimeout(() => startWebsocketIfReady(), 2000);
/* -------------------------------------------------------------
   FETCH LTP (SPOT)
-------------------------------------------------------------- */
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

/* -------------------------------------------------------------
   FETCH FUTURES LTP
-------------------------------------------------------------- */
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
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({
        exchange: tokenInfo.instrument?.exchange || "NFO",
        tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
        symboltoken: tokenInfo.token || ""
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   RESOLVE INSTRUMENT TOKEN
-------------------------------------------------------------- */
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

/* -------------------------------------------------------------
   EXPIRY DETECTOR (WEEKLY)
-------------------------------------------------------------- */
function detectExpiryForSymbol(symbol) {
  try {
    const today = moment();
    let currentWeek = today.clone().weekday(4);

    if (today.weekday() > 4) {
      currentWeek = today.clone().add(1, "weeks").weekday(4);
    }

    const nextWeek = currentWeek.clone().add(1, "weeks").weekday(4);

    return {
      currentWeek: currentWeek.format("YYYY-MM-DD"),
      nextWeek: nextWeek.format("YYYY-MM-DD")
    };
  } catch {
    return {
      currentWeek: moment().format("YYYY-MM-DD"),
      nextWeek: moment().add(7, "days").format("YYYY-MM-DD")
    };
  }
}

/* -------------------------------------------------------------
   TREND ENGINE HELPERS
-------------------------------------------------------------- */
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

/* -------------------------------------------------------------
   RSI TREND GATE
-------------------------------------------------------------- */
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);

  if (direction === "DOWN") return rsi < 40;
  if (direction === "UP") return rsi > 50;
  return false;
}

/* -------------------------------------------------------------
   HYBRID TREND ENGINE
-------------------------------------------------------------- */
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
/* -------------------------------------------------------------
   TRIPLE CONFIRMATION (Trend + Momentum + Volume)
-------------------------------------------------------------- */

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
    } else if (trendObj.direction === "DOWN") {
      if (localRSI && localRSI < 40 && score < -1) return { trendConfirmed: true };
    }

    return { trendConfirmed: false };
  } catch {
    return { trendConfirmed: Math.abs(score) >= 2 };
  }
}

async function tripleConfirmMomentum(symbol, getCandlesFn) {
  try {
    const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 6) : [];

    const closes1 = c1.map(x => Number(x.close)).filter(Boolean);
    const closes5 = c5.map(x => Number(x.close)).filter(Boolean);

    if (closes1.length < 6) return { momentumConfirmed: false };

    const last = closes1[closes1.length - 1];
    const meanPrev = closes1.slice(0, -1).reduce((a,b)=>a+b,0)/Math.max(1, closes1.length-1);
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

async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 12) : [];
    const vols = c5.map(x => Number(x.volume || x.vol || 0)).filter(v=>v>0);

    if (!vols.length) {
      const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
      const highs = c1.map(x=>Number(x.high)).filter(Boolean);
      const lows = c1.map(x=>Number(x.low)).filter(Boolean);

      const tr = [];
      for (let i=1;i<highs.length;i++){
        tr.push(Math.max(
          Math.abs(highs[i]-lows[i]),
          Math.abs(highs[i]-Number(c1[i-1].close)),
          Math.abs(lows[i]-Number(c1[i-1].close))
        ));
      }
      const avgTR = tr.length ? tr.reduce((a,b)=>a+b,0)/tr.length : 0;
      return { volumeConfirmed: avgTR > 0 && (avgTR / Math.max(1, Number(c1[c1.length-1]?.close||1))) > 0.001 };
    }

    const latest = vols[vols.length-1];
    const sorted = [...vols].sort((a,b)=>a-b);
    const median = sorted[Math.floor(sorted.length/2)] || 0;
    const mean = vols.reduce((a,b)=>a+b,0)/vols.length;

    return { volumeConfirmed: latest >= Math.max(median*0.9, mean*0.8) };
  } catch {
    return { volumeConfirmed: false };
  }
}

/* -------------------------------------------------------------
   FAKE BREAKOUT CHECK
-------------------------------------------------------------- */
function rejectFakeBreakout(trendObj, futDiff) {
  if (!trendObj) return true;

  const score = Number(trendObj.score || 0);

  if (Math.abs(score) < 2) return true;

  if (futDiff && Math.abs(futDiff) > 200) return true;

  return false;
}

/* -------------------------------------------------------------
   FINAL ENTRY GUARD
-------------------------------------------------------------- */
async function finalEntryGuard({ symbol, trendObj, futDiff, getCandlesFn }) {
  const t = await tripleConfirmTrend(trendObj, symbol, getCandlesFn);
  const m = await tripleConfirmMomentum(symbol, getCandlesFn);
  const v = await tripleConfirmVolume(symbol, getCandlesFn);

  const passedCount = (t.trendConfirmed?1:0) + (m.momentumConfirmed?1:0) + (v.volumeConfirmed?1:0);

  if (passedCount === 0) return { allowed: false, reason: "NO_CONFIRMATIONS", details: { t,m,v } };

  const softReject = rejectFakeBreakout(trendObj, futDiff);
  if (softReject) {
    return { allowed: false, reason: "FAKE_BREAKOUT_SOFT", details: { t,m,v, futDiff } };
  }

  if (futDiff && Math.abs(futDiff) > 300) return { allowed: false, reason: "FUT_MISMATCH_HARD", futDiff };

  return { allowed: true, reason: "ALLOWED", passedCount, details: { t,m,v } };
}

/* -------------------------------------------------------------
   OPTION LTP FETCHER
-------------------------------------------------------------- */
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
        "X-SourceID": "WEB"
      },
      body: JSON.stringify({
        exchange: tokenInfo.instrument?.exchange || "NFO",
        tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
        symboltoken: tokenInfo.token || ""
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   MAIN ENTRY ENGINE
-------------------------------------------------------------- */
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
  const trendObj = hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot });

  const futDiff = await detectFuturesDiff(market, spot);

  const strikes = generateStrikes(market, spot, expiry_days);

  const entryGate = await finalEntryGuard({
    symbol: market,
    trendObj,
    futDiff,
    getCandlesFn: fetchRecentCandles
  });

  if (!entryGate.allowed) {
    return {
      allowed: false,
      reason: entryGate.reason,
      details: entryGate.details || {},
      trend: trendObj,
      futDiff
    };
  }

  const ceATM  = await fetchOptionLTP(market, strikes.atm, "CE");
  const peATM  = await fetchOptionLTP(market, strikes.atm, "PE");

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
    target2: levels.target2
  };
}

/* -------------------------------------------------------------
   CANDLE FETCHERS
-------------------------------------------------------------- */
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

/* -------------------------------------------------------------
   fetchRecentCandles (Live first → fallback REST)
-------------------------------------------------------------- */
async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    if (interval === 1 && realtime.candles1m[symbol]) {
      return realtime.candles1m[symbol].slice(-limit);
    }

    let intv = "ONE_MINUTE";
    if (interval === 5) intv = "FIVE_MINUTE";

    const candles = await fetchCandles(symbol, intv, limit);
    return candles.slice(-limit);
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------
   RSI CALCULATOR
-------------------------------------------------------------- */
function computeRSI(closes, period = 14) {
  try {
    if (!closes || closes.length < period + 1) return null;

    let gains = 0;
    let losses = 0;

    for (let i = 1; i <= period; i++) {
      const diff = closes[i] - closes[i - 1];
      if (diff > 0) gains += diff;
      else losses -= diff;
    }

    if (losses === 0) return 100;

    let rs = gains / losses;
    return 100 - 100 / (1 + rs);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------
   API: GET SPOT
-------------------------------------------------------------- */
app.get("/api/spot", async (req, res) => {
  try {
    const market = String(req.query.market || "NIFTY").toUpperCase();

    if (lastKnown.spot && Date.now() - (lastKnown.updatedAt || 0) < 5000) {
      return res.json({
        success: true,
        source: "LIVE",
        spot: lastKnown.spot
      });
    }

    const fallback = await fetchLTP(market);
    if (fallback) {
      lastKnown.spot = fallback;
      lastKnown.updatedAt = Date.now();
      return res.json({ success: true, source: "REST", spot: fallback });
    }

    return res.json({ success: false, error: "SPOT_NOT_AVAILABLE" });
  } catch {
    return res.json({ success: false, error: "EXCEPTION" });
  }
});

/* -------------------------------------------------------------
   API: TOKEN RESOLVE
-------------------------------------------------------------- */
app.get("/api/token/resolve", async (req, res) => {
  try {
    const market = String(req.query.market || "");
    const strike = Number(req.query.strike || 0);
    const type   = String(req.query.type || "CE");

    const expiry = detectExpiryForSymbol(market).currentWeek;

    const tok = await resolveInstrumentToken(market, expiry, strike, type);
    if (!tok) return res.json({ success: false, error: "TOKEN_NOT_FOUND" });

    return res.json({ success: true, token: tok });
  } catch {
    res.json({ success: false, error: "EXCEPTION" });
  }
});

/* -------------------------------------------------------------
   API: /api/calc
-------------------------------------------------------------- */
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

    if (lastKnown.spot && Date.now() - (lastKnown.updatedAt || 0) < 5000) {
      finalSpot = lastKnown.spot;
    }
    else if (spot) {
      finalSpot = Number(spot);
      lastKnown.spot = finalSpot;
      lastKnown.updatedAt = Date.now();
    }
    else {
      const fallback = await fetchLTP(market);
      if (fallback) {
        finalSpot = fallback;
        lastKnown.spot = fallback;
        lastKnown.updatedAt = Date.now();
      }
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

    return res.json({
      success: true,
      entry
    });

  } catch (err) {
    return res.json({
      success: false,
      error: "EXCEPTION_IN_CALC",
      detail: String(err)
    });
  }
});

/* -------------------------------------------------------------
   API: PING
-------------------------------------------------------------- */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    live: wsStatus.connected,
    spot: lastKnown.spot || null
  });
});

/* -------------------------------------------------------------
   START SERVER
-------------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
