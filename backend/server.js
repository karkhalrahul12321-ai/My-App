/* ============================================================
   server.js — REBUILT (PART 1/10)
   - Imports, Master Loader, Express, SMARTAPI env, Session
   - TOTP generator, safeFetchJson, SmartAPI login + routes
   ============================================================ */

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
   GLOBALS & MASTER LOADER
------------------------------------------------------------ */
global.instrumentMaster = [];

async function loadMasterOnline() {
  try {
    const url =
      "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";

    const r = await fetch(url);
    const j = await r.json().catch(() => null);

    if (Array.isArray(j) && j.length > 0) {
      global.instrumentMaster = j;
      console.log("MASTER LOADED ONLINE ✔ COUNT:", j.length);
      return true;
    } else {
      console.log("MASTER LOAD FAILED → empty or invalid response");
      return false;
    }
  } catch (e) {
    console.log("MASTER LOAD ERROR:", e && e.message ? e.message : e);
    return false;
  }
}

// Load once on startup (non-blocking)
loadMasterOnline().catch(() => {});

// Periodic refresh (1 hour)
setInterval(() => {
  loadMasterOnline().catch(() => {});
}, 60 * 60 * 1000);

/* ------------------------------------------------------------
   EXPRESS APP SETUP
------------------------------------------------------------ */
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "1mb" }));

/* Serve frontend if exists */
const frontendPath = path.join(__dirname, "..", "frontend");
try {
  app.use(express.static(frontendPath));
} catch (e) {
  // ignore if folder missing
}

/* Basic pages if frontend present */
app.get("/", (req, res) => {
  try {
    res.sendFile(path.join(frontendPath, "index.html"));
  } catch {
    res.send({ ok: true, message: "Backend running" });
  }
});

app.get("/settings", (req, res) => {
  try {
    res.sendFile(path.join(frontendPath, "settings.html"));
  } catch {
    res.json({ ok: false, error: "No frontend settings page" });
  }
});

/* ------------------------------------------------------------
   SMARTAPI ENV (from process.env)
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
   TOTP / BASE32 decoder
------------------------------------------------------------ */
function base32Decode(input) {
  if (!input) return Buffer.from([]);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0;
  const output = [];

  input = String(input || "").replace(/=+$/, "").toUpperCase();

  for (const char of input) {
    const idx = alphabet.indexOf(char);
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
    if (!secret) return null;
    const key = base32Decode(secret);
    const timeStep = Math.floor(Date.now() / 30000);

    const buf = Buffer.alloc(8);
    // high 32 bits zero, low 32 bits timeStep
    buf.writeUInt32BE(0, 0);
    buf.writeUInt32BE(timeStep, 4);

    const hmac = crypto.createHmac("sha1", key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;

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

/* ------------------------------------------------------------
   SAFE JSON FETCH (helper)
------------------------------------------------------------ */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const txt = await r.text().catch(() => null);
    if (!txt) return { ok: true, data: null, status: r.status };
    try {
      const data = JSON.parse(txt);
      return { ok: true, data, status: r.status };
    } catch {
      // fallback: return raw text under data
      return { ok: true, data: txt, status: r.status };
    }
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
}

/* ------------------------------------------------------------
   SMARTAPI LOGIN (password-based) - stores tokens in session
------------------------------------------------------------ */
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }

  if (!tradingPassword || typeof tradingPassword !== "string") {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);
    const url = `${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`;

    const resp = await fetch(url, {
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
    });

    const j = await resp.json().catch(() => null);

    if (!j || j.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: j || null };
    }

    const d = j.data || {};

    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;
    session.login_time = Date.now();

    return { ok: true, raw: j };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err && err.message ? err.message : String(err) };
  }
}

/* ------------------------------------------------------------
   LOGIN ROUTES
------------------------------------------------------------ */
app.post("/api/login", async (req, res) => {
  try {
    const password = String(req.body?.password || "");
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

    return res.json({
      success: true,
      message: "SmartAPI Login Successful",
      session: { logged_in: true, expires_at: session.expires_at, login_time: session.login_time },
    });
  } catch (err) {
    return res.json({ success: false, error: "EXCEPTION", detail: String(err) });
  }
});

app.get("/api/login/status", (req, res) => {
  try {
    res.json({
      success: true,
      logged_in: !!session.access_token,
      expires_at: session.expires_at,
      login_time: session.login_time,
    });
  } catch {
    res.json({ success: false });
  }
});

/* ------------------------------------------------------------
   PART END (1/10)
   Next: WebSocket handlers, realtime memory, subscribe logic
------------------------------------------------------------ */
/* ============================================================
   server.js — REBUILT (PART 2/10)
   - Realtime memory holder
   - WebSocket start logic
   - Tick handling
   - 1m candle builder
   - Auto reconnect
   - Core symbol subscription
   ============================================================ */

/* ------------------------------------------------------------
   REALTIME MEMORY
------------------------------------------------------------ */
const realtime = {
  ticks: {},
  candles1m: {},
};

const lastKnown = {
  spot: null,
  updatedAt: 0,
};

let wsClient = null;

const wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: "",
  reconnectAttempts: 0,
  subscriptions: [],
};

/* ------------------------------------------------------------
   WS STARTER
------------------------------------------------------------ */
function startWebsocketIfReady() {
  try {
    if (!session.feed_token) {
      console.log("WS WAIT → feed_token missing");
      return;
    }

    if (wsClient) {
      try {
        wsClient.terminate();
      } catch {}
      wsClient = null;
    }

    const wsUrl = `wss://smartapisocket.angelbroking.com/v1/?clientcode=${SMART_USER_ID}&feedtoken=${session.feed_token}`;
    wsClient = new WebSocket(wsUrl);

    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.lastError = "";
      wsStatus.reconnectAttempts = 0;
      console.log("WS OPEN ✔");

      // resubscribe if available
      if (wsStatus.subscriptions.length) {
        try {
          const sub = {
            task: "cn",
            channel: {
              instrument_tokens: wsStatus.subscriptions,
              feed_type: "ltp",
            },
          };
          wsClient.send(JSON.stringify(sub));
          console.log("WS RESUBSCRIBED →", wsStatus.subscriptions);
        } catch (err) {
          console.log("WS RESUBSCRIBE ERROR:", err);
        }
      }
    });

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
      const sym = d.tradingsymbol || d.symbol || null;

      const ltp =
        Number(d.ltp || d.lastPrice || d.price || 0) || null;
      const oi =
        Number(d.oi || d.openInterest || 0) || null;

      const token = d.token || d.instrument_token || null;

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

      /* ---- BUILD 1-MIN CANDLES ---- */
      try {
        if (sym && ltp != null) {
          if (!realtime.candles1m[sym])
            realtime.candles1m[sym] = [];

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
              volume: Number(d.volume || 0),
            });

            if (arr.length > 180) arr.shift();
          } else {
            cur.high = Math.max(cur.high, ltp);
            cur.low = Math.min(cur.low, ltp);
            cur.close = ltp;
            cur.volume =
              (cur.volume || 0) + Number(d.volumeDelta || 0);
          }
        }
      } catch (e) {
        console.log("CANDLE ERROR:", e);
      }
    });

    wsClient.on("error", (err) => {
      wsStatus.connected = false;
      wsStatus.lastError = String(err);
      console.log("WS ERROR:", err);
      scheduleWSReconnect();
    });

    wsClient.on("close", (code) => {
      wsStatus.connected = false;
      wsStatus.lastError = "closed:" + code;
      console.log("WS CLOSED:", code);
      scheduleWSReconnect();
    });
  } catch (err) {
    console.log("WS START ERR:", err);
  }
}

/* ------------------------------------------------------------
   SAFE RECONNECT LOGIC
------------------------------------------------------------ */
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

/* ------------------------------------------------------------
   SUBSCRIBE CORE SYMBOLS (Index Futures)
------------------------------------------------------------ */
async function subscribeCoreSymbols() {
  try {
    const symbols = ["NIFTY", "SENSEX", "NATURALGAS"];

    const expiryInfo = detectExpiryForSymbol("NIFTY");
    const expiry = expiryInfo.currentWeek;

    const tokens = [];

    for (const s of symbols) {
      let tok = null;

      try {
        tok = await resolveInstrumentToken(s, expiry, 0, "FUT");
      } catch {
        tok = null;
      }

      if (tok && tok.token) {
        const clean = String(tok.token).replace(/\D/g, "");
        if (clean.length >= 5 && clean.length <= 8) {
          tokens.push(String(tok.token));
        } else {
          console.log("CORE SUBSCRIBE SKIP (bad token):", s, tok.token);
        }
      } else {
        console.log("CORE SUBSCRIBE SKIP (no token):", s);
      }
    }

    if (
      tokens.length > 0 &&
      wsClient &&
      wsClient.readyState === WebSocket.OPEN
    ) {
      try {
        const payload = {
          task: "cn",
          channel: {
            instrument_tokens: tokens,
            feed_type: "ltp",
          },
        };

        wsClient.send(JSON.stringify(payload));
        wsStatus.subscriptions = tokens;
        console.log("WS CORE SUBSCRIBED →", tokens);
      } catch (err) {
        console.log("CORE WS SEND ERR:", err);
      }
    } else {
      console.log("CORE WS: no valid tokens", tokens);
    }
  } catch (err) {
    console.log("CORE SUBSCRIBE ERR:", err);
  }
}

/* ------------------------------------------------------------
   WS STATUS ENDPOINT
------------------------------------------------------------ */
app.get("/api/ws/status", (req, res) => {
  try {
    res.json({
      connected: wsStatus.connected,
      lastMsgAt: wsStatus.lastMsgAt,
      lastError: wsStatus.lastError,
      subs: wsStatus.subscriptions,
    });
  } catch {
    res.json({ connected: false });
  }
});

/* ------------------------------------------------------------
   AUTO WS START after successful SmartAPI login
------------------------------------------------------------ */
const _origSmartLogin = smartApiLogin;
smartApiLogin = async function (pw) {
  const r = await _origSmartLogin(pw);
  if (r && r.ok) {
    setTimeout(() => startWebsocketIfReady(), 1500);
  }
  return r;
};

// Start websocket automatically a bit after boot
setTimeout(() => startWebsocketIfReady(), 2000);

/* ------------------------------------------------------------
   PART END (2/10)
   Next: Candlestick fetching, RSI, trend engines, helpers
------------------------------------------------------------ */
/* ============================================================
   server.js — REBUILT (PART 3/10)
   - Candle fetcher
   - RSI computation
   - EMA / VWAP helpers
   - Hybrid trend engine (base part)
   - Momentum analysis
   ============================================================ */

/* ------------------------------------------------------------
   FETCH RECENT CANDLES (SmartAPI)
------------------------------------------------------------ */
async function fetchRecentCandles(symbol, interval, count = 50) {
  try {
    if (!session.access_token) return [];

    const now = moment();
    const from = now.clone().subtract(count + 5, "minutes").format("YYYY-MM-DD HH:mm");
    const to = now.format("YYYY-MM-DD HH:mm");

    const payload = {
      exchange: "NSE",
      symboltoken: String(symbol),
      interval: String(interval),
      fromdate: from,
      todate: to,
    };

    const r = await fetch(`${SMARTAPI_BASE}/rest/market/v1/instruments/candleData`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + session.access_token,
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify(payload),
    });

    const j = await r.json().catch(() => null);
    if (!j || !j.data || !Array.isArray(j.data)) return [];

    return j.data.map((c) => ({
      time: c[0],
      open: Number(c[1]),
      high: Number(c[2]),
      low: Number(c[3]),
      close: Number(c[4]),
      volume: Number(c[5] || 0),
    }));
  } catch (err) {
    console.log("FETCH CANDLES ERROR:", err);
    return [];
  }
}

/* ------------------------------------------------------------
   BASIC UTILS
------------------------------------------------------------ */
function avg(arr) {
  if (!arr.length) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

/* ------------------------------------------------------------
   RSI CALCULATOR (14 default)
------------------------------------------------------------ */
function computeRSI(closes, period = 14) {
  if (!closes || closes.length <= period) return null;

  let gains = [];
  let losses = [];

  for (let i = 1; i < closes.length; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff >= 0) gains.push(diff);
    else losses.push(-diff);
  }

  const avgGain = avg(gains.slice(-period));
  const avgLoss = avg(losses.slice(-period));

  if (avgLoss === 0) return 100;

  const rs = avgGain / avgLoss;
  return 100 - 100 / (1 + rs);
}

/* ------------------------------------------------------------
   EMA CALCULATOR
------------------------------------------------------------ */
function computeEMA(closes, length = 20) {
  if (!closes || closes.length < length) return null;

  let ema = closes[0];
  const k = 2 / (length + 1);

  for (let i = 1; i < closes.length; i++) {
    ema = closes[i] * k + ema * (1 - k);
  }
  return ema;
}

/* ------------------------------------------------------------
   VWAP APPROX (simple volume-weighted)
------------------------------------------------------------ */
function computeVWAP(candles) {
  if (!candles || !candles.length) return null;
  let pv = 0,
    vol = 0;
  for (const c of candles) {
    const typical = (c.high + c.low + c.close) / 3;
    pv += typical * (c.volume || 0);
    vol += c.volume || 0;
  }
  if (!vol) return null;
  return pv / vol;
}

/* ------------------------------------------------------------
   HYBRID TREND ENGINE (EMA20 + EMA50 + VWAP + RSI + Spot)
------------------------------------------------------------ */
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
  const basic = { direction: "NEUTRAL", score: 0 };

  /* 1) EMA Trend */
  if (ema20 && ema50) {
    if (ema20 > ema50) {
      basic.direction = "UP";
      basic.score++;
    } else if (ema20 < ema50) {
      basic.direction = "DOWN";
      basic.score--;
    }
  }

  /* 2) VWAP Trend */
  if (vwap && spot) {
    if (spot > vwap) basic.score++;
    else basic.score--;
  }

  /* 3) RSI Filter */
  let rsiOk = true;
  if (rsi) {
    if (rsi < 40) {
      basic.score--;
      rsiOk = false;
    } else if (rsi > 60) {
      basic.score++;
      rsiOk = false;
    }
  }

  /* 4) Spot Momentum (simple) */
  if (lastSpot && spot) {
    if (spot > lastSpot) basic.score++;
    else basic.score--;
  }

  /* Final direction */
  if (basic.score >= 2) basic.direction = "UP";
  else if (basic.score <= -2) basic.direction = "DOWN";

  return {
    direction: basic.direction,
    base: basic,
    score: basic.score,
    rsiOk,
  };
}

/* ------------------------------------------------------------
   SIMPLE MOMENTUM CHECKER
------------------------------------------------------------ */
function momentumEngine(closes) {
  if (!closes || closes.length < 4)
    return { momentum: "NEUTRAL" };

  const last = closes[closes.length - 1];
  const prev = closes.slice(0, -1);
  const meanPrev = avg(prev);

  const pct = Math.abs((last - meanPrev) / Math.max(1, meanPrev));

  if (pct > 0.002) {
    if (last > meanPrev) return { momentum: "UP" };
    else return { momentum: "DOWN" };
  }

  return { momentum: "NEUTRAL" };
}

/* ------------------------------------------------------------
   PART END (3/10)
   Next: Volume engine, hybrid confirm, futures diff, 
         Option fetcher, strike utils
------------------------------------------------------------ */
/* ============================================================
   server.js — REBUILT (PART 4/10)
   - Volume engine
   - Triple-confirm helpers (finalEntryGuard)
   - Futures & Option LTP fetchers
   - Futures diff detector
   - Strike utils + Targets & SL
   ============================================================ */

/* ------------------------------------------------------------
   VOLUME CONFIRMATION ENGINE
------------------------------------------------------------ */
async function tripleConfirmVolume(symbol, getCandlesFn) {
  try {
    const c5 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 5, 12) : [];
    const vols = c5.map(x => Number(x.volume || x.vol || 0)).filter(v => v > 0);

    if (!vols.length) {
      const c1 = typeof getCandlesFn === "function" ? await getCandlesFn(symbol, 1, 12) : [];
      if (!c1.length) return { volumeConfirmed: false };

      const highs = c1.map(x => Number(x.high)).filter(Boolean);
      const lows = c1.map(x => Number(x.low)).filter(Boolean);

      const tr = [];
      for (let i = 1; i < highs.length; i++) {
        tr.push(Math.max(
          Math.abs(highs[i] - lows[i]),
          Math.abs(highs[i] - Number(c1[i - 1].close || 0)),
          Math.abs(lows[i] - Number(c1[i - 1].close || 0))
        ));
      }

      const avgTR = tr.length ? tr.reduce((a, b) => a + b, 0) / tr.length : 0;
      const lastClose = Number(c1[c1.length - 1]?.close || 1);

      return {
        volumeConfirmed: !!(avgTR > 0 && (avgTR / Math.max(1, lastClose)) > 0.001)
      };
    }

    const latest = vols[vols.length - 1];
    const sorted = [...vols].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)] || 0;
    const mean = vols.reduce((a, b) => a + b, 0) / vols.length;

    return { volumeConfirmed: latest >= Math.max(median * 0.9, mean * 0.8) };
  } catch {
    return { volumeConfirmed: false };
  }
}

/* ------------------------------------------------------------
   FINAL ENTRY GUARD (uses triple confirmations)
------------------------------------------------------------ */
async function finalEntryGuard({ symbol, trendObj, futDiff, getCandlesFn }) {
  try {
    const t = await tripleConfirmTrend(trendObj, symbol, getCandlesFn).catch(() => ({ trendConfirmed: false }));
    const m = await tripleConfirmMomentum(symbol, getCandlesFn).catch(() => ({ momentumConfirmed: false }));
    const v = await tripleConfirmVolume(symbol, getCandlesFn).catch(() => ({ volumeConfirmed: false }));

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

    // soft fake-breakout guard (re-use rejectFakeBreakout if present)
    if (typeof rejectFakeBreakout === "function" && rejectFakeBreakout(trendObj, futDiff)) {
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
  } catch (err) {
    return { allowed: false, reason: "GUARD_EXCEPTION", detail: String(err) };
  }
}

/* ------------------------------------------------------------
   FUTURES LTP FETCHER (REST fallback)
------------------------------------------------------------ */
async function fetchFuturesLTP(symbol) {
  try {
    // Resolve token using resolveInstrumentToken (will be implemented later)
    const expiry = detectExpiryForSymbol(symbol).currentWeek;
    const tokenInfo = await resolveInstrumentToken(symbol, expiry, 0, "FUT").catch(() => null);
    if (!tokenInfo || !tokenInfo.token) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const body = {
      exchange: tokenInfo.instrument?.exchange || "NFO",
      tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
      symboltoken: tokenInfo.token || "",
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: session.access_token || "",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify(body),
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0) || null;
    return ltp && ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   OPTION LTP FETCHER
------------------------------------------------------------ */
async function fetchOptionLTP(symbol, strike, type) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;
    const tokenInfo = await resolveInstrumentToken(symbol, expiry, strike, type).catch(() => null);
    if (!tokenInfo || !tokenInfo.token) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const body = {
      exchange: tokenInfo.instrument?.exchange || "NFO",
      tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
      symboltoken: tokenInfo.token || "",
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: session.access_token || "",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify(body),
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0) || null;
    return ltp && ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   FUTURES DIFF DETECTOR
------------------------------------------------------------ */
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut || !isFinite(spotUsed)) return null;
    return Number(fut) - Number(spotUsed);
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   STRIKE / TARGET UTILS
------------------------------------------------------------ */
function roundToStep(market, price) {
  price = Number(price) || 0;
  // For simplicity use 50 step for index-like, 100 for high values
  if (price >= 5000) return Math.round(price / 50) * 50;
  return Math.round(price / 25) * 25;
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

  const atm = base;
  const otm1 = base + dynamicDist;
  const otm2 = base - dynamicDist;

  return { atm, otm1, otm2 };
}

function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;
  const sl = entryLTP * 0.85;
  const tgt1 = entryLTP * 1.10;
  const tgt2 = entryLTP * 1.20;

  return {
    stopLoss: Number(sl.toFixed(2)),
    target1: Number(tgt1.toFixed(2)),
    target2: Number(tgt2.toFixed(2)),
  };
}

/* ------------------------------------------------------------
   PART END (4/10)
   Next: resolveInstrumentToken (big), token helpers, alias map, expiry parsing
------------------------------------------------------------ */
/* ============================================================
   server.js — REBUILT (PART 5/10)
   - resolveInstrumentToken() — COMPLETELY CLEAN VERSION
   - Symbol filtering, expiry parsing, FUT/OPT detection
   - Multi-stage fallback logic
   ============================================================ */

function isTokenSane(t) {
  const s = String(t || "").trim();
  if (!s) return false;
  if (!/^\d+$/.test(s)) return false;
  return s.length >= 5 && s.length <= 8;
}

function tsOf(it) {
  return String(it.tradingsymbol || it.symbol || "").trim().toUpperCase();
}
function itypeOf(it) {
  return String(it.instrumenttype || it.instrumentType || "").trim().toUpperCase();
}

function parseExpiryDate(ex) {
  if (!ex) return null;
  ex = String(ex).trim();

  // YYYY-MM-DD
  let m = ex.match(/^(\d{4})[-\/](\d{2})[-\/](\d{2})$/);
  if (m) return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));

  // YYYYMMDD
  m = ex.match(/^(\d{4})(\d{2})(\d{2})$/);
  if (m) return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));

  // DD-MON-YYYY
  m = ex.match(/^(\d{1,2})[- ]([A-Za-z]+)[- ](\d{4})$/);
  if (m) {
    const dd = Number(m[1]);
    const months = ["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"];
    const mm = months.indexOf(m[2].toUpperCase());
    if (mm >= 0) return new Date(Number(m[3]), mm, dd);
  }

  const parseTry = Date.parse(ex);
  if (!isNaN(parseTry)) return new Date(parseTry);

  return null;
}

/* ------------------------------------------------------------
   MAIN TOKEN RESOLVER
------------------------------------------------------------ */
async function resolveInstrumentToken(symbol, expiry = "", strike = 0, type = "FUT") {
  try {
    if (!Array.isArray(global.instrumentMaster)) return null;

    symbol = String(symbol || "").trim().toUpperCase();
    type = String(type || "").trim().toUpperCase();

    if (!symbol) return null;

    const key = symbol.replace(/[^A-Z]/g, "");
    if (!key) return null;

    const expiryStr = String(expiry || "").trim();
    const strikeNum = Number(strike || 0);

    /* 1) Filter by symbol key (index, underlying) */
    let marketCandidates = global.instrumentMaster.filter((it) => {
      const ts = tsOf(it);
      return (
        ts.startsWith(key) ||
        ts.includes(key) ||
        String(it.name || "").toUpperCase().includes(key)
      );
    });

    if (!marketCandidates.length) {
      console.log("resolveInstrumentToken: no candidates for", symbol);
      return null;
    }

    /* 2) If OPTION requested → filter CE/PE + strike match */
    if (type === "CE" || type === "PE") {
      const side = type;
      const approxStrike = Math.round(strikeNum);

      const optList = marketCandidates.filter((it) => {
        const ts = tsOf(it);
        const itype = itypeOf(it);
        const st = Number(it.strike || it.strikePrice || 0);

        const isOption =
          itype.includes("OPT") ||
          ts.includes("CE") ||
          ts.includes("PE");

        if (!isOption) return false;

        const sideMatch = ts.endsWith(side);
        const strikeMatch = st === approxStrike;

        return sideMatch && strikeMatch && isTokenSane(it.token);
      });

      if (optList.length) {
        const withExpiry = optList
          .map((it) => {
            const ex = parseExpiryDate(it.expiry || it.expiryDate || it.expiry_dt);
            const diff = ex ? Math.abs(ex.getTime() - Date.now()) : Infinity;
            return { it, diff };
          })
          .sort((a, b) => a.diff - b.diff);

        const pick = withExpiry[0].it;
        return { instrument: pick, token: String(pick.token) };
      }

      console.log("resolveInstrumentToken: no option match", symbol, strike, side);
    }

    /* 3) FUTURES detection */
    if (type === "FUT") {
      const futs = marketCandidates.filter((it) => {
        const ts = tsOf(it);
        const itype = itypeOf(it);
        const st = Number(it.strike || it.strikePrice || 0);

        const isFut =
          itype.includes("FUT") ||
          ts.includes("FUT") ||
          itype.includes("FUTIDX") ||
          itype.includes("FUTSTK") ||
          itype.includes("AMXIDX");

        return isFut && Math.abs(st) < 1 && isTokenSane(it.token);
      });

      if (futs.length) {
        const futsWithExpiry = futs
          .map((it) => {
            const ex = parseExpiryDate(it.expiry || it.expiryDate || it.expiry_dt);
            const diff = ex ? Math.abs(ex.getTime() - Date.now()) : Infinity;
            return { it, diff };
          })
          .sort((a, b) => a.diff - b.diff);

        const best = futsWithExpiry[0].it;
        return { instrument: best, token: String(best.token) };
      }

      /* fallback index/AMXIDX */
      const spots = marketCandidates.filter((it) => {
        const itype = itypeOf(it);
        const st = Number(it.strike || it.strikePrice || 0);
        return (
          (itype.includes("INDEX") || itype.includes("AMXIDX") || itype.includes("IND")) &&
          Math.abs(st) < 1 &&
          isTokenSane(it.token)
        );
      });

      if (spots.length) {
        const s = spots[0];
        return { instrument: s, token: String(s.token) };
      }
    }

    /* 4) GENERAL FUT-FIRST fallback */
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

    if (pref) return { instrument: pref, token: String(pref.token) };

    /* 5) General fallback */
    const general = marketCandidates.find((it) =>
      isTokenSane(it.token) &&
      String(it.tradingsymbol || it.symbol || it.name || "").trim().length > 3
    );

    if (general) return { instrument: general, token: String(general.token) };

    /* 6) last fallback */
    const any = marketCandidates.find((it) => it.token && isTokenSane(it.token));
    if (any) return { instrument: any, token: String(any.token) };

    return null;
  } catch (err) {
    console.log("resolveInstrumentToken ERROR:", err);
    return null;
  }
}
/* ============================================================
   server.js — REBUILT (PART 6/10)
   - detectExpiryForSymbol()
   - computeEntry() — FULL ENTRY ENGINE
   ============================================================ */

/* ------------------------------------------------------------
   WEEKLY EXPIRY DETECTOR
------------------------------------------------------------ */
function detectExpiryForSymbol(symbol) {
  try {
    const today = moment();

    // Weekly expiry = Thursday (weekday=4)
    let currentWeek = today.clone().weekday(4);
    if (today.weekday() > 4) {
      currentWeek = today.clone().add(1, "weeks").weekday(4);
    }

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

/* ------------------------------------------------------------
   MAIN ENTRY ENGINE (Trend + Momentum + Volume + Futures Diff)
------------------------------------------------------------ */
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
  try {
    /* 1) TREND OBJECT */
    const trendObj = hybridTrendEngine({
      ema20,
      ema50,
      vwap,
      rsi,
      spot,
      lastSpot,
    });

    /* 2) FUTURES DIFF */
    const futDiff = await detectFuturesDiff(market, spot);

    /* 3) STRIKE SUGGESTION */
    const strikes = generateStrikes(market, spot, expiry_days);

    /* 4) FINAL ENTRY GATE */
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

    /* 5) FETCH ATM OPTION LTPs */
    const ceATM = await fetchOptionLTP(market, strikes.atm, "CE");
    const peATM = await fetchOptionLTP(market, strikes.atm, "PE");

    const takeCE = trendObj.direction === "UP";
    const entryLTP = takeCE ? ceATM : peATM;

    if (!entryLTP) {
      return {
        allowed: false,
        reason: "OPTION_LTP_FAIL",
        trend: trendObj,
        futDiff,
      };
    }

    /* 6) TARGETS & SL */
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
      trendObj,
    };
  } catch (err) {
    return {
      allowed: false,
      reason: "ENTRY_EXCEPTION",
      error: String(err),
    };
  }
}
/* ============================================================
   server.js — REBUILT (PART 7/10)
   - ENTRY API endpoint
   - LTP (spot) endpoint
   - Candles endpoint
   - Master data status endpoint
   ============================================================ */

/* ------------------------------------------------------------
   SPOT LTP FETCHER (REST fallback)
------------------------------------------------------------ */
async function fetchSpotLTP(symbol) {
  try {
    const expiryInfo = detectExpiryForSymbol(symbol);
    const tokenInfo = await resolveInstrumentToken(symbol, expiryInfo.currentWeek, 0, "FUT").catch(() => null);

    if (!tokenInfo || !tokenInfo.token) return null;

    const url = `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;
    const body = {
      exchange: tokenInfo.instrument?.exchange || "NFO",
      tradingsymbol: tokenInfo.instrument?.tradingsymbol || "",
      symboltoken: tokenInfo.token || "",
    };

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: session.access_token || "",
        "X-PrivateKey": SMART_API_KEY,
      },
      body: JSON.stringify(body),
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0) || null;
    return ltp && ltp > 0 ? ltp : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------
   ENTRY API — MAIN ENDPOINT
------------------------------------------------------------ */
app.post("/api/entry", async (req, res) => {
  try {
    const market = String(req.body?.market || "").trim().toUpperCase();
    const spot = Number(req.body?.spot || 0);
    const ema20 = Number(req.body?.ema20 || 0);
    const ema50 = Number(req.body?.ema50 || 0);
    const vwap = Number(req.body?.vwap || 0);
    const rsi = Number(req.body?.rsi || 0);
    const expiry_days = Number(req.body?.expiry_days || 0);
    const lastSpot = Number(req.body?.lastSpot || 0);

    if (!market || !spot) {
      return res.json({ success: false, error: "MARKET_OR_SPOT_MISSING" });
    }

    const r = await computeEntry({
      market,
      spot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days,
      lastSpot,
    });

    res.json({ success: true, data: r });
  } catch (err) {
    res.json({
      success: false,
      error: "ENTRY_EXCEPTION",
      detail: String(err),
    });
  }
});

/* ------------------------------------------------------------
   SPOT LTP API
------------------------------------------------------------ */
app.get("/api/ltp/:symbol", async (req, res) => {
  try {
    const sym = String(req.params.symbol || "").trim().toUpperCase();
    if (!sym) return res.json({ success: false, error: "NO_SYMBOL" });

    const ltp = await fetchSpotLTP(sym);
    res.json({ success: true, symbol: sym, ltp });
  } catch (e) {
    res.json({ success: false, error: "LTP_EXCEPTION", detail: String(e) });
  }
});

/* ------------------------------------------------------------
   CANDLES API (last 50/100 etc)
------------------------------------------------------------ */
app.get("/api/candles/:symbol", async (req, res) => {
  try {
    const symbol = String(req.params.symbol || "").trim().toUpperCase();
    const interval = Number(req.query.interval || 1);
    const count = Number(req.query.count || 30);

    if (!symbol) return res.json({ success: false, error: "NO_SYMBOL" });

    const data = await fetchRecentCandles(symbol, interval, count);
    res.json({ success: true, symbol, interval, count, data });
  } catch (e) {
    res.json({ success: false, error: "CANDLES_EXCEPTION", detail: String(e) });
  }
});

/* ------------------------------------------------------------
   MASTER DATA STATUS
------------------------------------------------------------ */
app.get("/api/master/status", (req, res) => {
  try {
    res.json({
      success: true,
      count: Array.isArray(global.instrumentMaster)
        ? global.instrumentMaster.length
        : 0,
    });
  } catch {
    res.json({ success: false, count: 0 });
  }
});
/* ============================================================
   server.js — REBUILT (PART 8/10)
   - Realtime ticks endpoint
   - Candles dump endpoint
   - Futures diff quick check
   - WebSocket manual reconnect
   - Session snapshot
   - Health endpoint
   ============================================================ */

/* ------------------------------------------------------------
   REALTIME TICKS DUMP
------------------------------------------------------------ */
app.get("/api/realtime/ticks", (req, res) => {
  try {
    res.json({
      success: true,
      count: Object.keys(realtime.ticks).length,
      ticks: realtime.ticks,
    });
  } catch (e) {
    res.json({ success: false, error: String(e) });
  }
});

/* ------------------------------------------------------------
   1-MIN CANDLES DUMP
------------------------------------------------------------ */
app.get("/api/realtime/candles/:symbol", (req, res) => {
  try {
    const sym = String(req.params.symbol || "").trim().toUpperCase();
    if (!sym) return res.json({ success: false, error: "NO_SYMBOL" });

    const data = realtime.candles1m[sym] || [];
    res.json({
      success: true,
      symbol: sym,
      count: data.length,
      data,
    });
  } catch (e) {
    res.json({ success: false, error: String(e) });
  }
});

/* ------------------------------------------------------------
   FUTURES DIFF QUICK CHECK
------------------------------------------------------------ */
app.get("/api/futdiff/:symbol/:spot", async (req, res) => {
  try {
    const symbol = String(req.params.symbol || "").trim().toUpperCase();
    const spot = Number(req.params.spot || 0);

    if (!symbol || !spot)
      return res.json({ success: false, error: "INVALID_INPUT" });

    const diff = await detectFuturesDiff(symbol, spot);

    res.json({
      success: true,
      symbol,
      spot,
      diff,
    });
  } catch (e) {
    res.json({ success: false, error: String(e) });
  }
});

/* ------------------------------------------------------------
   MANUAL WS RECONNECT TRIGGER
------------------------------------------------------------ */
app.get("/api/ws/reconnect", (req, res) => {
  try {
    wsStatus.lastError = "manual_reconnect";
    wsStatus.connected = false;
    wsStatus.reconnectAttempts = 0;

    try {
      if (wsClient) wsClient.terminate();
    } catch {}

    wsClient = null;

    setTimeout(() => startWebsocketIfReady(), 300);

    res.json({ success: true, message: "WS reconnect triggered" });
  } catch (e) {
    res.json({ success: false, error: String(e) });
  }
});

/* ------------------------------------------------------------
   SESSION SNAPSHOT
------------------------------------------------------------ */
app.get("/api/session", (req, res) => {
  try {
    res.json({
      success: true,
      session: {
        logged_in: !!session.access_token,
        expires_at: session.expires_at,
        login_time: session.login_time,
        feed_token: !!session.feed_token,
      },
    });
  } catch (e) {
    res.json({ success: false });
  }
});

/* ------------------------------------------------------------
   HEALTH CHECK (for Render)
------------------------------------------------------------ */
app.get("/health", (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});
/* ============================================================
   server.js — REBUILT (PART 9/10)
   - Final server boot
   - Safe port selection
   - Fallback route
   - Global error trap
   - Graceful shutdown
   ============================================================ */

/* ------------------------------------------------------------
   FALLBACK ROUTE (if nothing matches)
------------------------------------------------------------ */
app.use((req, res, next) => {
  try {
    res.status(404).json({
      success: false,
      error: "NOT_FOUND",
      path: req.originalUrl,
    });
  } catch (e) {
    next(e);
  }
});

/* ------------------------------------------------------------
   GLOBAL ERROR HANDLER
------------------------------------------------------------ */
app.use((err, req, res, next) => {
  console.log("GLOBAL ERROR:", err);
  res.status(500).json({
    success: false,
    error: "SERVER_ERROR",
    detail: String(err),
  });
});

/* ------------------------------------------------------------
   START SERVER (Render compatible)
------------------------------------------------------------ */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("============================================");
  console.log(" BACKEND RUNNING ✔");
  console.log(" PORT:", PORT);
  console.log(" TIME:", new Date().toLocaleString());
  console.log("============================================");
});

/* ------------------------------------------------------------
   SAFE SHUTDOWN HANDLERS
------------------------------------------------------------ */
process.on("SIGINT", () => {
  console.log("Graceful shutdown (SIGINT)...");
  try {
    if (wsClient) wsClient.close();
  } catch {}
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log("Graceful shutdown (SIGTERM)...");
  try {
    if (wsClient) wsClient.close();
  } catch {}
  process.exit(0);
});
