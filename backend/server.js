/* PART 1/6 — BASE IMPORTS + CONFIG + SESSION + TOTP + LOGIN */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

/* ONLINE MASTER AUTO-LOADER (NO NEED TO STORE IN GIT) */
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

/* ENV SMARTAPI */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
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

/* BASE32 DECODE + TOTP */
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
/* PART 2/6 — WEBSOCKET (FULL FIXED VERSION) + HELPERS */

/* --- helpers used across file --- */
function tsOf(entry) {
  return String(
    entry.tradingsymbol || entry.symbol || entry.name || ""
  ).toUpperCase();
}
function itypeOf(entry) {
  return String(
    entry.instrumenttype || entry.instrumentType || entry.type || ""
  ).toUpperCase();
}
function parseExpiryDate(v) {
  if (!v) return null;
  const s = String(v).trim();
  const m = moment(
    s,
    [
      "YYYY-MM-DD",
      "YYYYMMDD",
      "DD-MM-YYYY",
      "DDMMMYYYY",
      "DDMMYYYY",
      moment.ISO_8601
    ],
    true
  );
  if (m.isValid()) return m.toDate();
  const fallback = new Date(s);
  return isFinite(fallback.getTime()) ? fallback : null;
}
function isTokenSane(t) {
  if (!t && t !== 0) return false;
  const n = Number(String(t).replace(/\D/g, "")) || 0;
  return n > 0;
}

/* WEBSOCKET CONFIG */
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

/* START WEBSOCKET WHEN TOKENS ARE READY */
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
        "x-feed-token": session.feed_token
      }
    });
  } catch (e) {
    console.log("WS INIT ERR", e);
    return;
  }

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
      source: "API"
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
    const ltp = Number(d.ltp || d.lastPrice || d.price || 0) || null;
    const sym = d.tradingsymbol || d.symbol || null;

    if (sym && ltp != null) {
      realtime.ticks[sym] = {
        ltp,
        time: Date.now()
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
        let cur = arr.length ? arr[arr.length - 1] : null;

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
    } catch (e) {
      console.log("CANDLE ERROR", e);
    }
  });

  wsClient.on("error", (err) => {
    wsStatus.connected = false;
    wsStatus.lastError = String(err);
    scheduleWSReconnect();
  });

  wsClient.on("close", (code) => {
    wsStatus.connected = false;
    wsStatus.lastError = "closed:" + code;
    scheduleWSReconnect();
  });
}

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
/* PART 4/6 — ENTRY ENGINE + FUTURES + OPTION LTP + TOKEN RESOLVE */

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

/* RESOLVE INSTRUMENT TOKEN */
async function resolveInstrumentToken(symbol, expiry = "", strike = 0, type = "FUT") {
  try {
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

    const wantedSymbol = String(symbol || "").toUpperCase().trim();
    const wantedStrike = Number(strike || 0);
    const wantedType = String(type || "").toUpperCase();

    function normalize(s) {
      return String(s || "").toUpperCase().replace(/\s+/g, " ").trim();
    }

    function matchesMarket(entry) {
      const candidates = [
        entry.symbol,
        entry.name,
        entry.tradingsymbol,
        entry.instrumentname
      ]
        .filter(Boolean)
        .map(normalize);

      const key = normalize(wantedSymbol);
      if (candidates.includes(key)) return true;
      if (candidates.some((c) => c.includes(key))) return true;
      return false;
    }

    const marketCandidates = master.filter((it) => matchesMarket(it));
    if (!marketCandidates.length) return null;

    /* OPTION */
    if (["CE", "PE"].includes(wantedType)) {
      const opts = marketCandidates.filter((it) => {
        const st = Number(it.strike || it.strikePrice || 0);
        const ts = String(it.tradingsymbol || "").toUpperCase();
        return Math.abs(st - wantedStrike) < 0.5 && ts.endsWith(wantedType);
      });

      if (opts.length) {
        return { instrument: opts[0], token: String(opts[0].token) };
      }
    }

    /* FUTURE */
    if (wantedType === "FUT") {
      const futs = marketCandidates.filter((it) => {
        const itype = itypeOf(it);
        const st = Number(it.strike || it.strikePrice || 0);
        return itype.includes("FUT") && Math.abs(st) < 1;
      });

      if (futs.length) {
        return { instrument: futs[0], token: String(futs[0].token) };
      }
    }

    /* FALLBACK */
    const any = marketCandidates.find((it) => it.token);
    if (any) return { instrument: any, token: String(any.token) };

    return null;
  } catch (err) {
    console.log("resolveInstrumentToken ERROR:", err);
    return null;
  }
}
/* PART 5/6 — CANDLES (HISTORICAL + REALTIME), RSI, ATR, LTP */

/* FETCH HISTORICAL CANDLES */
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
  } catch (e) {
    console.log("fetchCandles ERR", e);
    return [];
  }
}

/* fetchRecentCandles */
async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    if (interval === 1 && realtime.candles1m && realtime.candles1m[symbol]) {
      const arr = realtime.candles1m[symbol];
      return arr.slice(-limit);
    }

    let intv = "ONE_MINUTE";
    if (interval === 5) intv = "FIVE_MINUTE";

    const candles = await fetchCandles(
      symbol,
      intv,
      Math.ceil(limit / (interval === 1 ? 1 : 5))
    );
    return candles.slice(-limit);
  } catch (e) {
    console.log("fetchRecentCandles ERR", e);
    return [];
  }
}

/* RSI CALCULATOR */
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

    const rs = gains / losses;
    return 100 - 100 / (1 + rs);
  } catch (e) {
    console.log("computeRSI ERR", e);
    return null;
  }
}

/* ATR HELPER */
async function computeATR(symbol, interval = 1, limit = 14) {
  try {
    const candles = await fetchRecentCandles(symbol, interval, limit + 1);
    if (!candles || candles.length < 2) return 0;

    const trs = [];

    for (let i = 1; i < candles.length; i++) {
      const cur = candles[i];
      const prev = candles[i - 1];
      const tr = Math.max(
        cur.high - cur.low,
        Math.abs(cur.high - prev.close),
        Math.abs(cur.low - prev.close)
      );
      trs.push(tr);
    }

    if (!trs.length) return 0;
    return trs.reduce((a, b) => a + b, 0) / trs.length;
  } catch (e) {
    console.log("computeATR ERR", e);
    return 0;
  }
}

/* FETCH LTP (SPOT) — REST FALLBACK */
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
    const ltp = Number(
      j?.data?.ltp || j?.data?.ltpValue || j?.data?.lastPrice || 0
    );

    return ltp > 0 ? ltp : null;
  } catch (e) {
    console.log("fetchLTP ERR", e);
    return null;
  }
}
/* PART 6/6 — API ROUTES + AUTO MODE CALC */

/* API: GET SPOT */
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
      return res.json({
        success: true,
        source: "REST",
        spot: fallback
      });
    }

    return res.json({
      success: false,
      error: "SPOT_NOT_AVAILABLE"
    });
  } catch (e) {
    return res.json({
      success: false,
      error: "SPOT_EXCEPTION",
      detail: String(e)
    });
  }
});

/* API: /api/calc  — AUTO MODE */
app.post("/api/calc", async (req, res) => {
  try {
    const {
      market,
      ema20,
      ema50,
      vwap,
      rsi,
      spot,          // optional
      expiry_days    // optional
    } = req.body || {};

    /* -------------------------------
       AUTO EXPIRY (if not provided)
    -------------------------------- */
    let expiryDays = Number(expiry_days);
    let expirySource = "FRONTEND";

    if (!expiryDays || expiryDays <= 0) {
      const exp = detectExpiryForSymbol(market);
      expiryDays = moment(exp.currentWeek).diff(moment(), "days");
      expirySource = "AUTO";
    }

    /* -------------------------------
       AUTO SPOT RESOLUTION
       Priority:
       1) WS live
       2) Futures LTP
       3) Spot LTP (REST)
       4) Frontend spot (fallback)
    -------------------------------- */
    let finalSpot = null;
    let spotSource = null;

    // 1️⃣ WS LIVE
    if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) {
      finalSpot = lastKnown.spot;
      spotSource = "WS";
    }

    // 2️⃣ FUTURE LTP
    if (!finalSpot) {
      const fut = await fetchFuturesLTP(market);
      if (fut && isFinite(fut)) {
        finalSpot = fut;
        spotSource = "FUTURE";
        lastKnown.spot = fut;
        lastKnown.updatedAt = Date.now();
      }
    }

    // 3️⃣ SPOT REST LTP
    if (!finalSpot) {
      const ltp = await fetchLTP(market);
      if (ltp && isFinite(ltp)) {
        finalSpot = ltp;
        spotSource = "REST";
        lastKnown.spot = ltp;
        lastKnown.updatedAt = Date.now();
      }
    }

    // 4️⃣ FRONTEND FALLBACK
    if (!finalSpot && spot && isFinite(Number(spot))) {
      finalSpot = Number(spot);
      spotSource = "FRONTEND";
      lastKnown.spot = finalSpot;
      lastKnown.updatedAt = Date.now();
    }

    /* -------------------------------
       DATA READINESS GUARD
    -------------------------------- */
    if (!finalSpot || !isFinite(finalSpot) || !expiryDays) {
      return res.json({
        success: false,
        error: "WAITING_FOR_LIVE_DATA",
        debug: {
          finalSpot,
          expiryDays,
          wsConnected: wsStatus.connected,
          lastTickAt: lastKnown.updatedAt || null
        }
      });
    }

    /* -------------------------------
       ENTRY COMPUTE (UNCHANGED)
    -------------------------------- */
    const entry = await computeEntry({
      market,
      spot: finalSpot,
      ema20,
      ema50,
      vwap,
      rsi,
      expiry_days: expiryDays,
      lastSpot: lastKnown.prevSpot || null
    });

    lastKnown.prevSpot = finalSpot;

    return res.json({
      success: true,
      entry,
      meta: {
        spotSource,
        expirySource,
        wsConnected: wsStatus.connected
      }
    });
  } catch (err) {
    return res.json({
      success: false,
      error: "EXCEPTION_IN_CALC",
      detail: String(err)
    });
  }
});

/* API: WS STATUS */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions
  });
});

/* API: PING */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    live: wsStatus.connected,
    spot: lastKnown.spot || null
  });
});

/* START SERVER */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
