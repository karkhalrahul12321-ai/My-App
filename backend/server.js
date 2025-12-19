/* =========================================================
   PART 1/8 — BASE IMPORTS + GLOBALS + MASTER LOADER
   ========================================================= */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

/* =========================================================
   GLOBAL MASTER (ONLINE)
   ========================================================= */
global.instrumentMaster = [];

/* GLOBAL SYMBOL NORMALIZER */
global.tsof = function (entry) {
  return String(
    entry?.tradingsymbol ||
    entry?.tradingSymbol ||
    entry?.symbol ||
    entry?.name ||
    ""
  ).toUpperCase();
};

/* =========================================================
   LOAD MASTER ONLINE (ORIGINAL LOGIC)
   ========================================================= */
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

/* =========================================================
   EXPRESS APP
   ========================================================= */
const app = express();
app.use(cors());
app.use(bodyParser.json());

/* =========================================================
   FRONTEND SERVE (UNCHANGED)
   ========================================================= */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

app.get("/", (req, res) =>
  res.sendFile(path.join(frontendPath, "index.html"))
);

app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

/* =========================================================
   SMART API ENV (UNCHANGED)
   ========================================================= */
const SMARTAPI_BASE =
  process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";

const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

/* =========================================================
   SESSION STORE (UNCHANGED)
   ========================================================= */
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: null
};

/* =========================================================
   LAST KNOWN SPOT MEMORY (UNCHANGED)
   ========================================================= */
let lastKnown = {
  spot: null,
  prevSpot: null,
  updatedAt: 0
};
/* =========================================================
   PART 2/8 — TOTP + LOGIN + SAFE HELPERS
   ========================================================= */

/* =========================================================
   BASE32 + TOTP (ORIGINAL LOGIC)
   ========================================================= */
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

/* =========================================================
   SAFE FETCH JSON
   ========================================================= */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/* =========================================================
   SMART API LOGIN (ORIGINAL)
   ========================================================= */
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
    console.log("SMARTAPI LOGIN EXCEPTION:", err);
    return {
      ok: false,
      reason: "EXCEPTION",
      error: err.message
    };
  }
}

/* =========================================================
   LOGIN ROUTES (UNCHANGED)
   ========================================================= */
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
  const r = await smartApiLogin(password);

  if (!r.ok) {
    return res.json({
      success: false,
      error: r.reason,
      raw: r.raw || null
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

app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET || ""
  });
});

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
/* =========================================================
   PART 3/8 — WEBSOCKET CORE + TOKEN GROUPS
   ========================================================= */

const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";

let wsClient = null;
let wsHeartbeat = null;

/* =========================================================
   WS STATUS (UNCHANGED)
   ========================================================= */
let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

/* =========================================================
   REALTIME STORES (UNCHANGED)
   ========================================================= */
const realtime = {
  ticks: {},
  candles1m: {}
};

/* =========================================================
   OPTION WS TOKENS (ORIGINAL)
   ========================================================= */
const optionWsTokens = new Set();
let subscribedTokens = new Set();

/* OPTION LTP STORE */
const optionLTP = {};

/* =========================================================
   WS TOKEN GROUPS (EXCHANGE WISE)
   ========================================================= */
const wsTokenGroups = {
  NFO: [],
  BFO: [],
  MCX: []
};

function isTokenSane(t) {
  if (!t && t !== 0) return false;
  const n = Number(String(t).replace(/\D/g, "")) || 0;
  return n > 0;
}

function addWsToken(token, exchangeType) {
  if (!wsTokenGroups[exchangeType]) return;
  const t = String(token);
  if (!wsTokenGroups[exchangeType].includes(t)) {
    wsTokenGroups[exchangeType].push(t);
  }
}

/* =========================================================
   START WEBSOCKET (ORIGINAL FLOW)
   ========================================================= */
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

    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (!msg || !msg.data) return;
    const d = msg.data;

    const token = d.token || d.instrument_token || null;
    const sym = d.tradingsymbol || d.symbol || null;
    const ltp = Number(
      d.ltp ??
      d.last_traded_price ??
      d.lastPrice ??
      d.price ??
      d.close ??
      0
    );

    if (!token || !ltp) return;

    /* ===== OPTION LTP STORE ===== */
    optionLTP[token] = {
      ltp,
      symbol: sym,
      time: Date.now()
    };

    /* ===== TICK STORE ===== */
    if (sym) {
      realtime.ticks[sym] = {
        ltp,
        time: Date.now()
      };
    }

    /* ===== 1-MIN CANDLES ===== */
    if (sym) {
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
          volume: Number(d.volume || 0)
        });
        if (arr.length > 180) arr.shift();
      } else {
        cur.high = Math.max(cur.high, ltp);
        cur.low = Math.min(cur.low, ltp);
        cur.close = ltp;
        cur.volume += Number(d.volumeDelta || 0);
      }
    }
  });

  wsClient.on("error", (err) => {
    wsStatus.connected = false;
    wsStatus.lastError = String(err);
    console.log("WS ERR:", err);
    scheduleWSReconnect();
  });

  wsClient.on("close", (code) => {
    wsStatus.connected = false;
    wsStatus.lastError = "closed:" + code;
    console.log("WS CLOSED", code);
    scheduleWSReconnect();
  });
}

/* =========================================================
   WS RECONNECT (UNCHANGED)
   ========================================================= */
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

/* =========================================================
   WS STATUS API
   ========================================================= */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsTokenGroups
  });
});

/* =========================================================
   AUTO START WS AFTER LOGIN (UNCHANGED)
   ========================================================= */
const _origSmartLogin = smartApiLogin;
smartApiLogin = async function (pw) {
  const r = await _origSmartLogin(pw);
  if (r && r.ok) {
    setTimeout(() => startWebsocketIfReady(), 1200);
  }
  return r;
};

setTimeout(() => startWebsocketIfReady(), 2000);
/* =========================================================
   PART 4/8 — EXPIRY + TOKEN RESOLVER (ORIGINAL + FIX)
   ========================================================= */

/* =========================================================
   EXPIRY DETECTOR (ORIGINAL LOGIC)
   ========================================================= */
function detectExpiryForSymbol(symbol, expiryDays = 0) {
  symbol = String(symbol || "").toUpperCase();

  if (Number(expiryDays) > 0) {
    const base = new Date();
    const target = new Date(base);
    target.setDate(base.getDate() + Number(expiryDays));
    target.setHours(0, 0, 0, 0);

    return {
      targetDate: target,
      currentWeek: moment(target).format("YYYY-MM-DD"),
      monthly: moment(target).format("YYYY-MM-DD")
    };
  }

  const today = moment();
  let weeklyExpiryDay = 4; // Thursday

  if (symbol.includes("NIFTY")) weeklyExpiryDay = 2;
  if (symbol.includes("SENSEX")) weeklyExpiryDay = 2;

  let currentWeek = today.clone().day(weeklyExpiryDay);
  if (currentWeek.isBefore(today, "day")) {
    currentWeek.add(1, "week");
  }

  let monthly = today.clone().endOf("month");
  while (monthly.day() !== weeklyExpiryDay) {
    monthly.subtract(1, "day");
  }

  return {
    currentWeek: currentWeek.format("YYYY-MM-DD"),
    monthly: monthly.format("YYYY-MM-DD"),
    targetDate: currentWeek.toDate()
  };
}

/* =========================================================
   EXPIRY PARSER (ORIGINAL)
   ========================================================= */
function parseExpiryDate(v) {
  if (!v) return null;
  const m = moment(
    String(v).trim(),
    ["YYYY-MM-DD", "YYYYMMDD", "DD-MM-YYYY", "DDMMYYYY", "DDMMMYYYY"],
    true
  );
  if (m.isValid()) return m.toDate();

  const d = new Date(v);
  return isFinite(d.getTime()) ? d : null;
}

/* =========================================================
   TOKEN RESOLVER (ORIGINAL FLOW + 🔥 FIX)
   ========================================================= */
async function resolveInstrumentToken(symbol, expiry = "", strike = 0, type = "FUT") {
  try {
    if (!global.instrumentMaster || !global.instrumentMaster.length) {
      return null;
    }

    symbol = String(symbol || "").trim().toUpperCase();
    type = String(type || "").trim().toUpperCase();
    strike = Number(strike || 0);

    const wantedKey = symbol.replace(/[^A-Z]/g, "");
    if (!wantedKey) return null;

    /* -------------------------------
       FILTER BY SYMBOL
       ------------------------------- */
    const candidates = global.instrumentMaster.filter((it) => {
      const ts = global.tsof(it);
      return (
        ts.startsWith(wantedKey) ||
        ts.includes(wantedKey) ||
        String(it.name || "").toUpperCase().includes(wantedKey)
      );
    });

    if (!candidates.length) return null;

    /* =====================================================
       OPTION RESOLVER (CE / PE) — ORIGINAL + FIX
       ===================================================== */
    if (type === "CE" || type === "PE") {
      const side = type;
      const approxStrike = Number(strike || 0);

      const optList = candidates.filter((it) => {
        const itype =
          String(it.instrumenttype || it.instrumentType || "").toUpperCase();
        if (!itype.includes("OPT")) return false;

        const ts = global.tsof(it);
        if (!ts.includes(side)) return false;

        let st = Number(it.strike || it.strikePrice || 0);
        if (st > 100000) st = Math.round(st / 100);
        if (st > 10000) st = Math.round(st / 10);

        if (approxStrike > 0) {
          if (Math.abs(st - approxStrike) > 100) return false;
        }

        return true;
      });

      if (!optList.length) return null;

      /* nearest expiry */
      const pick = optList
        .map((it) => {
          const ex = parseExpiryDate(
            it.expiry || it.expiryDate || it.expiry_dt || it.expiryDateTime
          );
          const diff = ex ? Math.abs(ex.getTime() - Date.now()) : Infinity;
          return { it, diff };
        })
        .sort((a, b) => a.diff - b.diff)[0].it;

      console.log("✅ FINAL PICK (nearest expiry)", {
        tradingSymbol:
          pick.tradingSymbol ||
          pick.tradingsymbol ||
          pick.symbol ||
          pick.name,
        expiry:
          pick.expiry ||
          pick.expiryDate ||
          pick.expiry_dt ||
          pick.expiryDateTime,
        strike: pick.strike,
        token: pick.token
      });

      /* ===============================
         🔥 OPTION WS RESUBSCRIBE FIX
         =============================== */
      if (isTokenSane(pick.token)) {
        addWsToken(pick.token, "NFO");

        if (wsClient && wsStatus.connected) {
          if (!global._wsResubTimer) {
            global._wsResubTimer = setTimeout(() => {
              console.log("🔁 WS RESUBSCRIBE (OPTION TOKEN)", pick.token);
              subscribeCoreSymbols();
              global._wsResubTimer = null;
            }, 300);
          }
        }
      }

      return {
        instrument: pick,
        token: String(pick.token)
      };
    }

    /* =====================================================
       INDEX RESOLVER (ORIGINAL)
       ===================================================== */
    if (type === "INDEX") {
      const idx = candidates.find((it) =>
        String(it.instrumenttype || "").toUpperCase().includes("INDEX")
      );
      if (idx && isTokenSane(idx.token)) {
        return { instrument: idx, token: String(idx.token) };
      }
    }

    /* =====================================================
       FUTURES RESOLVER (ORIGINAL)
       ===================================================== */
    const futList = candidates
      .filter((it) =>
        String(it.instrumenttype || "").toUpperCase().includes("FUT")
      )
      .map((it) => {
        const ex = parseExpiryDate(
          it.expiry || it.expiryDate || it.expiry_dt
        );
        const diff = ex ? Math.abs(ex.getTime() - Date.now()) : Infinity;
        return { it, diff };
      })
      .sort((a, b) => a.diff - b.diff);

    if (futList.length && isTokenSane(futList[0].it.token)) {
      return {
        instrument: futList[0].it,
        token: String(futList[0].it.token)
      };
    }

    return null;
  } catch (err) {
    console.log("resolveInstrumentToken ERROR:", err);
    return null;
  }
}
/* =========================================================
   PART 5/8 — FUTURES LTP + OPTION LTP (ORIGINAL)
   ========================================================= */

/* =========================================================
   FUTURES LTP FETCHER
   ========================================================= */
async function fetchFuturesLTP(symbol) {
  try {
    const expiry = detectExpiryForSymbol(symbol).currentWeek;

    const tokenInfo = await resolveInstrumentToken(
      symbol,
      expiry,
      0,
      "FUT"
    );

    if (!tokenInfo) return null;

    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

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
  } catch (e) {
    console.log("fetchFuturesLTP ERR", e);
    return null;
  }
}

/* =========================================================
   FUTURES DIFF DETECTOR
   ========================================================= */
async function detectFuturesDiff(symbol, spotUsed) {
  try {
    const fut = await fetchFuturesLTP(symbol);
    if (!fut || !isFinite(spotUsed)) return null;
    return Number(fut) - Number(spotUsed);
  } catch {
    return null;
  }
}

/* =========================================================
   WAIT FOR FIRST OPTION WS TICK
   ========================================================= */
function waitForOptionFirstTick(token, timeout = 4000) {
  return new Promise((resolve) => {
    const start = Date.now();

    const t = setInterval(() => {
      if (optionLTP[token] && optionLTP[token].ltp > 0) {
        clearInterval(t);
        resolve(optionLTP[token].ltp);
      }

      if (Date.now() - start > timeout) {
        clearInterval(t);
        resolve(null);
      }
    }, 50);
  });
}

/* =========================================================
   OPTION LTP FETCHER (WS → REST FALLBACK)
   ========================================================= */
async function fetchOptionLTP(symbol, strike, type, expiry_days) {
  try {
    const expiryInfo = detectExpiryForSymbol(symbol, expiry_days);
    const expiry = expiryInfo.currentWeek;

    const tokenInfo = await resolveInstrumentToken(
      symbol,
      expiry,
      strike,
      type
    );

    if (!tokenInfo?.token) return null;

    /* -------------------------------
       STEP 1: WAIT FOR WS TICK
       ------------------------------- */
    const firstLTP = await waitForOptionFirstTick(tokenInfo.token);

    if (firstLTP && firstLTP > 0) {
      return firstLTP;
    }

    /* -------------------------------
       STEP 2: REST FALLBACK
       ------------------------------- */
    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

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
        symboltoken: String(tokenInfo.token)
      })
    });

    const j = await r.json().catch(() => null);
    const apiLtp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return apiLtp > 0 ? apiLtp : null;
  } catch (e) {
    console.log("fetchOptionLTP ERR", e);
    return null;
  }
}
/* =========================================================
   PART 6/8 — TREND + MOMENTUM + STRIKE + ENTRY GUARDS
   ========================================================= */

function safeNum(n) {
  n = Number(n);
  return isFinite(n) ? n : 0;
}

/* =========================================================
   BASIC TREND
   ========================================================= */
function computeBasicTrend(ema20, ema50, vwap, spot) {
  ema20 = safeNum(ema20);
  ema50 = safeNum(ema50);
  vwap = safeNum(vwap);
  spot = safeNum(spot);

  let score = 0;
  if (spot > ema20) score++;
  if (spot > ema50) score++;
  if (spot > vwap) score++;

  if (spot < ema20) score--;
  if (spot < ema50) score--;
  if (spot < vwap) score--;

  let direction = "NEUTRAL";
  if (score >= 2) direction = "UP";
  if (score <= -2) direction = "DOWN";

  return { score, direction };
}

/* =========================================================
   MOMENTUM
   ========================================================= */
function computeMomentumTrend(spot, prevSpot) {
  spot = safeNum(spot);
  prevSpot = safeNum(prevSpot);

  if (!prevSpot) return { momentum: "NEUTRAL", slope: 0 };

  const diff = spot - prevSpot;
  if (diff > 3) return { momentum: "UP", slope: diff };
  if (diff < -3) return { momentum: "DOWN", slope: diff };

  return { momentum: "NEUTRAL", slope: diff };
}

/* =========================================================
   RSI FILTER
   ========================================================= */
function rsiTrendGate(rsi, direction) {
  rsi = safeNum(rsi);
  if (direction === "UP") return rsi > 50;
  if (direction === "DOWN") return rsi < 40;
  return false;
}

/* =========================================================
   HYBRID TREND ENGINE
   ========================================================= */
function hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot }) {
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
    base,
    momentum: mom,
    rsiOk
  };
}

/* =========================================================
   STRIKE GENERATION
   ========================================================= */
function roundToStep(market, price) {
  price = Number(price) || 0;
  return Math.round(price / 50) * 50;
}

function generateStrikes(market, spot, expiry_days) {
  const base = roundToStep(market, spot);
  const dist =
    expiry_days <= 1 ? 50 :
    expiry_days <= 3 ? 100 :
    expiry_days <= 5 ? 150 :
    200;

  return {
    atm: base,
    otm1: base + dist,
    otm2: base - dist
  };
}

/* =========================================================
   TARGETS + SL
   ========================================================= */
function computeTargetsAndSL(entryLTP) {
  entryLTP = Number(entryLTP) || 0;

  const stopLoss = entryLTP * 0.85;
  const target1 = entryLTP * 1.10;
  const target2 = entryLTP * 1.20;

  return {
    stopLoss: Number(stopLoss.toFixed(2)),
    target1: Number(target1.toFixed(2)),
    target2: Number(target2.toFixed(2))
  };
}
/* =========================================================
   PART 7/8 — CANDLES + RSI + ATR + LTP HELPERS
   ========================================================= */

/* =========================================================
   FETCH HISTORICAL CANDLES
   ========================================================= */
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

/* =========================================================
   FETCH RECENT CANDLES
   ========================================================= */
async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    if (interval === 1 && realtime.candles1m && realtime.candles1m[symbol]) {
      return realtime.candles1m[symbol].slice(-limit);
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

/* =========================================================
   RSI CALCULATOR
   ========================================================= */
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

/* =========================================================
   ATR HELPER
   ========================================================= */
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

/* =========================================================
   INDEX SPOT LTP
   ========================================================= */
async function fetchLTP(symbol) {
  try {
    const idx = await resolveInstrumentToken(symbol, "", 0, "INDEX");
    if (!idx?.token) return null;

    const url =
      `${SMARTAPI_BASE}/rest/secure/angelbroking/order/v1/getLtpData`;

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
        exchange: idx.instrument.exchange || "NSE",
        tradingsymbol: idx.instrument.tradingsymbol,
        symboltoken: idx.token
      })
    });

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice || 0);

    return ltp > 0 ? ltp : null;
  } catch (e) {
    console.log("fetchLTP ERR", e);
    return null;
  }
}
/* =========================================================
   PART 8/8 — API ROUTES + CALC + SPOT + SERVER START
   ========================================================= */

/* =========================================================
   API: GET SPOT
   ========================================================= */
app.get("/api/spot", async (req, res) => {
  try {
    const market = String(req.query.market || "NIFTY").toUpperCase();

    /* WS CACHE (FAST) */
    if (
      lastKnown.spot &&
      Date.now() - (lastKnown.updatedAt || 0) < 5000
    ) {
      return res.json({
        success: true,
        source: "WS",
        spot: lastKnown.spot
      });
    }

    /* INDEX REST FALLBACK */
    if (market === "NIFTY" || market === "SENSEX") {
      const INDEX_MAP = {
        NIFTY: "NIFTY 50",
        SENSEX: "SENSEX"
      };

      const symbol = INDEX_MAP[market];
      const spot = await fetchLTP(symbol);

      if (!spot) {
        return res.json({
          success: false,
          error: "SPOT_NOT_AVAILABLE"
        });
      }

      lastKnown.prevSpot = lastKnown.spot;
      lastKnown.spot = spot;
      lastKnown.updatedAt = Date.now();

      return res.json({
        success: true,
        source: "REST",
        spot
      });
    }

    /* NATURAL GAS → FUTURE AS SPOT */
    if (market === "NATURALGAS" || market === "NATURAL GAS") {
      const fut = await fetchFuturesLTP("NATURALGAS");
      if (!fut) {
        return res.json({
          success: false,
          error: "FUT_LTP_NOT_AVAILABLE"
        });
      }
      return res.json({
        success: true,
        source: "FUTURE",
        spot: fut
      });
    }

    return res.json({
      success: false,
      error: "INVALID_MARKET"
    });
  } catch (e) {
    return res.json({
      success: false,
      error: "SPOT_EXCEPTION",
      detail: String(e)
    });
  }
});

/* =========================================================
   API: RESOLVE TOKEN
   ========================================================= */
app.get("/api/token/resolve", async (req, res) => {
  try {
    const market = String(req.query.market || "");
    const strike = Number(req.query.strike || 0);
    const type = String(req.query.type || "CE");

    const expiry = detectExpiryForSymbol(market).currentWeek;
    const tok = await resolveInstrumentToken(market, expiry, strike, type);

    if (!tok) {
      return res.json({
        success: false,
        error: "TOKEN_NOT_FOUND"
      });
    }

    return res.json({
      success: true,
      token: tok
    });
  } catch (e) {
    res.json({
      success: false,
      error: "EXCEPTION",
      detail: String(e)
    });
  }
});

/* =========================================================
   API: CALC (MAIN ENTRY ENGINE)
   ========================================================= */
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

    let finalSpot = null;

    /* 1) Manual spot */
    if (spot != null && isFinite(Number(spot))) {
      finalSpot = Number(spot);
    }
    /* 2) Cached WS spot */
    else if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) {
      finalSpot = lastKnown.spot;
    }
    /* 3) REST fallback */
    else {
      const INDEX_MAP = {
        NIFTY: "NIFTY 50",
        SENSEX: "SENSEX"
      };
      const sym = INDEX_MAP[market] || market;
      const fb = await fetchLTP(sym);
      if (fb && isFinite(fb)) {
        finalSpot = fb;
        lastKnown.spot = fb;
        lastKnown.updatedAt = Date.now();
      }
    }

    if (!finalSpot || !isFinite(finalSpot)) {
      return res.json({
        success: false,
        error: "SPOT_NOT_RESOLVED"
      });
    }

    const trendObj = hybridTrendEngine({
      ema20,
      ema50,
      vwap,
      rsi,
      spot: finalSpot,
      lastSpot: lastKnown.prevSpot || null
    });

    const futDiff = await detectFuturesDiff(market, finalSpot);
    const strikes = generateStrikes(market, finalSpot, expiry_days);

    const takeCE = trendObj.direction === "UP";
    const optionType = takeCE ? "CE" : "PE";

    const entryLTP = await fetchOptionLTP(
      market,
      strikes.atm,
      optionType,
      expiry_days
    );

    if (!entryLTP) {
      return res.json({
        success: true,
        entry: {
          allowed: false,
          reason: "OPTION_LTP_PENDING",
          hint: "WS waiting or REST retry",
          retryAfter: 1,
          trend: trendObj
        }
      });
    }

    const levels = computeTargetsAndSL(entryLTP);

    lastKnown.prevSpot = finalSpot;

    return res.json({
      success: true,
      entry: {
        allowed: true,
        direction: trendObj.direction,
        optionType,
        strike: strikes.atm,
        entryLTP,
        sl: levels.stopLoss,
        target1: levels.target1,
        target2: levels.target2,
        futDiff,
        trend: trendObj
      }
    });
  } catch (err) {
    console.error("❌ CALC ERROR:", err);
    return res.json({
      success: false,
      error: "EXCEPTION_IN_CALC",
      detail: err?.message || String(err)
    });
  }
});

/* =========================================================
   API: PING
   ========================================================= */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    live: wsStatus.connected,
    spot: lastKnown.spot || null
  });
});

/* =========================================================
   FALLBACK ROOT
   ========================================================= */
app.get("*", (req, res) => {
  res.send("Backend OK — WS Option Fix Applied 🚀");
});

/* =========================================================
   START SERVER
   ========================================================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
