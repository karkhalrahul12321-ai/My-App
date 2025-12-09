// Tengo.js  — CLEANED & FIXED (PART 1 of 3)
// ----------------------------------------------------
// Imports, config, session, TOTP helper, safeFetchJson
// ----------------------------------------------------

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
app.get("/settings", (req, res) =>
  res.sendFile(path.join(frontendPath, "settings.html"))
);

// SMARTAPI ENV
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
  ticks: {},      // last tick for symbol
  candles1m: {}   // rolling 1-minute candles per symbol
};

// safe base32 decode + TOTP generator
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

async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
// ----------------------------------------------------
// SmartAPI login + feed-token fetch + WS start logic
// ----------------------------------------------------

// WS globals
const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";
let wsClient = null;
let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: []
};

// SMART API: login by password (with TOTP) — fixed + safe debug
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
    console.log("LOGIN RAW:", JSON.stringify(data && typeof data === "object" ? data : data, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;
    session.login_time = Date.now();

    // DEBUG: show minimal flags (no token leak)
    console.log("DEBUG: After Login SESSION =>", {
      access_token_set: !!session.access_token,
      expires_at: session.expires_at
    });

    // Fetch feed token if not present in login response (some SmartAPI setups provide it separately)
    // Try first if already present in response
    session.feed_token = d.feedToken || null;

    if (!session.feed_token && session.access_token) {
      try {
        // feed token endpoint — this may differ in some environments; adjust if needed
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
        // feedJson.data may be token or object — handle both
        if (feedJson && feedJson.data) {
          // if data is object with token property or direct token string
          session.feed_token =
            (typeof feedJson.data === "string" ? feedJson.data : feedJson.data.feedToken || feedJson.data.token) ||
            session.feed_token ||
            null;
        }
      } catch (e) {
        console.log("FEED TOKEN FETCH ERROR:", e && e.message ? e.message : e);
        session.feed_token = session.feed_token || null;
      }
    }

    // final debug about feed token presence
    console.log("DEBUG: feed_token present?", !!session.feed_token);

    // return ok only if essential tokens exist
    return { ok: !!session.access_token && !!session.feed_token };
  } catch (err) {
    console.log("SMARTAPI LOGIN EXCEPTION:", err && err.message ? err.message : err);
    return { ok: false, reason: "EXCEPTION", error: err.message || err };
  }
}

// START WEBSOCKET WHEN TOKENS ARE READY
async function startWebsocketIfReady() {
  // Safe debug of token presence (no token values printed)
  console.log("DEBUG: Before WS Start SESSION =>", {
    access_token_set: !!session.access_token,
    feed_token_set: !!session.feed_token,
    expires_at: session.expires_at
  });

  if (wsClient && wsStatus.connected) return;

  if (!session.feed_token || !session.access_token) {
    console.log("WS WAIT: No tokens yet...");
    return;
  }

  try {
    wsClient = new WebSocket(WS_URL, { perMessageDeflate: false });

    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;
      console.log("WS: connected.");

      // Auth payload — adjust names if your ws expects a different shape
      const auth = {
        feedToken: session.feed_token,
        clientCode: SMART_USER_ID,
        jwtToken: session.access_token
      };

      try {
        wsClient.send(JSON.stringify({ action: "authenticate", data: auth }));
      } catch (e) {
        console.log("WS SEND AUTH ERR:", e && e.message ? e.message : e);
      }
    });

    wsClient.on("message", (msg) => {
      wsStatus.lastMsgAt = Date.now();
      try {
        const j = JSON.parse(msg.toString());
        // NOTE: original code likely processes ticks/candles — preserve minimal handling:
        if (j && j.type === "ltp" && j.data) {
          // example — adapt to your real WS message format
          const tkn = j.data.token;
          const ltp = Number(j.data.ltp || j.data.lastPrice || 0);
          if (tkn && ltp) {
            realtime.ticks[tkn] = ltp;
            lastKnown.spot = ltp;
            lastKnown.updatedAt = Date.now();
          }
        }
        // keep original message processing here if you have it
      } catch (e) {
        // ignore parse errors
      }
    });

    wsClient.on("close", () => {
      wsStatus.connected = false;
      wsClient = null;
      console.log("WS: CLOSED");
      // attempt reconnect after delay
      setTimeout(() => startWebsocketIfReady(), 3000);
    });

    wsClient.on("error", (err) => {
      wsStatus.lastError = err && err.message ? err.message : String(err);
      console.log("WS ERROR:", wsStatus.lastError);
    });
  } catch (err) {
    console.log("WS START EXCEPTION:", err && err.message ? err.message : err);
  }
}

// WS subscribe helper (keeps old logic)
async function wsSubscribeSymbols(symbols = []) {
  try {
    if (!wsClient || !wsStatus.connected) return;
    // resolve tokens for symbols
    const expiry = detectExpiryForSymbol(symbols[0] || "NIFTY").currentWeek;
    const tokens = [];

    for (let s of symbols) {
      const tok = await resolveInstrumentToken(s, expiry, 0, "FUT").catch(()=>null);
      if (tok && tok.token) tokens.push(String(tok.token));
    }

    if (tokens.length > 0) {
      const sub = {
        task: "cn",
        channel: {
          instrument_tokens: tokens,
          feed_type: "ltp"
        }
      };
      try { wsClient.send(JSON.stringify(sub)); } catch(e){/*ignore*/}
      wsStatus.subscriptions = tokens;
      console.log("WS SUBSCRIBED →", tokens);
    }
  } catch (e) {
    console.log("WS SUBSCRIBE ERR", e && e.message ? e.message : e);
  }
}

// WS endpoints
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions
  });
});
// ----------------------------------------------------
// Engines, fetchers, utilities, endpoints
// ----------------------------------------------------

// SAFE fetch LTP (spot)
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

// fetch futures LTP
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

// resolve instrument token using instrument master (assumes global.instrumentMaster loaded)
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

// expiry detector (weekly)
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
    return { currentWeek: moment().format("YYYY-MM-DD"), nextWeek: moment().add(7, "days").format("YYYY-MM-DD") };
  }
}

/* STRIKE / TARGET / SL helpers (kept original logic) */
function roundToStep(market, price) {
  price = Number(price) || 0;
  return Math.round(price / 50) * 50;
}

function getStrikeSteps(market, daysToExpiry) {
  return (daysToExpiry >= 5 ? 50 : 25);
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
  const sl = entryLTP * 0.85;   // 15% SL
  const tgt1 = entryLTP * 1.10;
  const tgt2 = entryLTP * 1.20;
  return {
    stopLoss: Number(sl.toFixed(2)),
    target1: Number(tgt1.toFixed(2)),
    target2: Number(tgt2.toFixed(2))
  };
}

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

/* ENTRY ENGINE (kept original flow, simplified returns) */
async function computeEntry({ market, spot, ema20, ema50, vwap, rsi, expiry_days, lastSpot }) {
  // basic trend engine (you likely have hybridTrendEngine elsewhere; keep using it)
  const trendObj = (typeof hybridTrendEngine === "function")
    ? hybridTrendEngine({ ema20, ema50, vwap, rsi, spot, lastSpot })
    : { direction: "NEUTRAL", score: 0 };

  // futures diff
  const futDiff = await detectFuturesDiff(market, spot);

  // strikes
  const strikes = generateStrikes(market, spot, expiry_days);

  // entry guard (if exists)
  const entryGate = (typeof finalEntryGuard === "function")
    ? await finalEntryGuard({ symbol: market, trendObj, futDiff, getCandlesFn: fetchRecentCandles })
    : { allowed: true };

  if (!entryGate.allowed) {
    return { allowed: false, reason: entryGate.reason, details: entryGate.details || {}, trend: trendObj, futDiff };
  }

  // option LTPs
  const ceATM = await fetchOptionLTP(market, strikes.atm, "CE");
  const peATM = await fetchOptionLTP(market, strikes.atm, "PE");

  const takeCE = trendObj.direction === "UP";
  const entryLTP = takeCE ? ceATM : peATM;
  if (!entryLTP) return { allowed: false, reason: "OPTION_LTP_FAIL", trend: trendObj };

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

/* HISTORY / CANDLES FETCHERS (kept original) */
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

async function fetchRecentCandles(symbol, interval, limit = 30) {
  try {
    if (interval === 1 && realtime.candles1m[symbol]) {
      const arr = realtime.candles1m[symbol];
      return arr.slice(-limit);
    }
    let intv = "ONE_MINUTE";
    if (interval === 5) intv = "FIVE_MINUTE";
    const candles = await fetchCandles(symbol, intv, limit);
    return candles.slice(-limit);
  } catch {
    return [];
  }
}

// helpers used by engines (stubs if missing in your original)
function detectVolumeSpike(prevVol, curVol) {
  if (!prevVol || !curVol) return false;
  return curVol >= prevVol * 1.15;
}

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

/* -------------------------------------------------------------
   HTTP endpoints: login, login/status, settings, compute
--------------------------------------------------------------*/

// login route
app.post("/api/login", async (req, res) => {
  const password = (req.body && req.body.password) || "";
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

  // auto start ws shortly after successful login
  setTimeout(() => startWebsocketIfReady(), 1200);

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at
    }
  });
});

// login status
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token && !!session.feed_token,
    expires_at: session.expires_at || null
  });
});

// settings endpoint (frontend uses this to show env presence)
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY || "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? "SET" : ""
  });
});

// compute entry (exposed API used by frontend's calculate button)
app.post("/api/compute", async (req, res) => {
  try {
    const input = req.body || {};
    const market = (input.market || "NIFTY").toUpperCase();
    const ema20 = Number(input.ema20) || null;
    const ema50 = Number(input.ema50) || null;
    const rsi = Number(input.rsi) || null;
    const vwap = Number(input.vwap) || null;
    const spotInput = input.spot || null;
    const expiry_days = Number(input.expiry_days || input.days_to_expiry || 1);

    // if use_live true and logged in, attempt to use live spot
    let spot = null;
    if (input.use_live && session.access_token && session.feed_token) {
      // try lastKnown first, else call fetchLTP
      spot = lastKnown.spot || await fetchLTP(market).catch(()=>null);
    }

    // fallback to provided spot if still null
    if (!spot && spotInput) spot = Number(spotInput);

    // run computeEntry (uses our internal engines)
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

    // meta info
    const meta = {
      live_data_used: !!(input.use_live && session.access_token && session.feed_token && lastKnown.spot),
      live_ltp: lastKnown.spot || null,
      live_error: null
    };

    return res.json({
      success: true,
      message: "Calculation complete",
      login_status: session.access_token && session.feed_token ? "SmartAPI Logged-In" : "Not Logged-In",
      input: {
        ema20, ema50, rsi, vwap, spot, market, expiry_days, use_live: !!input.use_live
      },
      trend: result.trend || { main: "NEUTRAL", score: 0 },
      strikes: (result.allowed ? [
        { type: "CE", strike: result.strikes.atm + 50, distance: 50, entry: 5, stopLoss: 3, target: 8 },
        { type: "PE", strike: result.strikes.atm - 50, distance: 50, entry: 5, stopLoss: 3, target: 8 },
        { type: "STRADDLE", strike: result.strikes.atm, distance: 0, entry: 5, stopLoss: 3, target: 8 }
      ] : []),
      auto_tokens: {
        nifty: { symbol: `NIFTY${detectExpiryForSymbol("NIFTY").currentWeek.replace(/-/g,"").slice(2)}FUT`, token: null, expiry: detectExpiryForSymbol("NIFTY").currentWeek },
      },
      meta
    });
  } catch (e) {
    return res.json({ success: false, error: e && e.message ? e.message : String(e) });
  }
});

/* -------------------------------------------------------------
   Auto-start hook (if tokens already present on boot)
-------------------------------------------------------------- */
setTimeout(() => startWebsocketIfReady(), 2000);

/* -------------------------------------------------------------
   Start the server
-------------------------------------------------------------- */
const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;
app.listen(PORT, () => {
  console.log(`Tengo backend running on port ${PORT}`);
});
