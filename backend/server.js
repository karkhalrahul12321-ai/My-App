// ------------------------------------------------------------
// SERVER.JS (FINAL MODE-1 SMART-STREAM VERSION)
// PART 1 of 6
// ------------------------------------------------------------

import crypto from "node:crypto";
import fetch from "node-fetch";
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";

// ENV
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP_SECRET || "";
const SMARTAPI_BASE = "https://apiconnect.angelbroking.com";

// SESSION
let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
};

// Live tick cache
let lastKnown = {
  spot: null,
  updatedAt: 0,
};

// EXPRESS
const app = express();
app.use(cors());
app.use(bodyParser.json());

// ----------------------------------------------
// BASE32 → BYTES → TOTP (6 digit)
// ----------------------------------------------
function generateTOTP(secret) {
  try {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const clean = secret.replace(/=+$/, "").toUpperCase();
    let bits = 0;
    let value = 0;
    const bytes = [];

    for (let i = 0; i < clean.length; i++) {
      value = (value << 5) | alphabet.indexOf(clean[i]);
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((value >>> bits) & 0xff);
      }
    }

    const key = Buffer.from(bytes);
    const epoch = Math.floor(Date.now() / 1000);
    const timeStep = Math.floor(epoch / 30);

    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64BE(BigInt(timeStep));

    const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
    const offset = hmac[hmac.length - 1] & 0xf;

    const code =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    return (code % 1_000_000).toString().padStart(6, "0");
  } catch {
    return null;
  }
}

// --------------------------------------
// SAFE FETCH WRAPPER
// --------------------------------------
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const json = await r.json().catch(() => null);
    return { ok: true, status: r.status, data: json };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ------------------------------------------------------------
// END OF PART 1 — reply “NEXT” for PART 2
// ------------------------------------------------------------
// ------------------------------------------------------------
// PART 2 of 6 — SmartAPI Login + Feed Token Fetch
// ------------------------------------------------------------

// ------------------------------------------------------------
// SMART API LOGIN (Password + TOTP)
// ------------------------------------------------------------
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }

  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

    const payload = {
      clientcode: SMART_USER_ID,
      password: tradingPassword,
      totp,
    };

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
        body: JSON.stringify(payload),
      }
    );

    const data = await resp.json().catch(() => null);

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data };
    }

    const d = data.data || {};

    // STORE TOKENS
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000; // 20 hours

    console.log("LOGIN SUCCESS:", {
      access: !!session.access_token,
      feed: !!session.feed_token,
    });

    // IF FEED TOKEN NOT FOUND, FETCH SEPARATELY
    if (!session.feed_token && session.access_token) {
      const ft = await fetchFeedToken();
      if (ft) session.feed_token = ft;
    }

    return { ok: true };
  } catch (err) {
    console.log("LOGIN ERROR:", err.message);
    return { ok: false, reason: "EXCEPTION", error: err.message };
  }
}

// ------------------------------------------------------------
// FETCH FEED TOKEN (Backup method)
// ------------------------------------------------------------
async function fetchFeedToken() {
  try {
    const r = await fetch(`${SMARTAPI_BASE}/rest/auth/angelfeed/token`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        "X-PrivateKey": SMART_API_KEY,
        Authorization: `Bearer ${session.access_token}`,
      },
    });

    const j = await r.json().catch(() => null);

    if (j?.data) {
      if (typeof j.data === "string") return j.data;
      if (typeof j.data.feedToken === "string") return j.data.feedToken;
      if (typeof j.data.token === "string") return j.data.token;
    }

    return null;
  } catch (err) {
    console.log("FEED TOKEN FETCH ERROR:", err.message);
    return null;
  }
}

// ------------------------------------------------------------
// END OF PART 2 — reply “NEXT” for PART 3 (Smart-Stream WebSocket)
// ------------------------------------------------------------
// ------------------------------------------------------------
// PART 3 of 6 — Smart-Stream V2 WebSocket (URL-based auth)
// ------------------------------------------------------------

const WS_BASE = "wss://smartapisocket.angelone.in/smart-stream";

let wsClient = null;
let wsStatus = {
  connected: false,
  lastMsgAt: 0,
  lastError: null,
  reconnectAttempts: 0,
  subscriptions: [] // array of token strings currently subscribed
};

// build full ws url with query params (clientCode, feedToken, apiKey)
function buildFullWsUrl() {
  // safety checks
  if (!SMART_USER_ID || !SMART_API_KEY || !session.feed_token) return null;

  const qc = `clientCode=${encodeURIComponent(SMART_USER_ID)}`;
  const qf = `feedToken=${encodeURIComponent(session.feed_token)}`;
  const qa = `apiKey=${encodeURIComponent(SMART_API_KEY)}`;

  return `${WS_BASE}?${qc}&${qf}&${qa}`;
}

// start websocket only when tokens are ready
async function startWebsocketIfReady() {
  try {
    const fullUrl = buildFullWsUrl();

    if (!fullUrl) {
      console.log("WS: missing tokens; waiting for feed_token/jwt.");
      return;
    }

    // if already connected, do nothing
    if (wsClient && wsStatus.connected) return;

    // close previous if exists
    if (wsClient) {
      try { wsClient.terminate(); } catch (e) {}
      wsClient = null;
      wsStatus.connected = false;
    }

    // create client using full URL (url-based auth)
    console.log("WS: connecting to", fullUrl.replace(/(feedToken=)[^&]+/, "$1<hidden>"));
    wsClient = new WebSocket(fullUrl);

    wsClient.on("open", () => {
      wsStatus.connected = true;
      wsStatus.reconnectAttempts = 0;
      wsStatus.lastError = null;
      console.log("WS: connected (smart-stream).");

      // re-subscribe if we had tokens
      if (Array.isArray(wsStatus.subscriptions) && wsStatus.subscriptions.length > 0) {
        try { sendWsSubscribe(wsStatus.subscriptions); } catch(_) {}
      }
    });

    wsClient.on("message", (raw) => {
      wsStatus.lastMsgAt = Date.now();
      let j = null;
      try { j = JSON.parse(raw.toString()); } catch (e) { return; }

      // Common patterns:
      // { event: "tick", data: { token: "...", ltp: 12345 } }
      // { type: "ltp", data: {...} }   etc.
      const payload = j.data || j;
      if (!payload) return;

      // normalize token & ltp detection
      const token = payload.token || payload.instrumentToken || payload.symboltoken || payload.tokenId;
      const ltp = Number(payload.ltp || payload.lastPrice || payload.price || payload.last);

      if (token && isFinite(ltp) && ltp > 0) {
        // store realtime tick
        try {
          lastKnown.spot = ltp;
          lastKnown.updatedAt = Date.now();
        } catch(e){}
      }

      // keep wsStatus.lastError clear
      wsStatus.lastError = null;
    });

    wsClient.on("close", (code, reason) => {
      wsStatus.connected = false;
      wsClient = null;
      wsStatus.reconnectAttempts = (wsStatus.reconnectAttempts || 0) + 1;
      wsStatus.lastError = `closed:${code}`;
      console.log("WS: closed", code, reason?.toString?.() || reason);
      // reconnect with backoff
      const wait = Math.min(10000, 1000 * wsStatus.reconnectAttempts);
      setTimeout(() => startWebsocketIfReady(), wait);
    });

    wsClient.on("error", (err) => {
      wsStatus.lastError = err?.message || String(err);
      console.log("WS ERROR:", wsStatus.lastError);
      // some errors are fatal and will trigger close; let close handler handle reconnect
    });

    // heartbeat ping if server supports it
    wsClient.on("open", () => {
      try {
        const pingInterval = setInterval(() => {
          if (!wsClient || wsClient.readyState !== WebSocket.OPEN) {
            clearInterval(pingInterval);
            return;
          }
          try { wsClient.ping(); } catch (e) {}
        }, 20000);
      } catch (e){}
    });

  } catch (e) {
    console.log("startWebsocketIfReady Exception:", e?.message || e);
  }
}

// send subscribe in smart-stream v2 format (example)
function sendWsSubscribe(tokens = []) {
  if (!wsClient || wsStatus.connected !== true) {
    console.log("WS: cannot subscribe, not connected.");
    return;
  }
  if (!Array.isArray(tokens) || tokens.length === 0) return;

  // Example subscribe payload — adapt if your provider expects different keys
  const payload = {
    action: "subscribe",
    params: {
      symbols: tokens,
      feed: "ltp"
    }
  };

  try {
    wsClient.send(JSON.stringify(payload));
    wsStatus.subscriptions = tokens.slice();
    console.log("WS: subscribe sent for", tokens);
  } catch (e) {
    console.log("WS subscribe send error:", e?.message || e);
  }
}

// simple helper to unsubscribe (optional)
function sendWsUnsubscribe(tokens = []) {
  if (!wsClient || wsStatus.connected !== true) return;
  if (!Array.isArray(tokens) || tokens.length === 0) return;

  const payload = {
    action: "unsubscribe",
    params: {
      symbols: tokens,
      feed: "ltp"
    }
  };

  try {
    wsClient.send(JSON.stringify(payload));
    // remove from local list
    wsStatus.subscriptions = wsStatus.subscriptions.filter(t => !tokens.includes(t));
    console.log("WS: unsubscribe sent for", tokens);
  } catch (e) {
    console.log("WS unsubscribe send error:", e?.message || e);
  }
}

// Expose small helper to request a subscription by symbol tokens (resolve outside)
async function subscribeByTokens(tokens = []) {
  if (!Array.isArray(tokens)) tokens = [tokens];
  // ensure ws started
  await startWebsocketIfReady();
  sendWsSubscribe(tokens);
}

// ------------------------------------------------------------
// END OF PART 3 — reply “NEXT” for PART 4 (token resolver, fetchers, engines)
// ------------------------------------------------------------
// ------------------------------------------------------------
// PART 4 of 6 — Token Resolver, LTP Fetch, Trend Engine, computeEntry
// ------------------------------------------------------------

// ------------------------------------------------------------
// EXPIRY DETECTION (Weekly Expiry)
// ------------------------------------------------------------
function detectWeeklyExpiry() {
  const today = new Date();
  const day = today.getDay(); // 0=Sun, 1=Mon, ... 4=Thu
  const thursday = new Date(today);

  if (day <= 4) {
    thursday.setDate(today.getDate() + (4 - day));
  } else {
    thursday.setDate(today.getDate() + (7 - (day - 4)));
  }

  const yyyy = thursday.getFullYear();
  const mm = String(thursday.getMonth() + 1).padStart(2, "0");
  const dd = String(thursday.getDate()).padStart(2, "0");

  return `${yyyy}-${mm}-${dd}`;
}

// ------------------------------------------------------------
// INSTRUMENT TOKEN RESOLVER  (REQUIRES instrument master LOADED)
// ------------------------------------------------------------
async function resolveInstrumentToken(symbol, strike = null, type = "FUT") {
  if (!global.instrumentMaster) return null;

  const expiry = detectWeeklyExpiry().replace(/-/g, "").slice(2);

  const filtered = global.instrumentMaster.filter((it) => {
    const ts = it.tradingsymbol || "";
    if (!ts.includes(symbol)) return false;
    if (!ts.includes(expiry)) return false;
    if (type === "FUT" && ts.includes("FUT")) return true;
    if (type === "CE" || type === "PE") {
      return ts.includes(type) && Number(it.strike) === Number(strike);
    }
    return false;
  });

  if (!filtered.length) return null;
  return { token: filtered[0].token, details: filtered[0] };
}

// ------------------------------------------------------------
// FETCH SPOT LTP
// ------------------------------------------------------------
async function fetchSpotLTP(symbol) {
  try {
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
        exchange: "NSE",
        tradingsymbol: symbol,
        symboltoken: "",
      }),
    });

    const j = await r.json().catch(() => null);
    const ltp =
      Number(j?.data?.ltp) ||
      Number(j?.data?.lastPrice) ||
      Number(j?.data?.ltpValue);

    return isFinite(ltp) ? ltp : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------
// FETCH FUTURES LTP
// ------------------------------------------------------------
async function fetchFuturesLTP(symbol) {
  try {
    const expiry = detectWeeklyExpiry();
    const tok = await resolveInstrumentToken(symbol, null, "FUT");
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
          "X-SourceID": "WEB",
        },
        body: JSON.stringify({
          exchange: tok.details.exchange || "NFO",
          tradingsymbol: tok.details.tradingsymbol,
          symboltoken: tok.token,
        }),
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice);

    return isFinite(ltp) ? ltp : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------
// FETCH OPTION LTP (CE / PE)
// ------------------------------------------------------------
async function fetchOptionLTP(symbol, strike, type) {
  try {
    const tok = await resolveInstrumentToken(symbol, strike, type);
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
          "X-SourceID": "WEB",
        },
        body: JSON.stringify({
          exchange: tok.details.exchange || "NFO",
          tradingsymbol: tok.details.tradingsymbol,
          symboltoken: tok.token,
        }),
      }
    );

    const j = await r.json().catch(() => null);
    const ltp = Number(j?.data?.ltp || j?.data?.lastPrice);

    return isFinite(ltp) ? ltp : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------
// STRIKE GENERATOR
// ------------------------------------------------------------
function generateStrikes(spot) {
  spot = Number(spot) || 0;
  const atm = Math.round(spot / 50) * 50;

  return {
    atm,
    ce: atm + 50,
    pe: atm - 50,
  };
}

// ------------------------------------------------------------
// SIMPLE TREND ENGINE
// ------------------------------------------------------------
function computeTrend({ ema20, ema50, rsi, vwap, spot }) {
  const direction =
    ema20 > ema50
      ? "UP"
      : ema20 < ema50
      ? "DOWN"
      : "NEUTRAL";

  return {
    direction,
    note: `EMA20=${ema20}, EMA50=${ema50}, RSI=${rsi}, VWAP=${vwap}, Spot=${spot}`,
  };
}

// ------------------------------------------------------------
// FUTURES DIFF
// ------------------------------------------------------------
async function computeFuturesDiff(symbol, spot) {
  const fut = await fetchFuturesLTP(symbol);
  if (!fut) return null;
  return fut - Number(spot);
}

// ------------------------------------------------------------
// COMPUTE ENTRY — FINAL ENGINE
// ------------------------------------------------------------
async function computeEntry({ symbol, spot, ema20, ema50, rsi, vwap }) {
  const trend = computeTrend({ ema20, ema50, rsi, vwap, spot });
  const futDiff = await computeFuturesDiff(symbol, spot);
  const strikes = generateStrikes(spot);

  const ceLTP = await fetchOptionLTP(symbol, strikes.ce, "CE");
  const peLTP = await fetchOptionLTP(symbol, strikes.pe, "PE");

  return {
    trend,
    futDiff,
    strikes,
    ceLTP,
    peLTP,
  };
}

// ------------------------------------------------------------
// END OF PART 4 — reply “NEXT” for PART 5 (API routes)
// ------------------------------------------------------------
// ------------------------------------------------------------
// PART 5 of 6 — API Routes (login, status, compute, ws-status)
// ------------------------------------------------------------

// -----------------------
// LOGIN API
// -----------------------
app.post("/api/login", async (req, res) => {
  const password = req.body?.password || "";

  const r = await smartApiLogin(password);

  if (!r.ok) {
    return res.json({
      success: false,
      error:
        r.reason === "ENV_MISSING"
          ? "SmartAPI env missing"
          : r.reason === "PASSWORD_MISSING"
          ? "Password missing"
          : r.reason === "LOGIN_FAILED"
          ? "Login failed"
          : r.error || "Unknown login error",
    });
  }

  // Start Smart-Stream websocket
  setTimeout(() => startWebsocketIfReady(), 1500);

  return res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at,
    },
  });
});

// -----------------------
// LOGIN STATUS
// -----------------------
app.get("/api/login/status", (req, res) => {
  res.json({
    success: true,
    logged_in: !!session.access_token,
    expires_at: session.expires_at,
  });
});

// -----------------------
// WS STATUS
// -----------------------
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions,
  });
});

// -----------------------
// SETTINGS DATA (APP USE)
// -----------------------
app.get("/api/settings", (req, res) => {
  res.json({
    apiKey: SMART_API_KEY ? "SET" : "",
    userId: SMART_USER_ID || "",
    totp: SMART_TOTP_SECRET ? "SET" : "",
  });
});

// -----------------------
// COMPUTE (FULL ENGINE)
// -----------------------
app.post("/api/compute", async (req, res) => {
  try {
    const body = req.body || {};
    const symbol = (body.market || "NIFTY").toUpperCase();

    let spot = Number(body.spot) || null;

    // LIVE SPOT FROM WS
    if (body.use_live && lastKnown.spot) {
      spot = lastKnown.spot;
    }

    // fallback if live missing
    if (!spot) {
      spot = await fetchSpotLTP(symbol);
    }

    const ema20 = Number(body.ema20 || 0);
    const ema50 = Number(body.ema50 || 0);
    const rsi = Number(body.rsi || 0);
    const vwap = Number(body.vwap || 0);

    const result = await computeEntry({
      symbol,
      spot,
      ema20,
      ema50,
      rsi,
      vwap,
    });

    return res.json({
      success: true,
      message: "Compute OK",
      input: {
        symbol,
        spot,
        ema20,
        ema50,
        rsi,
        vwap,
        use_live: !!body.use_live,
      },
      trend: result.trend,
      futures_diff: result.futDiff,
      strikes: result.strikes,
      ce_ltp: result.ceLTP,
      pe_ltp: result.peLTP,
      meta: {
        live_ltp: lastKnown.spot,
        live_time: lastKnown.updatedAt,
      },
    });
  } catch (err) {
    return res.json({
      success: false,
      error: err?.message || "Compute error",
    });
  }
});

// ------------------------------------------------------------
// END OF PART 5 — reply “NEXT” for PART 6 (final server listen)
// ------------------------------------------------------------
// ------------------------------------------------------------
// PART 6 of 6 — Final Server Listen + Auto WS Start
// ------------------------------------------------------------

// ------------------------
// HEALTH CHECK
// ------------------------
app.get("/", (req, res) => {
  res.send("Backend Running — Smart-Stream V2 Active");
});

// ------------------------
// AUTO-START WEBSOCKET
// ------------------------
setTimeout(() => {
  console.log("WS: attempting auto-start...");
  startWebsocketIfReady();
}, 2000);

// ------------------------
// START EXPRESS SERVER
// ------------------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`SERVER LIVE on PORT ${PORT}`);
});

// ------------------------------------------------------------
// END OF SERVER.JS (FULL FILE COMPLETED)
// ------------------------------------------------------------
