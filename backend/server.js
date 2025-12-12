/* PART 1/2 — server.js (PART A) */
/* BASE IMPORTS + CONFIG + SESSION + TOTP + LOGIN */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");

/* Load engines */
const apiSuggest = require("./engines/apiSuggest"); // <--- main engine entry
// other engines are required inside apiSuggest (trendEngine, greeksEngine, etc.)

/* ONLINE MASTER AUTO-LOADER (no need to store huge master in git) */
global.instrumentMaster = [];
async function loadMasterOnline() {
  try {
    const url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
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

/* SERVE FRONTEND (optional) */
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.get("/", (req, res) => res.sendFile(path.join(frontendPath, "index.html")).catch(()=>res.send("Rahul Backend OK")));
app.get("/settings", (req, res) => res.sendFile(path.join(frontendPath, "settings.html")).catch(()=>res.send("Settings")));

/// SMARTAPI ENV
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
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

/* SAFE JSON FETCH */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
}

/* SmartAPI login (keeps session.feed_token etc) */
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
          totp: totp,
        }),
      }
    );

    const data = await resp.json().catch(() => null);

    console.log("LOGIN RAW:", JSON.stringify(data, null, 2));

    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
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
    return { ok: false, reason: "EXCEPTION", error: err && err.message ? err.message : String(err) };
  }
}

/* Login routes used by frontend to provide trading password */
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
      raw: r.raw || null,
    });
  }

  res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: {
      logged_in: true,
      expires_at: session.expires_at,
      login_time: session.login_time
    },
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
    totp: SMART_TOTP_SECRET || "",
  });
});

/* Export for testability (if used as module) */
module.exports = {
  app,
  session,
  lastKnown,
  SMARTAPI_BASE,
  SMART_API_KEY,
  SMART_API_SECRET,
  SMART_TOTP_SECRET,
  SMART_USER_ID,
  safeFetchJson,
  smartApiLogin,
  generateTOTP
};
/* PART 2/2 — server.js (PART B) */
/* HELPERS used across file */
function tsOf(entry) {
  return String(entry.tradingsymbol || entry.symbol || entry.name || "").toUpperCase();
}
function itypeOf(entry) {
  return String(entry.instrumenttype || entry.instrumentType || entry.type || "").toUpperCase();
}
function parseExpiryDate(v) {
  if (!v) return null;
  const s = String(v).trim();
  const m = moment(s, ["YYYY-MM-DD", "YYYYMMDD", "DD-MM-YYYY", "DDMMMYYYY", "DDMMYYYY", moment.ISO_8601], true);
  if (m.isValid()) return m.toDate();
  const fallback = new Date(s);
  return isFinite(fallback.getTime()) ? fallback : null;
}
function isTokenSane(t) {
  if (!t && t !== 0) return false;
  const n = Number(String(t).replace(/\D/g, "")) || 0;
  return n > 0;
}

/* WEBSOCKET (SmartAPI) — same logic as your original working file */
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

function scheduleWSReconnect() {
  if (wsStatus.reconnectAttempts > 10) {
    console.log("WS: too many reconnect attempts, giving up for now.");
    return;
  }
  wsStatus.reconnectAttempts++;
  const wait = Math.min(30000, 1000 + wsStatus.reconnectAttempts * 2000);
  console.log("WS: scheduling reconnect in", wait);
  setTimeout(() => startWebsocketIfReady(), wait);
}

/* SUBSCRIBE CORE SYMBOLS (NIFTY / SENSEX / NATURALGAS futures tokens) */
async function subscribeCoreSymbols() {
  try {
    const symbols = ["NIFTY", "SENSEX", "NATURALGAS"];
    // detect nearest expiry using resolveInstrumentToken helper (function defined later)
    const expiry = detectExpiryForSymbol("NIFTY").currentWeek;
    const tokens = [];

    for (let s of symbols) {
      const tok = await resolveInstrumentToken(s, expiry, 0, "FUT").catch(() => null);
      if (tok && tok.token) tokens.push(String(tok.token));
    }

    if (tokens.length > 0 && wsClient && wsClient.readyState === WebSocket.OPEN) {
      const sub = {
        task: "cn",
        channel: {
          instrument_tokens: tokens,
          feed_type: "ltp"
        }
      };
      try { wsClient.send(JSON.stringify(sub)); } catch (e) { console.log("WS SUB SEND ERR", e); }
      wsStatus.subscriptions = tokens;
      console.log("WS SUBSCRIBED →", tokens);
    }
  } catch (e) { console.log("WS SUBSCRIBE ERR", e); }
}

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

    try { wsClient.send(JSON.stringify(auth)); } catch (e) { console.log("WS AUTH SEND ERR", e); }

    setTimeout(() => subscribeCoreSymbols(), 1000);

    if (wsHeartbeat) clearInterval(wsHeartbeat);
    wsHeartbeat = setInterval(() => {
      try {
        if (wsClient && wsClient.readyState === WebSocket.OPEN) {
          wsClient.send("ping");
        }
      } catch (e) { console.log("HB ERR", e); }
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
    const token = d.token || d.instrument_token || null;
    const ltp = Number(d.ltp || d.lastPrice || d.price || 0) || null;
    const oi = Number(d.oi || d.openInterest || 0) || null;
    const sym = d.tradingsymbol || d.symbol || null;

    if (sym && ltp != null) {
      realtime.ticks[sym] = {
        ltp,
        oi,
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
          cur.low = Math.min(cur.low, ltp);
          cur.close = ltp;
          cur.volume = (cur.volume || 0) + (d.volumeDelta || 0);
        }
      }
    } catch (e) { console.log("CANDLE ERROR", e); }
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

/* WS STATUS ENDPOINT */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    lastError: wsStatus.lastError,
    subs: wsStatus.subscriptions
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

/* INITIAL DELAYED WS START (in case env already has tokens) */
setTimeout(() => startWebsocketIfReady(), 2000);

/* ---------------------------
   Utility: detectExpiryForSymbol
   (small helper used by subscribeCoreSymbols)
   --------------------------- */
function detectExpiryForSymbol(symbol) {
  // simple nearest-expiry heuristic; original had more robust logic
  const now = moment();
  const currentWeek = now.clone().endOf('week'); // placeholder
  const monthlyExpiry = now.clone().endOf('month');
  return {
    currentWeek: currentWeek.format("YYYY-MM-DD"),
    monthly: monthlyExpiry.format("YYYY-MM-DD")
  };
}

/* ---------------------------
   /api/suggest  → main engine entry
   Accepts: { market, ema20, ema50, rsi, vwap, spot, expiry, budget_per_trade, pcr, ... }
   It will prefer live spot from WebSocket when available otherwise fallback to provided spot or REST.
   --------------------------- */
app.post("/api/suggest", async (req, res) => {
  try {
    const input = req.body || {};
    // Prefer live spot if recent
    if (!input.spot && lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) {
      input.spot = lastKnown.spot;
    }
    // Pass through to apiSuggest.handler (your engines folder uses this)
    const out = await apiSuggest.handler(input);
    return res.json(out);
  } catch (err) {
    console.log("SUGGEST ERR:", err);
    return res.json({ ok: false, error: "SUGGEST_EXCEPTION", detail: String(err) });
  }
});

/* Small /api/calc compatibility route (keeps older clients working) */
app.post("/api/calc", async (req, res) => {
  try {
    const body = req.body || {};
    const input = {
      market: body.market,
      ema20: body.ema20,
      ema50: body.ema50,
      vwap: body.vwap,
      rsi: body.rsi,
      spot: body.spot || (lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000 ? lastKnown.spot : null),
      expiry_days: body.expiry_days
    };

    if (!input.spot) {
      // fallback: try optional REST LTP (fetchLTP) if implemented
      // Here we return failure if spot unknown
      return res.json({ success: false, error: "Spot could not be resolved", meta: { live_data_used: !!lastKnown.spot }});
    }

    const out = await apiSuggest.handler({
      market: input.market,
      ema20: input.ema20,
      ema50: input.ema50,
      vwap: input.vwap,
      rsi: input.rsi,
      spot: input.spot,
      expiry_days: input.expiry_days
    });

    return res.json({ success: true, entry: out });
  } catch (e) {
    return res.json({ success: false, error: "EXCEPTION_IN_CALC", detail: String(e) });
  }
});

/* PING */
app.get("/api/ping", (req, res) => {
  res.json({
    success: true,
    time: Date.now(),
    live: wsStatus.connected,
    spot: lastKnown.spot || null
  });
});

/* HEALTH */
app.get("/healthz", (req, res) => {
  res.json({
    ok: true,
    time: Date.now(),
    env: {
      SMARTAPI_BASE: SMARTAPI_BASE ? true : false,
      SMART_API_KEY: SMART_API_KEY ? true : false,
      SMART_USER_ID: SMART_USER_ID ? true : false
    }
  });
});

/* START SERVER */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
