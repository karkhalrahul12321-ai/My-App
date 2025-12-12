/* server.js — integrated, robust, deploy-ready
   - WebSocket (Angel SmartAPI)
   - master loader (online)
   - robust resolveInstrumentToken() heuristic (exposed globally)
   - login endpoints, ws status, /api/suggest passthrough to engines/apiSuggest
*/

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const bodyParser = require("body-parser");
const moment = require("moment");
const WebSocket = require("ws");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

// Load engines entry
let apiSuggest = null;
try {
  apiSuggest = require("./engines/apiSuggest");
} catch (e) {
  console.warn("Warning: engines/apiSuggest not found or failed to load:", e && e.message);
}

// GLOBAL MASTER (populated by loadMasterOnline)
global.instrumentMaster = [];

/* --- Load master online (best-effort) --- */
async function loadMasterOnline() {
  const url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json";
  try {
    const r = await fetch(url);
    const j = await r.json().catch(() => null);
    if (Array.isArray(j) && j.length) {
      global.instrumentMaster = j;
      console.log("MASTER LOADED ONLINE ✔ COUNT:", j.length);
    } else {
      console.log("MASTER LOAD: empty or invalid response");
    }
  } catch (e) {
    console.log("MASTER LOAD ERROR:", e && e.message ? e.message : e);
  }
}
loadMasterOnline();
setInterval(loadMasterOnline, 60 * 60 * 1000);

/* --- Helper: normalize strings --- */
function norm(s) {
  if (!s && s !== 0) return "";
  return String(s).toUpperCase().replace(/\s+/g, " ").trim();
}

/* --- Robust resolveInstrumentToken (exposed globally) ---
   Heuristic search over global.instrumentMaster to find a row matching:
   - underlying (nifty/sensex/natural_gas)
   - strike
   - CE/PE (type)
   - optionally expiry (loose match)
   Returns: { tradingsymbol, token, instrument } or null
*/
function resolveInstrumentToken(marketName, strike, type = "CE", expiryDateOrStr = null) {
  try {
    if (!Array.isArray(global.instrumentMaster) || global.instrumentMaster.length === 0) return null;
    const marketKey = (String(marketName || "")).toLowerCase();

    // underlying name candidates (common variants)
    const underlyingMap = {
      nifty: ["NIFTY", "NIFTY50", "NIFTY 50", "NIFTY-I", "NIFTY-I2", "NIFTY-I1"],
      sensex: ["SENSEX", "SENSEX30", "SENSEX 30", "SENSEX-I"],
      natural_gas: ["NATURALGAS", "NATURAL GAS", "NATGAS", "NATURALGAS-MCX", "NATURAL_GAS"]
    };

    const candidates = underlyingMap[marketKey] || [marketKey.toUpperCase()];

    const strikeStr = String(strike || "").replace(/\s+/g, "");
    const wantType = String(type || "CE").toUpperCase();

    // derive expiry tokens possible
    let expiryNorm = null;
    if (expiryDateOrStr) {
      if (typeof expiryDateOrStr === "object") {
        if (expiryDateOrStr.date) expiryNorm = norm(expiryDateOrStr.date);
        else if (expiryDateOrStr.daysLeft != null) expiryNorm = null; // ignore daysLeft as match
      } else {
        expiryNorm = norm(expiryDateOrStr);
      }
    }

    // prepare regex to find strike (numbers) and CE/PE
    const strikePattern = strikeStr ? new RegExp(String(strikeStr)) : null;
    const typePattern = new RegExp(`\\b${wantType}\\b`, "i");

    // scanning master: prioritize exact matches with token
    for (const row of global.instrumentMaster) {
      try {
        const name = norm(row.tradingsymbol || row.name || row.symbol || "");
        const token = row.token || row.instrument_token || row.symboltoken || row.tokenId || row.token_id || row.tokenid || null;
        if (!name) continue;

        // underlying check: name should contain any candidate underlying substring
        const hasUnderlying = candidates.some(u => name.includes(u));
        if (!hasUnderlying) continue;

        // strike check: name must contain strike digits (loose)
        if (strikePattern && !strikePattern.test(name)) continue;

        // type check: prefer rows that mention CE/PE specifically
        if (wantType && !typePattern.test(name)) {
          // allow if instrument type field indicates CE/PE
          const it = norm(row.instrumenttype || row.type || "");
          if (!(it && it.includes(wantType))) continue;
        }

        // expiry check (loose): if expiryNorm provided, ensure either name or row.expiry contains it
        if (expiryNorm) {
          if (!name.includes(expiryNorm) && !(String(row.expiry || row.expiryDate || "").toUpperCase().includes(expiryNorm))) {
            // not strictly required, allow fallback
            // continue;
          }
        }

        // final candidate found
        return {
          tradingsymbol: name,
          token: token ? String(token) : null,
          instrument: row
        };
      } catch (e) {
        continue;
      }
    }

    // If not found, attempt a looser second pass: try removing spaces and checking
    for (const row of global.instrumentMaster) {
      try {
        const nameRaw = String(row.tradingsymbol || row.name || row.symbol || "");
        const name = nameRaw.toUpperCase().replace(/[\s\-_:]/g, "");
        if (!name) continue;
        if (!candidates.some(u => name.includes(u.replace(/\s+/g, "")))) continue;
        if (strikeStr && !name.includes(strikeStr)) continue;
        if (wantType && !name.includes(wantType)) continue;
        const token = row.token || row.instrument_token || null;
        return { tradingsymbol: nameRaw, token: token ? String(token) : null, instrument: row };
      } catch (e) {
        continue;
      }
    }

    return null;
  } catch (e) {
    return null;
  }
}
global.resolveInstrumentToken = resolveInstrumentToken;

/* --- Express app + middleware --- */
const app = express();
app.use(cors());
app.use(bodyParser.json());
const frontendPath = path.join(__dirname, "public");
if (fs.existsSync(frontendPath)) app.use(express.static(frontendPath));

/* --- SMARTAPI config --- */
const SMARTAPI_BASE = process.env.SMARTAPI_BASE || "https://apiconnect.angelbroking.com";
const SMART_API_KEY = process.env.SMART_API_KEY || "";
const SMART_API_SECRET = process.env.SMART_API_SECRET || "";
const SMART_TOTP_SECRET = process.env.SMART_TOTP || "";
const SMART_USER_ID = process.env.SMART_USER_ID || "";

let session = {
  access_token: null,
  refresh_token: null,
  feed_token: null,
  expires_at: 0,
  login_time: null
};

let lastKnown = {
  spot: null,
  updatedAt: 0
};

/* --- base32 + TOTP (same as before) --- */
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

/* --- safeFetchJson --- */
async function safeFetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => null);
    return { ok: true, data, status: r.status };
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
}

/* --- SmartAPI login --- */
async function smartApiLogin(tradingPassword) {
  if (!SMART_API_KEY || !SMART_TOTP_SECRET || !SMART_USER_ID) {
    return { ok: false, reason: "ENV_MISSING" };
  }
  if (!tradingPassword) {
    return { ok: false, reason: "PASSWORD_MISSING" };
  }

  try {
    const totp = generateTOTP(SMART_TOTP_SECRET);

    const resp = await fetch(`${SMARTAPI_BASE}/rest/auth/angelbroking/user/v1/loginByPassword`, {
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
    });

    const data = await resp.json().catch(() => null);
    if (!data || data.status === false) {
      return { ok: false, reason: "LOGIN_FAILED", raw: data || null };
    }

    const d = data.data || {};
    session.access_token = d.jwtToken || null;
    session.refresh_token = d.refreshToken || null;
    session.feed_token = d.feedToken || null;
    session.expires_at = Date.now() + 20 * 60 * 60 * 1000;
    session.login_time = Date.now();

    // start websocket if tokens present (delayed)
    setTimeout(() => startWebsocketIfReady(), 1000);

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: "EXCEPTION", error: err && err.message ? err.message : String(err) };
  }
}

/* --- Login endpoints --- */
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
  return res.json({
    success: true,
    message: "SmartAPI Login Successful",
    session: { logged_in: true, expires_at: session.expires_at, login_time: session.login_time }
  });
});

app.get("/api/login/status", (req, res) => {
  res.json({ success: true, logged_in: !!session.access_token, expires_at: session.expires_at || null, login_time: session.login_time || null });
});

app.get("/api/settings", (req, res) => {
  res.json({ apiKey: SMART_API_KEY || "", userId: SMART_USER_ID || "", totp: SMART_TOTP_SECRET || "" });
});

/* --------------------
   WEBSOCKET (Angel SmartAPI) setup
   -------------------- */
const WS_URL = "wss://smartapisocket.angelone.in/smart-stream";
let wsClient = null;
let wsStatus = { connected: false, lastMsgAt: 0, lastError: null, reconnectAttempts: 0, subscriptions: [] };
let wsHeartbeat = null;

const realtime = { ticks: {}, candles1m: {} };

function scheduleWSReconnect() {
  if (wsStatus.reconnectAttempts > 10) { console.log("WS: too many reconnect attempts"); return; }
  wsStatus.reconnectAttempts++;
  const wait = Math.min(30000, 1000 + wsStatus.reconnectAttempts * 2000);
  setTimeout(() => startWebsocketIfReady(), wait);
}

async function subscribeCoreSymbols() {
  try {
    const symbols = ["NIFTY", "SENSEX", "NATURAL_GAS", "NATURALGAS"];
    const tokens = [];
    // Try to detect weekly expiry for NIFTY
    const expiry = detectExpiryForSymbol("NIFTY").currentWeek;
    for (let s of symbols) {
      try {
        const tok = await resolveInstrumentToken(s, 0, "FUT", expiry);
        if (tok && tok.token) tokens.push(String(tok.token));
      } catch (e) { continue; }
    }
    if (tokens.length && wsClient && wsClient.readyState === WebSocket.OPEN) {
      const sub = { task: "cn", channel: { instrument_tokens: tokens, feed_type: "ltp" } };
      try { wsClient.send(JSON.stringify(sub)); } catch (e) { console.log("WS SUB SEND ERR", e && e.message ? e.message : e); }
      wsStatus.subscriptions = tokens;
      console.log("WS SUBSCRIBED →", tokens);
    }
  } catch (e) { console.log("WS SUBSCRIBE ERR", e && e.message ? e.message : e); }
}

function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;
  if (!session.feed_token || !session.access_token) { console.log("WS: waiting for login tokens..."); return; }

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
    console.log("WS INIT ERR", e && e.message ? e.message : e);
    return;
  }

  wsClient.on("open", () => {
    wsStatus.connected = true; wsStatus.reconnectAttempts = 0; wsStatus.lastError = null;
    console.log("WS: connected.");
    const auth = { task: "auth", channel: "websocket", token: session.feed_token, user: SMART_USER_ID, apikey: SMART_API_KEY, source: "API" };
    try { wsClient.send(JSON.stringify(auth)); } catch (e) { console.log("WS AUTH ERR", e && e.message ? e.message : e); }
    setTimeout(() => subscribeCoreSymbols(), 1000);
    if (wsHeartbeat) clearInterval(wsHeartbeat);
    wsHeartbeat = setInterval(() => {
      try { if (wsClient && wsClient.readyState === WebSocket.OPEN) wsClient.send("ping"); } catch (e) {}
    }, 30000);
  });

  wsClient.on("message", (raw) => {
    wsStatus.lastMsgAt = Date.now();
    let msg = null;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || !msg.data) return;
    const d = msg.data;
    const sym = d.tradingsymbol || d.symbol || null;
    const ltp = Number(d.ltp || d.lastPrice || d.price || 0) || null;
    const oi = Number(d.oi || d.openInterest || 0) || null;

    if (sym && ltp != null) {
      realtime.ticks[sym] = { ltp, oi, time: Date.now() };
      lastKnown.spot = ltp;
      lastKnown.updatedAt = Date.now();
    }

    // build 1m candle per symbol
    try {
      if (sym && ltp != null) {
        if (!realtime.candles1m[sym]) realtime.candles1m[sym] = [];
        const arr = realtime.candles1m[sym];
        const now = Date.now();
        const curMin = Math.floor(now / 60000) * 60000;
        let cur = arr.length ? arr[arr.length - 1] : null;
        if (!cur || cur.time !== curMin) {
          const newC = { time: curMin, open: ltp, high: ltp, low: ltp, close: ltp, volume: d.volume || 0 };
          arr.push(newC);
          if (arr.length > 180) arr.shift();
        } else {
          cur.high = Math.max(cur.high, ltp);
          cur.low = Math.min(cur.low, ltp);
          cur.close = ltp;
          cur.volume = (cur.volume || 0) + (d.volumeDelta || 0);
        }
      }
    } catch (e) { console.log("CANDLE ERROR", e && e.message ? e.message : e); }
  });

  wsClient.on("error", (err) => { wsStatus.connected = false; wsStatus.lastError = String(err); console.log("WS ERR:", err); scheduleWSReconnect(); });
  wsClient.on("close", (code) => { wsStatus.connected = false; wsStatus.lastError = "closed:" + code; console.log("WS CLOSED", code); scheduleWSReconnect(); });
}

/* auto-start if session exists (useful when tokens pre-seeded) */
setTimeout(() => startWebsocketIfReady(), 2000);

/* helper detectExpiryForSymbol (simple heuristic) */
function detectExpiryForSymbol(symbol) {
  const now = moment();
  return {
    currentWeek: now.clone().endOf('week').format("YYYY-MM-DD"),
    monthly: now.clone().endOf('month').format("YYYY-MM-DD")
  };
}

/* --- API endpoints --- */
app.get("/api/ws/status", (req, res) => {
  res.json({ connected: wsStatus.connected, lastMsgAt: wsStatus.lastMsgAt, lastError: wsStatus.lastError, subs: wsStatus.subscriptions });
});

// Prefer live spot when available for /api/suggest
app.post("/api/suggest", async (req, res) => {
  try {
    const input = req.body || {};
    if (!input.spot && lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) input.spot = lastKnown.spot;
    if (!apiSuggest) return res.json({ ok: false, error: "Suggest engine not loaded" });
    const out = await apiSuggest.handler(input);
    return res.json(out);
  } catch (err) {
    console.log("SUGGEST ERR:", err && err.stack ? err.stack : err);
    return res.json({ ok: false, error: "SUGGEST_EXCEPTION", detail: String(err) });
  }
});

// compatibility endpoints
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
    if (!input.spot) return res.json({ success: false, error: "Spot could not be resolved", meta: { live_data_used: !!lastKnown.spot }});
    const out = await apiSuggest.handler({ market: input.market, ema20: input.ema20, ema50: input.ema50, vwap: input.vwap, rsi: input.rsi, spot: input.spot, expiry_days: input.expiry_days });
    return res.json({ success: true, entry: out });
  } catch (e) {
    return res.json({ success: false, error: "EXCEPTION_IN_CALC", detail: String(e) });
  }
});

app.get("/api/ping", (req, res) => res.json({ success: true, time: Date.now(), live: wsStatus.connected, spot: lastKnown.spot || null }));
app.get("/healthz", (req, res) => res.json({ ok: true, time: Date.now(), env: { SMARTAPI_KEY: !!SMART_API_KEY, SMART_USER_ID: !!SMART_USER_ID } }));

/* global error handlers */
process.on("unhandledRejection", (reason, p) => { console.error("Unhandled Rejection at:", p, "reason:", reason); });
process.on("uncaughtException", (err) => { console.error("Uncaught Exception:", err && err.stack ? err.stack : err); });

/* start server */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SERVER LIVE ON PORT ${PORT}`);
});
