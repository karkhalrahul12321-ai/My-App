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

/* =========================
   🔧 FIX-A (IMPORTANT)
   lastKnown.spot अब सिर्फ़
   INDEX / SPOT से update होगा
   ========================= */

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
    return {
      ok: false,
      error: e && e.message ? e.message : String(e)
    };
  }
}

/* SmartAPI login */
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
    return {
      ok: false,
      reason: "EXCEPTION",
      error: err?.message || String(err)
    };
  }
}
/* PART 2/6 — WEBSOCKET (FULL FIXED VERSION) + HELPERS */

/* --- helpers used across file --- */
function tsOf(entry) {
  return String(entry.tradingsymbol || entry.symbol || entry.name || "").toUpperCase();
}
function itypeOf(entry) {
  return String(entry.instrumenttype || entry.instrumentType || entry.type || "").toUpperCase();
}
function parseExpiryDate(v) {
  if (!v) return null;
  const s = String(v).trim();
  const m = moment(
    s,
    ["YYYY-MM-DD", "YYYYMMDD", "DD-MM-YYYY", "DDMMMYYYY", "DDMMYYYY", moment.ISO_8601],
    true
  );
  if (m.isValid()) return m.toDate();
  const f = new Date(s);
  return isFinite(f.getTime()) ? f : null;
}
function isTokenSane(t) {
  if (!t && t !== 0) return false;
  const n = Number(String(t).replace(/\D/g, "")) || 0;
  return n > 0;
}

/* ================= WEBSOCKET ================= */

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

/* REALTIME MEMORY */
const realtime = {
  ticks: {},
  candles1m: {}
};

/* ================= START WS ================= */
async function startWebsocketIfReady() {
  if (wsClient && wsStatus.connected) return;
  if (!session.feed_token || !session.access_token) {
    console.log("WS: waiting for login tokens...");
    return;
  }

  wsClient = new WebSocket(WS_URL, {
    perMessageDeflate: false,
    headers: {
      Authorization: session.access_token,
      "x-api-key": SMART_API_KEY,
      "x-client-code": SMART_USER_ID,
      "x-feed-token": session.feed_token
    }
  });

  wsClient.on("open", () => {
    wsStatus.connected = true;
    wsStatus.reconnectAttempts = 0;
    wsStatus.lastError = null;
    console.log("WS: connected");

    const auth = {
      task: "auth",
      channel: "websocket",
      token: session.feed_token,
      user: SMART_USER_ID,
      apikey: SMART_API_KEY,
      source: "API"
    };

    wsClient.send(JSON.stringify(auth));

    setTimeout(() => subscribeCoreSymbols(), 1200);

    if (wsHeartbeat) clearInterval(wsHeartbeat);
    wsHeartbeat = setInterval(() => {
      try {
        if (wsClient?.readyState === WebSocket.OPEN) {
          wsClient.send("ping");
        }
      } catch {}
    }, 30000);
  });

  /* ========== 🔧 FIX-B : MESSAGE HANDLER ==========
     - INDEX / SPOT ही lastKnown.spot update करेगा
     - FUT / OPTION overwrite नहीं करेंगे
     =============================================== */
  wsClient.on("message", raw => {
    wsStatus.lastMsgAt = Date.now();

    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    const d = msg?.data;
    if (!d) return;

    const ltp = Number(d.ltp || d.lastPrice || 0);
    const sym = String(d.tradingsymbol || d.symbol || "").toUpperCase();

    if (!ltp || !sym) return;

    realtime.ticks[sym] = { ltp, time: Date.now() };

    // ✅ ONLY INDEX / SPOT updates global spot
    if (
      sym.includes("NIFTY") ||
      sym.includes("SENSEX")
    ) {
      lastKnown.spot = ltp;
      lastKnown.updatedAt = Date.now();
    }
  });

  wsClient.on("error", err => {
    wsStatus.connected = false;
    wsStatus.lastError = String(err);
    scheduleWSReconnect();
  });

  wsClient.on("close", code => {
    wsStatus.connected = false;
    wsStatus.lastError = "closed:" + code;
    scheduleWSReconnect();
  });
}

function scheduleWSReconnect() {
  wsStatus.reconnectAttempts++;
  const backoff = Math.min(30000, 1000 * Math.pow(1.5, wsStatus.reconnectAttempts));
  setTimeout(() => {
    try { wsClient?.terminate(); } catch {}
    wsClient = null;
    startWebsocketIfReady();
  }, backoff);
}

/* ================= 🔧 FIX-C =================
   CORE SYMBOL SUBSCRIPTION
   - INDEX + FUT BOTH
   ============================================ */
async function subscribeCoreSymbols() {
  try {
    const symbols = ["NIFTY", "SENSEX"];
    const tokens = [];

    for (let s of symbols) {
      // INDEX / SPOT
      const indexTok = await resolveInstrumentToken(s, "", 0, "INDEX");
      if (indexTok?.token) tokens.push(String(indexTok.token));

      // FUTURES
      const expiry = detectExpiryForSymbol(s).currentWeek;
      const futTok = await resolveInstrumentToken(s, expiry, 0, "FUT");
      if (futTok?.token) tokens.push(String(futTok.token));
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
    console.log("WS SUBSCRIBED TOKENS:", tokens);
  } catch (e) {
    console.log("WS SUBSCRIBE ERROR", e);
  }
}

/* AUTO START WS AFTER LOGIN */
const _origLogin = smartApiLogin;
smartApiLogin = async function (pw) {
  const r = await _origLogin(pw);
  if (r?.ok) setTimeout(startWebsocketIfReady, 1500);
  return r;
};

/* INITIAL DELAY */
setTimeout(startWebsocketIfReady, 3000);
/* PART 6/6 — API ROUTES + SPOT + CALC + SERVER START */

/* ================= 🔧 FIX-D =================
   AUTO EXPIRY DAYS FALLBACK
   frontend भेजे या ना भेजे
   backend खुद निकालेगा
   ============================================ */
function getAutoExpiryDays(market) {
  try {
    const exp = detectExpiryForSymbol(market).currentWeek;
    return moment(exp).diff(moment(), "days");
  } catch {
    return 0;
  }
}

/* API: GET SPOT */
app.get("/api/spot", async (req, res) => {
  if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) {
    return res.json({
      success: true,
      source: "WS",
      spot: lastKnown.spot
    });
  }

  return res.json({
    success: false,
    error: "SPOT_NOT_AVAILABLE"
  });
});

/* API: /api/calc  (Master Entry Engine) */
app.post("/api/calc", async (req, res) => {
  try {
    let {
      market,
      ema20,
      ema50,
      vwap,
      rsi,
      spot,
      expiry_days
    } = req.body;

    market = String(market || "NIFTY").toUpperCase();

    /* ===== 🔧 FIX-E : SPOT AUTO RESOLVE ===== */
    let finalSpot = null;

    if (lastKnown.spot && Date.now() - lastKnown.updatedAt < 5000) {
      finalSpot = lastKnown.spot;
    } else if (isFinite(Number(spot))) {
      finalSpot = Number(spot);
      lastKnown.spot = finalSpot;
      lastKnown.updatedAt = Date.now();
    }

    if (!finalSpot) {
      return res.json({
        success: false,
        error: "SPOT_NOT_RESOLVED",
        hint: "WS index feed not received yet"
      });
    }

    /* ===== 🔧 FIX-F : EXPIRY AUTO ===== */
    if (!expiry_days || !isFinite(Number(expiry_days))) {
      expiry_days = getAutoExpiryDays(market);
    }

    /* ===== MAIN ENTRY ENGINE ===== */
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

/* API: WS STATUS */
app.get("/api/ws/status", (req, res) => {
  res.json({
    connected: wsStatus.connected,
    lastMsgAt: wsStatus.lastMsgAt,
    subs: wsStatus.subscriptions,
    spot: lastKnown.spot
  });
});

/* SAFE FALLBACK ROOT */
app.get("/", (req, res) => {
  res.send("Backend OK — Live Index WS Enabled ✅");
});

/* START SERVER */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER LIVE ON PORT", PORT);
});
